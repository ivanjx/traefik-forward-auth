using RazorSlices;
using TraefikForwardAuth.Auth;
using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Policy;
using TraefikForwardAuth.Providers;
using TraefikForwardAuth.Rules;
using TraefikForwardAuth.Slices;

namespace TraefikForwardAuth.Http;

/// <summary>
/// Port of the Go forward-auth server: reserves the callback/logout paths, applies rule
/// matching, validates cookies and sessions, and performs the OAuth callback exchange.
/// </summary>
public sealed class ForwardAuthMiddleware
{
    private readonly Func<PolicySnapshot> _policy;
    private readonly SessionManager _sessions;
    private readonly TfaLogger _logger;
    private readonly TimeProvider _timeProvider;

    public ForwardAuthMiddleware(
        PolicyManager policy,
        SessionManager sessions,
        TfaLogger logger,
        TimeProvider timeProvider)
        : this(() => policy.Current, sessions, logger, timeProvider)
    {
    }

    public ForwardAuthMiddleware(
        Func<PolicySnapshot> policy,
        SessionManager sessions,
        TfaLogger logger,
        TimeProvider timeProvider)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public Task InvokeAsync(HttpContext context)
    {
        if (!ForwardedRequest.TryParse(context, out var forwarded, out _))
        {
            return GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "Bad Request");
        }

        var snapshot = _policy();
        var settings = snapshot.Settings;

        if (string.Equals(forwarded.Path, settings.UrlPath, StringComparison.Ordinal))
        {
            return HandleCallbackAsync(context, forwarded, snapshot);
        }

        if (string.Equals(forwarded.Path, LogoutPath(settings.UrlPath), StringComparison.Ordinal))
        {
            return HandleLogoutAsync(context, forwarded, snapshot);
        }

        var result = snapshot.Match(forwarded.ToDescriptor());

        if (result.Action == RuleAction.Allow)
        {
            LogRequest(context, "Allow", result.RuleLabel, "Allowing request");
            context.Response.StatusCode = StatusCodes.Status200OK;
            return Task.CompletedTask;
        }

        return HandleAuthAsync(context, forwarded, snapshot, result);
    }

    private Task HandleAuthAsync(
        HttpContext context,
        ForwardedRequest forwarded,
        PolicySnapshot snapshot,
        RuleMatchResult result)
    {
        var logger = LogRequest(context, "Auth", result.RuleLabel, "Authenticating request");
        var settings = snapshot.Settings;

        if (!context.Request.Cookies.TryGetValue(settings.CookieName, out var cookieValue) ||
            string.IsNullOrEmpty(cookieValue))
        {
            return RedirectToLoginAsync(context, forwarded, snapshot, result.ProviderName, logger);
        }

        var now = _timeProvider.GetUtcNow();
        var domain = CookieService.CookieDomain(settings, forwarded.Host);

        if (!CookieService.TryReadAuthCookieValue(
                settings.SigningSecret,
                domain,
                cookieValue,
                now,
                out var identity,
                out var failure,
                out var error))
        {
            if (failure == CookieValidationFailure.Expired)
            {
                logger.Info("Cookie has expired");
                return RedirectToLoginAsync(context, forwarded, snapshot, result.ProviderName, logger);
            }

            logger.Warn("Invalid cookie", ("error", error));
            return RenderPageAsync(context, StatusCodes.Status401Unauthorized, new AuthPageModel
            {
                Title = "Not authorized",
                Message = "Your sign-in is no longer valid. Sign out to clear it, then sign in again.",
                ActionHref = LogoutPath(settings.UrlPath),
                ActionLabel = "Sign out"
            });
        }

        if (!_sessions.TryGetActive(identity.SessionId, now, out var session) ||
            session.Kind != SessionKind.ForwardAuth ||
            !string.Equals(session.Email, identity.Email, StringComparison.Ordinal))
        {
            return RedirectToLoginAsync(context, forwarded, snapshot, result.ProviderName, logger);
        }

        if (!AccessValidator.IsAllowed(snapshot.Access, result.RuleId, identity.Email, settings.MatchWhitelistOrDomain))
        {
            logger.Warn("Invalid email", ("email", identity.Email));
            return RenderPageAsync(context, StatusCodes.Status401Unauthorized, new AuthPageModel
            {
                Title = "Not authorized",
                Message = "This account does not have access to " + forwarded.Host + ".",
                Email = identity.Email,
                ActionHref = LogoutPath(settings.UrlPath),
                ActionLabel = "Sign in with a different account"
            });
        }

        var role = AccessValidator.GetRole(snapshot.Access, result.RuleId, identity.Email);

        if (!string.IsNullOrEmpty(role))
        {
            logger.Debug("Role found: " + role);
            context.Response.Headers["X-Forwarded-Role"] = role;
        }

        logger.Debug("Allowing valid request");
        context.Response.Headers["X-Forwarded-User"] = identity.Email;
        context.Response.StatusCode = StatusCodes.Status200OK;
        _sessions.Touch(identity.SessionId);

        return Task.CompletedTask;
    }

    private Task HandleCallbackAsync(HttpContext context, ForwardedRequest forwarded, PolicySnapshot snapshot)
    {
        var settings = snapshot.Settings;
        var logger = LogRequest(context, "AuthCallback", "default", "Handling callback");

        var state = QueryValue(forwarded, "state");

        if (!CsrfService.ValidateState(state, out _))
        {
            logger.Warn("Error validating state");
            return GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "Not authorized");
        }

        var csrfCookieName = CsrfService.CookieName(settings, state!);

        if (!context.Request.Cookies.TryGetValue(csrfCookieName, out var csrfCookieValue) ||
            string.IsNullOrEmpty(csrfCookieValue))
        {
            logger.Info("Missing csrf cookie");
            return GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "Not authorized");
        }

        if (!CsrfService.TryValidateCookie(csrfCookieValue, state!, out var providerName, out var redirect, out var csrfError))
        {
            logger.Warn(
                "Error validating csrf cookie",
                ("error", csrfError),
                ("csrf_cookie", csrfCookieValue));
            return GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "Not authorized");
        }

        if (!snapshot.Providers.TryGetValue(providerName, out var provider))
        {
            logger.Warn(
                "Invalid provider in csrf cookie",
                ("csrf_cookie", csrfCookieValue),
                ("provider", providerName));
            return GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "Not authorized");
        }

        if (!TryValidateRedirect(settings, forwarded, redirect, out var redirectError))
        {
            logger.Warn(
                "Invalid redirect in csrf cookie",
                ("redirect", redirect),
                ("error", redirectError));
            return GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "Not authorized");
        }

        GoHttpCompat.DeleteCookie(
            context,
            csrfCookieName,
            CookieService.CsrfCookieDomain(settings, forwarded.Host),
            !settings.InsecureCookie);

        return ExchangeCodeAsync(context, forwarded, settings, provider, providerName, redirect, logger);
    }

    private async Task ExchangeCodeAsync(
        HttpContext context,
        ForwardedRequest forwarded,
        PolicySettings settings,
        IProvider provider,
        string providerName,
        string redirect,
        TfaLogger logger)
    {
        var code = QueryValue(forwarded, "code") ?? "";
        var redirectUri = BuildRedirectUri(settings, forwarded);

        ProviderToken token;
        ProviderUser user;

        try
        {
            token = await provider.ExchangeCodeAsync(redirectUri, code, context.RequestAborted);
            user = await provider.GetUserAsync(token, context.RequestAborted);
        }
        catch (Exception exception)
        {
            logger.Error("Code exchange failed with provider", ("error", exception.Message));
            await GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status503ServiceUnavailable, "Service unavailable");
            return;
        }

        if (string.IsNullOrEmpty(user.Email))
        {
            logger.Error("Provider returned an empty email");
            await GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status503ServiceUnavailable, "Service unavailable");
            return;
        }

        var domain = CookieService.CookieDomain(settings, forwarded.Host);
        SessionRecord session;

        try
        {
            session = await _sessions.CreateAsync(
                SessionKind.ForwardAuth,
                user.Email,
                providerName,
                domain,
                SourceIp(context),
                context.Request.Headers.UserAgent.ToString(),
                settings.Lifetime,
                context.RequestAborted);
        }
        catch (Exception exception) when (!context.RequestAborted.IsCancellationRequested)
        {
            logger.Error("Failed to store session", ("error", exception.Message));
            await GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status503ServiceUnavailable, "Service unavailable");
            return;
        }

        var cookieValue = CookieService.CreateAuthCookieValue(
            settings.SigningSecret,
            domain,
            user.Email,
            session.Id,
            session.ExpiresAt);

        GoHttpCompat.AppendCookie(
            context,
            settings.CookieName,
            cookieValue,
            domain,
            session.ExpiresAt,
            !settings.InsecureCookie);

        logger.Info(
            "Successfully generated auth cookie, redirecting user.",
            ("provider", providerName),
            ("redirect", redirect),
            ("user", user.Email));

        await GoHttpCompat.RedirectAsync(context, redirect);
    }

    private async Task HandleLogoutAsync(HttpContext context, ForwardedRequest forwarded, PolicySnapshot snapshot)
    {
        var settings = snapshot.Settings;
        var logger = LogRequest(context, "Logout", "default", "Handling logout");
        var domain = CookieService.CookieDomain(settings, forwarded.Host);

        if (context.Request.Cookies.TryGetValue(settings.CookieName, out var cookieValue) &&
            !string.IsNullOrEmpty(cookieValue) &&
            CookieService.TryReadAuthCookieValue(
                settings.SigningSecret,
                domain,
                cookieValue,
                _timeProvider.GetUtcNow(),
                out var identity,
                out _,
                out _))
        {
            try
            {
                await _sessions.RevokeAsync(identity.SessionId, audit: null, context.RequestAborted);
            }
            catch (Exception exception)
            {
                logger.Error("Failed to revoke session on logout", ("error", exception.Message));
            }
        }

        GoHttpCompat.DeleteCookie(context, settings.CookieName, domain, !settings.InsecureCookie);

        logger.Info("Logged out user");

        if (!string.IsNullOrEmpty(settings.LogoutRedirect))
        {
            await GoHttpCompat.RedirectAsync(context, settings.LogoutRedirect);
            return;
        }

        await RenderPageAsync(context, StatusCodes.Status401Unauthorized, new AuthPageModel
        {
            Title = "You have been logged out",
            Message = "You have been signed out of " + forwarded.Host + ".",
            ActionHref = "/",
            ActionLabel = "Sign in again"
        });
    }

    private Task RedirectToLoginAsync(
        HttpContext context,
        ForwardedRequest forwarded,
        PolicySnapshot snapshot,
        string providerName,
        TfaLogger logger)
    {
        var settings = snapshot.Settings;

        // Looked up only here so a missing provider never blocks users who already hold a valid session.
        if (!snapshot.Providers.TryGetValue(providerName, out var provider))
        {
            logger.Debug("Provider not configured", ("provider", providerName));
            return GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status503ServiceUnavailable, "Not configured");
        }

        var nonce = CsrfService.NewNonce();
        var csrfCookieName = CsrfService.CookieName(settings, nonce);
        var secure = !settings.InsecureCookie;
        var now = _timeProvider.GetUtcNow();

        GoHttpCompat.AppendCookie(
            context,
            csrfCookieName,
            nonce,
            CookieService.CsrfCookieDomain(settings, forwarded.Host),
            now.AddHours(1),
            secure);

        if (secure && !string.Equals(forwarded.Proto, "https", StringComparison.Ordinal))
        {
            logger.Warn(
                "You are using \"secure\" cookies for a request that was not " +
                "received via https. You should either redirect to https or pass the " +
                "\"insecure-cookie\" config option to permit cookies via http.");
        }

        var redirectUri = BuildRedirectUri(settings, forwarded);
        var state = CsrfService.BuildState(nonce, provider.Name, forwarded.ReturnUrl);
        var loginUrl = provider.GetLoginUrl(redirectUri, state);

        logger.Debug(
            "Set CSRF cookie and redirected to provider login url",
            ("csrf_cookie", string.Concat(csrfCookieName, "=", nonce)),
            ("login_url", loginUrl));

        return GoHttpCompat.RedirectAsync(context, loginUrl);
    }

    private static string BuildRedirectUri(PolicySettings settings, ForwardedRequest forwarded)
    {
        if (CookieService.UseAuthDomain(settings, forwarded.Host, out _))
        {
            return string.Concat(forwarded.Proto, "://", settings.AuthHost, settings.UrlPath);
        }

        return string.Concat(forwarded.Proto, "://", forwarded.Host, settings.UrlPath);
    }

    /// <summary>
    /// Port of upstream <c>ValidateRedirect</c>: the return URL must be http(s) and point at the request host,
    /// or at a host under the shared cookie domain when the auth host is in use.
    /// </summary>
    private static bool TryValidateRedirect(
        PolicySettings settings,
        ForwardedRequest forwarded,
        string redirect,
        out string error)
    {
        if (!Uri.TryCreate(redirect, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            error = "Redirect is not an absolute http(s) URL";
            return false;
        }

        var redirectHost = uri.Host;

        if (CookieService.UseAuthDomain(settings, forwarded.Host, out var authDomain))
        {
            if (!string.Equals(redirectHost, authDomain, StringComparison.OrdinalIgnoreCase) &&
                !redirectHost.EndsWith("." + authDomain, StringComparison.OrdinalIgnoreCase))
            {
                error = "Redirect host is not under the cookie domain";
                return false;
            }
        }
        else if (!string.Equals(redirectHost, CookieService.StripPort(forwarded.Host), StringComparison.OrdinalIgnoreCase))
        {
            error = "Redirect host does not match the request host";
            return false;
        }

        error = "";

        return true;
    }

    private static Task RenderPageAsync(HttpContext context, int statusCode, AuthPageModel model)
    {
        var slice = AuthPage.Create(model);
        slice.StatusCode = statusCode;
        context.Response.ContentType = "text/html; charset=utf-8";
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers.CacheControl = "no-store";

        return ((IResult)slice).ExecuteAsync(context);
    }

    private static string LogoutPath(string urlPath)
    {
        var trimmed = urlPath.Length > 1 ? urlPath.TrimEnd('/') : urlPath;

        if (trimmed.Length == 0)
        {
            trimmed = "/";
        }

        return trimmed == "/" ? "/logout" : trimmed + "/logout";
    }

    private static string? QueryValue(ForwardedRequest forwarded, string name) =>
        forwarded.Query.TryGetValue(name, out var values) && values.Length > 0 ? values[0] : null;

    private static string? SourceIp(HttpContext context)
    {
        if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var forwardedFor) &&
            forwardedFor.Count > 0)
        {
            var value = forwardedFor[0];

            if (!string.IsNullOrEmpty(value))
            {
                var comma = value.IndexOf(',');
                var first = (comma >= 0 ? value[..comma] : value).Trim();

                if (first.Length > 0)
                {
                    return first;
                }
            }
        }

        return context.Connection.RemoteIpAddress?.ToString();
    }

    private TfaLogger LogRequest(HttpContext context, string handler, string rule, string message)
    {
        var cookies = string.Join(
            ", ",
            context.Request.Cookies.Select(cookie => string.Concat(cookie.Key, "=", cookie.Value)));

        _logger.Debug(
            message,
            ("handler", handler),
            ("rule", rule),
            ("method", HeaderValue(context, "X-Forwarded-Method")),
            ("proto", HeaderValue(context, "X-Forwarded-Proto")),
            ("host", HeaderValue(context, "X-Forwarded-Host")),
            ("uri", HeaderValue(context, "X-Forwarded-Uri")),
            ("source_ip", HeaderValue(context, "X-Forwarded-For")),
            ("cookies", cookies));

        return _logger;
    }

    private static string HeaderValue(HttpContext context, string name) =>
        context.Request.Headers.TryGetValue(name, out var value) && value.Count > 0 ? value[0] ?? "" : "";
}
