using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using TraefikForwardAuth.Auth;
using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Policy;
using TraefikForwardAuth.Providers;

namespace TraefikForwardAuth.Admin;

public sealed record AdminIdentity(string Email, string SessionId);

public sealed class AdminAuthService
{
    public const string AdminCookieName = "_tfa_admin";
    public const string StateCookieName = "_tfa_admin_state";
    public static readonly TimeSpan AdminLifetime = TimeSpan.FromHours(8);
    private static readonly TimeSpan StateLifetime = TimeSpan.FromMinutes(10);
    private const string CookieAudience = "admin";

    private readonly TfaOptions _options;
    private readonly PolicyManager _policy;
    private readonly SessionManager _sessions;
    private readonly ProviderFactory _providerFactory;
    private readonly ProviderDefinition _definition;
    private readonly TfaLogger _logger;
    private readonly TimeProvider _timeProvider;
    private IProvider? _provider;

    public AdminAuthService(
        TfaOptions options,
        PolicyManager policy,
        SessionManager sessions,
        ProviderFactory providerFactory,
        TfaLogger logger,
        TimeProvider timeProvider)
    {
        _options = options;
        _policy = policy;
        _sessions = sessions;
        _providerFactory = providerFactory;
        _logger = logger;
        _timeProvider = timeProvider;
        _definition = new ProviderDefinition
        {
            Name = options.AdminProvider,
            ClientId = options.AdminClientId,
            ClientSecret = options.AdminClientSecret,
            IssuerUrl = options.AdminIssuerUrl,
            // OIDC providers may reject prompt values they do not support, so only GitHub and Google get the account picker.
            Prompt = options.AdminProvider == ProviderDefinition.Oidc ? null : "select_account"
        };
    }

    public bool IsAdminEmail(string email) => _options.AdminEmails.Contains(email);

    public string GetAntiforgeryToken(string sessionId)
    {
        var secret = _policy.Current.Settings.SigningSecret;

        return Base64Url(HMACSHA256(secret, $"csrf:{sessionId}"));
    }

    public bool ValidateAntiforgeryToken(string sessionId, string? token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return false;
        }

        var expected = GetAntiforgeryToken(sessionId);
        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        var actualBytes = Encoding.UTF8.GetBytes(token);

        return expectedBytes.Length == actualBytes.Length &&
               CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
    }

    public Task<AdminIdentity?> AuthenticateAsync(HttpContext context, CancellationToken cancellationToken)
    {
        if (!context.Request.Cookies.TryGetValue(AdminCookieName, out var value) || string.IsNullOrEmpty(value))
        {
            return Task.FromResult<AdminIdentity?>(null);
        }

        var settings = _policy.Current.Settings;
        var now = _timeProvider.GetUtcNow();

        if (!CookieService.TryReadAuthCookieValue(
                settings.SigningSecret,
                CookieAudience,
                value,
                now,
                out var identity,
                out _,
                out _))
        {
            return Task.FromResult<AdminIdentity?>(null);
        }

        if (!_sessions.TryGetActive(identity.SessionId, now, out var session) ||
            session.Kind != SessionKind.Admin ||
            session.Email != identity.Email ||
            !IsAdminEmail(identity.Email))
        {
            return Task.FromResult<AdminIdentity?>(null);
        }

        _sessions.Touch(identity.SessionId);

        return Task.FromResult<AdminIdentity?>(new AdminIdentity(identity.Email, identity.SessionId));
    }

    public async Task HandleLoginAsync(HttpContext context, CancellationToken cancellationToken)
    {
        IProvider provider;

        try
        {
            provider = await GetProviderAsync(cancellationToken);
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            _logger.Error("Admin login provider is unavailable", ("provider", _definition.Name), ("error", exception.Message));
            await Http.GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status503ServiceUnavailable, "Service unavailable");
            return;
        }

        var returnUrl = SafeReturnUrl(context.Request.Query["returnUrl"].ToString());
        var nonce = CsrfService.NewNonce();
        var state = $"{nonce}:{returnUrl}";
        var now = _timeProvider.GetUtcNow();

        GoHttpCompatAppendCookie(
            context,
            StateCookieName,
            nonce,
            "/",
            now.Add(StateLifetime),
            secure: true,
            sameSite: SameSiteMode.Lax);

        var redirectUri = $"{BaseUrl(context)}/auth/callback";
        var loginUrl = provider.GetLoginUrl(redirectUri, state);

        context.Response.StatusCode = StatusCodes.Status307TemporaryRedirect;
        context.Response.Headers.Location = loginUrl;
    }

    public async Task HandleCallbackAsync(HttpContext context, CancellationToken cancellationToken)
    {
        var state = context.Request.Query["state"].ToString();
        var code = context.Request.Query["code"].ToString();

        context.Request.Cookies.TryGetValue(StateCookieName, out var cookieNonce);

        if (!ValidateState(state, cookieNonce, out var returnUrl))
        {
            _logger.Warn("Admin login state validation failed");
            await Http.GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "Not authorized");
            return;
        }

        DeleteStateCookie(context);

        if (string.IsNullOrEmpty(code))
        {
            await Http.GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "Not authorized");
            return;
        }

        ProviderUser user;

        try
        {
            var redirectUri = $"{BaseUrl(context)}/auth/callback";
            var provider = await GetProviderAsync(cancellationToken);
            var token = await provider.ExchangeCodeAsync(redirectUri, code, cancellationToken);
            user = await provider.GetUserAsync(token, cancellationToken);
        }
        catch (Exception exception)
        {
            _logger.Error("Admin code exchange failed", ("error", exception.Message));
            await Http.GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status503ServiceUnavailable, "Service unavailable");
            return;
        }

        if (!user.EmailVerified || !IsAdminEmail(user.Email))
        {
            _logger.Warn("Admin access denied", ("email", user.Email), ("verified", user.EmailVerified));
            await Http.GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status403Forbidden, "Access denied");
            return;
        }

        var now = _timeProvider.GetUtcNow();
        var session = await _sessions.CreateAsync(
            SessionKind.Admin,
            user.Email,
            _options.AdminProvider,
            CookieService.StripPort(RequestHost(context)),
            ClientIp(context),
            context.Request.Headers.UserAgent.ToString(),
            AdminLifetime,
            cancellationToken);

        var value = CookieService.CreateAuthCookieValue(
            _policy.Current.Settings.SigningSecret,
            CookieAudience,
            session.Email,
            session.Id,
            session.ExpiresAt);

        GoHttpCompatAppendCookie(
            context,
            AdminCookieName,
            value,
            path: "/",
            session.ExpiresAt,
            secure: true,
            sameSite: SameSiteMode.Lax);

        _logger.Info("Admin signed in", ("user", user.Email));

        await Http.GoHttpCompat.RedirectAsync(context, returnUrl, StatusCodes.Status303SeeOther);
    }

    public void SignOut(HttpContext context)
    {
        Http.GoHttpCompat.DeleteCookie(context, AdminCookieName, domain: null, secure: true);
        DeleteStateCookie(context);
    }

    /// <summary>
    /// Creates the provider on first use and caches it. OIDC discovery needs the issuer to be
    /// reachable, so a failure is not cached and the next login tries again.
    /// </summary>
    private async Task<IProvider> GetProviderAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _provider) is { } cached)
        {
            return cached;
        }

        var provider = await _providerFactory.CreateAsync(_definition, cancellationToken)
            ?? throw new InvalidOperationException("Admin login provider configuration is invalid.");

        Volatile.Write(ref _provider, provider);

        return provider;
    }

    private static void DeleteStateCookie(HttpContext context) =>
        Http.GoHttpCompat.DeleteCookie(context, StateCookieName, domain: null, secure: true);

    private static bool ValidateState(string state, string? cookieNonce, out string returnUrl)
    {
        returnUrl = "/";

        if (string.IsNullOrEmpty(cookieNonce) || state.Length < CsrfService.NonceHexLength + 1)
        {
            return false;
        }

        if (!state.AsSpan(0, CsrfService.NonceHexLength).SequenceEqual(cookieNonce))
        {
            return false;
        }

        if (state[CsrfService.NonceHexLength] != ':')
        {
            return false;
        }

        var candidate = state[(CsrfService.NonceHexLength + 1)..];
        returnUrl = SafeReturnUrl(candidate);

        return true;
    }

    /// <summary>
    /// Accepts only a local absolute path. Browsers strip tab, CR and LF while parsing URLs, so a
    /// value like <c>/\t/evil.com</c> would become the protocol-relative <c>//evil.com</c>.
    /// </summary>
    private static string SafeReturnUrl(string? candidate)
    {
        if (string.IsNullOrEmpty(candidate) ||
            !candidate.StartsWith('/') ||
            candidate.StartsWith("//", StringComparison.Ordinal) ||
            candidate.Contains('\\') ||
            candidate.Any(char.IsControl) ||
            !Uri.TryCreate(candidate, UriKind.Relative, out _))
        {
            return "/";
        }

        return candidate;
    }

    private static string BaseUrl(HttpContext context)
    {
        var proto = context.Request.Headers["X-Forwarded-Proto"].FirstOrDefault();

        if (string.IsNullOrEmpty(proto))
        {
            proto = context.Request.Scheme;
        }

        return $"{proto}://{RequestHost(context)}";
    }

    private static string RequestHost(HttpContext context)
    {
        var host = context.Request.Headers["X-Forwarded-Host"].FirstOrDefault();

        return string.IsNullOrEmpty(host) ? context.Request.Host.Value ?? "localhost" : host;
    }

    private static string? ClientIp(HttpContext context)
    {
        var forwarded = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();

        if (!string.IsNullOrEmpty(forwarded))
        {
            var comma = forwarded.IndexOf(',');

            return comma >= 0 ? forwarded[..comma].Trim() : forwarded.Trim();
        }

        return context.Connection.RemoteIpAddress?.ToString();
    }

    private static void GoHttpCompatAppendCookie(
        HttpContext context,
        string name,
        string value,
        string path,
        DateTimeOffset expires,
        bool secure,
        SameSiteMode sameSite)
    {
        var options = new CookieOptions
        {
            Path = path,
            HttpOnly = true,
            Secure = secure,
            Expires = expires,
            SameSite = sameSite
        };

        context.Response.Cookies.Append(name, value, options);
    }

    private static string Base64Url(byte[] value) => Convert.ToBase64String(value)
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');

    private static byte[] HMACSHA256(byte[] secret, string value) =>
        System.Security.Cryptography.HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes(value));
}
