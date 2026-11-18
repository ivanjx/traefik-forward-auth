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
    private readonly GoogleProvider _provider;
    private readonly TfaLogger _logger;
    private readonly TimeProvider _timeProvider;

    public AdminAuthService(
        TfaOptions options,
        PolicyManager policy,
        SessionManager sessions,
        GoogleEndpoints googleEndpoints,
        IHttpClientFactory httpClients,
        TfaLogger logger,
        TimeProvider timeProvider)
    {
        _options = options;
        _policy = policy;
        _sessions = sessions;
        _logger = logger;
        _timeProvider = timeProvider;
        _provider = new GoogleProvider(
            new ProviderDefinition
            {
                Name = ProviderDefinition.Google,
                ClientId = options.AdminGoogleClientId,
                ClientSecret = options.AdminGoogleClientSecret,
                Prompt = "select_account"
            },
            httpClients,
            googleEndpoints,
            logger);
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

    public Task HandleLoginAsync(HttpContext context, CancellationToken cancellationToken)
    {
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
        var loginUrl = _provider.GetLoginUrl(redirectUri, state);

        context.Response.StatusCode = StatusCodes.Status307TemporaryRedirect;
        context.Response.Headers.Location = loginUrl;

        return Task.CompletedTask;
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
            var token = await _provider.ExchangeCodeAsync(redirectUri, code, cancellationToken);
            user = await _provider.GetUserAsync(token, cancellationToken);
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
            ProviderDefinition.Google,
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

        context.Response.StatusCode = StatusCodes.Status303SeeOther;
        context.Response.Headers.Location = returnUrl;
    }

    public void SignOut(HttpContext context)
    {
        Http.GoHttpCompat.DeleteCookie(context, AdminCookieName, domain: null, secure: true);
        DeleteStateCookie(context);
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

    private static string SafeReturnUrl(string? candidate)
    {
        if (string.IsNullOrEmpty(candidate) ||
            !candidate.StartsWith('/') ||
            candidate.StartsWith("//", StringComparison.Ordinal) ||
            candidate.Contains('\\'))
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
