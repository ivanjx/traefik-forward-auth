using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using TraefikForwardAuth.Policy;

namespace TraefikForwardAuth.Auth;

public sealed record AuthCookieIdentity(string Email, string SessionId, DateTimeOffset ExpiresAt);

public enum CookieValidationFailure
{
    None,
    Invalid,
    Expired
}

public static class CookieService
{
    /// <summary>Cookie domain for the request: the first configured domain that matches, otherwise the host without its port.</summary>
    public static string CookieDomain(PolicySettings settings, string host)
    {
        var hostWithoutPort = StripPort(host);

        return MatchConfiguredDomain(settings, hostWithoutPort) ?? hostWithoutPort;
    }

    public static string CsrfCookieDomain(PolicySettings settings, string host) =>
        UseAuthDomain(settings, host, out var matchedDomain) ? matchedDomain : StripPort(host);

    public static bool UseAuthDomain(PolicySettings settings, string host, out string matchedDomain)
    {
        var requestHost = StripPort(host);
        matchedDomain = requestHost;

        if (string.IsNullOrEmpty(settings.AuthHost))
        {
            return false;
        }

        var authHost = StripPort(settings.AuthHost);
        var requestDomain = MatchConfiguredDomain(settings, requestHost);
        var authDomain = MatchConfiguredDomain(settings, authHost);

        if (requestDomain is null || authDomain is null ||
            !string.Equals(requestDomain, authDomain, StringComparison.Ordinal))
        {
            return false;
        }

        matchedDomain = requestDomain;

        return true;
    }

    public static string CreateAuthCookieValue(
        byte[] secret,
        string domain,
        string email,
        string sessionId,
        DateTimeOffset expires)
    {
        var expiresUnix = expires.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        var mac = ComputeMac(secret, domain, email, expiresUnix, sessionId);

        return string.Concat(Base64UrlEncode(mac), "|", expiresUnix, "|", email, "|", sessionId);
    }

    public static bool TryReadAuthCookieValue(
        byte[] secret,
        string domain,
        string value,
        DateTimeOffset now,
        out AuthCookieIdentity identity,
        out CookieValidationFailure failure,
        out string error)
    {
        identity = new AuthCookieIdentity("", "", default);
        failure = CookieValidationFailure.Invalid;

        if (value is null)
        {
            error = "Invalid cookie format";
            return false;
        }

        var parts = value.Split('|');

        if (parts.Length != 4)
        {
            error = "Invalid cookie format";
            return false;
        }

        var email = parts[2];
        var expiresUnix = parts[1];
        var sessionId = parts[3];

        if (!TryBase64UrlDecode(parts[0], out var mac))
        {
            error = "Unable to decode cookie mac";
            return false;
        }

        var expected = ComputeMac(secret, domain, email, expiresUnix, sessionId);

        if (!CryptographicOperations.FixedTimeEquals(mac, expected))
        {
            error = "Invalid cookie mac";
            return false;
        }

        if (!long.TryParse(expiresUnix, NumberStyles.Integer, CultureInfo.InvariantCulture, out var expiresSeconds) ||
            !TryGetExpiry(expiresSeconds, out var expiresAt))
        {
            error = "Unable to parse cookie expiry";
            return false;
        }

        if (expiresAt < now)
        {
            failure = CookieValidationFailure.Expired;
            error = "Cookie has expired";
            return false;
        }

        identity = new AuthCookieIdentity(email, sessionId, expiresAt);
        failure = CookieValidationFailure.None;
        error = "";

        return true;
    }

    internal static string StripPort(string host)
    {
        if (string.IsNullOrEmpty(host))
        {
            return host;
        }

        if (host[0] == '[')
        {
            var close = host.IndexOf(']');

            if (close >= 0 && close + 1 < host.Length && host[close + 1] == ':')
            {
                return host[..(close + 1)];
            }

            return host;
        }

        var colon = host.IndexOf(':');

        return colon > 0 && colon == host.LastIndexOf(':') ? host[..colon] : host;
    }

    private static string? MatchConfiguredDomain(PolicySettings settings, string host)
    {
        foreach (var configured in settings.CookieDomains)
        {
            var domain = configured.Trim();

            if (domain.Length == 0)
            {
                continue;
            }

            if (string.Equals(host, domain, StringComparison.Ordinal) ||
                host.EndsWith("." + domain, StringComparison.Ordinal))
            {
                return domain;
            }
        }

        return null;
    }

    private static byte[] ComputeMac(byte[] secret, string domain, string email, string expiresUnix, string sessionId) =>
        HMACSHA256.HashData(
            secret,
            Encoding.UTF8.GetBytes(string.Concat(domain, email, expiresUnix, sessionId)));

    private static string Base64UrlEncode(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static bool TryBase64UrlDecode(string value, out byte[] decoded)
    {
        var normalized = value.Replace('-', '+').Replace('_', '/');

        switch (normalized.Length % 4)
        {
            case 0:
                break;
            case 2:
                normalized += "==";
                break;
            case 3:
                normalized += "=";
                break;
            default:
                decoded = [];
                return false;
        }

        try
        {
            decoded = Convert.FromBase64String(normalized);

            return true;
        }
        catch (FormatException)
        {
            decoded = [];
            return false;
        }
    }

    private static bool TryGetExpiry(long seconds, out DateTimeOffset expires)
    {
        try
        {
            expires = DateTimeOffset.FromUnixTimeSeconds(seconds);
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            expires = default;
            return false;
        }
    }
}

public static class CsrfService
{
    public const int NonceHexLength = 32;

    public static string NewNonce() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(NonceHexLength / 2));

    public static string CookieName(PolicySettings settings, string nonce)
    {
        ArgumentNullException.ThrowIfNull(nonce);

        if (nonce.Length < 6)
        {
            throw new ArgumentException("CSRF nonce must be at least 6 characters long.", nameof(nonce));
        }

        return settings.CsrfCookieName + "_" + nonce[..6];
    }

    public static string BuildState(string nonce, string provider, string returnUrl) =>
        string.Concat(nonce, ":", provider, ":", returnUrl);

    public static bool ValidateState(string? state, out string error)
    {
        if (state is null || state.Length < 34)
        {
            error = "Invalid CSRF state value";
            return false;
        }

        error = "";

        return true;
    }

    public static bool TryValidateCookie(
        string cookieValue,
        string state,
        out string provider,
        out string redirect,
        out string error)
    {
        provider = "";
        redirect = "";

        if (cookieValue is null || cookieValue.Length != NonceHexLength)
        {
            error = "Invalid CSRF cookie value";
            return false;
        }

        if (state is null || state.Length < NonceHexLength ||
            !string.Equals(cookieValue, state[..NonceHexLength], StringComparison.Ordinal))
        {
            error = "CSRF cookie does not match state";
            return false;
        }

        if (state.Length < 34)
        {
            error = "Invalid CSRF state format";
            return false;
        }

        var parameters = state[33..];
        var separator = parameters.IndexOf(':');

        if (separator < 0)
        {
            error = "Invalid CSRF state format";
            return false;
        }

        provider = parameters[..separator];
        redirect = parameters[(separator + 1)..];
        error = "";

        return true;
    }
}
