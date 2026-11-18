using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using TraefikForwardAuth.Rules;

namespace TraefikForwardAuth.Http;

public static class GoHttpCompat
{
    public static Task WriteErrorAsync(HttpContext context, int statusCode, string message)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "text/plain; charset=utf-8";
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        return context.Response.WriteAsync(message + "\n", context.RequestAborted);
    }

    public static Task RedirectAsync(
        HttpContext context,
        string location,
        int statusCode = StatusCodes.Status307TemporaryRedirect)
    {
        context.Response.StatusCode = statusCode;
        context.Response.Headers.Location = EscapeNonAscii(location);
        return Task.CompletedTask;
    }

    private const string HexDigits = "0123456789ABCDEF";

    /// <summary>
    /// Percent-encodes the UTF-8 bytes of non-ASCII characters, as Go's <c>http.Redirect</c> does.
    /// Kestrel rejects non-ASCII header values, and return URLs carry the decoded request path.
    /// </summary>
    internal static string EscapeNonAscii(string value)
    {
        if (Ascii.IsValid(value))
        {
            return value;
        }

        var builder = new StringBuilder(value.Length + 16);
        Span<byte> utf8 = stackalloc byte[4];

        foreach (var rune in value.EnumerateRunes())
        {
            if (rune.IsAscii)
            {
                builder.Append((char)rune.Value);
                continue;
            }

            var written = rune.EncodeToUtf8(utf8);

            for (var i = 0; i < written; i++)
            {
                builder.Append('%').Append(HexDigits[utf8[i] >> 4]).Append(HexDigits[utf8[i] & 0xF]);
            }
        }

        return builder.ToString();
    }

    public static void AppendCookie(
        HttpContext context,
        string name,
        string value,
        string? domain,
        DateTimeOffset expires,
        bool secure,
        bool httpOnly = true,
        SameSiteMode sameSite = SameSiteMode.Unspecified)
    {
        var options = new CookieOptions
        {
            Path = "/",
            HttpOnly = httpOnly,
            Secure = secure,
            Expires = expires,
            SameSite = sameSite
        };

        if (!string.IsNullOrEmpty(domain))
        {
            options.Domain = domain;
        }

        context.Response.Cookies.Append(name, value, options);
    }

    public static void DeleteCookie(HttpContext context, string name, string? domain, bool secure)
    {
        var options = new CookieOptions
        {
            Path = "/",
            HttpOnly = true,
            Secure = secure,
            Expires = DateTimeOffset.UnixEpoch,
            SameSite = SameSiteMode.Unspecified
        };

        if (!string.IsNullOrEmpty(domain))
        {
            options.Domain = domain;
        }

        context.Response.Cookies.Delete(name, options);
    }
}

public sealed record ForwardedRequest(
    string Method,
    string Host,
    string Proto,
    string Path,
    string QueryString,
    IReadOnlyDictionary<string, string[]> Headers,
    IReadOnlyDictionary<string, string[]> Query)
{
    public string ReturnUrl => $"{Proto}://{Host}{Path}";

    public RequestDescriptor ToDescriptor() => new(Method, Host, Path, Headers, Query);

    public static bool TryParse(HttpContext context, out ForwardedRequest request, out string error)
    {
        var method = HeaderOrFallback(context, "X-Forwarded-Method", context.Request.Method);
        var host = HeaderOrFallback(context, "X-Forwarded-Host", context.Request.Host.Value ?? "");
        var proto = HeaderOrFallback(context, "X-Forwarded-Proto", context.Request.Scheme);

        string rawPath;
        string queryString;

        if (context.Request.Headers.TryGetValue("X-Forwarded-Uri", out var forwardedUri) && forwardedUri.Count > 0)
        {
            var value = forwardedUri[0] ?? "";

            if (value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                if (!Uri.TryCreate(value, UriKind.Absolute, out var absolute))
                {
                    request = null!;
                    error = "Invalid X-Forwarded-Uri";
                    return false;
                }

                rawPath = absolute.AbsolutePath;
                queryString = absolute.Query;
            }
            else
            {
                var fragment = value.IndexOf('#');

                if (fragment >= 0)
                {
                    value = value[..fragment];
                }

                var question = value.IndexOf('?');

                if (question >= 0)
                {
                    rawPath = value[..question];
                    queryString = value[question..];
                }
                else
                {
                    rawPath = value;
                    queryString = "";
                }
            }
        }
        else
        {
            rawPath = context.Request.Path.Value ?? "/";
            queryString = context.Request.QueryString.Value ?? "";
        }

        if (string.IsNullOrEmpty(rawPath))
        {
            rawPath = "/";
        }

        var normalized = PathNormalizer.Normalize(rawPath);

        if (!normalized.Success)
        {
            request = null!;
            error = normalized.Error ?? "Invalid path";
            return false;
        }

        Dictionary<string, string[]> headers = new(StringComparer.OrdinalIgnoreCase);

        foreach (var header in context.Request.Headers)
        {
            if (header.Key.StartsWith(':'))
            {
                continue;
            }

            headers[header.Key] = header.Value.Where(value => value is not null).Select(value => value!).ToArray();
        }

        Dictionary<string, string[]> query = new(StringComparer.Ordinal);

        try
        {
            foreach (var (name, values) in QueryHelpers.ParseQuery(queryString))
            {
                query[name] = values.Where(value => value is not null).Select(value => value!).ToArray();
            }
        }
        catch (Exception exception)
        {
            request = null!;
            error = exception.Message;
            return false;
        }

        request = new ForwardedRequest(
            method,
            host,
            proto,
            normalized.Path,
            queryString,
            headers,
            query);
        error = "";
        return true;
    }

    private static string HeaderOrFallback(HttpContext context, string name, string fallback)
    {
        if (context.Request.Headers.TryGetValue(name, out var value) && value.Count > 0 && !string.IsNullOrEmpty(value[0]))
        {
            return value[0]!;
        }

        return fallback;
    }
}
