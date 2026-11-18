using System.Text;

namespace TraefikForwardAuth.Providers;

internal static class ProviderUrls
{
    /// <summary>Builds an absolute URL by appending percent-encoded query parameters to the endpoint.</summary>
    public static string WithQuery(Uri endpoint, params (string Key, string? Value)[] parameters)
    {
        var builder = new StringBuilder(endpoint.GetLeftPart(UriPartial.Path));
        var separator = '?';

        foreach (var (key, value) in parameters)
        {
            if (value is null)
            {
                continue;
            }

            builder.Append(separator)
                .Append(Uri.EscapeDataString(key))
                .Append('=')
                .Append(Uri.EscapeDataString(value));

            separator = '&';
        }

        return builder.ToString();
    }

    /// <summary>Collapses a response body into a short single-line snippet for error messages.</summary>
    public static string Snippet(string? body, int maximumLength = 200)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return "<empty>";
        }

        var collapsed = string.Join(' ', body.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

        return collapsed.Length <= maximumLength ? collapsed : collapsed[..maximumLength] + "…";
    }
}
