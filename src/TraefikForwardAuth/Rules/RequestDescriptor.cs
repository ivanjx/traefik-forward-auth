namespace TraefikForwardAuth.Rules;

/// <summary>Request data used for rule matching. Header names are case-insensitive; everything else is compared as supplied.</summary>
public sealed class RequestDescriptor
{
    private readonly Dictionary<string, string[]> _headers;

    public RequestDescriptor(
        string method,
        string host,
        string path,
        IReadOnlyDictionary<string, string[]>? headers = null,
        IReadOnlyDictionary<string, string[]>? query = null)
    {
        Method = method;
        Host = host;
        Path = path;
        _headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

        if (headers is not null)
        {
            foreach (var (name, values) in headers)
            {
                _headers[name] = values;
            }
        }

        Query = new Dictionary<string, string[]>(query ?? new Dictionary<string, string[]>(), StringComparer.Ordinal);
    }

    public string Method { get; }

    public string Host { get; }

    public string HostWithoutPort => HostNormalizer.StripPort(Host);

    public string Path { get; }

    public IReadOnlyDictionary<string, string[]> Headers => _headers;

    public IReadOnlyDictionary<string, string[]> Query { get; }

    public IReadOnlyList<string> GetHeader(string name) =>
        _headers.TryGetValue(name, out var values) ? values : [];

    public IReadOnlyList<string> GetQuery(string name) =>
        Query.TryGetValue(name, out var values) ? values : [];
}

public static class HostNormalizer
{
    public static string StripPort(string host)
    {
        if (string.IsNullOrEmpty(host))
        {
            return "";
        }

        if (host[0] == '[')
        {
            var close = host.IndexOf(']');
            return close > 0 ? host[..(close + 1)] : host;
        }

        var colon = host.LastIndexOf(':');

        // A single colon after the first character is a port separator. Anything else is not a
        // host:port pair (for example an unbracketed IPv6 address), so leave it untouched.
        if (colon > 0 && host.IndexOf(':') == colon)
        {
            return host[..colon];
        }

        return host;
    }

    public static string NormalizeForMatch(string host) => StripPort(host).ToLowerInvariant();
}
