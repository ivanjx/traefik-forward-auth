using System.Security.Cryptography;

namespace TraefikForwardAuth.Admin;

/// <summary>Loads the two embedded admin assets without touching the filesystem at runtime.</summary>
internal static class AdminAssets
{
    public const string CssPath = "/assets/site.css";
    public const string HtmxPath = "/assets/htmx.min.js";

    private static readonly Lazy<byte[]?> Css = new(() => Load(".site.css"));
    private static readonly Lazy<byte[]?> Htmx = new(() => Load(".htmx.min.js"));

    private static readonly Lazy<string> CssVersioned = new(() => Versioned(CssPath, Css.Value));
    private static readonly Lazy<string> HtmxVersioned = new(() => Versioned(HtmxPath, Htmx.Value));

    /// <summary>Asset URLs with a content hash, so browsers refetch after an upgrade instead of using a cached copy.</summary>
    public static string CssUrl => CssVersioned.Value;

    public static string HtmxUrl => HtmxVersioned.Value;

    public static byte[]? Read(string path) => path switch
    {
        CssPath => Css.Value,
        HtmxPath => Htmx.Value,
        _ => null
    };

    public static string ContentType(string path) =>
        path == CssPath ? "text/css; charset=utf-8" : "text/javascript; charset=utf-8";

    private static string Versioned(string path, byte[]? bytes)
    {
        if (bytes is null)
        {
            return path;
        }

        var hash = Convert.ToHexStringLower(SHA256.HashData(bytes).AsSpan(0, 6));

        return $"{path}?v={hash}";
    }

    private static byte[]? Load(string suffix)
    {
        var assembly = typeof(AdminAssets).Assembly;

        foreach (var name in assembly.GetManifestResourceNames())
        {
            if (!name.EndsWith(suffix, StringComparison.Ordinal))
            {
                continue;
            }

            using var stream = assembly.GetManifestResourceStream(name);

            if (stream is null)
            {
                continue;
            }

            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);

            return buffer.ToArray();
        }

        return null;
    }
}
