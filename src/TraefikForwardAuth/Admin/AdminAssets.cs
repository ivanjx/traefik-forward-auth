namespace TraefikForwardAuth.Admin;

/// <summary>Loads the two embedded admin assets without touching the filesystem at runtime.</summary>
internal static class AdminAssets
{
    public const string CssPath = "/assets/site.css";
    public const string HtmxPath = "/assets/htmx.min.js";

    private static readonly Lazy<byte[]?> Css = new(() => Load(".site.css"));
    private static readonly Lazy<byte[]?> Htmx = new(() => Load(".htmx.min.js"));

    public static byte[]? Read(string path) => path switch
    {
        CssPath => Css.Value,
        HtmxPath => Htmx.Value,
        _ => null
    };

    public static string ContentType(string path) =>
        path == CssPath ? "text/css; charset=utf-8" : "text/javascript; charset=utf-8";

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
