using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Policy;

namespace TraefikForwardAuth;

public sealed record TfaOptions
{
    /// <summary>
    /// Provider used to sign in to the admin UI: <see cref="ProviderDefinition.Oidc"/>,
    /// <see cref="ProviderDefinition.GitHub"/> or <see cref="ProviderDefinition.Google"/>.
    /// </summary>
    public required string AdminProvider { get; init; }

    /// <summary>Issuer URL when <see cref="AdminProvider"/> is <see cref="ProviderDefinition.Oidc"/>.</summary>
    public string? AdminIssuerUrl { get; init; }

    public required string AdminClientId { get; init; }

    public required string AdminClientSecret { get; init; }

    public required IReadOnlySet<string> AdminEmails { get; init; }

    public int Port { get; init; } = 4181;

    public int AdminPort { get; init; } = 4182;

    public string DataDir { get; init; } = "/data";

    public TfaLogLevel LogLevel { get; init; } = TfaLogLevel.Warn;

    public TfaLogFormat LogFormat { get; init; } = TfaLogFormat.Text;

    public static TfaOptions FromEnvironment()
    {
        var errors = new List<string>();
        var oidc = ParseGroup(errors, out var oidcConfigured, "ADMIN_OIDC_ISSUER_URL", "ADMIN_OIDC_CLIENT_ID", "ADMIN_OIDC_CLIENT_SECRET");
        var gitHub = ParseGroup(errors, out var gitHubConfigured, "ADMIN_GITHUB_CLIENT_ID", "ADMIN_GITHUB_CLIENT_SECRET");
        var google = ParseGroup(errors, out var googleConfigured, "ADMIN_GOOGLE_CLIENT_ID", "ADMIN_GOOGLE_CLIENT_SECRET");
        var adminEmails = Environment.GetEnvironmentVariable("ADMIN_EMAILS");

        if (!oidcConfigured && !gitHubConfigured && !googleConfigured)
        {
            errors.Add(
                "Admin login requires ADMIN_OIDC_ISSUER_URL, ADMIN_OIDC_CLIENT_ID and ADMIN_OIDC_CLIENT_SECRET, " +
                "or ADMIN_GITHUB_CLIENT_ID and ADMIN_GITHUB_CLIENT_SECRET, " +
                "or ADMIN_GOOGLE_CLIENT_ID and ADMIN_GOOGLE_CLIENT_SECRET");
        }

        if (oidc is not null && !IsAbsoluteHttpUrl(oidc[0]))
        {
            errors.Add("ADMIN_OIDC_ISSUER_URL must be an absolute http or https URL");
        }

        if (string.IsNullOrWhiteSpace(adminEmails)) errors.Add("ADMIN_EMAILS is required");

        var port = ParsePort("PORT", 4181, errors);
        var adminPort = ParsePort("ADMIN_PORT", 4182, errors);
        var dataDir = Environment.GetEnvironmentVariable("DATA_DIR");

        if (string.IsNullOrWhiteSpace(dataDir))
        {
            dataDir = "/data";
        }

        var logLevel = ParseLogLevel(Environment.GetEnvironmentVariable("LOG_LEVEL"), errors);
        var logFormat = ParseLogFormat(Environment.GetEnvironmentVariable("LOG_FORMAT"), errors);

        if (errors.Count > 0)
        {
            throw new TfaOptionsException(errors);
        }

        var emails = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var email in adminEmails!.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            emails.Add(email);
        }

        if (emails.Count == 0)
        {
            throw new TfaOptionsException(["ADMIN_EMAILS must contain at least one email address"]);
        }

        // Priority when several admin clients are configured: OIDC, then GitHub, then Google.
        var (adminProvider, issuerUrl, clientId, clientSecret) = (oidc, gitHub) switch
        {
            ({ } values, _) => (ProviderDefinition.Oidc, values[0], values[1], values[2]),
            (_, { } values) => (ProviderDefinition.GitHub, (string?)null, values[0], values[1]),
            _ => (ProviderDefinition.Google, (string?)null, google![0], google[1])
        };

        return new TfaOptions
        {
            AdminProvider = adminProvider,
            AdminIssuerUrl = issuerUrl,
            AdminClientId = clientId,
            AdminClientSecret = clientSecret,
            AdminEmails = emails,
            Port = port,
            AdminPort = adminPort,
            DataDir = dataDir,
            LogLevel = logLevel,
            LogFormat = logFormat
        };
    }

    /// <summary>
    /// Reads a group of variables that configure one admin login client. Returns the values when all
    /// are set and null otherwise; a partly set group is reported as an error so a typo never
    /// silently falls back to another provider.
    /// </summary>
    private static string[]? ParseGroup(List<string> errors, out bool configured, params string[] variables)
    {
        var values = new string[variables.Length];
        var missing = new List<string>();
        string? present = null;

        for (var index = 0; index < variables.Length; index++)
        {
            var value = Environment.GetEnvironmentVariable(variables[index]);

            if (string.IsNullOrWhiteSpace(value))
            {
                missing.Add(variables[index]);
                continue;
            }

            values[index] = value;
            present ??= variables[index];
        }

        configured = present is not null;

        if (!configured)
        {
            return null;
        }

        foreach (var variable in missing)
        {
            errors.Add($"{variable} is required when {present} is set");
        }

        return missing.Count == 0 ? values : null;
    }

    private static bool IsAbsoluteHttpUrl(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);

    private static int ParsePort(string variable, int fallback, List<string> errors)
    {
        var value = Environment.GetEnvironmentVariable(variable);

        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        if (!int.TryParse(value, out var port) || port is < 1 or > 65535)
        {
            errors.Add($"{variable} must be a port between 1 and 65535");
            return fallback;
        }

        return port;
    }

    private static TfaLogLevel ParseLogLevel(string? value, List<string> errors) => value?.Trim().ToLowerInvariant() switch
    {
        null or "" or "warn" => TfaLogLevel.Warn,
        "trace" => TfaLogLevel.Trace,
        "debug" => TfaLogLevel.Debug,
        "info" => TfaLogLevel.Info,
        "error" => TfaLogLevel.Error,
        "fatal" or "panic" => TfaLogLevel.Critical,
        _ => InvalidLevel(value, errors)
    };

    private static TfaLogLevel InvalidLevel(string value, List<string> errors)
    {
        errors.Add($"LOG_LEVEL must be one of trace, debug, info, warn, error, fatal, panic (got '{value}')");
        return TfaLogLevel.Warn;
    }

    private static TfaLogFormat ParseLogFormat(string? value, List<string> errors) => value?.Trim().ToLowerInvariant() switch
    {
        null or "" or "text" => TfaLogFormat.Text,
        "json" => TfaLogFormat.Json,
        "pretty" => TfaLogFormat.Pretty,
        _ => InvalidFormat(value, errors)
    };

    private static TfaLogFormat InvalidFormat(string value, List<string> errors)
    {
        errors.Add($"LOG_FORMAT must be one of text, json, pretty (got '{value}')");
        return TfaLogFormat.Text;
    }
}

public sealed class TfaOptionsException(IReadOnlyList<string> errors) : Exception(string.Join(Environment.NewLine, errors))
{
    public IReadOnlyList<string> Errors { get; } = errors;
}
