using TraefikForwardAuth.Logging;

namespace TraefikForwardAuth;

public sealed record TfaOptions
{
    public required string AdminGoogleClientId { get; init; }

    public required string AdminGoogleClientSecret { get; init; }

    public required IReadOnlySet<string> AdminEmails { get; init; }

    public int Port { get; init; } = 4181;

    public int AdminPort { get; init; } = 4182;

    public string DataDir { get; init; } = "/data";

    public TfaLogLevel LogLevel { get; init; } = TfaLogLevel.Warn;

    public TfaLogFormat LogFormat { get; init; } = TfaLogFormat.Text;

    public static TfaOptions FromEnvironment()
    {
        var errors = new List<string>();
        var clientId = Environment.GetEnvironmentVariable("ADMIN_GOOGLE_CLIENT_ID");
        var clientSecret = Environment.GetEnvironmentVariable("ADMIN_GOOGLE_CLIENT_SECRET");
        var adminEmails = Environment.GetEnvironmentVariable("ADMIN_EMAILS");

        if (string.IsNullOrWhiteSpace(clientId)) errors.Add("ADMIN_GOOGLE_CLIENT_ID is required");
        if (string.IsNullOrWhiteSpace(clientSecret)) errors.Add("ADMIN_GOOGLE_CLIENT_SECRET is required");
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

        return new TfaOptions
        {
            AdminGoogleClientId = clientId!,
            AdminGoogleClientSecret = clientSecret!,
            AdminEmails = emails,
            Port = port,
            AdminPort = adminPort,
            DataDir = dataDir,
            LogLevel = logLevel,
            LogFormat = logFormat
        };
    }

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
