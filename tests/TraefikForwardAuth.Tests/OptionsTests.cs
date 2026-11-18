using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Policy;

namespace TraefikForwardAuth.Tests;

[Collection("Environment")]
public sealed class OptionsTests
{
    private static readonly string[] Variables =
    [
        "ADMIN_OIDC_ISSUER_URL",
        "ADMIN_OIDC_CLIENT_ID",
        "ADMIN_OIDC_CLIENT_SECRET",
        "ADMIN_GITHUB_CLIENT_ID",
        "ADMIN_GITHUB_CLIENT_SECRET",
        "ADMIN_GOOGLE_CLIENT_ID",
        "ADMIN_GOOGLE_CLIENT_SECRET",
        "ADMIN_EMAILS",
        "PORT",
        "ADMIN_PORT",
        "DATA_DIR",
        "LOG_LEVEL",
        "LOG_FORMAT"
    ];

    [Fact]
    public void MissingRequiredVariablesThrows()
    {
        using var scope = new EnvironmentScope();
        scope.ClearAll();

        var exception = Assert.Throws<TfaOptionsException>(TfaOptions.FromEnvironment);

        Assert.Contains(
            exception.Errors,
            error => error.Contains("ADMIN_OIDC_ISSUER_URL") && error.Contains("ADMIN_GITHUB_CLIENT_ID") && error.Contains("ADMIN_GOOGLE_CLIENT_ID"));
        Assert.Contains(exception.Errors, error => error.Contains("ADMIN_EMAILS"));
    }

    [Fact]
    public void ParsesDefaultsAndAdminEmails()
    {
        using var scope = new EnvironmentScope();
        scope.ClearAll();
        scope.Set("ADMIN_GOOGLE_CLIENT_ID", "client");
        scope.Set("ADMIN_GOOGLE_CLIENT_SECRET", "secret");
        scope.Set("ADMIN_EMAILS", " Admin@Example.com , second@example.com ");

        var options = TfaOptions.FromEnvironment();

        Assert.Equal(ProviderDefinition.Google, options.AdminProvider);
        Assert.Equal("client", options.AdminClientId);
        Assert.Equal("secret", options.AdminClientSecret);
        Assert.Contains("admin@example.com", options.AdminEmails);
        Assert.Contains("SECOND@example.com", options.AdminEmails);
        Assert.Equal(4181, options.Port);
        Assert.Equal(4182, options.AdminPort);
        Assert.Equal("/data", options.DataDir);
        Assert.Equal(TfaLogLevel.Warn, options.LogLevel);
        Assert.Equal(TfaLogFormat.Text, options.LogFormat);
    }

    [Fact]
    public void GitHubAdminClientTakesPriorityOverGoogle()
    {
        using var scope = new EnvironmentScope();
        scope.ClearAll();
        scope.Set("ADMIN_GITHUB_CLIENT_ID", "github-client");
        scope.Set("ADMIN_GITHUB_CLIENT_SECRET", "github-secret");
        scope.Set("ADMIN_GOOGLE_CLIENT_ID", "google-client");
        scope.Set("ADMIN_GOOGLE_CLIENT_SECRET", "google-secret");
        scope.Set("ADMIN_EMAILS", "admin@example.com");

        var options = TfaOptions.FromEnvironment();

        Assert.Equal(ProviderDefinition.GitHub, options.AdminProvider);
        Assert.Equal("github-client", options.AdminClientId);
        Assert.Equal("github-secret", options.AdminClientSecret);
    }

    [Fact]
    public void OidcAdminClientTakesPriorityOverGitHubAndGoogle()
    {
        using var scope = new EnvironmentScope();
        scope.ClearAll();
        scope.Set("ADMIN_OIDC_ISSUER_URL", "https://idp.example.com/realms/main");
        scope.Set("ADMIN_OIDC_CLIENT_ID", "oidc-client");
        scope.Set("ADMIN_OIDC_CLIENT_SECRET", "oidc-secret");
        scope.Set("ADMIN_GITHUB_CLIENT_ID", "github-client");
        scope.Set("ADMIN_GITHUB_CLIENT_SECRET", "github-secret");
        scope.Set("ADMIN_GOOGLE_CLIENT_ID", "google-client");
        scope.Set("ADMIN_GOOGLE_CLIENT_SECRET", "google-secret");
        scope.Set("ADMIN_EMAILS", "admin@example.com");

        var options = TfaOptions.FromEnvironment();

        Assert.Equal(ProviderDefinition.Oidc, options.AdminProvider);
        Assert.Equal("https://idp.example.com/realms/main", options.AdminIssuerUrl);
        Assert.Equal("oidc-client", options.AdminClientId);
        Assert.Equal("oidc-secret", options.AdminClientSecret);
    }

    [Fact]
    public void IncompleteOidcAdminClientReportsEveryMissingVariable()
    {
        using var scope = new EnvironmentScope();
        scope.ClearAll();
        scope.Set("ADMIN_OIDC_ISSUER_URL", "https://idp.example.com");
        scope.Set("ADMIN_GOOGLE_CLIENT_ID", "google-client");
        scope.Set("ADMIN_GOOGLE_CLIENT_SECRET", "google-secret");
        scope.Set("ADMIN_EMAILS", "admin@example.com");

        var exception = Assert.Throws<TfaOptionsException>(TfaOptions.FromEnvironment);

        Assert.Contains(exception.Errors, error => error.StartsWith("ADMIN_OIDC_CLIENT_ID is required"));
        Assert.Contains(exception.Errors, error => error.StartsWith("ADMIN_OIDC_CLIENT_SECRET is required"));
    }

    [Fact]
    public void RelativeOidcIssuerUrlThrows()
    {
        using var scope = new EnvironmentScope();
        scope.ClearAll();
        scope.Set("ADMIN_OIDC_ISSUER_URL", "idp.example.com");
        scope.Set("ADMIN_OIDC_CLIENT_ID", "oidc-client");
        scope.Set("ADMIN_OIDC_CLIENT_SECRET", "oidc-secret");
        scope.Set("ADMIN_EMAILS", "admin@example.com");

        var exception = Assert.Throws<TfaOptionsException>(TfaOptions.FromEnvironment);

        Assert.Contains(exception.Errors, error => error.StartsWith("ADMIN_OIDC_ISSUER_URL must be"));
    }

    [Fact]
    public void IncompleteGitHubAdminClientThrowsEvenWithGoogleConfigured()
    {
        using var scope = new EnvironmentScope();
        scope.ClearAll();
        scope.Set("ADMIN_GITHUB_CLIENT_ID", "github-client");
        scope.Set("ADMIN_GOOGLE_CLIENT_ID", "google-client");
        scope.Set("ADMIN_GOOGLE_CLIENT_SECRET", "google-secret");
        scope.Set("ADMIN_EMAILS", "admin@example.com");

        var exception = Assert.Throws<TfaOptionsException>(TfaOptions.FromEnvironment);

        Assert.Contains(exception.Errors, error => error.StartsWith("ADMIN_GITHUB_CLIENT_SECRET is required"));
    }

    [Fact]
    public void ParsesDeploymentSettings()
    {
        using var scope = new EnvironmentScope();
        scope.Set("ADMIN_GOOGLE_CLIENT_ID", "client");
        scope.Set("ADMIN_GOOGLE_CLIENT_SECRET", "secret");
        scope.Set("ADMIN_EMAILS", "admin@example.com");
        scope.Set("PORT", "9001");
        scope.Set("ADMIN_PORT", "9002");
        scope.Set("DATA_DIR", "/tmp/tfa");
        scope.Set("LOG_LEVEL", "debug");
        scope.Set("LOG_FORMAT", "json");

        var options = TfaOptions.FromEnvironment();

        Assert.Equal(9001, options.Port);
        Assert.Equal(9002, options.AdminPort);
        Assert.Equal("/tmp/tfa", options.DataDir);
        Assert.Equal(TfaLogLevel.Debug, options.LogLevel);
        Assert.Equal(TfaLogFormat.Json, options.LogFormat);
    }

    [Theory]
    [InlineData("LOG_LEVEL", "verbose")]
    [InlineData("LOG_FORMAT", "xml")]
    [InlineData("PORT", "0")]
    [InlineData("ADMIN_PORT", "70000")]
    public void InvalidValuesAreReported(string variable, string value)
    {
        using var scope = new EnvironmentScope();
        scope.Set("ADMIN_GOOGLE_CLIENT_ID", "client");
        scope.Set("ADMIN_GOOGLE_CLIENT_SECRET", "secret");
        scope.Set("ADMIN_EMAILS", "admin@example.com");
        scope.Set(variable, value);

        var exception = Assert.Throws<TfaOptionsException>(TfaOptions.FromEnvironment);

        Assert.Contains(exception.Errors, error => error.Contains(variable));
    }

    [Fact]
    public void EmptyAdminEmailListThrows()
    {
        using var scope = new EnvironmentScope();
        scope.Set("ADMIN_GOOGLE_CLIENT_ID", "client");
        scope.Set("ADMIN_GOOGLE_CLIENT_SECRET", "secret");
        scope.Set("ADMIN_EMAILS", " , ");

        Assert.Throws<TfaOptionsException>(TfaOptions.FromEnvironment);
    }

    private sealed class EnvironmentScope : IDisposable
    {
        private readonly Dictionary<string, string?> _previous = new(StringComparer.Ordinal);

        public EnvironmentScope()
        {
            foreach (var variable in Variables)
            {
                _previous[variable] = Environment.GetEnvironmentVariable(variable);
            }
        }

        public void ClearAll()
        {
            foreach (var variable in Variables)
            {
                Environment.SetEnvironmentVariable(variable, null);
            }
        }

        public void Set(string variable, string? value) => Environment.SetEnvironmentVariable(variable, value);

        public void Dispose()
        {
            foreach (var (variable, value) in _previous)
            {
                Environment.SetEnvironmentVariable(variable, value);
            }
        }
    }
}

public sealed class LoggerTests
{
    [Fact]
    public void TextFormatQuotesAndSortsFields()
    {
        var output = new StringWriter();
        var logger = new TfaLogger(TfaLogLevel.Debug, TfaLogFormat.Text, output, new FixedTimeProvider());

        logger.Info("Hello world", ("z", 2), ("a", "value"));

        Assert.Equal(
            "time=\"2026-01-02T03:04:05Z\" level=info msg=\"Hello world\" a=value z=2" + Environment.NewLine,
            output.ToString());
    }

    [Fact]
    public void JsonFormatWritesFields()
    {
        var output = new StringWriter();
        var logger = new TfaLogger(TfaLogLevel.Debug, TfaLogFormat.Json, output, new FixedTimeProvider());

        logger.Warn("Careful", ("error", "boom"));

        Assert.Contains("\"level\":\"warning\"", output.ToString());
        Assert.Contains("\"msg\":\"Careful\"", output.ToString());
        Assert.Contains("\"error\":\"boom\"", output.ToString());
        Assert.Contains("\"time\":\"2026-01-02T03:04:05Z\"", output.ToString());
    }

    [Fact]
    public void MinimumLevelFilters()
    {
        var output = new StringWriter();
        var logger = new TfaLogger(TfaLogLevel.Warn, TfaLogFormat.Text, output, new FixedTimeProvider());

        logger.Info("hidden");
        logger.Error("shown");

        Assert.DoesNotContain("hidden", output.ToString());
        Assert.Contains("shown", output.ToString());
    }

    private sealed class FixedTimeProvider : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() =>
            new(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
    }
}
