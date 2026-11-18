using TraefikForwardAuth.Logging;

namespace TraefikForwardAuth.Tests;

[Collection("Environment")]
public sealed class OptionsTests
{
    private static readonly string[] Variables =
    [
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

        Assert.Contains(exception.Errors, error => error.Contains("ADMIN_GOOGLE_CLIENT_ID"));
        Assert.Contains(exception.Errors, error => error.Contains("ADMIN_GOOGLE_CLIENT_SECRET"));
        Assert.Contains(exception.Errors, error => error.Contains("ADMIN_EMAILS"));
    }

    [Fact]
    public void ParsesDefaultsAndAdminEmails()
    {
        using var scope = new EnvironmentScope();
        scope.Set("ADMIN_GOOGLE_CLIENT_ID", "client");
        scope.Set("ADMIN_GOOGLE_CLIENT_SECRET", "secret");
        scope.Set("ADMIN_EMAILS", " Admin@Example.com , second@example.com ");

        var options = TfaOptions.FromEnvironment();

        Assert.Equal("client", options.AdminGoogleClientId);
        Assert.Equal("secret", options.AdminGoogleClientSecret);
        Assert.Contains("admin@example.com", options.AdminEmails);
        Assert.Contains("SECOND@example.com", options.AdminEmails);
        Assert.Equal(4181, options.Port);
        Assert.Equal(4182, options.AdminPort);
        Assert.Equal("/data", options.DataDir);
        Assert.Equal(TfaLogLevel.Warn, options.LogLevel);
        Assert.Equal(TfaLogFormat.Text, options.LogFormat);
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
