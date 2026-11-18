using System;
using System.Collections.Generic;
using System.Linq;
using TraefikForwardAuth.Policy;
using TraefikForwardAuth.Providers;
using TraefikForwardAuth.Rules;

namespace TraefikForwardAuth.Tests;

public sealed class RulesTests
{
    [Theory]
    [InlineData("/", "/")]
    [InlineData("", "/")]
    [InlineData("/a", "/a")]
    [InlineData("/a/b", "/a/b")]
    [InlineData("/a//b", "/a/b")]
    [InlineData("/a//", "/a/")]
    [InlineData("/a//b//", "/a/b/")]
    [InlineData("/a/./b", "/a/b")]
    [InlineData("/a/./b/", "/a/b/")]
    [InlineData("/public/../admin", "/admin")]
    [InlineData("/public/..", "/")]
    [InlineData("/a/b/..", "/a/")]
    [InlineData("/a/b/../", "/a/")]
    [InlineData("/../../a", "/a")]
    [InlineData("/a/%2e%2e/b", "/b")]
    [InlineData("/%2e%2e", "/")]
    [InlineData("/a?b=1", "/a")]
    [InlineData("/a?x=%2F", "/a")]
    [InlineData("/a%252Fb", "/a%2Fb")]
    [InlineData("/a%25/b", "/a%/b")]
    [InlineData("/public/..;/admin", "/admin")]
    [InlineData("/public/..;jsessionid=x/admin", "/admin")]
    [InlineData("/public/%2e%2e%3b/admin", "/admin")]
    [InlineData("/a/.;x/b", "/a/b")]
    [InlineData("/a/b/..;", "/a/")]
    [InlineData("/a;x/b", "/a;x/b")]
    public void NormalizePath_ReturnsExpectedPath(string raw, string expected)
    {
        var result = PathNormalizer.Normalize(raw);

        Assert.True(result.Success, result.Error);
        Assert.Equal(expected, result.Path);
    }

    [Fact]
    public void NormalizePath_NullBecomesRoot()
    {
        var result = PathNormalizer.Normalize(null);

        Assert.True(result.Success);
        Assert.Equal("/", result.Path);
    }

    [Theory]
    [InlineData("relative/path", "must start with")]
    [InlineData("/a%2Fb", "encoded slash")]
    [InlineData("/a%2fb", "encoded slash")]
    [InlineData("/a%5Cb", "encoded slash")]
    [InlineData("/a%5cb", "encoded slash")]
    [InlineData("/a%zzb", "invalid percent")]
    [InlineData("/a%2", "invalid percent")]
    [InlineData("/a%", "invalid percent")]
    [InlineData("/a\nb", "control characters")]
    [InlineData("/a\tb", "control characters")]
    [InlineData("/a\0b", "control characters")]
    [InlineData("/a%0Ab", "control characters")]
    [InlineData("/a%00b", "control characters")]
    [InlineData("/a%7Fb", "control characters")]
    public void NormalizePath_RejectsInvalidPaths(string raw, string expectedError)
    {
        var result = PathNormalizer.Normalize(raw);

        Assert.False(result.Success);
        Assert.Contains(expectedError, result.Error);
    }

    [Theory]
    [InlineData("/users/*/avatar", "/users/1/avatar", true)]
    [InlineData("/users/*/avatar", "/users/a/b/avatar", false)]
    [InlineData("/users/*/avatar", "/users//avatar", true)]
    [InlineData("/static/**", "/static/", true)]
    [InlineData("/static/**", "/static", false)]
    [InlineData("/static/**", "/static/js/app.js", true)]
    [InlineData("/static/**", "/static/a/b/c", true)]
    [InlineData("/**", "/a/b", true)]
    [InlineData("/**", "/", true)]
    [InlineData("/api", "/api", true)]
    [InlineData("/api", "/api/", false)]
    [InlineData("/api*", "/apix", true)]
    [InlineData("/api*", "/api/x", false)]
    [InlineData("/a+b", "/a+b", true)]
    [InlineData("/a+b", "/aab", false)]
    [InlineData("/API", "/api", false)]
    [InlineData("*", "", true)]
    [InlineData("*", "a", true)]
    [InlineData("*", "a/b", false)]
    public void PathPattern_MatchesFullString(string pattern, string path, bool expected)
    {
        Assert.Equal(expected, PathPattern.IsMatch(pattern, path));
    }

    [Fact]
    public void ValidateRule_EmptyName_ReturnsError()
    {
        var rule = Rule("", HostIs("example.com"));

        var errors = ConditionCompiler.ValidateRule(rule);

        Assert.Contains(errors, error => error.Contains("name", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ValidateRule_NoConditions_ReturnsError()
    {
        var errors = ConditionCompiler.ValidateRule(Rule("empty"));

        Assert.Contains(errors, error => error.Contains("at least one condition", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ValidateRule_UnknownAction_ReturnsError()
    {
        var rule = Rule("bad action", HostIs("example.com")) with { Action = (RuleAction)99 };

        var errors = ConditionCompiler.ValidateRule(rule);

        Assert.Contains(errors, error => error.Contains("action", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ValidateRule_UnknownProvider_ReturnsError()
    {
        var rule = Rule("bad provider", HostIs("example.com")) with { Provider = "unknown-provider" };

        var errors = ConditionCompiler.ValidateRule(rule);

        Assert.Contains(errors, error => error.Contains("provider", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(ConditionField.Host, ConditionOperator.StartsWith)]
    [InlineData(ConditionField.Host, ConditionOperator.Contains)]
    [InlineData(ConditionField.Path, ConditionOperator.Exists)]
    [InlineData(ConditionField.Path, ConditionOperator.Contains)]
    [InlineData(ConditionField.Method, ConditionOperator.MatchesWildcard)]
    [InlineData(ConditionField.Header, ConditionOperator.StartsWith)]
    [InlineData(ConditionField.Header, ConditionOperator.MatchesWildcard)]
    [InlineData(ConditionField.Query, ConditionOperator.MatchesWildcard)]
    [InlineData(ConditionField.Query, ConditionOperator.Contains)]
    [InlineData(ConditionField.Query, ConditionOperator.MatchesRegex)]
    public void ValidateRule_UnsupportedOperator_ReturnsError(ConditionField field, ConditionOperator @operator)
    {
        var condition = new ConditionDefinition
        {
            Field = field,
            Operator = @operator,
            Name = field is ConditionField.Header or ConditionField.Query ? "X-Test" : null,
            Values = ["/x"]
        };

        var errors = ConditionCompiler.ValidateRule(Rule("unsupported", condition));

        Assert.Contains(errors, error => error.Contains("not supported", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(ConditionField.Header)]
    [InlineData(ConditionField.Query)]
    public void ValidateRule_MissingName_ReturnsError(ConditionField field)
    {
        var condition = new ConditionDefinition
        {
            Field = field,
            Operator = ConditionOperator.Exists,
            Values = []
        };

        var errors = ConditionCompiler.ValidateRule(Rule("missing name", condition));

        Assert.Contains(errors, error => error.Contains("name", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ValidateRule_EmptyValues_ReturnsError()
    {
        var condition = new ConditionDefinition
        {
            Field = ConditionField.Header,
            Operator = ConditionOperator.Is,
            Name = "X-Test",
            Values = []
        };

        var errors = ConditionCompiler.ValidateRule(Rule("empty values", condition));

        Assert.Contains(errors, error => error.Contains("value", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ValidateRule_PathValueWithoutLeadingSlash_ReturnsError()
    {
        var condition = new ConditionDefinition
        {
            Field = ConditionField.Path,
            Operator = ConditionOperator.StartsWith,
            Values = ["api"]
        };

        var errors = ConditionCompiler.ValidateRule(Rule("path value", condition));

        Assert.Contains(errors, error => error.Contains("start with '/'", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("(")]
    [InlineData("(a)\\1")]
    [InlineData("(?=a)")]
    public void ValidateRule_InvalidOrBacktrackingRegex_ReturnsError(string pattern)
    {
        var condition = new ConditionDefinition
        {
            Field = ConditionField.Header,
            Operator = ConditionOperator.MatchesRegex,
            Name = "X-Test",
            Values = [pattern]
        };

        var errors = ConditionCompiler.ValidateRule(Rule("bad regex", condition));

        Assert.NotEmpty(errors);
        Assert.False(ConditionCompiler.TryCompileRule(Rule("bad regex", condition), out var compiled, out var compileErrors));
        Assert.Null(compiled);
        Assert.NotEmpty(compileErrors);
    }

    [Fact]
    public void Compile_InvalidCondition_Throws()
    {
        var condition = new ConditionDefinition
        {
            Field = ConditionField.Header,
            Operator = ConditionOperator.Is,
            Name = null,
            Values = ["x"]
        };

        var exception = Assert.Throws<InvalidOperationException>(() => ConditionCompiler.Compile(condition));

        Assert.Contains("name is required", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryCompileRule_ValidRule_ProducesCompiledRuleAndSummary()
    {
        var rule = Rule(
            "API",
            HostWildcard("*.example.com"),
            PathStartsWith("/api"),
            MethodIs("get", "HEAD")) with { Action = RuleAction.Allow };

        var success = ConditionCompiler.TryCompileRule(rule, out var compiled, out var errors);

        Assert.True(success, string.Join("; ", errors));
        Assert.NotNull(compiled);
        Assert.Equal(3, compiled.Conditions.Count);
        Assert.Equal("Requests to `*.example.com` where path starts with `/api` and method is GET or HEAD → Allow without login", compiled.Summary);
    }

    [Theory]
    [InlineData("a.example.com", true)]
    [InlineData("a.b.example.com", true)]
    [InlineData("A.B.EXAMPLE.COM:8443", true)]
    [InlineData("example.com", false)]
    [InlineData("example.com:443", false)]
    [InlineData("badexample.com", false)]
    [InlineData("a.example.com.", true)]
    [InlineData("a.example.com.:443", true)]
    public void HostWildcard_MatchesAnyDepthButNotApex(string host, bool expected)
    {
        var compiled = Compile(Rule("wildcard", HostWildcard("*.example.com")));

        var result = Snapshot([compiled]).Match(Request(host: host));

        Assert.Equal(expected, !result.IsDefault);
    }

    [Fact]
    public void HostIs_IgnoresCaseAndPort()
    {
        var compiled = Compile(Rule("host", HostIs("Example.COM:8443")));

        var result = Snapshot([compiled]).Match(Request(host: "example.com:443"));

        Assert.False(result.IsDefault);
        Assert.Equal("host", result.RuleId);
    }

    [Theory]
    [InlineData("admin.example.com", "admin.example.com.")]
    [InlineData("admin.example.com.", "admin.example.com")]
    [InlineData("admin.example.com", "ADMIN.example.com.:8443")]
    public void HostIs_IgnoresTrailingDot(string ruleHost, string requestHost)
    {
        var compiled = Compile(Rule("host", HostIs(ruleHost)));

        var result = Snapshot([compiled]).Match(Request(host: requestHost));

        Assert.False(result.IsDefault);
    }

    [Fact]
    public void ConditionValues_AreAlternatives()
    {
        var compiled = Compile(Rule("alternatives", HostIs("a.example.com", "b.example.com")));

        Assert.False(Snapshot([compiled]).Match(Request(host: "b.example.com")).IsDefault);
        Assert.True(Snapshot([compiled]).Match(Request(host: "c.example.com")).IsDefault);
    }

    [Fact]
    public void NegatedCondition_IsNotOfAnyMatch()
    {
        var rule = Rule("negated", HostIs("a.example.com", "b.example.com") with { Negated = true });
        var compiled = Compile(rule);

        Assert.False(Snapshot([compiled]).Match(Request(host: "c.example.com")).IsDefault);
        Assert.True(Snapshot([compiled]).Match(Request(host: "a.example.com")).IsDefault);
    }

    [Fact]
    public void Method_IsCaseInsensitive()
    {
        var compiled = Compile(Rule("method", MethodIs("get", "Head")));

        Assert.False(Snapshot([compiled]).Match(Request(method: "GET")).IsDefault);
        Assert.False(Snapshot([compiled]).Match(Request(method: "head")).IsDefault);
        Assert.True(Snapshot([compiled]).Match(Request(method: "POST")).IsDefault);
    }

    [Theory]
    [InlineData(ConditionOperator.Is, "/api", "/api", true)]
    [InlineData(ConditionOperator.Is, "/api", "/api/x", false)]
    [InlineData(ConditionOperator.StartsWith, "/api", "/api/x", true)]
    [InlineData(ConditionOperator.StartsWith, "/api", "/other", false)]
    [InlineData(ConditionOperator.StartsWith, "/API", "/api/x", false)]
    [InlineData(ConditionOperator.MatchesPattern, "/users/*/avatar", "/users/1/avatar", true)]
    [InlineData(ConditionOperator.MatchesPattern, "/users/*/avatar", "/users/1/2/avatar", false)]
    [InlineData(ConditionOperator.MatchesPattern, "/static/**", "/static/js/app.js", true)]
    public void PathOperators_MatchAsExpected(ConditionOperator @operator, string value, string path, bool expected)
    {
        var condition = new ConditionDefinition
        {
            Field = ConditionField.Path,
            Operator = @operator,
            Values = [value]
        };

        var compiled = Compile(Rule("path", condition));

        Assert.Equal(expected, !Snapshot([compiled]).Match(Request(path: path)).IsDefault);
    }

    [Fact]
    public void HeaderName_IsCaseInsensitive()
    {
        var condition = new ConditionDefinition
        {
            Field = ConditionField.Header,
            Operator = ConditionOperator.Exists,
            Name = "X-Api-Client",
            Values = []
        };

        var compiled = Compile(Rule("header", condition));
        var result = Snapshot([compiled]).Match(Request(headers: new Dictionary<string, string[]> { ["x-api-client"] = [""] }));

        Assert.False(result.IsDefault);
    }

    [Fact]
    public void HeaderExists_MatchesEmptyValue()
    {
        var condition = new ConditionDefinition
        {
            Field = ConditionField.Header,
            Operator = ConditionOperator.Exists,
            Name = "X-Empty",
            Values = []
        };

        var compiled = Compile(Rule("header", condition));

        Assert.False(Snapshot([compiled]).Match(Request(headers: new Dictionary<string, string[]> { ["X-Empty"] = [""] })).IsDefault);
        Assert.True(Snapshot([compiled]).Match(Request()).IsDefault);
    }

    [Theory]
    [InlineData(ConditionOperator.Is, "Token", "Token", true)]
    [InlineData(ConditionOperator.Is, "Token", "token", false)]
    [InlineData(ConditionOperator.Is, "a", "b", false)]
    [InlineData(ConditionOperator.Contains, "foo", "xxfooyy", true)]
    [InlineData(ConditionOperator.Contains, "FOO", "xxfooyy", false)]
    public void HeaderValues_AreCaseSensitive(ConditionOperator @operator, string configured, string actual, bool expected)
    {
        var condition = new ConditionDefinition
        {
            Field = ConditionField.Header,
            Operator = @operator,
            Name = "X-Test",
            Values = [configured]
        };

        var compiled = Compile(Rule("header", condition));
        var result = Snapshot([compiled]).Match(Request(headers: new Dictionary<string, string[]> { ["X-Test"] = [actual] }));

        Assert.Equal(expected, !result.IsDefault);
    }

    [Fact]
    public void HeaderMultipleValues_AreAlternatives()
    {
        var condition = new ConditionDefinition
        {
            Field = ConditionField.Header,
            Operator = ConditionOperator.Is,
            Name = "X-Test",
            Values = ["a", "b"]
        };

        var compiled = Compile(Rule("header", condition));

        Assert.False(Snapshot([compiled]).Match(Request(headers: new Dictionary<string, string[]> { ["X-Test"] = ["b"] })).IsDefault);
    }

    [Fact]
    public void HeaderRegex_MatchesAnyActualValue()
    {
        var condition = new ConditionDefinition
        {
            Field = ConditionField.Header,
            Operator = ConditionOperator.MatchesRegex,
            Name = "X-Request-Id",
            Values = ["^req-\\d+$"]
        };

        var compiled = Compile(Rule("header", condition));

        Assert.False(Snapshot([compiled]).Match(Request(headers: new Dictionary<string, string[]> { ["X-Request-Id"] = ["req-12"] })).IsDefault);
        Assert.True(Snapshot([compiled]).Match(Request(headers: new Dictionary<string, string[]> { ["X-Request-Id"] = ["REQ-12"] })).IsDefault);
    }

    [Fact]
    public void NegatedHeaderCondition_IsNotOfWholeCondition()
    {
        var condition = new ConditionDefinition
        {
            Field = ConditionField.Header,
            Operator = ConditionOperator.Is,
            Name = "X-Blocked",
            Values = ["yes"],
            Negated = true
        };

        var compiled = Compile(Rule("header", condition));

        Assert.False(Snapshot([compiled]).Match(Request(headers: new Dictionary<string, string[]> { ["X-Blocked"] = ["no"] })).IsDefault);
        Assert.False(Snapshot([compiled]).Match(Request()).IsDefault);
        Assert.True(Snapshot([compiled]).Match(Request(headers: new Dictionary<string, string[]> { ["X-Blocked"] = ["yes"] })).IsDefault);
    }

    [Fact]
    public void QueryName_IsCaseSensitive()
    {
        var condition = new ConditionDefinition
        {
            Field = ConditionField.Query,
            Operator = ConditionOperator.Exists,
            Name = "token",
            Values = []
        };

        var compiled = Compile(Rule("query", condition));

        Assert.False(Snapshot([compiled]).Match(Request(query: new Dictionary<string, string[]> { ["token"] = [""] })).IsDefault);
        Assert.True(Snapshot([compiled]).Match(Request(query: new Dictionary<string, string[]> { ["Token"] = [""] })).IsDefault);
    }

    [Fact]
    public void QueryValues_AreCaseSensitive()
    {
        var condition = new ConditionDefinition
        {
            Field = ConditionField.Query,
            Operator = ConditionOperator.Is,
            Name = "token",
            Values = ["abc"]
        };

        var compiled = Compile(Rule("query", condition));

        Assert.False(Snapshot([compiled]).Match(Request(query: new Dictionary<string, string[]> { ["token"] = ["abc"] })).IsDefault);
        Assert.True(Snapshot([compiled]).Match(Request(query: new Dictionary<string, string[]> { ["token"] = ["ABC"] })).IsDefault);
    }

    [Fact]
    public void AllConditionsMustMatch()
    {
        var compiled = Compile(Rule(
            "all",
            HostIs("example.com"),
            PathStartsWith("/api"),
            MethodIs("GET")));

        Assert.False(Snapshot([compiled]).Match(Request(host: "example.com", path: "/api/x", method: "GET")).IsDefault);
        Assert.True(Snapshot([compiled]).Match(Request(host: "example.com", path: "/other", method: "GET")).IsDefault);
        Assert.True(Snapshot([compiled]).Match(Request(host: "example.com", path: "/api/x", method: "POST")).IsDefault);
    }

    [Fact]
    public void FirstMatchingEnabledRuleWins()
    {
        var first = Compile(Rule("first", HostIs("example.com")) with { Action = RuleAction.Allow });
        var second = Compile(Rule("second", HostIs("example.com")) with { Action = RuleAction.Auth });

        var result = Snapshot([first, second]).Match(Request(host: "example.com"));

        Assert.False(result.IsDefault);
        Assert.Equal("first", result.RuleId);
        Assert.Equal(RuleAction.Allow, result.Action);
    }

    [Fact]
    public void DisabledRulesAreSkipped()
    {
        var disabled = Compile(Rule("disabled", HostIs("example.com")) with { Enabled = false, Action = RuleAction.Allow });
        var enabled = Compile(Rule("enabled", HostIs("example.com")) with { Action = RuleAction.Auth });

        var result = Snapshot([disabled, enabled]).Match(Request(host: "example.com"));

        Assert.Equal("enabled", result.RuleId);
    }

    [Fact]
    public void NoMatch_ReturnsDefaultActionAndProvider()
    {
        var compiled = Compile(Rule("other", HostIs("other.example.com")));
        var snapshot = Snapshot([compiled], RuleAction.Allow, "oidc");

        var result = snapshot.Match(Request(host: "example.com"));

        Assert.True(result.IsDefault);
        Assert.Null(result.Rule);
        Assert.Null(result.RuleId);
        Assert.Equal(RuleAction.Allow, result.Action);
        Assert.Equal("oidc", result.ProviderName);
    }

    [Fact]
    public void RuleProviderNull_UsesDefaultAndOverrideWins()
    {
        var defaultProvider = Compile(Rule("default", HostIs("a.example.com")) with { Provider = null });
        var overrideProvider = Compile(Rule("override", HostIs("b.example.com")) with { Provider = "generic-oauth" });
        var snapshot = Snapshot([defaultProvider, overrideProvider], defaultProvider: "oidc");

        Assert.Equal("oidc", snapshot.Match(Request(host: "a.example.com")).ProviderName);
        Assert.Equal("generic-oauth", snapshot.Match(Request(host: "b.example.com")).ProviderName);
    }

    [Fact]
    public void Simulate_StopsAtFirstMatchAndIncludesDisabledRules()
    {
        var disabled = Compile(Rule("disabled", HostIs("example.com")) with { Enabled = false });
        var selected = Compile(Rule("selected", HostIs("example.com")) with { Action = RuleAction.Allow });
        var later = Compile(Rule("later", HostIs("example.com")) with { Action = RuleAction.Auth });

        var simulation = Snapshot([disabled, selected, later]).Simulate(Request(host: "example.com"));

        Assert.Equal(2, simulation.Rules.Count);
        Assert.Equal("disabled", simulation.Rules[0].Rule.Definition.Id);
        Assert.False(simulation.Rules[0].Matched);
        Assert.NotEmpty(simulation.Rules[0].Conditions);
        Assert.Equal("selected", simulation.Rules[1].Rule.Definition.Id);
        Assert.True(simulation.Rules[1].Matched);
        Assert.Equal("selected", simulation.Result.RuleId);
        Assert.Equal(RuleAction.Allow, simulation.Result.Action);
    }

    [Fact]
    public void Simulate_NoMatch_IncludesAllRulesAndDefaultResult()
    {
        var first = Compile(Rule("first", HostIs("other.example.com")));
        var second = Compile(Rule("second", PathStartsWith("/api")));
        var snapshot = Snapshot([first, second], RuleAction.Allow);

        var simulation = snapshot.Simulate(Request(host: "example.com", path: "/other"));

        Assert.Equal(2, simulation.Rules.Count);
        Assert.True(simulation.Result.IsDefault);
        Assert.Equal(RuleAction.Allow, simulation.Result.Action);
    }

    [Fact]
    public void Simulate_ExposesPassingAndFailingConditions()
    {
        var rule = Rule("two", HostIs("example.com"), MethodIs("POST"));
        var simulation = Snapshot([Compile(rule)]).Simulate(Request(host: "example.com", method: "GET"));

        Assert.Single(simulation.Rules);
        Assert.False(simulation.Rules[0].Matched);
        Assert.Equal(2, simulation.Rules[0].Conditions.Count);
        Assert.True(simulation.Rules[0].Conditions[0].Matched);
        Assert.False(simulation.Rules[0].Conditions[1].Matched);
    }

    [Theory]
    [InlineData(ConditionOperator.StartsWith, "does not start with")]
    [InlineData(ConditionOperator.Is, "is not")]
    public void Describe_NegatedCondition_UsesNegativeWording(ConditionOperator @operator, string expectedText)
    {
        var condition = new ConditionDefinition
        {
            Field = ConditionField.Path,
            Operator = @operator,
            Values = ["/public"],
            Negated = true
        };

        var summary = RuleDescriber.Describe(Rule("negated", condition));

        Assert.True(summary.Contains(expectedText, StringComparison.Ordinal), summary);
    }

    [Fact]
    public void Describe_HeaderExists()
    {
        var condition = new ConditionDefinition
        {
            Field = ConditionField.Header,
            Operator = ConditionOperator.Exists,
            Name = "X-Api-Client",
            Values = []
        };

        var summary = RuleDescriber.Describe(Rule("header", condition) with { Action = RuleAction.Allow });

        Assert.Equal("Requests where header `X-Api-Client` exists → Allow without login", summary);
    }

    [Fact]
    public void Describe_QueryAlternatives()
    {
        var condition = new ConditionDefinition
        {
            Field = ConditionField.Query,
            Operator = ConditionOperator.Is,
            Name = "token",
            Values = ["a", "b"]
        };

        var summary = RuleDescriber.Describe(Rule("query", condition));

        Assert.Equal("Requests where query `token` is `a` or `b` → Require login", summary);
    }

    [Fact]
    public void Describe_HostIsAndRegex()
    {
        var rule = Rule(
            "mixed",
            HostIs("app.example.com"),
            new ConditionDefinition
            {
                Field = ConditionField.Header,
                Operator = ConditionOperator.MatchesRegex,
                Name = "X-Request-Id",
                Values = ["^req-"]
            });

        var summary = RuleDescriber.Describe(rule);

        Assert.Equal("Requests to `app.example.com` where header `X-Request-Id` matches regex `^req-` → Require login", summary);
    }

    private static RuleDefinition Rule(string name, params ConditionDefinition[] conditions) => new()
    {
        Id = name,
        Name = name,
        Action = RuleAction.Auth,
        Conditions = conditions
    };

    private static ConditionDefinition HostIs(params string[] values) => new()
    {
        Field = ConditionField.Host,
        Operator = ConditionOperator.Is,
        Values = values
    };

    private static ConditionDefinition HostWildcard(params string[] values) => new()
    {
        Field = ConditionField.Host,
        Operator = ConditionOperator.MatchesWildcard,
        Values = values
    };

    private static ConditionDefinition PathStartsWith(params string[] values) => new()
    {
        Field = ConditionField.Path,
        Operator = ConditionOperator.StartsWith,
        Values = values
    };

    private static ConditionDefinition MethodIs(params string[] values) => new()
    {
        Field = ConditionField.Method,
        Operator = ConditionOperator.Is,
        Values = values
    };

    private static CompiledRule Compile(RuleDefinition rule)
    {
        Assert.True(ConditionCompiler.TryCompileRule(rule, out var compiled, out var errors), string.Join("; ", errors));
        return compiled!;
    }

    private static PolicySnapshot Snapshot(
        IReadOnlyList<CompiledRule> rules,
        RuleAction defaultAction = RuleAction.Auth,
        string defaultProvider = PolicySettings.DefaultProviderName) => new()
    {
        Settings = new PolicySettings
        {
            DefaultAction = defaultAction,
            DefaultProvider = defaultProvider
        },
        Rules = rules,
        Providers = new Dictionary<string, IProvider>(StringComparer.Ordinal),
        Access = AccessIndex.Build([])
    };

    private static RequestDescriptor Request(
        string method = "GET",
        string host = "example.com",
        string path = "/",
        IReadOnlyDictionary<string, string[]>? headers = null,
        IReadOnlyDictionary<string, string[]>? query = null) =>
        new(method, host, path, headers, query);
}
