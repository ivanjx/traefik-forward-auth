using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using TraefikForwardAuth.Policy;

namespace TraefikForwardAuth.Rules;

public static class ConditionCompiler
{
    private static readonly string[] KnownProviders =
        [ProviderDefinition.Google, ProviderDefinition.GitHub, ProviderDefinition.Oidc, ProviderDefinition.GenericOAuth];

    private static readonly RegexOptions RegexFlags = RegexOptions.NonBacktracking | RegexOptions.CultureInvariant;

    public static IReadOnlyList<string> ValidateRule(RuleDefinition rule)
    {
        var errors = new List<string>();

        if (rule is null)
        {
            errors.Add("Rule is required.");
            return errors;
        }

        if (string.IsNullOrWhiteSpace(rule.Name))
        {
            errors.Add("Rule name is required.");
        }

        if (!Enum.IsDefined(rule.Action))
        {
            errors.Add($"Unknown rule action: {(int)rule.Action}.");
        }

        if (rule.Provider is not null && !KnownProviders.Contains(rule.Provider, StringComparer.Ordinal))
        {
            errors.Add($"Unknown provider: {rule.Provider}.");
        }

        if (rule.Conditions is null || rule.Conditions.Count == 0)
        {
            errors.Add("A rule must have at least one condition.");
            return errors;
        }

        for (var i = 0; i < rule.Conditions.Count; i++)
        {
            var condition = rule.Conditions[i];

            if (condition is null)
            {
                errors.Add($"Condition {i + 1}: condition is required.");
                continue;
            }

            errors.AddRange(ValidateCondition(condition, i + 1));
        }

        return errors;
    }

    public static bool TryCompileRule(
        RuleDefinition rule,
        out CompiledRule? compiled,
        out IReadOnlyList<string> errors)
    {
        errors = ValidateRule(rule);

        if (errors.Count > 0)
        {
            compiled = null;
            return false;
        }

        var conditions = new CompiledCondition[rule.Conditions.Count];

        for (var i = 0; i < conditions.Length; i++)
        {
            conditions[i] = Compile(rule.Conditions[i]);
        }

        compiled = new CompiledRule
        {
            Definition = rule,
            Conditions = conditions,
            Summary = RuleDescriber.Describe(rule)
        };

        return true;
    }

    public static CompiledCondition Compile(ConditionDefinition condition)
    {
        if (condition is null)
        {
            throw new InvalidOperationException("Condition is required.");
        }

        var errors = ValidateCondition(condition, 0);

        if (errors.Count > 0)
        {
            throw new InvalidOperationException(string.Join(" ", errors));
        }

        return Create(condition);
    }

    private static IReadOnlyList<string> ValidateCondition(ConditionDefinition condition, int number)
    {
        var errors = new List<string>();
        var prefix = number > 0 ? $"Condition {number}: " : "";

        if (!Enum.IsDefined(condition.Field))
        {
            errors.Add(prefix + $"Unknown condition field: {(int)condition.Field}.");
            return errors;
        }

        if (!Enum.IsDefined(condition.Operator))
        {
            errors.Add(prefix + $"Unknown condition operator: {(int)condition.Operator}.");
            return errors;
        }

        if (!IsOperatorAllowed(condition.Field, condition.Operator))
        {
            errors.Add(prefix + $"Operator '{OperatorLabel(condition.Operator)}' is not supported for {FieldLabel(condition.Field)} conditions.");
            return errors;
        }

        if (condition.Field is ConditionField.Header or ConditionField.Query && string.IsNullOrWhiteSpace(condition.Name))
        {
            errors.Add(prefix + $"{FieldLabel(condition.Field)} name is required.");
        }

        if (condition.Operator == ConditionOperator.Exists)
        {
            return errors;
        }

        if (condition.Values is null || condition.Values.Count == 0)
        {
            errors.Add(prefix + "At least one value is required.");
            return errors;
        }

        for (var i = 0; i < condition.Values.Count; i++)
        {
            var value = condition.Values[i];

            if (string.IsNullOrEmpty(value))
            {
                errors.Add(prefix + "Values cannot be empty.");
                continue;
            }

            if (condition.Field == ConditionField.Path && !value.StartsWith('/'))
            {
                errors.Add(prefix + $"Path value '{value}' must start with '/'.");
            }

            if (condition.Operator == ConditionOperator.MatchesRegex)
            {
                try
                {
                    _ = new Regex(value, RegexFlags);
                }
                catch (ArgumentException exception)
                {
                    errors.Add(prefix + $"Invalid regular expression '{value}': {exception.Message}");
                }
                catch (NotSupportedException exception)
                {
                    errors.Add(prefix + $"Invalid regular expression '{value}': {exception.Message}");
                }
            }
        }

        return errors;
    }

    private static bool IsOperatorAllowed(ConditionField field, ConditionOperator @operator) => field switch
    {
        ConditionField.Host => @operator is ConditionOperator.Is or ConditionOperator.MatchesWildcard,
        ConditionField.Path => @operator is ConditionOperator.Is or ConditionOperator.StartsWith or ConditionOperator.MatchesPattern,
        ConditionField.Method => @operator is ConditionOperator.Is,
        ConditionField.Header => @operator is ConditionOperator.Is or ConditionOperator.Contains or ConditionOperator.Exists or ConditionOperator.MatchesRegex,
        ConditionField.Query => @operator is ConditionOperator.Is or ConditionOperator.Exists,
        _ => false
    };

    private static CompiledCondition Create(ConditionDefinition condition) => condition.Field switch
    {
        ConditionField.Host => new HostCondition(condition),
        ConditionField.Path => new PathCondition(condition),
        ConditionField.Method => new MethodCondition(condition),
        ConditionField.Header => new HeaderCondition(condition),
        ConditionField.Query => new QueryCondition(condition),
        _ => throw new InvalidOperationException($"Unknown condition field: {condition.Field}.")
    };

    internal static string FieldLabel(ConditionField field) => field switch
    {
        ConditionField.Host => "Host",
        ConditionField.Path => "Path",
        ConditionField.Method => "Method",
        ConditionField.Header => "Header",
        ConditionField.Query => "Query",
        _ => "unknown"
    };

    internal static string OperatorLabel(ConditionOperator @operator) => @operator switch
    {
        ConditionOperator.Is => "is",
        ConditionOperator.MatchesWildcard => "matches wildcard",
        ConditionOperator.StartsWith => "starts with",
        ConditionOperator.MatchesPattern => "matches pattern",
        ConditionOperator.Contains => "contains",
        ConditionOperator.Exists => "exists",
        ConditionOperator.MatchesRegex => "matches regex",
        _ => "unknown"
    };

    internal static Regex CompileRegex(string pattern) => new(pattern, RegexFlags);
}

internal abstract class ConditionBase : CompiledCondition
{
    protected ConditionBase(ConditionDefinition definition)
        : base(definition)
    {
    }

    protected ConditionOperator Operator => Definition.Operator;

    protected IReadOnlyList<string> Values => Definition.Values;

    protected bool Apply(bool matched) => Definition.Negated ? !matched : matched;

    public override string Describe() => RuleDescriber.DescribeCondition(Definition);
}

internal sealed class HostCondition : ConditionBase
{
    public HostCondition(ConditionDefinition definition)
        : base(definition)
    {
    }

    public override bool IsMatch(RequestDescriptor request)
    {
        var host = HostNormalizer.NormalizeForMatch(request.Host);
        var matched = false;

        foreach (var value in Values)
        {
            var expected = HostNormalizer.NormalizeForMatch(value);

            if (Operator == ConditionOperator.Is)
            {
                if (string.Equals(host, expected, StringComparison.Ordinal))
                {
                    matched = true;
                    break;
                }
            }
            else if (HostWildcardMatcher.IsMatch(expected, host))
            {
                matched = true;
                break;
            }
        }

        return Apply(matched);
    }
}

internal sealed class PathCondition : ConditionBase
{
    public PathCondition(ConditionDefinition definition)
        : base(definition)
    {
    }

    public override bool IsMatch(RequestDescriptor request)
    {
        var path = request.Path;
        var matched = false;

        foreach (var value in Values)
        {
            var candidate = Operator switch
            {
                ConditionOperator.Is => string.Equals(path, value, StringComparison.Ordinal),
                ConditionOperator.StartsWith => path.StartsWith(value, StringComparison.Ordinal),
                ConditionOperator.MatchesPattern => PathPattern.IsMatch(value, path),
                _ => false
            };

            if (candidate)
            {
                matched = true;
                break;
            }
        }

        return Apply(matched);
    }
}

internal sealed class MethodCondition : ConditionBase
{
    public MethodCondition(ConditionDefinition definition)
        : base(definition)
    {
    }

    public override bool IsMatch(RequestDescriptor request)
    {
        var matched = Values.Any(value => string.Equals(request.Method, value, StringComparison.OrdinalIgnoreCase));

        return Apply(matched);
    }
}

internal sealed class HeaderCondition : ConditionBase
{
    private readonly string _name;
    private readonly Regex[] _regexes;

    public HeaderCondition(ConditionDefinition definition)
        : base(definition)
    {
        _name = definition.Name!;
        _regexes = Operator == ConditionOperator.MatchesRegex
            ? Values.Select(ConditionCompiler.CompileRegex).ToArray()
            : [];
    }

    public override bool IsMatch(RequestDescriptor request)
    {
        var matched = Operator switch
        {
            ConditionOperator.Exists => request.Headers.ContainsKey(_name),
            ConditionOperator.Is => HasValue(request, (actual, expected) => string.Equals(actual, expected, StringComparison.Ordinal)),
            ConditionOperator.Contains => HasValue(request, (actual, expected) => actual.Contains(expected, StringComparison.Ordinal)),
            ConditionOperator.MatchesRegex => HasValue(request, (actual, _) => _regexes.Any(regex => regex.IsMatch(actual))),
            _ => false
        };

        return Apply(matched);
    }

    private bool HasValue(RequestDescriptor request, Func<string, string, bool> predicate) =>
        request.GetHeader(_name).Any(actual =>
            actual is not null && Values.Any(expected => predicate(actual, expected)));
}

internal sealed class QueryCondition : ConditionBase
{
    private readonly string _name;

    public QueryCondition(ConditionDefinition definition)
        : base(definition)
    {
        _name = definition.Name!;
    }

    public override bool IsMatch(RequestDescriptor request)
    {
        var matched = Operator switch
        {
            ConditionOperator.Exists => request.Query.ContainsKey(_name),
            ConditionOperator.Is => request.GetQuery(_name).Any(actual =>
                actual is not null && Values.Any(expected => string.Equals(actual, expected, StringComparison.Ordinal))),
            _ => false
        };

        return Apply(matched);
    }
}

/// <summary>Host glob matching for <c>*.example.com</c>-style patterns; <c>*</c> matches any characters.</summary>
internal static class HostWildcardMatcher
{
    public static bool IsMatch(string pattern, string host)
    {
        var patternIndex = 0;
        var hostIndex = 0;
        var starIndex = -1;
        var resumeHostIndex = 0;

        while (hostIndex < host.Length)
        {
            if (patternIndex < pattern.Length && pattern[patternIndex] != '*' && pattern[patternIndex] == host[hostIndex])
            {
                patternIndex++;
                hostIndex++;
                continue;
            }

            if (patternIndex < pattern.Length && pattern[patternIndex] == '*')
            {
                starIndex = patternIndex;
                resumeHostIndex = hostIndex;
                patternIndex++;
                continue;
            }

            if (starIndex >= 0)
            {
                patternIndex = starIndex + 1;
                hostIndex = ++resumeHostIndex;
                continue;
            }

            return false;
        }

        while (patternIndex < pattern.Length && pattern[patternIndex] == '*')
        {
            patternIndex++;
        }

        return patternIndex == pattern.Length;
    }
}
