using System;
using System.Collections.Generic;
using System.Linq;
using TraefikForwardAuth.Policy;

namespace TraefikForwardAuth.Rules;

public static class RuleDescriber
{
    public static string Describe(RuleDefinition rule)
    {
        var action = rule.Action switch
        {
            RuleAction.Allow => "Allow without login",
            RuleAction.Auth => "Require login",
            _ => rule.Action.ToString()
        };

        var conditions = rule.Conditions ?? [];

        if (conditions.Count == 0)
        {
            return $"Requests → {action}";
        }

        var first = conditions[0];
        string summary;

        if (first is not null
            && first.Field == ConditionField.Host
            && !first.Negated
            && first.Operator is ConditionOperator.Is or ConditionOperator.MatchesWildcard
            && first.Values is { Count: > 0 })
        {
            summary = "Requests to " + FormatValues(first.Values);

            if (conditions.Count > 1)
            {
                var rest = string.Join(" and ", conditions.Skip(1).Select(DescribeCondition));
                summary += " where " + rest;
            }
        }
        else
        {
            summary = "Requests where " + string.Join(" and ", conditions.Select(DescribeCondition));
        }

        return summary + " → " + action;
    }

    public static string DescribeCondition(ConditionDefinition condition)
    {
        if (condition is null)
        {
            return "an unspecified condition";
        }

        var field = condition.Field switch
        {
            ConditionField.Host => "host ",
            ConditionField.Path => "path ",
            ConditionField.Method => "method ",
            ConditionField.Header => condition.Name is null ? "header " : $"header `{condition.Name}` ",
            ConditionField.Query => condition.Name is null ? "query " : $"query `{condition.Name}` ",
            _ => "unknown field "
        };

        return field + DescribeOperator(condition);
    }

    private static string DescribeOperator(ConditionDefinition condition)
    {
        var values = FormatValues(
            condition.Values,
            condition.Field == ConditionField.Method,
            condition.Field != ConditionField.Method);

        return condition.Operator switch
        {
            ConditionOperator.Is => condition.Negated ? $"is not {values}" : $"is {values}",
            ConditionOperator.MatchesWildcard => condition.Negated ? $"does not match {values}" : $"matches {values}",
            ConditionOperator.StartsWith => condition.Negated ? $"does not start with {values}" : $"starts with {values}",
            ConditionOperator.MatchesPattern => condition.Negated ? $"does not match {values}" : $"matches {values}",
            ConditionOperator.Contains => condition.Negated ? $"does not contain {values}" : $"contains {values}",
            ConditionOperator.Exists => condition.Negated ? "does not exist" : "exists",
            ConditionOperator.MatchesRegex => condition.Negated ? $"does not match regex {values}" : $"matches regex {values}",
            _ => "matches an unknown condition"
        };
    }

    private static string FormatValues(IReadOnlyList<string>? values, bool uppercase = false, bool quote = true)
    {
        if (values is null || values.Count == 0)
        {
            return "no values";
        }

        return string.Join(
            " or ",
            values.Select(value =>
            {
                var text = uppercase ? value?.ToUpperInvariant() : value;
                return quote ? $"`{text}`" : text;
            }));
    }
}
