using System.Collections.Generic;
using TraefikForwardAuth.Policy;

namespace TraefikForwardAuth.Rules;

public static class RuleEvaluator
{
    public static RuleMatchResult Match(PolicySnapshot snapshot, RequestDescriptor request)
    {
        foreach (var rule in snapshot.Rules)
        {
            if (!rule.Definition.Enabled)
            {
                continue;
            }

            if (rule.Matches(request))
            {
                return CreateRuleResult(rule, snapshot);
            }
        }

        return CreateDefaultResult(snapshot);
    }

    public static SimulationResult Simulate(PolicySnapshot snapshot, RequestDescriptor request)
    {
        var simulations = new List<RuleSimulation>(snapshot.Rules.Count);
        RuleMatchResult? result = null;

        foreach (var rule in snapshot.Rules)
        {
            var matched = rule.Matches(request, out var conditions);
            var enabledMatch = rule.Definition.Enabled && matched;
            simulations.Add(new RuleSimulation(rule, enabledMatch, conditions));

            if (enabledMatch)
            {
                result = CreateRuleResult(rule, snapshot);
                break;
            }
        }

        result ??= CreateDefaultResult(snapshot);

        return new SimulationResult(result, simulations);
    }

    private static RuleMatchResult CreateRuleResult(CompiledRule rule, PolicySnapshot snapshot) =>
        new(
            rule,
            false,
            rule.Definition.Action,
            rule.Definition.Provider ?? snapshot.Settings.DefaultProvider);

    private static RuleMatchResult CreateDefaultResult(PolicySnapshot snapshot) =>
        new(
            null,
            true,
            snapshot.Settings.DefaultAction,
            snapshot.Settings.DefaultProvider);
}
