using TraefikForwardAuth.Policy;

namespace TraefikForwardAuth.Rules;

public abstract class CompiledCondition
{
    protected CompiledCondition(ConditionDefinition definition)
    {
        Definition = definition;
    }

    public ConditionDefinition Definition { get; }

    public abstract bool IsMatch(RequestDescriptor request);

    public abstract string Describe();
}

public sealed class CompiledRule
{
    public required RuleDefinition Definition { get; init; }

    public required IReadOnlyList<CompiledCondition> Conditions { get; init; }

    public required string Summary { get; init; }

    public bool Matches(RequestDescriptor request) => Matches(request, out _);

    public bool Matches(RequestDescriptor request, out IReadOnlyList<ConditionResult> results)
    {
        var found = new ConditionResult[Conditions.Count];
        var matched = true;

        for (var i = 0; i < Conditions.Count; i++)
        {
            var condition = Conditions[i];
            var conditionMatched = condition.IsMatch(request);
            found[i] = new ConditionResult(condition, conditionMatched);

            if (!conditionMatched)
            {
                matched = false;
            }
        }

        results = found;

        return matched;
    }
}

public sealed record ConditionResult(CompiledCondition Condition, bool Matched);

public sealed record RuleMatchResult(
    CompiledRule? Rule,
    bool IsDefault,
    RuleAction Action,
    string ProviderName)
{
    public string? RuleId => Rule?.Definition.Id;

    public string RuleLabel => Rule?.Definition.Name ?? "default";
}

public sealed record RuleSimulation(CompiledRule Rule, bool Matched, IReadOnlyList<ConditionResult> Conditions);

public sealed record SimulationResult(RuleMatchResult Result, IReadOnlyList<RuleSimulation> Rules);
