using System.Text.Json.Serialization;

namespace TraefikForwardAuth.Policy;

public sealed record ConditionDefinition
{
    public ConditionField Field { get; init; }

    public ConditionOperator Operator { get; init; }

    /// <summary>Header or query parameter name. Null for host, path and method conditions.</summary>
    public string? Name { get; init; }

    public IReadOnlyList<string> Values { get; init; } = [];

    public bool Negated { get; init; }
}

public sealed record RuleDefinition
{
    public required string Id { get; init; }

    public string Name { get; init; } = "";

    public bool Enabled { get; init; } = true;

    public RuleAction Action { get; init; } = RuleAction.Auth;

    /// <summary>Null means the global default provider.</summary>
    public string? Provider { get; init; }

    public int Position { get; init; }

    public IReadOnlyList<ConditionDefinition> Conditions { get; init; } = [];
}

public sealed record AccessEntry
{
    public required string Id { get; init; }

    /// <summary>Null for a global entry, otherwise the rule id.</summary>
    public string? RuleId { get; init; }

    public AccessKind Kind { get; init; }

    public string Value { get; init; } = "";

    public string? Role { get; init; }

    public bool IsGlobal => RuleId is null;
}
