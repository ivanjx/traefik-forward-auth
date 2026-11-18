namespace TraefikForwardAuth.Policy;

public sealed record StoredConfiguration
{
    public required PolicySettings Settings { get; init; }

    public IReadOnlyList<ProviderDefinition> Providers { get; init; } = [];

    public IReadOnlyList<RuleDefinition> Rules { get; init; } = [];

    public IReadOnlyList<AccessEntry> AccessEntries { get; init; } = [];
}
