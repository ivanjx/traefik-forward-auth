using TraefikForwardAuth.Providers;
using TraefikForwardAuth.Rules;

namespace TraefikForwardAuth.Policy;

public sealed class PolicySnapshot
{
    public static PolicySnapshot Empty { get; } = new()
    {
        Settings = new PolicySettings { SigningSecret = [] },
        Rules = [],
        Providers = new Dictionary<string, IProvider>(StringComparer.Ordinal),
        Access = AccessIndex.Build([])
    };

    public required PolicySettings Settings { get; init; }

    public required IReadOnlyList<CompiledRule> Rules { get; init; }

    public required IReadOnlyDictionary<string, IProvider> Providers { get; init; }

    public required AccessIndex Access { get; init; }

    public bool HasProviders => Providers.Count > 0;

    public RuleMatchResult Match(RequestDescriptor request) => RuleEvaluator.Match(this, request);

    public SimulationResult Simulate(RequestDescriptor request) => RuleEvaluator.Simulate(this, request);
}
