using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Providers;
using TraefikForwardAuth.Rules;
using TraefikForwardAuth.Storage;

namespace TraefikForwardAuth.Policy;

/// <summary>
/// Holds the immutable policy snapshot. Requests read it without locks; writers rebuild and
/// atomically swap in a new snapshot.
/// </summary>
public sealed class PolicyManager
{
    private readonly SqliteStore _store;
    private readonly ProviderFactory _providerFactory;
    private readonly TfaLogger _logger;
    private PolicySnapshot _current = PolicySnapshot.Empty;

    public PolicyManager(SqliteStore store, ProviderFactory providerFactory, TfaLogger logger)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _providerFactory = providerFactory ?? throw new ArgumentNullException(nameof(providerFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public PolicySnapshot Current => Volatile.Read(ref _current);

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await RebuildAsync(cancellationToken);
    }

    public async Task<PolicySnapshot> RebuildAsync(CancellationToken cancellationToken)
    {
        var configuration = await _store.LoadConfigurationAsync(cancellationToken);

        var rules = new List<CompiledRule>(configuration.Rules.Count);

        foreach (var definition in configuration.Rules)
        {
            if (ConditionCompiler.TryCompileRule(definition, out var compiled, out var errors) && compiled is not null)
            {
                rules.Add(compiled);
                continue;
            }

            _logger.Error(
                "Skipping invalid rule",
                ("rule", definition.Id),
                ("name", definition.Name),
                ("errors", string.Join("; ", errors)));
        }

        var providers = new Dictionary<string, IProvider>(StringComparer.Ordinal);

        foreach (var definition in configuration.Providers)
        {
            try
            {
                var provider = await _providerFactory.CreateAsync(definition, cancellationToken);

                if (provider is not null)
                {
                    providers[definition.Name] = provider;
                }
                else
                {
                    _logger.Error("Provider factory returned no provider", ("provider", definition.Name));
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                _logger.Error(
                    "Failed to create provider",
                    ("provider", definition.Name),
                    ("error", exception.Message));
            }
        }

        var snapshot = new PolicySnapshot
        {
            Settings = configuration.Settings,
            Rules = rules,
            Providers = providers,
            Access = AccessIndex.Build(configuration.AccessEntries)
        };

        Volatile.Write(ref _current, snapshot);

        return snapshot;
    }
}
