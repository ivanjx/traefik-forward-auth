using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Providers;
using TraefikForwardAuth.Rules;
using TraefikForwardAuth.Storage;

namespace TraefikForwardAuth.Policy;

/// <summary>
/// Holds the immutable policy snapshot. Requests read it without locks; writers rebuild and
/// atomically swap in a new snapshot. Rebuilds are serialized so the last one to start always
/// loads the newest configuration and wins the swap.
/// </summary>
public sealed class PolicyManager : IAsyncDisposable
{
    private static readonly TimeSpan InitialRetryDelay = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromMinutes(5);

    private readonly SqliteStore _store;
    private readonly ProviderFactory _providerFactory;
    private readonly TfaLogger _logger;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _rebuildGate = new(1, 1);
    private readonly CancellationTokenSource _shutdown = new();
    private readonly object _retryLock = new();
    private Dictionary<string, BuiltProvider> _builtProviders = new(StringComparer.Ordinal);
    private ITimer? _retryTimer;
    private TimeSpan _retryDelay = InitialRetryDelay;
    private PolicySnapshot _current = PolicySnapshot.Empty;

    public PolicyManager(
        SqliteStore store,
        ProviderFactory providerFactory,
        TfaLogger logger,
        TimeProvider? timeProvider = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _providerFactory = providerFactory ?? throw new ArgumentNullException(nameof(providerFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public PolicySnapshot Current => Volatile.Read(ref _current);

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await RebuildAsync(cancellationToken);
    }

    public async Task<PolicySnapshot> RebuildAsync(CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdown.Token);
        var token = linked.Token;

        await _rebuildGate.WaitAsync(token);

        try
        {
            return await RebuildCoreAsync(token);
        }
        finally
        {
            _rebuildGate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        lock (_retryLock)
        {
            _shutdown.Cancel();
            _retryTimer?.Dispose();
            _retryTimer = null;
        }

        // Wait for an in-flight rebuild so it never outlives the store it reads from.
        await _rebuildGate.WaitAsync();
        _rebuildGate.Release();
    }

    private async Task<PolicySnapshot> RebuildCoreAsync(CancellationToken cancellationToken)
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

        var built = new Dictionary<string, BuiltProvider>(StringComparer.Ordinal);
        var providers = new Dictionary<string, IProvider>(StringComparer.Ordinal);
        var hasTransientFailures = false;

        foreach (var definition in configuration.Providers)
        {
            // Reuse an unchanged provider so a transient issuer outage during an unrelated
            // save cannot drop a provider that is already working.
            if (_builtProviders.TryGetValue(definition.Name, out var previous) &&
                SameDefinition(previous.Definition, definition))
            {
                built[definition.Name] = previous;
                providers[definition.Name] = previous.Provider;
                continue;
            }

            try
            {
                var provider = await _providerFactory.CreateAsync(definition, cancellationToken);

                if (provider is not null)
                {
                    built[definition.Name] = new BuiltProvider(definition, provider);
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
                hasTransientFailures = true;

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

        _builtProviders = built;
        Volatile.Write(ref _current, snapshot);

        ScheduleRetry(hasTransientFailures);

        return snapshot;
    }

    private void ScheduleRetry(bool hasTransientFailures)
    {
        lock (_retryLock)
        {
            _retryTimer?.Dispose();
            _retryTimer = null;

            if (!hasTransientFailures)
            {
                _retryDelay = InitialRetryDelay;
                return;
            }

            if (_shutdown.IsCancellationRequested)
            {
                return;
            }

            _logger.Warn("Retrying failed providers", ("delay_seconds", (int)_retryDelay.TotalSeconds));

            _retryTimer = _timeProvider.CreateTimer(
                _ => _ = RetryAsync(),
                null,
                _retryDelay,
                Timeout.InfiniteTimeSpan);

            _retryDelay = TimeSpan.FromTicks(Math.Min(_retryDelay.Ticks * 2, MaxRetryDelay.Ticks));
        }
    }

    private async Task RetryAsync()
    {
        try
        {
            await RebuildAsync(CancellationToken.None);
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            _logger.Error("Background policy rebuild failed", ("error", exception.Message));
            ScheduleRetry(hasTransientFailures: true);
        }
    }

    private static bool SameDefinition(ProviderDefinition left, ProviderDefinition right) =>
        left with { Scopes = [] } == right with { Scopes = [] } &&
        left.Scopes.SequenceEqual(right.Scopes, StringComparer.Ordinal);

    private sealed record BuiltProvider(ProviderDefinition Definition, IProvider Provider);
}
