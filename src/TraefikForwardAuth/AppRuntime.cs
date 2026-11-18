using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Providers;

namespace TraefikForwardAuth;

public sealed record AppRuntimeOverrides
{
    public GoogleEndpoints? GoogleEndpoints { get; init; }

    public IHttpClientFactory? HttpClients { get; init; }

    public TimeProvider? TimeProvider { get; init; }
}

public sealed class AppRuntime : IAsyncDisposable
{
    public AppRuntime(TfaOptions options, AppRuntimeOverrides? overrides = null)
    {
        Options = options;
        TimeProvider = overrides?.TimeProvider ?? TimeProvider.System;
        Logger = new TfaLogger(options.LogLevel, options.LogFormat, timeProvider: TimeProvider);
        HttpClients = overrides?.HttpClients ?? new TfaHttpClientFactory();
        Store = new Storage.SqliteStore(Path.Combine(options.DataDir, "traefik-forward-auth.db"), Logger);
        ProviderFactory = new ProviderFactory(
            HttpClients,
            overrides?.GoogleEndpoints ?? GoogleEndpoints.Default,
            Logger);
        Policy = new Policy.PolicyManager(Store, ProviderFactory, Logger, TimeProvider);
        Sessions = new Auth.SessionManager(Store, Logger, TimeProvider);
        Admin = new Policy.AdminService(Store, Policy, Sessions, ProviderFactory, Logger, TimeProvider);
        AdminAuth = new Admin.AdminAuthService(
            options,
            Policy,
            Sessions,
            overrides?.GoogleEndpoints ?? GoogleEndpoints.Default,
            HttpClients,
            Logger,
            TimeProvider);
    }

    public TfaOptions Options { get; }

    public TimeProvider TimeProvider { get; }

    public TfaLogger Logger { get; }

    public IHttpClientFactory HttpClients { get; }

    public Storage.SqliteStore Store { get; }

    public Policy.PolicyManager Policy { get; }

    public Auth.SessionManager Sessions { get; }

    public ProviderFactory ProviderFactory { get; }

    public Policy.AdminService Admin { get; }

    public Admin.AdminAuthService AdminAuth { get; }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await Store.InitializeAsync(cancellationToken);
        await Sessions.InitializeAsync(cancellationToken);
        await Policy.InitializeAsync(cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        await Policy.DisposeAsync();
        await Sessions.DisposeAsync();
        await Store.DisposeAsync();

        if (HttpClients is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}
