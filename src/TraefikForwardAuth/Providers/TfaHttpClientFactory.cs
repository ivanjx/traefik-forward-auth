namespace TraefikForwardAuth.Providers;

/// <summary>Minimal IHttpClientFactory with a shared handler; avoids reflection-based DI registration.</summary>
public sealed class TfaHttpClientFactory : IHttpClientFactory, IDisposable
{
    private readonly SocketsHttpHandler _handler = new()
    {
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        ConnectTimeout = TimeSpan.FromSeconds(10)
    };

    public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false)
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public void Dispose() => _handler.Dispose();
}
