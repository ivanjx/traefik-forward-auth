using System.Collections.Concurrent;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace TraefikForwardAuth.Tests.TestSupport;

/// <summary>Small in-process OAuth2 server used by end-to-end tests.</summary>
public sealed class FakeProviderServer : IAsyncDisposable
{
    private readonly WebApplication _app;

    private FakeProviderServer(WebApplication app)
    {
        _app = app;
    }

    public string BaseUrl { get; private set; } = "";

    public string Email { get; set; } = "user@example.com";

    public bool EmailVerified { get; set; } = true;

    public bool RequireBasicAuth { get; set; }

    public bool RejectBasicAuth { get; set; }

    public bool FormEncodedTokenResponse { get; set; }

    public string TokenAuthorizationHeader { get; private set; } = "";

    public int LoginRequests;

    public int TokenRequests;

    public int UserInfoRequests;

    public ConcurrentQueue<string> RequestLog { get; } = new();

    public string LoginUrl => BaseUrl + "/login";

    public string TokenUrl => BaseUrl + "/token";

    public string UserInfoUrl => BaseUrl + "/userinfo";

    public static async Task<FakeProviderServer> StartAsync(CancellationToken cancellationToken = default)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");

        var app = builder.Build();
        var server = new FakeProviderServer(app);

        app.Run(server.HandleAsync);

        await app.StartAsync(cancellationToken);

        var addresses = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>();
        server.BaseUrl = addresses!.Addresses.First().TrimEnd('/');
        server.RequestLog.Enqueue($"listening {server.BaseUrl}");

        return server;
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }

    private async Task HandleAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? "";
        RequestLog.Enqueue($"{context.Request.Method} {path}{context.Request.QueryString}");

        switch (path)
        {
            case "/login":
                Interlocked.Increment(ref LoginRequests);
                await HandleLoginAsync(context);
                return;

            case "/token":
                Interlocked.Increment(ref TokenRequests);
                await HandleTokenAsync(context);
                return;

            case "/userinfo":
                Interlocked.Increment(ref UserInfoRequests);
                await HandleUserInfoAsync(context);
                return;

            case "/head":
                context.Response.StatusCode = StatusCodes.Status200OK;
                return;

            default:
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
        }
    }

    private static Task HandleLoginAsync(HttpContext context)
    {
        var redirectUri = context.Request.Query["redirect_uri"].ToString();
        var state = context.Request.Query["state"].ToString();

        if (string.IsNullOrEmpty(redirectUri))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return Task.CompletedTask;
        }

        var separator = redirectUri.Contains('?') ? '&' : '?';
        var location = $"{redirectUri}{separator}code=fake-code&state={Uri.EscapeDataString(state)}";

        context.Response.StatusCode = StatusCodes.Status302Found;
        context.Response.Headers.Location = location;

        return Task.CompletedTask;
    }

    private async Task HandleTokenAsync(HttpContext context)
    {
        TokenAuthorizationHeader = context.Request.Headers.Authorization.ToString();

        if (RequireBasicAuth && string.IsNullOrEmpty(TokenAuthorizationHeader))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "invalid_client" });
            return;
        }

        if (RejectBasicAuth && !string.IsNullOrEmpty(TokenAuthorizationHeader))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "invalid_client" });
            return;
        }

        var form = await context.Request.ReadFormAsync();

        if (form["client_id"] == "invalid")
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "invalid_client" });
            return;
        }

        if (FormEncodedTokenResponse)
        {
            context.Response.ContentType = "application/x-www-form-urlencoded";
            await context.Response.WriteAsync(
                "access_token=fake-access-token&token_type=Bearer&id_token=fake-id-token");
            return;
        }

        await context.Response.WriteAsJsonAsync(new
        {
            access_token = "fake-access-token",
            token_type = "Bearer",
            id_token = "fake-id-token"
        });
    }

    private async Task HandleUserInfoAsync(HttpContext context)
    {
        var authorized = context.Request.Headers.Authorization.ToString() == "Bearer fake-access-token" ||
                         context.Request.Query["access_token"].ToString() == "fake-access-token";

        if (!authorized)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        await context.Response.WriteAsJsonAsync(new
        {
            email = Email,
            verified_email = EmailVerified
        });
    }
}

public sealed class CookieJar
{
    private readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);

    public string Header => string.Join("; ", _cookies.Select(pair => $"{pair.Key}={pair.Value}"));

    public IReadOnlyDictionary<string, string> Cookies => _cookies;

    public void Capture(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            return;
        }

        foreach (var value in values)
        {
            var semicolon = value.IndexOf(';');
            var pair = semicolon >= 0 ? value[..semicolon] : value;
            var equals = pair.IndexOf('=');

            if (equals <= 0)
            {
                continue;
            }

            var name = pair[..equals];
            var cookieValue = pair[(equals + 1)..];

            if (cookieValue.Length == 0 ||
                value.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase) ||
                value.Contains("max-age=0", StringComparison.OrdinalIgnoreCase))
            {
                _cookies.Remove(name);
                continue;
            }

            _cookies[name] = cookieValue;
        }
    }

    public void Set(string name, string value) => _cookies[name] = value;

    public void Clear() => _cookies.Clear();
}

public sealed class TestHttpClient : IDisposable
{
    private readonly HttpClient _client;

    public TestHttpClient(HttpClient client)
    {
        _client = client;
        Cookies = new CookieJar();
    }

    public CookieJar Cookies { get; }

    public async Task<HttpResponseMessage> GetAsync(string path, Action<HttpRequestMessage>? configure = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        configure?.Invoke(request);
        return await SendAsync(request);
    }

    public async Task<HttpResponseMessage> PostAsync(
        string path,
        HttpContent content,
        Action<HttpRequestMessage>? configure = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = content };
        configure?.Invoke(request);
        return await SendAsync(request);
    }

    public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken = default)
    {
        if (Cookies.Cookies.Count > 0)
        {
            request.Headers.TryAddWithoutValidation("Cookie", Cookies.Header);
        }

        var response = await _client.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken);
        Cookies.Capture(response);

        return response;
    }

    public void Dispose() => _client.Dispose();
}
