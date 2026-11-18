using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Policy;
using TraefikForwardAuth.Providers;

namespace TraefikForwardAuth.Tests;

public sealed class ProviderTests
{
    private const string GoogleScope =
        "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email";

    private static readonly TfaLogger Logger = new(TfaLogLevel.Critical, TfaLogFormat.Text, TextWriter.Null);

    private static readonly TfaHttpClientFactory HttpClients = new();

    [Fact]
    public void GoogleLoginUrlUsesDefaultPrompt()
    {
        var provider = CreateGoogleProvider(new GoogleEndpoints(
            new Uri("https://accounts.example/auth"),
            new Uri("https://accounts.example/token"),
            new Uri("https://accounts.example/userinfo")));

        var query = ParseQuery(provider.GetLoginUrl("https://auth.example/_oauth", "state-1"));

        Assert.Equal("client-id", query["client_id"]);
        Assert.Equal("code", query["response_type"]);
        Assert.Equal(GoogleScope, query["scope"]);
        Assert.Equal("select_account", query["prompt"]);
        Assert.Equal("https://auth.example/_oauth", query["redirect_uri"]);
        Assert.Equal("state-1", query["state"]);
    }

    [Fact]
    public void GoogleLoginUrlOmitsEmptyPrompt()
    {
        var provider = CreateGoogleProvider(GoogleEndpoints.Default, prompt: "");
        var query = ParseQuery(provider.GetLoginUrl("https://auth.example/_oauth", "state"));

        Assert.False(query.ContainsKey("prompt"));

        var custom = CreateGoogleProvider(GoogleEndpoints.Default, prompt: "consent");
        Assert.Equal("consent", ParseQuery(custom.GetLoginUrl("https://auth.example/_oauth", "state"))["prompt"]);
    }

    [Fact]
    public async Task GoogleExchangeAndUserInfoRoundTrip()
    {
        Dictionary<string, string>? tokenForm = null;
        string? authorization = null;

        await using var server = await FakeServer.StartAsync(app =>
        {
            app.MapPost("/token", async (HttpContext context) =>
            {
                tokenForm = (await context.Request.ReadFormAsync()).ToDictionary(pair => pair.Key, pair => pair.Value.ToString());
                await WriteJsonAsync(context, """{"access_token":"access-1","id_token":"id-1","token_type":"Bearer"}""");
            });

            app.MapGet("/userinfo", async (HttpContext context) =>
            {
                authorization = context.Request.Headers.Authorization.ToString();
                await WriteJsonAsync(context, """{"email":"user@example.com","verified_email":true}""");
            });
        });

        var provider = CreateGoogleProvider(Endpoints(server));

        var token = await provider.ExchangeCodeAsync("https://auth.example/_oauth", "code-1", CancellationToken.None);

        Assert.Equal("access-1", token.AccessToken);
        Assert.Equal("id-1", token.IdToken);
        Assert.NotNull(tokenForm);
        Assert.Equal("client-id", tokenForm["client_id"]);
        Assert.Equal("client-secret", tokenForm["client_secret"]);
        Assert.Equal("authorization_code", tokenForm["grant_type"]);
        Assert.Equal("https://auth.example/_oauth", tokenForm["redirect_uri"]);
        Assert.Equal("code-1", tokenForm["code"]);

        var user = await provider.GetUserAsync(token, CancellationToken.None);

        Assert.Equal("Bearer access-1", authorization);
        Assert.Equal("user@example.com", user.Email);
        Assert.True(user.EmailVerified);
    }

    [Fact]
    public async Task GoogleTestConnectionAcceptsAnyHttpResponse()
    {
        await using var server = await FakeServer.StartAsync(app =>
            app.MapGet("/userinfo", (HttpContext context) =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            }));

        var result = await CreateGoogleProvider(Endpoints(server)).TestConnectionAsync(CancellationToken.None);

        Assert.True(result.Success);
    }

    [Fact]
    public async Task GoogleTestConnectionFailsWhenUnreachable()
    {
        var endpoints = new GoogleEndpoints(
            new Uri("http://127.0.0.1:1/auth"),
            new Uri("http://127.0.0.1:1/token"),
            new Uri("http://127.0.0.1:1/userinfo"));

        var result = await CreateGoogleProvider(endpoints).TestConnectionAsync(CancellationToken.None);

        Assert.False(result.Success);
        Assert.Contains("unreachable", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GenericLoginUrlUsesDefaultScopesAndResource()
    {
        var provider = CreateGenericProvider(new ProviderDefinition
        {
            Name = ProviderDefinition.GenericOAuth,
            ClientId = "generic-id",
            ClientSecret = "generic-secret",
            AuthUrl = "https://idp.example/auth",
            TokenUrl = "https://idp.example/token",
            UserUrl = "https://idp.example/user",
            Resource = "https://api.example"
        });

        var query = ParseQuery(provider.GetLoginUrl("https://auth.example/_oauth", "state-2"));

        Assert.Equal("generic-id", query["client_id"]);
        Assert.Equal("code", query["response_type"]);
        Assert.Equal("profile email", query["scope"]);
        Assert.Equal("https://api.example", query["resource"]);

        var custom = CreateGenericProvider(new ProviderDefinition
        {
            Name = ProviderDefinition.GenericOAuth,
            ClientId = "generic-id",
            ClientSecret = "generic-secret",
            AuthUrl = "https://idp.example/auth",
            TokenUrl = "https://idp.example/token",
            UserUrl = "https://idp.example/user",
            Scopes = ["openid", "custom"]
        });

        Assert.Equal("openid custom", ParseQuery(custom.GetLoginUrl("https://auth.example/_oauth", "state"))["scope"]);
        Assert.False(ParseQuery(custom.GetLoginUrl("https://auth.example/_oauth", "state")).ContainsKey("resource"));
    }

    [Fact]
    public async Task GenericGetUserSendsBearerToken()
    {
        string? authorization = null;

        await using var server = await FakeServer.StartAsync(app =>
            app.MapGet("/userinfo", async (HttpContext context) =>
            {
                authorization = context.Request.Headers.Authorization.ToString();
                await WriteJsonAsync(context, """{"email":"generic@example.com"}""");
            }));

        var provider = CreateGenericProvider(GenericDefinition(server, "header"));

        var user = await provider.GetUserAsync(new ProviderToken("token-1", null), CancellationToken.None);

        Assert.Equal("Bearer token-1", authorization);
        Assert.Equal("generic@example.com", user.Email);
        Assert.False(user.EmailVerified);
    }

    [Fact]
    public async Task GenericGetUserSendsQueryToken()
    {
        string? authorization = null;
        string? accessToken = null;

        await using var server = await FakeServer.StartAsync(app =>
            app.MapGet("/userinfo", async (HttpContext context) =>
            {
                authorization = context.Request.Headers.Authorization.ToString();
                accessToken = context.Request.Query["access_token"];
                await WriteJsonAsync(context, """{"email":"query@example.com"}""");
            }));

        var provider = CreateGenericProvider(GenericDefinition(server, "query"));

        var user = await provider.GetUserAsync(new ProviderToken("token-2", null), CancellationToken.None);

        Assert.Equal("", authorization);
        Assert.Equal("token-2", accessToken);
        Assert.Equal("query@example.com", user.Email);
    }

    [Fact]
    public async Task GenericExchangeFallsBackToFormCredentials()
    {
        var requests = 0;
        string? fallbackFormSecret = null;

        await using var server = await FakeServer.StartAsync(app =>
            app.MapPost("/token", async (HttpContext context) =>
            {
                requests++;

                if (context.Request.Headers.ContainsKey("Authorization"))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return;
                }

                var form = await context.Request.ReadFormAsync();
                fallbackFormSecret = form["client_secret"];
                await WriteJsonAsync(context, """{"access_token":"generic-access"}""");
            }));

        var provider = CreateGenericProvider(GenericDefinition(server, "header"));
        var token = await provider.ExchangeCodeAsync("https://auth.example/_oauth", "code", CancellationToken.None);

        Assert.Equal("generic-access", token.AccessToken);
        Assert.Equal(2, requests);
        Assert.Equal("generic-secret", fallbackFormSecret);
    }

    [Fact]
    public async Task OAuth2ClientSendsBasicCredentialsFirst()
    {
        var decodedCredentials = "";
        var formHasSecret = true;

        await using var server = await FakeServer.StartAsync(app =>
            app.MapPost("/token", async (HttpContext context) =>
            {
                var authorization = context.Request.Headers.Authorization.ToString();

                if (authorization.StartsWith("Basic ", StringComparison.Ordinal))
                {
                    decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(authorization[6..]));
                }

                var form = await context.Request.ReadFormAsync();
                formHasSecret = form.ContainsKey("client_secret");
                await WriteJsonAsync(context, """{"access_token":"basic-token"}""");
            }));

        var client = new OAuth2Client(HttpClients, "client-id", "client-secret");

        var token = await client.ExchangeCodeAsync(new Uri($"{server.BaseUrl}/token"), "https://auth.example/_oauth", "code", CancellationToken.None);

        Assert.Equal("basic-token", token.AccessToken);
        Assert.Equal("client-id:client-secret", decodedCredentials);
        Assert.False(formHasSecret);
    }

    [Fact]
    public async Task OAuth2ClientRetriesWithFormCredentialsOnFailure()
    {
        var requests = 0;
        string? secondSecret = null;

        await using var server = await FakeServer.StartAsync(app =>
            app.MapPost("/token", async (HttpContext context) =>
            {
                requests++;

                if (context.Request.Headers.ContainsKey("Authorization"))
                {
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    await context.Response.WriteAsync("basic auth rejected");
                    return;
                }

                var form = await context.Request.ReadFormAsync();
                secondSecret = form["client_secret"];
                await WriteJsonAsync(context, """{"access_token":"form-token"}""");
            }));

        var client = new OAuth2Client(HttpClients, "client-id", "client-secret");

        var token = await client.ExchangeCodeAsync(new Uri($"{server.BaseUrl}/token"), "https://auth.example/_oauth", "code", CancellationToken.None);

        Assert.Equal("form-token", token.AccessToken);
        Assert.Equal(2, requests);
        Assert.Equal("client-secret", secondSecret);
    }

    [Fact]
    public async Task OAuth2ClientParsesFormEncodedTokenResponse()
    {
        await using var server = await FakeServer.StartAsync(app =>
            app.MapPost("/token", async (HttpContext context) =>
            {
                context.Response.ContentType = "application/x-www-form-urlencoded";
                await context.Response.WriteAsync("access_token=form-access&id_token=form-id&token_type=bearer");
            }));

        var client = new OAuth2Client(HttpClients, "client-id", "client-secret");

        var token = await client.ExchangeCodeAsync(new Uri($"{server.BaseUrl}/token"), "https://auth.example/_oauth", "code", CancellationToken.None);

        Assert.Equal("form-access", token.AccessToken);
        Assert.Equal("form-id", token.IdToken);
    }

    [Fact]
    public async Task OAuth2ClientThrowsWithStatusAndBodySnippet()
    {
        await using var server = await FakeServer.StartAsync(app =>
            app.MapPost("/token", async (HttpContext context) =>
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await WriteJsonAsync(context, """{"error":"invalid_grant","error_description":"bad code"}""");
            }));

        var client = new OAuth2Client(HttpClients, "client-id", "client-secret");

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.ExchangeCodeAsync(new Uri($"{server.BaseUrl}/token"), "https://auth.example/_oauth", "code", CancellationToken.None));

        Assert.Contains("400", exception.Message);
        Assert.Contains("invalid_grant", exception.Message);
    }

    [Fact]
    public async Task ProviderFactoryReturnsNullForInvalidDefinition()
    {
        var factory = new ProviderFactory(HttpClients, GoogleEndpoints.Default, Logger);

        var provider = await factory.CreateAsync(
            new ProviderDefinition { Name = ProviderDefinition.Google, ClientId = "", ClientSecret = "" },
            CancellationToken.None);

        Assert.Null(provider);
    }

    [Fact]
    public async Task OidcDiscoveryIssuerMismatchThrows()
    {
        await using var server = await OidcServer.StartAsync();
        server.IssuerOverride = server.BaseUrl + "/somewhere-else";
        server.ServeKeys(OidcServer.RsaKey1Id);

        var factory = new ProviderFactory(HttpClients, GoogleEndpoints.Default, Logger);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => factory.CreateAsync(server.Definition, CancellationToken.None));

        Assert.Contains("does not match", exception.Message);
    }

    [Fact]
    public async Task OidcLoginUrlIncludesStandardParameters()
    {
        await using var server = await OidcServer.StartAsync();
        server.ServeKeys(OidcServer.RsaKey1Id);

        var provider = await OidcProvider.CreateAsync(server.Definition, HttpClients, Logger, CancellationToken.None);
        var query = ParseQuery(provider.GetLoginUrl("https://auth.example/_oauth", "state-3"));

        Assert.Equal(server.ClientId, query["client_id"]);
        Assert.Equal("code", query["response_type"]);
        Assert.Equal("openid profile email", query["scope"]);
        Assert.Equal("https://auth.example/_oauth", query["redirect_uri"]);
        Assert.Equal("state-3", query["state"]);
        Assert.StartsWith($"{server.BaseUrl}/authorize?", provider.GetLoginUrl("https://auth.example/_oauth", "state-3"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task OidcExchangeRequiresIdToken()
    {
        await using var server = await OidcServer.StartAsync();
        var provider = await OidcProvider.CreateAsync(server.Definition, HttpClients, Logger, CancellationToken.None);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.ExchangeCodeAsync("https://auth.example/_oauth", "code", CancellationToken.None));

        Assert.Contains("id_token", exception.Message);
    }

    [Fact]
    public async Task OidcValidIdTokenReturnsUser()
    {
        await using var server = await OidcServer.StartAsync();
        server.ServeKeys(OidcServer.RsaKey1Id);

        var provider = await OidcProvider.CreateAsync(server.Definition, HttpClients, Logger, CancellationToken.None);

        server.IdToken = server.SignRsa(JwtSigner.Payload(
            server.Issuer,
            server.ClientId,
            emailVerified: "true",
            audienceAsArray: true));

        var token = await provider.ExchangeCodeAsync("https://auth.example/_oauth", "code", CancellationToken.None);
        var user = await provider.GetUserAsync(token, CancellationToken.None);

        Assert.NotNull(token.IdToken);
        Assert.Equal("user@example.com", user.Email);
        Assert.True(user.EmailVerified);
    }

    [Fact]
    public async Task OidcRejectsInvalidSignature()
    {
        await using var server = await OidcServer.StartAsync();
        server.ServeKeys(OidcServer.RsaKey1Id);

        var provider = await OidcProvider.CreateAsync(server.Definition, HttpClients, Logger, CancellationToken.None);

        var token = JwtSigner.Create(
            "RS256",
            OidcServer.RsaKey1Id,
            JwtSigner.Payload(server.Issuer, server.ClientId, emailVerified: true),
            server.RotatedRsaKey);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.GetUserAsync(new ProviderToken("access", token), CancellationToken.None));

        Assert.Contains("signature", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OidcRejectsWrongIssuer()
    {
        var exception = await ValidateTokenAsync(server => JwtSigner.Payload(
            "https://evil.example", server.ClientId, emailVerified: true));

        Assert.Contains("issuer", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OidcRejectsWrongAudience()
    {
        var exception = await ValidateTokenAsync(server => JwtSigner.Payload(
            server.Issuer, "some-other-client", emailVerified: true));

        Assert.Contains("audience", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OidcRejectsExpiredToken()
    {
        var exception = await ValidateTokenAsync(server => JwtSigner.Payload(
            server.Issuer, server.ClientId, emailVerified: true, expiresInSeconds: -300));

        Assert.Contains("expired", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("HS256")]
    public async Task OidcRejectsForbiddenAlgorithms(string algorithm)
    {
        await using var server = await OidcServer.StartAsync();
        server.Algorithms = ["RS256", algorithm];
        server.ServeKeys(OidcServer.RsaKey1Id);

        var provider = await OidcProvider.CreateAsync(server.Definition, HttpClients, Logger, CancellationToken.None);

        var token = JwtSigner.CreateWithAlgorithm(
            algorithm,
            OidcServer.RsaKey1Id,
            JwtSigner.Payload(server.Issuer, server.ClientId, emailVerified: true));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.GetUserAsync(new ProviderToken("access", token), CancellationToken.None));
    }

    [Fact]
    public async Task OidcAcceptsEs256SignedToken()
    {
        await using var server = await OidcServer.StartAsync();
        server.Algorithms = ["RS256", "ES256"];
        server.ServeKeys(OidcServer.EcKey1Id);

        var provider = await OidcProvider.CreateAsync(server.Definition, HttpClients, Logger, CancellationToken.None);

        var token = JwtSigner.Create(
            "ES256",
            OidcServer.EcKey1Id,
            JwtSigner.Payload(server.Issuer, server.ClientId, emailVerified: true),
            server.EcKey);

        var user = await provider.GetUserAsync(new ProviderToken("access", token), CancellationToken.None);

        Assert.Equal("user@example.com", user.Email);
        Assert.True(user.EmailVerified);
    }

    [Fact]
    public async Task OidcRefetchesJwksWhenKeyIdIsUnknown()
    {
        await using var server = await OidcServer.StartAsync();
        server.ServeKeys(OidcServer.RsaKey1Id);

        var provider = await OidcProvider.CreateAsync(server.Definition, HttpClients, Logger, CancellationToken.None);

        var firstToken = server.SignRsa(JwtSigner.Payload(server.Issuer, server.ClientId, emailVerified: true));
        _ = await provider.GetUserAsync(new ProviderToken("access", firstToken), CancellationToken.None);

        Assert.Equal(1, server.JwksFetches);

        server.ServeKeys(OidcServer.RsaKey2Id);
        var secondToken = JwtSigner.Create(
            "RS256",
            OidcServer.RsaKey2Id,
            JwtSigner.Payload(server.Issuer, server.ClientId, emailVerified: true),
            server.RotatedRsaKey);

        var user = await provider.GetUserAsync(new ProviderToken("access", secondToken), CancellationToken.None);

        Assert.Equal("user@example.com", user.Email);
        Assert.Equal(2, server.JwksFetches);
    }

    [Fact]
    public async Task OidcTestConnectionReportsDiscoveryResult()
    {
        await using var server = await OidcServer.StartAsync();
        server.ServeKeys(OidcServer.RsaKey1Id);

        var provider = await OidcProvider.CreateAsync(server.Definition, HttpClients, Logger, CancellationToken.None);

        var success = await provider.TestConnectionAsync(CancellationToken.None);
        Assert.True(success.Success);
        Assert.Contains(server.BaseUrl, success.Message);

        server.DiscoveryFails = true;
        var failure = await provider.TestConnectionAsync(CancellationToken.None);
        Assert.False(failure.Success);
        Assert.Contains("discovery", failure.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<InvalidOperationException> ValidateTokenAsync(Func<OidcServer, JsonObject> payloadFactory)
    {
        await using var server = await OidcServer.StartAsync();
        server.ServeKeys(OidcServer.RsaKey1Id);

        var provider = await OidcProvider.CreateAsync(server.Definition, HttpClients, Logger, CancellationToken.None);
        var token = server.SignRsa(payloadFactory(server));

        return await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.GetUserAsync(new ProviderToken("access", token), CancellationToken.None));
    }

    private static GoogleProvider CreateGoogleProvider(GoogleEndpoints endpoints, string? prompt = null) =>
        new(
            new ProviderDefinition
            {
                Name = ProviderDefinition.Google,
                ClientId = "client-id",
                ClientSecret = "client-secret",
                Prompt = prompt
            },
            HttpClients,
            endpoints,
            Logger);

    private static GenericOAuthProvider CreateGenericProvider(ProviderDefinition definition) =>
        new(definition, HttpClients, Logger);

    private static GoogleEndpoints Endpoints(FakeServer server) => new(
        new Uri($"{server.BaseUrl}/auth"),
        new Uri($"{server.BaseUrl}/token"),
        new Uri($"{server.BaseUrl}/userinfo"));

    private static ProviderDefinition GenericDefinition(FakeServer server, string tokenStyle) => new()
    {
        Name = ProviderDefinition.GenericOAuth,
        ClientId = "generic-client",
        ClientSecret = "generic-secret",
        AuthUrl = $"{server.BaseUrl}/auth",
        TokenUrl = $"{server.BaseUrl}/token",
        UserUrl = $"{server.BaseUrl}/userinfo",
        TokenStyle = tokenStyle
    };

    private static Dictionary<string, string> ParseQuery(string url)
    {
        var parsed = QueryHelpers.ParseQuery(new Uri(url).Query);

        return parsed.ToDictionary(pair => pair.Key, pair => pair.Value.ToString(), StringComparer.Ordinal);
    }

    private static async Task WriteJsonAsync(HttpContext context, string json)
    {
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(json);
    }
}

internal sealed class FakeServer : IAsyncDisposable
{
    private readonly WebApplication _application;

    private FakeServer(WebApplication application, string baseUrl)
    {
        _application = application;
        BaseUrl = baseUrl;
    }

    public string BaseUrl { get; }

    public static async Task<FakeServer> StartAsync(Action<WebApplication> configure)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");

        var application = builder.Build();
        configure(application);
        await application.StartAsync();

        var addresses = application.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>();
        var address = addresses?.Addresses.FirstOrDefault()
            ?? throw new InvalidOperationException("The fake server did not report a listening address.");

        return new FakeServer(application, address.TrimEnd('/'));
    }

    public async ValueTask DisposeAsync()
    {
        await _application.StopAsync();
        await _application.DisposeAsync();
    }
}

internal sealed class OidcServer : IAsyncDisposable
{
    public const string RsaKey1Id = "rsa-key-1";
    public const string RsaKey2Id = "rsa-key-2";
    public const string EcKey1Id = "ec-key-1";

    private readonly FakeServer _server;
    private int _jwksFetches;

    private OidcServer(FakeServer server)
    {
        _server = server;
    }

    public RSA RsaKey { get; } = RSA.Create(2048);

    public RSA RotatedRsaKey { get; } = RSA.Create(2048);

    public ECDsa EcKey { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public string ClientId => "test-client";

    public string BaseUrl => _server.BaseUrl;

    public string Issuer => _server.BaseUrl;

    public string? IssuerOverride { get; set; }

    public List<string>? Algorithms { get; set; }

    public bool DiscoveryFails { get; set; }

    public string? IdToken { get; set; }

    public int JwksFetches => Volatile.Read(ref _jwksFetches);

    public List<JsonObject> Keys { get; } = [];

    public ProviderDefinition Definition => new()
    {
        Name = ProviderDefinition.Oidc,
        ClientId = ClientId,
        ClientSecret = "client-secret",
        IssuerUrl = Issuer
    };

    public static async Task<OidcServer> StartAsync()
    {
        OidcServer? server = null;

        var fake = await FakeServer.StartAsync(app =>
        {
            app.MapGet("/.well-known/openid-configuration", async (HttpContext context) =>
            {
                if (server!.DiscoveryFails)
                {
                    context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                    await context.Response.WriteAsync("discovery unavailable");
                    return;
                }

                var document = new JsonObject
                {
                    ["issuer"] = server.IssuerOverride ?? server.Issuer,
                    ["authorization_endpoint"] = server.BaseUrl + "/authorize",
                    ["token_endpoint"] = server.BaseUrl + "/token",
                    ["jwks_uri"] = server.BaseUrl + "/jwks"
                };

                if (server.Algorithms is { } algorithms)
                {
                    var supported = new JsonArray();

                    foreach (var algorithm in algorithms)
                    {
                        supported.Add(algorithm);
                    }

                    document["id_token_signing_alg_values_supported"] = supported;
                }

                await WriteJsonAsync(context, document.ToJsonString());
            });

            app.MapGet("/jwks", async (HttpContext context) =>
            {
                Interlocked.Increment(ref server!._jwksFetches);

                var keys = new JsonArray();

                foreach (var key in server.Keys)
                {
                    keys.Add(key.DeepClone());
                }

                await WriteJsonAsync(context, new JsonObject { ["keys"] = keys }.ToJsonString());
            });

            app.MapPost("/token", async (HttpContext context) =>
            {
                var document = new JsonObject
                {
                    ["access_token"] = "access-token",
                    ["token_type"] = "Bearer"
                };

                if (server!.IdToken is { } idToken)
                {
                    document["id_token"] = idToken;
                }

                await WriteJsonAsync(context, document.ToJsonString());
            });

            app.MapGet("/authorize", (HttpContext context) => context.Response.WriteAsync("authorize"));
        });

        server = new OidcServer(fake);

        return server;
    }

    public void ServeKeys(params string[] keyIds)
    {
        Keys.Clear();

        foreach (var keyId in keyIds)
        {
            Keys.Add(CreateJwk(keyId));
        }
    }

    public string SignRsa(JsonObject payload, string? keyId = null) =>
        JwtSigner.Create("RS256", keyId ?? RsaKey1Id, payload, RsaKey);

    public async ValueTask DisposeAsync() => await _server.DisposeAsync();

    private JsonObject CreateJwk(string keyId) => keyId switch
    {
        RsaKey1Id => RsaJwk(RsaKey, keyId),
        RsaKey2Id => RsaJwk(RotatedRsaKey, keyId),
        EcKey1Id => EcJwk(EcKey, keyId),
        _ => throw new ArgumentOutOfRangeException(nameof(keyId))
    };

    private static JsonObject RsaJwk(RSA rsa, string keyId)
    {
        var parameters = rsa.ExportParameters(false);

        return new JsonObject
        {
            ["kty"] = "RSA",
            ["kid"] = keyId,
            ["use"] = "sig",
            ["n"] = Base64Url.EncodeToString(parameters.Modulus!),
            ["e"] = Base64Url.EncodeToString(parameters.Exponent!)
        };
    }

    private static JsonObject EcJwk(ECDsa ecdsa, string keyId)
    {
        var parameters = ecdsa.ExportParameters(false);

        return new JsonObject
        {
            ["kty"] = "EC",
            ["kid"] = keyId,
            ["use"] = "sig",
            ["crv"] = "P-256",
            ["x"] = Base64Url.EncodeToString(parameters.Q.X!),
            ["y"] = Base64Url.EncodeToString(parameters.Q.Y!)
        };
    }

    private static async Task WriteJsonAsync(HttpContext context, string json)
    {
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(json);
    }
}

internal static class JwtSigner
{
    public static JsonObject Payload(
        string issuer,
        string audience,
        string email = "user@example.com",
        object? emailVerified = null,
        long expiresInSeconds = 300,
        long? notBeforeSeconds = null,
        bool audienceAsArray = false)
    {
        var payload = new JsonObject
        {
            ["iss"] = issuer,
            ["email"] = email,
            ["exp"] = DateTimeOffset.UtcNow.AddSeconds(expiresInSeconds).ToUnixTimeSeconds()
        };

        if (audienceAsArray)
        {
            payload["aud"] = new JsonArray(audience, "other-client");
        }
        else
        {
            payload["aud"] = audience;
        }

        if (emailVerified is bool verified)
        {
            payload["email_verified"] = verified;
        }
        else if (emailVerified is string text)
        {
            payload["email_verified"] = text;
        }

        if (notBeforeSeconds is { } notBefore)
        {
            payload["nbf"] = DateTimeOffset.UtcNow.AddSeconds(notBefore).ToUnixTimeSeconds();
        }

        return payload;
    }

    public static string Create(string algorithm, string? keyId, JsonObject payload, AsymmetricAlgorithm key)
    {
        var signingInput = CreateSigningInput(algorithm, keyId, payload);
        var bytes = Encoding.ASCII.GetBytes(signingInput);

        var signature = algorithm switch
        {
            "RS256" => ((RSA)key).SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            "RS384" => ((RSA)key).SignData(bytes, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
            "RS512" => ((RSA)key).SignData(bytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
            "PS256" => ((RSA)key).SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            "PS384" => ((RSA)key).SignData(bytes, HashAlgorithmName.SHA384, RSASignaturePadding.Pss),
            "PS512" => ((RSA)key).SignData(bytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pss),
            "ES256" => ((ECDsa)key).SignData(bytes, HashAlgorithmName.SHA256),
            "ES384" => ((ECDsa)key).SignData(bytes, HashAlgorithmName.SHA384),
            "ES512" => ((ECDsa)key).SignData(bytes, HashAlgorithmName.SHA512),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported test algorithm.")
        };

        return signingInput + "." + Base64Url.EncodeToString(signature);
    }

    public static string CreateWithAlgorithm(string algorithm, string? keyId, JsonObject payload, byte[]? signature = null)
    {
        var signingInput = CreateSigningInput(algorithm, keyId, payload);

        return signingInput + "." + Base64Url.EncodeToString(signature ?? []);
    }

    private static string CreateSigningInput(string algorithm, string? keyId, JsonObject payload)
    {
        var header = new JsonObject
        {
            ["typ"] = "JWT",
            ["alg"] = algorithm
        };

        if (keyId is not null)
        {
            header["kid"] = keyId;
        }

        var encodedHeader = Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(header));
        var encodedPayload = Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(payload));

        return encodedHeader + "." + encodedPayload;
    }
}
