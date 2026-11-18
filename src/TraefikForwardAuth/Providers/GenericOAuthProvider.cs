using System.Net.Http.Headers;
using System.Text.Json;
using TraefikForwardAuth.Json;
using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Policy;

namespace TraefikForwardAuth.Providers;

public sealed class GenericOAuthProvider : IProvider
{
    private static readonly string[] DefaultScopes = ["profile", "email"];
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(5);

    private readonly ProviderDefinition _definition;
    private readonly IHttpClientFactory _httpClients;
    private readonly OAuth2Client _client;
    private readonly IReadOnlyList<string> _scopes;
    private readonly Uri _authUrl;
    private readonly Uri _tokenUrl;
    private readonly Uri _userUrl;
    private readonly TfaLogger _logger;

    public GenericOAuthProvider(
        ProviderDefinition definition,
        IHttpClientFactory httpClients,
        TfaLogger logger)
    {
        _definition = definition;
        _httpClients = httpClients;
        _logger = logger;
        _client = new OAuth2Client(httpClients, definition.ClientId, definition.ClientSecret);
        _scopes = definition.Scopes.Count > 0 ? definition.Scopes : DefaultScopes;
        _authUrl = new Uri(definition.AuthUrl!, UriKind.Absolute);
        _tokenUrl = new Uri(definition.TokenUrl!, UriKind.Absolute);
        _userUrl = new Uri(definition.UserUrl!, UriKind.Absolute);
    }

    public string Name => "generic-oauth";

    public string GetLoginUrl(string redirectUri, string state) => ProviderUrls.WithQuery(
        _authUrl,
        ("client_id", _definition.ClientId),
        ("response_type", "code"),
        ("scope", string.Join(' ', _scopes)),
        ("redirect_uri", redirectUri),
        ("state", state),
        ("resource", string.IsNullOrEmpty(_definition.Resource) ? null : _definition.Resource));

    public Task<ProviderToken> ExchangeCodeAsync(string redirectUri, string code, CancellationToken cancellationToken) =>
        _client.ExchangeCodeAsync(_tokenUrl, redirectUri, code, cancellationToken);

    public async Task<ProviderUser> GetUserAsync(ProviderToken token, CancellationToken cancellationToken)
    {
        var userUrl = _definition.TokenStyle == "query"
            ? new Uri(ProviderUrls.WithQuery(_userUrl, ("access_token", token.AccessToken)), UriKind.Absolute)
            : _userUrl;

        using var client = _httpClients.CreateClient("providers");
        using var request = new HttpRequestMessage(HttpMethod.Get, userUrl);

        if (_definition.TokenStyle != "query")
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
        }

        using var response = await client.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"User info endpoint returned {(int)response.StatusCode} {response.ReasonPhrase}: {ProviderUrls.Snippet(body)}");
        }

        UserInfo? user;

        try
        {
            user = JsonSerializer.Deserialize(body, AppJsonContext.Default.UserInfo);
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException("User info endpoint returned malformed JSON.", exception);
        }

        if (user is null || string.IsNullOrEmpty(user.Email))
        {
            throw new InvalidOperationException("User info response did not contain an email address.");
        }

        return new ProviderUser(user.Email, false);
    }

    public async Task<ProviderTestResult> TestConnectionAsync(CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TestTimeout);

        try
        {
            using var client = _httpClients.CreateClient("providers");
            using var request = new HttpRequestMessage(HttpMethod.Head, _authUrl);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);

            _logger.Debug("Generic OAuth auth endpoint responded", ("provider", Name), ("status", (int)response.StatusCode));

            return ProviderTestResult.Ok(
                $"Authorization endpoint responded with {(int)response.StatusCode} {response.ReasonPhrase}.");
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested
            && exception is HttpRequestException or TaskCanceledException)
        {
            return ProviderTestResult.Fail($"Authorization endpoint is unreachable: {exception.Message}");
        }
    }
}
