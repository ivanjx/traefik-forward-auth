using System.Net.Http.Headers;
using System.Text.Json;
using TraefikForwardAuth.Json;
using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Policy;

namespace TraefikForwardAuth.Providers;

public sealed class GoogleProvider : IProvider
{
    private const string Scope = "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email";
    private const string DefaultPrompt = "select_account";

    private readonly ProviderDefinition _definition;
    private readonly IHttpClientFactory _httpClients;
    private readonly GoogleEndpoints _endpoints;
    private readonly TfaLogger _logger;

    public GoogleProvider(
        ProviderDefinition definition,
        IHttpClientFactory httpClients,
        GoogleEndpoints endpoints,
        TfaLogger logger)
    {
        _definition = definition;
        _httpClients = httpClients;
        _endpoints = endpoints;
        _logger = logger;
    }

    public string Name => "google";

    public string GetLoginUrl(string redirectUri, string state)
    {
        // A null prompt means the Google default ("select_account"); an empty string omits it.
        var prompt = _definition.Prompt ?? DefaultPrompt;

        return ProviderUrls.WithQuery(
            _endpoints.LoginUrl,
            ("client_id", _definition.ClientId),
            ("response_type", "code"),
            ("scope", Scope),
            ("prompt", prompt.Length == 0 ? null : prompt),
            ("redirect_uri", redirectUri),
            ("state", state));
    }

    public async Task<ProviderToken> ExchangeCodeAsync(string redirectUri, string code, CancellationToken cancellationToken)
    {
        using var client = _httpClients.CreateClient("providers");
        using var request = new HttpRequestMessage(HttpMethod.Post, _endpoints.TokenUrl)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = _definition.ClientId,
                ["client_secret"] = _definition.ClientSecret,
                ["grant_type"] = "authorization_code",
                ["redirect_uri"] = redirectUri,
                ["code"] = code
            })
        };

        using var response = await client.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"Google token endpoint returned {(int)response.StatusCode} {response.ReasonPhrase}: {ProviderUrls.Snippet(body)}");
        }

        TokenResponse? token;

        try
        {
            token = JsonSerializer.Deserialize(body, AppJsonContext.Default.TokenResponse);
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException("Google token endpoint returned malformed JSON.", exception);
        }

        if (token is null)
        {
            throw new InvalidOperationException("Google token endpoint returned an empty response.");
        }

        if (!string.IsNullOrEmpty(token.Error))
        {
            throw new InvalidOperationException($"Google token endpoint returned error '{token.Error}': {token.ErrorDescription}");
        }

        if (string.IsNullOrEmpty(token.AccessToken))
        {
            throw new InvalidOperationException("Google token endpoint response did not include an access_token.");
        }

        _logger.Debug("Exchanged Google authorization code", ("provider", Name));

        return new ProviderToken(token.AccessToken, token.IdToken);
    }

    public async Task<ProviderUser> GetUserAsync(ProviderToken token, CancellationToken cancellationToken)
    {
        var user = await FetchUserAsync(token.AccessToken, cancellationToken);

        if (string.IsNullOrEmpty(user.Email))
        {
            throw new InvalidOperationException("Google user info response did not contain an email address.");
        }

        return new ProviderUser(user.Email, user.VerifiedEmail ?? false);
    }

    public async Task<ProviderTestResult> TestConnectionAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var client = _httpClients.CreateClient("providers");
            using var request = new HttpRequestMessage(HttpMethod.Get, _endpoints.UserInfoUrl);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

            return ProviderTestResult.Ok(
                $"Google user info endpoint responded with {(int)response.StatusCode} {response.ReasonPhrase}.");
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested
            && exception is HttpRequestException or TaskCanceledException)
        {
            return ProviderTestResult.Fail($"Google user info endpoint is unreachable: {exception.Message}");
        }
    }

    private async Task<UserInfo> FetchUserAsync(string accessToken, CancellationToken cancellationToken)
    {
        using var client = _httpClients.CreateClient("providers");
        using var request = new HttpRequestMessage(HttpMethod.Get, _endpoints.UserInfoUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await client.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"Google user info endpoint returned {(int)response.StatusCode} {response.ReasonPhrase}: {ProviderUrls.Snippet(body)}");
        }

        try
        {
            return JsonSerializer.Deserialize(body, AppJsonContext.Default.UserInfo)
                ?? throw new InvalidOperationException("Google user info response was empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException("Google user info endpoint returned malformed JSON.", exception);
        }
    }
}
