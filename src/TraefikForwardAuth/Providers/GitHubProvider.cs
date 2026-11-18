using System.Net.Http.Headers;
using System.Text.Json;
using TraefikForwardAuth.Json;
using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Policy;

namespace TraefikForwardAuth.Providers;

public sealed class GitHubProvider : IProvider
{
    private const string Scope = "user:email";
    private const string DefaultPrompt = "select_account";
    private const string UserAgent = "traefik-forward-auth";

    private readonly ProviderDefinition _definition;
    private readonly IHttpClientFactory _httpClients;
    private readonly GitHubEndpoints _endpoints;
    private readonly TfaLogger _logger;

    public GitHubProvider(
        ProviderDefinition definition,
        IHttpClientFactory httpClients,
        GitHubEndpoints endpoints,
        TfaLogger logger)
    {
        _definition = definition;
        _httpClients = httpClients;
        _endpoints = endpoints;
        _logger = logger;
    }

    public string Name => "github";

    public string GetLoginUrl(string redirectUri, string state)
    {
        // A null prompt shows the GitHub account picker ("select_account"); an empty string omits it.
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

        // Without this GitHub answers with a form-encoded body.
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var response = await client.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"GitHub token endpoint returned {(int)response.StatusCode} {response.ReasonPhrase}: {ProviderUrls.Snippet(body)}");
        }

        TokenResponse? token;

        try
        {
            token = JsonSerializer.Deserialize(body, AppJsonContext.Default.TokenResponse);
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException("GitHub token endpoint returned malformed JSON.", exception);
        }

        if (token is null)
        {
            throw new InvalidOperationException("GitHub token endpoint returned an empty response.");
        }

        // GitHub reports failures such as bad_verification_code with a 200 status.
        if (!string.IsNullOrEmpty(token.Error))
        {
            throw new InvalidOperationException($"GitHub token endpoint returned error '{token.Error}': {token.ErrorDescription}");
        }

        if (string.IsNullOrEmpty(token.AccessToken))
        {
            throw new InvalidOperationException("GitHub token endpoint response did not include an access_token.");
        }

        _logger.Debug("Exchanged GitHub authorization code", ("provider", Name));

        return new ProviderToken(token.AccessToken, null);
    }

    /// <summary>
    /// Returns the account's primary email. GitHub lets users add addresses they do not own,
    /// so the primary email must be verified; otherwise sign-in fails.
    /// </summary>
    public async Task<ProviderUser> GetUserAsync(ProviderToken token, CancellationToken cancellationToken)
    {
        var emails = await FetchEmailsAsync(token.AccessToken, cancellationToken);
        var primary = emails.FirstOrDefault(email => email.Primary);

        if (primary is null || string.IsNullOrEmpty(primary.Email))
        {
            throw new InvalidOperationException("GitHub account does not have a primary email address.");
        }

        if (!primary.Verified)
        {
            throw new InvalidOperationException($"GitHub primary email '{primary.Email}' is not verified.");
        }

        return new ProviderUser(primary.Email, true);
    }

    public async Task<ProviderTestResult> TestConnectionAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var client = _httpClients.CreateClient("providers");
            using var request = CreateApiRequest(_endpoints.EmailsUrl);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

            return ProviderTestResult.Ok(
                $"GitHub emails endpoint responded with {(int)response.StatusCode} {response.ReasonPhrase}.");
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested
            && exception is HttpRequestException or TaskCanceledException)
        {
            return ProviderTestResult.Fail($"GitHub emails endpoint is unreachable: {exception.Message}");
        }
    }

    private async Task<GitHubEmail[]> FetchEmailsAsync(string accessToken, CancellationToken cancellationToken)
    {
        using var client = _httpClients.CreateClient("providers");
        using var request = CreateApiRequest(_endpoints.EmailsUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await client.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"GitHub emails endpoint returned {(int)response.StatusCode} {response.ReasonPhrase}: {ProviderUrls.Snippet(body)}");
        }

        try
        {
            return JsonSerializer.Deserialize(body, AppJsonContext.Default.GitHubEmailArray)
                ?? throw new InvalidOperationException("GitHub emails response was empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException("GitHub emails endpoint returned malformed JSON.", exception);
        }
    }

    /// <summary>The GitHub REST API rejects requests without a User-Agent.</summary>
    private static HttpRequestMessage CreateApiRequest(Uri url)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue(UserAgent, null));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));

        return request;
    }
}
