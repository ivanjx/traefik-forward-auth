using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using TraefikForwardAuth.Json;

namespace TraefikForwardAuth.Providers;

/// <summary>
/// OAuth2 authorization-code token client. Mirrors golang.org/x/oauth2's auth-style detection:
/// the first attempt sends the client credentials in an HTTP Basic header, and a non-success
/// response is retried with the credentials in the form body.
/// </summary>
public sealed class OAuth2Client
{
    private readonly IHttpClientFactory _httpClients;
    private readonly string _clientId;
    private readonly string _clientSecret;

    public OAuth2Client(IHttpClientFactory httpClients, string clientId, string clientSecret)
    {
        _httpClients = httpClients;
        _clientId = clientId;
        _clientSecret = clientSecret;
    }

    public async Task<ProviderToken> ExchangeCodeAsync(
        Uri tokenEndpoint,
        string redirectUri,
        string code,
        CancellationToken cancellationToken)
    {
        var first = await SendAsync(tokenEndpoint, redirectUri, code, useBasicAuth: true, cancellationToken);

        if (first.Success)
        {
            return ParseToken(first);
        }

        var second = await SendAsync(tokenEndpoint, redirectUri, code, useBasicAuth: false, cancellationToken);

        if (!second.Success)
        {
            throw new InvalidOperationException(
                $"Token endpoint '{tokenEndpoint}' returned {second.StatusCode} {second.ReasonPhrase}: {ProviderUrls.Snippet(second.Body)}");
        }

        return ParseToken(second);
    }

    private async Task<TokenHttpResult> SendAsync(
        Uri tokenEndpoint,
        string redirectUri,
        string code,
        bool useBasicAuth,
        CancellationToken cancellationToken)
    {
        var parameters = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "authorization_code"),
            new("code", code),
            new("redirect_uri", redirectUri)
        };

        using var client = _httpClients.CreateClient("providers");
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);

        if (useBasicAuth)
        {
            // oauth2 encodes the credentials with QueryEscape before base64-encoding them.
            var credentials = WebUtility.UrlEncode(_clientId) + ":" + WebUtility.UrlEncode(_clientSecret);
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials)));
        }
        else
        {
            parameters.Add(new("client_id", _clientId));
            parameters.Add(new("client_secret", _clientSecret));
        }

        request.Content = new FormUrlEncodedContent(parameters);

        using var response = await client.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        return new TokenHttpResult(
            response.IsSuccessStatusCode,
            (int)response.StatusCode,
            response.ReasonPhrase,
            response.Content.Headers.ContentType?.MediaType,
            body);
    }

    private static ProviderToken ParseToken(TokenHttpResult result)
    {
        TokenResponse? token;

        if (LooksLikeJson(result))
        {
            try
            {
                token = JsonSerializer.Deserialize(result.Body, AppJsonContext.Default.TokenResponse);
            }
            catch (JsonException exception)
            {
                throw new InvalidOperationException("Token endpoint returned malformed JSON.", exception);
            }
        }
        else
        {
            token = ParseForm(result.Body);
        }

        if (token is null)
        {
            throw new InvalidOperationException("Token endpoint returned an empty response.");
        }

        if (!string.IsNullOrEmpty(token.Error))
        {
            var description = string.IsNullOrEmpty(token.ErrorDescription) ? "" : $": {token.ErrorDescription}";
            throw new InvalidOperationException($"Token endpoint returned error '{token.Error}'{description}");
        }

        if (string.IsNullOrEmpty(token.AccessToken))
        {
            throw new InvalidOperationException("Token endpoint response did not include an access_token.");
        }

        return new ProviderToken(token.AccessToken, token.IdToken);
    }

    private static bool LooksLikeJson(TokenHttpResult result)
    {
        if (result.MediaType is { } mediaType)
        {
            if (mediaType.Contains("json", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (mediaType.Contains("x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return result.Body.TrimStart().StartsWith('{');
    }

    private static TokenResponse ParseForm(string body)
    {
        string? accessToken = null;
        string? idToken = null;
        string? tokenType = null;
        string? error = null;
        string? errorDescription = null;

        foreach (var pair in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = pair.IndexOf('=');
            var key = WebUtility.UrlDecode(separator < 0 ? pair : pair[..separator]);
            var value = separator < 0 ? "" : WebUtility.UrlDecode(pair[(separator + 1)..]);

            switch (key)
            {
                case "access_token":
                    accessToken = value;
                    break;
                case "id_token":
                    idToken = value;
                    break;
                case "token_type":
                    tokenType = value;
                    break;
                case "error":
                    error = value;
                    break;
                case "error_description":
                    errorDescription = value;
                    break;
            }
        }

        return new TokenResponse
        {
            AccessToken = accessToken,
            IdToken = idToken,
            TokenType = tokenType,
            Error = error,
            ErrorDescription = errorDescription
        };
    }

    private sealed record TokenHttpResult(bool Success, int StatusCode, string? ReasonPhrase, string? MediaType, string Body);
}
