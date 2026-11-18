using TraefikForwardAuth.Json;
using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Policy;
using TraefikForwardAuth.Providers.Oidc;

namespace TraefikForwardAuth.Providers;

public sealed class OidcProvider : IProvider
{
    private static readonly string[] Scopes = ["openid", "profile", "email"];

    private readonly string _clientId;
    private readonly OidcProviderMetadata _metadata;
    private readonly OAuth2Client _client;
    private readonly JwtValidator _validator;
    private readonly IHttpClientFactory _httpClients;
    private readonly TfaLogger _logger;

    private OidcProvider(
        string clientId,
        OidcProviderMetadata metadata,
        OAuth2Client client,
        JwtValidator validator,
        IHttpClientFactory httpClients,
        TfaLogger logger)
    {
        _clientId = clientId;
        _metadata = metadata;
        _client = client;
        _validator = validator;
        _httpClients = httpClients;
        _logger = logger;
    }

    public string Name => "oidc";

    public static async Task<OidcProvider> CreateAsync(
        ProviderDefinition definition,
        IHttpClientFactory httpClients,
        TfaLogger logger,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(definition.IssuerUrl))
        {
            throw new InvalidOperationException("OIDC issuer URL is required.");
        }

        var metadata = await OidcDiscovery.DiscoverAsync(definition.IssuerUrl, httpClients, logger, cancellationToken);
        var client = new OAuth2Client(httpClients, definition.ClientId, definition.ClientSecret);
        var keys = new JwksCache(metadata.JwksUri, httpClients, logger);

        return new OidcProvider(
            definition.ClientId,
            metadata,
            client,
            new JwtValidator(metadata, definition.ClientId, keys),
            httpClients,
            logger);
    }

    public string GetLoginUrl(string redirectUri, string state) => ProviderUrls.WithQuery(
        _metadata.AuthorizationEndpoint,
        ("client_id", _clientId),
        ("response_type", "code"),
        ("scope", string.Join(' ', Scopes)),
        ("redirect_uri", redirectUri),
        ("state", state));

    public async Task<ProviderToken> ExchangeCodeAsync(string redirectUri, string code, CancellationToken cancellationToken)
    {
        var token = await _client.ExchangeCodeAsync(_metadata.TokenEndpoint, redirectUri, code, cancellationToken);

        if (string.IsNullOrEmpty(token.IdToken))
        {
            throw new InvalidOperationException("OIDC token response is missing the id_token.");
        }

        return token;
    }

    public async Task<ProviderUser> GetUserAsync(ProviderToken token, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(token.IdToken))
        {
            throw new InvalidOperationException("OIDC provider requires an id_token to read the user.");
        }

        var user = await _validator.ValidateAsync(token.IdToken, cancellationToken);
        _logger.Debug("Validated OIDC ID token", ("provider", Name), ("issuer", _metadata.Issuer));

        return user;
    }

    public async Task<ProviderTestResult> TestConnectionAsync(CancellationToken cancellationToken)
    {
        try
        {
            var metadata = await OidcDiscovery.DiscoverAsync(_metadata.Issuer, _httpClients, _logger, cancellationToken);

            return ProviderTestResult.Ok($"OIDC discovery succeeded for issuer {metadata.Issuer}.");
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            return ProviderTestResult.Fail($"OIDC discovery failed: {exception.Message}");
        }
    }
}
