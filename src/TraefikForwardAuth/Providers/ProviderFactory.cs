using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Policy;

namespace TraefikForwardAuth.Providers;

public sealed class ProviderFactory
{
    private readonly IHttpClientFactory _httpClients;
    private readonly GoogleEndpoints _googleEndpoints;
    private readonly TfaLogger _logger;

    public ProviderFactory(IHttpClientFactory httpClients, GoogleEndpoints googleEndpoints, TfaLogger logger)
    {
        _httpClients = httpClients;
        _googleEndpoints = googleEndpoints;
        _logger = logger;
    }

    public async Task<IProvider?> CreateAsync(ProviderDefinition definition, CancellationToken cancellationToken)
    {
        var errors = definition.ValidationErrors();

        if (errors.Count > 0)
        {
            _logger.Warn(
                "Invalid provider configuration",
                ("provider", definition.Name),
                ("errors", string.Join(" ", errors)));

            return null;
        }

        switch (definition.Name)
        {
            case ProviderDefinition.Google:
                return new GoogleProvider(definition, _httpClients, _googleEndpoints, _logger);

            case ProviderDefinition.GenericOAuth:
                return new GenericOAuthProvider(definition, _httpClients, _logger);

            case ProviderDefinition.Oidc:
                return await OidcProvider.CreateAsync(definition, _httpClients, _logger, cancellationToken);

            default:
                _logger.Warn("Unknown provider", ("provider", definition.Name));
                return null;
        }
    }
}
