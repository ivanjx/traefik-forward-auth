using System.Text.Json;
using TraefikForwardAuth.Json;
using TraefikForwardAuth.Logging;

namespace TraefikForwardAuth.Providers.Oidc;

internal sealed record OidcProviderMetadata(
    string Issuer,
    Uri AuthorizationEndpoint,
    Uri TokenEndpoint,
    Uri JwksUri,
    IReadOnlyList<string> AllowedAlgorithms);

internal static class OidcDiscovery
{
    /// <summary>OIDC issuers are compared and combined without a trailing slash.</summary>
    public static string NormalizeIssuer(string issuer) => issuer.TrimEnd('/');

    public static Uri DiscoveryUrl(string issuer) =>
        new(NormalizeIssuer(issuer) + "/.well-known/openid-configuration", UriKind.Absolute);

    public static async Task<OidcProviderMetadata> DiscoverAsync(
        string issuer,
        IHttpClientFactory httpClients,
        TfaLogger logger,
        CancellationToken cancellationToken)
    {
        var normalizedIssuer = NormalizeIssuer(issuer);

        if (!Uri.TryCreate(normalizedIssuer, UriKind.Absolute, out var issuerUri)
            || (issuerUri.Scheme != Uri.UriSchemeHttp && issuerUri.Scheme != Uri.UriSchemeHttps))
        {
            throw new InvalidOperationException($"OIDC issuer '{issuer}' is not an absolute HTTP(S) URL.");
        }

        var discoveryUrl = DiscoveryUrl(normalizedIssuer);
        string body;

        try
        {
            using var client = httpClients.CreateClient("providers");
            using var response = await client.GetAsync(discoveryUrl, cancellationToken);
            body = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException(
                    $"OIDC discovery request to {discoveryUrl} returned {(int)response.StatusCode} {response.ReasonPhrase}: {ProviderUrls.Snippet(body)}");
            }
        }
        catch (HttpRequestException exception)
        {
            throw new InvalidOperationException(
                $"OIDC discovery request to {discoveryUrl} failed: {exception.Message}", exception);
        }
        catch (TaskCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            throw new InvalidOperationException($"OIDC discovery request to {discoveryUrl} timed out.", exception);
        }

        OidcDiscoveryDocument? document;

        try
        {
            document = JsonSerializer.Deserialize(body, AppJsonContext.Default.OidcDiscoveryDocument);
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException($"OIDC discovery document from {discoveryUrl} is not valid JSON.", exception);
        }

        if (document is null)
        {
            throw new InvalidOperationException($"OIDC discovery document from {discoveryUrl} is empty.");
        }

        if (string.IsNullOrWhiteSpace(document.Issuer))
        {
            throw new InvalidOperationException($"OIDC discovery document from {discoveryUrl} is missing the issuer.");
        }

        if (!string.Equals(NormalizeIssuer(document.Issuer), normalizedIssuer, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"OIDC discovery issuer '{document.Issuer}' does not match the configured issuer '{issuer}'.");
        }

        var metadata = new OidcProviderMetadata(
            normalizedIssuer,
            RequireEndpoint(document.AuthorizationEndpoint, "authorization_endpoint", discoveryUrl),
            RequireEndpoint(document.TokenEndpoint, "token_endpoint", discoveryUrl),
            RequireEndpoint(document.JwksUri, "jwks_uri", discoveryUrl),
            document.IdTokenSigningAlgValuesSupported ?? []);

        logger.Debug("Loaded OIDC discovery document", ("issuer", normalizedIssuer));

        return metadata;
    }

    private static Uri RequireEndpoint(string? value, string name, Uri discoveryUrl)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"OIDC discovery document from {discoveryUrl} is missing {name}.");
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new InvalidOperationException(
                $"OIDC discovery document from {discoveryUrl} has an invalid {name} '{value}'.");
        }

        return uri;
    }
}
