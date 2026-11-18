using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using TraefikForwardAuth.Json;
using TraefikForwardAuth.Logging;

namespace TraefikForwardAuth.Providers.Oidc;

internal sealed record JwkKey(string? KeyId, string? Algorithm, RSAParameters? Rsa, ECParameters? Ec, string? Curve);

/// <summary>Caches the OIDC JWKS key set, refetching on demand and when the cache expires.</summary>
internal sealed class JwksCache
{
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromMinutes(10);

    private readonly Uri _jwksUri;
    private readonly IHttpClientFactory _httpClients;
    private readonly TfaLogger _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private KeySet? _cache;

    public JwksCache(Uri jwksUri, IHttpClientFactory httpClients, TfaLogger logger)
    {
        _jwksUri = jwksUri;
        _httpClients = httpClients;
        _logger = logger;
    }

    public async Task<IReadOnlyList<JwkKey>> GetKeysAsync(CancellationToken cancellationToken)
    {
        var cache = Volatile.Read(ref _cache);

        if (cache is not null && DateTimeOffset.UtcNow - cache.FetchedAt < CacheLifetime)
        {
            return cache.Keys;
        }

        return await FetchAsync(force: false, cancellationToken);
    }

    public Task<IReadOnlyList<JwkKey>> RefetchAsync(CancellationToken cancellationToken) =>
        FetchAsync(force: true, cancellationToken);

    private async Task<IReadOnlyList<JwkKey>> FetchAsync(bool force, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);

        try
        {
            var cache = Volatile.Read(ref _cache);

            if (!force && cache is not null && DateTimeOffset.UtcNow - cache.FetchedAt < CacheLifetime)
            {
                return cache.Keys;
            }

            var keys = await DownloadAsync(cancellationToken);
            Volatile.Write(ref _cache, new KeySet(keys, DateTimeOffset.UtcNow));
            _logger.Debug("Fetched OIDC JWKS keys", ("jwks_uri", _jwksUri.ToString()), ("keys", keys.Count));

            return keys;
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<IReadOnlyList<JwkKey>> DownloadAsync(CancellationToken cancellationToken)
    {
        string body;

        try
        {
            using var client = _httpClients.CreateClient("providers");
            using var response = await client.GetAsync(_jwksUri, cancellationToken);
            body = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException(
                    $"JWKS request to {_jwksUri} returned {(int)response.StatusCode} {response.ReasonPhrase}: {ProviderUrls.Snippet(body)}");
            }
        }
        catch (HttpRequestException exception)
        {
            throw new InvalidOperationException($"JWKS request to {_jwksUri} failed: {exception.Message}", exception);
        }
        catch (TaskCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            throw new InvalidOperationException($"JWKS request to {_jwksUri} timed out.", exception);
        }

        JwksDocument? document;

        try
        {
            document = JsonSerializer.Deserialize(body, AppJsonContext.Default.JwksDocument);
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException($"JWKS document from {_jwksUri} is not valid JSON.", exception);
        }

        var keys = new List<JwkKey>();

        foreach (var jwk in document?.Keys ?? [])
        {
            if (TryConvert(jwk, out var key))
            {
                keys.Add(key);
            }
        }

        if (keys.Count == 0)
        {
            throw new InvalidOperationException($"JWKS document from {_jwksUri} did not contain any usable signing keys.");
        }

        return keys;
    }

    private static bool TryConvert(Jwk jwk, out JwkKey key)
    {
        key = null!;

        if (string.Equals(jwk.Kty, "RSA", StringComparison.Ordinal))
        {
            if (string.IsNullOrEmpty(jwk.Modulus) || string.IsNullOrEmpty(jwk.Exponent))
            {
                return false;
            }

            try
            {
                key = new JwkKey(
                    jwk.Kid,
                    jwk.Alg,
                    new RSAParameters
                    {
                        Modulus = Base64Url.DecodeFromChars(jwk.Modulus),
                        Exponent = Base64Url.DecodeFromChars(jwk.Exponent)
                    },
                    null,
                    null);

                return true;
            }
            catch (Exception exception) when (exception is FormatException or CryptographicException)
            {
                return false;
            }
        }

        if (string.Equals(jwk.Kty, "EC", StringComparison.Ordinal))
        {
            if (string.IsNullOrEmpty(jwk.Curve) || string.IsNullOrEmpty(jwk.X) || string.IsNullOrEmpty(jwk.Y))
            {
                return false;
            }

            var (knownCurve, curve) = jwk.Curve switch
            {
                "P-256" => (true, ECCurve.NamedCurves.nistP256),
                "P-384" => (true, ECCurve.NamedCurves.nistP384),
                "P-521" => (true, ECCurve.NamedCurves.nistP521),
                _ => (false, default(ECCurve))
            };

            if (!knownCurve)
            {
                return false;
            }

            try
            {
                key = new JwkKey(
                    jwk.Kid,
                    jwk.Alg,
                    null,
                    new ECParameters
                    {
                        Curve = curve,
                        Q = new ECPoint
                        {
                            X = Base64Url.DecodeFromChars(jwk.X),
                            Y = Base64Url.DecodeFromChars(jwk.Y)
                        }
                    },
                    jwk.Curve);

                return true;
            }
            catch (Exception exception) when (exception is FormatException or CryptographicException)
            {
                return false;
            }
        }

        return false;
    }

    private sealed record KeySet(IReadOnlyList<JwkKey> Keys, DateTimeOffset FetchedAt);
}
