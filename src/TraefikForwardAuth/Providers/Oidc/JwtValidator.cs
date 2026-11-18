using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using TraefikForwardAuth.Json;

namespace TraefikForwardAuth.Providers.Oidc;

/// <summary>Validates OIDC ID tokens (compact JWS) against the discovered issuer, client and JWKS.</summary>
internal sealed class JwtValidator
{
    private const long ClockSkewSeconds = 60;
    private const string GoogleIssuerUrl = "https://accounts.google.com";
    private const string GoogleIssuerHost = "accounts.google.com";

    private readonly string _issuer;
    private readonly string _clientId;
    private readonly IReadOnlyList<string> _algorithms;
    private readonly JwksCache _keys;

    public JwtValidator(OidcProviderMetadata metadata, string clientId, JwksCache keys)
    {
        _issuer = OidcDiscovery.NormalizeIssuer(metadata.Issuer);
        _clientId = clientId;
        _algorithms = SupportedAlgorithms(metadata.AllowedAlgorithms);
        _keys = keys;
    }

    /// <summary>Keeps only the discovered algorithms this validator implements, falling back to RS256 like go-oidc.</summary>
    private static IReadOnlyList<string> SupportedAlgorithms(IReadOnlyList<string> discovered)
    {
        var supported = discovered.Where(algorithm => GetSignatureKind(algorithm) is not null).ToArray();

        return supported.Length > 0 ? supported : ["RS256"];
    }

    public async Task<ProviderUser> ValidateAsync(string token, CancellationToken cancellationToken)
    {
        var parts = token.Split('.');

        if (parts.Length != 3)
        {
            throw new InvalidOperationException("ID token is not a compact JWS.");
        }

        var header = ParsePart(parts[0], AppJsonContext.Default.JwtHeader, "header");
        var algorithm = header.Algorithm;

        if (string.IsNullOrEmpty(algorithm))
        {
            throw new InvalidOperationException("ID token header is missing the alg field.");
        }

        if (algorithm == "none" || algorithm.StartsWith("HS", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"ID token algorithm '{algorithm}' is not allowed.");
        }

        if (!_algorithms.Contains(algorithm, StringComparer.Ordinal))
        {
            throw new InvalidOperationException(
                $"ID token algorithm '{algorithm}' is not in the issuer's supported algorithms.");
        }

        var signatureKind = GetSignatureKind(algorithm)
            ?? throw new InvalidOperationException($"ID token algorithm '{algorithm}' is not supported.");

        var payload = ParsePart(parts[1], AppJsonContext.Default.IdTokenPayload, "payload");
        var signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        var signature = Decode(parts[2], "signature");
        var keyId = string.IsNullOrEmpty(header.KeyId) ? null : header.KeyId;
        var keys = await _keys.GetKeysAsync(cancellationToken);

        if (!TryVerify(keys, keyId, algorithm, signatureKind, signingInput, signature, out _))
        {
            // The cached keys may predate a rotation (with or without a kid), so refetch once and retry.
            keys = await _keys.RefetchAsync(keys, cancellationToken);

            if (!TryVerify(keys, keyId, algorithm, signatureKind, signingInput, signature, out var hadCandidates))
            {
                throw new InvalidOperationException(hadCandidates
                    ? "ID token signature verification failed."
                    : $"No JWKS signing key matches the ID token (kid '{keyId ?? "<none>"}', alg '{algorithm}').");
            }
        }

        ValidateClaims(payload);

        if (string.IsNullOrWhiteSpace(payload.Email))
        {
            throw new InvalidOperationException("ID token does not contain an email claim.");
        }

        return new ProviderUser(payload.Email, payload.EmailVerified ?? false);
    }

    private static bool TryVerify(
        IReadOnlyList<JwkKey> keys,
        string? keyId,
        string algorithm,
        SignatureKind signatureKind,
        byte[] signingInput,
        byte[] signature,
        out bool hadCandidates)
    {
        var candidates = Filter(keys, keyId, algorithm, signatureKind);
        hadCandidates = candidates.Count > 0;

        foreach (var candidate in candidates)
        {
            if (Verify(candidate, signatureKind, signingInput, signature))
            {
                return true;
            }
        }

        return false;
    }

    private static List<JwkKey> Filter(
        IReadOnlyList<JwkKey> keys,
        string? keyId,
        string algorithm,
        SignatureKind signatureKind)
    {
        var candidates = new List<JwkKey>();

        foreach (var key in keys)
        {
            if (keyId is not null && !string.Equals(key.KeyId, keyId, StringComparison.Ordinal))
            {
                continue;
            }

            if (key.Algorithm is not null && !string.Equals(key.Algorithm, algorithm, StringComparison.Ordinal))
            {
                continue;
            }

            if (signatureKind.IsRsa)
            {
                if (key.Rsa is null)
                {
                    continue;
                }
            }
            else
            {
                if (key.Ec is null || !string.Equals(key.Curve, signatureKind.CurveName, StringComparison.Ordinal))
                {
                    continue;
                }
            }

            candidates.Add(key);
        }

        return candidates;
    }

    private static bool Verify(
        JwkKey key,
        SignatureKind signatureKind,
        byte[] signingInput,
        byte[] signature)
    {
        try
        {
            if (signatureKind.IsRsa)
            {
                using var rsa = RSA.Create();
                rsa.ImportParameters(key.Rsa!.Value);

                return rsa.VerifyData(
                    signingInput,
                    signature,
                    signatureKind.Hash,
                    signatureKind.Pss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
            }

            using var ecdsa = ECDsa.Create(key.Ec!.Value);

            return ecdsa.VerifyData(signingInput, signature, signatureKind.Hash);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private void ValidateClaims(IdTokenPayload payload)
    {
        if (!IsExpectedIssuer(payload.Issuer))
        {
            throw new InvalidOperationException(
                $"ID token issuer '{payload.Issuer}' does not match the expected issuer '{_issuer}'.");
        }

        if (payload.Audience is null || !payload.Audience.Contains(_clientId, StringComparer.Ordinal))
        {
            throw new InvalidOperationException(
                $"ID token audience does not contain the client ID '{_clientId}'.");
        }

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        if (payload.Expires is not { } expires)
        {
            throw new InvalidOperationException("ID token is missing the exp claim.");
        }

        if (expires + ClockSkewSeconds <= now)
        {
            throw new InvalidOperationException("ID token has expired.");
        }

        if (payload.NotBefore is { } notBefore && notBefore > now + ClockSkewSeconds)
        {
            throw new InvalidOperationException("ID token is not valid yet.");
        }
    }

    private bool IsExpectedIssuer(string? issuer)
    {
        if (OidcDiscovery.NormalizeIssuer(issuer ?? "") == _issuer)
        {
            return true;
        }

        // Google issues ID tokens with either form of its issuer (same exception as go-oidc).
        return _issuer == GoogleIssuerUrl && issuer == GoogleIssuerHost;
    }

    private static T ParsePart<T>(string part, JsonTypeInfo<T> typeInfo, string name)
    {
        var bytes = Decode(part, name);

        try
        {
            var value = JsonSerializer.Deserialize(bytes, typeInfo);

            return value ?? throw new InvalidOperationException($"ID token {name} is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException($"ID token {name} is not a valid JSON object.", exception);
        }
    }

    private static byte[] Decode(string part, string name)
    {
        if (part.Length == 0)
        {
            throw new InvalidOperationException($"ID token {name} is empty.");
        }

        try
        {
            return Base64Url.DecodeFromChars(part);
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException($"ID token {name} is not valid base64url.", exception);
        }
    }

    private static SignatureKind? GetSignatureKind(string algorithm) => algorithm switch
    {
        "RS256" => new SignatureKind(true, false, HashAlgorithmName.SHA256, null),
        "RS384" => new SignatureKind(true, false, HashAlgorithmName.SHA384, null),
        "RS512" => new SignatureKind(true, false, HashAlgorithmName.SHA512, null),
        "PS256" => new SignatureKind(true, true, HashAlgorithmName.SHA256, null),
        "PS384" => new SignatureKind(true, true, HashAlgorithmName.SHA384, null),
        "PS512" => new SignatureKind(true, true, HashAlgorithmName.SHA512, null),
        "ES256" => new SignatureKind(false, false, HashAlgorithmName.SHA256, "P-256"),
        "ES384" => new SignatureKind(false, false, HashAlgorithmName.SHA384, "P-384"),
        "ES512" => new SignatureKind(false, false, HashAlgorithmName.SHA512, "P-521"),
        _ => null
    };

    private sealed record SignatureKind(bool IsRsa, bool Pss, HashAlgorithmName Hash, string? CurveName);
}
