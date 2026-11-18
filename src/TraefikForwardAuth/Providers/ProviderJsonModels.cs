using System.Text.Json;
using System.Text.Json.Serialization;

namespace TraefikForwardAuth.Providers;

internal sealed class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string? AccessToken { get; init; }

    [JsonPropertyName("id_token")]
    public string? IdToken { get; init; }

    [JsonPropertyName("token_type")]
    public string? TokenType { get; init; }

    [JsonPropertyName("error")]
    public string? Error { get; init; }

    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; init; }
}

internal sealed class UserInfo
{
    [JsonPropertyName("email")]
    public string? Email { get; init; }

    [JsonPropertyName("verified_email")]
    public bool? VerifiedEmail { get; init; }
}

internal sealed class GitHubEmail
{
    [JsonPropertyName("email")]
    public string? Email { get; init; }

    [JsonPropertyName("primary")]
    public bool Primary { get; init; }

    [JsonPropertyName("verified")]
    public bool Verified { get; init; }
}

internal sealed class OidcDiscoveryDocument
{
    [JsonPropertyName("issuer")]
    public string? Issuer { get; init; }

    [JsonPropertyName("authorization_endpoint")]
    public string? AuthorizationEndpoint { get; init; }

    [JsonPropertyName("token_endpoint")]
    public string? TokenEndpoint { get; init; }

    [JsonPropertyName("jwks_uri")]
    public string? JwksUri { get; init; }

    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public List<string>? IdTokenSigningAlgValuesSupported { get; init; }
}

internal sealed class JwksDocument
{
    [JsonPropertyName("keys")]
    public List<Jwk>? Keys { get; init; }
}

internal sealed class Jwk
{
    [JsonPropertyName("kty")]
    public string? Kty { get; init; }

    [JsonPropertyName("kid")]
    public string? Kid { get; init; }

    [JsonPropertyName("alg")]
    public string? Alg { get; init; }

    [JsonPropertyName("use")]
    public string? Use { get; init; }

    [JsonPropertyName("crv")]
    public string? Curve { get; init; }

    [JsonPropertyName("n")]
    public string? Modulus { get; init; }

    [JsonPropertyName("e")]
    public string? Exponent { get; init; }

    [JsonPropertyName("x")]
    public string? X { get; init; }

    [JsonPropertyName("y")]
    public string? Y { get; init; }
}

internal sealed class JwtHeader
{
    [JsonPropertyName("alg")]
    public string? Algorithm { get; init; }

    [JsonPropertyName("kid")]
    public string? KeyId { get; init; }
}

internal sealed class IdTokenPayload
{
    [JsonPropertyName("iss")]
    public string? Issuer { get; init; }

    [JsonPropertyName("aud")]
    [JsonConverter(typeof(StringOrArrayConverter))]
    public string[]? Audience { get; init; }

    [JsonPropertyName("exp")]
    [JsonConverter(typeof(NumericDateConverter))]
    public long? Expires { get; init; }

    [JsonPropertyName("nbf")]
    [JsonConverter(typeof(NumericDateConverter))]
    public long? NotBefore { get; init; }

    [JsonPropertyName("iat")]
    [JsonConverter(typeof(NumericDateConverter))]
    public long? IssuedAt { get; init; }

    [JsonPropertyName("email")]
    public string? Email { get; init; }

    [JsonPropertyName("email_verified")]
    [JsonConverter(typeof(BoolOrStringConverter))]
    public bool? EmailVerified { get; init; }
}

/// <summary>Reads an "aud" claim that may be a single string or an array of strings.</summary>
internal sealed class StringOrArrayConverter : JsonConverter<string[]>
{
    public override string[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) => reader.TokenType switch
    {
        JsonTokenType.String => [ReadString(ref reader)],
        JsonTokenType.StartArray => ReadArray(ref reader),
        JsonTokenType.Null => [],
        _ => throw new JsonException("Expected a string or an array of strings.")
    };

    public override void Write(Utf8JsonWriter writer, string[] value, JsonSerializerOptions options)
    {
        writer.WriteStartArray();

        foreach (var item in value)
        {
            writer.WriteStringValue(item);
        }

        writer.WriteEndArray();
    }

    private static string ReadString(ref Utf8JsonReader reader) =>
        reader.GetString() ?? throw new JsonException("Expected a non-null audience string.");

    private static string[] ReadArray(ref Utf8JsonReader reader)
    {
        var values = new List<string>();

        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.EndArray:
                    return [.. values];
                case JsonTokenType.String:
                    values.Add(ReadString(ref reader));
                    break;
                default:
                    throw new JsonException("Expected an array of audience strings.");
            }
        }

        throw new JsonException("Unexpected end of JSON while reading the audience claim.");
    }
}

/// <summary>Reads an "email_verified" claim that may be a boolean or the string "true"/"false".</summary>
internal sealed class BoolOrStringConverter : JsonConverter<bool?>
{
    public override bool? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) => reader.TokenType switch
    {
        JsonTokenType.True => true,
        JsonTokenType.False => false,
        JsonTokenType.Null => null,
        JsonTokenType.String => ParseString(reader.GetString()),
        _ => throw new JsonException("Expected a boolean or a string boolean.")
    };

    public override void Write(Utf8JsonWriter writer, bool? value, JsonSerializerOptions options)
    {
        if (value is { } boolean)
        {
            writer.WriteBooleanValue(boolean);
        }
        else
        {
            writer.WriteNullValue();
        }
    }

    private static bool ParseString(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "true" => true,
        "false" => false,
        _ => throw new JsonException("Expected the string \"true\" or \"false\".")
    };
}

/// <summary>Reads a NumericDate claim ("exp", "nbf", "iat") that may be an integer or a fractional number of seconds.</summary>
internal sealed class NumericDateConverter : JsonConverter<long?>
{
    public override long? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        if (reader.TokenType != JsonTokenType.Number)
        {
            throw new JsonException("Expected a numeric date.");
        }

        if (reader.TryGetInt64(out var seconds))
        {
            return seconds;
        }

        var fractional = reader.GetDouble();

        if (!double.IsFinite(fractional) || fractional < long.MinValue || fractional >= long.MaxValue)
        {
            throw new JsonException("Numeric date is out of range.");
        }

        return (long)fractional;
    }

    public override void Write(Utf8JsonWriter writer, long? value, JsonSerializerOptions options)
    {
        if (value is { } seconds)
        {
            writer.WriteNumberValue(seconds);
        }
        else
        {
            writer.WriteNullValue();
        }
    }
}
