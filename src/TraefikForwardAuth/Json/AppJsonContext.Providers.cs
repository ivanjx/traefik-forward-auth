using System.Text.Json.Serialization;
using TraefikForwardAuth.Providers;

namespace TraefikForwardAuth.Json;

[JsonSerializable(typeof(TokenResponse))]
[JsonSerializable(typeof(UserInfo))]
[JsonSerializable(typeof(OidcDiscoveryDocument))]
[JsonSerializable(typeof(JwksDocument))]
[JsonSerializable(typeof(JwtHeader))]
[JsonSerializable(typeof(IdTokenPayload))]
internal partial class AppJsonContext : JsonSerializerContext;
