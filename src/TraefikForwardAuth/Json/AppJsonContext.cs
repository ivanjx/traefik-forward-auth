using System.Text.Json.Serialization;
using TraefikForwardAuth.Policy;

namespace TraefikForwardAuth.Json;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(List<ConditionDefinition>))]
[JsonSerializable(typeof(List<string>))]
internal partial class AppJsonContext : JsonSerializerContext;
