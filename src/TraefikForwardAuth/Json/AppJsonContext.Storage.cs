using System.Text.Json.Serialization;
using TraefikForwardAuth.Policy;

namespace TraefikForwardAuth.Json;

[JsonSerializable(typeof(Dictionary<string, string?>))]
[JsonSerializable(typeof(RuleDefinition))]
[JsonSerializable(typeof(AccessEntry))]
internal partial class AppJsonContext;
