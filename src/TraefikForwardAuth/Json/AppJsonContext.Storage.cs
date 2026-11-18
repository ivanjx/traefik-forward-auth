using System.Text.Json.Serialization;
using TraefikForwardAuth.Policy;
using TraefikForwardAuth.Storage;

namespace TraefikForwardAuth.Json;

[JsonSerializable(typeof(Dictionary<string, string?>))]
[JsonSerializable(typeof(RuleDefinition))]
[JsonSerializable(typeof(AccessEntry))]
[JsonSerializable(typeof(RuleDeletionDiff))]
internal partial class AppJsonContext;
