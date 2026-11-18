using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using TraefikForwardAuth.Auth;
using TraefikForwardAuth.Policy;
using TraefikForwardAuth.Rules;
using TraefikForwardAuth.Storage;

namespace TraefikForwardAuth.Admin;

public sealed record LayoutModel
{
    public required string Title { get; init; }

    public required string Active { get; init; }

    public required string AdminEmail { get; init; }

    public required string AntiforgeryToken { get; init; }

    public string? Flash { get; init; }

    public bool FlashIsError { get; init; }
}

public sealed record SettingsPageModel
{
    public required LayoutModel Layout { get; init; }

    public required PolicySettings Settings { get; init; }
}

public sealed record ProviderRow(string Name, string Label, bool HasSecret, string ClientId);

public sealed record ProvidersPageModel
{
    public required LayoutModel Layout { get; init; }

    public required IReadOnlyList<ProviderRow> Providers { get; init; }
}

public sealed record ProviderEditPageModel
{
    public required LayoutModel Layout { get; init; }

    public required ProviderDefinition Provider { get; init; }

    public required bool Exists { get; init; }

    /// <summary>Whether a secret is stored; the submitted <see cref="Provider"/> carries a blank secret after a failed save.</summary>
    public required bool HasStoredSecret { get; init; }
}

public sealed record ProviderTestModel(string ProviderName, bool Success, string Message);

public sealed record RuleRow(
    string Id,
    string Name,
    RuleAction Action,
    string Provider,
    bool Enabled,
    string Summary,
    bool IsFirst,
    bool IsLast);

public sealed record RulesPageModel
{
    public required LayoutModel Layout { get; init; }

    public required IReadOnlyList<RuleRow> Rules { get; init; }
}

public sealed record FieldOption(string Value, string Label);

public sealed record OperatorOption(string Value, string Label);

public sealed record ConditionRowModel
{
    public required int Index { get; init; }

    public required IReadOnlyList<FieldOption> Fields { get; init; }

    public required IReadOnlyList<OperatorOption> Operators { get; init; }

    public required ConditionField Field { get; init; }

    public required ConditionOperator Operator { get; init; }

    public required string Name { get; init; }

    public required IReadOnlyList<string> Values { get; init; }

    public bool Negated { get; init; }

    public string ValuesText => string.Join('\n', Values);
}

public sealed record RuleEditPageModel
{
    public required LayoutModel Layout { get; init; }

    public required RuleDefinition Rule { get; init; }

    public required bool IsNew { get; init; }

    public required IReadOnlyList<string> ProviderNames { get; init; }

    public required IReadOnlyList<string> Errors { get; init; }

    public required string Summary { get; init; }

    public required IReadOnlyList<ConditionRowModel> Conditions { get; init; }

    public required int NextConditionIndex { get; init; }

    public required IReadOnlyList<AccessEntry> AccessEntries { get; init; }
}

public sealed record RulePreviewModel
{
    public required string Summary { get; init; }

    public required IReadOnlyList<string> Errors { get; init; }
}

public sealed record AccessGroup(string RuleId, string RuleName, IReadOnlyList<AccessEntry> Entries);

public sealed record AccessPageModel
{
    public required LayoutModel Layout { get; init; }

    public required IReadOnlyList<AccessEntry> GlobalEntries { get; init; }

    public required IReadOnlyList<AccessGroup> RuleGroups { get; init; }

    public required IReadOnlyList<RuleDefinition> Rules { get; init; }

    public string? SelectedRuleId { get; init; }
}

public sealed record AccessTableModel
{
    public required IReadOnlyList<AccessEntry> Entries { get; init; }

    public required string AntiforgeryToken { get; init; }

    public required string EmptyText { get; init; }
}

public sealed record SessionsPageModel
{
    public required LayoutModel Layout { get; init; }

    public required IReadOnlyList<SessionRecord> Sessions { get; init; }

    public string? EmailFilter { get; init; }

    public string? CurrentSessionId { get; init; }

    public required bool AdminSessions { get; init; }
}

public sealed record AuditPageModel
{
    public required LayoutModel Layout { get; init; }

    public required IReadOnlyList<AuditEntry> Entries { get; init; }
}

public sealed record NotFoundPageModel
{
    public required LayoutModel Layout { get; init; }
}

public sealed record SimulateResultModel
{
    public RequestDescriptor? Request { get; init; }

    public SimulationResult? Result { get; init; }

    public string? Error { get; init; }
}

public static class AdminUi
{
    public static readonly IReadOnlyList<FieldOption> ConditionFields =
    [
        new("host", "Host"),
        new("path", "Path"),
        new("method", "Method"),
        new("header", "Header"),
        new("query", "Query parameter")
    ];

    public static readonly IReadOnlyList<string> HttpMethods =
        ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

    public static readonly IReadOnlyList<string> ProviderTypes =
        [ProviderDefinition.Google, ProviderDefinition.Oidc, ProviderDefinition.GenericOAuth];

    public static IReadOnlyList<OperatorOption> OperatorsFor(ConditionField field) => field switch
    {
        ConditionField.Host =>
        [
            new("is", "is"),
            new("matcheswildcard", "matches wildcard")
        ],
        ConditionField.Path =>
        [
            new("is", "is"),
            new("startswith", "starts with"),
            new("matchespattern", "matches pattern")
        ],
        ConditionField.Method =>
        [
            new("is", "is")
        ],
        ConditionField.Header =>
        [
            new("is", "equals"),
            new("contains", "contains"),
            new("exists", "exists"),
            new("matchesregex", "matches regex")
        ],
        ConditionField.Query =>
        [
            new("is", "equals"),
            new("exists", "exists")
        ],
        _ => [new("is", "is")]
    };

    public static ConditionOperator DefaultOperator(ConditionField field) => field switch
    {
        ConditionField.Host => ConditionOperator.Is,
        ConditionField.Path => ConditionOperator.Is,
        ConditionField.Method => ConditionOperator.Is,
        ConditionField.Header => ConditionOperator.Is,
        ConditionField.Query => ConditionOperator.Is,
        _ => ConditionOperator.Is
    };

    public static bool IsOperatorAllowed(ConditionField field, ConditionOperator @operator) =>
        OperatorsFor(field).Any(option => option.Value == OperatorValue(@operator));

    public static string OperatorValue(ConditionOperator @operator) => @operator.ToString().ToLowerInvariant();

    public static string FieldValue(ConditionField field) => field.ToString().ToLowerInvariant();

    public static string ActionLabel(RuleAction action) =>
        action == RuleAction.Allow ? "Allow without login" : "Require login";

    public static string Label(ProviderDefinition definition) => definition.Name switch
    {
        ProviderDefinition.Google => "Google",
        ProviderDefinition.Oidc => "OpenID Connect",
        ProviderDefinition.GenericOAuth => "Generic OAuth2",
        _ => definition.Name
    };

    /// <summary>Pretty-prints stored JSON for display. Escaping is relaxed because Razor HTML-encodes the result.</summary>
    public static string FormatJson(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            using var buffer = new MemoryStream();

            using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
            {
                document.WriteTo(writer);
            }

            return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
        }
        catch (JsonException)
        {
            return json;
        }
    }

    public static string Time(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);

    public static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    public static IReadOnlyList<string> SplitValues(string? text, bool whitespaceToo)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return [];
        }

        var separators = whitespaceToo
            ? new[] { ',', '\n', '\r', ' ', '\t' }
            : new[] { ',', '\n', '\r' };

        return text
            .Split(separators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(value => value.Length > 0)
            .ToArray();
    }

    public static ConditionRowModel ConditionRow(int index, ConditionField field, ConditionOperator @operator, string? name, IReadOnlyList<string> values, bool negated)
    {
        if (!IsOperatorAllowed(field, @operator))
        {
            @operator = DefaultOperator(field);
        }

        return new ConditionRowModel
        {
            Index = index,
            Fields = ConditionFields,
            Operators = OperatorsFor(field),
            Field = field,
            Operator = @operator,
            Name = name ?? "",
            Values = values,
            Negated = negated
        };
    }
}
