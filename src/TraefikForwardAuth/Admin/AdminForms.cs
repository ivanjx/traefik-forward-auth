using System.Globalization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using TraefikForwardAuth.Policy;
using TraefikForwardAuth.Rules;

namespace TraefikForwardAuth.Admin;

public sealed record ParsedConditions(
    IReadOnlyList<ConditionDefinition> Conditions,
    IReadOnlyList<string> Errors);

public sealed record ParsedRule(
    RuleDefinition Rule,
    IReadOnlyList<string> Errors);

public static class AdminForms
{
    public const string TokenField = "__RequestVerificationToken";

    public static bool IsChecked(IFormCollection form, string name)
    {
        if (!form.TryGetValue(name, out var values))
        {
            return false;
        }

        foreach (var value in values)
        {
            if (string.Equals(value, "on", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "1", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    public static string Text(IFormCollection form, string name) => form[name].ToString().Trim();

    public static string? OptionalText(IFormCollection form, string name)
    {
        var value = Text(form, name);

        return value.Length == 0 ? null : value;
    }

    public static IReadOnlyList<string> SplitList(IFormCollection form, string name, bool whitespaceToo) =>
        AdminUi.SplitValues(form[name].ToString(), whitespaceToo);

    public static ParsedSettings ParseSettings(IFormCollection form, PolicySettings current)
    {
        var errors = new List<string>();

        var lifetimeText = Text(form, "lifetime_seconds");
        TimeSpan lifetime;

        if (long.TryParse(lifetimeText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds) &&
            seconds is > 0 and <= 31536000)
        {
            lifetime = TimeSpan.FromSeconds(seconds);
        }
        else
        {
            lifetime = current.Lifetime;
            errors.Add("Lifetime must be a whole number of seconds between 1 and 31536000.");
        }

        var actionText = Text(form, "default_action");
        var action = actionText switch
        {
            "allow" => RuleAction.Allow,
            "auth" => RuleAction.Auth,
            _ => current.DefaultAction
        };

        if (actionText is not ("allow" or "auth"))
        {
            errors.Add("Default action must be auth or allow.");
        }

        var providerText = Text(form, "default_provider");
        var provider = AdminUi.ProviderTypes.Contains(providerText, StringComparer.Ordinal)
            ? providerText
            : current.DefaultProvider;

        if (!AdminUi.ProviderTypes.Contains(providerText, StringComparer.Ordinal))
        {
            errors.Add("Default provider must be google, oidc or generic-oauth.");
        }

        var settings = current with
        {
            CookieName = Text(form, "cookie_name"),
            CsrfCookieName = Text(form, "csrf_cookie_name"),
            CookieDomains = SplitList(form, "cookie_domains", whitespaceToo: false),
            AuthHost = Text(form, "auth_host"),
            InsecureCookie = IsChecked(form, "insecure_cookie"),
            UrlPath = Text(form, "url_path"),
            Lifetime = lifetime,
            LogoutRedirect = OptionalText(form, "logout_redirect"),
            DefaultAction = action,
            DefaultProvider = provider,
            MatchWhitelistOrDomain = IsChecked(form, "match_whitelist_or_domain")
        };

        if (settings.CookieName.Length == 0)
        {
            errors.Add("Cookie name is required.");
        }

        if (settings.CsrfCookieName.Length == 0)
        {
            errors.Add("CSRF cookie name is required.");
        }

        if (settings.UrlPath.Length == 0)
        {
            errors.Add("Callback path is required.");
        }

        return new ParsedSettings(settings, errors);
    }

    public static ProviderDefinition ParseProvider(
        string name,
        IFormCollection form,
        ProviderDefinition? existing)
    {
        var secret = Text(form, "client_secret");

        if (secret.Length == 0 && existing is not null)
        {
            secret = existing.ClientSecret;
        }

        return new ProviderDefinition
        {
            Name = name,
            ClientId = Text(form, "client_id"),
            ClientSecret = secret,
            IssuerUrl = OptionalText(form, "issuer_url"),
            AuthUrl = OptionalText(form, "auth_url"),
            TokenUrl = OptionalText(form, "token_url"),
            UserUrl = OptionalText(form, "user_url"),
            Prompt = OptionalText(form, "prompt"),
            Scopes = SplitList(form, "scopes", whitespaceToo: true),
            TokenStyle = Text(form, "token_style") is "query" ? "query" : "header",
            Resource = OptionalText(form, "resource")
        };
    }

    public static ParsedConditions ParseConditions(IFormCollection form)
    {
        var indexes = new SortedSet<int>();

        foreach (var key in form.Keys)
        {
            if (TryParseConditionIndex(key, out var index))
            {
                indexes.Add(index);
            }
        }

        var conditions = new List<ConditionDefinition>(indexes.Count);
        var errors = new List<string>();

        foreach (var index in indexes)
        {
            var number = index + 1;
            var fieldText = Text(form, $"Conditions[{index}].Field");
            var operatorText = Text(form, $"Conditions[{index}].Operator");

            if (!TryParseEnum<ConditionField>(fieldText, out var field))
            {
                errors.Add($"Condition {number}: unknown field '{fieldText}'.");
                field = ConditionField.Host;
            }

            if (!TryParseEnum<ConditionOperator>(operatorText, out var @operator))
            {
                errors.Add($"Condition {number}: unknown operator '{operatorText}'.");
                @operator = AdminUi.DefaultOperator(field);
            }

            var values = new List<string>();

            if (form.TryGetValue($"Conditions[{index}].Values", out var raw))
            {
                foreach (var item in raw)
                {
                    if (item is null)
                    {
                        continue;
                    }

                    foreach (var part in item.Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    {
                        if (part.Length > 0)
                        {
                            values.Add(part);
                        }
                    }
                }
            }

            conditions.Add(new ConditionDefinition
            {
                Field = field,
                Operator = @operator,
                Name = OptionalText(form, $"Conditions[{index}].Name"),
                Values = values,
                Negated = IsChecked(form, $"Conditions[{index}].Negated")
            });
        }

        return new ParsedConditions(conditions, errors);
    }

    public static ParsedRule ParseRule(
        IFormCollection form,
        string id,
        int position,
        IReadOnlyList<ConditionDefinition>? parsedConditions = null,
        IReadOnlyList<string>? parseErrors = null)
    {
        var errors = new List<string>(parseErrors ?? []);
        var actionText = Text(form, "action");
        var action = actionText == "allow" ? RuleAction.Allow : RuleAction.Auth;

        if (actionText is not ("allow" or "auth"))
        {
            errors.Add("Action must be auth or allow.");
        }

        var conditions = parsedConditions ?? ParseConditions(form).Conditions;

        var rule = new RuleDefinition
        {
            Id = id,
            Name = Text(form, "name"),
            Enabled = IsChecked(form, "enabled"),
            Action = action,
            Provider = OptionalText(form, "provider"),
            Position = position,
            Conditions = conditions
        };

        errors.AddRange(ConditionCompiler.ValidateRule(rule));

        return new ParsedRule(rule, errors);
    }

    public static ConditionRowModel ConditionRowFromForm(IFormCollection form, int index)
    {
        var fieldText = Text(form, $"Conditions[{index}].Field");
        var operatorText = Text(form, $"Conditions[{index}].Operator");

        if (!TryParseEnum<ConditionField>(fieldText, out var field))
        {
            field = ConditionField.Host;
        }

        if (!TryParseEnum<ConditionOperator>(operatorText, out var @operator))
        {
            @operator = AdminUi.DefaultOperator(field);
        }

        var values = new List<string>();

        if (form.TryGetValue($"Conditions[{index}].Values", out var raw))
        {
            foreach (var item in raw)
            {
                if (item is null)
                {
                    continue;
                }

                foreach (var part in item.Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    values.Add(part);
                }
            }
        }

        return AdminUi.ConditionRow(
            index,
            field,
            @operator,
            OptionalText(form, $"Conditions[{index}].Name"),
            values,
            IsChecked(form, $"Conditions[{index}].Negated"));
    }

    public static (RequestDescriptor? Request, string? Error) ParseSimulation(IFormCollection form)
    {
        var method = Text(form, "method").ToUpperInvariant();

        if (method.Length == 0)
        {
            method = "GET";
        }

        var host = Text(form, "host");
        var rawPath = Text(form, "path");

        if (rawPath.Length == 0)
        {
            rawPath = "/";
        }

        var normalized = PathNormalizer.Normalize(rawPath);

        if (!normalized.Success)
        {
            return (null, normalized.Error ?? "Invalid path.");
        }

        var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        var headerText = form["headers"].ToString();

        foreach (var line in headerText.Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var colon = line.IndexOf(':');

            if (colon <= 0)
            {
                return (null, $"Header line '{line}' must be in Name: value form.");
            }

            var name = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();

            if (name.Length == 0)
            {
                return (null, $"Header line '{line}' must have a name.");
            }

            headers[name] = headers.TryGetValue(name, out var existing)
                ? [.. existing, value]
                : [value];
        }

        Dictionary<string, string[]> query;

        try
        {
            query = ParseQueryInput(form["query"].ToString());
        }
        catch (Exception exception)
        {
            return (null, $"Invalid query string: {exception.Message}");
        }

        return (new RequestDescriptor(method, host, normalized.Path, headers, query), null);
    }

    private static Dictionary<string, string[]> ParseQueryInput(string text)
    {
        var query = new Dictionary<string, string[]>(StringComparer.Ordinal);

        if (string.IsNullOrWhiteSpace(text))
        {
            return query;
        }

        text = text.Trim();

        if (text.Contains('=') || text.Contains('&'))
        {
            var parsed = QueryHelpers.ParseQuery(text.StartsWith('?') ? text : "?" + text);

            foreach (var (name, values) in parsed)
            {
                query[name] = values.Where(value => value is not null).Select(value => value!).ToArray();
            }

            return query;
        }

        foreach (var line in text.Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separator = line.IndexOf('=');

            if (separator < 0)
            {
                separator = line.IndexOf(':');
            }

            if (separator <= 0)
            {
                throw new FormatException($"'{line}' must be name=value.");
            }

            var name = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();

            query[name] = query.TryGetValue(name, out var existing)
                ? [.. existing, value]
                : [value];
        }

        return query;
    }

    private static bool TryParseEnum<T>(string text, out T value)
        where T : struct, Enum
    {
        if (Enum.TryParse<T>(text, ignoreCase: true, out value) && Enum.IsDefined(value))
        {
            return true;
        }

        value = default;
        return false;
    }

    private static bool TryParseConditionIndex(string key, out int index)
    {
        index = -1;

        if (!key.StartsWith("Conditions[", StringComparison.Ordinal))
        {
            return false;
        }

        var close = key.IndexOf("].", StringComparison.Ordinal);

        if (close < 0)
        {
            return false;
        }

        var span = key.AsSpan("Conditions[".Length, close - "Conditions[".Length);

        return int.TryParse(span, NumberStyles.None, CultureInfo.InvariantCulture, out index) && index >= 0;
    }
}

public sealed record ParsedSettings(PolicySettings Settings, IReadOnlyList<string> Errors);
