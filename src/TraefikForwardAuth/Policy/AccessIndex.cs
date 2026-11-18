namespace TraefikForwardAuth.Policy;

/// <summary>
/// Access entries indexed by scope. Rule-scoped entries replace global entries entirely,
/// mirroring the Go position-matched whitelist/domain override behaviour.
/// </summary>
public sealed class AccessIndex
{
    private readonly ScopeRules _global;
    private readonly IReadOnlyDictionary<string, ScopeRules> _rules;

    private AccessIndex(ScopeRules global, IReadOnlyDictionary<string, ScopeRules> rules)
    {
        _global = global;
        _rules = rules;
    }

    public static AccessIndex Build(IEnumerable<AccessEntry> entries)
    {
        var global = new List<AccessEntry>();
        var byRule = new Dictionary<string, List<AccessEntry>>(StringComparer.Ordinal);

        foreach (var entry in entries)
        {
            if (entry.RuleId is null)
            {
                global.Add(entry);
                continue;
            }

            if (!byRule.TryGetValue(entry.RuleId, out var list))
            {
                list = [];
                byRule[entry.RuleId] = list;
            }

            list.Add(entry);
        }

        var scopes = byRule.ToDictionary(
            pair => pair.Key,
            pair => new ScopeRules(pair.Value),
            StringComparer.Ordinal);

        return new AccessIndex(new ScopeRules(global), scopes);
    }

    public ScopeRules ForRule(string? ruleId)
    {
        if (ruleId is not null && _rules.TryGetValue(ruleId, out var rules) && rules.HasEntries)
        {
            return rules;
        }

        return _global;
    }
}

public sealed class ScopeRules
{
    private readonly AccessEntry[] _entries;
    private readonly AccessEntry[] _emails;
    private readonly AccessEntry[] _domains;

    public ScopeRules(IEnumerable<AccessEntry> entries)
    {
        _entries = entries.ToArray();
        _emails = _entries.Where(entry => entry.Kind == AccessKind.Email).ToArray();
        _domains = _entries.Where(entry => entry.Kind == AccessKind.Domain).ToArray();
    }

    public bool HasEntries => _entries.Length > 0;

    public bool HasEmailEntries => _emails.Length > 0;

    public bool HasDomainEntries => _domains.Length > 0;

    public IReadOnlyList<AccessEntry> Entries => _entries;

    public bool IsAllowed(string email, bool matchWhitelistOrDomain)
    {
        if (_entries.Length == 0)
        {
            return true;
        }

        if (_emails.Length > 0)
        {
            if (_emails.Any(entry => entry.Value == email))
            {
                return true;
            }

            if (!matchWhitelistOrDomain)
            {
                return false;
            }
        }

        if (_domains.Length > 0 && _domains.Any(entry => MatchesDomain(email, entry.Value)))
        {
            return true;
        }

        return false;
    }

    public string? RoleFor(string email)
    {
        foreach (var entry in _emails)
        {
            if (entry.Value == email && !string.IsNullOrEmpty(entry.Role))
            {
                return entry.Role;
            }
        }

        foreach (var entry in _domains)
        {
            if (!string.IsNullOrEmpty(entry.Role) && MatchesDomain(email, entry.Value))
            {
                return entry.Role;
            }
        }

        return null;
    }

    private static bool MatchesDomain(string email, string domain)
    {
        var at = email.Split('@');

        return at.Length >= 2 && at[1] == domain;
    }
}
