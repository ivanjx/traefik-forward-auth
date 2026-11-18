namespace TraefikForwardAuth.Policy;

public enum RuleAction
{
    Auth,
    Allow
}

public enum AccessKind
{
    Email,
    Domain
}

public enum ConditionField
{
    Host,
    Path,
    Method,
    Header,
    Query
}

public enum ConditionOperator
{
    Is,
    MatchesWildcard,
    StartsWith,
    MatchesPattern,
    Contains,
    Exists,
    MatchesRegex
}
