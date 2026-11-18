namespace TraefikForwardAuth.Policy;

public sealed record PolicySettings
{
    public const string DefaultCookieName = "_forward_auth";
    public const string DefaultCsrfCookieName = "_forward_auth_csrf";
    public const string DefaultUrlPath = "/_oauth";
    public const string DefaultProviderName = "google";
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromHours(12);

    public string CookieName { get; init; } = DefaultCookieName;

    public string CsrfCookieName { get; init; } = DefaultCsrfCookieName;

    public IReadOnlyList<string> CookieDomains { get; init; } = [];

    public string AuthHost { get; init; } = "";

    public bool InsecureCookie { get; init; }

    /// <summary>Callback path, always starting with a slash.</summary>
    public string UrlPath { get; init; } = DefaultUrlPath;

    public TimeSpan Lifetime { get; init; } = DefaultLifetime;

    public string? LogoutRedirect { get; init; }

    public RuleAction DefaultAction { get; init; } = RuleAction.Auth;

    public string DefaultProvider { get; init; } = DefaultProviderName;

    public bool MatchWhitelistOrDomain { get; init; }

    public byte[] SigningSecret { get; init; } = [];
}

public sealed record ProviderDefinition
{
    public const string Google = "google";
    public const string Oidc = "oidc";
    public const string GenericOAuth = "generic-oauth";

    public required string Name { get; init; }

    public string ClientId { get; init; } = "";

    public string ClientSecret { get; init; } = "";

    public string? IssuerUrl { get; init; }

    public string? AuthUrl { get; init; }

    public string? TokenUrl { get; init; }

    public string? UserUrl { get; init; }

    public string? Prompt { get; init; }

    public IReadOnlyList<string> Scopes { get; init; } = [];

    public string TokenStyle { get; init; } = "header";

    public string? Resource { get; init; }

    public bool HasSecret => !string.IsNullOrEmpty(ClientSecret);

    public IReadOnlyList<string> ValidationErrors()
    {
        var errors = new List<string>();

        switch (Name)
        {
            case Google:
                if (string.IsNullOrWhiteSpace(ClientId)) errors.Add("Client ID is required.");
                if (string.IsNullOrWhiteSpace(ClientSecret)) errors.Add("Client secret is required.");
                break;

            case Oidc:
                if (!IsAbsoluteUrl(IssuerUrl)) errors.Add("Issuer URL must be an absolute URL.");
                if (string.IsNullOrWhiteSpace(ClientId)) errors.Add("Client ID is required.");
                if (string.IsNullOrWhiteSpace(ClientSecret)) errors.Add("Client secret is required.");
                break;

            case GenericOAuth:
                if (!IsAbsoluteUrl(AuthUrl)) errors.Add("Auth URL must be an absolute URL.");
                if (!IsAbsoluteUrl(TokenUrl)) errors.Add("Token URL must be an absolute URL.");
                if (!IsAbsoluteUrl(UserUrl)) errors.Add("User URL must be an absolute URL.");
                if (string.IsNullOrWhiteSpace(ClientId)) errors.Add("Client ID is required.");
                if (string.IsNullOrWhiteSpace(ClientSecret)) errors.Add("Client secret is required.");
                if (TokenStyle is not ("header" or "query")) errors.Add("Token style must be header or query.");
                break;

            default:
                errors.Add($"Unknown provider: {Name}.");
                break;
        }

        return errors;
    }

    private static bool IsAbsoluteUrl(string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
}
