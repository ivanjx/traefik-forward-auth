using System.Text.Json;
using TraefikForwardAuth.Auth;
using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Providers;
using TraefikForwardAuth.Rules;
using TraefikForwardAuth.Storage;

namespace TraefikForwardAuth.Policy;

/// <summary>
/// Coordinates admin writes: persistence, audit, snapshot rebuild and swap, and session revocation.
/// </summary>
public sealed class AdminService
{
    private readonly SqliteStore _store;
    private readonly PolicyManager _policy;
    private readonly SessionManager _sessions;
    private readonly ProviderFactory _providerFactory;
    private readonly TfaLogger _logger;
    private readonly TimeProvider _timeProvider;

    public AdminService(
        SqliteStore store,
        PolicyManager policy,
        SessionManager sessions,
        ProviderFactory providerFactory,
        TfaLogger logger,
        TimeProvider timeProvider)
    {
        _store = store;
        _policy = policy;
        _sessions = sessions;
        _providerFactory = providerFactory;
        _logger = logger;
        _timeProvider = timeProvider;
    }

    public PolicySnapshot Snapshot => _policy.Current;

    public Task<StoredConfiguration> GetConfigurationAsync(CancellationToken cancellationToken) =>
        _store.LoadConfigurationAsync(cancellationToken);

    public async Task UpdateSettingsAsync(PolicySettings settings, string adminEmail, CancellationToken cancellationToken)
    {
        var normalized = NormalizeSettings(settings);

        await _store.UpdateSettingsAsync(normalized, adminEmail, cancellationToken);
        await RebuildAfterCommitAsync();
    }

    public async Task RotateSecretAsync(string adminEmail, CancellationToken cancellationToken)
    {
        var secret = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secret);

        await _store.UpdateSigningSecretAsync(secret, adminEmail, cancellationToken);
        await _sessions.RevokeAllAsync(kind: null, CancellationToken.None);
        await RebuildAfterCommitAsync();

        _logger.Info("Signing secret rotated by admin", ("admin", adminEmail));
    }

    public async Task SaveProviderAsync(ProviderDefinition provider, string adminEmail, CancellationToken cancellationToken)
    {
        var (merged, error) = await MergeProviderSecretAsync(provider, cancellationToken);
        var errors = error is null ? merged.ValidationErrors() : [error];

        if (errors.Count > 0)
        {
            throw new ArgumentException(string.Join(" ", errors));
        }

        await _store.UpsertProviderAsync(provider, adminEmail, cancellationToken);
        await RebuildAfterCommitAsync();
    }

    public async Task DeleteProviderAsync(string name, string adminEmail, CancellationToken cancellationToken)
    {
        await _store.DeleteProviderAsync(name, adminEmail, cancellationToken);
        await RebuildAfterCommitAsync();
    }

    public async Task<ProviderTestResult> TestProviderAsync(ProviderDefinition provider, CancellationToken cancellationToken)
    {
        var (merged, error) = await MergeProviderSecretAsync(provider, cancellationToken);
        var errors = error is null ? merged.ValidationErrors() : [error];

        if (errors.Count > 0)
        {
            return ProviderTestResult.Fail(string.Join(" ", errors));
        }

        try
        {
            var instance = await _providerFactory.CreateAsync(merged, cancellationToken);

            if (instance is null)
            {
                return ProviderTestResult.Fail("Provider configuration is invalid.");
            }

            return await instance.TestConnectionAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            _logger.Warn("Provider connection test failed", ("provider", provider.Name), ("error", exception.Message));
            return ProviderTestResult.Fail(exception.Message);
        }
    }

    public async Task<RuleDefinition> CreateRuleAsync(
        RuleDefinition rule,
        string adminEmail,
        CancellationToken cancellationToken)
    {
        ValidateRule(rule);

        var created = await _store.CreateRuleAsync(rule, adminEmail, cancellationToken);
        await RebuildAfterCommitAsync();

        return created;
    }

    public async Task UpdateRuleAsync(RuleDefinition rule, string adminEmail, CancellationToken cancellationToken)
    {
        ValidateRule(rule);

        await _store.UpdateRuleAsync(rule, adminEmail, cancellationToken);
        await RebuildAfterCommitAsync();
    }

    public async Task DeleteRuleAsync(string id, string adminEmail, CancellationToken cancellationToken)
    {
        await _store.DeleteRuleAsync(id, adminEmail, cancellationToken);
        await RebuildAfterCommitAsync();
    }

    public async Task MoveRuleAsync(string id, int direction, string adminEmail, CancellationToken cancellationToken)
    {
        await _store.MoveRuleAsync(id, direction, adminEmail, cancellationToken);
        await RebuildAfterCommitAsync();
    }

    public async Task SetRuleEnabledAsync(
        string id,
        bool enabled,
        string adminEmail,
        CancellationToken cancellationToken)
    {
        await _store.SetRuleEnabledAsync(id, enabled, adminEmail, cancellationToken);
        await RebuildAfterCommitAsync();
    }

    public async Task AddAccessEntryAsync(
        AccessEntry entry,
        string adminEmail,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(entry.Value))
        {
            throw new ArgumentException("Value is required.");
        }

        if (entry.RuleId is not null)
        {
            var configuration = await _store.LoadConfigurationAsync(cancellationToken);

            if (configuration.Rules.All(rule => rule.Id != entry.RuleId))
            {
                throw new ArgumentException("The selected rule does not exist.");
            }
        }

        await _store.AddAccessEntryAsync(entry, adminEmail, cancellationToken);
        await RebuildAfterCommitAsync();
    }

    public async Task DeleteAccessEntryAsync(string id, string adminEmail, CancellationToken cancellationToken)
    {
        await _store.DeleteAccessEntryAsync(id, adminEmail, cancellationToken);
        await RebuildAfterCommitAsync();
    }

    public Task<IReadOnlyList<SessionRecord>> ListSessionsAsync(
        SessionKind kind,
        string? emailFilter,
        CancellationToken cancellationToken) =>
        _store.ListSessionsAsync(kind, emailFilter, cancellationToken);

    /// <summary>Revokes one session; returns false when it did not exist or was already revoked.</summary>
    public Task<bool> RevokeSessionAsync(string id, string adminEmail, CancellationToken cancellationToken)
    {
        var session = _sessions.Get(id);
        var action = session?.Kind == SessionKind.Admin ? "admin_session.revoke" : "session.revoke";

        return _sessions.RevokeAsync(
            id,
            new SessionRevocationAudit(adminEmail, action, id, _ => BuildStringDiff("id", id)),
            cancellationToken);
    }

    public Task<int> RevokeSessionsForEmailAsync(
        string email,
        SessionKind kind,
        string adminEmail,
        CancellationToken cancellationToken)
    {
        var action = kind == SessionKind.Admin ? "admin_session.revoke_email" : "session.revoke_email";

        return _sessions.RevokeForEmailAsync(
            email,
            kind,
            new SessionRevocationAudit(
                adminEmail,
                action,
                email,
                count => $"{{\"email\":{Quote(email)},\"count\":{count}}}"),
            cancellationToken);
    }

    public Task<IReadOnlyList<AuditEntry>> ListAuditAsync(int limit, CancellationToken cancellationToken) =>
        _store.ListAuditAsync(limit, cancellationToken);

    public SimulationResult Simulate(RequestDescriptor request) => _policy.Current.Simulate(request);

    /// <summary>
    /// Runs after the write has committed, so it must not observe the request's cancellation:
    /// a client disconnect would otherwise leave the database and the live snapshot out of sync.
    /// </summary>
    private Task RebuildAfterCommitAsync() => _policy.RebuildAsync(CancellationToken.None);

    /// <summary>
    /// A blank secret keeps the stored one, but only while every URL that receives the secret is unchanged;
    /// otherwise any admin could send the stored secret to an endpoint of their choice (for example via
    /// "Test connection") and read it there.
    /// </summary>
    private async Task<(ProviderDefinition Provider, string? Error)> MergeProviderSecretAsync(
        ProviderDefinition provider,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(provider.ClientSecret))
        {
            return (provider, null);
        }

        var configuration = await _store.LoadConfigurationAsync(cancellationToken);
        var existing = configuration.Providers.FirstOrDefault(candidate => candidate.Name == provider.Name);

        if (existing is null || !existing.HasSecret)
        {
            return (provider, null);
        }

        if (!existing.HasSameSecretEndpoints(provider))
        {
            return (provider, "Re-enter the client secret when changing the issuer, token or user info URL.");
        }

        return (provider with { ClientSecret = existing.ClientSecret }, null);
    }

    private static void ValidateRule(RuleDefinition rule)
    {
        if (string.IsNullOrWhiteSpace(rule.Name))
        {
            throw new ArgumentException("Rule name is required.");
        }

        var errors = ConditionCompiler.ValidateRule(rule);

        if (errors.Count > 0)
        {
            throw new ArgumentException(string.Join(" ", errors));
        }
    }

    private static PolicySettings NormalizeSettings(PolicySettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.CookieName) || string.IsNullOrWhiteSpace(settings.CsrfCookieName))
        {
            throw new ArgumentException("Cookie names are required.");
        }

        var path = settings.UrlPath;

        if (string.IsNullOrWhiteSpace(path) || path[0] != '/')
        {
            path = "/" + path.TrimStart('/');
        }

        if (path.Contains('?') || path.Contains('#'))
        {
            throw new ArgumentException("The callback path must not contain a query or fragment.");
        }

        if (settings.Lifetime <= TimeSpan.Zero || settings.Lifetime > TimeSpan.FromDays(365))
        {
            throw new ArgumentException("Lifetime must be between 1 second and 365 days.");
        }

        if (settings.DefaultProvider is not (ProviderDefinition.Google or ProviderDefinition.Oidc or ProviderDefinition.GenericOAuth))
        {
            throw new ArgumentException("Unknown default provider.");
        }

        if (!string.IsNullOrEmpty(settings.LogoutRedirect) &&
            !Uri.TryCreate(settings.LogoutRedirect, UriKind.Absolute, out _))
        {
            throw new ArgumentException("Logout redirect must be an absolute URL.");
        }

        var domains = settings.CookieDomains
            .Where(domain => !string.IsNullOrWhiteSpace(domain))
            .Select(domain => domain.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        return settings with
        {
            UrlPath = path,
            CookieDomains = domains,
            AuthHost = settings.AuthHost.Trim()
        };
    }

    private static string BuildStringDiff(string name, string value) =>
        $"{{\"{name}\":{Quote(value)}}}";

    private static string Quote(string value) =>
        "\"" + JsonEncodedText.Encode(value).ToString() + "\"";
}
