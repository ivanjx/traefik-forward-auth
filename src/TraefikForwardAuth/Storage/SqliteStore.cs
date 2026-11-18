using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using TraefikForwardAuth.Auth;
using TraefikForwardAuth.Json;
using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Policy;

namespace TraefikForwardAuth.Storage;

public sealed record AuditEntry(
    long Id,
    DateTimeOffset CreatedAt,
    string AdminEmail,
    string Action,
    string Entity,
    string DiffJson);

public sealed class SqliteStore : ISessionRepository, IAsyncDisposable
{
    private const int MaxAuditLimit = 1000;
    private const int SessionChunkSize = 400;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly TfaLogger _logger;
    private int _disposed;

    public SqliteStore(string databasePath, TfaLogger logger)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        DatabasePath = databasePath;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public string DatabasePath { get; }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(DatabasePath));

            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            await using var connection = await OpenConnectionAsync(cancellationToken);

            await ExecuteAsync(connection, null, "PRAGMA journal_mode=WAL;", cancellationToken);
            await ExecuteAsync(connection, null, "PRAGMA foreign_keys=ON;", cancellationToken);
            await ExecuteAsync(connection, null, "PRAGMA busy_timeout=5000;", cancellationToken);

            await ApplyMigrationsAsync(connection, cancellationToken);
            RestrictFilePermissions();

            await InsertDefaultSettingsAsync(connection, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<StoredConfiguration> LoadConfigurationAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);

            var settings = await ReadSettingsRowAsync(connection, null, cancellationToken)
                ?? throw new InvalidOperationException("The settings row is missing; the store has not been initialized.");

            var providers = await ReadProvidersAsync(connection, cancellationToken);
            var rules = await ReadRulesAsync(connection, cancellationToken);
            var entries = await ReadAccessEntriesAsync(connection, cancellationToken);

            return new StoredConfiguration
            {
                Settings = settings,
                Providers = providers,
                Rules = rules,
                AccessEntries = entries
            };
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task UpdateSettingsAsync(
        PolicySettings settings,
        string adminEmail,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

            var old = await ReadSettingsRowAsync(connection, transaction, cancellationToken)
                ?? throw new InvalidOperationException("The settings row is missing; the store has not been initialized.");

            await ExecuteAsync(
                connection,
                transaction,
                """
                UPDATE settings SET
                    cookie_name = $cookie_name,
                    csrf_cookie_name = $csrf_cookie_name,
                    cookie_domains = $cookie_domains,
                    auth_host = $auth_host,
                    insecure = $insecure,
                    url_path = $url_path,
                    lifetime_seconds = $lifetime_seconds,
                    logout_redirect = $logout_redirect,
                    default_action = $default_action,
                    default_provider = $default_provider,
                    match_whitelist_or_domain = $match_whitelist_or_domain
                WHERE id = 1;
                """,
                cancellationToken,
                ("$cookie_name", settings.CookieName),
                ("$csrf_cookie_name", settings.CsrfCookieName),
                ("$cookie_domains", SerializeStrings(settings.CookieDomains)),
                ("$auth_host", settings.AuthHost),
                ("$insecure", settings.InsecureCookie ? 1 : 0),
                ("$url_path", settings.UrlPath),
                ("$lifetime_seconds", (long)settings.Lifetime.TotalSeconds),
                ("$logout_redirect", settings.LogoutRedirect),
                ("$default_action", ActionToString(settings.DefaultAction)),
                ("$default_provider", settings.DefaultProvider),
                ("$match_whitelist_or_domain", settings.MatchWhitelistOrDomain ? 1 : 0));

            var diff = new Dictionary<string, string?>(StringComparer.Ordinal);
            AddChange(diff, "cookie_name", old.CookieName, settings.CookieName);
            AddChange(diff, "csrf_cookie_name", old.CsrfCookieName, settings.CsrfCookieName);
            AddChange(diff, "cookie_domains", JoinValues(old.CookieDomains), JoinValues(settings.CookieDomains));
            AddChange(diff, "auth_host", old.AuthHost, settings.AuthHost);
            AddChange(diff, "insecure", FormatBool(old.InsecureCookie), FormatBool(settings.InsecureCookie));
            AddChange(diff, "url_path", old.UrlPath, settings.UrlPath);
            AddChange(diff, "lifetime_seconds", FormatSeconds(old.Lifetime), FormatSeconds(settings.Lifetime));
            AddChange(diff, "logout_redirect", old.LogoutRedirect, settings.LogoutRedirect);
            AddChange(diff, "default_action", ActionToString(old.DefaultAction), ActionToString(settings.DefaultAction));
            AddChange(diff, "default_provider", old.DefaultProvider, settings.DefaultProvider);
            AddChange(
                diff,
                "match_whitelist_or_domain",
                FormatBool(old.MatchWhitelistOrDomain),
                FormatBool(settings.MatchWhitelistOrDomain));

            await AppendAuditAsync(
                connection,
                transaction,
                adminEmail,
                "settings.update",
                "settings",
                SerializeDiff(diff),
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task UpdateSigningSecretAsync(
        byte[] secret,
        string adminEmail,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(secret);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

            await ExecuteAsync(
                connection,
                transaction,
                "UPDATE settings SET signing_secret = $secret WHERE id = 1;",
                cancellationToken,
                ("$secret", secret));

            var diff = new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["signing_secret"] = "rotated"
            };

            await AppendAuditAsync(
                connection,
                transaction,
                adminEmail,
                "secret.rotate",
                "settings",
                SerializeDiff(diff),
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task UpsertProviderAsync(
        ProviderDefinition provider,
        string adminEmail,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(provider);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

            var old = await ReadProviderAsync(connection, transaction, provider.Name, cancellationToken);
            var effectiveSecret = string.IsNullOrEmpty(provider.ClientSecret)
                ? old?.ClientSecret ?? ""
                : provider.ClientSecret;

            await ExecuteAsync(
                connection,
                transaction,
                """
                INSERT INTO providers (
                    name, client_id, client_secret, issuer_url, auth_url, token_url, user_url,
                    prompt, scopes, token_style, resource, updated_at)
                VALUES (
                    $name, $client_id, $client_secret, $issuer_url, $auth_url, $token_url, $user_url,
                    $prompt, $scopes, $token_style, $resource, $updated_at)
                ON CONFLICT(name) DO UPDATE SET
                    client_id = excluded.client_id,
                    client_secret = excluded.client_secret,
                    issuer_url = excluded.issuer_url,
                    auth_url = excluded.auth_url,
                    token_url = excluded.token_url,
                    user_url = excluded.user_url,
                    prompt = excluded.prompt,
                    scopes = excluded.scopes,
                    token_style = excluded.token_style,
                    resource = excluded.resource,
                    updated_at = excluded.updated_at;
                """,
                cancellationToken,
                ("$name", provider.Name),
                ("$client_id", provider.ClientId),
                ("$client_secret", effectiveSecret),
                ("$issuer_url", provider.IssuerUrl),
                ("$auth_url", provider.AuthUrl),
                ("$token_url", provider.TokenUrl),
                ("$user_url", provider.UserUrl),
                ("$prompt", provider.Prompt),
                ("$scopes", SerializeStrings(provider.Scopes)),
                ("$token_style", provider.TokenStyle),
                ("$resource", provider.Resource),
                ("$updated_at", FormatTimestamp(DateTimeOffset.UtcNow)));

            var diff = new Dictionary<string, string?>(StringComparer.Ordinal);
            AddChange(diff, "name", old?.Name, provider.Name);
            AddChange(diff, "client_id", old?.ClientId, provider.ClientId);
            AddChange(diff, "issuer_url", old?.IssuerUrl, provider.IssuerUrl);
            AddChange(diff, "auth_url", old?.AuthUrl, provider.AuthUrl);
            AddChange(diff, "token_url", old?.TokenUrl, provider.TokenUrl);
            AddChange(diff, "user_url", old?.UserUrl, provider.UserUrl);
            AddChange(diff, "prompt", old?.Prompt, provider.Prompt);
            AddChange(diff, "scopes", old is null ? null : JoinValues(old.Scopes), JoinValues(provider.Scopes));
            AddChange(diff, "token_style", old?.TokenStyle, provider.TokenStyle);
            AddChange(diff, "resource", old?.Resource, provider.Resource);

            diff["client_secret"] = string.IsNullOrEmpty(provider.ClientSecret)
                ? (effectiveSecret.Length == 0 ? "unset" : "unchanged")
                : "set";

            await AppendAuditAsync(
                connection,
                transaction,
                adminEmail,
                "provider.save",
                provider.Name,
                SerializeDiff(diff),
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task DeleteProviderAsync(
        string name,
        string adminEmail,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

            var old = await ReadProviderAsync(connection, transaction, name, cancellationToken);

            await ExecuteAsync(
                connection,
                transaction,
                "DELETE FROM providers WHERE name = $name;",
                cancellationToken,
                ("$name", name));

            var diff = new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["name"] = old?.Name ?? name,
                ["client_id"] = old?.ClientId ?? "",
                ["client_secret"] = old is null || old.ClientSecret.Length == 0 ? "unset" : "set"
            };

            await AppendAuditAsync(
                connection,
                transaction,
                adminEmail,
                "provider.delete",
                name,
                SerializeDiff(diff),
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<RuleDefinition> CreateRuleAsync(
        RuleDefinition rule,
        string adminEmail,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(rule);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

            var position = await NextRulePositionAsync(connection, transaction, cancellationToken);
            var stored = rule with
            {
                Id = string.IsNullOrEmpty(rule.Id) ? Guid.NewGuid().ToString("N") : rule.Id,
                Position = position
            };

            await InsertRuleAsync(connection, transaction, stored, cancellationToken);
            await AppendAuditAsync(
                connection,
                transaction,
                adminEmail,
                "rule.create",
                stored.Id,
                SerializeRuleDiff(stored),
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            return stored;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task UpdateRuleAsync(
        RuleDefinition rule,
        string adminEmail,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(rule);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

            var old = await ReadRuleAsync(connection, transaction, rule.Id, cancellationToken)
                ?? throw new KeyNotFoundException($"Rule '{rule.Id}' was not found.");

            await ExecuteAsync(
                connection,
                transaction,
                """
                UPDATE rules SET
                    name = $name,
                    action = $action,
                    provider = $provider,
                    enabled = $enabled,
                    conditions = $conditions,
                    updated_at = $updated_at
                WHERE id = $id;
                """,
                cancellationToken,
                ("$id", old.Id),
                ("$name", rule.Name),
                ("$action", ActionToString(rule.Action)),
                ("$provider", rule.Provider),
                ("$enabled", rule.Enabled ? 1 : 0),
                ("$conditions", SerializeConditions(rule.Conditions)),
                ("$updated_at", FormatTimestamp(DateTimeOffset.UtcNow)));

            var diff = new Dictionary<string, string?>(StringComparer.Ordinal);
            AddChange(diff, "name", old.Name, rule.Name);
            AddChange(diff, "action", ActionToString(old.Action), ActionToString(rule.Action));
            AddChange(diff, "provider", old.Provider, rule.Provider);
            AddChange(diff, "enabled", FormatBool(old.Enabled), FormatBool(rule.Enabled));
            AddChange(
                diff,
                "conditions",
                SerializeConditions(old.Conditions),
                SerializeConditions(rule.Conditions));

            await AppendAuditAsync(
                connection,
                transaction,
                adminEmail,
                "rule.update",
                old.Id,
                SerializeDiff(diff),
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task DeleteRuleAsync(string id, string adminEmail, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

            var old = await ReadRuleAsync(connection, transaction, id, cancellationToken)
                ?? throw new KeyNotFoundException($"Rule '{id}' was not found.");

            await ExecuteAsync(
                connection,
                transaction,
                "DELETE FROM access_entries WHERE scope = $scope;",
                cancellationToken,
                ("$scope", id));

            await ExecuteAsync(
                connection,
                transaction,
                "DELETE FROM rules WHERE id = $id;",
                cancellationToken,
                ("$id", id));

            await AppendAuditAsync(
                connection,
                transaction,
                adminEmail,
                "rule.delete",
                id,
                SerializeRuleDiff(old),
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task MoveRuleAsync(
        string id,
        int direction,
        string adminEmail,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        if (direction is not (-1 or 1))
        {
            throw new ArgumentOutOfRangeException(nameof(direction), direction, "Direction must be -1 or 1.");
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

            var current = await ReadRuleAsync(connection, transaction, id, cancellationToken)
                ?? throw new KeyNotFoundException($"Rule '{id}' was not found.");

            var neighbor = await ReadNeighborRuleAsync(
                connection,
                transaction,
                current.Position,
                direction,
                cancellationToken);

            var diff = new Dictionary<string, string?>(StringComparer.Ordinal);

            if (neighbor is not null)
            {
                await ExecuteAsync(
                    connection,
                    transaction,
                    "UPDATE rules SET position = $position WHERE id = $id;",
                    cancellationToken,
                    ("$position", neighbor.Position),
                    ("$id", current.Id));

                await ExecuteAsync(
                    connection,
                    transaction,
                    "UPDATE rules SET position = $position WHERE id = $id;",
                    cancellationToken,
                    ("$position", current.Position),
                    ("$id", neighbor.Id));

                diff["position"] = string.Create(
                    CultureInfo.InvariantCulture,
                    $"{current.Position} -> {neighbor.Position}");
                diff["swapped_with"] = neighbor.Id;
            }
            else
            {
                diff["position"] = string.Create(
                    CultureInfo.InvariantCulture,
                    $"{current.Position} -> {current.Position}");
            }

            await AppendAuditAsync(
                connection,
                transaction,
                adminEmail,
                "rule.move",
                id,
                SerializeDiff(diff),
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SetRuleEnabledAsync(
        string id,
        bool enabled,
        string adminEmail,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

            var old = await ReadRuleAsync(connection, transaction, id, cancellationToken)
                ?? throw new KeyNotFoundException($"Rule '{id}' was not found.");

            await ExecuteAsync(
                connection,
                transaction,
                "UPDATE rules SET enabled = $enabled, updated_at = $updated_at WHERE id = $id;",
                cancellationToken,
                ("$enabled", enabled ? 1 : 0),
                ("$updated_at", FormatTimestamp(DateTimeOffset.UtcNow)),
                ("$id", id));

            var diff = new Dictionary<string, string?>(StringComparer.Ordinal);
            AddChange(diff, "enabled", FormatBool(old.Enabled), FormatBool(enabled));

            await AppendAuditAsync(
                connection,
                transaction,
                adminEmail,
                "rule.toggle",
                id,
                SerializeDiff(diff),
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task AddAccessEntryAsync(
        AccessEntry entry,
        string adminEmail,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

            var stored = entry with
            {
                Id = string.IsNullOrEmpty(entry.Id) ? Guid.NewGuid().ToString("N") : entry.Id
            };

            await ExecuteAsync(
                connection,
                transaction,
                """
                INSERT INTO access_entries (id, scope, kind, value, role, created_at)
                VALUES ($id, $scope, $kind, $value, $role, $created_at);
                """,
                cancellationToken,
                ("$id", stored.Id),
                ("$scope", stored.RuleId ?? "global"),
                ("$kind", KindToString(stored.Kind)),
                ("$value", stored.Value),
                ("$role", stored.Role),
                ("$created_at", FormatTimestamp(DateTimeOffset.UtcNow)));

            await AppendAuditAsync(
                connection,
                transaction,
                adminEmail,
                "access.add",
                stored.Id,
                SerializeAccessDiff(stored),
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task DeleteAccessEntryAsync(
        string id,
        string adminEmail,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

            var old = await ReadAccessEntryAsync(connection, transaction, id, cancellationToken)
                ?? throw new KeyNotFoundException($"Access entry '{id}' was not found.");

            await ExecuteAsync(
                connection,
                transaction,
                "DELETE FROM access_entries WHERE id = $id;",
                cancellationToken,
                ("$id", id));

            await AppendAuditAsync(
                connection,
                transaction,
                adminEmail,
                "access.delete",
                id,
                SerializeAccessDiff(old),
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task AppendAuditAsync(
        string adminEmail,
        string action,
        string entity,
        string diffJson,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

            await AppendAuditAsync(
                connection,
                transaction,
                adminEmail,
                action,
                entity,
                diffJson,
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<AuditEntry>> ListAuditAsync(int limit, CancellationToken cancellationToken)
    {
        var clamped = Math.Clamp(limit, 1, MaxAuditLimit);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText =
                """
                SELECT id, created_at, admin_email, action, entity, diff
                FROM audit_log
                ORDER BY id DESC
                LIMIT $limit;
                """;
            command.Parameters.AddWithValue("$limit", clamped);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            var entries = new List<AuditEntry>();

            while (await reader.ReadAsync(cancellationToken))
            {
                entries.Add(new AuditEntry(
                    reader.GetInt64(0),
                    ParseTimestamp(reader.GetString(1)),
                    reader.GetString(2),
                    reader.GetString(3),
                    reader.GetString(4),
                    reader.GetString(5)));
            }

            return entries;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<SessionRecord>> LoadSessionsAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText =
                """
                SELECT id, kind, email, provider, domain, created_at, expires_at, last_seen, ip, user_agent, revoked_at
                FROM sessions
                ORDER BY created_at ASC, id ASC;
                """;

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);

            return await ReadSessionsAsync(reader, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<SessionRecord>> ListSessionsAsync(
        SessionKind? kind,
        string? emailFilter,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var command = connection.CreateCommand();

            var sql = new StringBuilder(
                "SELECT id, kind, email, provider, domain, created_at, expires_at, last_seen, ip, user_agent, revoked_at " +
                "FROM sessions WHERE revoked_at IS NULL");

            if (kind is not null)
            {
                sql.Append(" AND kind = $kind");
                command.Parameters.AddWithValue("$kind", KindToString(kind.Value));
            }

            if (!string.IsNullOrWhiteSpace(emailFilter))
            {
                sql.Append(" AND email LIKE $email ESCAPE '\\'");
                command.Parameters.AddWithValue("$email", "%" + EscapeLike(emailFilter) + "%");
            }

            sql.Append(" ORDER BY last_seen DESC, id DESC;");
            command.CommandText = sql.ToString();

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);

            return await ReadSessionsAsync(reader, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task InsertSessionAsync(SessionRecord session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

            await ExecuteAsync(
                connection,
                transaction,
                """
                INSERT INTO sessions (
                    id, kind, email, provider, domain, created_at, expires_at, last_seen, ip, user_agent, revoked_at)
                VALUES (
                    $id, $kind, $email, $provider, $domain, $created_at, $expires_at, $last_seen, $ip, $user_agent, $revoked_at);
                """,
                cancellationToken,
                ("$id", session.Id),
                ("$kind", KindToString(session.Kind)),
                ("$email", session.Email),
                ("$provider", session.Provider),
                ("$domain", session.Domain),
                ("$created_at", FormatTimestamp(session.CreatedAt)),
                ("$expires_at", FormatTimestamp(session.ExpiresAt)),
                ("$last_seen", FormatTimestamp(session.LastSeenAt)),
                ("$ip", session.Ip),
                ("$user_agent", session.UserAgent),
                ("$revoked_at", session.RevokedAt is null ? null : FormatTimestamp(session.RevokedAt.Value)));

            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task MarkSessionsRevokedAsync(
        IReadOnlyCollection<string> ids,
        DateTimeOffset revokedAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ids);

        if (ids.Count == 0)
        {
            return;
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

            var timestamp = FormatTimestamp(revokedAt);

            foreach (var chunk in ids.Distinct(StringComparer.Ordinal).Chunk(SessionChunkSize))
            {
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;

                var builder = new StringBuilder(
                    "UPDATE sessions SET revoked_at = $revoked_at WHERE revoked_at IS NULL AND id IN (");

                for (var i = 0; i < chunk.Length; i++)
                {
                    if (i > 0)
                    {
                        builder.Append(", ");
                    }

                    var name = "$id" + i.ToString(CultureInfo.InvariantCulture);
                    builder.Append(name);
                    command.Parameters.AddWithValue(name, chunk[i]);
                }

                builder.Append(");");
                command.CommandText = builder.ToString();
                command.Parameters.AddWithValue("$revoked_at", timestamp);

                await command.ExecuteNonQueryAsync(cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task UpdateSessionsLastSeenAsync(
        IReadOnlyList<(string Id, DateTimeOffset LastSeenAt)> sessions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sessions);

        if (sessions.Count == 0)
        {
            return;
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

            foreach (var (id, lastSeenAt) in sessions)
            {
                await ExecuteAsync(
                    connection,
                    transaction,
                    "UPDATE sessions SET last_seen = $last_seen WHERE id = $id;",
                    cancellationToken,
                    ("$last_seen", FormatTimestamp(lastSeenAt)),
                    ("$id", id));
            }

            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<int> DeleteSessionsEndedBeforeAsync(DateTimeOffset cutoff, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var command = connection.CreateCommand();

            // Timestamps are stored as fixed-width UTC round-trip strings, so text comparison orders them.
            command.CommandText =
                """
                DELETE FROM sessions
                WHERE expires_at < $cutoff OR (revoked_at IS NOT NULL AND revoked_at < $cutoff);
                """;
            command.Parameters.AddWithValue("$cutoff", FormatTimestamp(cutoff));

            return await command.ExecuteNonQueryAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _gate.Dispose();
        }

        return ValueTask.CompletedTask;
    }

    private string BuildConnectionString()
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false
        };

        return builder.ToString();
    }

    private async Task<SqliteConnection> OpenConnectionAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(BuildConnectionString());
        await connection.OpenAsync(cancellationToken);
        await ExecuteAsync(connection, null, "PRAGMA foreign_keys=ON;", cancellationToken);
        await ExecuteAsync(connection, null, "PRAGMA busy_timeout=5000;", cancellationToken);

        return connection;
    }

    private async Task ApplyMigrationsAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        var currentVersion = await GetUserVersionAsync(connection, cancellationToken);

        foreach (var migration in GetMigrationResources())
        {
            if (migration.Version <= currentVersion)
            {
                continue;
            }

            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

            await ExecuteAsync(
                connection,
                transaction,
                await ReadResourceAsync(migration.ResourceName, cancellationToken),
                cancellationToken);

            await ExecuteAsync(
                connection,
                transaction,
                "PRAGMA user_version = " + migration.Version.ToString(CultureInfo.InvariantCulture) + ";",
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
            currentVersion = migration.Version;
        }
    }

    private static IEnumerable<(int Version, string ResourceName)> GetMigrationResources()
    {
        var assembly = typeof(SqliteStore).Assembly;
        var resources = new List<(int Version, string ResourceName)>();

        foreach (var resourceName in assembly.GetManifestResourceNames())
        {
            if (!resourceName.EndsWith(".sql", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var segments = resourceName.Split('.');
            var fileName = segments.Length >= 2
                ? segments[^2] + "." + segments[^1]
                : resourceName;

            var digits = new StringBuilder();

            foreach (var character in fileName)
            {
                if (!char.IsDigit(character))
                {
                    break;
                }

                digits.Append(character);
            }

            if (digits.Length > 0 && int.TryParse(digits.ToString(), CultureInfo.InvariantCulture, out var version))
            {
                resources.Add((version, resourceName));
            }
        }

        resources.Sort(static (left, right) => left.Version.CompareTo(right.Version));

        return resources;
    }

    private static async Task<string> ReadResourceAsync(string resourceName, CancellationToken cancellationToken)
    {
        await using var stream = typeof(SqliteStore).Assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"Migration resource '{resourceName}' was not found.");

        using var reader = new StreamReader(stream);

        return await reader.ReadToEndAsync(cancellationToken);
    }

    private static async Task<long> GetUserVersionAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version;";
        var result = await command.ExecuteScalarAsync(cancellationToken);

        return result is null or DBNull ? 0 : Convert.ToInt64(result, CultureInfo.InvariantCulture);
    }

    private async Task InsertDefaultSettingsAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        var secret = RandomNumberGenerator.GetBytes(32);

        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        await ExecuteAsync(
            connection,
            transaction,
            """
            INSERT OR IGNORE INTO settings (
                id, cookie_name, csrf_cookie_name, cookie_domains, auth_host, insecure,
                url_path, lifetime_seconds, logout_redirect, default_action, default_provider,
                match_whitelist_or_domain, signing_secret)
            VALUES (
                1, $cookie_name, $csrf_cookie_name, $cookie_domains, $auth_host, $insecure,
                $url_path, $lifetime_seconds, $logout_redirect, $default_action, $default_provider,
                $match_whitelist_or_domain, $signing_secret);
            """,
            cancellationToken,
            ("$cookie_name", PolicySettings.DefaultCookieName),
            ("$csrf_cookie_name", PolicySettings.DefaultCsrfCookieName),
            ("$cookie_domains", "[]"),
            ("$auth_host", ""),
            ("$insecure", 0),
            ("$url_path", PolicySettings.DefaultUrlPath),
            ("$lifetime_seconds", (long)PolicySettings.DefaultLifetime.TotalSeconds),
            ("$logout_redirect", null),
            ("$default_action", ActionToString(RuleAction.Auth)),
            ("$default_provider", PolicySettings.DefaultProviderName),
            ("$match_whitelist_or_domain", 0),
            ("$signing_secret", secret));

        await transaction.CommitAsync(cancellationToken);
    }

    private void RestrictFilePermissions()
    {
        if (OperatingSystem.IsWindows() || !File.Exists(DatabasePath))
        {
            return;
        }

        File.SetUnixFileMode(DatabasePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private static async Task<PolicySettings?> ReadSettingsRowAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT cookie_name, csrf_cookie_name, cookie_domains, auth_host, insecure,
                   url_path, lifetime_seconds, logout_redirect, default_action, default_provider,
                   match_whitelist_or_domain, signing_secret
            FROM settings
            WHERE id = 1
            LIMIT 1;
            """;

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new PolicySettings
        {
            CookieName = reader.GetString(0),
            CsrfCookieName = reader.GetString(1),
            CookieDomains = DeserializeStrings(reader.GetString(2)),
            AuthHost = reader.GetString(3),
            InsecureCookie = reader.GetInt64(4) != 0,
            UrlPath = reader.GetString(5),
            Lifetime = TimeSpan.FromSeconds(reader.GetInt64(6)),
            LogoutRedirect = reader.IsDBNull(7) ? null : reader.GetString(7),
            DefaultAction = ParseAction(reader.GetString(8)),
            DefaultProvider = reader.GetString(9),
            MatchWhitelistOrDomain = reader.GetInt64(10) != 0,
            SigningSecret = reader.GetFieldValue<byte[]>(11)
        };
    }

    private async Task<IReadOnlyList<ProviderDefinition>> ReadProvidersAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT name, client_id, client_secret, issuer_url, auth_url, token_url, user_url,
                   prompt, scopes, token_style, resource
            FROM providers
            ORDER BY name ASC;
            """;

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var providers = new List<ProviderDefinition>();

        while (await reader.ReadAsync(cancellationToken))
        {
            providers.Add(ReadProvider(reader));
        }

        return providers;
    }

    private static async Task<ProviderDefinition?> ReadProviderAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string name,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT name, client_id, client_secret, issuer_url, auth_url, token_url, user_url,
                   prompt, scopes, token_style, resource
            FROM providers
            WHERE name = $name
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$name", name);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        return await reader.ReadAsync(cancellationToken) ? ReadProvider(reader) : null;
    }

    private static ProviderDefinition ReadProvider(SqliteDataReader reader) => new()
    {
        Name = reader.GetString(0),
        ClientId = reader.GetString(1),
        ClientSecret = reader.GetString(2),
        IssuerUrl = reader.IsDBNull(3) ? null : reader.GetString(3),
        AuthUrl = reader.IsDBNull(4) ? null : reader.GetString(4),
        TokenUrl = reader.IsDBNull(5) ? null : reader.GetString(5),
        UserUrl = reader.IsDBNull(6) ? null : reader.GetString(6),
        Prompt = reader.IsDBNull(7) ? null : reader.GetString(7),
        Scopes = DeserializeStrings(reader.GetString(8)),
        TokenStyle = reader.GetString(9),
        Resource = reader.IsDBNull(10) ? null : reader.GetString(10)
    };

    private async Task<IReadOnlyList<RuleDefinition>> ReadRulesAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT id, name, position, action, provider, enabled, conditions
            FROM rules
            ORDER BY position ASC, id ASC;
            """;

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var rules = new List<RuleDefinition>();

        while (await reader.ReadAsync(cancellationToken))
        {
            rules.Add(ReadRule(reader));
        }

        return rules;
    }

    private async Task<RuleDefinition?> ReadRuleAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string id,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT id, name, position, action, provider, enabled, conditions
            FROM rules
            WHERE id = $id
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$id", id);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        return await reader.ReadAsync(cancellationToken) ? ReadRule(reader) : null;
    }

    private RuleDefinition ReadRule(SqliteDataReader reader) => new()
    {
        Id = reader.GetString(0),
        Name = reader.GetString(1),
        Position = reader.GetInt32(2),
        Action = ParseAction(reader.GetString(3)),
        Provider = reader.IsDBNull(4) ? null : reader.GetString(4),
        Enabled = reader.GetInt64(5) != 0,
        Conditions = DeserializeConditions(reader.GetString(6))
    };

    private async Task<RuleDefinition?> ReadNeighborRuleAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        int position,
        int direction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = direction < 0
            ? """
              SELECT id, name, position, action, provider, enabled, conditions
              FROM rules
              WHERE position < $position
              ORDER BY position DESC, id DESC
              LIMIT 1;
              """
            : """
              SELECT id, name, position, action, provider, enabled, conditions
              FROM rules
              WHERE position > $position
              ORDER BY position ASC, id ASC
              LIMIT 1;
              """;
        command.Parameters.AddWithValue("$position", position);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        return await reader.ReadAsync(cancellationToken) ? ReadRule(reader) : null;
    }

    private static async Task<int> NextRulePositionAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT COALESCE(MAX(position), -1) + 1 FROM rules;";
        var result = await command.ExecuteScalarAsync(cancellationToken);

        return result is null or DBNull ? 0 : Convert.ToInt32(result, CultureInfo.InvariantCulture);
    }

    private static Task InsertRuleAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        RuleDefinition rule,
        CancellationToken cancellationToken) =>
        ExecuteAsync(
            connection,
            transaction,
            """
            INSERT INTO rules (id, name, position, action, provider, enabled, conditions, updated_at)
            VALUES ($id, $name, $position, $action, $provider, $enabled, $conditions, $updated_at);
            """,
            cancellationToken,
            ("$id", rule.Id),
            ("$name", rule.Name),
            ("$position", rule.Position),
            ("$action", ActionToString(rule.Action)),
            ("$provider", rule.Provider),
            ("$enabled", rule.Enabled ? 1 : 0),
            ("$conditions", SerializeConditions(rule.Conditions)),
            ("$updated_at", FormatTimestamp(DateTimeOffset.UtcNow)));

    private async Task<IReadOnlyList<AccessEntry>> ReadAccessEntriesAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT id, scope, kind, value, role
            FROM access_entries
            ORDER BY created_at ASC, id ASC;
            """;

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var entries = new List<AccessEntry>();

        while (await reader.ReadAsync(cancellationToken))
        {
            entries.Add(ReadAccessEntry(reader));
        }

        return entries;
    }

    private static async Task<AccessEntry?> ReadAccessEntryAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string id,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT id, scope, kind, value, role
            FROM access_entries
            WHERE id = $id
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$id", id);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        return await reader.ReadAsync(cancellationToken) ? ReadAccessEntry(reader) : null;
    }

    private static AccessEntry ReadAccessEntry(SqliteDataReader reader)
    {
        var scope = reader.GetString(1);

        return new AccessEntry
        {
            Id = reader.GetString(0),
            RuleId = string.Equals(scope, "global", StringComparison.Ordinal) ? null : scope,
            Kind = ParseKind(reader.GetString(2)),
            Value = reader.GetString(3),
            Role = reader.IsDBNull(4) ? null : reader.GetString(4)
        };
    }

    private static async Task<IReadOnlyList<SessionRecord>> ReadSessionsAsync(
        SqliteDataReader reader,
        CancellationToken cancellationToken)
    {
        var sessions = new List<SessionRecord>();

        while (await reader.ReadAsync(cancellationToken))
        {
            sessions.Add(new SessionRecord
            {
                Id = reader.GetString(0),
                Kind = ParseSessionKind(reader.GetString(1)),
                Email = reader.GetString(2),
                Provider = reader.GetString(3),
                Domain = reader.IsDBNull(4) ? null : reader.GetString(4),
                CreatedAt = ParseTimestamp(reader.GetString(5)),
                ExpiresAt = ParseTimestamp(reader.GetString(6)),
                LastSeenAt = ParseTimestamp(reader.GetString(7)),
                Ip = reader.IsDBNull(8) ? null : reader.GetString(8),
                UserAgent = reader.IsDBNull(9) ? null : reader.GetString(9),
                RevokedAt = reader.IsDBNull(10) ? null : ParseTimestamp(reader.GetString(10))
            });
        }

        return sessions;
    }

    private static Task AppendAuditAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string adminEmail,
        string action,
        string entity,
        string diffJson,
        CancellationToken cancellationToken) =>
        ExecuteAsync(
            connection,
            transaction,
            """
            INSERT INTO audit_log (created_at, admin_email, action, entity, diff)
            VALUES ($created_at, $admin_email, $action, $entity, $diff);
            """,
            cancellationToken,
            ("$created_at", FormatTimestamp(DateTimeOffset.UtcNow)),
            ("$admin_email", adminEmail),
            ("$action", action),
            ("$entity", entity),
            ("$diff", diffJson));

    private static async Task ExecuteAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string sql,
        CancellationToken cancellationToken,
        params (string Name, object? Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;

        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private List<ConditionDefinition> DeserializeConditions(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize(json, AppJsonContext.Default.ListConditionDefinition) ?? [];
        }
        catch (JsonException exception)
        {
            _logger.Error("Failed to parse rule conditions; using an empty condition list", ("error", exception.Message));

            return [];
        }
    }

    private static List<string> DeserializeStrings(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize(json, AppJsonContext.Default.ListString) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static string SerializeConditions(IReadOnlyList<ConditionDefinition> conditions) =>
        JsonSerializer.Serialize(conditions.ToList(), AppJsonContext.Default.ListConditionDefinition);

    private static string SerializeStrings(IReadOnlyList<string> values) =>
        JsonSerializer.Serialize(values.ToList(), AppJsonContext.Default.ListString);

    private static string SerializeDiff(Dictionary<string, string?> diff) =>
        JsonSerializer.Serialize(diff, typeof(Dictionary<string, string?>), AppJsonContext.Default);

    private static string SerializeRuleDiff(RuleDefinition rule) =>
        JsonSerializer.Serialize(rule, typeof(RuleDefinition), AppJsonContext.Default);

    private static string SerializeAccessDiff(AccessEntry entry) =>
        JsonSerializer.Serialize(entry, typeof(AccessEntry), AppJsonContext.Default);

    private static string FormatTimestamp(DateTimeOffset value) =>
        value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseTimestamp(string value) =>
        DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private static string ActionToString(RuleAction action) =>
        action == RuleAction.Allow ? "allow" : "auth";

    private static RuleAction ParseAction(string value) =>
        string.Equals(value, "allow", StringComparison.OrdinalIgnoreCase) ? RuleAction.Allow : RuleAction.Auth;

    private static string KindToString(AccessKind kind) =>
        kind == AccessKind.Domain ? "domain" : "email";

    private static AccessKind ParseKind(string value) =>
        string.Equals(value, "domain", StringComparison.OrdinalIgnoreCase) ? AccessKind.Domain : AccessKind.Email;

    private static string KindToString(SessionKind kind) =>
        kind == SessionKind.Admin ? "admin" : "forward-auth";

    private static SessionKind ParseSessionKind(string value) =>
        string.Equals(value, "admin", StringComparison.OrdinalIgnoreCase) ? SessionKind.Admin : SessionKind.ForwardAuth;

    private static string FormatBool(bool value) => value ? "true" : "false";

    private static string FormatSeconds(TimeSpan value) =>
        ((long)value.TotalSeconds).ToString(CultureInfo.InvariantCulture);

    private static string JoinValues(IReadOnlyList<string> values) => string.Join(", ", values);

    private static void AddChange(
        Dictionary<string, string?> diff,
        string key,
        string? oldValue,
        string? newValue)
    {
        if (!string.Equals(oldValue, newValue, StringComparison.Ordinal))
        {
            diff[key] = (oldValue ?? "(none)") + " -> " + (newValue ?? "(none)");
        }
    }

    private static string EscapeLike(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("%", "\\%", StringComparison.Ordinal)
            .Replace("_", "\\_", StringComparison.Ordinal);
}
