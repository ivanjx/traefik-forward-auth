using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using TraefikForwardAuth.Auth;
using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Policy;
using TraefikForwardAuth.Providers;
using TraefikForwardAuth.Storage;

namespace TraefikForwardAuth.Tests;

public sealed class StorageTests
{
    [Fact]
    public async Task FirstBootCreatesDefaultsAndSecret()
    {
        await WithStoreAsync(async store =>
        {
            await store.InitializeAsync(CancellationToken.None);

            var configuration = await store.LoadConfigurationAsync(CancellationToken.None);
            var settings = configuration.Settings;

            Assert.Equal(PolicySettings.DefaultCookieName, settings.CookieName);
            Assert.Equal(PolicySettings.DefaultCsrfCookieName, settings.CsrfCookieName);
            Assert.Empty(settings.CookieDomains);
            Assert.Equal("", settings.AuthHost);
            Assert.False(settings.InsecureCookie);
            Assert.Equal(PolicySettings.DefaultUrlPath, settings.UrlPath);
            Assert.Equal(TimeSpan.FromHours(12), settings.Lifetime);
            Assert.Null(settings.LogoutRedirect);
            Assert.Equal(RuleAction.Auth, settings.DefaultAction);
            Assert.Equal(PolicySettings.DefaultProviderName, settings.DefaultProvider);
            Assert.False(settings.MatchWhitelistOrDomain);
            Assert.Equal(32, settings.SigningSecret.Length);
            Assert.Contains(settings.SigningSecret, value => value != 0);

            Assert.Empty(configuration.Providers);
            Assert.Empty(configuration.Rules);
            Assert.Empty(configuration.AccessEntries);

            Assert.True(File.Exists(store.DatabasePath));

            await using var connection = new SqliteConnection($"Data Source={store.DatabasePath};Pooling=False");
            await connection.OpenAsync();

            Assert.Equal(2L, await ScalarAsync(connection, "PRAGMA user_version;"));
            Assert.Equal("wal", await ScalarTextAsync(connection, "PRAGMA journal_mode;"));

            if (!OperatingSystem.IsWindows())
            {
                var mode = File.GetUnixFileMode(store.DatabasePath);
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
            }
        });
    }

    [Fact]
    public async Task InitializeIsIdempotent()
    {
        await WithStoreAsync(async store =>
        {
            await store.InitializeAsync(CancellationToken.None);
            var first = await store.LoadConfigurationAsync(CancellationToken.None);

            await store.InitializeAsync(CancellationToken.None);
            var second = await store.LoadConfigurationAsync(CancellationToken.None);

            Assert.Equal(first.Settings.SigningSecret, second.Settings.SigningSecret);

            await using var connection = new SqliteConnection($"Data Source={store.DatabasePath};Pooling=False");
            await connection.OpenAsync();

            Assert.Equal(1L, await ScalarAsync(connection, "SELECT COUNT(*) FROM settings;"));
            Assert.Equal(2L, await ScalarAsync(connection, "PRAGMA user_version;"));
        });
    }

    [Fact]
    public async Task SettingsRoundtripKeepsSigningSecret()
    {
        await WithStoreAsync(async store =>
        {
            await store.InitializeAsync(CancellationToken.None);
            var before = await store.LoadConfigurationAsync(CancellationToken.None);

            var updated = new PolicySettings
            {
                CookieName = "cookie",
                CsrfCookieName = "csrf",
                CookieDomains = ["example.com", "auth.example.com"],
                AuthHost = "auth.example.com",
                InsecureCookie = true,
                UrlPath = "/oauth2",
                Lifetime = TimeSpan.FromMinutes(90),
                LogoutRedirect = "https://example.com/logout",
                DefaultAction = RuleAction.Allow,
                DefaultProvider = "oidc",
                MatchWhitelistOrDomain = true,
                SigningSecret = [1, 2, 3]
            };

            await store.UpdateSettingsAsync(updated, "admin@example.com", CancellationToken.None);

            var after = (await store.LoadConfigurationAsync(CancellationToken.None)).Settings;

            Assert.Equal(updated.CookieName, after.CookieName);
            Assert.Equal(updated.CsrfCookieName, after.CsrfCookieName);
            Assert.Equal(updated.CookieDomains, after.CookieDomains);
            Assert.Equal(updated.AuthHost, after.AuthHost);
            Assert.True(after.InsecureCookie);
            Assert.Equal(updated.UrlPath, after.UrlPath);
            Assert.Equal(updated.Lifetime, after.Lifetime);
            Assert.Equal(updated.LogoutRedirect, after.LogoutRedirect);
            Assert.Equal(updated.DefaultAction, after.DefaultAction);
            Assert.Equal(updated.DefaultProvider, after.DefaultProvider);
            Assert.True(after.MatchWhitelistOrDomain);
            Assert.Equal(before.Settings.SigningSecret, after.SigningSecret);

            var audit = await store.ListAuditAsync(10, CancellationToken.None);
            Assert.Equal("settings.update", audit[0].Action);
            Assert.Equal("settings", audit[0].Entity);
            Assert.DoesNotContain("signing_secret", audit[0].DiffJson, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task ProviderSaveIsWriteOnlyAndDeleteWorks()
    {
        await WithStoreAsync(async store =>
        {
            await store.InitializeAsync(CancellationToken.None);

            await store.UpsertProviderAsync(
                new ProviderDefinition
                {
                    Name = "oidc",
                    ClientId = "client",
                    ClientSecret = "super-secret-value",
                    IssuerUrl = "https://issuer.example.com",
                    Scopes = ["openid", "email"],
                    TokenStyle = "header"
                },
                "admin@example.com",
                CancellationToken.None);

            var providers = (await store.LoadConfigurationAsync(CancellationToken.None)).Providers;
            Assert.Single(providers);
            Assert.Equal("super-secret-value", providers[0].ClientSecret);

            await store.UpsertProviderAsync(
                new ProviderDefinition
                {
                    Name = "oidc",
                    ClientId = "client-updated",
                    ClientSecret = "",
                    IssuerUrl = "https://issuer.example.com",
                    Prompt = "select_account",
                    Scopes = ["openid"],
                    TokenStyle = "query"
                },
                "admin@example.com",
                CancellationToken.None);

            var updated = (await store.LoadConfigurationAsync(CancellationToken.None)).Providers[0];
            Assert.Equal("client-updated", updated.ClientId);
            Assert.Equal("super-secret-value", updated.ClientSecret);
            Assert.Equal("select_account", updated.Prompt);
            Assert.Equal("query", updated.TokenStyle);
            Assert.Equal(["openid"], updated.Scopes);

            var audit = await store.ListAuditAsync(100, CancellationToken.None);
            Assert.All(audit, entry => Assert.DoesNotContain("super-secret-value", entry.DiffJson, StringComparison.Ordinal));
            Assert.All(audit, entry => Assert.DoesNotContain("client_secret\\\":\\\"super", entry.DiffJson, StringComparison.Ordinal));

            await store.DeleteProviderAsync("oidc", "admin@example.com", CancellationToken.None);

            Assert.Empty((await store.LoadConfigurationAsync(CancellationToken.None)).Providers);
            Assert.Contains(await store.ListAuditAsync(100, CancellationToken.None), entry => entry.Action == "provider.delete");
        });
    }

    [Fact]
    public async Task RulesCreateUpdateMoveAndDeleteCascade()
    {
        await WithStoreAsync(async store =>
        {
            await store.InitializeAsync(CancellationToken.None);

            var first = await store.CreateRuleAsync(
                new RuleDefinition { Id = "", Name = "first", Conditions = [HostCondition("first.example.com")] },
                "admin@example.com",
                CancellationToken.None);
            var second = await store.CreateRuleAsync(
                new RuleDefinition { Id = "", Name = "second" },
                "admin@example.com",
                CancellationToken.None);
            var third = await store.CreateRuleAsync(
                new RuleDefinition { Id = "", Name = "third" },
                "admin@example.com",
                CancellationToken.None);

            Assert.False(string.IsNullOrWhiteSpace(first.Id));
            Assert.Equal(0, first.Position);
            Assert.Equal(1, second.Position);
            Assert.Equal(2, third.Position);

            var stored = (await store.LoadConfigurationAsync(CancellationToken.None)).Rules;
            Assert.Equal(["first", "second", "third"], stored.Select(rule => rule.Name));
            Assert.Single(stored[0].Conditions);

            var updatedSecond = second with
            {
                Name = "second-edited",
                Position = 42,
                Enabled = false,
                Action = RuleAction.Allow,
                Provider = "oidc"
            };

            await store.UpdateRuleAsync(updatedSecond, "admin@example.com", CancellationToken.None);

            var afterUpdate = (await store.LoadConfigurationAsync(CancellationToken.None)).Rules;
            var reloadedSecond = Assert.Single(afterUpdate, rule => rule.Id == second.Id);
            Assert.Equal(1, reloadedSecond.Position);
            Assert.Equal("second-edited", reloadedSecond.Name);
            Assert.False(reloadedSecond.Enabled);
            Assert.Equal(RuleAction.Allow, reloadedSecond.Action);
            Assert.Equal("oidc", reloadedSecond.Provider);

            await store.MoveRuleAsync(third.Id, -1, "admin@example.com", CancellationToken.None);

            var afterMoveUp = (await store.LoadConfigurationAsync(CancellationToken.None)).Rules;
            Assert.Equal(["first", "third", "second-edited"], afterMoveUp.Select(rule => rule.Name));
            Assert.Equal(1, afterMoveUp.Single(rule => rule.Id == third.Id).Position);
            Assert.Equal(2, afterMoveUp.Single(rule => rule.Id == second.Id).Position);

            await store.MoveRuleAsync(third.Id, 1, "admin@example.com", CancellationToken.None);

            var afterMoveDown = (await store.LoadConfigurationAsync(CancellationToken.None)).Rules;
            Assert.Equal(["first", "second-edited", "third"], afterMoveDown.Select(rule => rule.Name));

            await store.MoveRuleAsync(first.Id, -1, "admin@example.com", CancellationToken.None);
            Assert.Equal(0, (await store.LoadConfigurationAsync(CancellationToken.None)).Rules[0].Position);

            await store.AddAccessEntryAsync(
                new AccessEntry { Id = "", Kind = AccessKind.Domain, Value = "first.example.com" },
                "admin@example.com",
                CancellationToken.None);
            await store.AddAccessEntryAsync(
                new AccessEntry { Id = "", RuleId = first.Id, Kind = AccessKind.Email, Value = "user@example.com" },
                "admin@example.com",
                CancellationToken.None);

            await store.DeleteRuleAsync(first.Id, "admin@example.com", CancellationToken.None);

            var afterDelete = await store.LoadConfigurationAsync(CancellationToken.None);
            Assert.DoesNotContain(afterDelete.Rules, rule => rule.Id == first.Id);
            Assert.Single(afterDelete.AccessEntries);
            Assert.Null(afterDelete.AccessEntries[0].RuleId);
            Assert.Contains(
                await store.ListAuditAsync(100, CancellationToken.None),
                entry => entry.Action == "rule.delete" && entry.DiffJson.Contains("first.example.com", StringComparison.Ordinal));

            await Assert.ThrowsAsync<KeyNotFoundException>(() =>
                store.UpdateRuleAsync(first with { Name = "gone" }, "admin@example.com", CancellationToken.None));
        });
    }

    [Fact]
    public async Task AccessEntriesRoundtripGlobalAndRuleScoped()
    {
        await WithStoreAsync(async store =>
        {
            await store.InitializeAsync(CancellationToken.None);

            await store.AddAccessEntryAsync(
                new AccessEntry { Id = "", Kind = AccessKind.Email, Value = "user@example.com", Role = "admin" },
                "admin@example.com",
                CancellationToken.None);
            await store.AddAccessEntryAsync(
                new AccessEntry { Id = "", RuleId = "rule-1", Kind = AccessKind.Domain, Value = "example.com" },
                "admin@example.com",
                CancellationToken.None);

            var entries = (await store.LoadConfigurationAsync(CancellationToken.None)).AccessEntries;

            Assert.Equal(2, entries.Count);
            var global = Assert.Single(entries, entry => entry.RuleId is null);
            var scoped = Assert.Single(entries, entry => entry.RuleId is not null);
            Assert.Equal(AccessKind.Email, global.Kind);
            Assert.Equal("user@example.com", global.Value);
            Assert.Equal("admin", global.Role);
            Assert.Equal("rule-1", scoped.RuleId);
            Assert.Equal(AccessKind.Domain, scoped.Kind);

            await store.DeleteAccessEntryAsync(global.Id, "admin@example.com", CancellationToken.None);

            var remaining = (await store.LoadConfigurationAsync(CancellationToken.None)).AccessEntries;
            Assert.Single(remaining);
            Assert.Equal(scoped.Id, remaining[0].Id);
            Assert.Contains(
                await store.ListAuditAsync(100, CancellationToken.None),
                entry => entry.Action == "access.delete");
        });
    }

    [Fact]
    public async Task AuditLogGrowsAndNeverContainsSecrets()
    {
        await WithStoreAsync(async store =>
        {
            await store.InitializeAsync(CancellationToken.None);
            var originalSecret = (await store.LoadConfigurationAsync(CancellationToken.None)).Settings.SigningSecret;

            await store.UpsertProviderAsync(
                new ProviderDefinition
                {
                    Name = "google",
                    ClientId = "client",
                    ClientSecret = "audit-secret-value"
                },
                "admin@example.com",
                CancellationToken.None);

            var settings = (await store.LoadConfigurationAsync(CancellationToken.None)).Settings;
            await store.UpdateSettingsAsync(
                settings with { CookieName = "changed_cookie" },
                "admin@example.com",
                CancellationToken.None);

            await store.CreateRuleAsync(
                new RuleDefinition { Id = "", Name = "rule", Conditions = [HostCondition("example.com")] },
                "admin@example.com",
                CancellationToken.None);

            await store.UpdateSigningSecretAsync([9, 9, 9], "admin@example.com", CancellationToken.None);

            var audit = await store.ListAuditAsync(100, CancellationToken.None);

            Assert.True(audit.Count >= 4);
            Assert.Equal("secret.rotate", audit[0].Action);

            foreach (var entry in audit)
            {
                using var document = JsonDocument.Parse(entry.DiffJson);
                Assert.Equal(JsonValueKind.Object, document.RootElement.ValueKind);
                Assert.DoesNotContain("audit-secret-value", entry.DiffJson, StringComparison.Ordinal);
                Assert.DoesNotContain(Convert.ToBase64String(originalSecret), entry.DiffJson, StringComparison.Ordinal);
                Assert.DoesNotContain(Convert.ToBase64String([9, 9, 9]), entry.DiffJson, StringComparison.Ordinal);
            }

            Assert.Single(await store.ListAuditAsync(0, CancellationToken.None));
            Assert.Equal(audit.Count, (await store.ListAuditAsync(10_000, CancellationToken.None)).Count);
        });
    }

    [Fact]
    public async Task SessionsInsertRevokeTouchAndFilter()
    {
        await WithStoreAsync(async store =>
        {
            await store.InitializeAsync(CancellationToken.None);

            var now = DateTimeOffset.UtcNow;
            var alice = new SessionRecord
            {
                Id = "s-alice",
                Kind = SessionKind.ForwardAuth,
                Email = "alice@example.com",
                Provider = "google",
                Domain = "example.com",
                CreatedAt = now.AddHours(-1),
                ExpiresAt = now.AddHours(8),
                LastSeenAt = now.AddMinutes(-5),
                Ip = "203.0.113.10",
                UserAgent = "Test Agent"
            };
            var bob = alice with
            {
                Id = "s-bob",
                Email = "bob@example.com",
                LastSeenAt = now,
                Ip = null,
                UserAgent = null
            };
            var admin = alice with
            {
                Id = "s-admin",
                Kind = SessionKind.Admin,
                Email = "ALICE@admin.example.com",
                LastSeenAt = now.AddMinutes(-10)
            };

            await store.InsertSessionAsync(alice, CancellationToken.None);
            await store.InsertSessionAsync(bob, CancellationToken.None);
            await store.InsertSessionAsync(admin, CancellationToken.None);

            var all = await store.LoadSessionsAsync(CancellationToken.None);
            Assert.Equal(3, all.Count);
            var loadedAlice = Assert.Single(all, session => session.Id == alice.Id);
            Assert.Equal(alice.Email, loadedAlice.Email);
            Assert.Equal(alice.CreatedAt, loadedAlice.CreatedAt);
            Assert.Equal(alice.ExpiresAt, loadedAlice.ExpiresAt);
            Assert.Equal(alice.LastSeenAt, loadedAlice.LastSeenAt);
            Assert.Equal(alice.Ip, loadedAlice.Ip);
            Assert.Equal(alice.UserAgent, loadedAlice.UserAgent);
            Assert.Equal(alice.Domain, loadedAlice.Domain);
            Assert.Null(loadedAlice.RevokedAt);

            Assert.Equal(2, (await store.ListSessionsAsync(SessionKind.ForwardAuth, null, CancellationToken.None)).Count);
            Assert.Equal(2, (await store.ListSessionsAsync(null, "alice", CancellationToken.None)).Count);
            var aliceForwardOnly = await store.ListSessionsAsync(
                SessionKind.ForwardAuth,
                "ALICE",
                CancellationToken.None);
            Assert.Equal(alice.Id, Assert.Single(aliceForwardOnly).Id);

            var revokedAt = now.AddMinutes(1);
            await store.MarkSessionsRevokedAsync([alice.Id], revokedAt, CancellationToken.None);

            Assert.DoesNotContain(
                await store.ListSessionsAsync(null, null, CancellationToken.None),
                session => session.Id == alice.Id);
            var revoked = Assert.Single(
                await store.LoadSessionsAsync(CancellationToken.None),
                session => session.Id == alice.Id);
            Assert.Equal(revokedAt, revoked.RevokedAt);

            await store.MarkSessionsRevokedAsync([alice.Id], revokedAt.AddMinutes(5), CancellationToken.None);
            revoked = Assert.Single(
                await store.LoadSessionsAsync(CancellationToken.None),
                session => session.Id == alice.Id);
            Assert.Equal(revokedAt, revoked.RevokedAt);

            var touchedAt = now.AddMinutes(30);
            await store.UpdateSessionsLastSeenAsync(
                [(bob.Id, touchedAt), (admin.Id, now.AddMinutes(-1))],
                CancellationToken.None);

            var active = await store.ListSessionsAsync(null, null, CancellationToken.None);
            Assert.Equal([bob.Id, admin.Id], active.Select(session => session.Id));
            Assert.Equal(touchedAt, active[0].LastSeenAt);
        });
    }

    [Fact]
    public async Task PolicyManagerBuildsSnapshotWithRulesAccessAndNoProviders()
    {
        await WithStoreAsync(async (SqliteStore store, TfaLogger logger) =>
        {
            await store.InitializeAsync(CancellationToken.None);

            var authRule = await store.CreateRuleAsync(
                new RuleDefinition
                {
                    Id = "",
                    Name = "auth-rule",
                    Action = RuleAction.Auth,
                    Conditions = [HostCondition("app.example.com")]
                },
                "admin@example.com",
                CancellationToken.None);
            var disabledRule = await store.CreateRuleAsync(
                new RuleDefinition
                {
                    Id = "",
                    Name = "disabled-rule",
                    Enabled = false,
                    Action = RuleAction.Allow,
                    Conditions = [HostCondition("public.example.com")]
                },
                "admin@example.com",
                CancellationToken.None);

            await store.AddAccessEntryAsync(
                new AccessEntry { Id = "", Kind = AccessKind.Email, Value = "global@example.com" },
                "admin@example.com",
                CancellationToken.None);
            await store.AddAccessEntryAsync(
                new AccessEntry
                {
                    Id = "",
                    RuleId = authRule.Id,
                    Kind = AccessKind.Domain,
                    Value = "example.com",
                    Role = "admin"
                },
                "admin@example.com",
                CancellationToken.None);

            var factory = new ProviderFactory(new StubHttpClientFactory(), GoogleEndpoints.Default, logger);
            var manager = new PolicyManager(store, factory, logger);

            await manager.InitializeAsync(CancellationToken.None);

            var snapshot = manager.Current;
            Assert.NotSame(PolicySnapshot.Empty, snapshot);
            Assert.Same(snapshot, manager.Current);
            Assert.False(snapshot.HasProviders);
            Assert.Empty(snapshot.Providers);
            Assert.Equal(RuleAction.Auth, snapshot.Settings.DefaultAction);
            Assert.Equal(PolicySettings.DefaultProviderName, snapshot.Settings.DefaultProvider);
            Assert.Equal(32, snapshot.Settings.SigningSecret.Length);
            Assert.Equal([authRule.Id, disabledRule.Id], snapshot.Rules.Select(rule => rule.Definition.Id));
            Assert.False(snapshot.Rules[1].Definition.Enabled);

            var globalScope = snapshot.Access.ForRule(null);
            Assert.True(globalScope.IsAllowed("global@example.com", matchWhitelistOrDomain: false));
            Assert.False(globalScope.IsAllowed("other@example.com", matchWhitelistOrDomain: false));

            var ruleScope = snapshot.Access.ForRule(authRule.Id);
            Assert.True(ruleScope.HasEntries);
            Assert.True(ruleScope.IsAllowed("user@example.com", matchWhitelistOrDomain: false));
            Assert.False(ruleScope.IsAllowed("user@other.com", matchWhitelistOrDomain: false));
            Assert.Equal("admin", ruleScope.RoleFor("user@example.com"));

            var third = await store.CreateRuleAsync(
                new RuleDefinition { Id = "", Name = "third", Conditions = [HostCondition("third.example.com")] },
                "admin@example.com",
                CancellationToken.None);

            var rebuilt = await manager.RebuildAsync(CancellationToken.None);
            Assert.Same(rebuilt, manager.Current);
            Assert.Equal(3, rebuilt.Rules.Count);
            Assert.Equal(third.Id, rebuilt.Rules[2].Definition.Id);
        });
    }

    [Fact]
    public async Task PolicyManagerRetriesFailedProviderAndKeepsItAcrossLaterOutages()
    {
        await WithStoreAsync(async (SqliteStore store, TfaLogger logger) =>
        {
            await store.InitializeAsync(CancellationToken.None);
            await store.UpsertProviderAsync(OidcDefinition(), "admin@example.com", CancellationToken.None);

            var issuer = new DiscoveryHandler { Available = false };
            var timers = new ManualTimeProvider();
            var factory = new ProviderFactory(new HandlerHttpClientFactory(issuer), GoogleEndpoints.Default, logger);
            await using var manager = new PolicyManager(store, factory, logger, timers);

            await manager.InitializeAsync(CancellationToken.None);
            Assert.False(manager.Current.Providers.ContainsKey(ProviderDefinition.Oidc));

            issuer.Available = true;
            timers.FireLast();
            await WaitUntilAsync(() => manager.Current.Providers.ContainsKey(ProviderDefinition.Oidc));

            var provider = manager.Current.Providers[ProviderDefinition.Oidc];

            issuer.Available = false;
            await store.CreateRuleAsync(
                new RuleDefinition { Id = "", Name = "unrelated", Conditions = [HostCondition("x.example.com")] },
                "admin@example.com",
                CancellationToken.None);
            var rebuilt = await manager.RebuildAsync(CancellationToken.None);

            Assert.Same(provider, rebuilt.Providers[ProviderDefinition.Oidc]);
            Assert.Single(rebuilt.Rules);
        });
    }

    [Fact]
    public async Task PolicyManagerConcurrentRebuildsNeverRestoreOlderConfiguration()
    {
        await WithStoreAsync(async (SqliteStore store, TfaLogger logger) =>
        {
            await store.InitializeAsync(CancellationToken.None);
            await store.UpsertProviderAsync(OidcDefinition(), "admin@example.com", CancellationToken.None);

            var issuer = new DiscoveryHandler { BlockFirstRequest = true };
            var factory = new ProviderFactory(new HandlerHttpClientFactory(issuer), GoogleEndpoints.Default, logger);
            await using var manager = new PolicyManager(store, factory, logger, new ManualTimeProvider());

            // The first rebuild loads the configuration without the rule, then stalls in discovery.
            var stale = manager.RebuildAsync(CancellationToken.None);
            await issuer.FirstRequestStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));

            await store.CreateRuleAsync(
                new RuleDefinition { Id = "", Name = "new", Conditions = [HostCondition("new.example.com")] },
                "admin@example.com",
                CancellationToken.None);
            var fresh = manager.RebuildAsync(CancellationToken.None);

            issuer.ReleaseFirstRequest.SetResult();
            await Task.WhenAll(stale, fresh).WaitAsync(TimeSpan.FromSeconds(10));

            Assert.Single(manager.Current.Rules);
            Assert.Same(await fresh, manager.Current);
        });
    }

    private static ProviderDefinition OidcDefinition() => new()
    {
        Name = ProviderDefinition.Oidc,
        IssuerUrl = DiscoveryHandler.Issuer,
        ClientId = "client",
        ClientSecret = "secret"
    };

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);

        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "Condition was not met in time.");
            await Task.Delay(10);
        }
    }

    private static ConditionDefinition HostCondition(string host) => new()
    {
        Field = ConditionField.Host,
        Operator = ConditionOperator.Is,
        Values = [host]
    };

    private static async Task WithStoreAsync(Func<SqliteStore, Task> test) =>
        await WithStoreAsync(async (store, _) => await test(store));

    private static async Task WithStoreAsync(Func<SqliteStore, TfaLogger, Task> test)
    {
        var directory = Path.Combine(
            Path.GetTempPath(),
            "tfa-storage-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        var logger = new TfaLogger(TfaLogLevel.Warn, TfaLogFormat.Text, new StringWriter());
        var store = new SqliteStore(Path.Combine(directory, "traefik-forward-auth.db"), logger);

        try
        {
            await test(store, logger);
        }
        finally
        {
            await store.DisposeAsync();
            TryDeleteDirectory(directory);
        }
    }

    private static void TryDeleteDirectory(string directory)
    {
        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                Directory.Delete(directory, recursive: true);
                return;
            }
            catch (IOException) when (attempt < 2)
            {
                Thread.Sleep(50);
            }
            catch (UnauthorizedAccessException) when (attempt < 2)
            {
                Thread.Sleep(50);
            }
        }
    }

    private static async Task<long> ScalarAsync(SqliteConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        var result = await command.ExecuteScalarAsync();

        return Convert.ToInt64(result, CultureInfo.InvariantCulture);
    }

    private static async Task<string> ScalarTextAsync(SqliteConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        var result = await command.ExecuteScalarAsync();

        return Convert.ToString(result, CultureInfo.InvariantCulture) ?? "";
    }

    private sealed class StubHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new();
    }

    private sealed class HandlerHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class DiscoveryHandler : HttpMessageHandler
    {
        public const string Issuer = "https://issuer.test";

        private int _requests;

        public volatile bool Available = true;

        public bool BlockFirstRequest { get; init; }

        public TaskCompletionSource FirstRequestStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ReleaseFirstRequest { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (BlockFirstRequest && Interlocked.Increment(ref _requests) == 1)
            {
                FirstRequestStarted.SetResult();
                await ReleaseFirstRequest.Task.WaitAsync(cancellationToken);
            }

            if (!Available)
            {
                return new HttpResponseMessage(System.Net.HttpStatusCode.ServiceUnavailable);
            }

            var body = $$"""
                {
                  "issuer": "{{Issuer}}",
                  "authorization_endpoint": "{{Issuer}}/authorize",
                  "token_endpoint": "{{Issuer}}/token",
                  "jwks_uri": "{{Issuer}}/jwks"
                }
                """;

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json")
            };
        }
    }

    /// <summary>Captures timers so a test can fire them on demand instead of waiting.</summary>
    private sealed class ManualTimeProvider : TimeProvider
    {
        private readonly List<ManualTimer> _timers = [];

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new ManualTimer(callback, state);

            lock (_timers)
            {
                _timers.Add(timer);
            }

            return timer;
        }

        public void FireLast()
        {
            ManualTimer timer;

            lock (_timers)
            {
                timer = _timers[^1];
            }

            timer.Fire();
        }

        private sealed class ManualTimer(TimerCallback callback, object? state) : ITimer
        {
            private bool _disposed;

            public void Fire()
            {
                Assert.False(_disposed, "Timer was disposed before firing.");
                callback(state);
            }

            public bool Change(TimeSpan dueTime, TimeSpan period) => !_disposed;

            public void Dispose() => _disposed = true;

            public ValueTask DisposeAsync()
            {
                _disposed = true;
                return ValueTask.CompletedTask;
            }
        }
    }
}
