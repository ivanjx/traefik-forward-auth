using System.Text;
using TraefikForwardAuth.Auth;
using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Policy;

namespace TraefikForwardAuth.Tests;

public sealed class AuthTests
{
    private static readonly byte[] Secret = Encoding.UTF8.GetBytes("test-signing-secret");

    [Fact]
    public void AuthCookieRoundTrips()
    {
        var now = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var expires = now.AddHours(1);

        var value = CookieService.CreateAuthCookieValue(
            Secret,
            "example.com",
            "user@example.com",
            "0123456789abcdef0123456789abcdef",
            expires);

        Assert.Equal(4, value.Split('|').Length);

        var valid = CookieService.TryReadAuthCookieValue(
            Secret,
            "example.com",
            value,
            now,
            out var identity,
            out var failure,
            out var error);

        Assert.True(valid);
        Assert.Equal(CookieValidationFailure.None, failure);
        Assert.Equal("", error);
        Assert.Equal("user@example.com", identity.Email);
        Assert.Equal("0123456789abcdef0123456789abcdef", identity.SessionId);
    }

    [Fact]
    public void AuthCookieAcceptsPaddedSignature()
    {
        var now = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var value = CookieService.CreateAuthCookieValue(
            Secret,
            "example.com",
            "user@example.com",
            "session",
            now.AddMinutes(5));
        var parts = value.Split('|');
        parts[0] += "=";

        var valid = CookieService.TryReadAuthCookieValue(
            Secret,
            "example.com",
            string.Join('|', parts),
            now,
            out var identity,
            out var failure,
            out _);

        Assert.True(valid);
        Assert.Equal(CookieValidationFailure.None, failure);
        Assert.Equal("session", identity.SessionId);
    }

    [Fact]
    public void AuthCookieRejectsTamperingAndBadFormat()
    {
        var now = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var value = CookieService.CreateAuthCookieValue(
            Secret,
            "example.com",
            "user@example.com",
            "session",
            now.AddMinutes(5));
        var parts = value.Split('|');
        parts[2] = "attacker@example.com";
        parts[0] = "AAAA" + parts[0][4..];

        Assert.False(CookieService.TryReadAuthCookieValue(
            Secret,
            "example.com",
            string.Join('|', parts),
            now,
            out _,
            out var failure,
            out var error));
        Assert.Equal(CookieValidationFailure.Invalid, failure);
        Assert.NotEqual("", error);

        Assert.False(CookieService.TryReadAuthCookieValue(
            Secret,
            "example.com",
            "only|two",
            now,
            out _,
            out failure,
            out _));
        Assert.Equal(CookieValidationFailure.Invalid, failure);
    }

    [Fact]
    public void AuthCookieIsBoundToDomain()
    {
        var now = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var value = CookieService.CreateAuthCookieValue(
            Secret,
            "example.com",
            "user@example.com",
            "session",
            now.AddMinutes(5));

        Assert.False(CookieService.TryReadAuthCookieValue(
            Secret,
            "other.com",
            value,
            now,
            out _,
            out var failure,
            out _));
        Assert.Equal(CookieValidationFailure.Invalid, failure);
    }

    [Fact]
    public void ExpiredCookieIsReportedOnlyAfterValidMac()
    {
        var now = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var expired = CookieService.CreateAuthCookieValue(
            Secret,
            "example.com",
            "user@example.com",
            "session",
            now.AddSeconds(-1));

        Assert.False(CookieService.TryReadAuthCookieValue(
            Secret,
            "example.com",
            expired,
            now,
            out _,
            out var failure,
            out var error));
        Assert.Equal(CookieValidationFailure.Expired, failure);
        Assert.NotEqual("", error);

        var parts = expired.Split('|');
        parts[0] = "AAAA" + parts[0][4..];

        Assert.False(CookieService.TryReadAuthCookieValue(
            Secret,
            "example.com",
            string.Join('|', parts),
            now,
            out _,
            out failure,
            out _));
        Assert.Equal(CookieValidationFailure.Invalid, failure);
    }

    [Theory]
    [InlineData("app.example.com:8443", "example.com")]
    [InlineData("example.com:443", "example.com")]
    [InlineData("two.levels.example.com", "example.com")]
    [InlineData("api.other.org", "other.org")]
    [InlineData("unknown.net:8080", "unknown.net")]
    [InlineData("notexample.com", "notexample.com")]
    [InlineData("EXAMPLE.com", "EXAMPLE.com")]
    public void CookieDomainMatchesConfiguredDomainsOrHost(string host, string expected)
    {
        var settings = Settings(["example.com", "other.org"]);

        Assert.Equal(expected, CookieService.CookieDomain(settings, host));
    }

    [Fact]
    public void CookieDomainUsesFirstMatchAndTrimsEntries()
    {
        var settings = Settings(["  example.com  ", "sub.example.com"]);

        Assert.Equal("example.com", CookieService.CookieDomain(settings, "sub.example.com:80"));
    }

    [Fact]
    public void UseAuthDomainRequiresBothSidesToMatchTheSameDomain()
    {
        var settings = Settings(["example.com", "other.org"]) with { AuthHost = "auth.example.com" };

        Assert.True(CookieService.UseAuthDomain(settings, "app.example.com:443", out var matched));
        Assert.Equal("example.com", matched);

        Assert.False(CookieService.UseAuthDomain(settings, "app.other.org", out matched));
        Assert.Equal("app.other.org", matched);
    }

    [Fact]
    public void UseAuthDomainHandlesExactHostsAndMissingAuthHost()
    {
        var settings = Settings(["example.com"]) with { AuthHost = "example.com" };

        Assert.True(CookieService.UseAuthDomain(settings, "example.com:8080", out var matched));
        Assert.Equal("example.com", matched);

        Assert.False(CookieService.UseAuthDomain(settings with { AuthHost = "unconfigured.net" }, "example.com", out matched));
        Assert.Equal("example.com", matched);

        Assert.False(CookieService.UseAuthDomain(settings with { AuthHost = "" }, "example.com", out matched));
        Assert.Equal("example.com", matched);
    }

    [Fact]
    public void CsrfCookieDomainUsesMatchedAuthDomainOtherwiseHost()
    {
        var settings = Settings(["example.com"]) with { AuthHost = "auth.example.com" };

        Assert.Equal("example.com", CookieService.CsrfCookieDomain(settings, "app.example.com:443"));
        Assert.Equal("app.other.org", CookieService.CsrfCookieDomain(settings, "app.other.org:443"));
        Assert.Equal(
            "app.example.com",
            CookieService.CsrfCookieDomain(settings with { AuthHost = "" }, "app.example.com:443"));
    }

    [Fact]
    public void NonceIsLowercaseHexAndUnique()
    {
        var first = CsrfService.NewNonce();
        var second = CsrfService.NewNonce();

        Assert.Equal(CsrfService.NonceHexLength, first.Length);
        Assert.All(first, character => Assert.True(char.IsAsciiHexDigitLower(character)));
        Assert.NotEqual(first, second);
    }

    [Fact]
    public void CsrfCookieNameUsesNoncePrefix()
    {
        var nonce = "abcdef0123456789abcdef0123456789";
        var settings = Settings([]);

        Assert.Equal("_forward_auth_csrf_abcdef", CsrfService.CookieName(settings, nonce));
        Assert.Throws<ArgumentException>(() => CsrfService.CookieName(settings, "abc"));
    }

    [Fact]
    public void StateValidationRequiresMinimumLength()
    {
        var nonce = CsrfService.NewNonce();

        Assert.True(CsrfService.ValidateState(CsrfService.BuildState(nonce, "google", "https://app/cb"), out var error));
        Assert.Equal("", error);

        Assert.False(CsrfService.ValidateState(nonce, out error));
        Assert.NotEqual("", error);

        Assert.False(CsrfService.ValidateState(null, out error));
        Assert.NotEqual("", error);
    }

    [Fact]
    public void CsrfCookieValidationExtractsProviderAndRedirectWithColons()
    {
        var nonce = CsrfService.NewNonce();
        var state = CsrfService.BuildState(nonce, "google", "https://app.example.com/path?x=1:2");

        Assert.True(CsrfService.TryValidateCookie(nonce, state, out var provider, out var redirect, out var error));
        Assert.Equal("google", provider);
        Assert.Equal("https://app.example.com/path?x=1:2", redirect);
        Assert.Equal("", error);
    }

    [Fact]
    public void CsrfCookieValidationAllowsEmptyRedirect()
    {
        var nonce = CsrfService.NewNonce();
        var state = CsrfService.BuildState(nonce, "oidc", "");

        Assert.True(CsrfService.TryValidateCookie(nonce, state, out var provider, out var redirect, out _));
        Assert.Equal("oidc", provider);
        Assert.Equal("", redirect);
    }

    [Theory]
    [InlineData("00000000000000000000000000000000")]
    [InlineData("short")]
    [InlineData("abcdef0123456789abcdef01234567890")]
    public void CsrfCookieValidationRejectsMismatchedCookie(string cookie)
    {
        var nonce = CsrfService.NewNonce();
        var state = CsrfService.BuildState(nonce, "google", "https://app/cb");

        Assert.False(CsrfService.TryValidateCookie(cookie, state, out var provider, out var redirect, out var error));
        Assert.Equal("", provider);
        Assert.Equal("", redirect);
        Assert.NotEqual("", error);
    }

    [Fact]
    public void CsrfCookieValidationRejectsMalformedState()
    {
        var nonce = CsrfService.NewNonce();

        Assert.False(CsrfService.TryValidateCookie(nonce, nonce, out _, out _, out var error));
        Assert.NotEqual("", error);

        Assert.False(CsrfService.TryValidateCookie(nonce, nonce + ":g", out _, out _, out error));
        Assert.NotEqual("", error);
    }

    [Fact]
    public async Task SessionCreateAndLookup()
    {
        var time = new MutableTimeProvider();
        var repository = new FakeSessionRepository();
        await using var manager = new SessionManager(repository, QuietLogger(time), time);

        var session = await manager.CreateAsync(
            SessionKind.ForwardAuth,
            "alice@example.com",
            "google",
            "example.com",
            "1.2.3.4",
            "agent",
            TimeSpan.FromHours(1),
            CancellationToken.None);

        Assert.Equal(32, session.Id.Length);
        Assert.All(session.Id, character => Assert.True(char.IsAsciiHexDigitLower(character)));
        Assert.Equal(time.Now, session.CreatedAt);
        Assert.Equal(time.Now, session.LastSeenAt);
        Assert.Equal(time.Now.AddHours(1), session.ExpiresAt);
        Assert.Single(repository.Inserts);
        Assert.Same(session, manager.Get(session.Id));

        Assert.True(manager.TryGetActive(session.Id, time.Now, out var active));
        Assert.Equal(session, active);
        Assert.Single(manager.List(SessionKind.ForwardAuth));
        Assert.Empty(manager.List(SessionKind.Admin));
        Assert.Single(manager.ListAll());
    }

    [Fact]
    public async Task SessionInsertFailureIsNotCached()
    {
        var time = new MutableTimeProvider();
        var repository = new FakeSessionRepository { ThrowOnInsert = true };
        await using var manager = new SessionManager(repository, QuietLogger(time), time);

        await Assert.ThrowsAsync<InvalidOperationException>(() => manager.CreateAsync(
            SessionKind.ForwardAuth,
            "alice@example.com",
            "google",
            null,
            null,
            null,
            TimeSpan.FromHours(1),
            CancellationToken.None));

        Assert.Empty(manager.ListAll());
    }

    [Fact]
    public async Task ExpiredSessionIsNotActiveButRemainsCached()
    {
        var time = new MutableTimeProvider();
        var repository = new FakeSessionRepository();
        await using var manager = new SessionManager(repository, QuietLogger(time), time);
        var session = await CreateForwardAuthAsync(manager);

        time.Advance(TimeSpan.FromHours(2));

        Assert.False(manager.TryGetActive(session.Id, time.Now, out _));
        Assert.NotNull(manager.Get(session.Id));
        Assert.Single(manager.List(SessionKind.ForwardAuth));
    }

    [Fact]
    public async Task RevokeRemovesSessionAndMarksRepository()
    {
        var time = new MutableTimeProvider();
        var repository = new FakeSessionRepository();
        await using var manager = new SessionManager(repository, QuietLogger(time), time);
        var first = await CreateForwardAuthAsync(manager);
        var second = await CreateForwardAuthAsync(manager, "bob@example.com");

        await manager.RevokeAsync(first.Id, CancellationToken.None);

        Assert.Null(manager.Get(first.Id));
        Assert.False(manager.TryGetActive(first.Id, time.Now, out _));
        Assert.True(manager.TryGetActive(second.Id, time.Now, out _));
        Assert.Single(repository.Revocations);
        Assert.Equal([first.Id], repository.Revocations[0].Ids);

        await manager.RevokeAsync("missing", CancellationToken.None);
        Assert.Equal(2, repository.Revocations.Count);
    }

    [Fact]
    public async Task RevokeForEmailOnlyMatchesKindAndEmail()
    {
        var time = new MutableTimeProvider();
        var repository = new FakeSessionRepository();
        await using var manager = new SessionManager(repository, QuietLogger(time), time);
        var forwardAuth = await CreateForwardAuthAsync(manager);
        var admin = await manager.CreateAsync(
            SessionKind.Admin,
            "alice@example.com",
            "google",
            null,
            null,
            null,
            TimeSpan.FromHours(1),
            CancellationToken.None);
        var other = await CreateForwardAuthAsync(manager, "bob@example.com");

        var count = await manager.RevokeForEmailAsync("alice@example.com", SessionKind.ForwardAuth, CancellationToken.None);

        Assert.Equal(1, count);
        Assert.Single(repository.Revocations);
        Assert.Equal([forwardAuth.Id], repository.Revocations[0].Ids);
        Assert.Null(manager.Get(forwardAuth.Id));
        Assert.True(manager.TryGetActive(admin.Id, time.Now, out _));
        Assert.True(manager.TryGetActive(other.Id, time.Now, out _));
        Assert.Equal(0, await manager.RevokeForEmailAsync("nobody@example.com", SessionKind.ForwardAuth, CancellationToken.None));
    }

    [Fact]
    public async Task RevokeAllCanTargetKindOrBoth()
    {
        var time = new MutableTimeProvider();
        var repository = new FakeSessionRepository();
        await using var manager = new SessionManager(repository, QuietLogger(time), time);
        var forwardAuth = await CreateForwardAuthAsync(manager);
        var admin = await manager.CreateAsync(
            SessionKind.Admin,
            "admin@example.com",
            "google",
            null,
            null,
            null,
            TimeSpan.FromHours(1),
            CancellationToken.None);

        await manager.RevokeAllAsync(SessionKind.Admin, CancellationToken.None);

        Assert.True(manager.TryGetActive(forwardAuth.Id, time.Now, out _));
        Assert.Null(manager.Get(admin.Id));
        Assert.Single(repository.Revocations);

        await manager.RevokeAllAsync(null, CancellationToken.None);

        Assert.Empty(manager.ListAll());
        Assert.Equal(2, repository.Revocations.Count);
    }

    [Fact]
    public async Task TouchUpdatesCacheAndFlushesBatchedLastSeen()
    {
        var time = new MutableTimeProvider();
        var repository = new FakeSessionRepository();
        await using var manager = new SessionManager(repository, QuietLogger(time), time);
        var session = await CreateForwardAuthAsync(manager);

        time.Advance(TimeSpan.FromMinutes(1));
        manager.Touch(session.Id);
        manager.Touch(session.Id);
        await manager.FlushPendingUpdatesAsync(TestContext.Current.CancellationToken);

        Assert.Equal(time.Now, manager.Get(session.Id)!.LastSeenAt);
        Assert.Single(repository.LastSeenUpdates);
        var update = Assert.Single(repository.LastSeenUpdates[0]);
        Assert.Equal(session.Id, update.Id);
        Assert.Equal(time.Now, update.LastSeenAt);
    }

    [Fact]
    public async Task TouchForMissingSessionIsIgnored()
    {
        var time = new MutableTimeProvider();
        var repository = new FakeSessionRepository();
        await using var manager = new SessionManager(repository, QuietLogger(time), time);

        manager.Touch("missing");
        await manager.FlushPendingUpdatesAsync(TestContext.Current.CancellationToken);

        Assert.Empty(repository.LastSeenUpdates);
    }

    [Fact]
    public async Task InitializeLoadsNonRevokedSessions()
    {
        var time = new MutableTimeProvider();
        var repository = new FakeSessionRepository();
        var active = Session("active", "active@example.com", time.Now.AddHours(1));
        var expired = Session("expired", "expired@example.com", time.Now.AddSeconds(-1));
        var revoked = Session("revoked", "revoked@example.com", time.Now.AddHours(1)) with
        {
            RevokedAt = time.Now.AddMinutes(-1)
        };
        repository.Sessions.AddRange([active, expired, revoked]);

        await using var manager = new SessionManager(repository, QuietLogger(time), time);
        await manager.InitializeAsync(CancellationToken.None);

        Assert.NotNull(manager.Get("active"));
        Assert.NotNull(manager.Get("expired"));
        Assert.Null(manager.Get("revoked"));
        Assert.False(manager.TryGetActive("expired", time.Now, out _));
    }

    [Fact]
    public async Task InitializeDeletesAndSkipsSessionsPastRetention()
    {
        var time = new MutableTimeProvider();
        var repository = new FakeSessionRepository();
        var recent = Session("recent", "recent@example.com", time.Now.AddDays(-1));
        var stale = Session("stale", "stale@example.com", time.Now - SessionManager.Retention - TimeSpan.FromMinutes(1));
        var staleRevoked = Session("stale-revoked", "revoked@example.com", time.Now.AddHours(1)) with
        {
            RevokedAt = time.Now - SessionManager.Retention - TimeSpan.FromMinutes(1)
        };
        repository.Sessions.AddRange([recent, stale, staleRevoked]);

        await using var manager = new SessionManager(repository, QuietLogger(time), time);
        await manager.InitializeAsync(CancellationToken.None);

        Assert.NotNull(manager.Get("recent"));
        Assert.Null(manager.Get("stale"));
        Assert.Equal(["recent"], repository.Sessions.Select(session => session.Id));
    }

    [Fact]
    public async Task PeriodicPruneRemovesSessionsPastRetention()
    {
        var time = new MutableTimeProvider();
        var repository = new FakeSessionRepository();
        await using var manager = new SessionManager(repository, QuietLogger(time), time);
        var old = await CreateForwardAuthAsync(manager, "old@example.com");

        time.Advance(SessionManager.Retention + TimeSpan.FromHours(2));
        var fresh = await CreateForwardAuthAsync(manager, "fresh@example.com");

        await manager.FlushPendingUpdatesAsync(TestContext.Current.CancellationToken);

        Assert.Null(manager.Get(old.Id));
        Assert.NotNull(manager.Get(fresh.Id));
        Assert.Equal([fresh.Id], repository.Sessions.Select(session => session.Id));
    }

    [Fact]
    public async Task DisposeFlushesPendingTouches()
    {
        var time = new MutableTimeProvider();
        var repository = new FakeSessionRepository();
        var manager = new SessionManager(repository, QuietLogger(time), time);
        var session = await CreateForwardAuthAsync(manager);

        time.Advance(TimeSpan.FromMinutes(1));
        manager.Touch(session.Id);
        await manager.DisposeAsync();

        var update = Assert.Single(repository.LastSeenUpdates);
        var entry = Assert.Single(update);
        Assert.Equal(session.Id, entry.Id);
        Assert.Equal(time.Now, entry.LastSeenAt);

        await manager.DisposeAsync();
    }

    [Fact]
    public void AccessValidatorUsesRuleScopeOverride()
    {
        var access = AccessIndex.Build(
        [
            Entry("global-email", null, AccessKind.Email, "global@example.com", "global-role"),
            Entry("global-domain", null, AccessKind.Domain, "globaldomain.com", "global-domain-role"),
            Entry("rule-domain", "r1", AccessKind.Domain, "corp.com", "corp-role")
        ]);

        Assert.True(AccessValidator.IsAllowed(access, null, "global@example.com", false));
        Assert.True(AccessValidator.IsAllowed(access, null, "user@globaldomain.com", true));
        Assert.False(AccessValidator.IsAllowed(access, null, "nobody@other.com", false));

        Assert.False(AccessValidator.IsAllowed(access, "r1", "global@example.com", false));
        Assert.True(AccessValidator.IsAllowed(access, "r1", "user@corp.com", false));
        Assert.True(AccessValidator.IsAllowed(access, "unknown-rule", "global@example.com", false));

        Assert.Equal("global-role", AccessValidator.GetRole(access, null, "global@example.com"));
        Assert.Equal("global-domain-role", AccessValidator.GetRole(access, null, "user@globaldomain.com"));
        Assert.Equal("corp-role", AccessValidator.GetRole(access, "r1", "user@corp.com"));
        Assert.Null(AccessValidator.GetRole(access, "r1", "global@example.com"));
    }

    [Fact]
    public void AccessValidatorMatchWhitelistOrDomainShortCircuits()
    {
        var access = AccessIndex.Build(
        [
            Entry("email", null, AccessKind.Email, "allowed@example.com", null),
            Entry("domain", null, AccessKind.Domain, "example.org", null)
        ]);

        Assert.False(AccessValidator.IsAllowed(access, null, "user@example.org", false));
        Assert.True(AccessValidator.IsAllowed(access, null, "user@example.org", true));
    }

    [Fact]
    public void AccessValidatorWithNoEntriesAllowsEveryone()
    {
        var access = AccessIndex.Build([]);

        Assert.True(AccessValidator.IsAllowed(access, null, "anyone@anywhere.com", false));
        Assert.True(AccessValidator.IsAllowed(access, "rule", "anyone@anywhere.com", false));
        Assert.Null(AccessValidator.GetRole(access, null, "anyone@anywhere.com"));
    }

    private static PolicySettings Settings(IReadOnlyList<string> cookieDomains) =>
        new() { CookieDomains = cookieDomains };

    private static AccessEntry Entry(string id, string? ruleId, AccessKind kind, string value, string? role) =>
        new()
        {
            Id = id,
            RuleId = ruleId,
            Kind = kind,
            Value = value,
            Role = role
        };

    private static Task<SessionRecord> CreateForwardAuthAsync(SessionManager manager, string email = "alice@example.com") =>
        manager.CreateAsync(
            SessionKind.ForwardAuth,
            email,
            "google",
            null,
            null,
            null,
            TimeSpan.FromHours(1),
            CancellationToken.None);

    private static SessionRecord Session(string id, string email, DateTimeOffset expiresAt) =>
        new()
        {
            Id = id,
            Kind = SessionKind.ForwardAuth,
            Email = email,
            Provider = "google",
            CreatedAt = expiresAt.AddHours(-1),
            ExpiresAt = expiresAt,
            LastSeenAt = expiresAt.AddHours(-1)
        };

    private static TfaLogger QuietLogger(TimeProvider timeProvider) =>
        new(TfaLogLevel.Critical, TfaLogFormat.Text, new StringWriter(), timeProvider);

    private sealed class MutableTimeProvider : TimeProvider
    {
        public DateTimeOffset Now { get; private set; } = new(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => Now;

        public void Advance(TimeSpan duration) => Now += duration;
    }

    private sealed class FakeSessionRepository : ISessionRepository
    {
        public List<SessionRecord> Sessions { get; } = [];

        public List<SessionRecord> Inserts { get; } = [];

        public List<(IReadOnlyCollection<string> Ids, DateTimeOffset RevokedAt)> Revocations { get; } = [];

        public List<IReadOnlyList<(string Id, DateTimeOffset LastSeenAt)>> LastSeenUpdates { get; } = [];

        public List<DateTimeOffset> PruneCutoffs { get; } = [];

        public bool ThrowOnInsert { get; init; }

        public Task<IReadOnlyList<SessionRecord>> LoadSessionsAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<SessionRecord>>(Sessions.ToArray());

        public Task InsertSessionAsync(SessionRecord session, CancellationToken cancellationToken)
        {
            if (ThrowOnInsert)
            {
                throw new InvalidOperationException("insert failed");
            }

            Inserts.Add(session);
            Sessions.Add(session);

            return Task.CompletedTask;
        }

        public Task MarkSessionsRevokedAsync(
            IReadOnlyCollection<string> ids,
            DateTimeOffset revokedAt,
            CancellationToken cancellationToken)
        {
            Revocations.Add((ids.ToArray(), revokedAt));

            return Task.CompletedTask;
        }

        public Task UpdateSessionsLastSeenAsync(
            IReadOnlyList<(string Id, DateTimeOffset LastSeenAt)> sessions,
            CancellationToken cancellationToken)
        {
            LastSeenUpdates.Add(sessions.ToArray());

            return Task.CompletedTask;
        }

        public Task<int> DeleteSessionsEndedBeforeAsync(DateTimeOffset cutoff, CancellationToken cancellationToken)
        {
            PruneCutoffs.Add(cutoff);

            return Task.FromResult(Sessions.RemoveAll(session =>
                session.ExpiresAt < cutoff || (session.RevokedAt is { } revokedAt && revokedAt < cutoff)));
        }
    }
}
