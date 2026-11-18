using System.Net;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using TraefikForwardAuth.Auth;
using TraefikForwardAuth.Http;
using TraefikForwardAuth.Logging;
using TraefikForwardAuth.Policy;
using TraefikForwardAuth.Providers;
using TraefikForwardAuth.Rules;

namespace TraefikForwardAuth.Tests;

public sealed class ForwardAuthTests
{
    private const string Host = "app.example.com";
    private const string Proto = "https";
    private const string Email = "user@example.com";
    private const string ProviderName = "google";
    private static readonly byte[] Secret = Encoding.UTF8.GetBytes("forward-auth-test-secret");

    [Fact]
    public async Task AllowRule_Returns200WithoutUserHeader()
    {
        var provider = new FakeProvider();
        var snapshot = Snapshot(
            Settings(),
            [Rule("allow", RuleAction.Allow, true, pathPrefix: "/public", name: "public")],
            Providers(provider));

        await RunAsync(snapshot, new FakeTimeProvider(), async (client, _) =>
        {
            var response = await client.SendAsync(Request("/public/page"));

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("", await response.Content.ReadAsStringAsync());
            Assert.False(response.Headers.Contains("X-Forwarded-User"));
            Assert.False(response.Headers.Contains("X-Forwarded-Role"));
        });
    }

    [Fact]
    public async Task AuthWithoutCookie_RedirectsToProviderWithCsrfCookieAndReturnUrl()
    {
        var provider = new FakeProvider();
        var snapshot = Snapshot(
            Settings(),
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers(provider));

        await RunAsync(snapshot, new FakeTimeProvider(), async (client, _) =>
        {
            var response = await client.SendAsync(Request("/some/path?ignored=1"));

            Assert.Equal(HttpStatusCode.TemporaryRedirect, response.StatusCode);

            var location = response.Headers.Location!.ToString();
            Assert.StartsWith("https://provider.example/login?", location);
            Assert.NotNull(provider.LastState);
            Assert.EndsWith(":https://app.example.com/some/path", provider.LastState);
            Assert.Equal("https://app.example.com/_oauth", provider.LastRedirectUri);

            var state = provider.LastState!;
            var csrfName = "_forward_auth_csrf_" + state[..6];
            var csrfHeader = FindCookieHeader(response, csrfName);

            Assert.NotNull(csrfHeader);
            Assert.Equal(state[..32], CookieValue(csrfHeader!));
            Assert.Contains("path=/", csrfHeader, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("httponly", csrfHeader, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("samesite", csrfHeader, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Fact]
    public async Task ValidCookieWithoutSession_RedirectsToLogin()
    {
        var provider = new FakeProvider();
        var settings = Settings();
        var snapshot = Snapshot(
            settings,
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers(provider));

        var time = new FakeTimeProvider();
        var cookie = AuthCookie(settings, Host, Email, "0123456789abcdef0123456789abcdef", time.GetUtcNow().AddHours(1));

        await RunAsync(snapshot, time, async (client, _) =>
        {
            var response = await client.SendAsync(Request("/private", cookies: [("_forward_auth", cookie)]));

            Assert.Equal(HttpStatusCode.TemporaryRedirect, response.StatusCode);
            Assert.False(response.Headers.Contains("X-Forwarded-User"));
        });
    }

    [Fact]
    public async Task RevokedSession_RedirectsToLogin()
    {
        var provider = new FakeProvider();
        var settings = Settings();
        var snapshot = Snapshot(
            settings,
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers(provider));
        var time = new FakeTimeProvider();

        await RunAsync(snapshot, time, async (client, sessions) =>
        {
            var session = await CreateSessionAsync(sessions);
            var cookie = AuthCookie(settings, Host, Email, session.Id, session.ExpiresAt);
            await sessions.RevokeAsync(session.Id, CancellationToken.None);

            var response = await client.SendAsync(Request("/private", cookies: [("_forward_auth", cookie)]));

            Assert.Equal(HttpStatusCode.TemporaryRedirect, response.StatusCode);
            Assert.False(response.Headers.Contains("X-Forwarded-User"));
        });
    }

    [Fact]
    public async Task ExpiredSession_RedirectsToLogin()
    {
        var provider = new FakeProvider();
        var settings = Settings();
        var snapshot = Snapshot(
            settings,
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers(provider));
        var time = new FakeTimeProvider();

        await RunAsync(snapshot, time, async (client, sessions) =>
        {
            var session = await CreateSessionAsync(sessions);
            // The cookie outlives the session so the session expiry check is what rejects it.
            var cookie = AuthCookie(settings, Host, Email, session.Id, time.GetUtcNow().AddHours(2));
            time.Advance(TimeSpan.FromMinutes(90));

            var response = await client.SendAsync(Request("/private", cookies: [("_forward_auth", cookie)]));

            Assert.Equal(HttpStatusCode.TemporaryRedirect, response.StatusCode);
            Assert.False(response.Headers.Contains("X-Forwarded-User"));
        });
    }

    [Fact]
    public async Task TamperedCookie_Returns401()
    {
        var provider = new FakeProvider();
        var settings = Settings();
        var snapshot = Snapshot(
            settings,
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers(provider));

        var time = new FakeTimeProvider();
        var valid = AuthCookie(settings, Host, Email, "session", time.GetUtcNow().AddHours(1));
        var parts = valid.Split('|');
        parts[2] = "attacker@example.com";
        var tampered = string.Join('|', parts);

        await RunAsync(snapshot, time, async (client, _) =>
        {
            var response = await client.SendAsync(Request("/private", cookies: [("_forward_auth", tampered)]));

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            var body = await response.Content.ReadAsStringAsync();
            Assert.Contains("Not authorized", body);
            Assert.Contains("href=\"/_oauth/logout\"", body);
            Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        });
    }

    [Fact]
    public async Task ValidUser_ReturnsUserAndRoleHeaders()
    {
        var provider = new FakeProvider();
        var settings = Settings();
        var access = new[]
        {
            new AccessEntry
            {
                Id = "entry-1",
                RuleId = "auth",
                Kind = AccessKind.Email,
                Value = Email,
                Role = "admin"
            }
        };
        var snapshot = Snapshot(
            settings,
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers(provider),
            access);
        var time = new FakeTimeProvider();

        await RunAsync(snapshot, time, async (client, sessions) =>
        {
            var session = await CreateSessionAsync(sessions);
            var cookie = AuthCookie(settings, Host, Email, session.Id, session.ExpiresAt);

            var response = await client.SendAsync(Request("/private", cookies: [("_forward_auth", cookie)]));

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("", await response.Content.ReadAsStringAsync());
            Assert.Equal(Email, response.Headers.GetValues("X-Forwarded-User").Single());
            Assert.Equal("admin", response.Headers.GetValues("X-Forwarded-Role").Single());
        });
    }

    [Fact]
    public async Task AccessDenied_Returns401()
    {
        var provider = new FakeProvider();
        var settings = Settings();
        var access = new[]
        {
            new AccessEntry
            {
                Id = "entry-1",
                RuleId = "auth",
                Kind = AccessKind.Email,
                Value = "other@example.com"
            }
        };
        var snapshot = Snapshot(
            settings,
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers(provider),
            access);
        var time = new FakeTimeProvider();

        await RunAsync(snapshot, time, async (client, sessions) =>
        {
            var session = await CreateSessionAsync(sessions);
            var cookie = AuthCookie(settings, Host, Email, session.Id, session.ExpiresAt);

            var response = await client.SendAsync(Request("/private", cookies: [("_forward_auth", cookie)]));

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            var body = await response.Content.ReadAsStringAsync();
            Assert.Contains(Email, body);
            Assert.Contains("href=\"/_oauth/logout\"", body);
        });
    }

    [Fact]
    public async Task NoProviderConfigured_Returns503ButAllowRulesStillWork()
    {
        var snapshot = Snapshot(
            Settings(),
            [Rule("allow", RuleAction.Allow, true, pathPrefix: "/public")],
            Providers());

        await RunAsync(snapshot, new FakeTimeProvider(), async (client, _) =>
        {
            var authResponse = await client.SendAsync(Request("/private"));
            Assert.Equal(HttpStatusCode.ServiceUnavailable, authResponse.StatusCode);
            Assert.Equal("Not configured\n", await authResponse.Content.ReadAsStringAsync());

            var allowResponse = await client.SendAsync(Request("/public/page"));
            Assert.Equal(HttpStatusCode.OK, allowResponse.StatusCode);
        });
    }

    [Fact]
    public async Task ValidSessionWithMissingProvider_StillAllowed()
    {
        var settings = Settings();
        var snapshot = Snapshot(
            settings,
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers());
        var time = new FakeTimeProvider();

        await RunAsync(snapshot, time, async (client, sessions) =>
        {
            var session = await CreateSessionAsync(sessions);
            var cookie = AuthCookie(settings, Host, Email, session.Id, session.ExpiresAt);

            var response = await client.SendAsync(Request("/private", cookies: [("_forward_auth", cookie)]));

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(Email, Assert.Single(response.Headers.GetValues("X-Forwarded-User")));
        });
    }

    [Fact]
    public async Task ReservedCallbackPath_WinsOverAuthRule()
    {
        var provider = new FakeProvider();
        var settings = Settings();
        var snapshot = Snapshot(
            settings,
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers(provider));
        var time = new FakeTimeProvider();

        await RunAsync(snapshot, time, async (client, sessions) =>
        {
            await CreateSessionAsync(sessions);

            var response = await client.SendAsync(Request("/_oauth"));

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal("Not authorized\n", await response.Content.ReadAsStringAsync());
        });
    }

    [Fact]
    public async Task Callback_WithValidStateAndCookie_ExchangesCodeAndSetsAuthCookie()
    {
        var provider = new FakeProvider { User = new ProviderUser(Email, true) };
        var settings = Settings();
        var snapshot = Snapshot(
            settings,
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers(provider));
        var time = new FakeTimeProvider();

        await RunAsync(snapshot, time, async (client, sessions) =>
        {
            var loginResponse = await client.SendAsync(Request("/private"));
            Assert.Equal(HttpStatusCode.TemporaryRedirect, loginResponse.StatusCode);

            var state = provider.LastState!;
            var csrfName = "_forward_auth_csrf_" + state[..6];
            var csrfHeader = FindCookieHeader(loginResponse, csrfName);
            Assert.NotNull(csrfHeader);
            var csrfValue = CookieValue(csrfHeader!);

            var callbackUri = "/_oauth?state=" + Uri.EscapeDataString(state) + "&code=code123";
            var callbackResponse = await client.SendAsync(
                Request(callbackUri, cookies: [(csrfName, csrfValue)]));

            Assert.Equal(HttpStatusCode.TemporaryRedirect, callbackResponse.StatusCode);
            Assert.Equal("https://app.example.com/private", callbackResponse.Headers.Location!.ToString());
            Assert.Equal("code123", provider.LastCode);
            Assert.Equal("https://app.example.com/_oauth", provider.LastRedirectUri);

            var authHeader = FindCookieHeader(callbackResponse, "_forward_auth");
            Assert.NotNull(authHeader);
            Assert.Contains("path=/", authHeader, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("httponly", authHeader, StringComparison.OrdinalIgnoreCase);

            var authValue = Uri.UnescapeDataString(CookieValue(authHeader!));

            Assert.True(CookieService.TryReadAuthCookieValue(
                settings.SigningSecret,
                CookieService.CookieDomain(settings, Host),
                authValue,
                time.GetUtcNow(),
                out var identity,
                out var failure,
                out _), authHeader);
            Assert.Equal(CookieValidationFailure.None, failure);
            Assert.Equal(Email, identity.Email);

            var csrfClear = FindCookieHeader(callbackResponse, csrfName);
            Assert.NotNull(csrfClear);
            Assert.Contains("expires=Thu, 01 Jan 1970", csrfClear, StringComparison.OrdinalIgnoreCase);

            var created = Assert.Single(sessions.List(SessionKind.ForwardAuth));
            Assert.Equal(Email, created.Email);
            Assert.Equal(identity.SessionId, created.Id);
            Assert.Equal(Host, created.Domain);
        });
    }

    [Fact]
    public async Task Callback_NonAsciiReturnPath_IsPercentEncodedInLocation()
    {
        var provider = new FakeProvider { User = new ProviderUser(Email, true) };
        var snapshot = Snapshot(
            Settings(),
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers(provider));

        await RunAsync(snapshot, new FakeTimeProvider(), async (client, _) =>
        {
            var loginResponse = await client.SendAsync(Request("/caf%C3%A9"));
            Assert.Equal(HttpStatusCode.TemporaryRedirect, loginResponse.StatusCode);

            var state = provider.LastState!;
            var csrfName = "_forward_auth_csrf_" + state[..6];
            var csrfValue = CookieValue(FindCookieHeader(loginResponse, csrfName)!);

            var callbackResponse = await client.SendAsync(Request(
                "/_oauth?state=" + Uri.EscapeDataString(state) + "&code=code123",
                cookies: [(csrfName, csrfValue)]));

            Assert.Equal(HttpStatusCode.TemporaryRedirect, callbackResponse.StatusCode);
            Assert.Equal(
                "https://app.example.com/caf%C3%A9",
                Assert.Single(callbackResponse.Headers.GetValues("Location")));
        });
    }

    [Fact]
    public async Task Callback_SessionStoreFailure_Returns503WithoutAuthCookie()
    {
        var provider = new FakeProvider { User = new ProviderUser(Email, true) };
        var snapshot = Snapshot(
            Settings(),
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers(provider));
        var repository = new FakeSessionRepository { ThrowOnInsert = true };

        await RunAsync(snapshot, new FakeTimeProvider(), async (client, _) =>
        {
            var response = await SendCallbackAsync(client, "https://app.example.com/private");

            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Equal("Service unavailable\n", await response.Content.ReadAsStringAsync());
            Assert.Null(FindCookieHeader(response, "_forward_auth"));
        }, repository);
    }

    [Theory]
    [InlineData("https://evil.example/private")]
    [InlineData("https://app.example.com.evil.example/")]
    [InlineData("https://app.example.com@evil.example/")]
    [InlineData("javascript:alert(1)")]
    [InlineData("/relative")]
    public async Task Callback_RedirectToOtherHost_Returns401(string redirect)
    {
        var provider = new FakeProvider { User = new ProviderUser(Email, true) };
        var snapshot = Snapshot(
            Settings(),
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers(provider));

        await RunAsync(snapshot, new FakeTimeProvider(), async (client, sessions) =>
        {
            var response = await SendCallbackAsync(client, redirect);

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Null(provider.LastCode);
            Assert.Empty(sessions.List(SessionKind.ForwardAuth));
        });
    }

    [Theory]
    [InlineData("https://other.example.com/page", HttpStatusCode.TemporaryRedirect)]
    [InlineData("https://example.com/", HttpStatusCode.TemporaryRedirect)]
    [InlineData("https://notexample.com/", HttpStatusCode.Unauthorized)]
    public async Task Callback_OnAuthHost_AllowsHostsUnderCookieDomain(string redirect, HttpStatusCode expected)
    {
        var provider = new FakeProvider { User = new ProviderUser(Email, true) };
        var settings = Settings() with { AuthHost = Host, CookieDomains = ["example.com"] };
        var snapshot = Snapshot(
            settings,
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers(provider));

        await RunAsync(snapshot, new FakeTimeProvider(), async (client, _) =>
        {
            var response = await SendCallbackAsync(client, redirect);

            Assert.Equal(expected, response.StatusCode);
        });
    }

    [Fact]
    public async Task Callback_WithoutCsrfCookie_Returns401()
    {
        var provider = new FakeProvider();
        var settings = Settings();
        var snapshot = Snapshot(
            settings,
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers(provider));

        var state = new string('a', 32) + ":" + ProviderName + ":https://app.example.com/private";

        await RunAsync(snapshot, new FakeTimeProvider(), async (client, _) =>
        {
            var response = await client.SendAsync(
                Request("/_oauth?state=" + Uri.EscapeDataString(state) + "&code=code123"));

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal("Not authorized\n", await response.Content.ReadAsStringAsync());
        });
    }

    [Fact]
    public async Task Logout_ClearsCookieAndRevokesSessionThenRedirects()
    {
        var provider = new FakeProvider();
        var settings = Settings() with { LogoutRedirect = "https://example.com/goodbye" };
        var snapshot = Snapshot(
            settings,
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers(provider));
        var time = new FakeTimeProvider();

        await RunAsync(snapshot, time, async (client, sessions) =>
        {
            var session = await CreateSessionAsync(sessions);
            var cookie = AuthCookie(settings, Host, Email, session.Id, session.ExpiresAt);

            var response = await client.SendAsync(
                Request("/_oauth/logout", cookies: [("_forward_auth", cookie)]));

            Assert.Equal(HttpStatusCode.TemporaryRedirect, response.StatusCode);
            Assert.Equal("https://example.com/goodbye", response.Headers.Location!.ToString());

            var clearHeader = FindCookieHeader(response, "_forward_auth");
            Assert.NotNull(clearHeader);
            Assert.Contains("expires=Thu, 01 Jan 1970", clearHeader, StringComparison.OrdinalIgnoreCase);

            Assert.False(sessions.TryGetActive(session.Id, time.GetUtcNow(), out _));
        });
    }

    [Fact]
    public async Task Logout_WithoutRedirect_Returns401()
    {
        var provider = new FakeProvider();
        var settings = Settings();
        var snapshot = Snapshot(
            settings,
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers(provider));

        await RunAsync(snapshot, new FakeTimeProvider(), async (client, _) =>
        {
            var response = await client.SendAsync(Request("/_oauth/logout"));

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Contains("You have been logged out", await response.Content.ReadAsStringAsync());
            Assert.NotNull(FindCookieHeader(response, "_forward_auth"));
        });
    }

    [Fact]
    public async Task LogoutPath_TrimsTrailingSlashFromUrlPath()
    {
        var provider = new FakeProvider();
        var settings = Settings() with { UrlPath = "/_oauth/" };
        var snapshot = Snapshot(
            settings,
            [Rule("auth", RuleAction.Auth, true, provider: ProviderName)],
            Providers(provider));

        await RunAsync(snapshot, new FakeTimeProvider(), async (client, _) =>
        {
            var response = await client.SendAsync(Request("/_oauth/logout"));

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Contains("You have been logged out", await response.Content.ReadAsStringAsync());
        });
    }

    [Fact]
    public async Task EncodedSlashPath_Returns400()
    {
        var provider = new FakeProvider();
        var snapshot = Snapshot(
            Settings(),
            [Rule("allow", RuleAction.Allow, true)],
            Providers(provider));

        await RunAsync(snapshot, new FakeTimeProvider(), async (client, _) =>
        {
            var response = await client.SendAsync(Request("/public%2Fadmin"));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("Bad Request\n", await response.Content.ReadAsStringAsync());
            Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        });
    }

    [Fact]
    public async Task DefaultActionAuth_RedirectsToLogin()
    {
        var provider = new FakeProvider();
        var snapshot = Snapshot(Settings(), [], Providers(provider));

        await RunAsync(snapshot, new FakeTimeProvider(), async (client, _) =>
        {
            var response = await client.SendAsync(Request("/anything"));

            Assert.Equal(HttpStatusCode.TemporaryRedirect, response.StatusCode);
            Assert.NotNull(provider.LastState);
        });
    }

    [Fact]
    public async Task DefaultActionAllow_Returns200()
    {
        var provider = new FakeProvider();
        var snapshot = Snapshot(
            Settings() with { DefaultAction = RuleAction.Allow },
            [],
            Providers(provider));

        await RunAsync(snapshot, new FakeTimeProvider(), async (client, _) =>
        {
            var response = await client.SendAsync(Request("/anything"));

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("", await response.Content.ReadAsStringAsync());
            Assert.False(response.Headers.Contains("X-Forwarded-User"));
        });
    }

    private static PolicySettings Settings() => new()
    {
        InsecureCookie = true,
        SigningSecret = Secret,
        UrlPath = "/_oauth",
        Lifetime = TimeSpan.FromHours(1)
    };

    private static PolicySnapshot Snapshot(
        PolicySettings settings,
        IReadOnlyList<CompiledRule> rules,
        IReadOnlyDictionary<string, IProvider> providers,
        IReadOnlyList<AccessEntry>? access = null) => new()
        {
            Settings = settings,
            Rules = rules,
            Providers = providers,
            Access = AccessIndex.Build(access ?? [])
        };

    private static IReadOnlyDictionary<string, IProvider> Providers(params IProvider[] providers) =>
        providers.ToDictionary(provider => provider.Name, provider => provider, StringComparer.Ordinal);

    private static CompiledRule Rule(
        string id,
        RuleAction action,
        bool matches,
        string? pathPrefix = null,
        string? provider = null,
        string name = "rule") => new()
        {
            Definition = new RuleDefinition
            {
                Id = id,
                Name = name,
                Action = action,
                Provider = provider
            },
            Conditions = [new TestCondition(matches, pathPrefix)],
            Summary = name
        };

    private static string AuthCookie(
        PolicySettings settings,
        string host,
        string email,
        string sessionId,
        DateTimeOffset expires) =>
        CookieService.CreateAuthCookieValue(
            settings.SigningSecret,
            CookieService.CookieDomain(settings, host),
            email,
            sessionId,
            expires);

    private static async Task<SessionRecord> CreateSessionAsync(SessionManager sessions) =>
        await sessions.CreateAsync(
            SessionKind.ForwardAuth,
            Email,
            ProviderName,
            null,
            null,
            null,
            TimeSpan.FromHours(1),
            CancellationToken.None);

    private static HttpRequestMessage Request(
        string forwardedUri,
        IEnumerable<(string Name, string Value)>? cookies = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Method", "GET");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Host", Host);
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", Proto);
        request.Headers.TryAddWithoutValidation("X-Forwarded-Uri", forwardedUri);
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", "203.0.113.9");

        if (cookies is not null)
        {
            request.Headers.TryAddWithoutValidation(
                "Cookie",
                string.Join("; ", cookies.Select(cookie => cookie.Name + "=" + cookie.Value)));
        }

        return request;
    }

    private static string? FindCookieHeader(HttpResponseMessage response, string name)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            return null;
        }

        foreach (var value in values)
        {
            if (value.StartsWith(name + "=", StringComparison.Ordinal))
            {
                return value;
            }
        }

        return null;
    }

    private static string CookieValue(string setCookieHeader)
    {
        var semicolon = setCookieHeader.IndexOf(';');
        var pair = semicolon >= 0 ? setCookieHeader[..semicolon] : setCookieHeader;
        var equal = pair.IndexOf('=');

        return equal >= 0 ? pair[(equal + 1)..] : "";
    }

    private static Task<HttpResponseMessage> SendCallbackAsync(HttpClient client, string redirect)
    {
        var nonce = new string('a', 32);
        var state = nonce + ":" + ProviderName + ":" + redirect;

        return client.SendAsync(Request(
            "/_oauth?state=" + Uri.EscapeDataString(state) + "&code=code123",
            cookies: [("_forward_auth_csrf_" + nonce[..6], nonce)]));
    }

    private static TfaLogger Logger() => new(TfaLogLevel.Error, TfaLogFormat.Text, TextWriter.Null);

    private static async Task RunAsync(
        PolicySnapshot snapshot,
        FakeTimeProvider time,
        Func<HttpClient, SessionManager, Task> test,
        FakeSessionRepository? repository = null)
    {
        repository ??= new FakeSessionRepository();
        var sessions = new SessionManager(repository, Logger(), time);
        await sessions.InitializeAsync(CancellationToken.None);

        try
        {
            var builder = WebApplication.CreateSlimBuilder();
            builder.WebHost.UseTestServer();

            var app = builder.Build();
            var middleware = new ForwardAuthMiddleware(() => snapshot, sessions, Logger(), time);
            app.Run(middleware.InvokeAsync);

            await app.StartAsync();

            try
            {
                var client = app.GetTestServer().CreateClient();
                await test(client, sessions);
            }
            finally
            {
                await app.StopAsync();
                await app.DisposeAsync();
            }
        }
        finally
        {
            await sessions.DisposeAsync();
        }
    }

    private sealed class TestCondition : CompiledCondition
    {
        private readonly bool _matches;
        private readonly string? _pathPrefix;

        public TestCondition(bool matches, string? pathPrefix)
            : base(new ConditionDefinition
            {
                Field = ConditionField.Path,
                Operator = ConditionOperator.StartsWith,
                Values = [pathPrefix ?? "/"]
            })
        {
            _matches = matches;
            _pathPrefix = pathPrefix;
        }

        public override bool IsMatch(RequestDescriptor request) =>
            _matches && (_pathPrefix is null || request.Path.StartsWith(_pathPrefix, StringComparison.Ordinal));

        public override string Describe() => _matches ? "matches" : "does not match";
    }

    private sealed class FakeProvider : IProvider
    {
        public string Name { get; init; } = ProviderName;

        public string LoginBaseUrl { get; init; } = "https://provider.example/login";

        public ProviderUser User { get; init; } = new(Email, true);

        public ProviderToken Token { get; init; } = new("access-token", null);

        public Exception? ExchangeError { get; init; }

        public string? LastRedirectUri { get; private set; }

        public string? LastState { get; private set; }

        public string? LastCode { get; private set; }

        public string GetLoginUrl(string redirectUri, string state)
        {
            LastRedirectUri = redirectUri;
            LastState = state;

            return LoginBaseUrl
                + "?redirect_uri=" + Uri.EscapeDataString(redirectUri)
                + "&state=" + Uri.EscapeDataString(state);
        }

        public Task<ProviderToken> ExchangeCodeAsync(
            string redirectUri,
            string code,
            CancellationToken cancellationToken)
        {
            LastRedirectUri = redirectUri;
            LastCode = code;

            if (ExchangeError is not null)
            {
                throw ExchangeError;
            }

            return Task.FromResult(Token);
        }

        public Task<ProviderUser> GetUserAsync(ProviderToken token, CancellationToken cancellationToken) =>
            Task.FromResult(User);

        public Task<ProviderTestResult> TestConnectionAsync(CancellationToken cancellationToken) =>
            Task.FromResult(ProviderTestResult.Ok("ok"));
    }

    private sealed class FakeTimeProvider : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan delta) => _now += delta;
    }

    private sealed class FakeSessionRepository : ISessionRepository
    {
        private readonly List<SessionRecord> _sessions = [];

        public Task<IReadOnlyList<SessionRecord>> LoadSessionsAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<SessionRecord>>(_sessions.ToArray());

        public bool ThrowOnInsert { get; set; }

        public Task InsertSessionAsync(SessionRecord session, CancellationToken cancellationToken)
        {
            if (ThrowOnInsert)
            {
                throw new InvalidOperationException("database is locked");
            }

            _sessions.Add(session);
            return Task.CompletedTask;
        }

        public Task MarkSessionsRevokedAsync(
            IReadOnlyCollection<string> ids,
            DateTimeOffset revokedAt,
            CancellationToken cancellationToken)
        {
            for (var i = 0; i < _sessions.Count; i++)
            {
                if (ids.Contains(_sessions[i].Id))
                {
                    _sessions[i] = _sessions[i] with { RevokedAt = revokedAt };
                }
            }

            return Task.CompletedTask;
        }

        public Task UpdateSessionsLastSeenAsync(
            IReadOnlyList<(string Id, DateTimeOffset LastSeenAt)> sessions,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<int> DeleteSessionsEndedBeforeAsync(DateTimeOffset cutoff, CancellationToken cancellationToken) =>
            Task.FromResult(0);
    }
}
