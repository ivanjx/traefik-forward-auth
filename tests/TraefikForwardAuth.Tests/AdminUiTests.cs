using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using TraefikForwardAuth.Admin;
using TraefikForwardAuth.Auth;
using TraefikForwardAuth.Hosting;
using TraefikForwardAuth.Policy;
using TraefikForwardAuth.Providers;
using TraefikForwardAuth.Tests.TestSupport;

namespace TraefikForwardAuth.Tests;

public sealed class AdminUiTests
{
    [Fact]
    public async Task UnauthenticatedRequestRedirectsToLogin()
    {
        await using var environment = await AdminEnvironment.StartAsync();

        var response = await environment.GetAsync("/settings");

        Assert.Equal(HttpStatusCode.TemporaryRedirect, response.StatusCode);
        Assert.Equal(
            "/auth/login?returnUrl=%2Fsettings",
            response.Headers.Location!.ToString());

        var post = await environment.PostFormAsync(
            "/settings",
            new Dictionary<string, string> { ["cookie_name"] = "_x" });

        Assert.Equal(HttpStatusCode.Unauthorized, post.StatusCode);
    }

    [Fact]
    public async Task LoginAllowsConfiguredAdminAndSettingsPageShowsNavigation()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        var token = await environment.LoginAsync();

        Assert.False(string.IsNullOrEmpty(token));

        var settings = await environment.GetAsync("/settings");
        var html = await settings.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, settings.StatusCode);
        Assert.Contains("Settings", html);
        Assert.Contains("/providers", html);
        Assert.Contains("/rules", html);
        Assert.Contains("/access", html);
        Assert.Contains("/sessions", html);
        Assert.Contains("/admin-sessions", html);
        Assert.Contains("/audit", html);
        Assert.Contains("/logout", html);
        Assert.Contains("admin@example.com", html);
    }

    [Fact]
    public async Task LoginRejectsEmailOutsideAllowlist()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        environment.Provider.Email = "intruder@example.com";

        var callback = await environment.AttemptLoginAsync();

        Assert.Equal(HttpStatusCode.Forbidden, callback.StatusCode);
        Assert.False(environment.Client.Cookies.Cookies.ContainsKey("_tfa_admin"));
    }

    [Fact]
    public async Task OidcAdminLoginRetriesDiscoveryAndSignsInVerifiedAdmin()
    {
        await using var oidc = await OidcServer.StartAsync();
        oidc.DiscoveryFails = true;
        oidc.ServeKeys(OidcServer.RsaKey1Id);
        oidc.IdToken = oidc.SignRsa(JwtSigner.Payload(oidc.Issuer, oidc.ClientId, "admin@example.com", emailVerified: true));

        await using var environment = await AdminEnvironment.StartAsync(configure: options => options with
        {
            AdminProvider = ProviderDefinition.Oidc,
            AdminIssuerUrl = oidc.Issuer,
            AdminClientId = oidc.ClientId,
            AdminClientSecret = "client-secret"
        });

        var unavailable = await environment.GetAsync("/auth/login?returnUrl=/settings");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, unavailable.StatusCode);

        oidc.DiscoveryFails = false;

        var login = await environment.GetAsync("/auth/login?returnUrl=/settings");
        Assert.Equal(HttpStatusCode.TemporaryRedirect, login.StatusCode);

        var location = login.Headers.Location!;
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(location.Query);

        Assert.StartsWith(oidc.BaseUrl + "/authorize?", location.ToString());
        Assert.False(query.ContainsKey("prompt"));

        var callback = await environment.GetAsync(
            $"/auth/callback?code=fake-code&state={Uri.EscapeDataString(query["state"].ToString())}");

        Assert.Equal(HttpStatusCode.SeeOther, callback.StatusCode);
        Assert.Equal("/settings", callback.Headers.Location!.ToString());
        Assert.True(environment.Client.Cookies.Cookies.ContainsKey("_tfa_admin"));
    }

    [Fact]
    public async Task SettingsSavePersistsValues()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        var token = await environment.LoginAsync();

        var response = await environment.PostFormAsync(
            "/settings",
            new Dictionary<string, string>
            {
                ["cookie_name"] = "_custom_auth",
                ["csrf_cookie_name"] = "_custom_csrf",
                ["cookie_domains"] = "example.com\nexample.org",
                ["auth_host"] = "admin.example.com",
                ["insecure_cookie"] = "on",
                ["url_path"] = "/auth",
                ["lifetime_value"] = "3",
                ["lifetime_unit"] = "days",
                ["logout_redirect"] = "https://example.com/bye",
                ["default_action"] = "allow",
                ["default_provider"] = "oidc",
                ["match_whitelist_or_domain"] = "on",
                ["__RequestVerificationToken"] = token
            });

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.Equal("/settings?saved=1", response.Headers.Location!.ToString());

        var configuration = await environment.Runtime.Store.LoadConfigurationAsync(TestContext.Current.CancellationToken);
        var settings = configuration.Settings;

        Assert.Equal("_custom_auth", settings.CookieName);
        Assert.Equal("_custom_csrf", settings.CsrfCookieName);
        Assert.Equal(["example.com", "example.org"], settings.CookieDomains);
        Assert.Equal("admin.example.com", settings.AuthHost);
        Assert.True(settings.InsecureCookie);
        Assert.Equal("/auth", settings.UrlPath);
        Assert.Equal(TimeSpan.FromDays(3), settings.Lifetime);
        Assert.Equal("https://example.com/bye", settings.LogoutRedirect);
        Assert.Equal(RuleAction.Allow, settings.DefaultAction);
        Assert.Equal("oidc", settings.DefaultProvider);
        Assert.True(settings.MatchWhitelistOrDomain);

        var page = await environment.GetAsync("/settings");
        var html = await page.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("_custom_auth", html);
        Assert.Matches("name=\"lifetime_value\" value=\"3\"", html);
        Assert.Matches("<option value=\"days\"[^>]*selected", html);
    }

    [Fact]
    public async Task SettingsSaveRejectsLifetimeOverOneYear()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        var token = await environment.LoginAsync();

        var response = await environment.PostFormAsync(
            "/settings",
            new Dictionary<string, string>
            {
                ["cookie_name"] = "_custom_auth",
                ["csrf_cookie_name"] = "_custom_csrf",
                ["url_path"] = "/auth",
                ["lifetime_value"] = "366",
                ["lifetime_unit"] = "days",
                ["default_action"] = "auth",
                ["default_provider"] = "google",
                ["__RequestVerificationToken"] = token
            });

        Assert.NotEqual(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.Contains("up to 365 days", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        var configuration = await environment.Runtime.Store.LoadConfigurationAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PolicySettings.DefaultLifetime, configuration.Settings.Lifetime);
    }

    [Theory]
    [InlineData("30", "seconds", 30)]
    [InlineData("90", "minutes", 5400)]
    [InlineData("12", "hours", 43200)]
    [InlineData("365", "days", 31536000)]
    [InlineData("31536000", "seconds", 31536000)]
    public void LifetimeParsesWholeNumbersInTheChosenUnit(string value, string unit, long expectedSeconds)
    {
        Assert.True(AdminForms.TryParseLifetime(value, unit, out var lifetime));
        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), lifetime);
    }

    [Theory]
    [InlineData("366", "days")]
    [InlineData("8761", "hours")]
    [InlineData("31536001", "seconds")]
    [InlineData("99999999999999999999", "days")]
    [InlineData("9223372036854775807", "days")]
    [InlineData("0", "hours")]
    [InlineData("-1", "hours")]
    [InlineData("1.5", "hours")]
    [InlineData("", "hours")]
    [InlineData("1", "weeks")]
    [InlineData("1", "")]
    public void LifetimeRejectsOutOfRangeFractionalAndUnknownInput(string value, string unit)
    {
        Assert.False(AdminForms.TryParseLifetime(value, unit, out _));
    }

    [Theory]
    [InlineData(43200, 12, "hours")]
    [InlineData(172800, 2, "days")]
    [InlineData(5400, 90, "minutes")]
    [InlineData(90, 90, "seconds")]
    [InlineData(3601, 3601, "seconds")]
    public void LifetimeIsShownInTheLargestExactUnit(long seconds, long expectedValue, string expectedUnit)
    {
        var (value, unit) = AdminUi.SplitLifetime(TimeSpan.FromSeconds(seconds));

        Assert.Equal(expectedValue, value);
        Assert.Equal(expectedUnit, unit);
    }

    [Fact]
    public async Task SettingsSaveRejectsInvalidAntiforgeryToken()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        await environment.LoginAsync();

        var response = await environment.PostFormAsync(
            "/settings",
            new Dictionary<string, string> { ["cookie_name"] = "_tfa" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("Invalid antiforgery token", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ProviderSaveListsProviderWithoutRenderingSecret()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        var token = await environment.LoginAsync();
        var provider = environment.Provider;

        var response = await environment.PostFormAsync(
            "/providers/generic-oauth",
            new Dictionary<string, string>
            {
                ["client_id"] = "client-id",
                ["client_secret"] = "super-secret-value",
                ["auth_url"] = provider.LoginUrl,
                ["token_url"] = provider.TokenUrl,
                ["user_url"] = provider.UserInfoUrl,
                ["prompt"] = "consent",
                ["scopes"] = "openid, email",
                ["token_style"] = "query",
                ["__RequestVerificationToken"] = token
            });

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var page = await environment.GetAsync("/providers");
        var html = await page.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Contains("generic-oauth", html);
        Assert.Contains("Set", html);
        Assert.DoesNotContain("super-secret-value", html);

        var configuration = await environment.Runtime.Store.LoadConfigurationAsync(TestContext.Current.CancellationToken);
        var saved = Assert.Single(configuration.Providers);

        Assert.Equal("generic-oauth", saved.Name);
        Assert.Equal("super-secret-value", saved.ClientSecret);
        Assert.Equal("query", saved.TokenStyle);
        Assert.Equal(["openid", "email"], saved.Scopes);

        var editor = await environment.GetAsync("/providers/generic-oauth");
        var editorHtml = await editor.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, editor.StatusCode);
        Assert.Contains("Secret is set", editorHtml);
        Assert.DoesNotContain("super-secret-value", editorHtml);
        Assert.Contains("Test connection", editorHtml);
    }

    [Fact]
    public async Task RuleCreateSavesSummaryAndKeepsFirstMatchOrder()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        var token = await environment.LoginAsync();

        var first = await environment.PostFormAsync(
            "/rules/new",
            new Dictionary<string, string>
            {
                ["name"] = "Public app",
                ["enabled"] = "on",
                ["action"] = "allow",
                ["provider"] = "",
                ["Conditions[0].Field"] = "Host",
                ["Conditions[0].Operator"] = "Is",
                ["Conditions[0].Values"] = "app.example.com",
                ["__RequestVerificationToken"] = token
            });

        Assert.Equal(HttpStatusCode.SeeOther, first.StatusCode);

        var second = await environment.PostFormAsync(
            "/rules/new",
            new Dictionary<string, string>
            {
                ["name"] = "API",
                ["enabled"] = "on",
                ["action"] = "auth",
                ["provider"] = "",
                ["Conditions[0].Field"] = "Path",
                ["Conditions[0].Operator"] = "StartsWith",
                ["Conditions[0].Values"] = "/api/\n/v2/",
                ["__RequestVerificationToken"] = token
            });

        Assert.Equal(HttpStatusCode.SeeOther, second.StatusCode);

        var configuration = await environment.Runtime.Store.LoadConfigurationAsync(TestContext.Current.CancellationToken);

        Assert.Equal(2, configuration.Rules.Count);
        Assert.Equal("Public app", configuration.Rules[0].Name);
        Assert.Equal("API", configuration.Rules[1].Name);
        Assert.True(configuration.Rules[0].Position < configuration.Rules[1].Position);
        Assert.Equal(["app.example.com"], configuration.Rules[0].Conditions[0].Values);
        Assert.Equal(["/api/", "/v2/"], configuration.Rules[1].Conditions[0].Values);

        var snapshot = environment.Runtime.Admin.Snapshot;
        Assert.Equal(2, snapshot.Rules.Count);
        Assert.Equal("Public app", snapshot.Rules[0].Definition.Name);
        Assert.Contains("Allow without login", snapshot.Rules[0].Summary);
        Assert.Contains("app.example.com", snapshot.Rules[0].Summary);

        var page = await environment.GetAsync("/rules");
        var html = await page.Content.ReadAsStringAsync();

        Assert.Contains("Public app", html);
        Assert.Contains("Requests to", html);

        var rule = configuration.Rules[0];
        var editor = await environment.GetAsync($"/rules/{rule.Id}");
        var editorHtml = await editor.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, editor.StatusCode);
        Assert.Contains("app.example.com", editorHtml);
        Assert.Contains("Requests to", editorHtml);
        Assert.Contains("Conditions[0].Field", editorHtml);

        var newEditor = await environment.GetAsync("/rules/new");
        Assert.Equal(HttpStatusCode.OK, newEditor.StatusCode);
        Assert.Contains("Add condition", await newEditor.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task RulePreviewReturnsSummaryAndErrors()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        var token = await environment.LoginAsync();

        var response = await environment.PostFormAsync(
            "/rules/preview",
            new Dictionary<string, string>
            {
                ["name"] = "Preview",
                ["enabled"] = "on",
                ["action"] = "allow",
                ["Conditions[0].Field"] = "Host",
                ["Conditions[0].Operator"] = "MatchesWildcard",
                ["Conditions[0].Values"] = "*.example.com",
                ["__RequestVerificationToken"] = token
            });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var html = await response.Content.ReadAsStringAsync();

        Assert.Contains("*.example.com", html);
        Assert.Contains("Allow without login", html);

        var invalid = await environment.PostFormAsync(
            "/rules/preview",
            new Dictionary<string, string>
            {
                ["name"] = "",
                ["action"] = "allow",
                ["Conditions[0].Field"] = "Path",
                ["Conditions[0].Operator"] = "StartsWith",
                ["Conditions[0].Values"] = "",
                ["__RequestVerificationToken"] = token
            });

        var invalidHtml = await invalid.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, invalid.StatusCode);
        Assert.Contains("Rule name is required", invalidHtml);
        Assert.Contains("At least one value is required", invalidHtml);
    }

    [Fact]
    public async Task ConditionEditorRendersOperatorsForField()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        await environment.LoginAsync();

        var response = await environment.GetAsync(
            "/rules/conditions/editor?index=3&Conditions%5B3%5D.Field=Header&Conditions%5B3%5D.Operator=Contains&Conditions%5B3%5D.Name=X-Api-Client&Conditions%5B3%5D.Values=web");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var html = await response.Content.ReadAsStringAsync();

        Assert.Contains("Conditions[3].Field", html);
        Assert.Contains("Conditions[3].Operator", html);
        Assert.Contains("X-Api-Client", html);
        Assert.Contains("matches regex", html);
        Assert.DoesNotContain("<html", html);
    }

    [Fact]
    public async Task SimulateReturnsRuleAndConditionResults()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        var token = await environment.LoginAsync();

        var created = await environment.PostFormAsync(
            "/rules/new",
            new Dictionary<string, string>
            {
                ["name"] = "Simulated",
                ["enabled"] = "on",
                ["action"] = "allow",
                ["Conditions[0].Field"] = "Header",
                ["Conditions[0].Operator"] = "Contains",
                ["Conditions[0].Name"] = "X-Api-Client",
                ["Conditions[0].Values"] = "web",
                ["__RequestVerificationToken"] = token
            });

        Assert.Equal(HttpStatusCode.SeeOther, created.StatusCode);

        var response = await environment.PostFormAsync(
            "/simulate",
            new Dictionary<string, string>
            {
                ["method"] = "GET",
                ["host"] = "app.example.com",
                ["path"] = "/private",
                ["headers"] = "X-Api-Client: web-client",
                ["query"] = "a=b&c=d",
                ["__RequestVerificationToken"] = token
            });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var html = await response.Content.ReadAsStringAsync();

        Assert.Contains("Simulated", html);
        Assert.Contains("Allow without login", html);
        Assert.Contains("pass", html);
        Assert.Contains("X-Api-Client", html);
    }

    [Fact]
    public async Task ProviderTestEndpointRendersResultFragment()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        var token = await environment.LoginAsync();
        var provider = environment.Provider;

        var response = await environment.PostFormAsync(
            "/providers/generic-oauth/test",
            new Dictionary<string, string>
            {
                ["client_id"] = "client-id",
                ["client_secret"] = "secret",
                ["auth_url"] = provider.LoginUrl,
                ["token_url"] = provider.TokenUrl,
                ["user_url"] = provider.UserInfoUrl,
                ["__RequestVerificationToken"] = token
            });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var html = await response.Content.ReadAsStringAsync();

        Assert.Contains("Connection OK", html);
        Assert.Contains("Authorization endpoint responded", html);
    }

    [Fact]
    public async Task AccessAddAndDeleteRoundTrips()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        var token = await environment.LoginAsync();

        var added = await environment.PostFormAsync(
            "/access",
            new Dictionary<string, string>
            {
                ["scope"] = "global",
                ["kind"] = "domain",
                ["value"] = "example.com",
                ["role"] = "staff",
                ["__RequestVerificationToken"] = token
            });

        Assert.Equal(HttpStatusCode.SeeOther, added.StatusCode);

        var configuration = await environment.Runtime.Store.LoadConfigurationAsync(TestContext.Current.CancellationToken);
        var entry = Assert.Single(configuration.AccessEntries);

        Assert.Null(entry.RuleId);
        Assert.Equal(AccessKind.Domain, entry.Kind);
        Assert.Equal("example.com", entry.Value);
        Assert.Equal("staff", entry.Role);

        var page = await environment.GetAsync("/access");
        Assert.Contains("example.com", await page.Content.ReadAsStringAsync());

        var deleted = await environment.PostFormAsync(
            $"/access/{entry.Id}/delete",
            new Dictionary<string, string> { ["__RequestVerificationToken"] = token });

        Assert.Equal(HttpStatusCode.SeeOther, deleted.StatusCode);

        var after = await environment.Runtime.Store.LoadConfigurationAsync(TestContext.Current.CancellationToken);
        Assert.Empty(after.AccessEntries);
    }

    [Fact]
    public async Task AdminSessionRevokeSignsOutAndWritesAuditEntry()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        var token = await environment.LoginAsync();

        var session = Assert.Single(environment.Runtime.Sessions.List(SessionKind.Admin));

        var page = await environment.GetAsync("/admin-sessions");
        var html = await page.Content.ReadAsStringAsync();
        Assert.Contains("Current", html);
        Assert.Contains(session.Id[..8], html);

        var revoked = await environment.PostFormAsync(
            $"/admin-sessions/{session.Id}/revoke",
            new Dictionary<string, string> { ["__RequestVerificationToken"] = token });

        Assert.Equal(HttpStatusCode.SeeOther, revoked.StatusCode);
        Assert.Equal("/auth/login", revoked.Headers.Location!.ToString());
        Assert.False(environment.Client.Cookies.Cookies.ContainsKey("_tfa_admin"));

        var audit = await environment.Runtime.Admin.ListAuditAsync(50, TestContext.Current.CancellationToken);
        Assert.Contains(audit, entry => entry.Action == "admin_session.revoke" && entry.Entity == session.Id);
    }

    [Fact]
    public async Task AuditPageListsChanges()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        var token = await environment.LoginAsync();

        var saved = await environment.PostFormAsync(
            "/rules/new",
            new Dictionary<string, string>
            {
                ["name"] = "Audited",
                ["enabled"] = "on",
                ["action"] = "auth",
                ["Conditions[0].Field"] = "Host",
                ["Conditions[0].Operator"] = "Is",
                ["Conditions[0].Values"] = "audit.example.com",
                ["__RequestVerificationToken"] = token
            });

        Assert.Equal(HttpStatusCode.SeeOther, saved.StatusCode);

        var page = await environment.GetAsync("/audit");
        var html = await page.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Contains("rule.create", html);
        Assert.Contains("admin@example.com", html);
    }

    [Fact]
    public async Task AssetsServeWithoutAuthentication()
    {
        await using var environment = await AdminEnvironment.StartAsync();

        var css = await environment.GetAsync("/assets/site.css");
        Assert.Equal(HttpStatusCode.OK, css.StatusCode);
        Assert.Equal("text/css", css.Content.Headers.ContentType!.MediaType);
        Assert.NotNull(css.Headers.CacheControl);
        Assert.Contains("site-header", await css.Content.ReadAsStringAsync());

        var js = await environment.GetAsync("/assets/htmx.min.js");
        Assert.Equal(HttpStatusCode.OK, js.StatusCode);
        Assert.Equal("text/javascript", js.Content.Headers.ContentType!.MediaType);
        Assert.Contains("htmx", await js.Content.ReadAsStringAsync());

        var missing = await environment.GetAsync("/assets/other.css");
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
    }

    [Fact]
    public async Task LogoutClearsCookieAndProtectsPagesAgain()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        var token = await environment.LoginAsync();

        var crossSite = await environment.GetAsync("/logout");

        Assert.Equal(HttpStatusCode.NotFound, crossSite.StatusCode);
        Assert.True(environment.Client.Cookies.Cookies.ContainsKey("_tfa_admin"));

        var forged = await environment.PostFormAsync("/logout", new Dictionary<string, string>());

        Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
        Assert.True(environment.Client.Cookies.Cookies.ContainsKey("_tfa_admin"));

        var logout = await environment.PostFormAsync(
            "/logout",
            new Dictionary<string, string> { ["__RequestVerificationToken"] = token });

        Assert.Equal(HttpStatusCode.SeeOther, logout.StatusCode);
        Assert.Equal("/auth/login", logout.Headers.Location!.ToString());
        Assert.False(environment.Client.Cookies.Cookies.ContainsKey("_tfa_admin"));

        var settings = await environment.GetAsync("/settings");
        Assert.Equal(HttpStatusCode.TemporaryRedirect, settings.StatusCode);
        Assert.Contains("/auth/login", settings.Headers.Location!.ToString());
    }

    [Fact]
    public async Task UnknownPageRendersNotFound()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        await environment.LoginAsync();

        var response = await environment.GetAsync("/nope");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Contains("Not found", await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("%2F%09%2Fevil.com")]
    [InlineData("%2F%0A%2Fevil.com")]
    [InlineData("%2F%2Fevil.com")]
    [InlineData("%2F%5Cevil.com")]
    [InlineData("https%3A%2F%2Fevil.com")]
    public async Task LoginReturnUrlRejectsOffSiteTargets(string returnUrl)
    {
        await using var environment = await AdminEnvironment.StartAsync();

        var callback = await environment.AttemptLoginAsync(returnUrl);

        Assert.Equal(HttpStatusCode.SeeOther, callback.StatusCode);
        Assert.Equal("/", callback.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task AdminResponsesForbidFraming()
    {
        await using var environment = await AdminEnvironment.StartAsync();

        var anonymous = await environment.GetAsync("/settings");

        await environment.LoginAsync();
        var page = await environment.GetAsync("/settings");

        foreach (var response in new[] { anonymous, page })
        {
            Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
            Assert.Equal("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
        }
    }

    [Fact]
    public async Task RevokeForEmailIgnoresCaseAndReportsCount()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        var token = await environment.LoginAsync();

        await environment.Runtime.Sessions.CreateAsync(
            SessionKind.ForwardAuth,
            "User@Corp.com",
            "google",
            null,
            null,
            null,
            TimeSpan.FromHours(1),
            TestContext.Current.CancellationToken);

        var revoked = await environment.PostFormAsync(
            "/sessions/revoke-email",
            new Dictionary<string, string> { ["email"] = "user@corp.com", ["__RequestVerificationToken"] = token });

        Assert.Equal(HttpStatusCode.SeeOther, revoked.StatusCode);
        Assert.Equal("/sessions?revoked=1", revoked.Headers.Location!.ToString());
        Assert.Empty(environment.Runtime.Sessions.List(SessionKind.ForwardAuth));

        var page = await environment.GetAsync("/sessions?revoked=1");
        Assert.Contains("Revoked 1 session.", await page.Content.ReadAsStringAsync());

        var none = await environment.PostFormAsync(
            "/sessions/revoke-email",
            new Dictionary<string, string> { ["email"] = "user@corp.com", ["__RequestVerificationToken"] = token });

        Assert.Equal("/sessions?revoked=0", none.Headers.Location!.ToString());

        var audit = await environment.Runtime.Admin.ListAuditAsync(50, TestContext.Current.CancellationToken);
        var entry = Assert.Single(audit, candidate => candidate.Action == "session.revoke_email");
        Assert.Contains("\"count\":1", entry.DiffJson);
    }

    [Fact]
    public async Task StoredSecretIsNotReusedForChangedEndpoints()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        var token = await environment.LoginAsync();
        var provider = environment.Provider;

        Dictionary<string, string> Form(string secret, string userUrl) => new()
        {
            ["client_id"] = "client-id",
            ["client_secret"] = secret,
            ["auth_url"] = provider.LoginUrl,
            ["token_url"] = provider.TokenUrl,
            ["user_url"] = userUrl,
            ["__RequestVerificationToken"] = token
        };

        var saved = await environment.PostFormAsync("/providers/generic-oauth", Form("stored-secret", provider.UserInfoUrl));
        Assert.Equal(HttpStatusCode.SeeOther, saved.StatusCode);

        var test = await environment.PostFormAsync("/providers/generic-oauth/test", Form("", "https://attacker.example/userinfo"));
        Assert.Contains("Re-enter the client secret", await test.Content.ReadAsStringAsync());

        var save = await environment.PostFormAsync("/providers/generic-oauth", Form("", "https://attacker.example/userinfo"));
        var html = await save.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, save.StatusCode);
        Assert.Contains("Re-enter the client secret", html);
        Assert.Contains("Secret is set", html);

        var unchanged = await environment.PostFormAsync("/providers/generic-oauth", Form("", provider.UserInfoUrl));
        Assert.Equal(HttpStatusCode.SeeOther, unchanged.StatusCode);

        var configuration = await environment.Runtime.Store.LoadConfigurationAsync(TestContext.Current.CancellationToken);
        var stored = Assert.Single(configuration.Providers);
        Assert.Equal("stored-secret", stored.ClientSecret);
        Assert.Equal(provider.UserInfoUrl, stored.UserUrl);
    }

    [Fact]
    public async Task AuditSkipsMissingTargetsAndRecordsCascadedAccessEntries()
    {
        await using var environment = await AdminEnvironment.StartAsync();
        var token = await environment.LoginAsync();
        var form = new Dictionary<string, string> { ["__RequestVerificationToken"] = token };

        var missingSession = await environment.PostFormAsync("/sessions/does-not-exist/revoke", form);
        Assert.Equal("/sessions?revoked=0", missingSession.Headers.Location!.ToString());

        var missingProvider = await environment.PostFormAsync("/providers/oidc/delete", form);
        Assert.Equal(HttpStatusCode.NotFound, missingProvider.StatusCode);

        await environment.PostFormAsync(
            "/rules/new",
            new Dictionary<string, string>
            {
                ["name"] = "App",
                ["enabled"] = "on",
                ["action"] = "auth",
                ["provider"] = "",
                ["Conditions[0].Field"] = "Host",
                ["Conditions[0].Operator"] = "Is",
                ["Conditions[0].Values"] = "app.example.com",
                ["__RequestVerificationToken"] = token
            });

        var rule = Assert.Single((await environment.Runtime.Store.LoadConfigurationAsync(TestContext.Current.CancellationToken)).Rules);

        await environment.PostFormAsync(
            "/access",
            new Dictionary<string, string>
            {
                ["scope"] = rule.Id,
                ["kind"] = "email",
                ["value"] = "member@example.com",
                ["__RequestVerificationToken"] = token
            });

        var deleted = await environment.PostFormAsync($"/rules/{rule.Id}/delete", form);
        Assert.Equal(HttpStatusCode.SeeOther, deleted.StatusCode);

        var audit = await environment.Runtime.Admin.ListAuditAsync(50, TestContext.Current.CancellationToken);

        Assert.DoesNotContain(audit, entry => entry.Action is "session.revoke" or "provider.delete");
        Assert.Contains("member@example.com", Assert.Single(audit, entry => entry.Action == "rule.delete").DiffJson);
    }

    private sealed class AdminEnvironment : IAsyncDisposable
    {
        private readonly string _dataDir;
        private readonly FakeProviderServer _provider;
        private readonly WebApplication _app;
        private readonly HttpClient _fakeClient;

        private AdminEnvironment(
            string dataDir,
            FakeProviderServer provider,
            WebApplication app,
            AppRuntime runtime)
        {
            _dataDir = dataDir;
            _provider = provider;
            _app = app;
            Runtime = runtime;

            var server = (TestServer)app.Services.GetRequiredService<IServer>();
            Client = new TestHttpClient(server.CreateClient());
            _fakeClient = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        }

        public AppRuntime Runtime { get; }

        public FakeProviderServer Provider => _provider;

        public TestHttpClient Client { get; }

        public static async Task<AdminEnvironment> StartAsync(
            string adminEmail = "admin@example.com",
            Func<TfaOptions, TfaOptions>? configure = null)
        {
            var dataDir = Path.Combine(Path.GetTempPath(), "tfa-admin-ui-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dataDir);

            var provider = await FakeProviderServer.StartAsync(TestContext.Current.CancellationToken);
            provider.Email = adminEmail;
            var options = new TfaOptions
            {
                AdminProvider = TraefikForwardAuth.Policy.ProviderDefinition.Google,
                AdminClientId = "admin-client",
                AdminClientSecret = "admin-secret",
                AdminEmails = new HashSet<string>([adminEmail], StringComparer.OrdinalIgnoreCase),
                DataDir = dataDir,
                LogLevel = TraefikForwardAuth.Logging.TfaLogLevel.Warn,
                LogFormat = TraefikForwardAuth.Logging.TfaLogFormat.Text
            };

            if (configure is not null)
            {
                options = configure(options);
            }

            var runtime = new AppRuntime(
                options,
                new AppRuntimeOverrides
                {
                    GoogleEndpoints = new GoogleEndpoints(
                        new Uri(provider.LoginUrl),
                        new Uri(provider.TokenUrl),
                        new Uri(provider.UserInfoUrl))
                });

            await runtime.InitializeAsync(TestContext.Current.CancellationToken);

            var app = TfaHost.CreateAdminApp(
                runtime,
                builder => builder.WebHost.UseTestServer(),
                listen: false);

            await app.StartAsync(TestContext.Current.CancellationToken);

            return new AdminEnvironment(dataDir, provider, app, runtime);
        }

        public async Task<HttpResponseMessage> AttemptLoginAsync(string returnUrl = "/settings")
        {
            var login = await GetAsync("/auth/login?returnUrl=" + returnUrl);

            Assert.Equal(HttpStatusCode.TemporaryRedirect, login.StatusCode);
            Assert.True(Client.Cookies.Cookies.ContainsKey("_tfa_admin_state"));

            var fakeLocation = login.Headers.Location!.ToString();
            using var fakeResponse = await _fakeClient.GetAsync(fakeLocation, HttpCompletionOption.ResponseHeadersRead);

            Assert.Equal(HttpStatusCode.Found, fakeResponse.StatusCode);
            var callback = new Uri(fakeResponse.Headers.Location!.ToString());

            return await GetAsync(callback.PathAndQuery);
        }

        public async Task<string> LoginAsync()
        {
            var callback = await AttemptLoginAsync();

            Assert.Equal(HttpStatusCode.SeeOther, callback.StatusCode);
            Assert.True(Client.Cookies.Cookies.ContainsKey("_tfa_admin"));

            var settings = await GetAsync("/settings");
            var html = await settings.Content.ReadAsStringAsync();
            var match = Regex.Match(
                html,
                "name=\"__RequestVerificationToken\"\\s+value=\"([^\"]+)\"|value=\"([^\"]+)\"\\s+name=\"__RequestVerificationToken\"");

            Assert.True(match.Success, "Expected an antiforgery token on the settings page.");

            return match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Value;
        }

        public Task<HttpResponseMessage> GetAsync(string path) =>
            Client.GetAsync(path, request =>
            {
                request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
                request.Headers.TryAddWithoutValidation("X-Forwarded-Host", "admin.example.com");
            });

        public Task<HttpResponseMessage> PostFormAsync(string path, Dictionary<string, string> fields) =>
            Client.PostAsync(path, new FormUrlEncodedContent(fields), request =>
            {
                request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
                request.Headers.TryAddWithoutValidation("X-Forwarded-Host", "admin.example.com");
            });

        public async ValueTask DisposeAsync()
        {
            _fakeClient.Dispose();
            Client.Dispose();
            await _app.StopAsync();
            await _app.DisposeAsync();
            await _provider.DisposeAsync();
            await Runtime.DisposeAsync();

            try
            {
                Directory.Delete(_dataDir, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }
}
