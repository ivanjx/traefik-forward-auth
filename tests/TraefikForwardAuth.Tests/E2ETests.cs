using System.Net;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using TraefikForwardAuth.Providers;
using TraefikForwardAuth.Tests.TestSupport;
using TraefikForwardAuth.Hosting;

namespace TraefikForwardAuth.Tests;

public sealed class E2ETests
{
    [Fact]
    public async Task AdminConfiguresProviderRuleAndAccessThenForwardAuthAllowsAndRevocationRedirects()
    {
        await using var environment = await TestEnvironment.StartAsync();
        var admin = environment.AdminClient;
        var adminToken = await environment.LoginAdminAsync();

        var providerSaved = await environment.PostAdminFormAsync(
            "/providers/generic-oauth",
            new Dictionary<string, string>
            {
                ["client_id"] = "client-id",
                ["client_secret"] = "client-secret",
                ["auth_url"] = environment.Provider.LoginUrl,
                ["token_url"] = environment.Provider.TokenUrl,
                ["user_url"] = environment.Provider.UserInfoUrl,
                ["scopes"] = "profile,email",
                ["token_style"] = "header",
                ["__RequestVerificationToken"] = adminToken
            });

        Assert.Equal(HttpStatusCode.SeeOther, providerSaved.StatusCode);

        var accessSaved = await environment.PostAdminFormAsync(
            "/access",
            new Dictionary<string, string>
            {
                ["scope"] = "global",
                ["kind"] = "email",
                ["value"] = "user@example.com",
                ["role"] = "reader",
                ["__RequestVerificationToken"] = adminToken
            });

        Assert.Equal(HttpStatusCode.SeeOther, accessSaved.StatusCode);

        var ruleSaved = await environment.PostAdminFormAsync(
            "/rules/new",
            new Dictionary<string, string>
            {
                ["name"] = "App hosts",
                ["enabled"] = "on",
                ["action"] = "auth",
                ["provider"] = "generic-oauth",
                ["Conditions[0].Field"] = "Host",
                ["Conditions[0].Operator"] = "Is",
                ["Conditions[0].Values"] = "app.example.com",
                ["__RequestVerificationToken"] = adminToken
            });

        Assert.Equal(HttpStatusCode.SeeOther, ruleSaved.StatusCode);

        var rulesPage = await environment.GetAdminAsync("/rules");
        Assert.Equal(HttpStatusCode.OK, rulesPage.StatusCode);
        Assert.Contains("App hosts", await rulesPage.Content.ReadAsStringAsync());

        // The fake provider is shared with the admin login; the forward-auth user is a different account.
        environment.Provider.Email = "user@example.com";

        var loginRedirect = await environment.ForwardAuthAsync("/private");
        Assert.Equal(HttpStatusCode.TemporaryRedirect, loginRedirect.StatusCode);

        var loginLocation = loginRedirect.Headers.Location!.ToString();
        Assert.Contains(environment.Provider.BaseUrl, loginLocation);

        var callbackLocation = await environment.FakeLoginAsync(loginLocation);
        Assert.StartsWith("https://app.example.com/_oauth?", callbackLocation);

        var callback = await environment.ForwardAuthCallbackAsync(callbackLocation);
        Assert.Equal(HttpStatusCode.TemporaryRedirect, callback.StatusCode);
        Assert.Equal("https://app.example.com/private", callback.Headers.Location!.ToString());

        var allowed = await environment.ForwardAuthAsync("/private");
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        Assert.Equal("user@example.com", allowed.Headers.GetValues("X-Forwarded-User").Single());
        Assert.Equal("reader", allowed.Headers.GetValues("X-Forwarded-Role").Single());

        var sessionsPage = await environment.GetAdminAsync("/sessions");
        var sessionsHtml = await sessionsPage.Content.ReadAsStringAsync();
        var revokeMatch = Regex.Match(sessionsHtml, "/sessions/([0-9a-fA-F]+)/revoke");

        Assert.True(revokeMatch.Success, "Expected a forward-auth session revoke link on the sessions page.");

        var revoked = await environment.PostAdminFormAsync(
            $"/sessions/{revokeMatch.Groups[1].Value}/revoke",
            new Dictionary<string, string> { ["__RequestVerificationToken"] = adminToken });

        Assert.Equal(HttpStatusCode.SeeOther, revoked.StatusCode);

        var afterRevoke = await environment.ForwardAuthAsync("/private");
        Assert.Equal(HttpStatusCode.TemporaryRedirect, afterRevoke.StatusCode);
        Assert.Contains(environment.Provider.BaseUrl, afterRevoke.Headers.Location!.ToString());
    }

    [Fact]
    public async Task AdminFormsRejectMissingAntiforgeryToken()
    {
        await using var environment = await TestEnvironment.StartAsync();
        await environment.LoginAdminAsync();

        var response = await environment.PostAdminFormAsync(
            "/settings",
            new Dictionary<string, string> { ["cookie_name"] = "_tfa" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task AdminLoginRejectsEmailOutsideAllowlist()
    {
        await using var environment = await TestEnvironment.StartAsync(adminEmail: "someone@example.com");
        environment.Provider.Email = "intruder@example.com";

        var response = await environment.AttemptAdminLoginAsync();

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task AdminAssetsAreServedWithoutAuthentication()
    {
        await using var environment = await TestEnvironment.StartAsync();

        var js = await environment.AdminClient.GetAsync("/assets/htmx.min.js");
        var css = await environment.AdminClient.GetAsync("/assets/site.css");

        Assert.Equal(HttpStatusCode.OK, js.StatusCode);
        Assert.Contains("htmx", await js.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, css.StatusCode);
    }

    [Fact]
    public async Task AdminSettingsPersist()
    {
        await using var environment = await TestEnvironment.StartAsync();
        var token = await environment.LoginAdminAsync();

        var response = await environment.PostAdminFormAsync(
            "/settings",
            new Dictionary<string, string>
            {
                ["cookie_name"] = "_custom_auth",
                ["csrf_cookie_name"] = "_custom_csrf",
                ["url_path"] = "/auth",
                ["lifetime_value"] = "1",
                ["lifetime_unit"] = "hours",
                ["default_action"] = "allow",
                ["default_provider"] = "google",
                ["insecure_cookie"] = "on",
                ["__RequestVerificationToken"] = token
            });

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var configuration = await environment.Runtime.Store.LoadConfigurationAsync(TestContext.Current.CancellationToken);

        Assert.Equal("_custom_auth", configuration.Settings.CookieName);
        Assert.Equal("/auth", configuration.Settings.UrlPath);
        Assert.Equal(TimeSpan.FromHours(1), configuration.Settings.Lifetime);
        Assert.Equal(TraefikForwardAuth.Policy.RuleAction.Allow, configuration.Settings.DefaultAction);
    }

    private sealed class TestEnvironment : IAsyncDisposable
    {
        private readonly string _dataDir;
        private readonly FakeProviderServer _provider;
        private readonly WebApplication _adminApp;
        private readonly WebApplication _forwardApp;
        private readonly HttpClient _fakeClient;

        private TestEnvironment(
            string dataDir,
            FakeProviderServer provider,
            WebApplication adminApp,
            WebApplication forwardApp,
            AppRuntime runtime)
        {
            _dataDir = dataDir;
            _provider = provider;
            Runtime = runtime;
            _adminApp = adminApp;
            _forwardApp = forwardApp;
            AdminClient = new TestHttpClient(GetClient(adminApp));
            ForwardClient = new TestHttpClient(GetClient(forwardApp));
            _fakeClient = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        }

        public AppRuntime Runtime { get; }

        public FakeProviderServer Provider => _provider;

        public TestHttpClient AdminClient { get; }

        public TestHttpClient ForwardClient { get; }

        public static async Task<TestEnvironment> StartAsync(string adminEmail = "admin@example.com")
        {
            var dataDir = Path.Combine(Path.GetTempPath(), "tfa-e2e-" + Guid.NewGuid().ToString("N"));
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

            var adminApp = TfaHost.CreateAdminApp(
                runtime,
                builder => builder.WebHost.UseTestServer(),
                listen: false);
            var forwardApp = TfaHost.CreateForwardAuthApp(
                runtime,
                builder => builder.WebHost.UseTestServer(),
                listen: false);

            await adminApp.StartAsync(TestContext.Current.CancellationToken);
            await forwardApp.StartAsync(TestContext.Current.CancellationToken);

            return new TestEnvironment(dataDir, provider, adminApp, forwardApp, runtime);
        }

        public async Task<HttpResponseMessage> AttemptAdminLoginAsync()
        {
            var login = await GetAdminAsync("/auth/login?returnUrl=/settings");
            Assert.Equal(HttpStatusCode.TemporaryRedirect, login.StatusCode);
            Assert.True(AdminClient.Cookies.Cookies.ContainsKey("_tfa_admin_state"));

            var fakeLocation = login.Headers.Location!.ToString();
            using var fakeResponse = await _fakeClient.GetAsync(fakeLocation, HttpCompletionOption.ResponseHeadersRead);

            Assert.Equal(HttpStatusCode.Found, fakeResponse.StatusCode);
            var callbackLocation = fakeResponse.Headers.Location!.ToString();
            var callbackUri = new Uri(callbackLocation);

            return await GetAdminAsync(callbackUri.PathAndQuery);
        }

        public async Task<string> LoginAdminAsync()
        {
            var callback = await AttemptAdminLoginAsync();

            Assert.Equal(HttpStatusCode.SeeOther, callback.StatusCode);
            Assert.True(AdminClient.Cookies.Cookies.ContainsKey("_tfa_admin"));

            var settings = await GetAdminAsync("/settings");
            var html = await settings.Content.ReadAsStringAsync();
            var match = Regex.Match(
                html,
                "name=\"__RequestVerificationToken\"\\s+value=\"([^\"]+)\"|value=\"([^\"]+)\"\\s+name=\"__RequestVerificationToken\"");

            Assert.True(match.Success, "Expected an antiforgery token on the settings page.");

            return match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Value;
        }

        public Task<HttpResponseMessage> GetAdminAsync(string path) =>
            AdminClient.GetAsync(path, AddAdminForwardedHeaders);

        public Task<HttpResponseMessage> PostAdminFormAsync(
            string path,
            Dictionary<string, string> fields) =>
            AdminClient.PostAsync(path, new FormUrlEncodedContent(fields), AddAdminForwardedHeaders);

        public async Task<HttpResponseMessage> ForwardAuthAsync(string path)
        {
            var response = await ForwardClient.GetAsync(
                path,
                request =>
                {
                    AddHeaders(request, "GET", "app.example.com", path);
                });

            return response;
        }

        public async Task<string> FakeLoginAsync(string loginLocation)
        {
            using var response = await _fakeClient.GetAsync(loginLocation, HttpCompletionOption.ResponseHeadersRead);
            Assert.Equal(HttpStatusCode.Found, response.StatusCode);

            return response.Headers.Location!.ToString();
        }

        public async Task<HttpResponseMessage> ForwardAuthCallbackAsync(string callbackLocation)
        {
            var uri = new Uri(callbackLocation);

            return await ForwardClient.GetAsync(
                uri.PathAndQuery,
                request => AddHeaders(request, "GET", "app.example.com", uri.PathAndQuery));
        }

        private static void AddAdminForwardedHeaders(HttpRequestMessage request)
        {
            request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
            request.Headers.TryAddWithoutValidation("X-Forwarded-Host", "admin.example.com");
        }

        private static void AddHeaders(
            HttpRequestMessage request,
            string method,
            string host,
            string uri)
        {
            request.Headers.TryAddWithoutValidation("X-Forwarded-Method", method);
            request.Headers.TryAddWithoutValidation("X-Forwarded-Host", host);
            request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
            request.Headers.TryAddWithoutValidation("X-Forwarded-Uri", uri);
            request.Headers.TryAddWithoutValidation("X-Forwarded-For", "203.0.113.7");
            request.Headers.TryAddWithoutValidation("User-Agent", "E2E");
        }

        private static HttpClient GetClient(WebApplication app)
        {
            var server = (TestServer)app.Services.GetRequiredService<IServer>();
            return server.CreateClient();
        }

        public async ValueTask DisposeAsync()
        {
            _fakeClient.Dispose();
            AdminClient.Dispose();
            ForwardClient.Dispose();
            await _adminApp.StopAsync();
            await _forwardApp.StopAsync();
            await _adminApp.DisposeAsync();
            await _forwardApp.DisposeAsync();
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
