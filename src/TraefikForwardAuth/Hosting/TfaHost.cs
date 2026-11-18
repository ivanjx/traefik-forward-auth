using TraefikForwardAuth.Http;

namespace TraefikForwardAuth.Hosting;

public static class TfaHost
{
    public static WebApplication CreateForwardAuthApp(
        AppRuntime runtime,
        Action<WebApplicationBuilder>? configure = null,
        bool listen = true)
    {
        var builder = CreateBuilder(runtime, configure, listen, runtime.Options.Port);
        var app = builder.Build();
        var middleware = new ForwardAuthMiddleware(runtime.Policy, runtime.Sessions, runtime.Logger, runtime.TimeProvider);

        app.Run(middleware.InvokeAsync);

        return app;
    }

    public static WebApplication CreateAdminApp(
        AppRuntime runtime,
        Action<WebApplicationBuilder>? configure = null,
        bool listen = true)
    {
        var builder = CreateBuilder(runtime, configure, listen, runtime.Options.AdminPort);
        var app = builder.Build();

        Admin.AdminEndpoints.Map(app, runtime);

        return app;
    }

    private static WebApplicationBuilder CreateBuilder(
        AppRuntime runtime,
        Action<WebApplicationBuilder>? configure,
        bool listen,
        int port)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();

        if (listen)
        {
            builder.WebHost.UseUrls($"http://0.0.0.0:{port}");
        }

        configure?.Invoke(builder);

        return builder;
    }
}
