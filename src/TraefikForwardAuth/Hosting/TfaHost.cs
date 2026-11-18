using TraefikForwardAuth.Http;
using TraefikForwardAuth.Logging;

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

        UseExceptionLogging(app, runtime.Logger);
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

        UseExceptionLogging(app, runtime.Logger);
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

    /// <summary>
    /// Framework logging is cleared, so unhandled exceptions would otherwise turn into silent 500s.
    /// </summary>
    private static void UseExceptionLogging(WebApplication app, TfaLogger logger)
    {
        app.Use(async (context, next) =>
        {
            try
            {
                await next(context);
            }
            catch (Exception exception) when (!context.RequestAborted.IsCancellationRequested)
            {
                logger.Error(
                    "Unhandled request exception",
                    ("path", context.Request.Path.Value),
                    ("error", exception.Message));

                if (context.Response.HasStarted)
                {
                    throw;
                }

                context.Response.Clear();
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            }
        });
    }
}
