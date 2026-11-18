namespace TraefikForwardAuth.Admin;

public static class AdminEndpoints
{
    public static void Map(WebApplication app, AppRuntime runtime)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(runtime);

        var pipeline = new AdminPipeline(runtime);

        app.Run(pipeline.HandleAsync);
    }
}
