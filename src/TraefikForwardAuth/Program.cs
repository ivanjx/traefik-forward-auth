using TraefikForwardAuth.Hosting;

namespace TraefikForwardAuth;

public static class Program
{
    public static async Task<int> Main()
    {
        TfaOptions options;

        try
        {
            options = TfaOptions.FromEnvironment();
        }
        catch (TfaOptionsException exception)
        {
            foreach (var error in exception.Errors)
            {
                Console.Error.WriteLine(error);
            }

            return 1;
        }

        try
        {
            await using var runtime = new AppRuntime(options);
            await runtime.InitializeAsync(CancellationToken.None);

            var forwardAuth = TfaHost.CreateForwardAuthApp(runtime);
            var admin = TfaHost.CreateAdminApp(runtime);

            await forwardAuth.StartAsync();
            await admin.StartAsync();

            runtime.Logger.Info(
                "Listening",
                ("forward_auth", $"0.0.0.0:{options.Port}"),
                ("admin", $"0.0.0.0:{options.AdminPort}"),
                ("admin_login", options.AdminProvider));

            await Task.WhenAny(
                forwardAuth.WaitForShutdownAsync(),
                admin.WaitForShutdownAsync());

            await forwardAuth.StopAsync();
            await admin.StopAsync();

            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception);
            return 1;
        }
    }
}
