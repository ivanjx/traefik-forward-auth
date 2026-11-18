namespace TraefikForwardAuth.Providers;

public sealed record ProviderToken(string AccessToken, string? IdToken);

public sealed record ProviderUser(string Email, bool EmailVerified);

public sealed record ProviderTestResult(bool Success, string Message)
{
    public static ProviderTestResult Ok(string message) => new(true, message);

    public static ProviderTestResult Fail(string message) => new(false, message);
}

public sealed record GoogleEndpoints(Uri LoginUrl, Uri TokenUrl, Uri UserInfoUrl)
{
    public static GoogleEndpoints Default { get; } = new(
        new Uri("https://accounts.google.com/o/oauth2/auth"),
        new Uri("https://www.googleapis.com/oauth2/v3/token"),
        new Uri("https://www.googleapis.com/oauth2/v2/userinfo"));
}

public sealed record GitHubEndpoints(Uri LoginUrl, Uri TokenUrl, Uri EmailsUrl)
{
    public static GitHubEndpoints Default { get; } = new(
        new Uri("https://github.com/login/oauth/authorize"),
        new Uri("https://github.com/login/oauth/access_token"),
        new Uri("https://api.github.com/user/emails"));
}

public interface IProvider
{
    string Name { get; }

    string GetLoginUrl(string redirectUri, string state);

    Task<ProviderToken> ExchangeCodeAsync(string redirectUri, string code, CancellationToken cancellationToken);

    Task<ProviderUser> GetUserAsync(ProviderToken token, CancellationToken cancellationToken);

    Task<ProviderTestResult> TestConnectionAsync(CancellationToken cancellationToken);
}
