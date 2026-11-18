namespace TraefikForwardAuth.Http;

/// <summary>Standalone page shown to end users on protected hosts (access denied, invalid sign-in, logged out).</summary>
public sealed record AuthPageModel
{
    public required string Title { get; init; }

    public required string Message { get; init; }

    /// <summary>Signed-in email, shown when the user is authenticated but not allowed.</summary>
    public string? Email { get; init; }

    public required string ActionHref { get; init; }

    public required string ActionLabel { get; init; }
}
