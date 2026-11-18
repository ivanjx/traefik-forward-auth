namespace TraefikForwardAuth.Auth;

public enum SessionKind
{
    ForwardAuth,
    Admin
}

public sealed record SessionRecord
{
    public required string Id { get; init; }

    public SessionKind Kind { get; init; }

    public string Email { get; init; } = "";

    public string Provider { get; init; } = "";

    /// <summary>Domain the session cookie was issued for; null for sessions created before it was recorded.</summary>
    public string? Domain { get; init; }

    public DateTimeOffset CreatedAt { get; init; }

    public DateTimeOffset ExpiresAt { get; init; }

    public DateTimeOffset LastSeenAt { get; init; }

    public string? Ip { get; init; }

    public string? UserAgent { get; init; }

    public DateTimeOffset? RevokedAt { get; init; }

    public bool IsActive(DateTimeOffset now) => RevokedAt is null && ExpiresAt > now;
}

public interface ISessionStore
{
    bool TryGetActive(string id, DateTimeOffset now, out SessionRecord session);
}

public interface ISessionRepository
{
    Task<IReadOnlyList<SessionRecord>> LoadSessionsAsync(CancellationToken cancellationToken);

    Task InsertSessionAsync(SessionRecord session, CancellationToken cancellationToken);

    Task MarkSessionsRevokedAsync(IReadOnlyCollection<string> ids, DateTimeOffset revokedAt, CancellationToken cancellationToken);

    Task UpdateSessionsLastSeenAsync(
        IReadOnlyList<(string Id, DateTimeOffset LastSeenAt)> sessions,
        CancellationToken cancellationToken);
}
