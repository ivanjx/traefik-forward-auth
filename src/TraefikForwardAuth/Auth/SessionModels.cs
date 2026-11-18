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

/// <summary>
/// Audit row written in the same transaction as a revocation, only when at least one session was revoked.
/// <paramref name="Diff"/> receives the number of revoked sessions and returns the diff JSON.
/// </summary>
public sealed record SessionRevocationAudit(string AdminEmail, string Action, string Entity, Func<int, string> Diff);

public interface ISessionRepository
{
    Task<IReadOnlyList<SessionRecord>> LoadSessionsAsync(CancellationToken cancellationToken);

    Task InsertSessionAsync(SessionRecord session, CancellationToken cancellationToken);

    /// <summary>Marks the sessions revoked and returns how many were not revoked before.</summary>
    Task<int> MarkSessionsRevokedAsync(
        IReadOnlyCollection<string> ids,
        DateTimeOffset revokedAt,
        SessionRevocationAudit? audit,
        CancellationToken cancellationToken);

    Task UpdateSessionsLastSeenAsync(
        IReadOnlyList<(string Id, DateTimeOffset LastSeenAt)> sessions,
        CancellationToken cancellationToken);

    /// <summary>Deletes sessions that expired, or were revoked, before <paramref name="cutoff"/>. Returns the number deleted.</summary>
    Task<int> DeleteSessionsEndedBeforeAsync(DateTimeOffset cutoff, CancellationToken cancellationToken);
}
