using System.Security.Cryptography;
using System.Threading.Channels;
using TraefikForwardAuth.Logging;

namespace TraefikForwardAuth.Auth;

/// <summary>
/// In-memory session cache. Forward-auth checks hit this cache without doing per-request I/O;
/// last-seen updates are batched and written to SQLite in the background.
/// </summary>
public sealed class SessionManager : ISessionStore, IAsyncDisposable
{
    private const int BatchSize = 200;
    private static readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan PruneInterval = TimeSpan.FromHours(1);

    /// <summary>How long expired or revoked sessions are kept for the admin UI before they are deleted.</summary>
    public static readonly TimeSpan Retention = TimeSpan.FromDays(7);

    private readonly ISessionRepository _repository;
    private readonly TfaLogger _logger;
    private readonly TimeProvider _timeProvider;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, SessionRecord> _sessions =
        new(StringComparer.Ordinal);
    private readonly Channel<TouchCommand> _commands = Channel.CreateUnbounded<TouchCommand>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });
    private readonly Lock _pendingGate = new();
    private readonly Dictionary<string, DateTimeOffset> _pending = new(StringComparer.Ordinal);
    private readonly Queue<TaskCompletionSource<bool>> _flushWaiters = new();
    private readonly CancellationTokenSource _disposeCts = new();
    private readonly Task _flushLoop;
    private int _disposed;
    private DateTimeOffset _lastPrune;

    public SessionManager(ISessionRepository repository, TfaLogger logger, TimeProvider timeProvider)
    {
        _repository = repository;
        _logger = logger;
        _timeProvider = timeProvider;
        _lastPrune = timeProvider.GetUtcNow();
        _flushLoop = Task.Run(FlushLoopAsync);
    }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        var cutoff = _timeProvider.GetUtcNow() - Retention;

        await DeleteEndedBeforeAsync(cutoff, cancellationToken);

        var sessions = await _repository.LoadSessionsAsync(cancellationToken);

        _sessions.Clear();

        foreach (var session in sessions)
        {
            // Revoked rows can be omitted: they can never become active again. Expired rows are
            // kept for the retention window so the admin UI can still show them; IsActive filters
            // them on every read.
            if (session.RevokedAt is null && session.ExpiresAt >= cutoff)
            {
                _sessions[session.Id] = session;
            }
        }

        _logger.Debug("Loaded sessions", ("count", _sessions.Count));
    }

    public bool TryGetActive(string id, DateTimeOffset now, out SessionRecord session)
    {
        if (_sessions.TryGetValue(id, out var cached) && cached.IsActive(now))
        {
            session = cached;
            return true;
        }

        session = default!;

        return false;
    }

    public SessionRecord? Get(string id) => _sessions.TryGetValue(id, out var session) ? session : null;

    /// <summary>
    /// Snapshot of the cached sessions of one kind. Expired sessions are included so the admin UI
    /// can report them; revoked sessions are removed from the cache and never appear.
    /// </summary>
    public IReadOnlyList<SessionRecord> List(SessionKind kind) =>
        _sessions.Values
            .Where(session => session.Kind == kind)
            .OrderByDescending(session => session.CreatedAt)
            .ToArray();

    /// <summary>
    /// Snapshot of every cached session. Expired sessions are included; revoked sessions are absent.
    /// </summary>
    public IReadOnlyList<SessionRecord> ListAll() =>
        _sessions.Values
            .OrderByDescending(session => session.CreatedAt)
            .ToArray();

    public async Task<SessionRecord> CreateAsync(
        SessionKind kind,
        string email,
        string provider,
        string? domain,
        string? ip,
        string? userAgent,
        TimeSpan lifetime,
        CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var session = new SessionRecord
        {
            Id = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)),
            Kind = kind,
            Email = email,
            Provider = provider,
            Domain = domain,
            CreatedAt = now,
            ExpiresAt = now + lifetime,
            LastSeenAt = now,
            Ip = ip,
            UserAgent = userAgent
        };

        await _repository.InsertSessionAsync(session, cancellationToken);

        // Only cache after a successful insert; a failed insert must not leave an active-looking session.
        _sessions[session.Id] = session;
        _logger.Debug("Created session", ("id", session.Id), ("kind", kind.ToString()));

        return session;
    }

    public void Touch(string id)
    {
        try
        {
            var now = _timeProvider.GetUtcNow();

            while (_sessions.TryGetValue(id, out var session))
            {
                if (session.RevokedAt is not null || session.LastSeenAt > now)
                {
                    return;
                }

                if (_sessions.TryUpdate(id, session with { LastSeenAt = now }, session))
                {
                    break;
                }
            }

            _commands.Writer.TryWrite(new TouchCommand(id, null));
        }
        catch (Exception exception)
        {
            // Touch is best-effort bookkeeping and must never fail a request.
            _logger.Debug("Failed to record session touch", ("error", exception.Message));
        }
    }

    public async Task RevokeAsync(string id, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();

        // Mark in the database even when the session is not cached; the operation is idempotent.
        await _repository.MarkSessionsRevokedAsync([id], now, cancellationToken);
        _sessions.TryRemove(id, out _);
        _logger.Debug("Revoked session", ("id", id));
    }

    public async Task<int> RevokeForEmailAsync(string email, SessionKind kind, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var ids = _sessions.Values
            .Where(session =>
                session.Kind == kind &&
                string.Equals(session.Email, email, StringComparison.Ordinal) &&
                session.IsActive(now))
            .Select(session => session.Id)
            .ToArray();

        if (ids.Length == 0)
        {
            return 0;
        }

        await _repository.MarkSessionsRevokedAsync(ids, now, cancellationToken);

        foreach (var id in ids)
        {
            _sessions.TryRemove(id, out _);
        }

        _logger.Debug("Revoked sessions for email", ("kind", kind.ToString()), ("count", ids.Length));

        return ids.Length;
    }

    public async Task RevokeAllAsync(SessionKind? kind, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var ids = _sessions.Values
            .Where(session => (kind is null || session.Kind == kind) && session.IsActive(now))
            .Select(session => session.Id)
            .ToArray();

        if (ids.Length == 0)
        {
            return;
        }

        await _repository.MarkSessionsRevokedAsync(ids, now, cancellationToken);

        foreach (var id in ids)
        {
            _sessions.TryRemove(id, out _);
        }

        _logger.Debug("Revoked sessions", ("kind", kind?.ToString() ?? "all"), ("count", ids.Length));
    }

    /// <summary>
    /// Flushes queued last-seen updates immediately instead of waiting for the periodic batch.
    /// Exposed so callers can observe a deterministic flush (tests and shutdown checks).
    /// </summary>
    public async Task FlushPendingUpdatesAsync(CancellationToken cancellationToken = default)
    {
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        if (!_commands.Writer.TryWrite(new TouchCommand(null, completion)))
        {
            await FlushPendingAsync(CancellationToken.None);
            return;
        }

        await completion.Task.WaitAsync(cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _commands.Writer.TryComplete();

        try
        {
            await _flushLoop;
        }
        catch (Exception exception)
        {
            _logger.Error("Session last-seen loop ended unexpectedly", ("error", exception.Message));
        }

        CompleteFlushWaiters();
        _disposeCts.Cancel();
        _disposeCts.Dispose();
    }

    private async Task FlushLoopAsync()
    {
        var lastFlush = _timeProvider.GetUtcNow();

        try
        {
            while (true)
            {
                var remaining = FlushInterval - (_timeProvider.GetUtcNow() - lastFlush);

                if (remaining < TimeSpan.Zero)
                {
                    remaining = TimeSpan.Zero;
                }

                TouchCommand command;

                try
                {
                    using var waitCts = CancellationTokenSource.CreateLinkedTokenSource(_disposeCts.Token);
                    waitCts.CancelAfter(remaining);
                    command = await _commands.Reader.ReadAsync(waitCts.Token);
                }
                catch (OperationCanceledException) when (!_disposeCts.IsCancellationRequested)
                {
                    // Interval elapsed with no traffic: flush whatever is pending.
                    await PruneIfDueAsync(_disposeCts.Token);
                    await FlushPendingAsync(_disposeCts.Token);
                    lastFlush = _timeProvider.GetUtcNow();
                    continue;
                }
                catch (ChannelClosedException)
                {
                    break;
                }

                var flushRequested = Process(command);

                while (PendingCount < BatchSize && _commands.Reader.TryRead(out var next))
                {
                    flushRequested |= Process(next);
                }

                // Prune before flushing so flush waiters observe a completed prune.
                await PruneIfDueAsync(_disposeCts.Token);

                var now = _timeProvider.GetUtcNow();

                if (flushRequested || PendingCount >= BatchSize || now - lastFlush >= FlushInterval)
                {
                    await FlushPendingAsync(_disposeCts.Token);
                    lastFlush = now;
                }
            }
        }
        catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            _logger.Error("Session last-seen loop failed", ("error", exception.Message));
        }
        finally
        {
            await FlushPendingAsync(CancellationToken.None);
            CompleteFlushWaiters();
        }
    }

    private bool Process(in TouchCommand command)
    {
        if (command.Id is { } id)
        {
            if (_sessions.TryGetValue(id, out var session) && session.RevokedAt is null)
            {
                lock (_pendingGate)
                {
                    _pending[id] = _timeProvider.GetUtcNow();
                }
            }

            return false;
        }

        if (command.FlushCompletion is { } completion)
        {
            lock (_pendingGate)
            {
                _flushWaiters.Enqueue(completion);
            }
        }

        return true;
    }

    private int PendingCount
    {
        get
        {
            lock (_pendingGate)
            {
                return _pending.Count;
            }
        }
    }

    private async Task PruneIfDueAsync(CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();

        if (now - _lastPrune < PruneInterval)
        {
            return;
        }

        _lastPrune = now;

        var cutoff = now - Retention;

        foreach (var entry in _sessions)
        {
            if (entry.Value.ExpiresAt < cutoff)
            {
                _sessions.TryRemove(entry);
            }
        }

        await DeleteEndedBeforeAsync(cutoff, cancellationToken);
    }

    private async Task DeleteEndedBeforeAsync(DateTimeOffset cutoff, CancellationToken cancellationToken)
    {
        try
        {
            var deleted = await _repository.DeleteSessionsEndedBeforeAsync(cutoff, cancellationToken);

            if (deleted > 0)
            {
                _logger.Debug("Pruned ended sessions", ("count", deleted));
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            // Pruning is housekeeping; a failure must not stop startup or the last-seen loop.
            _logger.Error("Failed to prune sessions", ("error", exception.Message));
        }
    }

    private async Task FlushPendingAsync(CancellationToken cancellationToken)
    {
        List<(string Id, DateTimeOffset LastSeenAt)> batch;

        lock (_pendingGate)
        {
            if (_pending.Count == 0)
            {
                CompleteFlushWaiters();
                return;
            }

            batch = new List<(string Id, DateTimeOffset LastSeenAt)>(_pending.Count);

            foreach (var (id, lastSeenAt) in _pending)
            {
                // Revoked sessions are removed from the cache, so their pending touches are dropped.
                if (_sessions.ContainsKey(id))
                {
                    batch.Add((id, lastSeenAt));
                }
            }

            _pending.Clear();
        }

        if (batch.Count > 0)
        {
            try
            {
                await _repository.UpdateSessionsLastSeenAsync(batch, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
            catch (Exception exception)
            {
                _logger.Error("Failed to update session last seen", ("error", exception.Message));
            }
        }

        CompleteFlushWaiters();
    }

    private void CompleteFlushWaiters()
    {
        lock (_pendingGate)
        {
            while (_flushWaiters.Count > 0)
            {
                _flushWaiters.Dequeue().TrySetResult(true);
            }
        }
    }

    private readonly record struct TouchCommand(string? Id, TaskCompletionSource<bool>? FlushCompletion);
}

public static class AccessValidator
{
    public static bool IsAllowed(Policy.AccessIndex access, string? ruleId, string email, bool matchWhitelistOrDomain) =>
        access.ForRule(ruleId).IsAllowed(email, matchWhitelistOrDomain);

    public static string? GetRole(Policy.AccessIndex access, string? ruleId, string email) =>
        access.ForRule(ruleId).RoleFor(email);
}
