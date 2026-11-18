CREATE TABLE settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    cookie_name TEXT NOT NULL,
    csrf_cookie_name TEXT NOT NULL,
    cookie_domains TEXT NOT NULL,
    auth_host TEXT NOT NULL,
    insecure INTEGER NOT NULL,
    url_path TEXT NOT NULL,
    lifetime_seconds INTEGER NOT NULL,
    logout_redirect TEXT NULL,
    default_action TEXT NOT NULL,
    default_provider TEXT NOT NULL,
    match_whitelist_or_domain INTEGER NOT NULL,
    signing_secret BLOB NOT NULL
);

CREATE TABLE providers (
    name TEXT PRIMARY KEY,
    client_id TEXT NOT NULL DEFAULT '',
    client_secret TEXT NOT NULL DEFAULT '',
    issuer_url TEXT NULL,
    auth_url TEXT NULL,
    token_url TEXT NULL,
    user_url TEXT NULL,
    prompt TEXT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    token_style TEXT NOT NULL DEFAULT 'header',
    resource TEXT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    position INTEGER NOT NULL DEFAULT 0,
    action TEXT NOT NULL DEFAULT 'auth',
    provider TEXT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    conditions TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL
);

CREATE TABLE access_entries (
    id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    role TEXT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    email TEXT NOT NULL,
    provider TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    ip TEXT NULL,
    user_agent TEXT NULL,
    revoked_at TEXT NULL
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    admin_email TEXT NOT NULL,
    action TEXT NOT NULL,
    entity TEXT NOT NULL,
    diff TEXT NOT NULL
);

CREATE INDEX idx_rules_position ON rules (position);
CREATE INDEX idx_access_entries_scope ON access_entries (scope);
CREATE INDEX idx_sessions_kind ON sessions (kind);
CREATE INDEX idx_sessions_email ON sessions (email);
