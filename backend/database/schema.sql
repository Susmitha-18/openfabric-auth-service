
-- Maps verified Cognito identities to application user IDs.
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    cognito_sub TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Resource-level permissions for sample and application users.
CREATE TABLE IF NOT EXISTS user_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('read', 'write', 'delete')),
    resource TEXT NOT NULL,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    expires_at TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_permissions_lookup
ON user_permissions (user_id, action);

CREATE INDEX IF NOT EXISTS idx_users_cognito_sub
ON users (cognito_sub);

-- ALTER TABLE user_permissions ADD COLUMN expires_at DATETIME NULL;
