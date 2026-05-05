CREATE TABLE IF NOT EXISTS user_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    effect TEXT NOT NULL,
    UNIQUE(user_id, action, resource)
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    external_user_id TEXT NOT NULL,
    UNIQUE(external_user_id)
);

CREATE INDEX IF NOT EXISTS idx_user_id_action
ON user_permissions(user_id, action);

CREATE INDEX IF NOT EXISTS idx_user_id_ext_user_id
ON users(external_user_id);