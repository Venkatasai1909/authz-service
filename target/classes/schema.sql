CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    resource_pattern TEXT NOT NULL,
    action TEXT NOT NULL,
    effect TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_id_action
ON permissions(user_id, action);