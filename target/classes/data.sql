INSERT OR IGNORE INTO user_permissions (user_id, action, resource, effect) VALUES
-- user123: can read/write transactions, explicit deny on delete, can read accounts
('user123', 'read',   'transactions', 'allow'),
('user123', 'write',  'transactions', 'allow'),
('user123', 'delete', 'transactions', 'deny'),
('user123', 'read',   'accounts',     'allow'),

-- user456: read any wallet, write a specific wallet, read a specific wallet's transactions
('user456', 'read',  'wallets/*',                        'allow'),
('user456', 'write', 'wallets/wallet-789',               'allow'),
('user456', 'read',  'wallets/wallet-789/transactions',  'allow'),

-- user789: write any transaction under any wallet
('user789', 'write', 'wallets/*/transactions/*', 'allow'),

-- admin789: full access to everything
('admin789', 'read',   '*', 'allow'),
('admin789', 'write',  '*', 'allow'),
('admin789', 'delete', '*', 'allow');


INSERT OR IGNORE INTO users (user_id, external_user_id) VALUES
('user123',  'user_3DJ8wQ65vmgaH5SogzTltSPhQZF'),
('user456',  'user_3DJ90IUzAhSJWgsuPGSJOe9L59T'),
('user789',  'user_3DJ938xEXC9cxJE5diLDaX9rWdN'),
('admin789', 'user_3DJ95erzmggthgHoQhayVoxfGCw');