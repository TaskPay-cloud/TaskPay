CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    auth_provider TEXT NOT NULL DEFAULT 'password',
    email_confirmed INTEGER NOT NULL DEFAULT 0,
    confirmation_token TEXT,
    is_admin INTEGER NOT NULL DEFAULT 0,
    referral_code TEXT UNIQUE,
    referred_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL,
    bank_code TEXT,
    bank_name TEXT,
    account_number TEXT,
    account_name TEXT,
    paystack_recipient_code TEXT
);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    reward REAL NOT NULL,
    repeatable INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_completions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    task_id INTEGER NOT NULL REFERENCES tasks(id),
    month_key TEXT NOT NULL,
    reward_earned REAL NOT NULL,
    completed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS provider_settlements (
    source TEXT NOT NULL,
    month_key TEXT NOT NULL,
    settled INTEGER NOT NULL DEFAULT 0,
    settled_at TEXT,
    processed INTEGER NOT NULL DEFAULT 0,
    processed_at TEXT,
    PRIMARY KEY (source, month_key)
);

CREATE TABLE IF NOT EXISTS provider_conversions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    external_id TEXT,
    amount REAL NOT NULL,
    month_key TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS referral_commissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    referrer_id INTEGER NOT NULL REFERENCES users(id),
    referred_user_id INTEGER NOT NULL REFERENCES users(id),
    source TEXT NOT NULL,
    month_key TEXT NOT NULL,
    base_amount REAL NOT NULL,
    commission_amount REAL NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS payouts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    month_key TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'internal',
    amount REAL NOT NULL,
    paid_at TEXT NOT NULL,
    transfer_reference TEXT,
    transfer_status TEXT NOT NULL DEFAULT 'pending'
);
