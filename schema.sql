-- D1 schema for Zeabur Monitor
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  token_encrypted TEXT,
  token_iv TEXT,
  token_plain TEXT,
  sort_index INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_name ON accounts(name);

CREATE TABLE IF NOT EXISTS admin_password (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at);
