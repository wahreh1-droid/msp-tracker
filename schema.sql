-- MSP Server Tracker — D1 Schema
-- Run: npx wrangler d1 execute msp-tracker --file=schema.sql --remote

CREATE TABLE IF NOT EXISTS servers (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  server_name  TEXT    NOT NULL,
  type         TEXT    NOT NULL DEFAULT '',
  environment  TEXT    NOT NULL DEFAULT '',
  status       TEXT    NOT NULL DEFAULT 'active',       -- 'active' | 'decommissioned'
  enabled      INTEGER NOT NULL DEFAULT 0,              -- 0 | 1
  enabled_date TEXT,                                    -- YYYY-MM-DD, set when toggled ON
  monthly_cost REAL    NOT NULL DEFAULT 0,
  notes        TEXT    NOT NULL DEFAULT '',
  created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS status_logs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  server_id   INTEGER NOT NULL,
  server_name TEXT    NOT NULL,
  action      TEXT    NOT NULL,   -- 'enabled' | 'disabled' | 'decommissioned'
  timestamp   TEXT    NOT NULL DEFAULT (datetime('now')),
  notes       TEXT    NOT NULL DEFAULT '',
  performed_by TEXT   NOT NULL DEFAULT '',   -- username who performed the action
  FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS transactions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  txn_id       TEXT    NOT NULL,
  server_id    INTEGER,
  server_name  TEXT    NOT NULL,
  action       TEXT    NOT NULL DEFAULT 'billing',
  amount       REAL    NOT NULL DEFAULT 0,
  days_billed  INTEGER NOT NULL DEFAULT 0,
  period_start TEXT,                                    -- YYYY-MM-DD
  period_end   TEXT,                                    -- YYYY-MM-DD
  date         TEXT    NOT NULL DEFAULT (date('now')),
  notes        TEXT    NOT NULL DEFAULT '',
  created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
  performed_by TEXT    NOT NULL DEFAULT '',   -- username who performed the action
  FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,
  salt          TEXT    NOT NULL,
  role          TEXT    NOT NULL DEFAULT 'user',   -- 'admin' | 'user'
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_servers_name    ON servers(server_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_servers_status  ON servers(status);
CREATE INDEX IF NOT EXISTS idx_logs_server     ON status_logs(server_id);
CREATE INDEX IF NOT EXISTS idx_logs_ts         ON status_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_txn_txnid       ON transactions(txn_id);
CREATE INDEX IF NOT EXISTS idx_txn_date        ON transactions(date);
CREATE INDEX IF NOT EXISTS idx_txn_server      ON transactions(server_id);
CREATE INDEX IF NOT EXISTS idx_users_username  ON users(username);
