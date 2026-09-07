CREATE TABLE IF NOT EXISTS servers (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  server_name  TEXT    NOT NULL,
  type         TEXT    NOT NULL DEFAULT '',
  environment  TEXT    NOT NULL DEFAULT '',
  status       TEXT    NOT NULL DEFAULT 'active',
  enabled      INTEGER NOT NULL DEFAULT 0,
  enabled_date TEXT,
  monthly_cost REAL    NOT NULL DEFAULT 0,
  notes        TEXT    NOT NULL DEFAULT '',
  created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS status_logs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  server_id   INTEGER NOT NULL,
  server_name TEXT    NOT NULL,
  action      TEXT    NOT NULL,
  timestamp   TEXT    NOT NULL DEFAULT (datetime('now')),
  notes       TEXT    NOT NULL DEFAULT '',
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
  period_start TEXT,
  period_end   TEXT,
  date         TEXT    NOT NULL DEFAULT (date('now')),
  notes        TEXT    NOT NULL DEFAULT '',
  created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_servers_name   ON servers(server_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_servers_status ON servers(status);
CREATE INDEX IF NOT EXISTS idx_logs_server    ON status_logs(server_id);
CREATE INDEX IF NOT EXISTS idx_logs_ts        ON status_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_txn_txnid      ON transactions(txn_id);
CREATE INDEX IF NOT EXISTS idx_txn_date       ON transactions(date);
CREATE INDEX IF NOT EXISTS idx_txn_server     ON transactions(server_id);
