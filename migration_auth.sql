-- MSP Server Tracker — Auth migration
-- Run against the ALREADY-DEPLOYED database (adds to existing data, doesn't touch it)
-- Run: npx wrangler d1 execute msp-tracker --file=migration_auth.sql --remote

ALTER TABLE status_logs  ADD COLUMN performed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE transactions ADD COLUMN performed_by TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,
  salt          TEXT    NOT NULL,
  role          TEXT    NOT NULL DEFAULT 'user',   -- 'admin' | 'user'
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
