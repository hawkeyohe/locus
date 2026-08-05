CREATE TABLE IF NOT EXISTS api_tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at TEXT, last_used_at TEXT, revoked_at TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, run_id TEXT NOT NULL UNIQUE REFERENCES test_runs(id) ON DELETE CASCADE, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, available_at TEXT NOT NULL, claimed_at TEXT, lease_expires_at TEXT, worker_id TEXT, last_error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_jobs_available ON jobs(status, available_at, lease_expires_at);
