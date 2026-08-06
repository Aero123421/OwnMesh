-- OAuth auth codes, device authorization (RFC 8628), used refresh reuse ledger,
-- enrollment challenges. Builds on 0001_init.sql.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS oauth_auth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
  principal_id TEXT NOT NULL REFERENCES principals(id),
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL DEFAULT 'S256',
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_codes (
  device_code_hash TEXT PRIMARY KEY,
  user_code TEXT NOT NULL UNIQUE,
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  verification_uri TEXT NOT NULL,
  interval_sec INTEGER NOT NULL DEFAULT 5,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  principal_id TEXT,
  last_polled_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS used_refresh_tokens (
  refresh_token_hash TEXT PRIMARY KEY,
  refresh_family TEXT NOT NULL,
  used_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollment_challenges (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id),
  nonce TEXT NOT NULL,
  message TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_migrations (
  id TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_client ON oauth_auth_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_device_codes_user ON device_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_used_refresh_family ON used_refresh_tokens(refresh_family);
CREATE INDEX IF NOT EXISTS idx_enroll_device ON enrollment_challenges(device_id);
