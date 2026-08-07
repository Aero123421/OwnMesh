-- v1.0.2 control-plane P0 hardening: explicit device lifecycle,
-- device credentials, and one-time authenticated device verification transactions.
PRAGMA foreign_keys = ON;

ALTER TABLE devices ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'
  CHECK (status IN ('pending', 'active', 'revoked'));

-- Existing installs predate proof-gated activation. Preserve their availability while
-- all newly enrolled devices are explicitly inserted as pending.
UPDATE devices SET status = CASE WHEN revoked = 1 THEN 'revoked' ELSE 'active' END;

CREATE TABLE IF NOT EXISTS revoked_refresh_families (
  refresh_family TEXT PRIMARY KEY,
  detected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_credentials (
  credential_hash TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id),
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  principal_id TEXT NOT NULL REFERENCES principals(id),
  role TEXT NOT NULL CHECK (role = 'agent'),
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_verification_transactions (
  id TEXT PRIMARY KEY,
  csrf_hash TEXT NOT NULL,
  user_code TEXT NOT NULL,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_credentials_device ON device_credentials(device_id);
CREATE INDEX IF NOT EXISTS idx_device_verification_user ON device_verification_transactions(user_code);
