-- Issue #247: atomic device-code exchange.
--
-- An approved device code is consumed and the token pair is persisted in one
-- D1 batch. This table stores a bounded, encrypted replay receipt keyed by the
-- device code hash so a post-commit retry (for example after a lost response
-- or a transient audit failure) converges on the same token pair instead of
-- being rejected as invalid_grant. The plaintext token pair is encrypted under
-- a key derived from the device code itself; D1 never stores a plaintext
-- token.
CREATE TABLE IF NOT EXISTS device_code_exchange_receipts (
  device_code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource TEXT,
  access_token_hash TEXT NOT NULL,
  refresh_token_hash TEXT NOT NULL,
  refresh_family TEXT NOT NULL,
  encrypted_successor TEXT NOT NULL,
  iv TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_code_receipts_expiry
  ON device_code_exchange_receipts(expires_at);
