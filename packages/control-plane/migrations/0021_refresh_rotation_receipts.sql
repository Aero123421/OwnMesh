-- Bounded idempotency receipts for refresh-token rotation (#213).
-- They let an exact duplicate retry (concurrent request or response-loss
-- retransmission) converge to the same successor token set without treating the
-- retry as a reuse attack. Receipts expire quickly; an expired receipt is
-- treated the same as an ordinary ledger hit.
--
-- The encrypted_successor field is AES-256-GCM ciphertext of a short JSON
-- object containing the plaintext access_token and refresh_token. The key is
-- derived from SHA-256 of the *old* refresh token, so the receipt ciphertext
-- alone cannot be decrypted by someone who does not also possess the old
-- refresh token. Plaintext tokens are never stored unencrypted in D1.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS refresh_rotation_receipts (
  old_refresh_token_hash TEXT PRIMARY KEY,
  refresh_family TEXT NOT NULL,
  client_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  successor_access_token_hash TEXT NOT NULL,
  successor_refresh_token_hash TEXT NOT NULL,
  encrypted_successor TEXT NOT NULL,
  iv TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_refresh_rotation_receipts_expires_at
ON refresh_rotation_receipts(expires_at);
