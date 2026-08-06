-- v1.0.2 authorization consent transactions: short-lived one-time CSRF-bound
-- snapshots for OAuth authorize GET→POST (principal/tenant/client/redirect/scope/state/PKCE).
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS authorize_transactions (
  id TEXT PRIMARY KEY,
  csrf_hash TEXT NOT NULL,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT '',
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL DEFAULT 'S256',
  expires_at TEXT NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_authorize_tx_principal ON authorize_transactions(principal_id);
CREATE INDEX IF NOT EXISTS idx_authorize_tx_expires ON authorize_transactions(expires_at);
