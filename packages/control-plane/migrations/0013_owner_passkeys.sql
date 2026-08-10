-- Built-in single-owner passkey authentication.
-- Bootstrap secrets remain Wrangler secrets; D1 stores only public
-- credentials and short-lived, one-time WebAuthn challenges.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS owner_passkeys (
  credential_id TEXT PRIMARY KEY
    CHECK (length(credential_id) BETWEEN 16 AND 1024),
  principal_id TEXT NOT NULL,
  webauthn_user_id TEXT NOT NULL
    CHECK (length(webauthn_user_id) BETWEEN 16 AND 128),
  public_key BLOB NOT NULL
    CHECK (length(public_key) BETWEEN 32 AND 2048),
  counter INTEGER NOT NULL DEFAULT 0 CHECK (counter >= 0),
  transports_json TEXT NOT NULL DEFAULT '[]'
    CHECK (length(transports_json) <= 512),
  device_type TEXT NOT NULL
    CHECK (device_type IN ('singleDevice', 'multiDevice')),
  backed_up INTEGER NOT NULL DEFAULT 0 CHECK (backed_up IN (0, 1)),
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_owner_passkeys_principal
  ON owner_passkeys(principal_id);

CREATE TABLE IF NOT EXISTS owner_auth_challenges (
  id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 8 AND 128),
  kind TEXT NOT NULL CHECK (kind IN ('register', 'authenticate')),
  challenge TEXT NOT NULL CHECK (length(challenge) BETWEEN 16 AND 512),
  webauthn_user_id TEXT,
  return_to TEXT NOT NULL CHECK (length(return_to) BETWEEN 1 AND 4096),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_owner_auth_challenges_expiry
  ON owner_auth_challenges(expires_at);
