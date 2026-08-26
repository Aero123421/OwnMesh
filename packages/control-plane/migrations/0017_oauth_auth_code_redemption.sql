-- Bind a successfully redeemed authorization code to exactly one persisted
-- token family. NULL preserves compatibility for tokens issued by other grants.
ALTER TABLE oauth_tokens ADD COLUMN auth_code_hash TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_tokens_auth_code_hash
ON oauth_tokens(auth_code_hash)
WHERE auth_code_hash IS NOT NULL;
