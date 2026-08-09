-- Server-owned credential generation for exact action binding.
--
-- This is deliberately principal-auth-record state, not a caller supplied
-- claim/version. Refresh rotation, refresh-reuse detection, and explicit token
-- revocation advance it so a previously bound operation cannot be redelivered
-- under an old credential generation.
PRAGMA foreign_keys = ON;

ALTER TABLE principals
  ADD COLUMN credential_generation INTEGER NOT NULL DEFAULT 1
  CHECK (credential_generation >= 1);
