-- Keep API bearer tokens short-lived while allowing an actively used OAuth
-- connection to rotate its refresh token over a longer inactivity window.
ALTER TABLE oauth_tokens ADD COLUMN refresh_expires_at TEXT;

-- Existing credentials keep their old deadline. Users authorize once more to
-- receive the new rolling lifetime; a migration must never silently extend a
-- previously issued bearer credential.
UPDATE oauth_tokens
SET refresh_expires_at = expires_at
WHERE refresh_expires_at IS NULL;
