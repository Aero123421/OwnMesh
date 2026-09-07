-- Issue #195: RFC 8707 resource / MCP audience binding.
-- New issuance always binds the canonical `https://<issuer>/mcp` resource.
-- Pre-migration rows have NULL (unbound) and stay usable at /mcp for
-- migration compat; reauthorization binds them. See docs/mcp-clients.md.
PRAGMA foreign_keys = ON;

ALTER TABLE oauth_tokens ADD COLUMN resource TEXT;
ALTER TABLE oauth_auth_codes ADD COLUMN resource TEXT;
ALTER TABLE authorize_transactions ADD COLUMN resource TEXT;
ALTER TABLE device_codes ADD COLUMN resource TEXT;
