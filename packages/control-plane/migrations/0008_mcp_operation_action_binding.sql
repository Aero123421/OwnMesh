-- v1.2 E3: bind exact authorized MCP actions on durable operation rows.
-- payload_hash is server-computed; client-supplied hashes are never authority.
PRAGMA foreign_keys = ON;

ALTER TABLE mcp_operations ADD COLUMN payload_hash TEXT;
ALTER TABLE mcp_operations ADD COLUMN idempotency_key TEXT;
ALTER TABLE mcp_operations ADD COLUMN workspace_id TEXT;
ALTER TABLE mcp_operations ADD COLUMN expires_at TEXT;
ALTER TABLE mcp_operations ADD COLUMN claim_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mcp_operations ADD COLUMN action_json TEXT NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_mcp_ops_idempotency
  ON mcp_operations(principal_id, tenant_id, device_id, idempotency_key);

CREATE INDEX IF NOT EXISTS idx_mcp_ops_payload_hash
  ON mcp_operations(payload_hash);
