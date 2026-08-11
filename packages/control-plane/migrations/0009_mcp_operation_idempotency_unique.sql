-- v1.2 E3: one durable owner per (principal, tenant, device, idempotency_key).
-- Concurrent MCP callers must not insert two rows for the same key and then
-- race-route different actions. Partial unique index excludes NULL keys so
-- mismatch failure rows (idempotency_key cleared) do not collide.
PRAGMA foreign_keys = ON;

CREATE UNIQUE INDEX IF NOT EXISTS uq_mcp_ops_idempotency
  ON mcp_operations(principal_id, tenant_id, device_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL AND length(idempotency_key) > 0;
