-- Issue #224 plan F (P1): seed hot-path bootstrap rows, drop proven-redundant
-- hot indexes, and add quota-probe + operation-store cutover tables.
--
-- Index drops (verified: no WHERE/ORDER BY usage remains, EXPLAIN covered):
-- - idx_mcp_ops_payload_hash: payload_hash is never a lookup key (write/read
--   column only).
-- - idx_mcp_ops_idempotency (0008, non-unique): equality lookups are served by
--   the uq_mcp_ops_idempotency / uq_mcp_ops_idempotency_no_device partial
--   UNIQUE indexes.
-- - idx_mcp_outbox_op: operation_id is UNIQUE (implicit autoindex covers it).
-- - idx_audit_tenant(tenant_id, created_at): prefix-covered by
--   idx_audit_events_retention(tenant_id, created_at, id).
-- - idx_mcp_ops_updated: retention ORDER BY updated_at is served by the 0019
--   partial expiry indexes; point deletes are by PRIMARY KEY.
PRAGMA foreign_keys = ON;

-- Hot-path bootstrap seed so request handlers can verify-then-skip instead of
-- issuing three INSERT OR IGNORE writes per call.
INSERT OR IGNORE INTO tenants (id, name, created_at)
VALUES ('ten_default', 'Default', '2026-01-01T00:00:00.000Z');
INSERT OR IGNORE INTO principals (id, tenant_id, kind, display_name, created_at)
VALUES ('prin_dev', 'ten_default', 'human', 'Dev User', '2026-01-01T00:00:00.000Z');
INSERT OR IGNORE INTO oauth_clients (client_id, tenant_id, client_name, redirect_uris, created_at)
VALUES (
  'client_ownmesh_cli',
  'ten_default',
  'OwnMesh CLI',
  '["http://127.0.0.1:8750/callback","http://localhost:8750/callback"]',
  '2026-01-01T00:00:00.000Z'
);

DROP INDEX IF EXISTS idx_mcp_ops_payload_hash;
DROP INDEX IF EXISTS idx_mcp_ops_idempotency;
DROP INDEX IF EXISTS idx_mcp_outbox_op;
DROP INDEX IF EXISTS idx_audit_tenant;
DROP INDEX IF EXISTS idx_mcp_ops_updated;

-- Single-row write probe for /health/ready auth_write_ready (quota-aware).
CREATE TABLE IF NOT EXISTS quota_probe (
  id TEXT PRIMARY KEY,
  checked_at TEXT NOT NULL
);

-- Per-tenant DeviceRoom operation-store cutover cursor (ISO time or 'd1').
-- Absent row means D1 authority (current behavior).
CREATE TABLE IF NOT EXISTS operation_store_cutover (
  tenant_id TEXT PRIMARY KEY,
  cutover_at TEXT NOT NULL
);
