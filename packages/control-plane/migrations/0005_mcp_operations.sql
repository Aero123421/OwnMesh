-- v1.0.2 MCP operation / result / approval authoritative persistence.
-- Worker isolate Maps are cache-only; D1 (or DO-written D1) is source of truth.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS mcp_operations (
  operation_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  device_id TEXT,
  tool TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  data_json TEXT NOT NULL DEFAULT '{}',
  truncated INTEGER NOT NULL DEFAULT 0,
  next_cursor TEXT,
  approval_required INTEGER NOT NULL DEFAULT 0,
  approval_url TEXT,
  approval_id TEXT,
  session_id TEXT,
  warnings_json TEXT NOT NULL DEFAULT '[]',
  correlation_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mcp_ops_principal_tenant
  ON mcp_operations(principal_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_mcp_ops_device
  ON mcp_operations(device_id);
CREATE INDEX IF NOT EXISTS idx_mcp_ops_correlation
  ON mcp_operations(correlation_id);
CREATE INDEX IF NOT EXISTS idx_mcp_ops_updated
  ON mcp_operations(updated_at);

-- One-time CSRF-bound human approval decisions for approval_required ops.
CREATE TABLE IF NOT EXISTS mcp_approval_transactions (
  id TEXT PRIMARY KEY,
  csrf_hash TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  device_id TEXT,
  expires_at TEXT NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0,
  decision TEXT CHECK (decision IS NULL OR decision IN ('approve', 'deny')),
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mcp_apr_op
  ON mcp_approval_transactions(operation_id);
CREATE INDEX IF NOT EXISTS idx_mcp_apr_principal
  ON mcp_approval_transactions(principal_id);
CREATE INDEX IF NOT EXISTS idx_mcp_apr_expires
  ON mcp_approval_transactions(expires_at);

-- Durable one-time approval decision outbox (delivery before authoritative CAS).
-- delivery_status: pending → delivering (claim) → delivered.
CREATE TABLE IF NOT EXISTS mcp_approval_outbox (
  id TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL UNIQUE,
  principal_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  device_id TEXT,
  decision TEXT NOT NULL CHECK (decision IN ('approve', 'deny')),
  correlation_id TEXT NOT NULL,
  delivery_status TEXT NOT NULL DEFAULT 'pending'
    CHECK (delivery_status IN ('pending', 'delivering', 'delivered')),
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at TEXT NOT NULL,
  delivered_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_mcp_outbox_op
  ON mcp_approval_outbox(operation_id);
CREATE INDEX IF NOT EXISTS idx_mcp_outbox_status
  ON mcp_approval_outbox(delivery_status);
