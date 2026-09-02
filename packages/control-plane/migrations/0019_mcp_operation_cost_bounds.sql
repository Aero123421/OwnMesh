-- v1.2.27: keep MCP operation admission and retention independent of table size.
-- The counter is maintained by the same SQLite statement transaction as each
-- INSERT/DELETE, so concurrent admissions cannot pass a stale COUNT(*) check.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS mcp_operation_tenant_counters (
  tenant_id TEXT PRIMARY KEY,
  operation_count INTEGER NOT NULL DEFAULT 0 CHECK (operation_count >= 0),
  maintenance_after TEXT NOT NULL DEFAULT '1970-01-01T00:00:00.000Z'
);

-- One bounded deployment-time backfill replaces request-path COUNT(*).
INSERT INTO mcp_operation_tenant_counters (tenant_id, operation_count)
SELECT tenant_id, COUNT(*)
FROM mcp_operations
GROUP BY tenant_id
ON CONFLICT(tenant_id) DO UPDATE SET operation_count = excluded.operation_count;

CREATE TRIGGER IF NOT EXISTS trg_mcp_ops_counter_insert
AFTER INSERT ON mcp_operations
BEGIN
  INSERT INTO mcp_operation_tenant_counters (tenant_id, operation_count)
  VALUES (NEW.tenant_id, 1)
  ON CONFLICT(tenant_id) DO UPDATE
    SET operation_count = operation_count + 1;
END;

CREATE TRIGGER IF NOT EXISTS trg_mcp_ops_counter_delete
AFTER DELETE ON mcp_operations
BEGIN
  UPDATE mcp_operation_tenant_counters
  SET operation_count = CASE
    WHEN operation_count > 0 THEN operation_count - 1
    ELSE 0
  END
  WHERE tenant_id = OLD.tenant_id;
END;

-- Tenant ownership is immutable through SqlStore, but keep direct SQL repairs
-- and future migrations from drifting the admission counter.
CREATE TRIGGER IF NOT EXISTS trg_mcp_ops_counter_move
AFTER UPDATE OF tenant_id ON mcp_operations
WHEN OLD.tenant_id != NEW.tenant_id
BEGIN
  UPDATE mcp_operation_tenant_counters
  SET operation_count = CASE
    WHEN operation_count > 0 THEN operation_count - 1
    ELSE 0
  END
  WHERE tenant_id = OLD.tenant_id;
  INSERT INTO mcp_operation_tenant_counters (tenant_id, operation_count)
  VALUES (NEW.tenant_id, 1)
  ON CONFLICT(tenant_id) DO UPDATE
    SET operation_count = operation_count + 1;
END;

-- One-time legacy cleanup. SqlStore no longer admits a keyless tombstone, and
-- the DELETE trigger keeps the freshly backfilled counter exact.
DELETE FROM mcp_operations
WHERE status = 'tombstone'
  AND (idempotency_key IS NULL OR idempotency_key = '');

-- Equality lookup for operations without a device must be unique too. SQLite
-- considers NULL values distinct in the older composite unique index.
CREATE UNIQUE INDEX IF NOT EXISTS uq_mcp_ops_idempotency_no_device
  ON mcp_operations(principal_id, tenant_id, idempotency_key)
  WHERE device_id IS NULL
    AND idempotency_key IS NOT NULL
    AND length(idempotency_key) > 0;

-- Partial indexes exactly match the three bounded retention batches.
CREATE INDEX IF NOT EXISTS idx_mcp_ops_tombstone_expiry
  ON mcp_operations(tenant_id, updated_at, operation_id)
  WHERE status = 'tombstone';

CREATE INDEX IF NOT EXISTS idx_mcp_ops_terminal_keyless_expiry
  ON mcp_operations(tenant_id, updated_at, operation_id)
  WHERE status IN ('completed','failed','denied','cancelled','device_offline')
    AND (idempotency_key IS NULL OR idempotency_key = '');

CREATE INDEX IF NOT EXISTS idx_mcp_ops_terminal_keyed_expiry
  ON mcp_operations(tenant_id, updated_at, operation_id)
  WHERE status IN ('completed','failed','denied','cancelled','device_offline')
    AND idempotency_key IS NOT NULL
    AND idempotency_key != '';
