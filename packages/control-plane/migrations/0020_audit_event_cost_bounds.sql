-- v1.2.31: bound audit retention and admission independently of table size.
-- The counter is transactionally maintained by SQLite triggers; request paths
-- never use COUNT(*) and retention touches at most one indexed batch.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS audit_event_tenant_counters (
  tenant_id TEXT PRIMARY KEY,
  event_count INTEGER NOT NULL DEFAULT 0 CHECK (event_count >= 0),
  maintenance_after TEXT NOT NULL DEFAULT '1970-01-01T00:00:00.000Z'
);

INSERT INTO audit_event_tenant_counters (tenant_id, event_count)
SELECT tenant_id, COUNT(*)
FROM audit_events
GROUP BY tenant_id
ON CONFLICT(tenant_id) DO UPDATE SET event_count = excluded.event_count;

CREATE TRIGGER IF NOT EXISTS trg_audit_events_counter_insert
AFTER INSERT ON audit_events
BEGIN
  INSERT INTO audit_event_tenant_counters (tenant_id, event_count)
  VALUES (NEW.tenant_id, 1)
  ON CONFLICT(tenant_id) DO UPDATE SET event_count = event_count + 1;
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_events_counter_delete
AFTER DELETE ON audit_events
BEGIN
  UPDATE audit_event_tenant_counters
  SET event_count = CASE WHEN event_count > 0 THEN event_count - 1 ELSE 0 END
  WHERE tenant_id = OLD.tenant_id;
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_events_counter_move
AFTER UPDATE OF tenant_id ON audit_events
WHEN OLD.tenant_id != NEW.tenant_id
BEGIN
  UPDATE audit_event_tenant_counters
  SET event_count = CASE WHEN event_count > 0 THEN event_count - 1 ELSE 0 END
  WHERE tenant_id = OLD.tenant_id;
  INSERT INTO audit_event_tenant_counters (tenant_id, event_count)
  VALUES (NEW.tenant_id, 1)
  ON CONFLICT(tenant_id) DO UPDATE SET event_count = event_count + 1;
END;

CREATE INDEX IF NOT EXISTS idx_audit_events_retention
  ON audit_events(tenant_id, created_at, id);
