-- Stale-claim recovery lease for mcp_approval_outbox delivering claims.
-- claimed_at records when the exclusive delivering claim was taken; a delivering
-- row may be reclaimed only after the lease TTL elapses (see store const).
-- Depends on 0005_mcp_operations.sql (mcp_approval_outbox table).
ALTER TABLE mcp_approval_outbox ADD COLUMN claimed_at TEXT;
