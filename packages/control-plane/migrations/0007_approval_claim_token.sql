-- Claim ownership token/version for mcp_approval_outbox.
-- Issued on every successful claim/reclaim; release/finalize require owner match
-- (claim_token + claim_version). Stale reclaim invalidates the previous owner.
-- Depends on 0006_approval_outbox_claim_lease.sql (claimed_at lease column).
ALTER TABLE mcp_approval_outbox ADD COLUMN claim_token TEXT;
ALTER TABLE mcp_approval_outbox ADD COLUMN claim_version INTEGER NOT NULL DEFAULT 0;
