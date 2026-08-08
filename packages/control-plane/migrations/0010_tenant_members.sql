-- Minimal tenant membership for multi-principal device operation (E3/E5).
-- Device owners remain authoritative for enrollment; members may operate
-- already-active devices in the same tenant (sessions/ops/transfers).

CREATE TABLE IF NOT EXISTS tenant_members (
  tenant_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, principal_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_members_principal
  ON tenant_members (principal_id);
