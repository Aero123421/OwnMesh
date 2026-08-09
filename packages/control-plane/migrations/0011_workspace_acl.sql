-- E4 cloud workspace custody.  Filesystem roots remain device-local; this
-- table is the authoritative tenant/principal/device ACL and version binding.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS workspaces (
  workspace_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  owner_principal_id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (device_id) REFERENCES devices(id),
  FOREIGN KEY (owner_principal_id) REFERENCES principals(id)
);

CREATE INDEX IF NOT EXISTS idx_workspaces_tenant_device
  ON workspaces(tenant_id, device_id, active);
CREATE INDEX IF NOT EXISTS idx_workspaces_owner
  ON workspaces(tenant_id, owner_principal_id, active);

CREATE TABLE IF NOT EXISTS workspace_members (
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, principal_id),
  FOREIGN KEY (workspace_id) REFERENCES workspaces(workspace_id),
  FOREIGN KEY (principal_id) REFERENCES principals(id)
);

CREATE INDEX IF NOT EXISTS idx_workspace_members_principal
  ON workspace_members(principal_id, workspace_id);
