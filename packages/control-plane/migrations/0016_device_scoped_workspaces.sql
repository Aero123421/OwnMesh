-- Workspace ids are device-local names (every device has ws_default).
-- Keep the legacy 0011 tables for migration compatibility, but move active
-- authority to device-scoped tables so one device can never capture another
-- device's same-named workspace.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS device_workspaces (
  workspace_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  owner_principal_id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1),
  -- Opaque Agent mapping token. NULL legacy/backfill rows are fail-closed until
  -- the first authenticated generation-aware Agent ready snapshot.
  local_generation TEXT,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (device_id, workspace_id),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (device_id) REFERENCES devices(id),
  FOREIGN KEY (owner_principal_id) REFERENCES principals(id)
);

CREATE INDEX IF NOT EXISTS idx_device_workspaces_tenant_device
  ON device_workspaces(tenant_id, device_id, active);
CREATE INDEX IF NOT EXISTS idx_device_workspaces_owner
  ON device_workspaces(tenant_id, owner_principal_id, active);

CREATE TABLE IF NOT EXISTS device_workspace_members (
  device_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (device_id, workspace_id, principal_id),
  FOREIGN KEY (device_id, workspace_id)
    REFERENCES device_workspaces(device_id, workspace_id),
  FOREIGN KEY (principal_id) REFERENCES principals(id)
);

CREATE INDEX IF NOT EXISTS idx_device_workspace_members_principal
  ON device_workspace_members(principal_id, device_id, workspace_id);

-- Preserve every pre-0016 custody row under its original device binding.
INSERT OR IGNORE INTO device_workspaces
  (workspace_id, tenant_id, device_id, owner_principal_id, version, local_generation, active,
   created_at, updated_at)
SELECT workspace_id, tenant_id, device_id, owner_principal_id, version, NULL, active,
       created_at, updated_at
FROM workspaces;

INSERT OR IGNORE INTO device_workspace_members
  (device_id, workspace_id, principal_id, created_at)
SELECT w.device_id, m.workspace_id, m.principal_id, m.created_at
FROM workspace_members AS m
JOIN workspaces AS w ON w.workspace_id = m.workspace_id;

-- Every OwnMesh runtime creates this device-local root. Backfill all enrolled
-- devices, including the second and later device that the global 0011 key
-- could not represent.
INSERT OR IGNORE INTO device_workspaces
  (workspace_id, tenant_id, device_id, owner_principal_id, version, local_generation, active,
   created_at, updated_at)
SELECT 'ws_default', tenant_id, id, principal_id, 1, NULL, 1, created_at, created_at
FROM devices
WHERE revoked = 0;
