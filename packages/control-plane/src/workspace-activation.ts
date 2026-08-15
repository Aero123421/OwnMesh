/**
 * Authoritative workspace activation view.
 *
 * Cloud custody can reserve an id before the Agent has advertised a generation.
 * Execution may use a workspace only after that generation is observed. Listing
 * and show must expose the bounded lifecycle instead of implying readiness.
 */

import type { WorkspaceRecord } from "./store.ts";

export const WORKSPACE_GENERATION_RE = /^wsg_[a-f0-9]{32}$/;

export const WORKSPACE_ROOT_ENFORCEMENT_NOTE =
  "Independent of access_preset. When true, filesystem and command tools require a registered workspace. Full Access still allows an explicitly permitted absolute path only with workspace_id: null.";

export type WorkspaceActivationState = "pending_activation" | "active" | "unavailable";

export type WorkspaceUnavailableCause =
  | "not_found"
  | "pending_activation"
  | "inactive"
  | "not_authorized"
  | "device_mismatch";

export type WorkspaceNextAction =
  | "retry_activation"
  | "select_active_workspace"
  | "use_permitted_absolute_path"
  | "none";

export type WorkspaceActivationView = {
  activation_state: WorkspaceActivationState;
  activation_reason: WorkspaceUnavailableCause | "ready";
  next_action: WorkspaceNextAction;
};

export type WorkspaceOperableGate =
  | { ok: true; workspace: WorkspaceRecord }
  | {
      ok: false;
      error: "workspace_not_available";
      cause: WorkspaceUnavailableCause;
      next_action: WorkspaceNextAction;
    };

export function parseWorkspaceGeneration(value: unknown): string | undefined {
  return typeof value === "string" && WORKSPACE_GENERATION_RE.test(value) ? value : undefined;
}

export function workspaceActivationView(
  workspace: WorkspaceRecord | null | undefined,
): WorkspaceActivationView {
  if (!workspace) {
    return {
      activation_state: "unavailable",
      activation_reason: "not_found",
      next_action: "select_active_workspace",
    };
  }
  if (!workspace.local_generation) {
    return {
      activation_state: "pending_activation",
      activation_reason: "pending_activation",
      next_action: "retry_activation",
    };
  }
  if (!workspace.active) {
    return {
      activation_state: "unavailable",
      activation_reason: "inactive",
      next_action: "select_active_workspace",
    };
  }
  return {
    activation_state: "active",
    activation_reason: "ready",
    next_action: "none",
  };
}

export function classifyWorkspaceVisibility(
  workspace: WorkspaceRecord | null,
  deviceId: string,
  tenantId: string,
): WorkspaceOperableGate {
  if (!workspace) {
    return {
      ok: false,
      error: "workspace_not_available",
      cause: "not_found",
      next_action: "select_active_workspace",
    };
  }
  if (workspace.tenant_id !== tenantId || workspace.device_id !== deviceId) {
    return {
      ok: false,
      error: "workspace_not_available",
      cause: "device_mismatch",
      next_action: "select_active_workspace",
    };
  }
  return { ok: true, workspace };
}

export function classifyWorkspaceAvailability(
  workspace: WorkspaceRecord | null,
  deviceId: string,
  tenantId: string,
): WorkspaceOperableGate {
  if (!workspace) {
    return {
      ok: false,
      error: "workspace_not_available",
      cause: "not_found",
      next_action: "select_active_workspace",
    };
  }
  if (workspace.tenant_id !== tenantId || workspace.device_id !== deviceId) {
    return {
      ok: false,
      error: "workspace_not_available",
      cause: "device_mismatch",
      next_action: "select_active_workspace",
    };
  }
  if (!workspace.local_generation) {
    return {
      ok: false,
      error: "workspace_not_available",
      cause: "pending_activation",
      next_action: "retry_activation",
    };
  }
  if (!workspace.active) {
    return {
      ok: false,
      error: "workspace_not_available",
      cause: "inactive",
      next_action: "select_active_workspace",
    };
  }
  return { ok: true, workspace };
}

export function applyObservedGeneration(
  existing: WorkspaceRecord | null,
  input: {
    workspaceId: string;
    deviceId: string;
    tenantId: string;
    ownerPrincipalId: string;
    generation: string;
    observedAt: string;
  },
): WorkspaceRecord {
  if (!existing) {
    return {
      workspace_id: input.workspaceId,
      tenant_id: input.tenantId,
      device_id: input.deviceId,
      owner_principal_id: input.ownerPrincipalId,
      version: 1,
      local_generation: input.generation,
      active: true,
      created_at: input.observedAt,
      updated_at: input.observedAt,
    };
  }
  const generationChanged =
    existing.local_generation !== undefined && existing.local_generation !== input.generation;
  const needsActivation = !existing.active || !existing.local_generation || generationChanged;
  if (!needsActivation) {
    return { ...existing };
  }
  return {
    ...existing,
    active: true,
    version: existing.version + 1,
    local_generation: input.generation,
    updated_at: input.observedAt,
  };
}

export function annotateWorkspaceRecord(
  data: Record<string, unknown>,
  workspace: WorkspaceRecord | null | undefined,
): Record<string, unknown> {
  const view = workspaceActivationView(workspace);
  const { generation: _generation, ...rest } = data;
  return {
    ...rest,
    activation_state: view.activation_state,
    activation_reason: view.activation_reason,
    next_action: view.next_action,
  };
}

export function annotateWorkspaceList(
  data: Record<string, unknown>,
  records: Map<string, WorkspaceRecord>,
  enforceWorkspace: boolean | undefined,
): Record<string, unknown> {
  const workspaces = Array.isArray(data.workspaces) ? data.workspaces : [];
  const annotated = workspaces.map((entry) => {
    if (!entry || typeof entry !== "object") return entry;
    const row = entry as Record<string, unknown>;
    const id = typeof row.id === "string" ? row.id : "";
    return annotateWorkspaceRecord(row, records.get(id));
  });
  const { enforce_workspace: _legacy, ...rest } = data;
  return {
    ...rest,
    workspaces: annotated,
    workspace_root_enforcement: enforceWorkspace === true,
    enforce_workspace: enforceWorkspace === true,
    workspace_root_enforcement_note: WORKSPACE_ROOT_ENFORCEMENT_NOTE,
  };
}

export function annotatePolicyObservation(
  data: Record<string, unknown>,
  enforceWorkspace: boolean | undefined,
): Record<string, unknown> {
  return {
    ...data,
    workspace_root_enforcement: enforceWorkspace === true,
    enforce_workspace: enforceWorkspace === true,
    workspace_root_enforcement_note: WORKSPACE_ROOT_ENFORCEMENT_NOTE,
  };
}
