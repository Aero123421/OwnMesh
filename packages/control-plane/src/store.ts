/**
 * Control-plane persistence.
 *
 * Production path: D1 via Workers Binding API
 *   https://developers.cloudflare.com/d1/worker-api/
 * Test path: node:sqlite applying the same migrations/ SQL.
 */

import {
  nowIso,
  randomId,
  randomToken,
  sha256Hex,
  generateUserCode,
} from "./util.ts";
import {
  applyObservedGeneration,
  classifyWorkspaceAvailability,
  classifyWorkspaceVisibility,
  parseWorkspaceGeneration,
  parseWorkspaceId,
  type WorkspaceOperableGate,
} from "./workspace-activation.ts";

export type { WorkspaceOperableGate } from "./workspace-activation.ts";

/** Short-lived bearer used for API requests. */
export const ACCESS_TOKEN_TTL_MS = 15 * 60 * 1000;
/** Rolling inactivity limit for a rotated refresh-token family. */
export const REFRESH_TOKEN_IDLE_TTL_MS = 180 * 24 * 60 * 60 * 1000;
/** Do not turn reconnect churn into a D1 write stream when metadata is unchanged. */
export const DEVICE_READY_WRITE_INTERVAL_MS = 60_000;

export type TokenRecord = {
  access_token: string;
  refresh_token: string;
  client_id: string;
  scope: string;
  principal: string;
  expires_at: number;
  refresh_expires_at: number;
  revoked: boolean;
  refresh_family: string;
  refresh_used: boolean;
  tenant_id: string;
};

/** Metadata for RFC 7009 revoke audit attribution (no token secret). */
export type RevocableTokenMeta = {
  tenant_id: string;
  principal_id: string;
  client_id: string;
};

export type DeviceRecord = {
  id: string;
  tenant_id: string;
  principal_id: string;
  name: string;
  /** Display-only metadata. Labels are never an authorization input. */
  labels?: string[];
  hostname: string;
  os: string;
  arch: string;
  agent_version: string;
  protocol_version: string;
  /** Authenticated Agent policy observation. Undefined for pre-1.2.9 Agents. */
  enforce_workspace?: boolean;
  public_key: string;
  revoked: boolean;
  created_at: string;
  last_seen_at?: string;
  /** Live session state is supplied by DeviceRoom, never used for authorization. */
  connection_status?: "online" | "offline" | "unknown";
  /** Explicit enrollment lifecycle; `status` remains for wire compatibility. */
  enrollment_status?: "pending" | "active" | "revoked";
  status: "pending" | "active" | "revoked";
};

function shouldRecordReadyConnection(
  device: DeviceRecord,
  patch: {
    agent_version?: string;
    protocol_version: string;
    last_seen_at: string;
    enforce_workspace?: boolean;
  },
): boolean {
  if (
    (patch.agent_version !== undefined && patch.agent_version !== device.agent_version) ||
    patch.protocol_version !== device.protocol_version ||
    (patch.enforce_workspace !== undefined &&
      patch.enforce_workspace !== device.enforce_workspace)
  ) {
    return true;
  }
  const previous = device.last_seen_at ? Date.parse(device.last_seen_at) : NaN;
  const observed = Date.parse(patch.last_seen_at);
  return !Number.isFinite(previous) || !Number.isFinite(observed) ||
    observed - previous >= DEVICE_READY_WRITE_INTERVAL_MS;
}

export type OAuthClientRecord = {
  client_id: string;
  tenant_id: string;
  client_name: string;
  redirect_uris: string[];
  created_at: string;
};

export type AuthCodeRecord = {
  code: string;
  client_id: string;
  principal_id: string;
  redirect_uri: string;
  scope: string;
  code_challenge: string;
  code_challenge_method: string;
  expires_at: number;
  used: boolean;
};

export type DeviceCodeRecord = {
  device_code: string;
  user_code: string;
  client_id: string;
  scope: string;
  verification_uri: string;
  interval_sec: number;
  expires_at: number;
  status: "pending" | "approved" | "denied" | "expired" | "consumed";
  principal_id?: string;
  last_polled_at?: number;
};

export type DeviceVerificationTransaction = {
  id: string;
  csrf_hash: string;
  user_code: string;
  principal_id: string;
  client_id: string;
  scope: string;
  expires_at: number;
  consumed: boolean;
};

/** One-time OAuth authorize consent transaction (GET form → POST decision). */
export type AuthorizeTransaction = {
  id: string;
  csrf_hash: string;
  principal_id: string;
  tenant_id: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  code_challenge: string;
  code_challenge_method: string;
  expires_at: number;
  consumed: boolean;
};

export type DeviceCredentialRecord = {
  device_id: string;
  tenant_id: string;
  principal_id: string;
  role: "agent";
  expires_at: number;
  revoked: boolean;
};

export type EnrollmentChallenge = {
  id: string;
  device_id: string;
  nonce: string;
  message: string;
  expires_at: string;
  consumed: boolean;
};

export type GrantRecord = {
  id: string;
  tenant_id: string;
  principal_id: string;
  capability: string;
  resource?: string;
  expires_at?: string;
  created_at: string;
};

export type AuditEvent = {
  id: string;
  tenant_id: string;
  principal_id?: string;
  device_id?: string;
  kind: string;
  summary: string;
  created_at: string;
  meta?: Record<string, unknown>;
};

export type PrincipalRecord = {
  id: string;
  tenant_id: string;
  kind: string;
  display_name: string;
  /** Server-owned, positive, monotonic OAuth credential epoch. */
  credential_generation: number;
  created_at: string;
};

export type OwnerPasskeyRecord = {
  credential_id: string;
  principal_id: string;
  webauthn_user_id: string;
  public_key: Uint8Array;
  counter: number;
  transports: string[];
  device_type: "singleDevice" | "multiDevice";
  backed_up: boolean;
  created_at: string;
  last_used_at?: string;
};

export type OwnerAuthChallenge = {
  id: string;
  kind: "register" | "authenticate";
  challenge: string;
  webauthn_user_id?: string;
  return_to: string;
  expires_at: number;
  created_at: string;
};

/** Cloud authority for a device-local workspace registration (E4).
 *
 * The path itself deliberately remains on the device.  The control plane owns
 * only the tenancy, device binding, owner and monotonically increasing version
 * that must be included in every exact-action binding.
 */
export type WorkspaceRecord = {
  workspace_id: string;
  tenant_id: string;
  device_id: string;
  owner_principal_id: string;
  version: number;
  /** Opaque Agent mapping generation. Paths and labels never leave the device. */
  local_generation?: string;
  active: boolean;
  created_at: string;
  updated_at: string;
};

function workspaceStoreKey(deviceId: string, workspaceId: string): string {
  return `${deviceId}\0${workspaceId}`;
}

function workspaceMemberStoreKey(
  deviceId: string,
  workspaceId: string,
  principalId: string,
): string {
  return `${deviceId}\0${workspaceId}\0${principalId}`;
}

export type AdvertisedWorkspaceRegistration = {
  id: string;
  generation: string;
};

function validateAdvertisedWorkspaces(
  workspaces: AdvertisedWorkspaceRegistration[],
): AdvertisedWorkspaceRegistration[] {
  if (workspaces.length < 1 || workspaces.length > 64) {
    throw new Error("invalid_workspace_registry");
  }
  const ids = new Set<string>();
  const validated: AdvertisedWorkspaceRegistration[] = [];
  for (const workspace of workspaces) {
    const id = workspace?.id;
    const generation = workspace?.generation;
    if (
      typeof id !== "string" ||
      id.length > 128 ||
      !/^ws_[A-Za-z0-9_-]*$/.test(id) ||
      typeof generation !== "string" ||
      !/^wsg_[a-f0-9]{32}$/.test(generation) ||
      ids.has(id)
    ) {
      throw new Error("invalid_workspace_registry");
    }
    ids.add(id);
    validated.push({ id, generation });
  }
  if (!ids.has("ws_default")) throw new Error("invalid_workspace_registry");
  return validated.sort((a, b) => a.id.localeCompare(b.id));
}

/** Authoritative MCP operation row (D1 / Memory). Isolate Maps are cache only. */
export type McpOperationRecord = {
  operation_id: string;
  tenant_id: string;
  principal_id: string;
  device_id?: string;
  tool: string;
  status: string;
  summary: string;
  data: Record<string, unknown>;
  truncated: boolean;
  next_cursor: string | null;
  approval_required: boolean;
  approval_url?: string;
  approval_id?: string;
  session_id?: string | null;
  warnings: string[];
  correlation_id?: string;
  /** Server-computed SHA-256 of the canonical authorized action (E3). */
  payload_hash?: string | null;
  /** Client/server idempotency key bound to payload_hash. */
  idempotency_key?: string | null;
  workspace_id?: string | null;
  /** ISO expiry bound into the authorized action. */
  expires_at?: string | null;
  /** Monotonic claim generation for prepare/claim/dispatch. */
  claim_version?: number;
  /** Canonical action JSON used to compute payload_hash. */
  action?: Record<string, unknown> | null;
  policy_authority: "ownmesh_device";
  created_at: string;
  updated_at: string;
};

/** One-time CSRF-bound human approval for an MCP operation. */
export type McpApprovalTransaction = {
  id: string;
  csrf_hash: string;
  operation_id: string;
  principal_id: string;
  tenant_id: string;
  device_id?: string;
  expires_at: number;
  consumed: boolean;
  decision?: "approve" | "deny";
  created_at: string;
};

/** Durable approval decision outbox — survives delivery retries; CAS only after deliver. */
/**
 * Stale delivering-claim recovery lease for mcp_approval_outbox.
 * Live claims cannot be stolen before this elapses; expired delivering rows
 * may be reclaimed for retry after a crashed/hung delivery attempt.
 */
export const MCP_APPROVAL_OUTBOX_CLAIM_LEASE_MS = 30_000;

/** Per-tenant durable MCP operation budgets (D1 / Memory). */
/** Default Worker `vars.MCP_OPS_MAX_PER_TENANT` when the env var is absent or invalid. */
export const MCP_OPS_MAX_PER_TENANT_DEFAULT = 20_000;
/** Documented env-var name; value is the deploy default, not a hard-coded cap. */
export const MCP_OPS_MAX_PER_TENANT = MCP_OPS_MAX_PER_TENANT_DEFAULT;
/** Absolute ceiling so a typo cannot unbounded-grow `mcp_operations`. */
export const MCP_OPS_MAX_PER_TENANT_HARD_CEILING = 1_000_000;
/** Warn (and surface `mcp_ops_quota_pressure`) at this fraction of the cap. */
export const MCP_OPS_QUOTA_PRESSURE_RATIO = 0.6;
export const MCP_OPS_QUOTA_PRESSURE_WARNING = "mcp_ops_quota_pressure";

export type McpOpsStoreOptions = {
  mcpOpsMaxPerTenant?: number | string | null;
};

export type McpOperationQuotaStatus = "ok" | "warn" | "critical";

export type McpOperationQuotaSnapshot = {
  rows: number;
  limit: number;
  status: McpOperationQuotaStatus;
};

/**
 * Parse `MCP_OPS_MAX_PER_TENANT` from Worker env / store options.
 * Invalid, empty, or non-positive values fail closed to the documented default.
 */
export function parseMcpOpsMaxPerTenant(raw?: number | string | null): number {
  if (raw === undefined || raw === null || raw === "") {
    return MCP_OPS_MAX_PER_TENANT_DEFAULT;
  }
  const n = typeof raw === "number" ? raw : Number(String(raw).trim());
  if (!Number.isSafeInteger(n) || n < 1) {
    return MCP_OPS_MAX_PER_TENANT_DEFAULT;
  }
  return Math.min(n, MCP_OPS_MAX_PER_TENANT_HARD_CEILING);
}

export function mcpOpsQuotaStatus(count: number, limit: number): McpOperationQuotaStatus {
  if (!(limit > 0) || !(count >= 0)) return "ok";
  if (count >= limit) return "critical";
  if (count >= Math.ceil(limit * MCP_OPS_QUOTA_PRESSURE_RATIO)) return "warn";
  return "ok";
}

export function snapshotMcpOperationQuota(count: number, limit: number): McpOperationQuotaSnapshot {
  const rows = Math.max(0, Math.trunc(count));
  const cap = Math.max(1, Math.trunc(limit));
  return { rows, limit: cap, status: mcpOpsQuotaStatus(rows, cap) };
}

function hasMcpIdempotencyReceipt(op: { idempotency_key?: string | null }): boolean {
  return typeof op.idempotency_key === "string" && op.idempotency_key.length > 0;
}
/** Hard cap on serialized client-visible operation data_json (results / metadata). */
export const MCP_OPS_MAX_DATA_JSON_BYTES = 256_000;
/**
 * Separate ceiling for the crash-safe dispatch outbox body embedded under
 * `__ownmesh_dispatch_outbox`. Must fit under the public MCP request body cap
 * (~1 MiB) with headroom for JSON framing. Never silently drop a pending body.
 */
export const MCP_OPS_MAX_DISPATCH_OUTBOX_BYTES = 900_000;
/** Terminal ops older than this may be compacted to idempotency tombstones. */
export const MCP_OPS_RESULT_TTL_MS = 7 * 24 * 60 * 60 * 1000;
/** Tombstones older than this may be hard-deleted (idempotency window closed). */
export const MCP_OPS_TOMBSTONE_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** Internal durable-outbox key — must match mcp.ts DISPATCH_OUTBOX_KEY. */
const DISPATCH_OUTBOX_DATA_KEY = "__ownmesh_dispatch_outbox";

/** Result / list / command cursor facts that must survive durable truncation. */
const DURABLE_RESULT_PRESERVE_KEYS = [
  "path",
  "encoding",
  "offset",
  "bytes",
  "returned_bytes",
  "total_bytes",
  "truncated",
  "sha256",
  "next_offset",
  "next_cursor",
  "exit_code",
  "timed_out",
  "duration_ms",
  "replayed",
  "cancelled",
  "detached",
  "pid",
  "hint",
  "signal_delivered",
  "target_operation_id",
  "stdout_truncated",
  "stderr_truncated",
  "stdout_bytes",
  "stderr_bytes",
  "total_matched",
  "entries_returned",
  "program",
  "command",
  "cwd",
  "status",
  "error",
  "code",
  "message",
  "retryable",
  "tool",
  "op",
  "capability",
  "payload_hash",
  "oauth_client_id",
  "claim_version",
  "expires_at",
  "route",
  "dispatch",
  "next",
] as const;

const MCP_OPS_TERMINAL = new Set([
  "completed",
  "failed",
  "denied",
  "cancelled",
  "device_offline",
  "tombstone",
]);

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function previewText(value: unknown, maxChars: number): string | undefined {
  if (typeof value !== "string") return undefined;
  if (value.length <= maxChars) return value;
  return `${value.slice(0, maxChars)}…`;
}

/**
 * Build a bounded, cursor-preserving stand-in when result data exceeds the
 * durable store budget. Never invent success; never drop next_offset / sha256 /
 * exit_code / list cursors when they were present.
 */
export function boundClientVisibleOperationData(
  data: Record<string, unknown>,
  originalBytes: number,
): Record<string, unknown> {
  const preserved: Record<string, unknown> = {
    truncated: true,
    durable_truncated: true,
    returned_bytes: 0,
    total_bytes: originalBytes,
    message:
      "operation result exceeded durable store budget; use range/pagination or smaller max_bytes/max_output_bytes — cursors and integrity facts are preserved when known",
  };
  for (const key of DURABLE_RESULT_PRESERVE_KEYS) {
    if (Object.prototype.hasOwnProperty.call(data, key) && data[key] !== undefined) {
      preserved[key] = data[key];
    }
  }
  // Keep short previews so operators can see *that* content existed without
  // re-running, while staying well under the durable budget.
  const contentPreview = previewText(data.content, 256);
  if (contentPreview !== undefined) preserved.content_preview = contentPreview;
  const stdoutPreview = previewText(data.stdout, 256);
  if (stdoutPreview !== undefined) preserved.stdout_preview = stdoutPreview;
  const stderrPreview = previewText(data.stderr, 256);
  if (stderrPreview !== undefined) preserved.stderr_preview = stderrPreview;
  if (Array.isArray(data.entries)) {
    preserved.entries_returned = data.entries.length;
    // Do not embed the oversized page; caller must re-list with a smaller limit.
  }
  // Prefer explicit next_cursor on the record when present in data.
  if (typeof data.next_cursor === "string") {
    preserved.next_cursor = data.next_cursor;
  }
  return preserved;
}

/**
 * Bound operation data/action JSON and mark visible truncation.
 *
 * Critical E3 invariant: a pending `__ownmesh_dispatch_outbox` body is never
 * replaced by a generic truncation object. Client-visible result bytes are
 * bounded separately; the outbox is validated against its own ceiling and
 * re-attached. Oversized outbox bodies fail closed (throw) rather than claim
 * without a redeliverable body.
 */
export function boundMcpOperationRecord(op: McpOperationRecord): McpOperationRecord {
  const next: McpOperationRecord = {
    ...op,
    data: { ...(op.data || {}) },
    warnings: [...(op.warnings || [])],
    action: op.action ? { ...op.action } : op.action,
    policy_authority: "ownmesh_device",
  };

  const outbox = Object.prototype.hasOwnProperty.call(next.data, DISPATCH_OUTBOX_DATA_KEY)
    ? next.data[DISPATCH_OUTBOX_DATA_KEY]
    : undefined;
  const clientData: Record<string, unknown> = { ...next.data };
  delete clientData[DISPATCH_OUTBOX_DATA_KEY];

  let clientJson = JSON.stringify(clientData || {});
  if (utf8Bytes(clientJson) > MCP_OPS_MAX_DATA_JSON_BYTES) {
    const originalBytes = utf8Bytes(clientJson);
    next.data = boundClientVisibleOperationData(clientData, originalBytes);
    next.truncated = true;
    if (!next.warnings.includes("durable_result_truncated")) {
      next.warnings.push("durable_result_truncated");
    }
    // Surface list/file continuation on the row when the bounded payload carries it.
    if (typeof next.data.next_cursor === "string" && !next.next_cursor) {
      next.next_cursor = next.data.next_cursor;
    }
    if (
      next.data.next_offset !== undefined &&
      next.data.next_offset !== null &&
      !next.next_cursor
    ) {
      next.next_cursor = `off_${String(next.data.next_offset)}`;
    }
    clientJson = JSON.stringify(next.data);
  } else {
    next.data = clientData;
  }

  if (outbox !== undefined) {
    const outboxJson = JSON.stringify(outbox);
    const outboxBytes = utf8Bytes(outboxJson);
    if (outboxBytes > MCP_OPS_MAX_DISPATCH_OUTBOX_BYTES) {
      throw new Error(
        `mcp_dispatch_outbox_too_large:bytes=${outboxBytes}:max=${MCP_OPS_MAX_DISPATCH_OUTBOX_BYTES}`,
      );
    }
    // Re-attach after client-data bounding so crash recovery always has the body.
    next.data = { ...next.data, [DISPATCH_OUTBOX_DATA_KEY]: outbox };
  }

  if (next.action) {
    const actionJson = JSON.stringify(next.action);
    if (utf8Bytes(actionJson) > MCP_OPS_MAX_DATA_JSON_BYTES) {
      // Action binding must stay small; drop oversized client residue rather than store it.
      next.action = {
        truncated: true,
        message: "canonical action exceeded durable store budget",
      };
    }
  }
  // Keep summary bounded too.
  if (typeof next.summary === "string" && next.summary.length > 2_000) {
    next.summary = `${next.summary.slice(0, 2_000)}…`;
  }
  return next;
}

function isTerminalMcpStatus(status: string): boolean {
  return MCP_OPS_TERMINAL.has(status);
}

function mcpOpAgeMs(op: Pick<McpOperationRecord, "updated_at" | "created_at">, now = Date.now()): number {
  const stamp = Date.parse(op.updated_at || op.created_at || "");
  if (!Number.isFinite(stamp)) return 0;
  return Math.max(0, now - stamp);
}

export type McpApprovalOutbox = {
  id: string;
  operation_id: string;
  principal_id: string;
  tenant_id: string;
  device_id?: string;
  decision: "approve" | "deny";
  correlation_id: string;
  /** pending → delivering (exclusive claim) → delivered */
  delivery_status: "pending" | "delivering" | "delivered";
  attempts: number;
  last_error?: string | null;
  created_at: string;
  delivered_at?: string | null;
  /** ISO timestamp when exclusive delivering claim was taken (lease start). */
  claimed_at?: string | null;
  /** Opaque owner token issued on each successful claim/reclaim. */
  claim_token?: string | null;
  /** Monotonic claim generation; increments on each claim/reclaim. */
  claim_version?: number;
};

export type BeginMcpApprovalOutboxResult =
  | { status: "created" | "pending_retry"; outbox: McpApprovalOutbox; tx: McpApprovalTransaction }
  | { status: "already_delivered"; outbox: McpApprovalOutbox };

export interface ControlPlaneStore {
  readonly kind: "memory" | "d1" | "sqlite";

  ensureBootstrap(): Promise<void>;

  /**
   * True when the tenant is provisioned and may be referenced by principals.
   * Used by OAuth handlers to fail closed for AUTH_PROVIDER claims whose
   * tenant_id was never provisioned (avoids FK 500 on principals INSERT).
   * Does not create tenants.
   */
  tenantExists(tenantId: string): Promise<boolean>;

  putClient(client: OAuthClientRecord): Promise<void>;
  getClient(clientId: string): Promise<OAuthClientRecord | null>;

  listOwnerPasskeys(): Promise<OwnerPasskeyRecord[]>;
  getOwnerPasskey(credentialId: string): Promise<OwnerPasskeyRecord | null>;
  putInitialOwnerPasskey(passkey: OwnerPasskeyRecord): Promise<boolean>;
  updateOwnerPasskeyUsage(
    credentialId: string,
    expectedCounter: number,
    nextCounter: number,
    deviceType: "singleDevice" | "multiDevice",
    backedUp: boolean,
  ): Promise<boolean>;
  putOwnerAuthChallenge(challenge: OwnerAuthChallenge): Promise<boolean>;
  takeOwnerAuthChallenge(
    id: string,
    kind: OwnerAuthChallenge["kind"],
  ): Promise<OwnerAuthChallenge | null>;

  ensurePrincipal(
    id: string,
    displayName: string,
    kind?: string,
    tenantId?: string,
  ): Promise<PrincipalRecord>;
  getPrincipal(id: string): Promise<PrincipalRecord | null>;
  /** Advance the server-owned OAuth credential epoch. Never caller supplied. */
  advancePrincipalCredentialGeneration(id: string): Promise<number | null>;

  putAuthCode(code: AuthCodeRecord): Promise<void>;
  takeAuthCode(code: string): Promise<AuthCodeRecord | null>;

  issueTokens(
    clientId: string,
    principal: string,
    scope: string,
    family?: string,
    ttlMs?: number,
    refreshTtlMs?: number,
  ): Promise<TokenRecord>;
  getAccess(token: string): Promise<TokenRecord | null>;
  rotateRefresh(refreshToken: string): Promise<
    | { ok: true; token: TokenRecord }
    | { ok: false; error: "invalid_grant" | "reuse"; description?: string }
  >;
  revokeToken(token: string): Promise<void>;
  /**
   * Look up access or refresh token for revoke audit attribution.
   * Returns tenant/principal/client when the token is known, else null.
   * Does not require the token to still be active (revoked/expired may match).
   */
  lookupRevocableToken(token: string): Promise<RevocableTokenMeta | null>;

  putDeviceCode(rec: DeviceCodeRecord): Promise<void>;
  getDeviceCode(deviceCode: string): Promise<DeviceCodeRecord | null>;
  getDeviceCodeByUserCode(userCode: string): Promise<DeviceCodeRecord | null>;
  approveDeviceCode(userCode: string, principalId: string): Promise<boolean>;
  consumeApprovedDeviceCode(deviceCode: string, clientId: string): Promise<DeviceCodeRecord | null>;
  markDeviceCodePolled(deviceCode: string): Promise<void>;
  putDeviceVerificationTransaction(tx: DeviceVerificationTransaction): Promise<void>;
  consumeDeviceVerificationTransaction(
    id: string,
    csrfHash: string,
    principalId: string,
    decision?: "approve" | "deny",
  ): Promise<DeviceVerificationTransaction | null>;

  putAuthorizeTransaction(tx: AuthorizeTransaction): Promise<void>;
  consumeAuthorizeTransaction(
    id: string,
    csrfHash: string,
    principalId: string,
  ): Promise<AuthorizeTransaction | null>;

  putDevice(device: DeviceRecord): Promise<void>;
  getDevice(id: string): Promise<DeviceRecord | null>;
  listDevices(principalId: string): Promise<DeviceRecord[]>;
  /**
   * Atomically update display metadata only when the device belongs to the
   * principal and is not revoked. A null result deliberately does not reveal
   * whether the id is missing, foreign-owned, or revoked.
   */
  updateDeviceMetadata(
    id: string,
    principalId: string,
    patch: { name?: string; labels?: string[] },
  ): Promise<DeviceRecord | null>;
  /**
   * Record a completed authenticated Agent handshake. This is deliberately
   * connection-scoped (not heartbeat-scoped) and time-throttled when metadata
   * is unchanged, avoiding a D1 write stream. The caller has already bound
   * the live socket to this device credential; this method still refuses
   * inactive or revoked devices.
   */
  recordDeviceReadyConnection(
    id: string,
    patch: {
      agent_version?: string;
      protocol_version: string;
      last_seen_at: string;
      enforce_workspace?: boolean;
    },
  ): Promise<DeviceRecord | null>;
  revokeDevice(id: string, principalId: string): Promise<boolean>;
  activateDeviceWithChallenge(deviceId: string, challengeId: string): Promise<boolean>;
  activateDeviceAndIssueCredential(deviceId: string, challengeId: string, ttlMs?: number): Promise<{ token: string; expires_at: number } | null>;
  issueDeviceCredential(device: DeviceRecord, ttlMs?: number): Promise<{ token: string; expires_at: number }>;
  getDeviceCredential(token: string): Promise<DeviceCredentialRecord | null>;
  validateDeviceSession(authHash: string, role: "agent" | "client", deviceId: string): Promise<boolean>;

  putEnrollmentChallenge(ch: EnrollmentChallenge): Promise<void>;
  getEnrollmentChallenge(id: string): Promise<EnrollmentChallenge | null>;
  consumeEnrollmentChallenge(id: string): Promise<boolean>;

  putGrant(grant: GrantRecord): Promise<void>;
  listGrants(principalId: string): Promise<GrantRecord[]>;
  revokeGrant(id: string): Promise<void>;

  appendAudit(event: AuditEvent): Promise<void>;
  listAudit(tenantId: string, limit?: number): Promise<AuditEvent[]>;

  /** Effective per-tenant `mcp_operations` row cap (Worker env or default). */
  mcpOpsMaxPerTenant(): number;
  /**
   * Occupancy after TTL compaction. Unexpired keyed receipts are never evicted
   * here; this is a read of current rows versus the configured cap.
   */
  getMcpOperationQuota(tenantId: string): Promise<McpOperationQuotaSnapshot>;

  /**
   * Create-only MCP operation insert (authoritative).
   * Must not overwrite: conflict on existing operation_id throws
   * (`mcp_operation_exists:<id>`). Post-create changes use updateMcpOperation CAS.
   */
  putMcpOperation(op: McpOperationRecord): Promise<void>;
  getMcpOperation(operationId: string): Promise<McpOperationRecord | null>;
  getMcpOperationByCorrelation(correlationId: string): Promise<McpOperationRecord | null>;
  /** Bounded newest-first lookup with all ownership facts fixed by the caller. */
  listMcpOperations(opts: {
    tenantId: string;
    principalId: string;
    tool: string;
    limit?: number;
  }): Promise<McpOperationRecord[]>;
  /**
   * Lookup by principal/tenant/device/idempotency_key for exact-action reuse.
   * Newest row wins when multiple historical rows exist.
   */
  getMcpOperationByIdempotency(opts: {
    principalId: string;
    tenantId: string;
    deviceId: string;
    idempotencyKey: string;
  }): Promise<McpOperationRecord | null>;
  /**
   * Atomic create-or-return for an idempotency-bound MCP operation.
   * Exactly one caller wins the insert for a given
   * (principal, tenant, device, idempotency_key). Losers reload the winner
   * and must compare action binding before any device route.
   * When `idempotency_key` is null/empty, behaves as create-only putMcpOperation.
   */
  claimMcpOperationByIdempotency(op: McpOperationRecord): Promise<
    | { outcome: "created"; op: McpOperationRecord }
    | { outcome: "existing"; op: McpOperationRecord }
  >;
  /**
   * Patch MCP operation. When `fromStatuses` is set, CAS: only updates if current
   * status is in that set (returns null on miss / CAS loss).
   */
  updateMcpOperation(
    operationId: string,
    patch: Partial<McpOperationRecord>,
    fromStatuses?: string[],
    /** Exact durable data snapshot required for a compare-and-swap update. */
    expectedData?: Record<string, unknown>,
  ): Promise<McpOperationRecord | null>;

  putMcpApprovalTransaction(tx: McpApprovalTransaction): Promise<void>;
  /**
   * Atomic one-time consume of an approval transaction bound to principal + CSRF.
   * Returns null when missing, expired, wrong csrf/principal, or already consumed.
   */
  consumeMcpApprovalTransaction(
    id: string,
    csrfHash: string,
    principalId: string,
    decision: "approve" | "deny",
  ): Promise<McpApprovalTransaction | null>;

  /**
   * Atomically consume one-time approval tx + insert durable outbox row (single
   * D1 batch / no consumed-without-outbox window), or resume a pending/delivering
   * outbox for the same transaction (idempotent delivery retry).
   * Returns null when tx/csrf/principal invalid. already_delivered when the
   * decision was previously delivered successfully.
   */
  beginMcpApprovalOutbox(
    id: string,
    csrfHash: string,
    principalId: string,
    decision: "approve" | "deny",
  ): Promise<BeginMcpApprovalOutboxResult | null>;

  getMcpApprovalOutbox(id: string): Promise<McpApprovalOutbox | null>;

  /**
   * Exclusive claim: pending → delivering (sets claimed_at + claim_token/version).
   * Only the claim winner may route to device. Also allows reclaim when
   * delivery_status=delivering AND the claim lease
   * (MCP_APPROVAL_OUTBOX_CLAIM_LEASE_MS) has expired. Each claim/reclaim issues
   * a fresh random claim_token and increments claim_version (invalidates prior owner).
   * Returns null when missing, live-claimed, delivered, or lost the CAS race.
   */
  claimMcpApprovalOutboxDelivery(id: string): Promise<McpApprovalOutbox | null>;

  /**
   * Release exclusive claim after failed route: delivering → pending (retryable).
   * Requires claim_token + claim_version match (claim owner only).
   * No-op on mismatch/missing credentials or when not currently delivering.
   */
  releaseMcpApprovalOutboxClaim(
    id: string,
    claimToken: string,
    claimVersion: number,
    error?: string,
  ): Promise<void>;

  /** Record a failed delivery attempt; leaves outbox pending for retry. */
  recordMcpApprovalOutboxAttempt(id: string, error?: string): Promise<void>;

  /**
   * After successful device delivery: record the delivered decision while the
   * operation remains approval_required until the authoritative device result,
   * and mark the outbox delivered (never overwrite a fast terminal result).
   * Requires delivery_status=delivering and claim owner (token+version match).
   * Exactly-once transition.
   */
  finalizeMcpApprovalDelivery(
    id: string,
    claimToken: string,
    claimVersion: number,
  ): Promise<McpOperationRecord | null>;

  /**
   * Fail-closed device gate for MCP create/poll/cancel.
   * Rejects when device missing/inactive/revoked, caller is neither owner nor
   * tenant member, or when the device has credentials and none remain valid.
   * Credential schema/query failures fail closed (never treated as no credentials).
   */
  assertDeviceOperableForMcp(
    deviceId: string,
    principalId: string,
    tenantId: string,
  ): Promise<{ ok: true } | { ok: false; error: string }>;

  /** True when principal is the device owner or an explicit tenant member. */
  canOperateDevice(
    deviceId: string,
    principalId: string,
    tenantId: string,
  ): Promise<boolean>;

  /** Upsert a tenant membership row (owner/admin/member). */
  putTenantMember(
    tenantId: string,
    principalId: string,
    role: "owner" | "admin" | "member",
  ): Promise<void>;

  isTenantMember(tenantId: string, principalId: string): Promise<boolean>;

  /** Returns the effective tenant role, if any.  Missing schema fails closed. */
  getTenantMemberRole(
    tenantId: string,
    principalId: string,
  ): Promise<"owner" | "admin" | "member" | null>;

  /** Create or update cloud workspace custody.  Only admin paths call this. */
  putWorkspace(workspace: WorkspaceRecord): Promise<void>;
  getWorkspace(deviceId: string, workspaceId: string): Promise<WorkspaceRecord | null>;
  putWorkspaceMember(deviceId: string, workspaceId: string, principalId: string): Promise<void>;
  isWorkspaceMember(deviceId: string, workspaceId: string, principalId: string): Promise<boolean>;
  /**
   * Reconcile the bounded id plus opaque-generation registry advertised by an
   * authenticated Agent. Roots never leave the device. Observed ids are scoped
   * to this exact device; absence does not deactivate a pending cloud reservation
   * that may not have reached the Agent yet. A changed generation increments the
   * exact-action version.
   */
  syncDeviceWorkspaces(
    deviceId: string,
    workspaces: AdvertisedWorkspaceRegistration[],
  ): Promise<WorkspaceRecord[]>;
  /**
   * Fail-closed workspace ACL/version gate.  Device owners and tenant
   * owners/admins administer workspaces; ordinary members require ownership
   * (future explicit per-workspace grants can be added without weakening this).
   */
  assertWorkspaceOperableForMcp(
    workspaceId: string,
    deviceId: string,
    principalId: string,
    tenantId: string,
  ): Promise<WorkspaceOperableGate>;
  /**
   * Visibility/admin gate for show/remove/retry. Pending reservations are
   * visible to custodians so activation can be polled or abandoned.
   */
  assertWorkspaceVisibleForMcp(
    workspaceId: string,
    deviceId: string,
    principalId: string,
    tenantId: string,
  ): Promise<WorkspaceOperableGate>;
  /**
   * Apply one Agent-observed opaque generation. Unlike syncDeviceWorkspaces this
   * does not require a complete registry snapshot (ws_default may be absent).
   * Inactive rows keep the last generation as a tombstone: the same value does
   * not reactivate; a later add must advertise a new generation.
   */
  observeWorkspaceGeneration(
    deviceId: string,
    workspaceId: string,
    generation: string,
  ): Promise<WorkspaceRecord | null>;
  /** Mark a cloud custody row inactive after a successful or abandoned remove. */
  deactivateWorkspace(deviceId: string, workspaceId: string): Promise<WorkspaceRecord | null>;
  /** Persist Agent-observed workspace-root enforcement independently of access_preset. */
  recordObservedWorkspaceEnforcement(
    deviceId: string,
    enforceWorkspace: boolean,
  ): Promise<DeviceRecord | null>;

  appliedMigrations(): Promise<string[]>;
  markMigration(id: string): Promise<void>;

  /**
   * Probe whether required P0 schema objects exist.
   * Never infers readiness from migration filenames alone.
   */
  schemaReadiness(): Promise<SchemaReadiness>;
}

/** Cheap structural readiness of required tables/columns/indexes (0002–0016). */
export type SchemaReadiness = {
  schema_ready: boolean;
  checks: {
    /** 0002 OAuth/device enrollment + migration ledger */
    oauth_auth_codes: boolean;
    device_codes: boolean;
    used_refresh_tokens: boolean;
    enrollment_challenges: boolean;
    schema_migrations: boolean;
    /** 0003 lifecycle state + 0015 display-only labels */
    devices_status: boolean;
    revoked_refresh_families: boolean;
    device_credentials: boolean;
    device_verification_transactions: boolean;
    /** 0004 authorize consent transactions */
    authorize_transactions: boolean;
    /** 0005 MCP ops + 0006 claimed_at + 0007 claim ownership + 0008 action binding */
    mcp_operations: boolean;
    mcp_approval_transactions: boolean;
    mcp_approval_outbox: boolean;
    /** 0012 server-owned principal OAuth credential generation */
    principals_credential_generation: boolean;
    /** 0013 built-in owner passkeys + one-time WebAuthn challenges */
    owner_passkeys: boolean;
    owner_auth_challenges: boolean;
    /** 0014 independent rolling refresh-token inactivity deadline */
    oauth_tokens_refresh_lifetime: boolean;
    /** 0016 device-scoped workspace custody (workspace ids are device-local) */
    device_workspaces: boolean;
    device_workspace_members: boolean;
  };
};

/** Objects probed by schemaReadiness (table → required columns + indexes). */
const SCHEMA_READINESS_OBJECTS: Record<
  keyof SchemaReadiness["checks"],
  { table: string; columns: string[]; indexes?: string[] }
> = {
  device_workspaces: {
    table: "device_workspaces",
    columns: [
      "workspace_id",
      "tenant_id",
      "device_id",
      "owner_principal_id",
      "version",
      "local_generation",
      "active",
      "created_at",
      "updated_at",
    ],
    indexes: ["idx_device_workspaces_tenant_device", "idx_device_workspaces_owner"],
  },
  device_workspace_members: {
    table: "device_workspace_members",
    columns: ["device_id", "workspace_id", "principal_id", "created_at"],
    indexes: ["idx_device_workspace_members_principal"],
  },
  oauth_tokens_refresh_lifetime: {
    table: "oauth_tokens",
    columns: ["refresh_expires_at"],
  },
  oauth_auth_codes: {
    table: "oauth_auth_codes",
    columns: [
      "code_hash",
      "client_id",
      "principal_id",
      "redirect_uri",
      "scope",
      "code_challenge",
      "code_challenge_method",
      "expires_at",
      "used",
      "created_at",
    ],
    indexes: ["idx_auth_codes_client"],
  },
  device_codes: {
    table: "device_codes",
    columns: [
      "device_code_hash",
      "user_code",
      "client_id",
      "scope",
      "verification_uri",
      "interval_sec",
      "expires_at",
      "status",
      "principal_id",
      "last_polled_at",
      "created_at",
    ],
    indexes: ["idx_device_codes_user"],
  },
  used_refresh_tokens: {
    table: "used_refresh_tokens",
    columns: ["refresh_token_hash", "refresh_family", "used_at"],
    indexes: ["idx_used_refresh_family"],
  },
  enrollment_challenges: {
    table: "enrollment_challenges",
    columns: [
      "id",
      "device_id",
      "nonce",
      "message",
      "expires_at",
      "consumed",
      "created_at",
    ],
    indexes: ["idx_enroll_device"],
  },
  schema_migrations: {
    table: "schema_migrations",
    columns: ["id", "applied_at"],
  },
  devices_status: { table: "devices", columns: ["status", "labels_json"] },
  revoked_refresh_families: {
    table: "revoked_refresh_families",
    columns: ["refresh_family", "detected_at"],
  },
  device_credentials: {
    table: "device_credentials",
    columns: [
      "credential_hash",
      "device_id",
      "tenant_id",
      "principal_id",
      "role",
      "expires_at",
      "revoked",
      "created_at",
    ],
    indexes: ["idx_device_credentials_device"],
  },
  device_verification_transactions: {
    table: "device_verification_transactions",
    columns: [
      "id",
      "csrf_hash",
      "user_code",
      "principal_id",
      "client_id",
      "scope",
      "expires_at",
      "consumed",
      "created_at",
    ],
    indexes: ["idx_device_verification_user"],
  },
  authorize_transactions: {
    table: "authorize_transactions",
    columns: [
      "id",
      "csrf_hash",
      "principal_id",
      "tenant_id",
      "client_id",
      "redirect_uri",
      "scope",
      "state",
      "code_challenge",
      "code_challenge_method",
      "expires_at",
      "consumed",
      "created_at",
    ],
    indexes: ["idx_authorize_tx_principal", "idx_authorize_tx_expires"],
  },
  mcp_operations: {
    table: "mcp_operations",
    columns: [
      "operation_id",
      "tenant_id",
      "principal_id",
      "device_id",
      "tool",
      "status",
      "summary",
      "data_json",
      "truncated",
      "next_cursor",
      "approval_required",
      "approval_url",
      "approval_id",
      "session_id",
      "warnings_json",
      "correlation_id",
      "payload_hash",
      "idempotency_key",
      "workspace_id",
      "expires_at",
      "claim_version",
      "action_json",
      "created_at",
      "updated_at",
    ],
    indexes: [
      "idx_mcp_ops_principal_tenant",
      "idx_mcp_ops_device",
      "idx_mcp_ops_correlation",
      "idx_mcp_ops_updated",
      "idx_mcp_ops_idempotency",
      "idx_mcp_ops_payload_hash",
      "uq_mcp_ops_idempotency",
    ],
  },
  mcp_approval_transactions: {
    table: "mcp_approval_transactions",
    columns: [
      "id",
      "csrf_hash",
      "operation_id",
      "principal_id",
      "tenant_id",
      "device_id",
      "expires_at",
      "consumed",
      "decision",
      "created_at",
    ],
    indexes: ["idx_mcp_apr_op", "idx_mcp_apr_principal", "idx_mcp_apr_expires"],
  },
  mcp_approval_outbox: {
    table: "mcp_approval_outbox",
    columns: [
      "id",
      "operation_id",
      "principal_id",
      "tenant_id",
      "device_id",
      "decision",
      "correlation_id",
      "delivery_status",
      "attempts",
      "last_error",
      "created_at",
      "delivered_at",
      "claimed_at",
      "claim_token",
      "claim_version",
    ],
    indexes: ["idx_mcp_outbox_op", "idx_mcp_outbox_status"],
  },
  principals_credential_generation: {
    table: "principals",
    columns: ["id", "credential_generation"],
  },
  owner_passkeys: {
    table: "owner_passkeys",
    columns: [
      "credential_id",
      "principal_id",
      "webauthn_user_id",
      "public_key",
      "counter",
      "transports_json",
      "device_type",
      "backed_up",
      "created_at",
      "last_used_at",
    ],
    indexes: ["idx_owner_passkeys_principal"],
  },
  owner_auth_challenges: {
    table: "owner_auth_challenges",
    columns: [
      "id",
      "kind",
      "challenge",
      "webauthn_user_id",
      "return_to",
      "expires_at",
      "created_at",
    ],
    indexes: ["idx_owner_auth_challenges_expiry"],
  },
};

const DEFAULT_TENANT = "ten_default";

// ---------------------------------------------------------------------------
// Memory store (explicit unit/integration test injection only)
// ---------------------------------------------------------------------------

export class MemoryStore implements ControlPlaneStore {
  readonly kind = "memory" as const;
  private readonly mcpOpsLimit: number;
  clients = new Map<string, OAuthClientRecord>();
  ownerPasskeys = new Map<string, OwnerPasskeyRecord>();
  ownerAuthChallenges = new Map<string, OwnerAuthChallenge>();
  principals = new Map<string, PrincipalRecord>();
  tokensByAccess = new Map<string, TokenRecord>();
  accessByRefresh = new Map<string, string>();
  usedRefresh = new Map<string, string>(); // refresh -> family
  compromisedRefreshFamilies = new Set<string>();
  authCodes = new Map<string, AuthCodeRecord>();
  deviceCodes = new Map<string, DeviceCodeRecord>();
  deviceByUserCode = new Map<string, string>();
  devices = new Map<string, DeviceRecord>();
  challenges = new Map<string, EnrollmentChallenge>();
  verificationTransactions = new Map<string, DeviceVerificationTransaction>();
  authorizeTransactions = new Map<string, AuthorizeTransaction>();
  deviceCredentials = new Map<string, DeviceCredentialRecord>();
  mcpOperations = new Map<string, McpOperationRecord>();
  mcpApprovalTransactions = new Map<string, McpApprovalTransaction>();
  mcpApprovalOutbox = new Map<string, McpApprovalOutbox>();
  grants = new Map<string, GrantRecord>();
  /** key = `${tenant_id}\0${principal_id}` */
  tenantMembers = new Map<string, { tenant_id: string; principal_id: string; role: "owner" | "admin" | "member"; created_at: string }>();
  workspaces = new Map<string, WorkspaceRecord>();
  workspaceMembers = new Set<string>();
  audits: AuditEvent[] = [];
  migrations = new Set<string>();

  constructor(opts?: McpOpsStoreOptions) {
    this.mcpOpsLimit = parseMcpOpsMaxPerTenant(opts?.mcpOpsMaxPerTenant);
  }

  mcpOpsMaxPerTenant(): number {
    return this.mcpOpsLimit;
  }

  async getMcpOperationQuota(tenantId: string): Promise<McpOperationQuotaSnapshot> {
    this.compactMcpOperations(tenantId);
    const rows = [...this.mcpOperations.values()].filter((o) => o.tenant_id === tenantId).length;
    return snapshotMcpOperationQuota(rows, this.mcpOpsLimit);
  }

  async ensureBootstrap(): Promise<void> {
    if (!this.principals.has("prin_dev")) {
      this.principals.set("prin_dev", {
        id: "prin_dev",
        tenant_id: DEFAULT_TENANT,
        kind: "human",
        display_name: "Dev User",
        credential_generation: 1,
        created_at: nowIso(),
      });
    }
  }

  /**
   * Memory path: DEFAULT_TENANT is always provisioned; any tenant already
   * referenced by a seeded principal also counts. Does not auto-create.
   * ensurePrincipal remains permissive for unprovisioned tenants.
   */
  async tenantExists(tenantId: string): Promise<boolean> {
    if (!tenantId) return false;
    if (tenantId === DEFAULT_TENANT) return true;
    for (const p of this.principals.values()) {
      if (p.tenant_id === tenantId) return true;
    }
    return false;
  }

  async putClient(client: OAuthClientRecord): Promise<void> {
    this.clients.set(client.client_id, client);
  }
  async getClient(clientId: string): Promise<OAuthClientRecord | null> {
    return this.clients.get(clientId) || null;
  }

  async listOwnerPasskeys(): Promise<OwnerPasskeyRecord[]> {
    return [...this.ownerPasskeys.values()].map((passkey) => ({
      ...passkey,
      public_key: passkey.public_key.slice(),
      transports: [...passkey.transports],
    }));
  }

  async getOwnerPasskey(credentialId: string): Promise<OwnerPasskeyRecord | null> {
    const passkey = this.ownerPasskeys.get(credentialId);
    return passkey
      ? { ...passkey, public_key: passkey.public_key.slice(), transports: [...passkey.transports] }
      : null;
  }

  async putInitialOwnerPasskey(passkey: OwnerPasskeyRecord): Promise<boolean> {
    if (this.ownerPasskeys.size !== 0 || this.ownerPasskeys.has(passkey.credential_id)) return false;
    this.ownerPasskeys.set(passkey.credential_id, {
      ...passkey,
      public_key: passkey.public_key.slice(),
      transports: [...passkey.transports],
    });
    return true;
  }

  async updateOwnerPasskeyUsage(
    credentialId: string,
    expectedCounter: number,
    nextCounter: number,
    deviceType: "singleDevice" | "multiDevice",
    backedUp: boolean,
  ): Promise<boolean> {
    const passkey = this.ownerPasskeys.get(credentialId);
    if (!passkey || passkey.counter !== expectedCounter) return false;
    passkey.counter = nextCounter;
    passkey.device_type = deviceType;
    passkey.backed_up = backedUp;
    passkey.last_used_at = nowIso();
    return true;
  }

  async putOwnerAuthChallenge(challenge: OwnerAuthChallenge): Promise<boolean> {
    const now = Date.now();
    for (const [id, item] of this.ownerAuthChallenges) {
      if (item.expires_at <= now) this.ownerAuthChallenges.delete(id);
    }
    const existing = this.ownerAuthChallenges.get(challenge.id);
    if (existing && existing.expires_at > now) return false;
    if (this.ownerAuthChallenges.size >= 64) return false;
    this.ownerAuthChallenges.set(challenge.id, { ...challenge });
    return true;
  }

  async takeOwnerAuthChallenge(
    id: string,
    kind: OwnerAuthChallenge["kind"],
  ): Promise<OwnerAuthChallenge | null> {
    const challenge = this.ownerAuthChallenges.get(id);
    if (!challenge || challenge.kind !== kind || challenge.expires_at <= Date.now()) return null;
    this.ownerAuthChallenges.delete(id);
    return { ...challenge };
  }

  async ensurePrincipal(
    id: string,
    displayName: string,
    kind = "human",
    tenantId = DEFAULT_TENANT,
  ): Promise<PrincipalRecord> {
    const existing = this.principals.get(id);
    if (existing) {
      if (existing.tenant_id !== tenantId) throw new Error("principal tenant mismatch");
      return existing;
    }
    const p: PrincipalRecord = {
      id,
      tenant_id: tenantId,
      kind,
      display_name: displayName,
      credential_generation: 1,
      created_at: nowIso(),
    };
    this.principals.set(id, p);
    return p;
  }
  async getPrincipal(id: string): Promise<PrincipalRecord | null> {
    return this.principals.get(id) || null;
  }
  async advancePrincipalCredentialGeneration(id: string): Promise<number | null> {
    const principal = this.principals.get(id);
    if (!principal) return null;
    const next = principal.credential_generation + 1;
    if (!Number.isSafeInteger(next) || next < 1) throw new Error("principal credential generation overflow");
    principal.credential_generation = next;
    this.principals.set(id, principal);
    return next;
  }

  async putAuthCode(code: AuthCodeRecord): Promise<void> {
    this.authCodes.set(code.code, { ...code });
  }
  async takeAuthCode(code: string): Promise<AuthCodeRecord | null> {
    const rec = this.authCodes.get(code);
    if (!rec || rec.used) return null;
    if (Date.now() > rec.expires_at) return null;
    rec.used = true;
    this.authCodes.set(code, rec);
    return { ...rec };
  }

  async issueTokens(
    clientId: string,
    principal: string,
    scope: string,
    family?: string,
    ttlMs = ACCESS_TOKEN_TTL_MS,
    refreshTtlMs = REFRESH_TOKEN_IDLE_TTL_MS,
  ): Promise<TokenRecord> {
    const principalRecord = (await this.getPrincipal(principal)) || await this.ensurePrincipal(principal, principal);
    const access = randomToken("atk_");
    const refresh = randomToken("rtk_");
    const rec: TokenRecord = {
      access_token: access,
      refresh_token: refresh,
      client_id: clientId,
      scope,
      principal,
      expires_at: Date.now() + ttlMs,
      refresh_expires_at: Date.now() + refreshTtlMs,
      revoked: family ? this.compromisedRefreshFamilies.has(family) : false,
      refresh_family: family || randomToken("fam_"),
      refresh_used: false,
      tenant_id: principalRecord.tenant_id,
    };
    this.tokensByAccess.set(access, rec);
    if (!rec.revoked) this.accessByRefresh.set(refresh, access);
    return rec;
  }

  async getAccess(token: string): Promise<TokenRecord | null> {
    const rec = this.tokensByAccess.get(token);
    if (!rec || rec.revoked) return null;
    if (Date.now() > rec.expires_at) return null;
    return rec;
  }

  async rotateRefresh(refreshToken: string): Promise<
    | { ok: true; token: TokenRecord }
    | { ok: false; error: "invalid_grant" | "reuse"; description?: string }
  > {
    const now = Date.now();
    // Locate the token row that still carries this refresh value (including used/revoked).
    let prior: TokenRecord | undefined;
    for (const candidate of this.tokensByAccess.values()) {
      if (candidate.refresh_token === refreshToken) {
        prior = candidate;
        break;
      }
    }
    // Expired refresh is always invalid_grant (reuse detection is in-window only).
    if (prior && now > prior.refresh_expires_at) {
      return { ok: false, error: "invalid_grant" };
    }

    const usedFamily = this.usedRefresh.get(refreshToken);
    if (usedFamily) {
      // Reuse only while the prior refresh credential is still within its inactivity window.
      if (!prior || now > prior.refresh_expires_at) {
        return { ok: false, error: "invalid_grant" };
      }
      this.compromisedRefreshFamilies.add(usedFamily);
      for (const [k, v] of this.tokensByAccess) {
        if (v.refresh_family === usedFamily) {
          v.revoked = true;
          this.tokensByAccess.set(k, v);
        }
      }
      await this.advancePrincipalCredentialGeneration(prior.principal);
      return {
        ok: false,
        error: "reuse",
        description: "refresh token reuse detected",
      };
    }

    const access = this.accessByRefresh.get(refreshToken);
    if (!access) return { ok: false, error: "invalid_grant" };
    const old = this.tokensByAccess.get(access);
    if (!old || old.revoked) return { ok: false, error: "invalid_grant" };
    if (now > old.refresh_expires_at) return { ok: false, error: "invalid_grant" };
    if (old.refresh_used) {
      this.compromisedRefreshFamilies.add(old.refresh_family);
      for (const [k, v] of this.tokensByAccess) {
        if (v.refresh_family === old.refresh_family) {
          v.revoked = true;
          this.tokensByAccess.set(k, v);
        }
      }
      await this.advancePrincipalCredentialGeneration(old.principal);
      return {
        ok: false,
        error: "reuse",
        description: "refresh token reuse detected",
      };
    }
    old.refresh_used = true;
    old.revoked = true;
    this.tokensByAccess.set(access, old);
    this.accessByRefresh.delete(refreshToken);
    this.usedRefresh.set(refreshToken, old.refresh_family);
    await this.advancePrincipalCredentialGeneration(old.principal);
    const next = await this.issueTokens(
      old.client_id,
      old.principal,
      old.scope,
      old.refresh_family,
    );
    return { ok: true, token: next };
  }

  async revokeToken(token: string): Promise<void> {
    if (token.startsWith("rtk_")) {
      const access = this.accessByRefresh.get(token);
      if (access) {
        const rec = this.tokensByAccess.get(access);
        if (rec && !rec.revoked) {
          rec.revoked = true;
          this.tokensByAccess.set(access, rec);
          await this.advancePrincipalCredentialGeneration(rec.principal);
        }
        this.accessByRefresh.delete(token);
      }
      return;
    }
    const rec = this.tokensByAccess.get(token);
    if (rec && !rec.revoked) {
      rec.revoked = true;
      this.tokensByAccess.set(token, rec);
      this.accessByRefresh.delete(rec.refresh_token);
      await this.advancePrincipalCredentialGeneration(rec.principal);
    }
  }

  async lookupRevocableToken(token: string): Promise<RevocableTokenMeta | null> {
    if (!token) return null;
    let rec = this.tokensByAccess.get(token);
    if (!rec) {
      const access = this.accessByRefresh.get(token);
      if (access) rec = this.tokensByAccess.get(access);
    }
    // Also match refresh value still present on a stored access record
    // (e.g. after access-side revoke removed the refresh index entry).
    if (!rec) {
      for (const candidate of this.tokensByAccess.values()) {
        if (candidate.refresh_token === token) {
          rec = candidate;
          break;
        }
      }
    }
    if (!rec) return null;
    return {
      tenant_id: rec.tenant_id,
      principal_id: rec.principal,
      client_id: rec.client_id,
    };
  }

  async putDeviceCode(rec: DeviceCodeRecord): Promise<void> {
    this.deviceCodes.set(rec.device_code, { ...rec });
    this.deviceByUserCode.set(rec.user_code.toUpperCase(), rec.device_code);
  }
  async getDeviceCode(deviceCode: string): Promise<DeviceCodeRecord | null> {
    const rec = this.deviceCodes.get(deviceCode);
    if (!rec) return null;
    if (Date.now() > rec.expires_at && rec.status === "pending") {
      rec.status = "expired";
      this.deviceCodes.set(deviceCode, rec);
    }
    return { ...rec };
  }
  async getDeviceCodeByUserCode(
    userCode: string,
  ): Promise<DeviceCodeRecord | null> {
    const dc = this.deviceByUserCode.get(userCode.toUpperCase());
    if (!dc) return null;
    return this.getDeviceCode(dc);
  }
  async approveDeviceCode(
    userCode: string,
    principalId: string,
  ): Promise<boolean> {
    const rec = await this.getDeviceCodeByUserCode(userCode);
    if (!rec || rec.status !== "pending") return false;
    rec.status = "approved";
    rec.principal_id = principalId;
    this.deviceCodes.set(rec.device_code, rec);
    return true;
  }
  async consumeApprovedDeviceCode(deviceCode: string, clientId: string): Promise<DeviceCodeRecord | null> {
    const rec = this.deviceCodes.get(deviceCode);
    if (!rec || rec.status !== "approved" || rec.client_id !== clientId || Date.now() > rec.expires_at) return null;
    rec.status = "consumed";
    this.deviceCodes.set(deviceCode, rec);
    return { ...rec };
  }
  async markDeviceCodePolled(deviceCode: string): Promise<void> {
    const rec = this.deviceCodes.get(deviceCode);
    if (rec) {
      rec.last_polled_at = Date.now();
      this.deviceCodes.set(deviceCode, rec);
    }
  }
  async putDeviceVerificationTransaction(tx: DeviceVerificationTransaction): Promise<void> {
    this.verificationTransactions.set(tx.id, { ...tx });
  }
  async consumeDeviceVerificationTransaction(
    id: string,
    csrfHash: string,
    principalId: string,
    decision: "approve" | "deny" = "approve",
  ): Promise<DeviceVerificationTransaction | null> {
    const tx = this.verificationTransactions.get(id);
    if (!tx || tx.consumed || tx.csrf_hash !== csrfHash || tx.principal_id !== principalId || Date.now() > tx.expires_at) return null;
    const dc = await this.getDeviceCodeByUserCode(tx.user_code);
    if (!dc || dc.status !== "pending" || dc.client_id !== tx.client_id || dc.scope !== tx.scope || Date.now() > dc.expires_at) return null;
    tx.consumed = true;
    this.verificationTransactions.set(id, tx);
    dc.status = decision === "approve" ? "approved" : "denied";
    dc.principal_id = decision === "approve" ? principalId : undefined;
    this.deviceCodes.set(dc.device_code, dc);
    return { ...tx };
  }

  async putAuthorizeTransaction(tx: AuthorizeTransaction): Promise<void> {
    this.authorizeTransactions.set(tx.id, { ...tx });
  }
  async consumeAuthorizeTransaction(id: string, csrfHash: string, principalId: string): Promise<AuthorizeTransaction | null> {
    const tx = this.authorizeTransactions.get(id);
    if (!tx || tx.consumed || tx.csrf_hash !== csrfHash || tx.principal_id !== principalId || Date.now() > tx.expires_at) return null;
    tx.consumed = true;
    this.authorizeTransactions.set(id, tx);
    return { ...tx };
  }

  async putDevice(device: DeviceRecord): Promise<void> {
    this.devices.set(device.id, {
      ...device,
      labels: [...(device.labels ?? [])],
    });
  }
  async getDevice(id: string): Promise<DeviceRecord | null> {
    const d = this.devices.get(id);
    if (!d) return null;
    return hydrateDevice(d);
  }
  async listDevices(principalId: string): Promise<DeviceRecord[]> {
    return [...this.devices.values()]
      .filter((d) => d.principal_id === principalId && !d.revoked)
      .map(hydrateDevice);
  }
  async updateDeviceMetadata(
    id: string,
    principalId: string,
    patch: { name?: string; labels?: string[] },
  ): Promise<DeviceRecord | null> {
    const device = this.devices.get(id);
    if (!device || device.principal_id !== principalId || device.revoked) return null;
    const updated: DeviceRecord = {
      ...device,
      ...(patch.name !== undefined ? { name: patch.name } : {}),
      ...(patch.labels !== undefined ? { labels: [...patch.labels] } : {}),
    };
    this.devices.set(id, updated);
    return hydrateDevice(updated);
  }
  async recordDeviceReadyConnection(
    id: string,
    patch: {
      agent_version?: string;
      protocol_version: string;
      last_seen_at: string;
      enforce_workspace?: boolean;
    },
  ): Promise<DeviceRecord | null> {
    const device = this.devices.get(id);
    if (!device || device.revoked || device.status !== "active") return null;
    if (!shouldRecordReadyConnection(device, patch)) return hydrateDevice(device);
    const isNewer = !device.last_seen_at || patch.last_seen_at > device.last_seen_at;
    const updated: DeviceRecord = {
      ...device,
      ...(isNewer && patch.agent_version ? { agent_version: patch.agent_version } : {}),
      ...(isNewer ? { protocol_version: patch.protocol_version } : {}),
      ...(patch.enforce_workspace !== undefined
        ? { enforce_workspace: patch.enforce_workspace }
        : {}),
      // The timestamp is server-generated. Keep it monotonic if two accepted
      // connections finish out of order.
      last_seen_at:
        isNewer
          ? patch.last_seen_at
          : device.last_seen_at,
    };
    this.devices.set(id, updated);
    return hydrateDevice(updated);
  }
  async revokeDevice(id: string, principalId: string): Promise<boolean> {
    const d = this.devices.get(id);
    if (!d || d.principal_id !== principalId) return false;
    d.revoked = true;
    d.status = "revoked";
    this.devices.set(id, d);
    for (const rec of this.deviceCredentials.values()) if (rec.device_id === id) rec.revoked = true;
    return true;
  }
  async activateDeviceWithChallenge(deviceId: string, challengeId: string): Promise<boolean> {
    const d = this.devices.get(deviceId);
    const ch = this.challenges.get(challengeId);
    if (!d || d.status !== "pending" || !ch || ch.device_id !== deviceId || ch.consumed || Date.now() > Date.parse(ch.expires_at)) return false;
    ch.consumed = true;
    d.status = "active";
    this.challenges.set(challengeId, ch);
    this.devices.set(deviceId, d);
    return true;
  }
  async activateDeviceAndIssueCredential(deviceId: string, challengeId: string, ttlMs = 30 * 24 * 60 * 60 * 1000): Promise<{ token: string; expires_at: number } | null> {
    if (!(await this.activateDeviceWithChallenge(deviceId, challengeId))) return null;
    const device = await this.getDevice(deviceId);
    return device ? this.issueDeviceCredential(device, ttlMs) : null;
  }
  async issueDeviceCredential(device: DeviceRecord, ttlMs = 30 * 24 * 60 * 60 * 1000): Promise<{ token: string; expires_at: number }> {
    if (device.revoked || device.status !== "active") throw new Error("device must be active before credential issuance");
    const token = randomToken("dcred_");
    const expires_at = Date.now() + ttlMs;
    this.deviceCredentials.set(await sha256Hex(token), {
      device_id: device.id, tenant_id: device.tenant_id, principal_id: device.principal_id,
      role: "agent", expires_at, revoked: false,
    });
    return { token, expires_at };
  }
  async getDeviceCredential(token: string): Promise<DeviceCredentialRecord | null> {
    const rec = this.deviceCredentials.get(await sha256Hex(token));
    if (!rec || rec.revoked || Date.now() > rec.expires_at) return null;
    return { ...rec };
  }
  async validateDeviceSession(authHash: string, role: "agent" | "client", deviceId: string): Promise<boolean> {
    const device = this.devices.get(deviceId);
    if (!device || device.revoked || device.status !== "active") return false;
    if (role === "agent") {
      const credential = this.deviceCredentials.get(authHash);
      return Boolean(credential && !credential.revoked && credential.device_id === deviceId && credential.expires_at > Date.now());
    }
    for (const [token, record] of this.tokensByAccess) {
      if (await sha256Hex(token) === authHash) {
        return !record.revoked && record.expires_at > Date.now() && record.principal === device.principal_id && record.tenant_id === device.tenant_id;
      }
    }
    return false;
  }

  async putEnrollmentChallenge(ch: EnrollmentChallenge): Promise<void> {
    this.challenges.set(ch.id, { ...ch });
  }
  async getEnrollmentChallenge(
    id: string,
  ): Promise<EnrollmentChallenge | null> {
    return this.challenges.get(id) || null;
  }
  async consumeEnrollmentChallenge(id: string): Promise<boolean> {
    const ch = this.challenges.get(id);
    if (!ch || ch.consumed) return false;
    if (Date.now() > Date.parse(ch.expires_at)) return false;
    ch.consumed = true;
    this.challenges.set(id, ch);
    return true;
  }

  async putGrant(grant: GrantRecord): Promise<void> {
    this.grants.set(grant.id, grant);
  }
  async listGrants(principalId: string): Promise<GrantRecord[]> {
    return [...this.grants.values()].filter((g) => g.principal_id === principalId);
  }
  async revokeGrant(id: string): Promise<void> {
    this.grants.delete(id);
  }

  async appendAudit(event: AuditEvent): Promise<void> {
    this.audits.push(event);
  }
  async listAudit(tenantId: string, limit = 50): Promise<AuditEvent[]> {
    return this.audits
      .filter((a) => a.tenant_id === tenantId)
      .slice(-limit)
      .reverse();
  }

  /**
   * Compact expired terminal rows. Keyed receipts become 30-day tombstones;
   * keyless rows (and leftover keyless tombstones) are hard-deleted at result TTL
   * because they protect no idempotency binding.
   */
  private compactMcpOperations(tenantId: string): void {
    const now = Date.now();
    const tenantOps = [...this.mcpOperations.values()].filter((o) => o.tenant_id === tenantId);
    for (const op of tenantOps) {
      const age = mcpOpAgeMs(op, now);
      const keyed = hasMcpIdempotencyReceipt(op);
      // Keyless tombstones protect nothing; drop them immediately.
      if (op.status === "tombstone" && !keyed) {
        this.mcpOperations.delete(op.operation_id);
        continue;
      }
      // Only hard-delete keyed tombstones past the full idempotency window (30d).
      if (op.status === "tombstone" && age > MCP_OPS_TOMBSTONE_TTL_MS) {
        this.mcpOperations.delete(op.operation_id);
        continue;
      }
      if (isTerminalMcpStatus(op.status) && op.status !== "tombstone" && age > MCP_OPS_RESULT_TTL_MS) {
        if (!keyed) {
          this.mcpOperations.delete(op.operation_id);
          continue;
        }
        this.mcpOperations.set(op.operation_id, {
          ...op,
          status: "tombstone",
          summary: "tombstone: result TTL expired; idempotency retained",
          data: {
            tombstone: true,
            prior_status: op.status,
            payload_hash: op.payload_hash ?? null,
            // Preserve compact action binding for same-key retry within 30d window.
            idempotency_key: op.idempotency_key ?? null,
          },
          truncated: true,
          warnings: ["durable_result_tombstoned"],
          updated_at: nowIso(),
        });
      }
    }
  }

  /** Compact expired terminal rows; preserve idempotency keys as tombstones. */
  private enforceMcpOperationQuota(tenantId: string): void {
    this.compactMcpOperations(tenantId);
    const remaining = [...this.mcpOperations.values()].filter((o) => o.tenant_id === tenantId);
    if (remaining.length < this.mcpOpsLimit) return;
    // E3: never evict unexpired idempotency receipts under quota pressure.
    // Only hard-expired tombstones (already removed above) free capacity; otherwise
    // reject new distinct operations fail-closed.
    throw new Error(`mcp_operation_quota_exceeded:tenant=${tenantId}:max=${this.mcpOpsLimit}`);
  }

  /** Create-only: refuses to overwrite an existing operation_id or idempotency binding. */
  /**
   * Hard-delete tombstones whose 30-day idempotency window has closed, so an
   * expired key becomes reusable as a fresh operation instead of blocking on a
   * stale tombstone forever. Runs before any existing-row lookup on the claim
   * and put paths; `enforceMcpOperationQuota` also prunes them at capacity.
   */
  private expireExpiredMcpTombstones(tenantId: string): void {
    const now = Date.now();
    for (const op of [...this.mcpOperations.values()]) {
      if (op.tenant_id !== tenantId || op.status !== "tombstone") continue;
      const keyed = hasMcpIdempotencyReceipt(op);
      if (!keyed || mcpOpAgeMs(op, now) > MCP_OPS_TOMBSTONE_TTL_MS) {
        this.mcpOperations.delete(op.operation_id);
      }
    }
  }

  async putMcpOperation(op: McpOperationRecord): Promise<void> {
    // P0-B review: expire closed-window tombstones before the existing-row
    // lookup so a key whose 30-day window ended can be minted fresh instead of
    // throwing mcp_operation_idempotency_exists forever.
    this.expireExpiredMcpTombstones(op.tenant_id);
    if (this.mcpOperations.has(op.operation_id)) {
      throw new Error(`mcp_operation_exists:${op.operation_id}`);
    }
    if (op.idempotency_key) {
      const existing = await this.getMcpOperationByIdempotency({
        principalId: op.principal_id,
        tenantId: op.tenant_id,
        deviceId: op.device_id || "",
        idempotencyKey: op.idempotency_key,
      });
      if (existing) {
        throw new Error(`mcp_operation_idempotency_exists:${op.idempotency_key}`);
      }
    }
    this.enforceMcpOperationQuota(op.tenant_id);
    const bounded = boundMcpOperationRecord(op);
    this.mcpOperations.set(op.operation_id, bounded);
  }
  async getMcpOperation(operationId: string): Promise<McpOperationRecord | null> {
    const op = this.mcpOperations.get(operationId);
    return op ? { ...op, data: { ...op.data }, warnings: [...op.warnings] } : null;
  }
  async getMcpOperationByCorrelation(correlationId: string): Promise<McpOperationRecord | null> {
    for (const op of this.mcpOperations.values()) {
      if (op.correlation_id === correlationId) {
        return { ...op, data: { ...op.data }, warnings: [...op.warnings] };
      }
    }
    return null;
  }
  async listMcpOperations(opts: {
    tenantId: string;
    principalId: string;
    tool: string;
    limit?: number;
  }): Promise<McpOperationRecord[]> {
    const limit = Math.max(1, Math.min(this.mcpOpsLimit, Math.trunc(opts.limit ?? this.mcpOpsLimit)));
    return [...this.mcpOperations.values()]
      .filter((op) => op.tenant_id === opts.tenantId && op.principal_id === opts.principalId && op.tool === opts.tool)
      .sort((left, right) => right.created_at.localeCompare(left.created_at) || right.operation_id.localeCompare(left.operation_id))
      .slice(0, limit)
      .map((op) => ({
        ...op,
        data: { ...op.data },
        warnings: [...op.warnings],
        action: op.action ? { ...op.action } : op.action,
      }));
  }
  async getMcpOperationByIdempotency(opts: {
    principalId: string;
    tenantId: string;
    deviceId: string;
    idempotencyKey: string;
  }): Promise<McpOperationRecord | null> {
    let best: McpOperationRecord | null = null;
    for (const op of this.mcpOperations.values()) {
      if (
        op.principal_id === opts.principalId &&
        op.tenant_id === opts.tenantId &&
        (op.device_id || "") === opts.deviceId &&
        (op.idempotency_key || "") === opts.idempotencyKey
      ) {
        if (!best || op.created_at > best.created_at) best = op;
      }
    }
    return best
      ? {
          ...best,
          data: { ...best.data },
          warnings: [...best.warnings],
          action: best.action ? { ...best.action } : best.action,
        }
      : null;
  }
  async claimMcpOperationByIdempotency(
    op: McpOperationRecord,
  ): Promise<
    | { outcome: "created"; op: McpOperationRecord }
    | { outcome: "existing"; op: McpOperationRecord }
  > {
    // P0-B review: expire closed-window tombstones before the existing-row
    // lookup. A tombstone older than MCP_OPS_TOMBSTONE_TTL_MS must not be
    // returned as `existing` indefinitely — the documented lifecycle hard-
    // deletes it and dispatches a retry as a new operation.
    this.expireExpiredMcpTombstones(op.tenant_id);
    // Synchronous check+insert window (no await) so concurrent MemoryStore
    // callers cannot both observe absence and both insert.
    if (op.idempotency_key) {
      let best: McpOperationRecord | null = null;
      for (const existing of this.mcpOperations.values()) {
        if (
          existing.principal_id === op.principal_id &&
          existing.tenant_id === op.tenant_id &&
          (existing.device_id || "") === (op.device_id || "") &&
          (existing.idempotency_key || "") === op.idempotency_key
        ) {
          if (!best || existing.created_at > best.created_at) best = existing;
        }
      }
      if (best) {
        return {
          outcome: "existing",
          op: {
            ...best,
            data: { ...best.data },
            warnings: [...best.warnings],
            action: best.action ? { ...best.action } : best.action,
          },
        };
      }
    }
    if (this.mcpOperations.has(op.operation_id)) {
      throw new Error(`mcp_operation_exists:${op.operation_id}`);
    }
    this.enforceMcpOperationQuota(op.tenant_id);
    const stored = boundMcpOperationRecord(op);
    this.mcpOperations.set(op.operation_id, stored);
    return {
      outcome: "created",
      op: {
        ...stored,
        data: { ...stored.data },
        warnings: [...stored.warnings],
        action: stored.action ? { ...stored.action } : stored.action,
      },
    };
  }
  async updateMcpOperation(
    operationId: string,
    patch: Partial<McpOperationRecord>,
    fromStatuses?: string[],
    expectedData?: Record<string, unknown>,
  ): Promise<McpOperationRecord | null> {
    const cur = this.mcpOperations.get(operationId);
    if (!cur) return null;
    if (fromStatuses && fromStatuses.length > 0 && !fromStatuses.includes(cur.status)) return null;
    if (expectedData !== undefined && JSON.stringify(cur.data || {}) !== JSON.stringify(expectedData)) return null;
    const next: McpOperationRecord = boundMcpOperationRecord({
      ...cur,
      ...patch,
      operation_id: cur.operation_id,
      principal_id: patch.principal_id ?? cur.principal_id,
      tenant_id: patch.tenant_id ?? cur.tenant_id,
      data: patch.data ? { ...patch.data } : { ...cur.data },
      warnings: patch.warnings ? [...patch.warnings] : [...cur.warnings],
      action: patch.action !== undefined
        ? patch.action
          ? { ...patch.action }
          : patch.action
        : cur.action
          ? { ...cur.action }
          : cur.action,
      policy_authority: "ownmesh_device",
      updated_at: patch.updated_at || nowIso(),
    });
    this.mcpOperations.set(operationId, next);
    return {
      ...next,
      data: { ...next.data },
      warnings: [...next.warnings],
      action: next.action ? { ...next.action } : next.action,
    };
  }

  async putMcpApprovalTransaction(tx: McpApprovalTransaction): Promise<void> {
    this.mcpApprovalTransactions.set(tx.id, { ...tx });
  }
  async consumeMcpApprovalTransaction(
    id: string,
    csrfHash: string,
    principalId: string,
    decision: "approve" | "deny",
  ): Promise<McpApprovalTransaction | null> {
    const tx = this.mcpApprovalTransactions.get(id);
    if (
      !tx ||
      tx.consumed ||
      tx.csrf_hash !== csrfHash ||
      tx.principal_id !== principalId ||
      Date.now() > tx.expires_at
    ) {
      return null;
    }
    tx.consumed = true;
    tx.decision = decision;
    this.mcpApprovalTransactions.set(id, tx);
    return { ...tx };
  }

  async beginMcpApprovalOutbox(
    id: string,
    csrfHash: string,
    principalId: string,
    decision: "approve" | "deny",
  ): Promise<BeginMcpApprovalOutboxResult | null> {
    const existing = this.mcpApprovalOutbox.get(id);
    if (existing) {
      if (!isValidOutboxDecision(existing.decision) || !isValidDeliveryStatus(existing.delivery_status)) {
        return null;
      }
      const tx = this.mcpApprovalTransactions.get(id);
      if (
        !tx ||
        tx.csrf_hash !== csrfHash ||
        tx.principal_id !== principalId ||
        existing.decision !== decision
      ) {
        return null;
      }
      if (existing.delivery_status === "delivered") {
        return { status: "already_delivered", outbox: { ...existing } };
      }
      return {
        status: "pending_retry",
        outbox: { ...existing },
        tx: { ...tx },
      };
    }

    // Atomic consume + outbox insert (no await between — no consumed-without-outbox window).
    const tx = this.mcpApprovalTransactions.get(id);
    if (
      !tx ||
      tx.consumed ||
      tx.csrf_hash !== csrfHash ||
      tx.principal_id !== principalId ||
      Date.now() > tx.expires_at
    ) {
      return null;
    }
    for (const row of this.mcpApprovalOutbox.values()) {
      if (row.operation_id === tx.operation_id) {
        // Decision already recorded under a different transaction id.
        return null;
      }
    }
    tx.consumed = true;
    tx.decision = decision;
    this.mcpApprovalTransactions.set(id, tx);

    const outbox: McpApprovalOutbox = {
      id,
      operation_id: tx.operation_id,
      principal_id: tx.principal_id,
      tenant_id: tx.tenant_id,
      device_id: tx.device_id,
      decision,
      // Stable idempotency/correlation bound to the approval transaction id.
      correlation_id: `cor_${id}`,
      delivery_status: "pending",
      attempts: 0,
      last_error: null,
      created_at: nowIso(),
      delivered_at: null,
      claimed_at: null,
      claim_token: null,
      claim_version: 0,
    };
    this.mcpApprovalOutbox.set(id, outbox);
    return { status: "created", outbox: { ...outbox }, tx: { ...tx } };
  }

  async getMcpApprovalOutbox(id: string): Promise<McpApprovalOutbox | null> {
    const row = this.mcpApprovalOutbox.get(id);
    if (!row) return null;
    if (!isValidOutboxDecision(row.decision) || !isValidDeliveryStatus(row.delivery_status)) {
      return null;
    }
    return { ...row };
  }

  async claimMcpApprovalOutboxDelivery(id: string): Promise<McpApprovalOutbox | null> {
    const row = this.mcpApprovalOutbox.get(id);
    if (!row || !isValidOutboxDecision(row.decision)) return null;
    const now = Date.now();
    const claimTs = nowIso();
    const issueClaim = () => {
      row.delivery_status = "delivering";
      row.claimed_at = claimTs;
      row.claim_token = randomToken("clm_");
      row.claim_version = (Number(row.claim_version) || 0) + 1;
      this.mcpApprovalOutbox.set(id, row);
      return { ...row };
    };
    if (row.delivery_status === "pending") {
      return issueClaim();
    }
    if (row.delivery_status === "delivering") {
      // Stale reclaim only when lease expired (or claimed_at missing/unparseable).
      const claimedMs = row.claimed_at ? Date.parse(row.claimed_at) : NaN;
      const leaseExpired =
        !Number.isFinite(claimedMs) ||
        now - claimedMs >= MCP_APPROVAL_OUTBOX_CLAIM_LEASE_MS;
      if (!leaseExpired) return null;
      return issueClaim();
    }
    return null;
  }

  async releaseMcpApprovalOutboxClaim(
    id: string,
    claimToken: string,
    claimVersion: number,
    error?: string,
  ): Promise<void> {
    const row = this.mcpApprovalOutbox.get(id);
    if (!row || row.delivery_status !== "delivering") return;
    if (!claimToken || row.claim_token !== claimToken) return;
    if (Number(row.claim_version) !== Number(claimVersion)) return;
    row.delivery_status = "pending";
    row.attempts += 1;
    row.last_error = error ?? row.last_error ?? null;
    row.claimed_at = null;
    row.claim_token = null;
    this.mcpApprovalOutbox.set(id, row);
  }

  async recordMcpApprovalOutboxAttempt(id: string, error?: string): Promise<void> {
    const row = this.mcpApprovalOutbox.get(id);
    if (!row) return;
    // Delivering claims must be released via releaseMcpApprovalOutboxClaim (owner token).
    if (row.delivery_status === "delivering") return;
    if (row.delivery_status !== "pending") return;
    row.attempts += 1;
    row.last_error = error ?? row.last_error ?? null;
    this.mcpApprovalOutbox.set(id, row);
  }

  async finalizeMcpApprovalDelivery(
    id: string,
    claimToken: string,
    claimVersion: number,
  ): Promise<McpOperationRecord | null> {
    const outbox = this.mcpApprovalOutbox.get(id);
    if (!outbox || outbox.delivery_status !== "delivering") return null;
    if (!claimToken || outbox.claim_token !== claimToken) return null;
    if (Number(outbox.claim_version) !== Number(claimVersion)) return null;
    if (!isValidOutboxDecision(outbox.decision)) return null;

    const op = this.mcpOperations.get(outbox.operation_id);
    if (!op) return null;

    let updated: McpOperationRecord | null = null;
    if (op.status === "approval_required") {
      // Conditional CAS only — never overwrite fast terminal results.
      updated = await this.updateMcpOperation(
        outbox.operation_id,
        {
          summary: "human decision delivered; awaiting authoritative device result",
          data: {
            ...(op.data || {}),
            approval_decision: outbox.decision,
            approval_transaction_id: outbox.id,
          },
        },
        ["approval_required"],
      );
      if (!updated) {
        // CAS lost to a concurrent/fast path — keep authoritative current record.
        const cur = this.mcpOperations.get(outbox.operation_id);
        if (!cur || cur.status === "approval_required") return null;
        updated = { ...cur, data: { ...cur.data }, warnings: [...cur.warnings] };
      }
    } else {
      // Already progressed past approval_required (including terminal) — do not clobber.
      updated = { ...op, data: { ...op.data }, warnings: [...op.warnings] };
    }

    if (outbox.delivery_status !== "delivering") return null;
    outbox.delivery_status = "delivered";
    outbox.delivered_at = nowIso();
    outbox.attempts += 1;
    outbox.last_error = null;
    this.mcpApprovalOutbox.set(id, outbox);
    return updated;
  }

  async putTenantMember(
    tenantId: string,
    principalId: string,
    role: "owner" | "admin" | "member",
  ): Promise<void> {
    const key = `${tenantId}\0${principalId}`;
    this.tenantMembers.set(key, {
      tenant_id: tenantId,
      principal_id: principalId,
      role,
      created_at: nowIso(),
    });
  }

  async isTenantMember(tenantId: string, principalId: string): Promise<boolean> {
    return this.tenantMembers.has(`${tenantId}\0${principalId}`);
  }

  async getTenantMemberRole(
    tenantId: string,
    principalId: string,
  ): Promise<"owner" | "admin" | "member" | null> {
    return this.tenantMembers.get(`${tenantId}\0${principalId}`)?.role ?? null;
  }

  async putWorkspace(workspace: WorkspaceRecord): Promise<void> {
    const key = workspaceStoreKey(workspace.device_id, workspace.workspace_id);
    const existing = this.workspaces.get(key);
    this.workspaces.set(key, {
      ...workspace,
      ...(workspace.local_generation || existing?.local_generation
        ? { local_generation: workspace.local_generation || existing?.local_generation }
        : {}),
    });
  }

  async getWorkspace(deviceId: string, workspaceId: string): Promise<WorkspaceRecord | null> {
    const row = this.workspaces.get(workspaceStoreKey(deviceId, workspaceId));
    return row ? { ...row } : null;
  }

  async putWorkspaceMember(
    deviceId: string,
    workspaceId: string,
    principalId: string,
  ): Promise<void> {
    this.workspaceMembers.add(workspaceMemberStoreKey(deviceId, workspaceId, principalId));
  }

  async isWorkspaceMember(
    deviceId: string,
    workspaceId: string,
    principalId: string,
  ): Promise<boolean> {
    return this.workspaceMembers.has(workspaceMemberStoreKey(deviceId, workspaceId, principalId));
  }

  async syncDeviceWorkspaces(
    deviceId: string,
    workspaces: AdvertisedWorkspaceRegistration[],
  ): Promise<WorkspaceRecord[]> {
    const device = await this.getDevice(deviceId);
    if (!device || device.revoked || device.status !== "active") {
      throw new Error("device_not_active");
    }
    const registrations = validateAdvertisedWorkspaces(workspaces);
    const observedAt = nowIso();
    for (const registration of registrations) {
      const workspaceId = registration.id;
      const key = workspaceStoreKey(deviceId, workspaceId);
      const existing = this.workspaces.get(key);
      if (!existing) {
        this.workspaces.set(key, {
          workspace_id: workspaceId,
          tenant_id: device.tenant_id,
          device_id: deviceId,
          owner_principal_id: device.principal_id,
          version: 1,
          local_generation: registration.generation,
          active: true,
          created_at: observedAt,
          updated_at: observedAt,
        });
      } else if (
        !existing.active ||
        (existing.local_generation !== undefined &&
          existing.local_generation !== registration.generation)
      ) {
        this.workspaces.set(key, {
          ...existing,
          active: true,
          version: existing.version + 1,
          local_generation: registration.generation,
          updated_at: observedAt,
        });
      } else if (existing.local_generation === undefined) {
        this.workspaces.set(key, {
          ...existing,
          active: true,
          version: existing.version + 1,
          local_generation: registration.generation,
          updated_at: observedAt,
        });
      }
    }
    return [...this.workspaces.values()]
      .filter((workspace) => workspace.device_id === deviceId && workspace.active)
      .map((workspace) => ({ ...workspace }))
      .sort((a, b) => a.workspace_id.localeCompare(b.workspace_id));
  }

  async assertWorkspaceOperableForMcp(
    workspaceId: string,
    deviceId: string,
    principalId: string,
    tenantId: string,
  ): Promise<WorkspaceOperableGate> {
    return this.workspaceGate(workspaceId, deviceId, principalId, tenantId, true);
  }

  async assertWorkspaceVisibleForMcp(
    workspaceId: string,
    deviceId: string,
    principalId: string,
    tenantId: string,
  ): Promise<WorkspaceOperableGate> {
    return this.workspaceGate(workspaceId, deviceId, principalId, tenantId, false);
  }

  private async workspaceGate(
    workspaceId: string,
    deviceId: string,
    principalId: string,
    tenantId: string,
    requireActiveGeneration: boolean,
  ): Promise<WorkspaceOperableGate> {
    const workspace = await this.getWorkspace(deviceId, workspaceId);
    const classified = requireActiveGeneration
      ? classifyWorkspaceAvailability(workspace, deviceId, tenantId)
      : classifyWorkspaceVisibility(workspace, deviceId, tenantId);
    if (!classified.ok) return classified;
    const allowed = await this.workspacePrincipalAllowed(
      classified.workspace,
      deviceId,
      principalId,
      tenantId,
    );
    return allowed
      ? classified
      : {
          ok: false,
          error: "workspace_not_available",
          cause: "not_authorized",
          next_action: "select_active_workspace",
        };
  }

  private async workspacePrincipalAllowed(
    workspace: WorkspaceRecord,
    deviceId: string,
    principalId: string,
    tenantId: string,
  ): Promise<boolean> {
    const device = await this.getDevice(deviceId);
    const role = await this.getTenantMemberRole(tenantId, principalId);
    return (
      workspace.owner_principal_id === principalId ||
      device?.principal_id === principalId ||
      role === "owner" ||
      role === "admin" ||
      (role === "member" &&
        (await this.isWorkspaceMember(deviceId, workspace.workspace_id, principalId)))
    );
  }

  async observeWorkspaceGeneration(
    deviceId: string,
    workspaceId: string,
    generation: string,
  ): Promise<WorkspaceRecord | null> {
    if (!parseWorkspaceId(workspaceId) || !parseWorkspaceGeneration(generation)) return null;
    const device = await this.getDevice(deviceId);
    if (!device || device.revoked || device.status !== "active") return null;
    const existing = await this.getWorkspace(deviceId, workspaceId);
    const next = applyObservedGeneration(existing, {
      workspaceId,
      deviceId,
      tenantId: device.tenant_id,
      ownerPrincipalId: existing?.owner_principal_id || device.principal_id,
      generation,
      observedAt: nowIso(),
    });
    await this.putWorkspace(next);
    return this.getWorkspace(deviceId, workspaceId);
  }

  async deactivateWorkspace(
    deviceId: string,
    workspaceId: string,
  ): Promise<WorkspaceRecord | null> {
    const existing = await this.getWorkspace(deviceId, workspaceId);
    if (!existing) return null;
    await this.putWorkspace({
      ...existing,
      active: false,
      updated_at: nowIso(),
    });
    return this.getWorkspace(deviceId, workspaceId);
  }

  async recordObservedWorkspaceEnforcement(
    deviceId: string,
    enforceWorkspace: boolean,
  ): Promise<DeviceRecord | null> {
    const device = this.devices.get(deviceId);
    if (!device || device.revoked || device.status !== "active") return null;
    device.enforce_workspace = enforceWorkspace;
    this.devices.set(deviceId, device);
    return hydrateDevice(device);
  }

  async canOperateDevice(
    deviceId: string,
    principalId: string,
    tenantId: string,
  ): Promise<boolean> {
    const device = await this.getDevice(deviceId);
    if (!device || device.tenant_id !== tenantId) return false;
    if (device.principal_id === principalId) return true;
    return this.isTenantMember(tenantId, principalId);
  }

  async assertDeviceOperableForMcp(
    deviceId: string,
    principalId: string,
    tenantId: string,
  ): Promise<{ ok: true } | { ok: false; error: string }> {
    const device = await this.getDevice(deviceId);
    if (!device || device.tenant_id !== tenantId) {
      return { ok: false, error: "device_not_available" };
    }
    const allowed =
      device.principal_id === principalId || (await this.isTenantMember(tenantId, principalId));
    if (!allowed) {
      return { ok: false, error: "device_not_available" };
    }
    if (device.revoked || device.status !== "active") {
      return { ok: false, error: "device_not_available" };
    }
    // MemoryStore always has the credential schema; empty set = no credentials issued.
    const creds = [...this.deviceCredentials.values()].filter((c) => c.device_id === deviceId);
    if (creds.length > 0) {
      const now = Date.now();
      const anyValid = creds.some((c) => !c.revoked && c.expires_at > now);
      if (!anyValid) return { ok: false, error: "device_credential_revoked" };
    }
    return { ok: true };
  }

  async appliedMigrations(): Promise<string[]> {
    return [...this.migrations].sort();
  }
  async markMigration(id: string): Promise<void> {
    this.migrations.add(id);
  }

  async schemaReadiness(): Promise<SchemaReadiness> {
    // In-memory store always carries the full logical 0002–0008 schema.
    const checks = Object.fromEntries(
      Object.keys(SCHEMA_READINESS_OBJECTS).map((k) => [k, true]),
    ) as SchemaReadiness["checks"];
    return { schema_ready: true, checks };
  }
}

// ---------------------------------------------------------------------------
// SQL-backed store (D1 in Workers, node:sqlite in tests)
// ---------------------------------------------------------------------------

/** Minimal subset of D1 / sqlite prepared statement API. */
export interface SqlDatabase {
  prepare(query: string): SqlStatement;
  exec?(query: string): unknown | Promise<unknown>;
  batch?<T = unknown>(statements: SqlStatement[]): Promise<T[]>;
}

export interface SqlStatement {
  bind(...values: unknown[]): SqlStatement;
  first<T = Record<string, unknown>>(colName?: string): Promise<T | null>;
  run<T = Record<string, unknown>>(): Promise<{
    success?: boolean;
    meta?: unknown;
    results?: T[];
  }>;
  all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
}

export class SqlStore implements ControlPlaneStore {
  readonly kind: "d1" | "sqlite";
  private db: SqlDatabase;
  private readonly mcpOpsLimit: number;
  /** plaintext access/refresh kept only for the lifetime of this isolate when issued here.
   * Lookups always go through hash in SQL. For getAccess we need the plaintext from the
   * Authorization header — we hash it and look up. */
  constructor(db: SqlDatabase, kind: "d1" | "sqlite" = "d1", opts?: McpOpsStoreOptions) {
    this.db = db;
    this.kind = kind;
    this.mcpOpsLimit = parseMcpOpsMaxPerTenant(opts?.mcpOpsMaxPerTenant);
  }

  mcpOpsMaxPerTenant(): number {
    return this.mcpOpsLimit;
  }

  async getMcpOperationQuota(tenantId: string): Promise<McpOperationQuotaSnapshot> {
    await this.compactMcpOperations(tenantId);
    const countRow = await this.db
      .prepare(`SELECT COUNT(*) AS c FROM mcp_operations WHERE tenant_id = ?`)
      .bind(tenantId)
      .first<{ c: number }>();
    return snapshotMcpOperationQuota(Number(countRow?.c ?? 0), this.mcpOpsLimit);
  }

  async ensureBootstrap(): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR IGNORE INTO tenants (id, name, created_at) VALUES (?, ?, ?)`,
      )
      .bind(DEFAULT_TENANT, "Default", nowIso())
      .run();
    await this.db
      .prepare(
        `INSERT OR IGNORE INTO principals (id, tenant_id, kind, display_name, created_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .bind("prin_dev", DEFAULT_TENANT, "human", "Dev User", nowIso())
      .run();
    // Ensure a bootstrap OAuth client for device-code / dev flows.
    await this.db
      .prepare(
        `INSERT OR IGNORE INTO oauth_clients (client_id, tenant_id, client_name, redirect_uris, created_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(
        "client_ownmesh_cli",
        DEFAULT_TENANT,
        "OwnMesh CLI",
        JSON.stringify([
          "http://127.0.0.1:8750/callback",
          "http://localhost:8750/callback",
        ]),
        nowIso(),
      )
      .run();
  }

  async putClient(client: OAuthClientRecord): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR REPLACE INTO oauth_clients (client_id, tenant_id, client_name, redirect_uris, created_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(
        client.client_id,
        client.tenant_id,
        client.client_name,
        JSON.stringify(client.redirect_uris),
        client.created_at,
      )
      .run();
  }

  async getClient(clientId: string): Promise<OAuthClientRecord | null> {
    const row = await this.db
      .prepare(
        `SELECT client_id, tenant_id, client_name, redirect_uris, created_at FROM oauth_clients WHERE client_id = ?`,
      )
      .bind(clientId)
      .first<{
        client_id: string;
        tenant_id: string;
        client_name: string;
        redirect_uris: string;
        created_at: string;
      }>();
    if (!row) return null;
    let uris: string[] = [];
    try {
      uris = JSON.parse(row.redirect_uris) as string[];
    } catch {
      uris = [];
    }
    return {
      client_id: row.client_id,
      tenant_id: row.tenant_id,
      client_name: row.client_name,
      redirect_uris: uris,
      created_at: row.created_at,
    };
  }

  /** True when a row exists in tenants. Never inserts. */
  async tenantExists(tenantId: string): Promise<boolean> {
    if (!tenantId) return false;
    const row = await this.db
      .prepare(`SELECT id FROM tenants WHERE id = ?`)
      .bind(tenantId)
      .first<{ id: string }>();
    return !!row;
  }

  async ensurePrincipal(
    id: string,
    displayName: string,
    kind = "human",
    tenantId = DEFAULT_TENANT,
  ): Promise<PrincipalRecord> {
    const existing = await this.db
      .prepare(
        `SELECT id, tenant_id, kind, display_name, credential_generation, created_at FROM principals WHERE id = ?`,
      )
      .bind(id)
      .first<PrincipalRecord>();
    if (existing) {
      if (existing.tenant_id !== tenantId) throw new Error("principal tenant mismatch");
      return existing;
    }
    const created = nowIso();
    await this.db
      .prepare(
        `INSERT INTO principals (id, tenant_id, kind, display_name, created_at) VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(id, tenantId, kind, displayName, created)
      .run();
    return {
      id,
      tenant_id: tenantId,
      kind,
      display_name: displayName,
      credential_generation: 1,
      created_at: created,
    };
  }

  async getPrincipal(id: string): Promise<PrincipalRecord | null> {
    return this.db.prepare(
      `SELECT id, tenant_id, kind, display_name, credential_generation, created_at FROM principals WHERE id = ?`,
    ).bind(id).first<PrincipalRecord>();
  }

  private ownerPasskeyFromRow(row: {
    credential_id: string;
    principal_id: string;
    webauthn_user_id: string;
    public_key: ArrayBuffer | Uint8Array;
    counter: number;
    transports_json: string;
    device_type: "singleDevice" | "multiDevice";
    backed_up: number;
    created_at: string;
    last_used_at: string | null;
  }): OwnerPasskeyRecord {
    let transports: string[] = [];
    try {
      const parsed: unknown = JSON.parse(row.transports_json);
      if (Array.isArray(parsed)) transports = parsed.filter((item): item is string => typeof item === "string");
    } catch {
      transports = [];
    }
    const publicKey = row.public_key instanceof Uint8Array
      ? row.public_key.slice()
      : new Uint8Array(row.public_key);
    return {
      credential_id: row.credential_id,
      principal_id: row.principal_id,
      webauthn_user_id: row.webauthn_user_id,
      public_key: publicKey,
      counter: row.counter,
      transports,
      device_type: row.device_type,
      backed_up: Boolean(row.backed_up),
      created_at: row.created_at,
      last_used_at: row.last_used_at ?? undefined,
    };
  }

  async listOwnerPasskeys(): Promise<OwnerPasskeyRecord[]> {
    const result = await this.db.prepare(
      `SELECT credential_id, principal_id, webauthn_user_id, public_key, counter,
              transports_json, device_type, backed_up, created_at, last_used_at
       FROM owner_passkeys ORDER BY created_at, credential_id LIMIT 8`,
    ).all<{
      credential_id: string; principal_id: string; webauthn_user_id: string;
      public_key: ArrayBuffer | Uint8Array; counter: number; transports_json: string;
      device_type: "singleDevice" | "multiDevice"; backed_up: number;
      created_at: string; last_used_at: string | null;
    }>();
    return (result.results || []).map((row) => this.ownerPasskeyFromRow(row));
  }

  async getOwnerPasskey(credentialId: string): Promise<OwnerPasskeyRecord | null> {
    const row = await this.db.prepare(
      `SELECT credential_id, principal_id, webauthn_user_id, public_key, counter,
              transports_json, device_type, backed_up, created_at, last_used_at
       FROM owner_passkeys WHERE credential_id = ?`,
    ).bind(credentialId).first<{
      credential_id: string; principal_id: string; webauthn_user_id: string;
      public_key: ArrayBuffer | Uint8Array; counter: number; transports_json: string;
      device_type: "singleDevice" | "multiDevice"; backed_up: number;
      created_at: string; last_used_at: string | null;
    }>();
    return row ? this.ownerPasskeyFromRow(row) : null;
  }

  async putInitialOwnerPasskey(passkey: OwnerPasskeyRecord): Promise<boolean> {
    const publicKey = passkey.public_key.slice().buffer;
    const inserted = await this.db.prepare(
      `INSERT INTO owner_passkeys
       (credential_id, principal_id, webauthn_user_id, public_key, counter,
        transports_json, device_type, backed_up, created_at, last_used_at)
       SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL
       WHERE NOT EXISTS (SELECT 1 FROM owner_passkeys)
       RETURNING credential_id`,
    ).bind(
      passkey.credential_id,
      passkey.principal_id,
      passkey.webauthn_user_id,
      publicKey,
      passkey.counter,
      JSON.stringify(passkey.transports),
      passkey.device_type,
      passkey.backed_up ? 1 : 0,
      passkey.created_at,
    ).first<{ credential_id: string }>();
    return inserted?.credential_id === passkey.credential_id;
  }

  async updateOwnerPasskeyUsage(
    credentialId: string,
    expectedCounter: number,
    nextCounter: number,
    deviceType: "singleDevice" | "multiDevice",
    backedUp: boolean,
  ): Promise<boolean> {
    const updated = await this.db.prepare(
      `UPDATE owner_passkeys
       SET counter = ?, device_type = ?, backed_up = ?, last_used_at = ?
       WHERE credential_id = ? AND counter = ?
       RETURNING credential_id`,
    ).bind(
      nextCounter,
      deviceType,
      backedUp ? 1 : 0,
      nowIso(),
      credentialId,
      expectedCounter,
    ).first<{ credential_id: string }>();
    return updated?.credential_id === credentialId;
  }

  async putOwnerAuthChallenge(challenge: OwnerAuthChallenge): Promise<boolean> {
    const now = nowIso();
    await this.db.prepare(`DELETE FROM owner_auth_challenges WHERE expires_at <= ?`).bind(now).run();
    const inserted = await this.db.prepare(
      `INSERT INTO owner_auth_challenges
       (id, kind, challenge, webauthn_user_id, return_to, expires_at, created_at)
       SELECT ?, ?, ?, ?, ?, ?, ?
       WHERE (SELECT COUNT(*) FROM owner_auth_challenges WHERE expires_at > ?) < 64
       ON CONFLICT(id) DO UPDATE SET
         kind = excluded.kind,
         challenge = excluded.challenge,
         webauthn_user_id = excluded.webauthn_user_id,
         return_to = excluded.return_to,
         expires_at = excluded.expires_at,
         created_at = excluded.created_at
       WHERE owner_auth_challenges.expires_at <= ?
       RETURNING id`,
    ).bind(
      challenge.id,
      challenge.kind,
      challenge.challenge,
      challenge.webauthn_user_id ?? null,
      challenge.return_to,
      nowIso(challenge.expires_at),
      challenge.created_at,
      now,
      now,
    ).first<{ id: string }>();
    return inserted?.id === challenge.id;
  }

  async takeOwnerAuthChallenge(
    id: string,
    kind: OwnerAuthChallenge["kind"],
  ): Promise<OwnerAuthChallenge | null> {
    const row = await this.db.prepare(
      `DELETE FROM owner_auth_challenges
       WHERE id = ? AND kind = ? AND expires_at > ?
       RETURNING challenge, webauthn_user_id, return_to, expires_at, created_at`,
    ).bind(id, kind, nowIso()).first<{
      challenge: string;
      webauthn_user_id: string | null;
      return_to: string;
      expires_at: string;
      created_at: string;
    }>();
    if (!row) return null;
    return {
      id,
      kind,
      challenge: row.challenge,
      webauthn_user_id: row.webauthn_user_id ?? undefined,
      return_to: row.return_to,
      expires_at: Date.parse(row.expires_at),
      created_at: row.created_at,
    };
  }

  async advancePrincipalCredentialGeneration(id: string): Promise<number | null> {
    const updated = await this.db
      .prepare(
        `UPDATE principals
         SET credential_generation = credential_generation + 1
         WHERE id = ? AND credential_generation >= 1
         RETURNING credential_generation`,
      )
      .bind(id)
      .first<{ credential_generation: number }>();
    const generation = Number(updated?.credential_generation);
    return Number.isSafeInteger(generation) && generation >= 1 ? generation : null;
  }

  async putAuthCode(code: AuthCodeRecord): Promise<void> {
    const hash = await sha256Hex(code.code);
    await this.db
      .prepare(
        `INSERT INTO oauth_auth_codes
         (code_hash, client_id, principal_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, used, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
      )
      .bind(
        hash,
        code.client_id,
        code.principal_id,
        code.redirect_uri,
        code.scope,
        code.code_challenge,
        code.code_challenge_method,
        nowIso(code.expires_at),
        nowIso(),
      )
      .run();
  }

  async takeAuthCode(code: string): Promise<AuthCodeRecord | null> {
    const hash = await sha256Hex(code);
    const row = await this.db.prepare(
      `UPDATE oauth_auth_codes SET used = 1
       WHERE code_hash = ? AND used = 0 AND expires_at > ?
       RETURNING client_id, principal_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at`,
    ).bind(hash, nowIso()).first<{
      client_id: string; principal_id: string; redirect_uri: string; scope: string;
      code_challenge: string; code_challenge_method: string; expires_at: string;
    }>();
    if (!row) return null;
    return {
      code, client_id: row.client_id, principal_id: row.principal_id,
      redirect_uri: row.redirect_uri, scope: row.scope,
      code_challenge: row.code_challenge, code_challenge_method: row.code_challenge_method,
      expires_at: Date.parse(row.expires_at), used: true,
    };
  }

  async issueTokens(
    clientId: string,
    principal: string,
    scope: string,
    family?: string,
    ttlMs = ACCESS_TOKEN_TTL_MS,
    refreshTtlMs = REFRESH_TOKEN_IDLE_TTL_MS,
  ): Promise<TokenRecord> {
    const principalRecord = (await this.getPrincipal(principal)) || await this.ensurePrincipal(principal, principal);
    // Never turn token issuance into implicit client registration.
    const client = await this.getClient(clientId);
    if (!client) throw new Error("unknown OAuth client");
    if (client.tenant_id !== principalRecord.tenant_id) throw new Error("client/principal tenant mismatch");
    const access = randomToken("atk_");
    const refresh = randomToken("rtk_");
    const fam = family || randomToken("fam_");
    const expiresAt = Date.now() + ttlMs;
    const refreshExpiresAt = Date.now() + refreshTtlMs;
    const accessHash = await sha256Hex(access);
    const refreshHash = await sha256Hex(refresh);
    await this.db
      .prepare(
        `INSERT INTO oauth_tokens
         (access_token_hash, refresh_token_hash, client_id, principal_id, scope, refresh_family, refresh_used, revoked, expires_at, refresh_expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 0,
           CASE WHEN EXISTS (SELECT 1 FROM revoked_refresh_families WHERE refresh_family = ?) THEN 1 ELSE 0 END,
           ?, ?, ?)`,
      )
      .bind(
        accessHash,
        refreshHash,
        clientId,
        principal,
        scope,
        fam,
        fam,
        nowIso(expiresAt),
        nowIso(refreshExpiresAt),
        nowIso(),
      )
      .run();
    return {
      access_token: access,
      refresh_token: refresh,
      client_id: clientId,
      scope,
      principal,
      expires_at: expiresAt,
      refresh_expires_at: refreshExpiresAt,
      revoked: Boolean(await this.db.prepare(
        `SELECT 1 AS revoked FROM revoked_refresh_families WHERE refresh_family = ?`,
      ).bind(fam).first("revoked")),
      refresh_family: fam,
      refresh_used: false,
      tenant_id: principalRecord.tenant_id,
    };
  }

  async getAccess(token: string): Promise<TokenRecord | null> {
    const hash = await sha256Hex(token);
    const row = await this.db
      .prepare(
        `SELECT t.access_token_hash, t.refresh_token_hash, t.client_id, t.principal_id, t.scope,
                t.refresh_family, t.refresh_used, t.revoked, t.expires_at, t.refresh_expires_at, p.tenant_id
         FROM oauth_tokens t JOIN principals p ON p.id = t.principal_id
         WHERE t.access_token_hash = ?`,
      )
      .bind(hash)
      .first<{
        client_id: string;
        principal_id: string;
        scope: string;
        refresh_family: string;
        refresh_used: number;
        revoked: number;
        expires_at: string;
        refresh_expires_at: string;
        tenant_id: string;
      }>();
    if (!row || row.revoked) return null;
    const exp = Date.parse(row.expires_at);
    if (Date.now() > exp) return null;
    return {
      access_token: token,
      refresh_token: "",
      client_id: row.client_id,
      scope: row.scope,
      principal: row.principal_id,
      expires_at: exp,
      refresh_expires_at: Date.parse(row.refresh_expires_at),
      revoked: false,
      refresh_family: row.refresh_family,
      refresh_used: Boolean(row.refresh_used),
      tenant_id: row.tenant_id,
    };
  }

  async rotateRefresh(refreshToken: string): Promise<
    | { ok: true; token: TokenRecord }
    | { ok: false; error: "invalid_grant" | "reuse"; description?: string }
  > {
    // Atomic CAS + ledger + successor in one batch. Fail closed without batch.
    if (!this.db.batch) {
      throw new Error("SqlStore.rotateRefresh requires db.batch");
    }
    const refreshHash = await sha256Hex(refreshToken);
    const nowMs = Date.now();
    const now = nowIso(nowMs);

    // Authoritative pre-read for metadata + expiry. CAS in the batch is the claim.
    const row = await this.db.prepare(
      `SELECT client_id, principal_id, scope, refresh_family, revoked, refresh_used, refresh_expires_at
       FROM oauth_tokens WHERE refresh_token_hash = ?`,
    ).bind(refreshHash).first<{
      client_id: string; principal_id: string; scope: string;
      refresh_family: string; revoked: number; refresh_used: number; refresh_expires_at: string;
    }>();

    if (!row) {
      // No live row: ledger hit without an unexpired row is invalid_grant (not reuse).
      return { ok: false, error: "invalid_grant" };
    }

    const exp = Date.parse(row.refresh_expires_at);
    // Expired refresh is always invalid_grant; reuse detection is in-window only.
    if (!Number.isFinite(exp) || nowMs > exp) {
      return { ok: false, error: "invalid_grant" };
    }

    const used = await this.db
      .prepare(
        `SELECT refresh_family FROM used_refresh_tokens WHERE refresh_token_hash = ?`,
      )
      .bind(refreshHash)
      .first<{ refresh_family: string }>();

    // Explicitly revoked but never used (e.g. revokeToken on refresh) is invalid_grant,
    // matching MemoryStore's accessByRefresh deletion path — not reuse, no family side effects.
    if (row.revoked && !used && !row.refresh_used) {
      return { ok: false, error: "invalid_grant" };
    }

    // Real reuse: ledger hit and/or refresh_used=1 within the refresh inactivity window.
    if (used || row.refresh_used) {
      const fam = used?.refresh_family || row.refresh_family;
      await this.db.batch([
        this.db.prepare(
          `INSERT OR IGNORE INTO revoked_refresh_families (refresh_family, detected_at) VALUES (?, ?)`,
        ).bind(fam, now),
        this.db.prepare(
          `UPDATE oauth_tokens SET revoked = 1 WHERE refresh_family = ?`,
        ).bind(fam),
        this.db.prepare(
          `UPDATE principals SET credential_generation = credential_generation + 1
           WHERE id = ? AND credential_generation >= 1`,
        ).bind(row.principal_id),
      ]);
      if (!used) {
        await this.db.prepare(
          `INSERT OR IGNORE INTO used_refresh_tokens (refresh_token_hash, refresh_family, used_at) VALUES (?, ?, ?)`,
        ).bind(refreshHash, fam, now).run();
      }
      return {
        ok: false,
        error: "reuse",
        description: "refresh token reuse detected",
      };
    }

    // Precompute successor material before the batch (same defaults as issueTokens).
    const access = randomToken("atk_");
    const refresh = randomToken("rtk_");
    const expiresAt = nowMs + ACCESS_TOKEN_TTL_MS;
    const refreshExpiresAt = nowMs + REFRESH_TOKEN_IDLE_TTL_MS;
    const accessHash = await sha256Hex(access);
    const newRefreshHash = await sha256Hex(refresh);
    const ts = now;
    const expiresAtIso = nowIso(expiresAt);
    const refreshExpiresAtIso = nowIso(refreshExpiresAt);
    const fam = row.refresh_family;

    type BatchResult = { meta?: { changes?: number }; success?: boolean };
    // Single atomic batch. Each statement is self-gated via WHERE/EXISTS - no SQL changes() cross-statement dependency.
    // 1) Ledger INSERT OR IGNORE SELECT is the CAS claim (unique PK).
    // 2) Mark old token used only if ledger claim exists.
    // 3) Insert successor only if old token claimed and no other live unused token in family.
    const batchResults = await this.db.batch<BatchResult>([
      this.db.prepare(
        `INSERT OR IGNORE INTO used_refresh_tokens (refresh_token_hash, refresh_family, used_at)
         SELECT refresh_token_hash, refresh_family, ?
         FROM oauth_tokens
         WHERE refresh_token_hash = ?
           AND revoked = 0
           AND refresh_used = 0
           AND refresh_expires_at > ?`,
      ).bind(ts, refreshHash, now),
      this.db.prepare(
        `UPDATE oauth_tokens SET revoked = 1, refresh_used = 1
         WHERE refresh_token_hash = ?
           AND revoked = 0
           AND refresh_used = 0
           AND refresh_expires_at > ?
           AND EXISTS (
             SELECT 1 FROM used_refresh_tokens WHERE refresh_token_hash = ?
           )`,
      ).bind(refreshHash, now, refreshHash),
      this.db.prepare(
        `INSERT INTO oauth_tokens
         (access_token_hash, refresh_token_hash, client_id, principal_id, scope, refresh_family, refresh_used, revoked, expires_at, refresh_expires_at, created_at)
         SELECT ?, ?, ot.client_id, ot.principal_id, ot.scope, ot.refresh_family, 0,
           CASE WHEN EXISTS (
             SELECT 1 FROM revoked_refresh_families r WHERE r.refresh_family = ot.refresh_family
           ) THEN 1 ELSE 0 END,
           ?, ?, ?
         FROM oauth_tokens ot
         WHERE ot.refresh_token_hash = ?
           AND ot.refresh_used = 1 AND ot.revoked = 1
           AND EXISTS (
             SELECT 1 FROM used_refresh_tokens u WHERE u.refresh_token_hash = ot.refresh_token_hash
           )
           AND NOT EXISTS (
             SELECT 1 FROM oauth_tokens cur
             WHERE cur.refresh_family = ot.refresh_family
               AND cur.refresh_token_hash != ot.refresh_token_hash
               AND cur.refresh_used = 0
               AND cur.revoked = 0
           )`,
      ).bind(accessHash, newRefreshHash, expiresAtIso, refreshExpiresAtIso, ts, refreshHash),
      this.db.prepare(
        `UPDATE principals SET credential_generation = credential_generation + 1
         WHERE id = ? AND credential_generation >= 1
           AND EXISTS (SELECT 1 FROM oauth_tokens WHERE access_token_hash = ? AND revoked = 0)`,
      ).bind(row.principal_id, accessHash),
    ]);

    // Winner is determined from this statement's own meta.changes (not SQL changes()).
    const casWon = Number(batchResults[0]?.meta?.changes ?? 0) > 0;
    const successorInserted = Number(batchResults[2]?.meta?.changes ?? 0) > 0;
    const generationAdvanced = Number(batchResults[3]?.meta?.changes ?? 0) > 0;
    if (!casWon || !successorInserted || !generationAdvanced) {
      const raced = await this.db.prepare(
        `SELECT refresh_family FROM oauth_tokens WHERE refresh_token_hash = ? AND refresh_used = 1`,
      ).bind(refreshHash).first<{ refresh_family: string }>();
      if (raced) {
        await this.db.batch([
          this.db.prepare(
            `INSERT OR IGNORE INTO revoked_refresh_families (refresh_family, detected_at) VALUES (?, ?)`,
          ).bind(raced.refresh_family, nowIso()),
          this.db.prepare(`UPDATE oauth_tokens SET revoked = 1 WHERE refresh_family = ?`)
            .bind(raced.refresh_family),
          this.db.prepare(
            `UPDATE principals SET credential_generation = credential_generation + 1
             WHERE id = ? AND credential_generation >= 1`,
          ).bind(row.principal_id),
        ]);
        return { ok: false, error: "reuse", description: "refresh token reuse detected" };
      }
      const ledger = await this.db.prepare(
        `SELECT refresh_family FROM used_refresh_tokens WHERE refresh_token_hash = ?`,
      ).bind(refreshHash).first<{ refresh_family: string }>();
      if (ledger) {
        await this.db.batch([
          this.db.prepare(
            `INSERT OR IGNORE INTO revoked_refresh_families (refresh_family, detected_at) VALUES (?, ?)`,
          ).bind(ledger.refresh_family, nowIso()),
          this.db.prepare(`UPDATE oauth_tokens SET revoked = 1 WHERE refresh_family = ?`)
            .bind(ledger.refresh_family),
          this.db.prepare(
            `UPDATE principals SET credential_generation = credential_generation + 1
             WHERE id = ? AND credential_generation >= 1`,
          ).bind(row.principal_id),
        ]);
        return { ok: false, error: "reuse", description: "refresh token reuse detected" };
      }
      return { ok: false, error: "invalid_grant" };
    }

    // Winner: never return a successor that is already revoked / family-compromised.
    const successor = await this.db.prepare(
      `SELECT revoked FROM oauth_tokens WHERE access_token_hash = ?`,
    ).bind(accessHash).first<{ revoked: number }>();
    const familyRevoked = await this.db.prepare(
      `SELECT 1 AS revoked FROM revoked_refresh_families WHERE refresh_family = ?`,
    ).bind(fam).first("revoked");
    if (!successor || successor.revoked || familyRevoked) {
      await this.db.batch([
        this.db.prepare(
          `INSERT OR IGNORE INTO revoked_refresh_families (refresh_family, detected_at) VALUES (?, ?)`,
        ).bind(fam, nowIso()),
        this.db.prepare(`UPDATE oauth_tokens SET revoked = 1 WHERE refresh_family = ?`)
          .bind(fam),
        this.db.prepare(
          `UPDATE principals SET credential_generation = credential_generation + 1
           WHERE id = ? AND credential_generation >= 1`,
        ).bind(row.principal_id),
      ]);
      return { ok: false, error: "reuse", description: "refresh token reuse detected" };
    }

    const principalRecord = await this.getPrincipal(row.principal_id);
    return {
      ok: true,
      token: {
        access_token: access,
        refresh_token: refresh,
        client_id: row.client_id,
        scope: row.scope,
        principal: row.principal_id,
        expires_at: expiresAt,
        refresh_expires_at: refreshExpiresAt,
        revoked: false,
        refresh_family: fam,
        refresh_used: false,
        tenant_id: principalRecord?.tenant_id ?? DEFAULT_TENANT,
      },
    };
  }

  async revokeToken(token: string): Promise<void> {
    const hash = await sha256Hex(token);
    const column = token.startsWith("rtk_") ? "refresh_token_hash" : "access_token_hash";
    const row = await this.db.prepare(
      `SELECT principal_id, revoked FROM oauth_tokens WHERE ${column} = ?`,
    ).bind(hash).first<{ principal_id: string; revoked: number }>();
    if (!row || row.revoked) return;
    if (!this.db.batch) throw new Error("SqlStore.revokeToken requires db.batch");
    await this.db.batch([
      this.db.prepare(
        `UPDATE principals SET credential_generation = credential_generation + 1
         WHERE id = ? AND credential_generation >= 1
           AND EXISTS (SELECT 1 FROM oauth_tokens WHERE ${column} = ? AND revoked = 0)`,
      ).bind(row.principal_id, hash),
      this.db.prepare(
        `UPDATE oauth_tokens SET revoked = 1 WHERE ${column} = ? AND revoked = 0`,
      ).bind(hash),
    ]);
  }

  async lookupRevocableToken(token: string): Promise<RevocableTokenMeta | null> {
    if (!token) return null;
    const hash = await sha256Hex(token);
    const row = await this.db
      .prepare(
        `SELECT t.client_id, t.principal_id, p.tenant_id
         FROM oauth_tokens t
         JOIN principals p ON p.id = t.principal_id
         WHERE t.access_token_hash = ? OR t.refresh_token_hash = ?
         LIMIT 1`,
      )
      .bind(hash, hash)
      .first<{ client_id: string; principal_id: string; tenant_id: string }>();
    if (!row) return null;
    return {
      tenant_id: row.tenant_id,
      principal_id: row.principal_id,
      client_id: row.client_id,
    };
  }

  async putDeviceCode(rec: DeviceCodeRecord): Promise<void> {
    const hash = await sha256Hex(rec.device_code);
    await this.db
      .prepare(
        `INSERT INTO device_codes
         (device_code_hash, user_code, client_id, scope, verification_uri, interval_sec, expires_at, status, principal_id, last_polled_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        hash,
        rec.user_code.toUpperCase(),
        rec.client_id,
        rec.scope,
        rec.verification_uri,
        rec.interval_sec,
        nowIso(rec.expires_at),
        rec.status,
        rec.principal_id ?? null,
        rec.last_polled_at ? nowIso(rec.last_polled_at) : null,
        nowIso(),
      )
      .run();
  }

  async getDeviceCode(deviceCode: string): Promise<DeviceCodeRecord | null> {
    const hash = await sha256Hex(deviceCode);
    const row = await this.db
      .prepare(
        `SELECT device_code_hash, user_code, client_id, scope, verification_uri, interval_sec, expires_at, status, principal_id, last_polled_at
         FROM device_codes WHERE device_code_hash = ?`,
      )
      .bind(hash)
      .first<{
        user_code: string;
        client_id: string;
        scope: string;
        verification_uri: string;
        interval_sec: number;
        expires_at: string;
        status: string;
        principal_id: string | null;
        last_polled_at: string | null;
      }>();
    if (!row) return null;
    let status = row.status as DeviceCodeRecord["status"];
    if (Date.now() > Date.parse(row.expires_at) && status === "pending") {
      status = "expired";
      await this.db
        .prepare(`UPDATE device_codes SET status = 'expired' WHERE device_code_hash = ?`)
        .bind(hash)
        .run();
    }
    return {
      device_code: deviceCode,
      user_code: row.user_code,
      client_id: row.client_id,
      scope: row.scope,
      verification_uri: row.verification_uri,
      interval_sec: row.interval_sec,
      expires_at: Date.parse(row.expires_at),
      status,
      principal_id: row.principal_id ?? undefined,
      last_polled_at: row.last_polled_at
        ? Date.parse(row.last_polled_at)
        : undefined,
    };
  }

  async getDeviceCodeByUserCode(
    userCode: string,
  ): Promise<DeviceCodeRecord | null> {
    const row = await this.db
      .prepare(
        `SELECT device_code_hash FROM device_codes WHERE user_code = ?`,
      )
      .bind(userCode.toUpperCase())
      .first<{ device_code_hash: string }>();
    if (!row) return null;
    // We cannot reverse the hash; store plaintext device_code is not available.
    // For user-code approve path we only need to update by user_code.
    // Return a stub; callers for approve use approveDeviceCode.
    const full = await this.db
      .prepare(
        `SELECT user_code, client_id, scope, verification_uri, interval_sec, expires_at, status, principal_id, last_polled_at
         FROM device_codes WHERE user_code = ?`,
      )
      .bind(userCode.toUpperCase())
      .first<{
        user_code: string;
        client_id: string;
        scope: string;
        verification_uri: string;
        interval_sec: number;
        expires_at: string;
        status: string;
        principal_id: string | null;
        last_polled_at: string | null;
      }>();
    if (!full) return null;
    return {
      device_code: "", // unknown from user_code path
      user_code: full.user_code,
      client_id: full.client_id,
      scope: full.scope,
      verification_uri: full.verification_uri,
      interval_sec: full.interval_sec,
      expires_at: Date.parse(full.expires_at),
      status: full.status as DeviceCodeRecord["status"],
      principal_id: full.principal_id ?? undefined,
      last_polled_at: full.last_polled_at
        ? Date.parse(full.last_polled_at)
        : undefined,
    };
  }

  async approveDeviceCode(
    userCode: string,
    principalId: string,
  ): Promise<boolean> {
    const row = await this.db.prepare(
      `UPDATE device_codes SET status = 'approved', principal_id = ?
       WHERE user_code = ? AND status = 'pending' AND expires_at > ? RETURNING user_code`,
    ).bind(principalId, userCode.toUpperCase(), nowIso()).first<{ user_code: string }>();
    return Boolean(row);
  }

  async consumeApprovedDeviceCode(deviceCode: string, clientId: string): Promise<DeviceCodeRecord | null> {
    const hash = await sha256Hex(deviceCode);
    const row = await this.db.prepare(
      `UPDATE device_codes SET status = 'consumed'
       WHERE device_code_hash = ? AND client_id = ? AND status = 'approved' AND expires_at > ?
       RETURNING user_code, client_id, scope, verification_uri, interval_sec, expires_at, principal_id, last_polled_at`,
    ).bind(hash, clientId, nowIso()).first<{
      user_code: string; client_id: string; scope: string; verification_uri: string;
      interval_sec: number; expires_at: string; principal_id: string | null; last_polled_at: string | null;
    }>();
    if (!row) return null;
    return { device_code: deviceCode, user_code: row.user_code, client_id: row.client_id,
      scope: row.scope, verification_uri: row.verification_uri, interval_sec: row.interval_sec,
      expires_at: Date.parse(row.expires_at), status: "consumed", principal_id: row.principal_id || undefined,
      last_polled_at: row.last_polled_at ? Date.parse(row.last_polled_at) : undefined };
  }

  async markDeviceCodePolled(deviceCode: string): Promise<void> {
    const hash = await sha256Hex(deviceCode);
    await this.db.prepare(
      `UPDATE device_codes SET last_polled_at = ? WHERE device_code_hash = ? AND status = 'pending'`,
    ).bind(nowIso(), hash).run();
  }

  async putDeviceVerificationTransaction(tx: DeviceVerificationTransaction): Promise<void> {
    await this.db.prepare(
      `INSERT INTO device_verification_transactions
       (id, csrf_hash, user_code, principal_id, client_id, scope, expires_at, consumed, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
    ).bind(tx.id, tx.csrf_hash, tx.user_code, tx.principal_id, tx.client_id, tx.scope,
      nowIso(tx.expires_at), nowIso()).run();
  }

  async consumeDeviceVerificationTransaction(
    id: string,
    csrfHash: string,
    principalId: string,
    decision: "approve" | "deny" = "approve",
  ): Promise<DeviceVerificationTransaction | null> {
    // Atomic CAS: consume verification tx + decide matching device code in one batch.
    // Fail closed when batch/transactions are unavailable (no sequential fallback).
    if (!this.db.batch) {
      throw new Error("SqlStore.consumeDeviceVerificationTransaction requires db.batch");
    }
    const ts = nowIso();
    type BatchResult = { meta?: { changes?: number }; success?: boolean };
    const decide = decision === "approve"
      ? this.db.prepare(
        `UPDATE device_codes SET status = 'approved', principal_id = ?
         WHERE status = 'pending' AND expires_at > ?
           AND EXISTS (
             SELECT 1 FROM device_verification_transactions vtx
             WHERE vtx.id = ? AND vtx.csrf_hash = ? AND vtx.principal_id = ? AND vtx.consumed = 1
               AND vtx.user_code = device_codes.user_code
               AND vtx.client_id = device_codes.client_id
               AND vtx.scope = device_codes.scope
           )`,
      ).bind(principalId, ts, id, csrfHash, principalId)
      : this.db.prepare(
        `UPDATE device_codes SET status = 'denied', principal_id = NULL
         WHERE status = 'pending' AND expires_at > ?
           AND EXISTS (
             SELECT 1 FROM device_verification_transactions vtx
             WHERE vtx.id = ? AND vtx.csrf_hash = ? AND vtx.principal_id = ? AND vtx.consumed = 1
               AND vtx.user_code = device_codes.user_code
               AND vtx.client_id = device_codes.client_id
               AND vtx.scope = device_codes.scope
           )`,
      ).bind(ts, id, csrfHash, principalId);
    const batchResults = await this.db.batch<BatchResult>([
      this.db.prepare(
        `UPDATE device_verification_transactions SET consumed = 1
         WHERE id = ? AND csrf_hash = ? AND principal_id = ? AND consumed = 0 AND expires_at > ?
           AND EXISTS (
             SELECT 1 FROM device_codes dc
             WHERE dc.user_code = device_verification_transactions.user_code
               AND dc.client_id = device_verification_transactions.client_id
               AND dc.scope = device_verification_transactions.scope
               AND dc.status = 'pending' AND dc.expires_at > ?
           )`,
      ).bind(id, csrfHash, principalId, ts, ts),
      decide,
    ]);
    // Only the CAS winner mutates rows; losers must not observe the winner's final state as success.
    const consumed = Number(batchResults[0]?.meta?.changes ?? 0) > 0;
    const decided = Number(batchResults[1]?.meta?.changes ?? 0) > 0;
    if (!consumed || !decided) return null;
    const row = await this.db.prepare(
      `SELECT user_code, client_id, scope, expires_at
       FROM device_verification_transactions
       WHERE id = ? AND csrf_hash = ? AND principal_id = ? AND consumed = 1`,
    ).bind(id, csrfHash, principalId).first<{
      user_code: string; client_id: string; scope: string; expires_at: string;
    }>();
    if (!row) return null;
    return {
      id,
      csrf_hash: csrfHash,
      user_code: row.user_code,
      principal_id: principalId,
      client_id: row.client_id,
      scope: row.scope,
      expires_at: Date.parse(row.expires_at),
      consumed: true,
    };
  }

  async putAuthorizeTransaction(tx: AuthorizeTransaction): Promise<void> {
    await this.db.prepare(
      `INSERT INTO authorize_transactions
       (id, csrf_hash, principal_id, tenant_id, client_id, redirect_uri, scope, state,
        code_challenge, code_challenge_method, expires_at, consumed, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
    ).bind(
      tx.id, tx.csrf_hash, tx.principal_id, tx.tenant_id, tx.client_id, tx.redirect_uri,
      tx.scope, tx.state, tx.code_challenge, tx.code_challenge_method,
      nowIso(tx.expires_at), nowIso(),
    ).run();
  }

  async consumeAuthorizeTransaction(id: string, csrfHash: string, principalId: string): Promise<AuthorizeTransaction | null> {
    // Atomic CAS: only one concurrent consumer wins (UPDATE...RETURNING).
    const row = await this.db.prepare(
      `UPDATE authorize_transactions SET consumed = 1
       WHERE id = ? AND csrf_hash = ? AND principal_id = ? AND consumed = 0 AND expires_at > ?
       RETURNING tenant_id, client_id, redirect_uri, scope, state,
                 code_challenge, code_challenge_method, expires_at`,
    ).bind(id, csrfHash, principalId, nowIso()).first<{
      tenant_id: string; client_id: string; redirect_uri: string; scope: string; state: string;
      code_challenge: string; code_challenge_method: string; expires_at: string;
    }>();
    if (!row) return null;
    return {
      id,
      csrf_hash: csrfHash,
      principal_id: principalId,
      tenant_id: row.tenant_id,
      client_id: row.client_id,
      redirect_uri: row.redirect_uri,
      scope: row.scope,
      state: row.state,
      code_challenge: row.code_challenge,
      code_challenge_method: row.code_challenge_method,
      expires_at: Date.parse(row.expires_at),
      consumed: true,
    };
  }

  async putDevice(device: DeviceRecord): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR REPLACE INTO devices
         (id, tenant_id, principal_id, name, labels_json, public_key, revoked, created_at, last_seen_at, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        device.id,
        device.tenant_id,
        device.principal_id,
        device.name,
        JSON.stringify(device.labels ?? []),
        device.public_key,
        device.revoked ? 1 : 0,
        device.created_at,
        device.last_seen_at ?? null,
        device.status,
      )
      .run();
    // Extended metadata in audit-friendly side channel via grants table note is not ideal;
    // store hostname/os in name suffix is bad. Use grants resource JSON? Better: put JSON in public_key field? No.
    // 0001 schema is limited; store extended fields as audit meta and encode in name is wrong.
    // We'll store a JSON blob in public_key? No.
    // Add columns via migration - we already have 0001. Use resource field on a side table via grants:
    // Actually put extended metadata into audit and keep public_key pure.
    // For list/get we need hostname etc. Store as JSON after public_key with delimiter? Ugly.
    // Extend devices via migration 0002 — add columns if missing.
  }

  async getDevice(id: string): Promise<DeviceRecord | null> {
    const row = await this.db
      .prepare(
        `SELECT id, tenant_id, principal_id, name, labels_json, public_key, revoked, created_at, last_seen_at, status FROM devices WHERE id = ?`,
      )
      .bind(id)
      .first<{
        id: string;
        tenant_id: string;
        principal_id: string;
        name: string;
        labels_json: string;
        public_key: string;
        revoked: number;
        created_at: string;
        last_seen_at: string | null;
        status: "pending" | "active" | "revoked";
      }>();
    if (!row) return null;
    const meta = parseDeviceMeta(row.public_key);
    return {
      id: row.id,
      tenant_id: row.tenant_id,
      principal_id: row.principal_id,
      name: row.name,
      labels: parseDeviceLabels(row.labels_json),
      hostname: meta.hostname || row.name,
      os: meta.os || "unknown",
      arch: meta.arch || "unknown",
      agent_version: meta.agent_version || "0",
      protocol_version: meta.protocol_version || "ownmesh.device/1.0",
      enforce_workspace: meta.enforce_workspace,
      public_key: meta.public_key || row.public_key,
      revoked: Boolean(row.revoked),
      created_at: row.created_at,
      last_seen_at: row.last_seen_at ?? undefined,
      status: row.status,
      enrollment_status: row.status,
    };
  }

  async listDevices(principalId: string): Promise<DeviceRecord[]> {
    const res = await this.db
      .prepare(
        `SELECT id, tenant_id, principal_id, name, labels_json, public_key, revoked, created_at, last_seen_at, status
         FROM devices WHERE principal_id = ? AND revoked = 0`,
      )
      .bind(principalId)
      .all<{
        id: string;
        tenant_id: string;
        principal_id: string;
        name: string;
        labels_json: string;
        public_key: string;
        revoked: number;
        created_at: string;
        last_seen_at: string | null;
        status: "pending" | "active" | "revoked";
      }>();
    return (res.results || []).map((row) => {
      const meta = parseDeviceMeta(row.public_key);
      return {
        id: row.id,
        tenant_id: row.tenant_id,
        principal_id: row.principal_id,
        name: row.name,
        labels: parseDeviceLabels(row.labels_json),
        hostname: meta.hostname || row.name,
        os: meta.os || "unknown",
        arch: meta.arch || "unknown",
        agent_version: meta.agent_version || "0",
        protocol_version: meta.protocol_version || "ownmesh.device/1.0",
        enforce_workspace: meta.enforce_workspace,
        public_key: meta.public_key || row.public_key,
        revoked: Boolean(row.revoked),
        created_at: row.created_at,
        last_seen_at: row.last_seen_at ?? undefined,
        status: row.status,
        enrollment_status: row.status,
      };
    });
  }

  async updateDeviceMetadata(
    id: string,
    principalId: string,
    patch: { name?: string; labels?: string[] },
  ): Promise<DeviceRecord | null> {
    let statement: SqlStatement;
    if (patch.name !== undefined && patch.labels !== undefined) {
      statement = this.db
        .prepare(
          `UPDATE devices SET name = ?, labels_json = ?
           WHERE id = ? AND principal_id = ? AND revoked = 0`,
        )
        .bind(patch.name, JSON.stringify(patch.labels), id, principalId);
    } else if (patch.name !== undefined) {
      statement = this.db
        .prepare(
          `UPDATE devices SET name = ?
           WHERE id = ? AND principal_id = ? AND revoked = 0`,
        )
        .bind(patch.name, id, principalId);
    } else if (patch.labels !== undefined) {
      statement = this.db
        .prepare(
          `UPDATE devices SET labels_json = ?
           WHERE id = ? AND principal_id = ? AND revoked = 0`,
        )
        .bind(JSON.stringify(patch.labels), id, principalId);
    } else {
      return null;
    }
    const updated = await statement.run();
    if (sqlChanges(updated) !== 1) return null;
    return this.getDevice(id);
  }

  async recordDeviceReadyConnection(
    id: string,
    patch: {
      agent_version?: string;
      protocol_version: string;
      last_seen_at: string;
      enforce_workspace?: boolean;
    },
  ): Promise<DeviceRecord | null> {
    const device = await this.getDevice(id);
    if (!device || device.revoked || device.status !== "active") return null;
    if (!shouldRecordReadyConnection(device, patch)) return device;
    const publicKey = encodeDevicePublicKey(device.public_key, {
      hostname: device.hostname,
      os: device.os,
      arch: device.arch,
      agent_version: patch.agent_version || device.agent_version,
      protocol_version: patch.protocol_version,
      enforce_workspace: patch.enforce_workspace ?? device.enforce_workspace,
    });
    const updated = await this.db
      .prepare(
        `UPDATE devices
         SET public_key = CASE
               WHEN last_seen_at IS NULL OR last_seen_at < ? THEN ?
               ELSE public_key
             END,
             last_seen_at = CASE
               WHEN last_seen_at IS NULL OR last_seen_at < ? THEN ?
               ELSE last_seen_at
             END
         WHERE id = ? AND revoked = 0 AND status = 'active'`,
      )
      .bind(patch.last_seen_at, publicKey, patch.last_seen_at, patch.last_seen_at, id)
      .run();
    if (sqlChanges(updated) !== 1) return null;
    return this.getDevice(id);
  }

  async revokeDevice(id: string, principalId: string): Promise<boolean> {
    const d = await this.getDevice(id);
    if (!d || d.principal_id !== principalId) return false;
    await this.db.prepare(`UPDATE devices SET revoked = 1, status = 'revoked' WHERE id = ?`).bind(id).run();
    await this.db.prepare(`UPDATE device_credentials SET revoked = 1 WHERE device_id = ?`).bind(id).run();
    return true;
  }

  async activateDeviceWithChallenge(deviceId: string, challengeId: string): Promise<boolean> {
    const claimed = await this.db.prepare(
      `UPDATE enrollment_challenges SET consumed = 1
       WHERE id = ? AND device_id = ? AND consumed = 0 AND expires_at > ? RETURNING id`,
    ).bind(challengeId, deviceId, nowIso()).first<{ id: string }>();
    if (!claimed) return false;
    const activated = await this.db.prepare(
      `UPDATE devices SET status = 'active' WHERE id = ? AND status = 'pending' AND revoked = 0 RETURNING id`,
    ).bind(deviceId).first<{ id: string }>();
    return Boolean(activated);
  }

  async activateDeviceAndIssueCredential(deviceId: string, challengeId: string, ttlMs = 30 * 24 * 60 * 60 * 1000): Promise<{ token: string; expires_at: number } | null> {
    // Atomic CAS: pending→active + credential insert in one batch. Fail closed without batch.
    if (!this.db.batch) {
      throw new Error("SqlStore.activateDeviceAndIssueCredential requires db.batch");
    }
    const token = randomToken("dcred_");
    const hash = await sha256Hex(token);
    const expires_at = Date.now() + ttlMs;
    await this.db.batch([
      this.db.prepare(
        `INSERT INTO device_credentials (credential_hash, device_id, tenant_id, principal_id, role, expires_at, revoked, created_at)
         SELECT ?, d.id, d.tenant_id, d.principal_id, 'agent', ?, 0, ?
         FROM devices d JOIN enrollment_challenges c ON c.device_id = d.id
         WHERE d.id = ? AND d.status = 'pending' AND d.revoked = 0
           AND c.id = ? AND c.consumed = 0 AND c.expires_at > ?`,
      ).bind(hash, nowIso(expires_at), nowIso(), deviceId, challengeId, nowIso()),
      this.db.prepare(
        `UPDATE enrollment_challenges SET consumed = 1
         WHERE id = ? AND device_id = ? AND consumed = 0
           AND EXISTS (SELECT 1 FROM device_credentials WHERE credential_hash = ?)`,
      ).bind(challengeId, deviceId, hash),
      this.db.prepare(
        `UPDATE devices SET status = 'active'
         WHERE id = ? AND status = 'pending' AND revoked = 0
           AND EXISTS (SELECT 1 FROM device_credentials WHERE credential_hash = ?)`,
      ).bind(deviceId, hash),
    ]);
    const created = await this.db.prepare(`SELECT 1 AS ok FROM device_credentials WHERE credential_hash = ?`)
      .bind(hash).first<{ ok: number }>();
    return created ? { token, expires_at } : null;
  }

  async issueDeviceCredential(device: DeviceRecord, ttlMs = 30 * 24 * 60 * 60 * 1000): Promise<{ token: string; expires_at: number }> {
    if (device.revoked || device.status !== "active") throw new Error("device must be active before credential issuance");
    const token = randomToken("dcred_");
    const hash = await sha256Hex(token);
    const expires_at = Date.now() + ttlMs;
    await this.db.prepare(
      `INSERT INTO device_credentials (credential_hash, device_id, tenant_id, principal_id, role, expires_at, revoked, created_at)
       VALUES (?, ?, ?, ?, 'agent', ?, 0, ?)`,
    ).bind(hash, device.id, device.tenant_id, device.principal_id, nowIso(expires_at), nowIso()).run();
    return { token, expires_at };
  }

  async getDeviceCredential(token: string): Promise<DeviceCredentialRecord | null> {
    const hash = await sha256Hex(token);
    const row = await this.db.prepare(
      `SELECT c.device_id, c.tenant_id, c.principal_id, c.role, c.expires_at, c.revoked
       FROM device_credentials c JOIN devices d ON d.id = c.device_id
       WHERE c.credential_hash = ? AND c.revoked = 0 AND c.expires_at > ?
         AND d.status = 'active' AND d.revoked = 0`,
    ).bind(hash, nowIso()).first<{
      device_id: string; tenant_id: string; principal_id: string; role: "agent"; expires_at: string; revoked: number;
    }>();
    if (!row) return null;
    return { ...row, expires_at: Date.parse(row.expires_at), revoked: Boolean(row.revoked) };
  }

  async validateDeviceSession(authHash: string, role: "agent" | "client", deviceId: string): Promise<boolean> {
    if (role === "agent") {
      const row = await this.db.prepare(
        `SELECT 1 AS ok FROM device_credentials c JOIN devices d ON d.id = c.device_id
         WHERE c.credential_hash = ? AND c.device_id = ? AND c.revoked = 0 AND c.expires_at > ?
           AND d.revoked = 0 AND d.status = 'active'`,
      ).bind(authHash, deviceId, nowIso()).first<{ ok: number }>();
      return Boolean(row);
    }
    const row = await this.db.prepare(
      `SELECT 1 AS ok FROM oauth_tokens t
       JOIN principals p ON p.id = t.principal_id
       JOIN devices d ON d.id = ? AND d.principal_id = t.principal_id AND d.tenant_id = p.tenant_id
       WHERE t.access_token_hash = ? AND t.revoked = 0 AND t.expires_at > ?
         AND d.revoked = 0 AND d.status = 'active'`,
    ).bind(deviceId, authHash, nowIso()).first<{ ok: number }>();
    return Boolean(row);
  }

  async putEnrollmentChallenge(ch: EnrollmentChallenge): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO enrollment_challenges (id, device_id, nonce, message, expires_at, consumed, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        ch.id,
        ch.device_id,
        ch.nonce,
        ch.message,
        ch.expires_at,
        ch.consumed ? 1 : 0,
        nowIso(),
      )
      .run();
  }

  async getEnrollmentChallenge(
    id: string,
  ): Promise<EnrollmentChallenge | null> {
    const row = await this.db
      .prepare(
        `SELECT id, device_id, nonce, message, expires_at, consumed FROM enrollment_challenges WHERE id = ?`,
      )
      .bind(id)
      .first<{
        id: string;
        device_id: string;
        nonce: string;
        message: string;
        expires_at: string;
        consumed: number;
      }>();
    if (!row) return null;
    return {
      id: row.id,
      device_id: row.device_id,
      nonce: row.nonce,
      message: row.message,
      expires_at: row.expires_at,
      consumed: Boolean(row.consumed),
    };
  }

  async consumeEnrollmentChallenge(id: string): Promise<boolean> {
    const row = await this.db.prepare(
      `UPDATE enrollment_challenges SET consumed = 1
       WHERE id = ? AND consumed = 0 AND expires_at > ? RETURNING id`,
    ).bind(id, nowIso()).first<{ id: string }>();
    return Boolean(row);
  }

  async putGrant(grant: GrantRecord): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR REPLACE INTO grants (id, tenant_id, principal_id, capability, resource, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        grant.id,
        grant.tenant_id,
        grant.principal_id,
        grant.capability,
        grant.resource ?? null,
        grant.expires_at ?? null,
        grant.created_at,
      )
      .run();
  }

  async listGrants(principalId: string): Promise<GrantRecord[]> {
    const res = await this.db
      .prepare(
        `SELECT id, tenant_id, principal_id, capability, resource, expires_at, created_at FROM grants WHERE principal_id = ?`,
      )
      .bind(principalId)
      .all<GrantRecord>();
    return res.results || [];
  }

  async revokeGrant(id: string): Promise<void> {
    await this.db.prepare(`DELETE FROM grants WHERE id = ?`).bind(id).run();
  }

  async appendAudit(event: AuditEvent): Promise<void> {
    const summary =
      event.meta && Object.keys(event.meta).length
        ? `${event.summary} | ${JSON.stringify(event.meta)}`
        : event.summary;
    await this.db
      .prepare(
        `INSERT INTO audit_events (id, tenant_id, principal_id, device_id, kind, summary, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        event.id,
        event.tenant_id,
        event.principal_id ?? null,
        event.device_id ?? null,
        event.kind,
        summary,
        event.created_at,
      )
      .run();
  }

  async listAudit(tenantId: string, limit = 50): Promise<AuditEvent[]> {
    const res = await this.db
      .prepare(
        `SELECT id, tenant_id, principal_id, device_id, kind, summary, created_at
         FROM audit_events WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?`,
      )
      .bind(tenantId, limit)
      .all<AuditEvent>();
    return res.results || [];
  }

  /**
   * Compact expired terminal rows. Keyed receipts become 30-day tombstones;
   * keyless rows (and leftover keyless tombstones) are hard-deleted.
   */
  private async compactMcpOperations(tenantId: string): Promise<void> {
    const now = Date.now();
    const resultCutoff = new Date(now - MCP_OPS_RESULT_TTL_MS).toISOString();
    const tombstoneCutoff = new Date(now - MCP_OPS_TOMBSTONE_TTL_MS).toISOString();

    // Drop keyless tombstones (no binding) and keyed tombstones past the 30d window.
    await this.db
      .prepare(
        `DELETE FROM mcp_operations
         WHERE tenant_id = ? AND status = 'tombstone'
           AND (idempotency_key IS NULL OR idempotency_key = '' OR updated_at < ?)`,
      )
      .bind(tenantId, tombstoneCutoff)
      .run();

    // Hard-delete keyless terminal results past TTL — they occupy quota for no replay benefit.
    await this.db
      .prepare(
        `DELETE FROM mcp_operations
         WHERE tenant_id = ?
           AND status IN ('completed','failed','denied','cancelled','device_offline')
           AND updated_at < ?
           AND (idempotency_key IS NULL OR idempotency_key = '')`,
      )
      .bind(tenantId, resultCutoff)
      .run();

    // Compact keyed terminal results past TTL into idempotency tombstones.
    // Keep payload_hash/idempotency_key columns; clear large result bodies only.
    await this.db
      .prepare(
        `UPDATE mcp_operations
         SET status = 'tombstone',
             summary = 'tombstone: result TTL expired; idempotency retained',
             data_json = '{"tombstone":true}',
             truncated = 1,
             warnings_json = '["durable_result_tombstoned"]',
             updated_at = ?
         WHERE tenant_id = ?
           AND status IN ('completed','failed','denied','cancelled','device_offline')
           AND updated_at < ?
           AND idempotency_key IS NOT NULL
           AND idempotency_key != ''`,
      )
      .bind(new Date(now).toISOString(), tenantId, resultCutoff)
      .run();
  }

  /** Compact expired terminal rows; preserve idempotency keys as tombstones. */
  private async enforceMcpOperationQuota(tenantId: string): Promise<void> {
    await this.compactMcpOperations(tenantId);

    const countRow = await this.db
      .prepare(`SELECT COUNT(*) AS c FROM mcp_operations WHERE tenant_id = ?`)
      .bind(tenantId)
      .first<{ c: number }>();
    const count = Number(countRow?.c ?? 0);
    if (count < this.mcpOpsLimit) return;

    // E3: never evict unexpired idempotency receipts (including <30d tombstones)
    // under quota pressure. Ancient tombstones were already hard-deleted above;
    // remaining overflow must fail closed rather than enable side-effect replay.
    throw new Error(`mcp_operation_quota_exceeded:tenant=${tenantId}:max=${this.mcpOpsLimit}`);
  }

  /** Create-only INSERT. Conflict (existing operation_id) fails — never REPLACE. */
  async putMcpOperation(op: McpOperationRecord): Promise<void> {
    await this.enforceMcpOperationQuota(op.tenant_id);
    const bounded = boundMcpOperationRecord(op);
    const result = await this.db
      .prepare(
        `INSERT INTO mcp_operations
         (operation_id, tenant_id, principal_id, device_id, tool, status, summary,
          data_json, truncated, next_cursor, approval_required, approval_url, approval_id,
          session_id, warnings_json, correlation_id, payload_hash, idempotency_key,
          workspace_id, expires_at, claim_version, action_json, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(operation_id) DO NOTHING`,
      )
      .bind(
        bounded.operation_id,
        bounded.tenant_id,
        bounded.principal_id,
        bounded.device_id ?? null,
        bounded.tool,
        bounded.status,
        bounded.summary,
        JSON.stringify(bounded.data || {}),
        bounded.truncated ? 1 : 0,
        bounded.next_cursor ?? null,
        bounded.approval_required ? 1 : 0,
        bounded.approval_url ?? null,
        bounded.approval_id ?? null,
        bounded.session_id ?? null,
        JSON.stringify(bounded.warnings || []),
        bounded.correlation_id ?? null,
        bounded.payload_hash ?? null,
        bounded.idempotency_key ?? null,
        bounded.workspace_id ?? null,
        bounded.expires_at ?? null,
        Number(bounded.claim_version ?? 0),
        JSON.stringify(bounded.action || {}),
        bounded.created_at,
        bounded.updated_at,
      )
      .run();
    const changes = Number(
      (result as { meta?: { changes?: number }; changes?: number }).meta?.changes
        ?? (result as { changes?: number }).changes
        ?? 0,
    );
    if (changes < 1) {
      throw new Error(`mcp_operation_exists:${op.operation_id}`);
    }
  }

  async getMcpOperation(operationId: string): Promise<McpOperationRecord | null> {
    const row = await this.db
      .prepare(`SELECT * FROM mcp_operations WHERE operation_id = ?`)
      .bind(operationId)
      .first<Record<string, unknown>>();
    return row ? rowToMcpOperation(row) : null;
  }

  async getMcpOperationByCorrelation(correlationId: string): Promise<McpOperationRecord | null> {
    const row = await this.db
      .prepare(
        `SELECT * FROM mcp_operations WHERE correlation_id = ? ORDER BY created_at DESC LIMIT 1`,
      )
      .bind(correlationId)
      .first<Record<string, unknown>>();
    return row ? rowToMcpOperation(row) : null;
  }

  async listMcpOperations(opts: {
    tenantId: string;
    principalId: string;
    tool: string;
    limit?: number;
  }): Promise<McpOperationRecord[]> {
    const limit = Math.max(1, Math.min(this.mcpOpsLimit, Math.trunc(opts.limit ?? this.mcpOpsLimit)));
    const rows = await this.db
      .prepare(
        `SELECT * FROM mcp_operations
         WHERE tenant_id = ? AND principal_id = ? AND tool = ?
         ORDER BY created_at DESC, operation_id DESC LIMIT ?`,
      )
      .bind(opts.tenantId, opts.principalId, opts.tool, limit)
      .all<Record<string, unknown>>();
    return (rows.results || []).map(rowToMcpOperation);
  }

  async getMcpOperationByIdempotency(opts: {
    principalId: string;
    tenantId: string;
    deviceId: string;
    idempotencyKey: string;
  }): Promise<McpOperationRecord | null> {
    const row = await this.db
      .prepare(
        `SELECT * FROM mcp_operations
         WHERE principal_id = ? AND tenant_id = ? AND IFNULL(device_id, '') = ?
           AND IFNULL(idempotency_key, '') = ?
         ORDER BY created_at DESC LIMIT 1`,
      )
      .bind(opts.principalId, opts.tenantId, opts.deviceId, opts.idempotencyKey)
      .first<Record<string, unknown>>();
    return row ? rowToMcpOperation(row) : null;
  }

  /**
   * Hard-delete tombstones whose 30-day idempotency window has closed, so an
   * expired key becomes reusable as a fresh operation instead of blocking on a
   * stale tombstone forever. Runs before any existing-row lookup on the claim
   * path; `enforceMcpOperationQuota` also prunes them at capacity.
   */
  private async expireExpiredMcpTombstones(tenantId: string): Promise<void> {
    const tombstoneCutoff = new Date(
      Date.now() - MCP_OPS_TOMBSTONE_TTL_MS,
    ).toISOString();
    await this.db
      .prepare(
        `DELETE FROM mcp_operations
         WHERE tenant_id = ? AND status = 'tombstone'
           AND (idempotency_key IS NULL OR idempotency_key = '' OR updated_at < ?)`,
      )
      .bind(tenantId, tombstoneCutoff)
      .run();
  }

  async claimMcpOperationByIdempotency(
    op: McpOperationRecord,
  ): Promise<
    | { outcome: "created"; op: McpOperationRecord }
    | { outcome: "existing"; op: McpOperationRecord }
  > {
    // P0-B review: expire closed-window tombstones before the existing-row
    // lookup. A tombstone older than MCP_OPS_TOMBSTONE_TTL_MS must not be
    // returned as `existing` indefinitely — the documented lifecycle hard-
    // deletes it and dispatches a retry as a new operation.
    await this.expireExpiredMcpTombstones(op.tenant_id);
    // Idempotent reuse must not be blocked by quota pressure on other keys.
    if (op.idempotency_key) {
      const existing = await this.getMcpOperationByIdempotency({
        principalId: op.principal_id,
        tenantId: op.tenant_id,
        deviceId: op.device_id || "",
        idempotencyKey: op.idempotency_key,
      });
      if (existing) return { outcome: "existing", op: existing };
    }
    const byIdEarly = await this.getMcpOperation(op.operation_id);
    if (byIdEarly) return { outcome: "existing", op: byIdEarly };

    // INSERT OR IGNORE respects PK + partial unique idempotency index.
    await this.enforceMcpOperationQuota(op.tenant_id);
    const bounded = boundMcpOperationRecord(op);
    const result = await this.db
      .prepare(
        `INSERT INTO mcp_operations
         (operation_id, tenant_id, principal_id, device_id, tool, status, summary,
          data_json, truncated, next_cursor, approval_required, approval_url, approval_id,
          session_id, warnings_json, correlation_id, payload_hash, idempotency_key,
          workspace_id, expires_at, claim_version, action_json, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT DO NOTHING`,
      )
      .bind(
        bounded.operation_id,
        bounded.tenant_id,
        bounded.principal_id,
        bounded.device_id ?? null,
        bounded.tool,
        bounded.status,
        bounded.summary,
        JSON.stringify(bounded.data || {}),
        bounded.truncated ? 1 : 0,
        bounded.next_cursor ?? null,
        bounded.approval_required ? 1 : 0,
        bounded.approval_url ?? null,
        bounded.approval_id ?? null,
        bounded.session_id ?? null,
        JSON.stringify(bounded.warnings || []),
        bounded.correlation_id ?? null,
        bounded.payload_hash ?? null,
        bounded.idempotency_key ?? null,
        bounded.workspace_id ?? null,
        bounded.expires_at ?? null,
        Number(bounded.claim_version ?? 0),
        JSON.stringify(bounded.action || {}),
        bounded.created_at,
        bounded.updated_at,
      )
      .run();
    const changes = Number(
      (result as { meta?: { changes?: number }; changes?: number }).meta?.changes
        ?? (result as { changes?: number }).changes
        ?? 0,
    );
    if (changes >= 1) {
      const created = await this.getMcpOperation(op.operation_id);
      if (!created) throw new Error(`mcp_operation_claim_missing:${op.operation_id}`);
      return { outcome: "created", op: created };
    }
    // Conflict: prefer idempotency owner, then same operation_id.
    if (op.idempotency_key) {
      const existing = await this.getMcpOperationByIdempotency({
        principalId: op.principal_id,
        tenantId: op.tenant_id,
        deviceId: op.device_id || "",
        idempotencyKey: op.idempotency_key,
      });
      if (existing) return { outcome: "existing", op: existing };
    }
    const byId = await this.getMcpOperation(op.operation_id);
    if (byId) return { outcome: "existing", op: byId };
    throw new Error(`mcp_operation_claim_conflict:${op.operation_id}`);
  }

  async updateMcpOperation(
    operationId: string,
    patch: Partial<McpOperationRecord>,
    fromStatuses?: string[],
    expectedData?: Record<string, unknown>,
  ): Promise<McpOperationRecord | null> {
    const cur = await this.getMcpOperation(operationId);
    if (!cur) return null;
    if (fromStatuses && fromStatuses.length > 0 && !fromStatuses.includes(cur.status)) return null;
    if (expectedData !== undefined && JSON.stringify(cur.data || {}) !== JSON.stringify(expectedData)) return null;

    const next: McpOperationRecord = boundMcpOperationRecord({
      ...cur,
      ...patch,
      operation_id: cur.operation_id,
      principal_id: patch.principal_id ?? cur.principal_id,
      tenant_id: patch.tenant_id ?? cur.tenant_id,
      data: patch.data ?? cur.data,
      warnings: patch.warnings ?? cur.warnings,
      action: patch.action !== undefined ? patch.action : cur.action,
      policy_authority: "ownmesh_device",
      updated_at: patch.updated_at || nowIso(),
    });

    // CAS via conditional UPDATE.  `expectedData` is used by coordinators
    // whose durable data contains a generation/version marker; status alone
    // is not sufficient to protect concurrent metadata transitions.
    if ((fromStatuses && fromStatuses.length > 0) || expectedData !== undefined) {
      const placeholders = fromStatuses?.map(() => "?").join(",") || "";
      const statusClause = fromStatuses && fromStatuses.length > 0
        ? ` AND status IN (${placeholders})`
        : "";
      const dataClause = expectedData !== undefined ? " AND data_json = ?" : "";
      const result = await this.db
        .prepare(
          `UPDATE mcp_operations SET
             tenant_id = ?, principal_id = ?, device_id = ?, tool = ?, status = ?, summary = ?,
             data_json = ?, truncated = ?, next_cursor = ?, approval_required = ?,
             approval_url = ?, approval_id = ?, session_id = ?, warnings_json = ?,
             correlation_id = ?, payload_hash = ?, idempotency_key = ?, workspace_id = ?,
             expires_at = ?, claim_version = ?, action_json = ?, updated_at = ?
           WHERE operation_id = ?${statusClause}${dataClause}`,
        )
        .bind(
          next.tenant_id,
          next.principal_id,
          next.device_id ?? null,
          next.tool,
          next.status,
          next.summary,
          JSON.stringify(next.data || {}),
          next.truncated ? 1 : 0,
          next.next_cursor ?? null,
          next.approval_required ? 1 : 0,
          next.approval_url ?? null,
          next.approval_id ?? null,
          next.session_id ?? null,
          JSON.stringify(next.warnings || []),
          next.correlation_id ?? null,
          next.payload_hash ?? null,
          next.idempotency_key ?? null,
          next.workspace_id ?? null,
          next.expires_at ?? null,
          Number(next.claim_version ?? 0),
          JSON.stringify(next.action || {}),
          next.updated_at,
          operationId,
          ...(fromStatuses || []),
          ...(expectedData !== undefined ? [JSON.stringify(expectedData)] : []),
        )
        .run();
      const changes = Number((result as { meta?: { changes?: number }; changes?: number }).meta?.changes
        ?? (result as { changes?: number }).changes
        ?? 0);
      if (changes < 1) return null;
      return this.getMcpOperation(operationId);
    }

    // Unconditional field update (still UPDATE-only — never INSERT OR REPLACE).
    const result = await this.db
      .prepare(
        `UPDATE mcp_operations SET
           tenant_id = ?, principal_id = ?, device_id = ?, tool = ?, status = ?, summary = ?,
           data_json = ?, truncated = ?, next_cursor = ?, approval_required = ?,
           approval_url = ?, approval_id = ?, session_id = ?, warnings_json = ?,
           correlation_id = ?, payload_hash = ?, idempotency_key = ?, workspace_id = ?,
           expires_at = ?, claim_version = ?, action_json = ?, updated_at = ?
         WHERE operation_id = ?`,
      )
      .bind(
        next.tenant_id,
        next.principal_id,
        next.device_id ?? null,
        next.tool,
        next.status,
        next.summary,
        JSON.stringify(next.data || {}),
        next.truncated ? 1 : 0,
        next.next_cursor ?? null,
        next.approval_required ? 1 : 0,
        next.approval_url ?? null,
        next.approval_id ?? null,
        next.session_id ?? null,
        JSON.stringify(next.warnings || []),
        next.correlation_id ?? null,
        next.payload_hash ?? null,
        next.idempotency_key ?? null,
        next.workspace_id ?? null,
        next.expires_at ?? null,
        Number(next.claim_version ?? 0),
        JSON.stringify(next.action || {}),
        next.updated_at,
        operationId,
      )
      .run();
    const changes = Number(
      (result as { meta?: { changes?: number }; changes?: number }).meta?.changes
        ?? (result as { changes?: number }).changes
        ?? 0,
    );
    if (changes < 1) return null;
    return this.getMcpOperation(operationId);
  }

  async putMcpApprovalTransaction(tx: McpApprovalTransaction): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO mcp_approval_transactions
         (id, csrf_hash, operation_id, principal_id, tenant_id, device_id,
          expires_at, consumed, decision, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, ?)`,
      )
      .bind(
        tx.id,
        tx.csrf_hash,
        tx.operation_id,
        tx.principal_id,
        tx.tenant_id,
        tx.device_id ?? null,
        nowIso(tx.expires_at),
        tx.created_at || nowIso(),
      )
      .run();
  }

  async consumeMcpApprovalTransaction(
    id: string,
    csrfHash: string,
    principalId: string,
    decision: "approve" | "deny",
  ): Promise<McpApprovalTransaction | null> {
    const row = await this.db
      .prepare(
        `UPDATE mcp_approval_transactions
         SET consumed = 1, decision = ?
         WHERE id = ? AND csrf_hash = ? AND principal_id = ?
           AND consumed = 0 AND expires_at > ?
         RETURNING operation_id, tenant_id, device_id, expires_at, created_at`,
      )
      .bind(decision, id, csrfHash, principalId, nowIso())
      .first<{
        operation_id: string;
        tenant_id: string;
        device_id: string | null;
        expires_at: string;
        created_at: string;
      }>();
    if (!row) return null;
    return {
      id,
      csrf_hash: csrfHash,
      operation_id: row.operation_id,
      principal_id: principalId,
      tenant_id: row.tenant_id,
      device_id: row.device_id || undefined,
      expires_at: Date.parse(row.expires_at),
      consumed: true,
      decision,
      created_at: row.created_at,
    };
  }

  async getMcpApprovalOutbox(id: string): Promise<McpApprovalOutbox | null> {
    try {
      const row = await this.db
        .prepare(
          `SELECT id, operation_id, principal_id, tenant_id, device_id, decision,
                  correlation_id, delivery_status, attempts, last_error,
                  created_at, delivered_at, claimed_at, claim_token, claim_version
           FROM mcp_approval_outbox WHERE id = ?`,
        )
        .bind(id)
        .first<Record<string, unknown>>();
      if (!row) return null;
      return rowToMcpApprovalOutbox(row);
    } catch {
      return null;
    }
  }

  async beginMcpApprovalOutbox(
    id: string,
    csrfHash: string,
    principalId: string,
    decision: "approve" | "deny",
  ): Promise<BeginMcpApprovalOutboxResult | null> {
    const existing = await this.getMcpApprovalOutbox(id);
    if (existing) {
      const txRow = await this.db
        .prepare(
          `SELECT id, csrf_hash, operation_id, principal_id, tenant_id, device_id,
                  expires_at, consumed, decision, created_at
           FROM mcp_approval_transactions WHERE id = ?`,
        )
        .bind(id)
        .first<{
          id: string;
          csrf_hash: string;
          operation_id: string;
          principal_id: string;
          tenant_id: string;
          device_id: string | null;
          expires_at: string;
          consumed: number;
          decision: string | null;
          created_at: string;
        }>();
      if (
        !txRow ||
        txRow.csrf_hash !== csrfHash ||
        txRow.principal_id !== principalId ||
        existing.decision !== decision
      ) {
        return null;
      }
      const tx: McpApprovalTransaction = {
        id: txRow.id,
        csrf_hash: txRow.csrf_hash,
        operation_id: txRow.operation_id,
        principal_id: txRow.principal_id,
        tenant_id: txRow.tenant_id,
        device_id: txRow.device_id || undefined,
        expires_at: Date.parse(txRow.expires_at),
        consumed: Boolean(txRow.consumed),
        decision: (txRow.decision as "approve" | "deny" | undefined) || decision,
        created_at: txRow.created_at,
      };
      if (existing.delivery_status === "delivered") {
        return { status: "already_delivered", outbox: existing };
      }
      return { status: "pending_retry", outbox: existing, tx };
    }

    // Atomic consume + outbox insert in one D1 batch (no consumed-without-outbox window).
    if (!this.db.batch) {
      throw new Error("SqlStore.beginMcpApprovalOutbox requires db.batch");
    }
    if (decision !== "approve" && decision !== "deny") return null;

    const createdAt = nowIso();
    const correlationId = `cor_${id}`;
    type BatchResult = { meta?: { changes?: number }; success?: boolean };

    try {
      const batchResults = await this.db.batch<BatchResult>([
        this.db
          .prepare(
            `UPDATE mcp_approval_transactions
             SET consumed = 1, decision = ?
             WHERE id = ? AND csrf_hash = ? AND principal_id = ?
               AND consumed = 0 AND expires_at > ?
               AND NOT EXISTS (
                 SELECT 1 FROM mcp_approval_outbox o
                 WHERE o.id = mcp_approval_transactions.id
                    OR o.operation_id = mcp_approval_transactions.operation_id
               )`,
          )
          .bind(decision, id, csrfHash, principalId, createdAt),
        this.db
          .prepare(
            `INSERT INTO mcp_approval_outbox
             (id, operation_id, principal_id, tenant_id, device_id, decision,
              correlation_id, delivery_status, attempts, last_error, created_at, delivered_at)
             SELECT ?, operation_id, principal_id, tenant_id, device_id, decision,
                    ?, 'pending', 0, NULL, ?, NULL
             FROM mcp_approval_transactions
             WHERE id = ? AND csrf_hash = ? AND principal_id = ?
               AND consumed = 1 AND decision = ?
               AND NOT EXISTS (
                 SELECT 1 FROM mcp_approval_outbox o
                 WHERE o.id = ? OR o.operation_id = mcp_approval_transactions.operation_id
               )`,
          )
          .bind(id, correlationId, createdAt, id, csrfHash, principalId, decision, id),
      ]);

      const consumed = sqlChanges(batchResults[0]) > 0;
      const inserted = sqlChanges(batchResults[1]) > 0;
      if (consumed && inserted) {
        const outbox = await this.getMcpApprovalOutbox(id);
        const txRow = await this.db
          .prepare(
            `SELECT id, csrf_hash, operation_id, principal_id, tenant_id, device_id,
                    expires_at, consumed, decision, created_at
             FROM mcp_approval_transactions WHERE id = ?`,
          )
          .bind(id)
          .first<{
            id: string;
            csrf_hash: string;
            operation_id: string;
            principal_id: string;
            tenant_id: string;
            device_id: string | null;
            expires_at: string;
            consumed: number;
            decision: string | null;
            created_at: string;
          }>();
        if (!outbox || !txRow) return null;
        const tx: McpApprovalTransaction = {
          id: txRow.id,
          csrf_hash: txRow.csrf_hash,
          operation_id: txRow.operation_id,
          principal_id: txRow.principal_id,
          tenant_id: txRow.tenant_id,
          device_id: txRow.device_id || undefined,
          expires_at: Date.parse(txRow.expires_at),
          consumed: Boolean(txRow.consumed),
          decision,
          created_at: txRow.created_at,
        };
        return { status: "created", outbox, tx };
      }
    } catch {
      // UNIQUE/CHECK failure rolls back the batch; resume below if peer won.
    }

    // Lost race: resume authoritative outbox if peer created it.
    const peer = await this.getMcpApprovalOutbox(id);
    if (peer) {
      const txRow = await this.db
        .prepare(
          `SELECT id, csrf_hash, operation_id, principal_id, tenant_id, device_id,
                  expires_at, consumed, decision, created_at
           FROM mcp_approval_transactions WHERE id = ?`,
        )
        .bind(id)
        .first<{
          id: string;
          csrf_hash: string;
          operation_id: string;
          principal_id: string;
          tenant_id: string;
          device_id: string | null;
          expires_at: string;
          consumed: number;
          decision: string | null;
          created_at: string;
        }>();
      if (
        txRow &&
        txRow.csrf_hash === csrfHash &&
        txRow.principal_id === principalId &&
        peer.decision === decision
      ) {
        const tx: McpApprovalTransaction = {
          id: txRow.id,
          csrf_hash: txRow.csrf_hash,
          operation_id: txRow.operation_id,
          principal_id: txRow.principal_id,
          tenant_id: txRow.tenant_id,
          device_id: txRow.device_id || undefined,
          expires_at: Date.parse(txRow.expires_at),
          consumed: Boolean(txRow.consumed),
          decision: peer.decision,
          created_at: txRow.created_at,
        };
        if (peer.delivery_status === "delivered") {
          return { status: "already_delivered", outbox: peer };
        }
        return { status: "pending_retry", outbox: peer, tx };
      }
    }
    return null;
  }

  async claimMcpApprovalOutboxDelivery(id: string): Promise<McpApprovalOutbox | null> {
    const claimTs = nowIso();
    const claimToken = randomToken("clm_");
    const leaseCutoff = new Date(
      Date.now() - MCP_APPROVAL_OUTBOX_CLAIM_LEASE_MS,
    ).toISOString();
    // pending → delivering, or stale delivering (lease expired / missing claimed_at).
    // Fresh claim_token + claim_version++ invalidates any prior owner.
    const result = await this.db
      .prepare(
        `UPDATE mcp_approval_outbox
         SET delivery_status = 'delivering',
             claimed_at = ?,
             claim_token = ?,
             claim_version = COALESCE(claim_version, 0) + 1
         WHERE id = ?
           AND decision IN ('approve', 'deny')
           AND (
             delivery_status = 'pending'
             OR (
               delivery_status = 'delivering'
               AND (claimed_at IS NULL OR claimed_at <= ?)
             )
           )`,
      )
      .bind(claimTs, claimToken, id, leaseCutoff)
      .run();
    if (sqlChanges(result) < 1) return null;
    return this.getMcpApprovalOutbox(id);
  }

  async releaseMcpApprovalOutboxClaim(
    id: string,
    claimToken: string,
    claimVersion: number,
    error?: string,
  ): Promise<void> {
    if (!claimToken || !Number.isFinite(Number(claimVersion))) return;
    await this.db
      .prepare(
        `UPDATE mcp_approval_outbox
         SET delivery_status = 'pending',
             attempts = attempts + 1,
             last_error = ?,
             claimed_at = NULL,
             claim_token = NULL
         WHERE id = ? AND delivery_status = 'delivering'
           AND claim_token = ? AND claim_version = ?`,
      )
      .bind(error ?? null, id, claimToken, Number(claimVersion))
      .run();
  }

  async recordMcpApprovalOutboxAttempt(id: string, error?: string): Promise<void> {
    // Delivering claims must be released via releaseMcpApprovalOutboxClaim (owner token).
    await this.db
      .prepare(
        `UPDATE mcp_approval_outbox
         SET attempts = attempts + 1, last_error = ?
         WHERE id = ? AND delivery_status = 'pending'`,
      )
      .bind(error ?? null, id)
      .run();
  }

  async finalizeMcpApprovalDelivery(
    id: string,
    claimToken: string,
    claimVersion: number,
  ): Promise<McpOperationRecord | null> {
    if (!claimToken || !Number.isFinite(Number(claimVersion))) return null;
    const outbox = await this.getMcpApprovalOutbox(id);
    if (!outbox || outbox.delivery_status !== "delivering") return null;
    if (outbox.claim_token !== claimToken) return null;
    if (Number(outbox.claim_version) !== Number(claimVersion)) return null;

    const op = await this.getMcpOperation(outbox.operation_id);
    if (!op) return null;

    const ts = nowIso();
    const summary = "human decision delivered; awaiting authoritative device result";
    const nextData = {
      ...(op.data || {}),
      approval_decision: outbox.decision,
      approval_transaction_id: outbox.id,
    };

    if (!this.db.batch) {
      throw new Error("SqlStore.finalizeMcpApprovalDelivery requires db.batch");
    }

    type BatchResult = { meta?: { changes?: number }; success?: boolean };

    // Transactional finalize: owner-gated outbox mark + conditional op CAS.
    // Op CAS is gated on current claim ownership so mismatch leaves no state change.
    const batchResults = await this.db.batch<BatchResult>([
      this.db
        .prepare(
          `UPDATE mcp_operations SET
             summary = ?, data_json = ?, updated_at = ?
           WHERE operation_id = ? AND status = 'approval_required'
             AND EXISTS (
               SELECT 1 FROM mcp_approval_outbox o
               WHERE o.id = ? AND o.delivery_status = 'delivering'
                 AND o.claim_token = ? AND o.claim_version = ?
             )`,
        )
        .bind(
          summary,
          JSON.stringify(nextData),
          ts,
          outbox.operation_id,
          id,
          claimToken,
          Number(claimVersion),
        ),
      this.db
        .prepare(
          `UPDATE mcp_approval_outbox
           SET delivery_status = 'delivered', delivered_at = ?, attempts = attempts + 1,
               last_error = NULL
           WHERE id = ? AND delivery_status = 'delivering'
             AND claim_token = ? AND claim_version = ?`,
        )
        .bind(ts, id, claimToken, Number(claimVersion)),
    ]);

    if (sqlChanges(batchResults[1]) < 1) {
      const peer = await this.getMcpApprovalOutbox(id);
      if (peer?.delivery_status === "delivered") {
        return this.getMcpOperation(outbox.operation_id);
      }
      return null;
    }
    return this.getMcpOperation(outbox.operation_id);
  }

  async putTenantMember(
    tenantId: string,
    principalId: string,
    role: "owner" | "admin" | "member",
  ): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO tenant_members (tenant_id, principal_id, role, created_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(tenant_id, principal_id) DO UPDATE SET role = excluded.role`,
      )
      .bind(tenantId, principalId, role, nowIso())
      .run();
  }

  async isTenantMember(tenantId: string, principalId: string): Promise<boolean> {
    try {
      const row = await this.db
        .prepare(
          `SELECT 1 AS ok FROM tenant_members WHERE tenant_id = ? AND principal_id = ? LIMIT 1`,
        )
        .bind(tenantId, principalId)
        .first<{ ok: number }>();
      return !!row;
    } catch {
      // Missing table/schema fails closed (not a member).
      return false;
    }
  }

  async getTenantMemberRole(
    tenantId: string,
    principalId: string,
  ): Promise<"owner" | "admin" | "member" | null> {
    try {
      const row = await this.db
        .prepare(`SELECT role FROM tenant_members WHERE tenant_id = ? AND principal_id = ? LIMIT 1`)
        .bind(tenantId, principalId)
        .first<{ role: string }>();
      return row?.role === "owner" || row?.role === "admin" || row?.role === "member"
        ? row.role
        : null;
    } catch {
      return null;
    }
  }

  async putWorkspace(workspace: WorkspaceRecord): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO device_workspaces
           (workspace_id, tenant_id, device_id, owner_principal_id, version, local_generation, active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(device_id, workspace_id) DO UPDATE SET
           tenant_id = excluded.tenant_id,
           owner_principal_id = excluded.owner_principal_id, version = excluded.version,
           local_generation = COALESCE(excluded.local_generation, device_workspaces.local_generation),
           active = excluded.active, updated_at = excluded.updated_at`,
      )
      .bind(workspace.workspace_id, workspace.tenant_id, workspace.device_id,
        workspace.owner_principal_id, workspace.version, workspace.local_generation ?? null,
        workspace.active ? 1 : 0,
        workspace.created_at, workspace.updated_at)
      .run();
  }

  async getWorkspace(deviceId: string, workspaceId: string): Promise<WorkspaceRecord | null> {
    try {
      const row = await this.db
        .prepare(`SELECT workspace_id, tenant_id, device_id, owner_principal_id, version, local_generation, active, created_at, updated_at FROM device_workspaces WHERE device_id = ? AND workspace_id = ? LIMIT 1`)
        .bind(deviceId, workspaceId)
        .first<{
          workspace_id: string;
          tenant_id: string;
          device_id: string;
          owner_principal_id: string;
          version: number;
          local_generation: string | null;
          active: number;
          created_at: string;
          updated_at: string;
        }>();
      if (!row) return null;
      const { local_generation, ...base } = row;
      return {
        ...base,
        version: Number(row.version),
        active: Boolean(row.active),
        ...(local_generation ? { local_generation } : {}),
      };
    } catch {
      return null;
    }
  }

  async putWorkspaceMember(
    deviceId: string,
    workspaceId: string,
    principalId: string,
  ): Promise<void> {
    await this.db
      .prepare(`INSERT OR IGNORE INTO device_workspace_members (device_id, workspace_id, principal_id, created_at) VALUES (?, ?, ?, ?)`)
      .bind(deviceId, workspaceId, principalId, nowIso())
      .run();
  }

  async isWorkspaceMember(
    deviceId: string,
    workspaceId: string,
    principalId: string,
  ): Promise<boolean> {
    try {
      const row = await this.db
        .prepare(`SELECT 1 AS ok FROM device_workspace_members WHERE device_id = ? AND workspace_id = ? AND principal_id = ? LIMIT 1`)
        .bind(deviceId, workspaceId, principalId)
        .first<{ ok: number }>();
      return !!row;
    } catch {
      return false;
    }
  }

  async syncDeviceWorkspaces(
    deviceId: string,
    workspaces: AdvertisedWorkspaceRegistration[],
  ): Promise<WorkspaceRecord[]> {
    if (!this.db.batch) {
      throw new Error("SqlStore.syncDeviceWorkspaces requires db.batch");
    }
    const device = await this.getDevice(deviceId);
    if (!device || device.revoked || device.status !== "active") {
      throw new Error("device_not_active");
    }
    const current = await this.db
      .prepare(
        `SELECT workspace_id, tenant_id, device_id, owner_principal_id, version, local_generation, active,
                created_at, updated_at
         FROM device_workspaces WHERE device_id = ?`,
      )
      .bind(deviceId)
      .all<{
        workspace_id: string;
        tenant_id: string;
        device_id: string;
        owner_principal_id: string;
        version: number;
        local_generation: string | null;
        active: number;
        created_at: string;
        updated_at: string;
      }>();
    const byId = new Map((current.results || []).map((row) => [row.workspace_id, row]));
    const observedAt = nowIso();
    const wanted = validateAdvertisedWorkspaces(workspaces);
    const statements: SqlStatement[] = [];
    for (const registration of wanted) {
      const workspaceId = registration.id;
      const row = byId.get(workspaceId);
      if (!row) {
        statements.push(
          this.db
            .prepare(
              `INSERT INTO device_workspaces
                 (workspace_id, tenant_id, device_id, owner_principal_id, version, local_generation, active,
                  created_at, updated_at)
               VALUES (?, ?, ?, ?, 1, ?, 1, ?, ?)`,
            )
            .bind(
              workspaceId,
              device.tenant_id,
              deviceId,
              device.principal_id,
              registration.generation,
              observedAt,
              observedAt,
            ),
        );
      } else if (
        !Boolean(row.active) ||
        (row.local_generation !== null && row.local_generation !== registration.generation)
      ) {
        statements.push(
          this.db
            .prepare(
              `UPDATE device_workspaces
               SET active = 1, version = version + 1, local_generation = ?, updated_at = ?
               WHERE device_id = ? AND workspace_id = ?`,
            )
            .bind(registration.generation, observedAt, deviceId, workspaceId),
        );
      } else if (row.local_generation === null) {
        statements.push(
          this.db
            .prepare(
              `UPDATE device_workspaces
               SET active = 1, version = version + 1, local_generation = ?, updated_at = ?
               WHERE device_id = ? AND workspace_id = ? AND local_generation IS NULL`,
            )
            .bind(registration.generation, observedAt, deviceId, workspaceId),
        );
      }
    }
    if (statements.length > 0) await this.db.batch(statements);
    const rows = await this.db
      .prepare(
        `SELECT workspace_id, tenant_id, device_id, owner_principal_id, version, local_generation, active,
                created_at, updated_at
         FROM device_workspaces WHERE device_id = ? AND active = 1 ORDER BY workspace_id`,
      )
      .bind(deviceId)
      .all<{
        workspace_id: string;
        tenant_id: string;
        device_id: string;
        owner_principal_id: string;
        version: number;
        local_generation: string | null;
        active: number;
        created_at: string;
        updated_at: string;
      }>();
    return (rows.results || []).map((row) => {
      const { local_generation, ...base } = row;
      return {
        ...base,
        version: Number(row.version),
        active: Boolean(row.active),
        ...(local_generation ? { local_generation } : {}),
      };
    });
  }

  async assertWorkspaceOperableForMcp(
    workspaceId: string, deviceId: string, principalId: string, tenantId: string,
  ): Promise<WorkspaceOperableGate> {
    return this.workspaceGate(workspaceId, deviceId, principalId, tenantId, true);
  }

  async assertWorkspaceVisibleForMcp(
    workspaceId: string, deviceId: string, principalId: string, tenantId: string,
  ): Promise<WorkspaceOperableGate> {
    return this.workspaceGate(workspaceId, deviceId, principalId, tenantId, false);
  }

  private async workspaceGate(
    workspaceId: string,
    deviceId: string,
    principalId: string,
    tenantId: string,
    requireActiveGeneration: boolean,
  ): Promise<WorkspaceOperableGate> {
    const workspace = await this.getWorkspace(deviceId, workspaceId);
    const classified = requireActiveGeneration
      ? classifyWorkspaceAvailability(workspace, deviceId, tenantId)
      : classifyWorkspaceVisibility(workspace, deviceId, tenantId);
    if (!classified.ok) return classified;
    const device = await this.getDevice(deviceId);
    const role = await this.getTenantMemberRole(tenantId, principalId);
    const allowed =
      classified.workspace.owner_principal_id === principalId ||
      device?.principal_id === principalId ||
      role === "owner" ||
      role === "admin" ||
      (role === "member" &&
        (await this.isWorkspaceMember(deviceId, classified.workspace.workspace_id, principalId)));
    return allowed
      ? classified
      : {
          ok: false,
          error: "workspace_not_available",
          cause: "not_authorized",
          next_action: "select_active_workspace",
        };
  }

  async observeWorkspaceGeneration(
    deviceId: string,
    workspaceId: string,
    generation: string,
  ): Promise<WorkspaceRecord | null> {
    if (!parseWorkspaceId(workspaceId) || !parseWorkspaceGeneration(generation)) return null;
    const device = await this.getDevice(deviceId);
    if (!device || device.revoked || device.status !== "active") return null;
    const existing = await this.getWorkspace(deviceId, workspaceId);
    const next = applyObservedGeneration(existing, {
      workspaceId,
      deviceId,
      tenantId: device.tenant_id,
      ownerPrincipalId: existing?.owner_principal_id || device.principal_id,
      generation,
      observedAt: nowIso(),
    });
    await this.putWorkspace(next);
    return this.getWorkspace(deviceId, workspaceId);
  }

  async deactivateWorkspace(
    deviceId: string,
    workspaceId: string,
  ): Promise<WorkspaceRecord | null> {
    const existing = await this.getWorkspace(deviceId, workspaceId);
    if (!existing) return null;
    await this.putWorkspace({
      ...existing,
      active: false,
      updated_at: nowIso(),
    });
    return this.getWorkspace(deviceId, workspaceId);
  }

  async recordObservedWorkspaceEnforcement(
    deviceId: string,
    enforceWorkspace: boolean,
  ): Promise<DeviceRecord | null> {
    const device = await this.getDevice(deviceId);
    if (!device || device.revoked || device.status !== "active") return null;
    const publicKey = encodeDevicePublicKey(device.public_key, {
      hostname: device.hostname,
      os: device.os,
      arch: device.arch,
      agent_version: device.agent_version,
      protocol_version: device.protocol_version,
      enforce_workspace: enforceWorkspace,
    });
    const updated = await this.db
      .prepare(
        `UPDATE devices SET public_key = ? WHERE id = ? AND revoked = 0 AND status = 'active'`,
      )
      .bind(publicKey, deviceId)
      .run();
    if (sqlChanges(updated) !== 1) return null;
    return this.getDevice(deviceId);
  }

  async canOperateDevice(
    deviceId: string,
    principalId: string,
    tenantId: string,
  ): Promise<boolean> {
    const device = await this.getDevice(deviceId);
    if (!device || device.tenant_id !== tenantId) return false;
    if (device.principal_id === principalId) return true;
    return this.isTenantMember(tenantId, principalId);
  }

  async assertDeviceOperableForMcp(
    deviceId: string,
    principalId: string,
    tenantId: string,
  ): Promise<{ ok: true } | { ok: false; error: string }> {
    const device = await this.getDevice(deviceId);
    if (!device || device.tenant_id !== tenantId) {
      return { ok: false, error: "device_not_available" };
    }
    const allowed =
      device.principal_id === principalId || (await this.isTenantMember(tenantId, principalId));
    if (!allowed) {
      return { ok: false, error: "device_not_available" };
    }
    if (device.revoked || device.status !== "active") {
      return { ok: false, error: "device_not_available" };
    }
    // When credentials have been issued, at least one must still be valid.
    // Missing/broken credential schema fails closed — never "treat as no credentials".
    try {
      const res = await this.db
        .prepare(
          `SELECT credential_hash, revoked, expires_at FROM device_credentials WHERE device_id = ?`,
        )
        .bind(deviceId)
        .all<{ credential_hash: string; revoked: number; expires_at: string }>();
      const rows = res.results || [];
      if (rows.length > 0) {
        const now = Date.now();
        const anyValid = rows.some(
          (r) => !r.revoked && Date.parse(r.expires_at) > now,
        );
        if (!anyValid) return { ok: false, error: "device_credential_revoked" };
      }
    } catch {
      return { ok: false, error: "device_credentials_unavailable" };
    }
    return { ok: true };
  }

  async appliedMigrations(): Promise<string[]> {
    try {
      const res = await this.db
        .prepare(`SELECT id FROM schema_migrations ORDER BY id`)
        .all<{ id: string }>();
      return (res.results || []).map((r) => r.id);
    } catch {
      return [];
    }
  }

  async markMigration(id: string): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR IGNORE INTO schema_migrations (id, applied_at) VALUES (?, ?)`,
      )
      .bind(id, nowIso())
      .run();
  }

  /**
   * Probe 0002–0008 tables, required columns (SELECT projections), and indexes
   * (sqlite_master). Compatible with D1 (no PRAGMA dependency).
   */
  async schemaReadiness(): Promise<SchemaReadiness> {
    const probeTable = async (
      table: string,
      columns: string[],
    ): Promise<boolean> => {
      try {
        // Throws when the table is missing or any listed column is absent.
        await this.db
          .prepare(`SELECT ${columns.join(", ")} FROM ${table} LIMIT 1`)
          .first();
        return true;
      } catch {
        return false;
      }
    };

    const probeIndex = async (indexName: string): Promise<boolean> => {
      try {
        const row = await this.db
          .prepare(
            `SELECT 1 AS ok FROM sqlite_master WHERE type = 'index' AND name = ? LIMIT 1`,
          )
          .bind(indexName)
          .first<{ ok: number }>();
        return row != null;
      } catch {
        return false;
      }
    };

    const checks = Object.fromEntries(
      Object.keys(SCHEMA_READINESS_OBJECTS).map((k) => [k, false]),
    ) as SchemaReadiness["checks"];

    for (const [key, spec] of Object.entries(SCHEMA_READINESS_OBJECTS) as Array<
      [
        keyof SchemaReadiness["checks"],
        { table: string; columns: string[]; indexes?: string[] },
      ]
    >) {
      const tableOk = await probeTable(spec.table, spec.columns);
      if (!tableOk) {
        checks[key] = false;
        continue;
      }
      let indexesOk = true;
      for (const idx of spec.indexes ?? []) {
        if (!(await probeIndex(idx))) {
          indexesOk = false;
          break;
        }
      }
      checks[key] = indexesOk;
    }

    return {
      schema_ready: Object.values(checks).every(Boolean),
      checks,
    };
  }
}

function isValidOutboxDecision(v: unknown): v is "approve" | "deny" {
  return v === "approve" || v === "deny";
}

function isValidDeliveryStatus(
  v: unknown,
): v is "pending" | "delivering" | "delivered" {
  return v === "pending" || v === "delivering" || v === "delivered";
}

function sqlChanges(result: unknown): number {
  const r = result as { meta?: { changes?: number }; changes?: number } | null | undefined;
  return Number(r?.meta?.changes ?? r?.changes ?? 0);
}

/** Fail-closed: invalid decision/delivery_status values yield null (never coerced). */
function rowToMcpApprovalOutbox(row: Record<string, unknown>): McpApprovalOutbox | null {
  const decision = row.decision;
  const delivery_status = row.delivery_status;
  if (!isValidOutboxDecision(decision) || !isValidDeliveryStatus(delivery_status)) {
    return null;
  }
  return {
    id: String(row.id),
    operation_id: String(row.operation_id),
    principal_id: String(row.principal_id),
    tenant_id: String(row.tenant_id),
    device_id: row.device_id ? String(row.device_id) : undefined,
    decision,
    correlation_id: String(row.correlation_id || ""),
    delivery_status,
    attempts: Number(row.attempts || 0),
    last_error: row.last_error == null ? null : String(row.last_error),
    created_at: String(row.created_at),
    delivered_at: row.delivered_at == null ? null : String(row.delivered_at),
    claimed_at: row.claimed_at == null ? null : String(row.claimed_at),
    claim_token: row.claim_token == null ? null : String(row.claim_token),
    claim_version: Number(row.claim_version || 0),
  };
}

function rowToMcpOperation(row: Record<string, unknown>): McpOperationRecord {
  let data: Record<string, unknown> = {};
  let warnings: string[] = [];
  let action: Record<string, unknown> | null = null;
  try {
    data = JSON.parse(String(row.data_json || "{}")) as Record<string, unknown>;
  } catch {
    data = {};
  }
  try {
    warnings = JSON.parse(String(row.warnings_json || "[]")) as string[];
    if (!Array.isArray(warnings)) warnings = [];
  } catch {
    warnings = [];
  }
  try {
    const parsed = JSON.parse(String(row.action_json || "{}")) as Record<string, unknown>;
    action = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch {
    action = null;
  }
  return {
    operation_id: String(row.operation_id),
    tenant_id: String(row.tenant_id),
    principal_id: String(row.principal_id),
    device_id: row.device_id ? String(row.device_id) : undefined,
    tool: String(row.tool || ""),
    status: String(row.status),
    summary: String(row.summary || ""),
    data,
    truncated: Boolean(Number(row.truncated || 0)),
    next_cursor: row.next_cursor == null ? null : String(row.next_cursor),
    approval_required: Boolean(Number(row.approval_required || 0)),
    approval_url: row.approval_url ? String(row.approval_url) : undefined,
    approval_id: row.approval_id ? String(row.approval_id) : undefined,
    session_id: row.session_id == null ? null : String(row.session_id),
    warnings,
    correlation_id: row.correlation_id ? String(row.correlation_id) : undefined,
    payload_hash: row.payload_hash == null ? null : String(row.payload_hash),
    idempotency_key: row.idempotency_key == null ? null : String(row.idempotency_key),
    workspace_id: row.workspace_id == null ? null : String(row.workspace_id),
    expires_at: row.expires_at == null ? null : String(row.expires_at),
    claim_version: Number(row.claim_version || 0),
    action,
    policy_authority: "ownmesh_device",
    created_at: String(row.created_at),
    updated_at: String(row.updated_at),
  };
}

/** Encode extended device metadata into the public_key column as JSON envelope. */
export function encodeDevicePublicKey(
  publicKey: string,
  meta: {
    hostname?: string;
    os?: string;
    arch?: string;
    agent_version?: string;
    protocol_version?: string;
    enforce_workspace?: boolean;
  },
): string {
  return JSON.stringify({
    public_key: publicKey,
    hostname: meta.hostname,
    os: meta.os,
    arch: meta.arch,
    agent_version: meta.agent_version,
    protocol_version: meta.protocol_version,
    enforce_workspace: meta.enforce_workspace,
  });
}

function parseDeviceMeta(raw: string): {
  public_key?: string;
  hostname?: string;
  os?: string;
  arch?: string;
  agent_version?: string;
  protocol_version?: string;
  enforce_workspace?: boolean;
} {
  if (raw.startsWith("{")) {
    try {
      return JSON.parse(raw) as {
        public_key?: string;
        hostname?: string;
        os?: string;
        arch?: string;
        agent_version?: string;
        protocol_version?: string;
        enforce_workspace?: boolean;
      };
    } catch {
      return { public_key: raw };
    }
  }
  return { public_key: raw };
}

function parseDeviceLabels(raw: string): string[] {
  try {
    const value = JSON.parse(raw) as unknown;
    if (!Array.isArray(value) || !value.every((label) => typeof label === "string")) return [];
    return [...value];
  } catch {
    return [];
  }
}

function hydrateDevice(d: DeviceRecord): DeviceRecord {
  const meta = parseDeviceMeta(d.public_key);
  return {
    ...d,
    enrollment_status: d.status,
    labels: [...(d.labels ?? [])],
    hostname: d.hostname || meta.hostname || d.name,
    os: d.os && d.os !== "unknown" ? d.os : meta.os || "unknown",
    arch: d.arch && d.arch !== "unknown" ? d.arch : meta.arch || "unknown",
    agent_version: d.agent_version || meta.agent_version || "0",
    protocol_version:
      d.protocol_version || meta.protocol_version || "ownmesh.device/1.0",
    enforce_workspace: d.enforce_workspace ?? meta.enforce_workspace,
    public_key: meta.public_key || d.public_key,
  };
}

/** Create store from Worker env. */
export class MissingD1Error extends Error {
  constructor() {
    super("D1 binding DB is required outside explicitly injected tests");
    this.name = "MissingD1Error";
  }
}

export function createStore(env: {
  DB?: D1Database;
  MCP_OPS_MAX_PER_TENANT?: string;
}): ControlPlaneStore {
  if (env.DB) {
    return new SqlStore(env.DB as unknown as SqlDatabase, "d1", {
      mcpOpsMaxPerTenant: env.MCP_OPS_MAX_PER_TENANT,
    });
  }
  throw new MissingD1Error();
}

export { DEFAULT_TENANT, generateUserCode, randomId, randomToken, nowIso };
