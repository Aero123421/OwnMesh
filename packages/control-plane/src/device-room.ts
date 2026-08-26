/**
 * DeviceRoom — per-device Durable Object connection room.
 *
 * Hibernation WebSocket API (Cloudflare):
 *   https://developers.cloudflare.com/durable-objects/best-practices/websockets/
 *   https://developers.cloudflare.com/durable-objects/examples/websocket-hibernation-server/
 *
 * Uses state.acceptWebSocket (not ws.accept) so the DO can hibernate while
 * clients remain connected. Handlers: webSocketMessage / webSocketClose / webSocketError.
 *
 * lastSeq / seenMessageIds / pending are persisted via state.storage() so they
 * survive hibernation. Replay windows and pending entries are pruned by TTL + hard limits.
 *
 * Protocol envelopes: ownmesh.device/1.0 (OWNMESH_SPECIFICATION §21).
 */

import {
  INTERNAL_CONTEXT_REPLAY_MAX,
  internalContextHeaderName,
  json,
  nowIso,
  pruneNonceExpMap,
  randomId,
  randomToken,
  rememberNonceInMap,
  requireScope,
  sha256Hex,
  verifyEd25519Hex,
  verifyInternalContext,
} from "./util.ts";
import { createStore, type ControlPlaneStore, type McpOperationRecord, type WorkspaceRecord } from "./store.ts";
import {
  authorityInvalidationError,
  authorityInvalidationSummary,
  boundAuthorityInvalidationReason,
  boundPrincipalAuthority,
  boundPrincipalAuthorityCurrent,
  normalizeSystemDiagnosis,
} from "./mcp.ts";
import {
  annotatePolicyObservation,
  annotateWorkspaceList,
  annotateWorkspaceRecord,
  parseWorkspaceGeneration,
  parseWorkspaceId,
} from "./workspace-activation.ts";
import { parseTransferPreflightResult, type TransferServerBinding } from "./transfer-orchestrator.ts";

export const PROTOCOL = "ownmesh.device/1.0";
/** Independent operation payload contract (must match Rust/TS schema packages). */
export const OPERATION_CONTRACT_V1 = "ownmesh.operation/1.0";
/** Default operation.request lifetime when the caller does not supply expires_at. */
export const OPERATION_REQUEST_TTL_MS = 60_000;

/** States that must never be dispatched or resurrected from room persistence. */
const OPERATION_DISPATCH_FENCE_STATUSES = new Set([
  "cancel_requested",
  "completed",
  "failed",
  "denied",
  "cancelled",
  "device_offline",
  "tombstone",
]);

/** Stream a request body with a hard cap. Returns null when oversized. */
async function readTextLimited(request: Request, maxBytes: number): Promise<string | null> {
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      try {
        await reader.cancel();
      } catch {
        /* ignore */
      }
      return null;
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder().decode(merged);
}

/** Per-session replay-id hard cap (FIFO after TTL prune). */
export const MAX_SEEN_MESSAGE_IDS = 4096;
/** Drop seen message_ids older than this window. */
export const SEEN_MESSAGE_ID_TTL_MS = 10 * 60 * 1000;
/** Pending operation hard cap. */
export const MAX_PENDING_OPERATIONS = 1024;
/** Drop pending ops older than this TTL. */
export const PENDING_TTL_MS = 15 * 60 * 1000;
/** A live transfer-result tombstone is correlation-only, but must still have a
 * finite upper bound independent of its 60-second bearer ticket. */
export const LIVE_TRANSFER_TOMBSTONE_MAX_TTL_MS = 24 * 60 * 60 * 1000;
/** Hard cap on serialized hibernation state (UTF-8 JSON bytes). */
export const MAX_SERIALIZED_STATE_BYTES = 1_048_576;
/** Hard cap on ingress-guard session entries (beyond per-session seen-id cap). */
export const MAX_GUARD_SESSIONS = 128;
/**
 * Bytes reserved in a DO snapshot for non-payload fields (guards, nonces,
 * pending envelopes, JSON structure). Pending payload budget must fit under
 * MAX_SERIALIZED_STATE_BYTES after this reserve.
 */
export const ROOM_STATE_NON_PAYLOAD_RESERVE_BYTES = 256 * 1024;
/**
 * Hard cap on total pending payload JSON bytes across all pending ops.
 * Invariant: MAX_PENDING_PAYLOAD_BYTES + ROOM_STATE_NON_PAYLOAD_RESERVE_BYTES
 *   <= MAX_SERIALIZED_STATE_BYTES (stronger than an unbounded payload budget).
 */
export const MAX_PENDING_PAYLOAD_BYTES =
  MAX_SERIALIZED_STATE_BYTES - ROOM_STATE_NON_PAYLOAD_RESERVE_BYTES;

// Fail fast if constants are edited into an impossible configuration.
if (MAX_PENDING_PAYLOAD_BYTES + ROOM_STATE_NON_PAYLOAD_RESERVE_BYTES > MAX_SERIALIZED_STATE_BYTES) {
  throw new Error("pending_payload_budget_exceeds_state_limit");
}
if (MAX_PENDING_PAYLOAD_BYTES <= 0) {
  throw new Error("pending_payload_budget_non_positive");
}

function legacyAction(op: string): string {
  switch (op) {
    case "ownmesh_fs_list":
    case "ownmesh_list_files":
      return "fs.list";
    case "ownmesh_fs_stat":
      return "fs.stat";
    case "ownmesh_fs_read":
    case "ownmesh_read_file":
      return "fs.read";
    case "ownmesh_fs_write":
    case "ownmesh_write_file":
      return "fs.write";
    case "ownmesh_fs_delete":
    case "ownmesh_delete_file":
      return "fs.delete";
    case "ownmesh_command_run":
    case "ownmesh_run_command":
      return "command.run";
    case "ownmesh_command_shell":
    case "ownmesh_run_shell":
      return "command.shell";
    case "ownmesh_cancel_operation":
    case "cancel":
      return "cancel";
    case "ownmesh_workspace_list":
      return "workspace.list";
    case "ownmesh_workspace_show":
      return "workspace.show";
    case "ownmesh_workspace_add":
      return "workspace.add";
    case "ownmesh_workspace_update":
      return "workspace.update";
    case "ownmesh_workspace_remove":
      return "workspace.remove";
    case "approval.decision":
      return "approval.decision";
    default:
      return op || "unknown";
  }
}

function legacyCapability(op: string, payload: Record<string, unknown>): string {
  if (typeof payload.capability === "string" && payload.capability.trim() !== "") {
    return String(payload.capability);
  }
  const action = legacyAction(op);
  if (action.startsWith("fs.read") || action === "fs.list" || action === "fs.stat") {
    return "filesystem.read";
  }
  if (action === "fs.write" || action === "fs.delete" || action === "fs.patch") {
    return "filesystem.write";
  }
  if (action.startsWith("command.")) return "command.run";
  if (action.startsWith("workspace.")) {
    return action === "workspace.list" || action === "workspace.show"
      ? "workspace.list"
      : action;
  }
  if (action === "cancel") return "operation.cancel";
  if (action.startsWith("session")) return "session.open";
  if (op.startsWith("ownmesh_fs_write") || op.startsWith("ownmesh_fs_delete")) {
    return "filesystem.write";
  }
  if (op.startsWith("ownmesh_fs_") || op.startsWith("ownmesh_profile")) {
    return "filesystem.read";
  }
  if (op.startsWith("ownmesh_command") || op === "ownmesh_cancel_operation") {
    return op === "ownmesh_cancel_operation" ? "operation.cancel" : "command.run";
  }
  if (op.startsWith("ownmesh_session")) return "session.open";
  return op || "unknown";
}

function requiredScopeForCapability(capability: string, actionOrOp: string): string {
  if (capability === "filesystem.write" || actionOrOp.startsWith("ownmesh_fs_write") || actionOrOp === "fs.write" || actionOrOp === "fs.delete") {
    return "ownmesh.write";
  }
  if (
    capability === "command.run" ||
    capability === "operation.cancel" ||
    actionOrOp.startsWith("ownmesh_command") ||
    actionOrOp === "ownmesh_cancel_operation" ||
    actionOrOp.startsWith("command.") ||
    actionOrOp === "cancel"
  ) {
    return "ownmesh.exec";
  }
  if (capability.startsWith("session") || actionOrOp.startsWith("ownmesh_session") || actionOrOp.startsWith("session")) {
    return "ownmesh.session";
  }
  if (
    capability.startsWith("workspace.") ||
    actionOrOp.startsWith("ownmesh_workspace_") ||
    actionOrOp.startsWith("workspace.")
  ) {
    if (
      capability === "workspace.list" ||
      capability === "workspace.show" ||
      actionOrOp === "ownmesh_workspace_list" ||
      actionOrOp === "ownmesh_workspace_show" ||
      actionOrOp === "workspace.list" ||
      actionOrOp === "workspace.show"
    ) {
      return "ownmesh.read";
    }
    return "ownmesh.write";
  }
  if (
    capability === "filesystem.read" ||
    capability === "system.diagnose" ||
    actionOrOp === "ownmesh_system_diagnose" ||
    actionOrOp === "system.diagnose" ||
    actionOrOp.startsWith("ownmesh_fs_") ||
    actionOrOp.startsWith("ownmesh_profile") ||
    actionOrOp.startsWith("fs.")
  ) {
    return "ownmesh.read";
  }
  return "";
}

/** Durable Object storage key for hibernation-safe room state. */
export const ROOM_STATE_STORAGE_KEY = "ownmesh:device-room:v1";

export type SessionRole = "agent" | "client";

export type SessionAttachment = {
  role: SessionRole;
  device_id: string;
  session_id: string;
  connected_at: number;
  phase: "connected" | "challenged" | "proven" | "ready";
  challenge_message?: string;
  auth_hash?: string;
  scope?: string;
  /** Mirrored lastSeq for attachment-level recovery (storage is authoritative). */
  lastSeq?: number;
  /**
   * Set from agent `ready.remote_routing_enabled`. Inject/dispatch only counts
   * agents that explicitly enable remote routing (E2+). Harness tests must set
   * this when forcing phase=ready.
   */
  remote_routing_enabled?: boolean;
};

export type DeviceEnvelope = {
  protocol: string;
  message_id: string;
  type: string;
  device_id: string;
  correlation_id?: string;
  seq: number;
  sent_at: string;
  expires_at?: string;
  payload: Record<string, unknown>;
};

export type AuditSink = {
  append(event: {
    kind: string;
    summary: string;
    device_id?: string;
    meta?: Record<string, unknown>;
  }): void | Promise<void>;
};

export type PendingOperation = {
  correlation_id: string;
  type: string;
  from_session: string;
  created_at: number;
  payload: Record<string, unknown>;
  /** Bound envelope expiry used when redelivering after Agent reconnect. */
  expires_at?: string;
  /** Last successful dispatch time (ms). */
  dispatched_at?: number;
  /** How many times this pending op was sent to an Agent. */
  dispatch_count?: number;
  /**
   * A transfer ticket delivery keeps only this correlation record durable.  Its
   * original operation body is socket-only and must never be replayed after a
   * hibernation/reconnect.
   */
  live_only?: boolean;
};

/** Absolute deadline for a durable pending entry. Keep this shared by pruning
 * and DO alarms so an idle/hibernated room cannot outlive its own TTL. */
function pendingDeadlineMs(p: PendingOperation): number {
  if (typeof p.expires_at === "string" && p.expires_at.trim() !== "") {
    const parsed = Date.parse(p.expires_at);
    if (Number.isFinite(parsed)) return parsed;
  }
  if (!Number.isFinite(p.created_at)) return NaN;
  return p.created_at + (p.live_only ? LIVE_TRANSFER_TOMBSTONE_MAX_TTL_MS : PENDING_TTL_MS);
}

/**
 * Detached `command.run` keeps Device Room correlation until `expires_at`.
 * Do not mark these `live_only`: that flag skips Agent redelivery, which
 * detached commands still need (spawn is journal-deduped on the device).
 */
function isDetachedCommandPending(p: PendingOperation): boolean {
  const payload = p.payload;
  if (!payload || typeof payload !== "object") return false;
  if (payload.capability !== "command.run") return false;
  const args = payload.arguments;
  if (!args || typeof args !== "object" || Array.isArray(args)) return false;
  return (args as Record<string, unknown>).detach === true;
}

type ApprovalDecisionBinding = {
  target_operation_id: string;
  decision: "approve" | "deny";
  approval_id: string;
  transaction_id: string;
};

function approvalDecisionBindingFromPayload(
  payload: Record<string, unknown> | undefined,
): ApprovalDecisionBinding | null {
  if (!payload || payload.capability !== "approval.decision") return null;
  const args =
    payload.arguments && typeof payload.arguments === "object"
      ? (payload.arguments as Record<string, unknown>)
      : null;
  const authorization =
    payload.authorization && typeof payload.authorization === "object"
      ? (payload.authorization as Record<string, unknown>)
      : null;
  const boundAction =
    authorization?.bound_action && typeof authorization.bound_action === "object"
      ? (authorization.bound_action as Record<string, unknown>)
      : null;
  const targetOperationId = String(args?.target_operation_id || "").trim();
  const decision = String(args?.decision || "").toLowerCase();
  const approvalId = String(args?.approval_id || "").trim();
  const transactionId = String(boundAction?.outbox_id || "").trim();
  if (
    !targetOperationId ||
    !approvalId ||
    !transactionId ||
    (decision !== "approve" && decision !== "deny")
  ) {
    return null;
  }
  return {
    target_operation_id: targetOperationId,
    decision,
    approval_id: approvalId,
    transaction_id: transactionId,
  };
}

/** Announced in accepted.session_parameters and enforced on inbound frames. */
export const MAX_PAYLOAD_BYTES = 1_000_000;

/** Deferred WS operation.request dispatch — mutate only; send after durable persist. */
export type DeferredDispatch = {
  /** Raw frame to deliver (agent operation.request, or client device_offline). */
  frame: string;
  /** Session ids that should receive `frame` after persist succeeds. */
  recipients: string[];
  /**
   * Pending correlation staged for this request. Rolled back on persist failure.
   * Absent when the deferred frame is a client-side device_offline (no pending).
   */
  pending_key?: string;
  /** Originating client session — used if post-persist agent delivery yields zero sends. */
  client_session_id?: string;
};

export type HandleMessageResult = {
  ok: boolean;
  error?: string;
  /** When true, DeviceRoom.webSocketMessage should gracefully close the socket. */
  close?: boolean;
  closeCode?: number;
  closeReason?: string;
  /**
   * When set, DeviceRoom must CAS-persist authoritative MCP op state BEFORE
   * finalizeOperationResult (forward + pending removal). Harness finalizes
   * immediately when no store is present.
   */
  mcp_result?: {
    correlation_id?: string;
    operation_id?: string;
    payload: Record<string, unknown>;
  };
  /** JSON envelope deferred until after authoritative CAS (operation.result). */
  deferred_forward?: string;
  /**
   * operation.request: router stages pending/replay only; DO persists then dispatches.
   * Harness finalizes immediately (no durable store).
   */
  deferred_dispatch?: DeferredDispatch;
  /** Pending entries dropped for TTL/expiry — DO must mark matching MCP ops failed. */
  expired_pending?: PendingOperation[];
  /** Ready Agent whose durable pending work must be revalidated by the DO. */
  agent_ready_session_id?: string;
  /** Agent-local crash outbox correlations offered for authoritative cleanup. */
  agent_pending_correlations?: string[];
  /** Metadata observed only after this Agent has completed proof and ready. */
  authenticated_agent?: {
    agent_version?: string;
    protocol_version: string;
    workspaces?: Array<{ id: string; generation: string }>;
    enforce_workspace?: boolean;
  };
  /**
   * #146: incremental workspace-registry refresh from a live ready agent.
   * DeviceRoom must persist the full registry snapshot via
   * store.syncDeviceWorkspaces before the agent may rely on it.
   */
  workspace_registry_sync?: {
    enforce_workspace: boolean;
    workspaces: Array<{ id: string; generation: string }>;
  };
};

const MAX_AGENT_VERSION_LENGTH = 128;

function readyPendingCorrelations(value: unknown): string[] | undefined | null {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 64) return null;
  const seen = new Set<string>();
  const correlations: string[] = [];
  for (const candidate of value) {
    if (
      typeof candidate !== "string" ||
      candidate.length > 128 ||
      !/^op_[A-Za-z0-9][A-Za-z0-9._-]*$/.test(candidate) ||
      seen.has(candidate)
    ) return null;
    seen.add(candidate);
    correlations.push(candidate);
  }
  return correlations;
}

function readyAgentVersion(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const version = value.trim();
  // Keep a display value bounded and line-safe. It is never an authority input.
  if (version.length === 0 || version.length > MAX_AGENT_VERSION_LENGTH || /[\x00-\x1f\x7f]/.test(version)) {
    return undefined;
  }
  return version;
}

const MAX_READY_WORKSPACES = 64;

function readyWorkspaceRegistry(
  value: unknown,
): { workspaces?: Array<{ id: string; generation: string }>; enforce_workspace: boolean } | undefined | null {
  if (value === undefined) return undefined;
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const raw = value as Record<string, unknown>;
  if (typeof raw.enforce_workspace !== "boolean") return null;
  // Pre-generation Agents advertised only ids. Preserve their policy
  // observation but never authorize or refresh a cloud workspace mapping from
  // an id that cannot prove which local root it currently denotes.
  if (Array.isArray(raw.ids) && raw.workspaces === undefined) {
    if (raw.ids.length < 1 || raw.ids.length > MAX_READY_WORKSPACES) return null;
    const legacyIds = new Set<string>();
    for (const candidate of raw.ids) {
      if (
        typeof candidate !== "string" ||
        candidate.length > 128 ||
        !/^ws_[A-Za-z0-9_-]*$/.test(candidate) ||
        legacyIds.has(candidate)
      ) return null;
      legacyIds.add(candidate);
    }
    if (!legacyIds.has("ws_default")) return null;
    return { enforce_workspace: raw.enforce_workspace };
  }
  if (!Array.isArray(raw.workspaces)) return null;
  if (raw.workspaces.length < 1 || raw.workspaces.length > MAX_READY_WORKSPACES) return null;
  const workspaces: Array<{ id: string; generation: string }> = [];
  const seen = new Set<string>();
  for (const candidate of raw.workspaces) {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return null;
    const entry = candidate as Record<string, unknown>;
    if (Object.keys(entry).some((key) => key !== "id" && key !== "generation")) return null;
    const id = entry.id;
    const generation = entry.generation;
    if (
      typeof id !== "string" ||
      id.length > 128 ||
      !/^ws_[A-Za-z0-9_-]*$/.test(id) ||
      typeof generation !== "string" ||
      !/^wsg_[a-f0-9]{32}$/.test(generation) ||
      seen.has(id)
    ) return null;
    seen.add(id);
    workspaces.push({ id, generation });
  }
  if (!seen.has("ws_default")) return null;
  workspaces.sort((a, b) => a.id.localeCompare(b.id));
  return { workspaces, enforce_workspace: raw.enforce_workspace };
}



type WorkspaceAuthorityResult =
  | "ok"
  | "binding_mismatch"
  | "workspace_authority_changed"
  | "storage_unavailable";

function workspaceAuthorityBinding(
  payload: Record<string, unknown>,
): { workspace_id: string | null; version: number | null } | null {
  const authorization = payload.authorization;
  if (!authorization || typeof authorization !== "object" || Array.isArray(authorization)) return null;
  const bound = (authorization as Record<string, unknown>).bound_action;
  if (!bound || typeof bound !== "object" || Array.isArray(bound)) return null;
  const action = bound as Record<string, unknown>;
  if (action.workspace_id === null && action.workspace_version === null) {
    return { workspace_id: null, version: null };
  }
  if (
    typeof action.workspace_id !== "string" ||
    !/^ws_[A-Za-z0-9_-]*$/.test(action.workspace_id) ||
    typeof action.workspace_version !== "number" ||
    !Number.isSafeInteger(action.workspace_version) ||
    action.workspace_version < 1
  ) return null;
  return { workspace_id: action.workspace_id, version: action.workspace_version };
}

/** Extract only a complete, server-bound credential epoch from an operation. */


type SessionIngressGuard = {
  lastSeq: number;
  /** message_id -> first-seen epoch ms */
  seenMessageIds: Map<string, number>;
};

export type PersistedIngressGuard = {
  lastSeq: number;
  seenMessageIds: Array<{ id: string; at: number }>;
};

export type PersistedRoomState = {
  v: 1;
  /** Device identity survives a socket-free hibernation wake for D1 binding. */
  device_id?: string;
  seqOut: number;
  ingressGuards: Record<string, PersistedIngressGuard>;
  pending: PendingOperation[];
  /**
   * Internal-context nonces consumed by this room (nonce → exp epoch ms).
   * Survives DO hibernation; room-level authority (not process-local util guard).
   */
  consumedNonces?: Record<string, number>;
};

/** Staged HTTP inject — pending+seq reserved; send only after durable persist. */
export type PreparedInjectOperation = {
  correlation_id: string;
  envelope: DeviceEnvelope;
  from_session: string;
  /** Synthetic client session created for this inject (optional cleanup). */
  created_session_id?: string;
};

/**
 * Pure routing logic — unit-tested without Workers runtime.
 * DeviceRoom DO delegates to this for message handling.
 * Close decisions are signaled via HandleMessageResult.close; the DO owns the socket.
 */
export class DeviceRoomRouter {
  deviceId: string;
  /** session_id -> attachment */
  sessions = new Map<string, SessionAttachment>();
  /** WebSocket tag or mock id -> session_id (set by adapter) */
  pending = new Map<string, PendingOperation>();
  /** per-session inbound seq / message_id replay guard */
  ingressGuards = new Map<string, SessionIngressGuard>();
  /** Durable internal-context nonces (nonce → exp ms); exported with room state. */
  consumedNonces = new Map<string, number>();
  seqOut = 0;
  audit: AuditSink;
  /** outbound send by session_id */
  sendToSession: (sessionId: string, data: string) => boolean;
  /** broadcast to all sessions with role */
  sendToRole: (role: SessionRole, data: string) => number;
  verifyProof: (deviceId: string, message: string, signature: string) => boolean | Promise<boolean>;
  /** Optional hook fired after mutating lastSeq/seen/pending (DO persists here). */
  onStateChange?: () => void | Promise<void>;

  constructor(
    deviceId: string,
    opts: {
      audit?: AuditSink;
      sendToSession: (sessionId: string, data: string) => boolean;
      sendToRole: (role: SessionRole, data: string) => number;
      verifyProof?: (deviceId: string, message: string, signature: string) => boolean | Promise<boolean>;
      onStateChange?: () => void | Promise<void>;
    },
  ) {
    this.deviceId = deviceId;
    this.audit = opts.audit || { append: () => undefined };
    this.sendToSession = opts.sendToSession;
    this.sendToRole = opts.sendToRole;
    this.verifyProof = opts.verifyProof || (() => false);
    this.onStateChange = opts.onStateChange;
  }

  private notifyStateChange(): void {
    try {
      const r = this.onStateChange?.();
      if (r && typeof (r as Promise<void>).then === "function") {
        void (r as Promise<void>).catch(() => undefined);
      }
    } catch {
      /* persistence must not break routing */
    }
  }

  /** Total UTF-8 bytes of JSON-serialized pending payloads. */
  totalPendingPayloadBytes(): number {
    let n = 0;
    const enc = new TextEncoder();
    for (const p of this.pending.values()) {
      n += enc.encode(JSON.stringify(p.payload || {})).byteLength;
    }
    return n;
  }

  /** Snapshot for DO storage / hibernation restore. Enforces serialized-size bound. */
  exportState(): PersistedRoomState {
    // Do not prune pending here. A hibernated wake must surface every expired
    // correlation to DeviceRoom so its matching D1 operation can be terminally
    // reconciled; silently dropping it here was the stale-pending path.
    for (const guard of this.ingressGuards.values()) pruneSeenMessageIds(guard, Date.now());
    // Bound guard-session count after prune (drop detached guards first).
    this.enforceGuardSessionBound();
    this.pruneConsumedNonces();
    const ingressGuards: Record<string, PersistedIngressGuard> = {};
    for (const [sid, guard] of this.ingressGuards) {
      ingressGuards[sid] = {
        lastSeq: guard.lastSeq,
        seenMessageIds: [...guard.seenMessageIds.entries()].map(([id, at]) => ({ id, at })),
      };
    }
    const consumedNonces: Record<string, number> = {};
    for (const [nonce, exp] of this.consumedNonces) {
      consumedNonces[nonce] = exp;
    }
    const state: PersistedRoomState = {
      v: 1,
      device_id: this.deviceId,
      seqOut: this.seqOut,
      ingressGuards,
      pending: [...this.pending.values()].map((p) => ({ ...p, payload: { ...p.payload } })),
      consumedNonces,
    };
    assertRoomStateBounds(state);
    return state;
  }

  /** Restore after hibernation (or test harness transfer). Rejects over-bound snapshots. */
  importState(state: PersistedRoomState | null | undefined): void {
    if (!state || state.v !== 1) return;
    // Cheap pre-check on raw serialized size before allocating maps.
    const rawBytes = new TextEncoder().encode(JSON.stringify(state)).byteLength;
    if (rawBytes > MAX_SERIALIZED_STATE_BYTES) {
      throw new Error("room_state_too_large");
    }
    if (typeof state.device_id === "string" && state.device_id.trim() !== "") {
      this.deviceId = state.device_id;
    }
    this.seqOut = Number.isFinite(state.seqOut) ? Math.max(0, Math.floor(state.seqOut)) : 0;
    this.ingressGuards.clear();
    for (const [sid, g] of Object.entries(state.ingressGuards || {})) {
      const seen = new Map<string, number>();
      const list = Array.isArray(g.seenMessageIds) ? g.seenMessageIds : [];
      for (const entry of list) {
        if (entry && typeof entry.id === "string" && Number.isFinite(entry.at)) {
          seen.set(entry.id, entry.at);
        }
      }
      this.ingressGuards.set(sid, {
        lastSeq: Number.isFinite(g.lastSeq) ? Math.max(0, Math.floor(g.lastSeq)) : 0,
        seenMessageIds: seen,
      });
    }
    this.pending.clear();
    for (const p of state.pending || []) {
      if (!p || typeof p.correlation_id !== "string") continue;
      const restored: PendingOperation = {
        correlation_id: p.correlation_id,
        type: String(p.type || ""),
        from_session: String(p.from_session || ""),
        created_at: Number(p.created_at) || 0,
        payload: p.payload && typeof p.payload === "object" ? { ...p.payload } : {},
      };
      if (typeof (p as PendingOperation).expires_at === "string") {
        restored.expires_at = String((p as PendingOperation).expires_at);
      }
      if (Number.isFinite((p as PendingOperation).dispatched_at)) {
        restored.dispatched_at = Number((p as PendingOperation).dispatched_at);
      }
      if (Number.isFinite((p as PendingOperation).dispatch_count)) {
        restored.dispatch_count = Number((p as PendingOperation).dispatch_count);
      }
      if ((p as PendingOperation).live_only === true) {
        restored.live_only = true;
      }
      this.pending.set(p.correlation_id, restored);
    }
    this.consumedNonces.clear();
    for (const [nonce, exp] of Object.entries(state.consumedNonces || {})) {
      if (typeof nonce === "string" && nonce && Number.isFinite(exp)) {
        this.consumedNonces.set(nonce, Number(exp));
      }
    }
    // Do not prune pending during import. Expired correlations must be handed
    // to DeviceRoom's D1 reconciliation after restore, not silently discarded.
    for (const guard of this.ingressGuards.values()) pruneSeenMessageIds(guard, Date.now());
    this.enforceGuardSessionBound();
    this.pruneConsumedNonces();
    // Re-check after prune — still over bound means corrupt/hostile snapshot.
    assertRoomStateBounds(this.exportStateUnchecked());
  }

  /** exportState without re-assert (used after import prune for bound re-check). */
  private exportStateUnchecked(): PersistedRoomState {
    const ingressGuards: Record<string, PersistedIngressGuard> = {};
    for (const [sid, guard] of this.ingressGuards) {
      ingressGuards[sid] = {
        lastSeq: guard.lastSeq,
        seenMessageIds: [...guard.seenMessageIds.entries()].map(([id, at]) => ({ id, at })),
      };
    }
    const consumedNonces: Record<string, number> = {};
    for (const [nonce, exp] of this.consumedNonces) {
      consumedNonces[nonce] = exp;
    }
    return {
      v: 1,
      device_id: this.deviceId,
      seqOut: this.seqOut,
      ingressGuards,
      pending: [...this.pending.values()].map((p) => ({ ...p, payload: { ...p.payload } })),
      consumedNonces,
    };
  }

  /** Prune TTL-expired + over-cap internal-context nonces. */
  pruneConsumedNonces(nowMs = Date.now()): number {
    const before = this.consumedNonces.size;
    pruneNonceExpMap(this.consumedNonces, nowMs, INTERNAL_CONTEXT_REPLAY_MAX);
    return before - this.consumedNonces.size;
  }

  /**
   * Room-level durable nonce consume. Returns true when fresh; false on replay.
   * Caller must persist room state before treating the consume as durable.
   */
  consumeInternalNonce(nonce: string, expMs: number, nowMs = Date.now()): boolean {
    if (!nonce || !Number.isFinite(expMs)) return false;
    return rememberNonceInMap(this.consumedNonces, nonce, expMs, nowMs, INTERNAL_CONTEXT_REPLAY_MAX);
  }

  /** Undo an in-memory nonce consume (rollback before durable persist). */
  releaseInternalNonce(nonce: string): void {
    this.consumedNonces.delete(nonce);
  }

  hasInternalNonce(nonce: string): boolean {
    return this.consumedNonces.has(nonce);
  }

  /**
   * Drop detached guards (no live session) down to targetSize.
   * Never evicts a guard that still has a live session — lastSeq of live
   * sessions is never cleared by capacity enforcement.
   */
  private pruneDetachedGuards(targetSize: number): void {
    if (this.ingressGuards.size <= targetSize) return;
    // Oldest lastSeq first among detached only.
    const detached = [...this.ingressGuards.entries()]
      .filter(([sid]) => !this.sessions.has(sid))
      .sort((a, b) => a[1].lastSeq - b[1].lastSeq);
    for (const [sid] of detached) {
      if (this.ingressGuards.size <= targetSize) break;
      this.ingressGuards.delete(sid);
    }
  }

  /** Bound guard map by pruning detached only — never drops live sessions. */
  private enforceGuardSessionBound(): void {
    this.pruneDetachedGuards(MAX_GUARD_SESSIONS);
  }

  /**
   * True when a brand-new guard session_id can be admitted without evicting
   * any live session (free slot or at least one detached guard to prune).
   */
  canAdmitNewGuardSession(): boolean {
    if (this.ingressGuards.size < MAX_GUARD_SESSIONS) return true;
    for (const sid of this.ingressGuards.keys()) {
      if (!this.sessions.has(sid)) return true;
    }
    return false;
  }

  /** Prune TTL-expired + over-limit seen ids and pending ops. Returns counts removed. */
  pruneAll(now = Date.now()): { seen: number; pending: number; expired: PendingOperation[] } {
    let seen = 0;
    for (const guard of this.ingressGuards.values()) {
      seen += pruneSeenMessageIds(guard, now);
    }
    const expired = this.pruneExpiredPending(now);
    return { seen, pending: expired.length, expired };
  }

  /**
   * Drop TTL-expired / over-cap pending entries.
   * Returns removed entries so the Durable Object can mark matching MCP ops
   * terminal (`failed` / expired) instead of silently losing them.
   */
  pruneExpiredPending(now = Date.now()): PendingOperation[] {
    const removed: PendingOperation[] = [];
    for (const [key, p] of [...this.pending]) {
      const expMs = pendingDeadlineMs(p);
      // A live-only tombstone has no bearer to replay and exists solely to
      // correlate a genuine long-running transfer result. Its bounded transfer
      // expiry, rather than the ordinary 15-minute dispatch TTL, controls it.
      // Detached command.run is the other long-lived pending shape: skip the
      // 15-minute TTL, but still expire at expires_at (24h dispatch cap).
      const detached = isDetachedCommandPending(p);
      const staleByTtl =
        !p.live_only &&
        (!Number.isFinite(p.created_at) ||
          (!detached && now - p.created_at > PENDING_TTL_MS));
      const staleByExpiry = Number.isFinite(expMs) && expMs <= now;
      if (staleByTtl || staleByExpiry) {
        this.pending.delete(key);
        removed.push(p);
      }
    }
    // Hard cap: drop oldest first (visible expiry path).
    if (this.pending.size > MAX_PENDING_OPERATIONS) {
      const ordered = [...this.pending.entries()].sort((a, b) => a[1].created_at - b[1].created_at);
      const overflow = this.pending.size - MAX_PENDING_OPERATIONS;
      for (let i = 0; i < overflow; i++) {
        const entry = ordered[i]!;
        this.pending.delete(entry[0]);
        removed.push(entry[1]);
      }
    }
    return removed;
  }

  /**
   * After an Agent becomes ready, redeliver durable pending operation.request
   * frames with fresh seq/message_id. Completed correlations are handled by the
   * Agent cache; in-flight side effects remain journal-deduped on the device.
   */
  redeliverPendingToAgent(sessionId: string, now = Date.now()): number {
    const session = this.sessions.get(sessionId);
    if (!session || !this.isRemoteRoutingAgent(session)) return 0;
    let n = 0;
    for (const p of this.pending.values()) {
      // Live transfer starts deliberately retain no request body.  A new
      // ticket/proof generation is required after a disconnect, never a DO
      // replay of a bearer that may already have been consumed.
      if (p.live_only) continue;
      const expMs =
        typeof p.expires_at === "string" && p.expires_at.trim() !== ""
          ? Date.parse(p.expires_at)
          : p.created_at + PENDING_TTL_MS;
      if (Number.isFinite(expMs) && expMs <= now) continue;
      const envelope = this.nextEnvelope(
        "operation.request",
        p.payload,
        p.correlation_id,
        typeof p.expires_at === "string" && p.expires_at.trim() !== ""
          ? { expiresAt: p.expires_at }
          : undefined,
      );
      if (this.sendToSession(sessionId, JSON.stringify(envelope))) {
        p.dispatched_at = now;
        p.dispatch_count = (p.dispatch_count || 0) + 1;
        n++;
      }
    }
    if (n > 0) this.notifyStateChange();
    return n;
  }

  /**
   * Register or refresh a session.
   * Returns false when a NEW guard cannot be admitted without evicting a live
   * session (at MAX_GUARD_SESSIONS with no detached guard to prune). Existing
   * session_ids always succeed. lastSeq of an existing guard is never rewound.
   */
  registerSession(att: SessionAttachment): boolean {
    const sid = att.session_id;
    if (this.ingressGuards.has(sid)) {
      // Existing guard — always reattach; attachment must not rewind storage seq.
      if (Number.isFinite(att.lastSeq)) {
        const guard = this.ingressGuards.get(sid)!;
        guard.lastSeq = Math.max(guard.lastSeq, Math.floor(att.lastSeq!));
      }
      this.sessions.set(sid, { ...att, phase: att.phase || "connected" });
      return true;
    }

    // New guard required — prune detached only to free a slot; never evict live.
    if (this.ingressGuards.size >= MAX_GUARD_SESSIONS) {
      this.pruneDetachedGuards(MAX_GUARD_SESSIONS - 1);
    }
    if (this.ingressGuards.size >= MAX_GUARD_SESSIONS) {
      return false;
    }

    const lastSeq = Number.isFinite(att.lastSeq) ? Math.max(0, Math.floor(att.lastSeq!)) : 0;
    this.ingressGuards.set(sid, { lastSeq, seenMessageIds: new Map() });
    this.sessions.set(sid, { ...att, phase: att.phase || "connected" });
    return true;
  }

  unregisterSession(sessionId: string): void {
    this.sessions.delete(sessionId);
    this.ingressGuards.delete(sessionId);
    this.notifyStateChange();
  }

  private sendError(
    sessionId: string,
    code: string,
    message: string,
    correlationId?: string,
  ): void {
    const err = this.nextEnvelope("error", { code, message }, correlationId);
    this.sendToSession(sessionId, JSON.stringify(err));
  }

  private guardOrReject(
    sessionId: string,
    msg: DeviceEnvelope,
  ): HandleMessageResult | null {
    this.pruneAll();
    let guard = this.ingressGuards.get(sessionId);
    if (!guard) {
      // Only repair-create for an already-live session; never admit a new guard here.
      if (!this.sessions.has(sessionId)) {
        this.sendError(sessionId, "OWNMESH_E_NO_SESSION", "session not registered", msg.correlation_id);
        return { ok: false, error: "no_session" };
      }
      guard = { lastSeq: 0, seenMessageIds: new Map<string, number>() };
      this.ingressGuards.set(sessionId, guard);
    }

    if (msg.expires_at) {
      const exp = Date.parse(msg.expires_at);
      if (Number.isFinite(exp) && exp <= Date.now()) {
        this.sendError(sessionId, "OWNMESH_E_ENVELOPE_EXPIRED", "envelope expired", msg.correlation_id);
        return { ok: false, error: "envelope_expired" };
      }
    }

    const messageId = typeof msg.message_id === "string" ? msg.message_id : "";
    if (!messageId) {
      this.sendError(sessionId, "OWNMESH_E_BAD_ENVELOPE", "message_id required", msg.correlation_id);
      return { ok: false, error: "bad_message_id" };
    }
    if (guard.seenMessageIds.has(messageId)) {
      this.sendError(sessionId, "OWNMESH_E_DUPLICATE_MESSAGE", "duplicate message_id", msg.correlation_id);
      return { ok: false, error: "duplicate_message_id" };
    }

    const seq = Number(msg.seq);
    if (!Number.isFinite(seq) || !Number.isInteger(seq) || seq <= guard.lastSeq) {
      this.sendError(
        sessionId,
        "OWNMESH_E_BAD_SEQ",
        `seq must be monotonically increasing (last=${guard.lastSeq})`,
        msg.correlation_id,
      );
      return { ok: false, error: "bad_seq" };
    }

    const now = Date.now();
    guard.seenMessageIds.set(messageId, now);
    pruneSeenMessageIds(guard, now);
    guard.lastSeq = seq;
    // Mirror onto session attachment for hibernation attachment recovery.
    const att = this.sessions.get(sessionId);
    if (att) {
      att.lastSeq = seq;
      this.sessions.set(sessionId, att);
    }
    this.notifyStateChange();
    return null;
  }

  nextEnvelope(
    type: string,
    payload: Record<string, unknown>,
    correlationId?: string,
    opts?: { expiresAt?: string },
  ): DeviceEnvelope {
    this.seqOut += 1;
    const env: DeviceEnvelope = {
      protocol: PROTOCOL,
      message_id: randomId("msg_"),
      type,
      device_id: this.deviceId,
      seq: this.seqOut,
      sent_at: nowIso(),
      payload,
    };
    if (correlationId) env.correlation_id = correlationId;
    if (opts?.expiresAt) {
      env.expires_at = opts.expiresAt;
    } else if (type === "operation.request") {
      env.expires_at = nowIso(Date.now() + OPERATION_REQUEST_TTL_MS);
    }
    return env;
  }

  /** True when an agent is authenticated, ready, and advertises remote routing. */
  isRemoteRoutingAgent(session: SessionAttachment): boolean {
    return (
      session.role === "agent" &&
      session.phase === "ready" &&
      session.remote_routing_enabled === true
    );
  }

  /**
   * Normalize HTTP/WS inject payloads into ownmesh.operation/1.0.
   * Already-valid contracts pass through; legacy flat `{op,...}` shapes are wrapped.
   */
  buildOperationRequestPayload(
    opType: string,
    payload: Record<string, unknown>,
    correlationId: string,
  ): Record<string, unknown> {
    if (payload.operation_contract === OPERATION_CONTRACT_V1) {
      const operationId = String(payload.operation_id || correlationId);
      if (operationId !== correlationId) {
        // Fail closed later at inject; keep identity consistent here.
      }
      const normalized: Record<string, unknown> = {
        ...payload,
        operation_contract: OPERATION_CONTRACT_V1,
        operation_id: operationId,
        capability: String(payload.capability || ""),
        idempotency_key: String(payload.idempotency_key || operationId),
        arguments:
          payload.arguments && typeof payload.arguments === "object" && !Array.isArray(payload.arguments)
            ? (payload.arguments as Record<string, unknown>)
            : {},
      };
      if (typeof payload.payload_hash === "string" && payload.payload_hash.trim() !== "") {
        normalized.payload_hash = String(payload.payload_hash).toLowerCase();
      }
      return normalized;
    }

    const legacyOp = String(payload.op || opType || "");
    const capability = legacyCapability(legacyOp, payload);
    const {
      op: _op,
      tool: _tool,
      operation_id: legacyOpId,
      idempotency_key: legacyIdem,
      workspace_id: legacyWorkspace,
      _client_hints: clientHints,
      force_allow: _fa,
      bypass_policy: _bp,
      skip_approval: _sa,
      allow: _allow,
      approved: _approved,
      async: _async,
      device_id: _deviceId,
      intent_summary: _intent,
      risk_note: _risk,
      principal: _prin,
      principal_id: _pid,
      tenant_id: _tid,
      policy_result: _pr,
      payload_hash: _ph,
      risk_level: _rl,
      ...rest
    } = payload;
    const argumentsBody: Record<string, unknown> = {
      action: legacyAction(legacyOp),
      ...rest,
    };
    if (clientHints !== undefined) argumentsBody._client_hints = clientHints;
    const built: Record<string, unknown> = {
      operation_contract: OPERATION_CONTRACT_V1,
      operation_id: String(legacyOpId || correlationId),
      capability,
      idempotency_key: String(legacyIdem || legacyOpId || correlationId),
      arguments: argumentsBody,
    };
    if (typeof legacyWorkspace === "string" && legacyWorkspace.trim() !== "") {
      built.workspace_id = legacyWorkspace;
    }
    return built;
  }

  /** Handle an inbound WS text message from a known session. */
  async handleMessage(sessionId: string, raw: string): Promise<HandleMessageResult> {
    const att = this.sessions.get(sessionId);
    if (!att) return { ok: false, error: "unknown_session" };

    // Measure UTF-8 bytes (Cloudflare Workers has no Buffer without nodejs_compat).
    const payloadBytes = new TextEncoder().encode(raw).byteLength;
    if (payloadBytes > MAX_PAYLOAD_BYTES) {
      this.sendError(
        sessionId,
        "OWNMESH_E_PAYLOAD_TOO_LARGE",
        `payload exceeds ${MAX_PAYLOAD_BYTES} bytes`,
      );
      return {
        ok: false,
        error: "payload_too_large",
        close: true,
        closeCode: 1009,
        closeReason: "payload too large",
      };
    }

    let msg: DeviceEnvelope;
    try {
      msg = JSON.parse(raw) as DeviceEnvelope;
    } catch {
      this.sendError(sessionId, "OWNMESH_E_BAD_JSON", "malformed JSON");
      return {
        ok: false,
        error: "bad_json",
        close: true,
        closeCode: 1003,
        closeReason: "malformed JSON",
      };
    }
    if (!msg || typeof msg !== "object" || Array.isArray(msg)) {
      this.sendError(sessionId, "OWNMESH_E_BAD_JSON", "malformed envelope");
      return {
        ok: false,
        error: "bad_json",
        close: true,
        closeCode: 1003,
        closeReason: "malformed JSON",
      };
    }
    if (msg.protocol !== PROTOCOL) {
      this.sendError(sessionId, "OWNMESH_E_UNSUPPORTED_PROTOCOL", `expected ${PROTOCOL}`);
      return { ok: false, error: "bad_protocol" };
    }
    if (msg.device_id && msg.device_id !== this.deviceId) {
      return { ok: false, error: "device_mismatch" };
    }

    const rejected = this.guardOrReject(sessionId, msg);
    if (rejected) return rejected;

    switch (msg.type) {
      case "hello": {
        if (att.role !== "agent" || att.phase !== "connected") return { ok: false, error: "invalid_state" };
        const nonceB = randomToken("nb_").slice(0, 16);
        const connectionId = randomId("conn_");
        const challenge = this.nextEnvelope(
          "challenge",
          {
            nonce_b: nonceB,
            connection_id: connectionId,
            message: `ownmesh-device-challenge:${nonceB}:${this.deviceId}`,
          },
          msg.correlation_id,
        );
        att.phase = "challenged";
        att.challenge_message = String(challenge.payload.message);
        this.sessions.set(sessionId, att);
        this.sendToSession(sessionId, JSON.stringify(challenge));
        void this.audit.append({
          kind: "device.hello",
          summary: "agent hello",
          device_id: this.deviceId,
          meta: { session_id: sessionId },
        });
        return { ok: true };
      }
      case "proof": {
        if (att.role !== "agent" || att.phase !== "challenged" || !att.challenge_message) return { ok: false, error: "invalid_state" };
        const signature = String(msg.payload.signature || "");
        if (!(await this.verifyProof(this.deviceId, att.challenge_message, signature))) return { ok: false, error: "invalid_proof" };
        att.phase = "proven";
        delete att.challenge_message;
        this.sessions.set(sessionId, att);
        const accepted = this.nextEnvelope(
          "accepted",
          {
            selected_protocol: PROTOCOL,
            session_parameters: {
              heartbeat_sec: 30,
              max_payload_bytes: MAX_PAYLOAD_BYTES,
            },
          },
          msg.correlation_id,
        );
        this.sendToSession(sessionId, JSON.stringify(accepted));
        return { ok: true };
      }
      case "ready": {
        if (att.role !== "agent" || att.phase !== "proven") return { ok: false, error: "invalid_state" };
        const agentVersion = readyAgentVersion(msg.payload.agent_version);
        const workspaceRegistry = readyWorkspaceRegistry(msg.payload.workspace_registry);
        const pendingCorrelations = readyPendingCorrelations(msg.payload.pending_correlations);
        if (workspaceRegistry === null) {
          return { ok: false, error: "invalid_workspace_registry" };
        }
        if (pendingCorrelations === null) {
          return { ok: false, error: "invalid_pending_correlations" };
        }
        att.phase = "ready";
        att.remote_routing_enabled = msg.payload.remote_routing_enabled === true;
        this.sessions.set(sessionId, att);
        const ack = this.nextEnvelope(
          "ready.ack",
          { ok: true },
          msg.correlation_id,
        );
        this.sendToSession(sessionId, JSON.stringify(ack));
        // The DO revalidates every durable pending credential generation before
        // redelivery. The pure router intentionally never sends old authority.
        const expired = this.pruneExpiredPending();
        void this.audit.append({
          kind: "device.ready",
          summary: "agent ready",
          device_id: this.deviceId,
          meta: {
            capability_count: Array.isArray(msg.payload.capabilities)
              ? msg.payload.capabilities.length
              : 0,
            remote_routing_enabled: att.remote_routing_enabled === true,
            pending_redelivered: 0,
            pending_expired: expired.length,
          },
        });
        return {
          ok: true,
          expired_pending: expired,
          ...(pendingCorrelations ? { agent_pending_correlations: pendingCorrelations } : {}),
          authenticated_agent: {
            ...(agentVersion ? { agent_version: agentVersion } : {}),
            // The envelope protocol was validated before the proof/ready state
            // transition; do not trust a second payload claim for this value.
            protocol_version: msg.protocol,
            ...(workspaceRegistry
              ? {
                  ...(workspaceRegistry.workspaces
                    ? { workspaces: workspaceRegistry.workspaces }
                    : {}),
                  enforce_workspace: workspaceRegistry.enforce_workspace,
                }
              : {}),
          },
          ...(att.remote_routing_enabled === true ? { agent_ready_session_id: sessionId } : {}),
        };
      }
      case "operation.request": {
        if (att.role !== "client") return { ok: false, error: "invalid_role" };
        const pendingKey = msg.correlation_id || msg.message_id;
        if (!pendingKey) return { ok: false, error: "missing_correlation" };
        const normalized = this.buildOperationRequestPayload(
          String(msg.payload.op || msg.payload.capability || ""),
          msg.payload || {},
          pendingKey,
        );
        if (String(normalized.operation_id) !== pendingKey) {
          this.sendError(
            sessionId,
            "OWNMESH_E_BAD_ENVELOPE",
            "correlation_id must equal payload operation_id",
            pendingKey,
          );
          return { ok: false, error: "operation_id_mismatch" };
        }
        const capability = String(normalized.capability || "");
        const action = String(
          (normalized.arguments as Record<string, unknown> | undefined)?.action ||
            msg.payload.op ||
            "",
        );
        const requiredScope = requiredScopeForCapability(capability, action);
        if (!requiredScope || !requireScope(att.scope || "", requiredScope)) {
          return { ok: false, error: "insufficient_scope" };
        }
        this.pruneExpiredPending();
        if (this.pending.size >= MAX_PENDING_OPERATIONS) {
          this.sendError(sessionId, "OWNMESH_E_PENDING_LIMIT", "too many pending operations", pendingKey);
          return { ok: false, error: "pending_limit" };
        }
        const addBytes = new TextEncoder().encode(JSON.stringify(normalized)).byteLength;
        if (this.totalPendingPayloadBytes() + addBytes > MAX_PENDING_PAYLOAD_BYTES) {
          this.sendError(sessionId, "OWNMESH_E_PENDING_PAYLOAD_LIMIT", "pending payload budget exceeded", pendingKey);
          return { ok: false, error: "pending_payload_limit" };
        }
        // Client -> ready agent: stage pending only. DO persists then dispatches;
        // harness finalizes deferred_dispatch immediately. No direct sends here.
        const recipients: string[] = [];
        for (const [sid, session] of this.sessions) {
          if (this.isRemoteRoutingAgent(session)) recipients.push(sid);
        }
        const agentFrame = this.nextEnvelope("operation.request", normalized, pendingKey);
        void this.audit.append({
          kind: "operation.route",
          summary: "operation.request routed to agent",
          device_id: this.deviceId,
          meta: {
            correlation_id: pendingKey,
            agent_recipients: recipients.length,
            capability,
            action,
            deferred: true,
          },
        });
        if (recipients.length === 0) {
          // No pending mutation; defer device_offline to client after persist barrier.
          const offline = this.nextEnvelope(
            "operation.result",
            {
              operation_contract: OPERATION_CONTRACT_V1,
              operation_id: pendingKey,
              status: "device_offline",
              error: {
                code: "OWNMESH_E_DEVICE_OFFLINE",
                message: "No remote-routing-ready agent is connected",
                retryable: true,
              },
            },
            pendingKey,
          );
          return {
            ok: true,
            deferred_dispatch: {
              frame: JSON.stringify(offline),
              recipients: [sessionId],
              client_session_id: sessionId,
            },
          };
        }
        // Stage pending without notifyStateChange — caller owns the persist barrier
        // (mirrors prepareInjectOperation).
        this.pending.set(pendingKey, {
          correlation_id: pendingKey,
          type: action || capability || "operation.request",
          from_session: sessionId,
          created_at: Date.now(),
          payload: normalized,
          expires_at: agentFrame.expires_at,
          dispatch_count: 0,
        });
        return {
          ok: true,
          deferred_dispatch: {
            frame: JSON.stringify(agentFrame),
            recipients,
            pending_key: pendingKey,
            client_session_id: sessionId,
          },
        };
      }
      case "operation.result":
      case "operation.event":
      case "operation.progress": {
        if (att.role !== "agent" || att.phase !== "ready") return { ok: false, error: "invalid_state" };
        this.pruneExpiredPending();
        // Agent -> waiting clients (or all clients)
        const corr = msg.correlation_id;
        if (!corr || !this.pending.has(corr)) return { ok: false, error: "unknown_correlation" };
        const p = this.pending.get(corr)!;
        const resultOpId = msg.payload?.operation_id != null ? String(msg.payload.operation_id) : undefined;
        const pendingOpId = p.payload?.operation_id != null ? String(p.payload.operation_id) : undefined;
        // Bind operation_id when both sides present — mismatch rejected before forward.
        if (resultOpId && pendingOpId && resultOpId !== pendingOpId) {
          return { ok: false, error: "operation_id_mismatch" };
        }
        const boundOpId = resultOpId || pendingOpId;

        if (msg.type === "operation.result") {
          // Defer forward + pending removal until authoritative CAS succeeds.
          void this.audit.append({
            kind: "operation.result",
            summary: msg.type,
            device_id: this.deviceId,
            meta: {
              correlation_id: corr,
              from: att.role,
              operation_id: boundOpId,
              status: msg.payload?.status,
              deferred: true,
            },
          });
          return {
            ok: true,
            mcp_result: {
              correlation_id: corr,
              operation_id: boundOpId,
              payload: msg.payload || {},
            },
            deferred_forward: JSON.stringify(msg),
          };
        }

        // progress/event: forward immediately, keep pending.
        this.sendToSession(p.from_session, JSON.stringify(msg));
        void this.audit.append({
          kind: "operation.result",
          summary: msg.type,
          device_id: this.deviceId,
          meta: {
            correlation_id: corr,
            from: att.role,
            operation_id: boundOpId,
            status: msg.payload?.status,
          },
        });
        return { ok: true };
      }
      case "workspace.registry": {
        // #146: incremental registry refresh from a live ready agent. The
        // payload is the same shape as ready.workspace_registry and is
        // validated by the same allowlist; activation stays fail-closed in
        // workspace-activation until these generations are observed.
        if (att.role !== "agent" || att.phase !== "ready") return { ok: false, error: "invalid_state" };
        const refreshRegistry = readyWorkspaceRegistry(msg.payload);
        // Unlike `ready`, a legacy ids-only advertisement cannot prove which
        // local root a generation denotes, so a refresh without concrete
        // generations is rejected.
        if (
          refreshRegistry == null ||
          !Array.isArray(refreshRegistry.workspaces) ||
          refreshRegistry.workspaces.length < 1
        ) {
          this.sendError(
            sessionId,
            "OWNMESH_E_BAD_ENVELOPE",
            "invalid workspace registry",
            msg.correlation_id,
          );
          return { ok: false, error: "invalid_workspace_registry" };
        }
        const ack = this.nextEnvelope("workspace.registry.ack", { ok: true }, msg.correlation_id);
        this.sendToSession(sessionId, JSON.stringify(ack));
        void this.audit.append({
          kind: "device.ready",
          summary: "agent workspace registry refresh",
          device_id: this.deviceId,
          meta: { workspace_count: refreshRegistry.workspaces.length },
        });
        return {
          ok: true,
          workspace_registry_sync: {
            enforce_workspace: refreshRegistry.enforce_workspace,
            workspaces: refreshRegistry.workspaces,
          },
        };
      }
      case "ping": {
        const pong = this.nextEnvelope("pong", { t: Date.now() }, msg.correlation_id);
        this.sendToSession(sessionId, JSON.stringify(pong));
        return { ok: true };
      }
      default:
        return { ok: false, error: "unsupported_message_type" };
    }
  }

  /**
   * After authoritative MCP CAS succeeds, forward the deferred operation.result
   * and drop the matching pending entry. No-op (false) if correlation unknown.
   */
  finalizeOperationResult(correlationId: string, rawEnvelope: string): boolean {
    const p = this.pending.get(correlationId);
    if (!p) return false;
    this.sendToSession(p.from_session, rawEnvelope);
    this.pending.delete(correlationId);
    // Durable correlation tombstone: an approval/result may complete between a
    // Worker delivery and outbox finalization. Lease recovery must reconcile,
    // never dispatch the same stable correlation again after pending is gone.
    this.consumeInternalNonce(
      `correlation:${correlationId}`,
      Date.now() + PENDING_TTL_MS,
    );
    this.notifyStateChange();
    return true;
  }

  /**
   * Deliver deferred operation.request frames after durable persist (or immediately
   * in the harness). Re-probes ready agents at send time; if a staged pending_key
   * yields zero deliveries, clears pending and emits device_offline to the client.
   */
  finalizeDeferredDispatch(deferred: DeferredDispatch): number {
    let n = 0;
    if (deferred.pending_key) {
      // Agent path: deliver only to remote-routing-ready agents (socket may have died).
      for (const [sid, session] of this.sessions) {
        if (this.isRemoteRoutingAgent(session) && this.sendToSession(sid, deferred.frame)) {
          n++;
        }
      }
      if (n === 0) {
        this.pending.delete(deferred.pending_key);
        this.notifyStateChange();
        if (deferred.client_session_id) {
          const offline = this.nextEnvelope(
            "operation.result",
            {
              operation_contract: OPERATION_CONTRACT_V1,
              operation_id: deferred.pending_key,
              status: "device_offline",
              error: {
                code: "OWNMESH_E_DEVICE_OFFLINE",
                message: "No remote-routing-ready agent is connected",
                retryable: true,
              },
            },
            deferred.pending_key,
          );
          this.sendToSession(deferred.client_session_id, JSON.stringify(offline));
        }
      } else {
        const pending = this.pending.get(deferred.pending_key);
        if (pending) {
          pending.dispatched_at = Date.now();
          pending.dispatch_count = (pending.dispatch_count || 0) + 1;
        }
      }
      return n;
    }
    // Offline / client-only deferred frame (no pending staged).
    for (const sid of deferred.recipients) {
      if (this.sendToSession(sid, deferred.frame)) n++;
    }
    return n;
  }

  /** Roll back a staged WS operation.request pending entry (persist failure path). */
  rollbackDeferredDispatch(deferred: DeferredDispatch): void {
    if (deferred.pending_key) {
      this.pending.delete(deferred.pending_key);
    }
  }

  /**
   * Prepare HTTP-side operation injection: reserve pending + outbound seq.
   * Does NOT send to any agent. DeviceRoom must durable-persist then dispatch.
   * Does not call onStateChange — caller owns the persist barrier.
   */
  prepareInjectOperation(op: {
    type: string;
    payload: Record<string, unknown>;
    correlation_id: string;
    from_session?: string;
    /** Immutable control-plane expiry for the outbound operation.request envelope. */
    expires_at?: string;
  }):
    | { ok: true; prepared: PreparedInjectOperation }
    | { ok: false; result: { status: string; detail?: unknown } } {
    this.pruneExpiredPending();
    if (this.pending.size >= MAX_PENDING_OPERATIONS) {
      return { ok: false, result: { status: "rejected", detail: { code: "OWNMESH_E_PENDING_LIMIT" } } };
    }
    const payload = op.payload || {};
    const durableOfflineCancel =
      op.type === "ownmesh_cancel_operation" &&
      payload.capability === "operation.cancel";
    const addBytes = new TextEncoder().encode(JSON.stringify(payload)).byteLength;
    if (this.totalPendingPayloadBytes() + addBytes > MAX_PENDING_PAYLOAD_BYTES) {
      return {
        ok: false,
        result: { status: "rejected", detail: { code: "OWNMESH_E_PENDING_PAYLOAD_LIMIT" } },
      };
    }
    // Fail closed on offline before mutating ordinary operations. An exact
    // operation.cancel control is the sole exception: it must remain durable
    // and win reconnect ordering over the fenced original request.
    // Only agents that advertised remote_routing_enabled=true count as ready for E2.
    let readyAgents = 0;
    for (const session of this.sessions.values()) {
      if (this.isRemoteRoutingAgent(session)) readyAgents++;
    }
    if (readyAgents === 0 && !durableOfflineCancel) {
      return {
        ok: false,
        result: {
          status: "device_offline",
          detail: { code: "OWNMESH_E_DEVICE_OFFLINE", reason: "no_ready_agent" },
        },
      };
    }
    const from = op.from_session || "http_client";
    let created_session_id: string | undefined;
    if (!this.sessions.has(from)) {
      const admitted = this.registerSession({
        role: "client",
        device_id: this.deviceId,
        session_id: from,
        connected_at: Date.now(),
        phase: "connected",
      });
      if (!admitted) {
        return {
          ok: false,
          result: { status: "rejected", detail: { code: "OWNMESH_E_GUARD_SESSION_LIMIT" } },
        };
      }
      created_session_id = from;
    }
    const normalized = this.buildOperationRequestPayload(op.type, payload, op.correlation_id);
    if (String(normalized.operation_id) !== op.correlation_id) {
      return {
        ok: false,
        result: {
          status: "rejected",
          detail: {
            code: "OWNMESH_E_BAD_ENVELOPE",
            message: "correlation_id must equal payload operation_id",
          },
        },
      };
    }
    if (!String(normalized.capability || "").trim()) {
      return {
        ok: false,
        result: {
          status: "rejected",
          detail: { code: "OWNMESH_E_BAD_ENVELOPE", message: "capability is required" },
        },
      };
    }
    // E3: prefer the immutable control-plane expiry from inject metadata (not a
    // protocol payload field — ownmesh.operation/1.0 request denies unknown keys).
    // Reject already-expired bindings before staging pending/seq.
    let boundExpiresAt: string | undefined;
    const injectExpiry =
      typeof op.expires_at === "string" && op.expires_at.trim() !== ""
        ? String(op.expires_at)
        : undefined;
    if (injectExpiry) {
      const expMs = Date.parse(injectExpiry);
      if (!Number.isFinite(expMs)) {
        return {
          ok: false,
          result: {
            status: "rejected",
            detail: { code: "OWNMESH_E_BAD_ENVELOPE", message: "expires_at is not a valid timestamp" },
          },
        };
      }
      if (expMs <= Date.now()) {
        return {
          ok: false,
          result: {
            status: "rejected",
            detail: { code: "OWNMESH_E_ENVELOPE_EXPIRED", message: "operation expires_at already elapsed" },
          },
        };
      }
      boundExpiresAt = injectExpiry;
    }
    const envelope = this.nextEnvelope(
      "operation.request",
      normalized,
      op.correlation_id,
      boundExpiresAt ? { expiresAt: boundExpiresAt } : undefined,
    );
    this.pending.set(op.correlation_id, {
      correlation_id: op.correlation_id,
      type: op.type || String((normalized.arguments as Record<string, unknown> | undefined)?.action || normalized.capability),
      from_session: from,
      created_at: Date.now(),
      payload: normalized,
      expires_at: envelope.expires_at,
      dispatched_at: undefined,
      dispatch_count: 0,
    });
    return {
      ok: true,
      prepared: {
        correlation_id: op.correlation_id,
        envelope,
        from_session: from,
        created_session_id,
      },
    };
  }

  /** Roll back a prepared inject that was never durably persisted / dispatched. */
  rollbackPreparedInject(prepared: PreparedInjectOperation): void {
    this.pending.delete(prepared.correlation_id);
    if (prepared.created_session_id && this.sessions.has(prepared.created_session_id)) {
      // Only drop synthetic session if it still has no other pending work.
      let other = false;
      for (const p of this.pending.values()) {
        if (p.from_session === prepared.created_session_id) {
          other = true;
          break;
        }
      }
      if (!other) this.unregisterSession(prepared.created_session_id);
    }
  }

  /**
   * Dispatch a previously prepared inject — send only.
   * Must be called only after durable persist of pending/seq/(nonce) succeeded.
   * Explicit ordering (Cloudflare output-gate compatible): prepare → persist → dispatch.
   */
  dispatchPreparedInject(prepared: PreparedInjectOperation): { status: string; detail?: unknown } {
    const raw = JSON.stringify(prepared.envelope);
    let n = 0;
    for (const [sid, session] of this.sessions) {
      if (this.isRemoteRoutingAgent(session) && this.sendToSession(sid, raw)) n++;
    }
    void this.audit.append({
      kind: "operation.route",
      summary: "http inject operation",
      device_id: this.deviceId,
      meta: {
        correlation_id: prepared.correlation_id,
        agent_recipients: n,
        capability: prepared.envelope.payload?.capability,
        action: (prepared.envelope.payload?.arguments as Record<string, unknown> | undefined)?.action,
      },
    });
    const pending = this.pending.get(prepared.correlation_id);
    const durableOfflineCancel =
      pending?.type === "ownmesh_cancel_operation" &&
      prepared.envelope.payload?.capability === "operation.cancel";
    if (n === 0 && durableOfflineCancel) {
      return {
        status: "pending",
        detail: {
          code: "OWNMESH_CANCEL_QUEUED_FOR_RECONNECT",
          correlation_id: prepared.correlation_id,
          queued_for_reconnect: true,
        },
      };
    }
    if (n === 0) {
      this.pending.delete(prepared.correlation_id);
      this.notifyStateChange();
      return {
        status: "device_offline",
        detail: { code: "OWNMESH_E_DEVICE_OFFLINE", reason: "no_ready_agent" },
      };
    }
    if (pending) {
      pending.dispatched_at = Date.now();
      pending.dispatch_count = (pending.dispatch_count || 0) + 1;
      if (prepared.envelope.expires_at) pending.expires_at = prepared.envelope.expires_at;
    }
    return {
      status: "routed_to_device",
      detail: { recipients: n, correlation_id: prepared.correlation_id },
    };
  }

  /**
   * HTTP-side injection of an operation (from Worker MCP path / harness).
   * Public signature stable: prepare + dispatch without an intervening persist barrier.
   * DeviceRoom.fetch inserts durable persist between prepare and dispatch.
   */
  injectOperation(op: {
    type: string;
    payload: Record<string, unknown>;
    correlation_id: string;
    from_session?: string;
    expires_at?: string;
  }): { status: string; detail?: unknown } {
    const prep = this.prepareInjectOperation(op);
    if (!prep.ok) return prep.result;
    // Harness/unit path: no DO storage — notify so optional onStateChange hooks still fire.
    this.notifyStateChange();
    return this.dispatchPreparedInject(prep.prepared);
  }

  status(): {
    device_id: string;
    sessions: number;
    pending: number;
    agents: number;
    clients: number;
    ready_agents: number;
    connection_status: "online" | "offline";
  } {
    this.pruneExpiredPending();
    let agents = 0;
    let clients = 0;
    let readyAgents = 0;
    for (const s of this.sessions.values()) {
      if (s.role === "agent") {
        agents++;
        if (s.phase === "ready") readyAgents++;
      }
      else clients++;
    }
    return {
      device_id: this.deviceId,
      sessions: this.sessions.size,
      pending: this.pending.size,
      agents,
      clients,
      ready_agents: readyAgents,
      // A room can authoritatively say online/offline only while it has a
      // live hibernatable WebSocket attachment. The Worker maps probe failures
      // to `unknown` rather than inferring a disconnect.
      connection_status: readyAgents > 0 ? "online" : "offline",
    };
  }
}

function pruneSeenMessageIds(guard: SessionIngressGuard, now: number): number {
  let removed = 0;
  for (const [id, at] of [...guard.seenMessageIds]) {
    if (!Number.isFinite(at) || now - at > SEEN_MESSAGE_ID_TTL_MS) {
      guard.seenMessageIds.delete(id);
      removed++;
    }
  }
  // Bound memory: keep a rolling window of most-recent ids.
  if (guard.seenMessageIds.size > MAX_SEEN_MESSAGE_IDS) {
    const ordered = [...guard.seenMessageIds.entries()].sort((a, b) => a[1] - b[1]);
    const overflow = guard.seenMessageIds.size - MAX_SEEN_MESSAGE_IDS;
    for (let i = 0; i < overflow; i++) {
      guard.seenMessageIds.delete(ordered[i]![0]);
      removed++;
    }
  }
  return removed;
}

/**
 * In-memory harness for E2E tests (no real WebSocket / DO runtime).
 */
export class DeviceRoomHarness {
  router: DeviceRoomRouter;
  /** session_id -> received messages */
  inboxes = new Map<string, string[]>();

  constructor(deviceId: string, verifyProof?: (deviceId: string, message: string, signature: string) => boolean | Promise<boolean>) {
    this.router = new DeviceRoomRouter(deviceId, {
      sendToSession: (sessionId, data) => {
        const box = this.inboxes.get(sessionId) || [];
        box.push(data);
        this.inboxes.set(sessionId, box);
        return true;
      },
      sendToRole: (role, data) => {
        let n = 0;
        for (const [sid, att] of this.router.sessions) {
          if (att.role === role) {
            const box = this.inboxes.get(sid) || [];
            box.push(data);
            this.inboxes.set(sid, box);
            n++;
          }
        }
        return n;
      },
      verifyProof,
    });
  }

  connect(role: SessionRole, sessionId?: string, scope = "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session"): string {
    const sid = sessionId || randomId(role === "agent" ? "ags_" : "cls_");
    this.inboxes.set(sid, []);
    const admitted = this.router.registerSession({
      role,
      device_id: this.router.deviceId,
      session_id: sid,
      connected_at: Date.now(),
      phase: "connected",
      scope: role === "client" ? scope : undefined,
    });
    if (!admitted) {
      this.inboxes.delete(sid);
      throw new Error("guard_session_limit");
    }
    return sid;
  }

  async send(sessionId: string, envelope: DeviceEnvelope | Record<string, unknown>): Promise<HandleMessageResult> {
    const result = await this.router.handleMessage(sessionId, JSON.stringify(envelope));
    // Harness has no durable store — finalize deferred result/request routing immediately.
    // Production DeviceRoom applies persist/CAS barriers before finalize.
    if (result.ok && result.mcp_result?.correlation_id && result.deferred_forward) {
      this.router.finalizeOperationResult(result.mcp_result.correlation_id, result.deferred_forward);
    }
    if (result.ok && result.deferred_dispatch) {
      this.router.finalizeDeferredDispatch(result.deferred_dispatch);
    }
    return result;
  }

  /** Send a raw WS text frame (for malformed / oversized guard tests). */
  async sendRaw(sessionId: string, raw: string): Promise<HandleMessageResult> {
    const result = await this.router.handleMessage(sessionId, raw);
    if (result.ok && result.mcp_result?.correlation_id && result.deferred_forward) {
      this.router.finalizeOperationResult(result.mcp_result.correlation_id, result.deferred_forward);
    }
    if (result.ok && result.deferred_dispatch) {
      this.router.finalizeDeferredDispatch(result.deferred_dispatch);
    }
    return result;
  }

  drain(sessionId: string): string[] {
    const box = this.inboxes.get(sessionId) || [];
    this.inboxes.set(sessionId, []);
    return box;
  }
}

/** Minimal storage surface used by DeviceRoom persistence (DO state.storage()). */
export type DeviceRoomStorage = {
  get<T = unknown>(key: string): Promise<T | undefined>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<boolean | void>;
  setAlarm?(scheduledTime: number): Promise<void>;
  deleteAlarm?(): Promise<boolean | void>;
};

/**
 * Durable Object class — hibernation-friendly WebSocket device room.
 * Exported from the Worker module.
 */
export class DeviceRoom {
  state: DurableObjectState;
  env: { DB?: D1Database; OAUTH_ISSUER?: string; OWNMESH_ALLOWED_ORIGINS?: string; SESSION_SECRET?: string };
  router: DeviceRoomRouter;
  /** ws -> session_id */
  wsSessions = new Map<WebSocket, string>();
  deviceId: string;
  devicePublicKey = "";
  /** Settles after hibernation storage + socket restore. */
  readonly ready: Promise<void>;
  private persistChain: Promise<void> = Promise.resolve();
  /**
   * When true, storage restore/persist failed — refuse ops/upgrade and close sockets.
   * Fail closed: never silently start clean after a restore error.
   */
  private storageBroken = false;

  constructor(state: DurableObjectState, env: { DB?: D1Database; OAUTH_ISSUER?: string; OWNMESH_ALLOWED_ORIGINS?: string; SESSION_SECRET?: string }) {
    this.state = state;
    this.env = env;
    this.deviceId = "unknown";
    this.router = this.buildRouter("unknown");

    // Cloudflare: block concurrency until storage-backed state is loaded.
    // https://developers.cloudflare.com/durable-objects/api/state/#blockconcurrencywhile
    this.ready = this.state.blockConcurrencyWhile(async () => {
      await this.restoreFromStorage();
      if (this.storageBroken) return;
      if (this.router.deviceId !== "unknown") this.deviceId = this.router.deviceId;
      // Restore hibernated sockets after authoritative storage import.
      // https://developers.cloudflare.com/durable-objects/examples/websocket-hibernation-server/
      for (const ws of this.state.getWebSockets()) {
        const att = ws.deserializeAttachment() as SessionAttachment | null;
        if (att) {
          if (att.device_id) this.deviceId = att.device_id;
          const admitted = this.router.registerSession(att);
          if (!admitted) {
            // At cap with no detached slot — reject excess without evicting live peers.
            try {
              ws.close(1013, "guard session limit");
            } catch {
              /* ignore */
            }
            continue;
          }
          this.wsSessions.set(ws, att.session_id);
        }
      }
      if (this.deviceId !== "unknown") {
        this.router.deviceId = this.deviceId;
      }
      const expired = this.router.pruneExpiredPending();
      if (expired.length > 0) {
        try {
          await this.reconcileExpiredPending(expired);
          await this.persistNow();
        } catch {
          this.storageBroken = true;
          this.failClosedAll("storage unavailable", 1013);
        }
      } else {
        try {
          await this.reschedulePendingAlarm();
        } catch {
          this.storageBroken = true;
          this.failClosedAll("storage unavailable", 1013);
        }
      }
    });

    try {
      this.state.setWebSocketAutoResponse?.(
        new WebSocketRequestResponsePair("ping", "pong"),
      );
    } catch {
      // older runtime without auto-response
    }
  }

  private buildRouter(deviceId: string): DeviceRoomRouter {
    return new DeviceRoomRouter(deviceId, {
      verifyProof: (_deviceId, message, signature) => verifyEd25519Hex(this.devicePublicKey, message, signature),
      sendToSession: (sessionId, data) => {
        for (const [ws, sid] of this.wsSessions) {
          if (sid === sessionId) {
            try {
              ws.send(data);
              return true;
            } catch {
              return false;
            }
          }
        }
        return false;
      },
      sendToRole: (role, data) => {
        let n = 0;
        for (const [ws, sid] of this.wsSessions) {
          const att = this.router.sessions.get(sid);
          if (att?.role === role) {
            try {
              ws.send(data);
              n++;
            } catch {
              /* ignore broken socket */
            }
          }
        }
        return n;
      },
      onStateChange: () => {
        this.queuePersist();
      },
    });
  }

  private storage(): DeviceRoomStorage {
    return this.state.storage as unknown as DeviceRoomStorage;
  }

  private async restoreFromStorage(): Promise<void> {
    try {
      const snap = await this.storage().get<PersistedRoomState>(ROOM_STATE_STORAGE_KEY);
      if (snap) this.router.importState(snap);
    } catch {
      // Fail closed: never swallow restore errors into a clean-slate success path.
      this.storageBroken = true;
      this.router = this.buildRouter(this.deviceId || "unknown");
    }
  }

  private queuePersist(): void {
    if (this.storageBroken) return;
    this.persistChain = this.persistChain
      .then(() => this.persistNow())
      .catch(() => {
        /* persistNow already fail-closed */
      });
  }

  /**
   * Durable write of room state. On failure marks storage broken, closes sockets,
   * and throws — callers must not report success afterward.
   */
  private async persistNow(): Promise<void> {
    if (this.storageBroken) {
      throw new Error("storage_broken");
    }
    try {
      const snap = this.router.exportState();
      await this.storage().put(ROOM_STATE_STORAGE_KEY, snap);
      await this.reschedulePendingAlarm();
    } catch (err) {
      this.storageBroken = true;
      const message = err instanceof Error ? err.message : String(err);
      void this.router.audit.append({
        kind: "device.storage_fail",
        summary: message,
        device_id: this.deviceId,
        meta: { phase: "persistNow" },
      });
      this.failClosedAll("storage unavailable", 1013);
      throw err instanceof Error ? err : new Error("storage_persist_failed");
    }
  }

  /** Keep the single DO alarm at the earliest pending deadline. */
  private async reschedulePendingAlarm(): Promise<void> {
    const storage = this.storage();
    let earliest = Number.POSITIVE_INFINITY;
    for (const pending of this.router.pending.values()) {
      const deadline = pendingDeadlineMs(pending);
      if (Number.isFinite(deadline) && deadline < earliest) earliest = deadline;
    }
    if (Number.isFinite(earliest)) {
      await storage.setAlarm?.(earliest);
    } else {
      await storage.deleteAlarm?.();
    }
  }

  /**
   * Terminalize only the operation that is exactly bound to the expired room
   * correlation.  A malformed/substituted pending snapshot is dropped locally
   * but must never update an unrelated D1 row.
   */
  private async reconcileExpiredPending(expired: PendingOperation[]): Promise<void> {
    if (expired.length === 0) return;
    if (!this.env.DB) throw new Error("storage_unavailable");
    const store = createStore(this.env);
    for (const pending of expired) {
      const operationId =
        typeof pending.payload?.operation_id === "string"
          ? pending.payload.operation_id
          : "";
      if (!operationId || operationId !== pending.correlation_id || this.deviceId === "unknown") {
        continue;
      }
      const expectedApprovalDecision = approvalDecisionBindingFromPayload(pending.payload);
      const deadline = pendingDeadlineMs(pending);
      const approvalDecisionResult = expectedApprovalDecision
        ? {
            approval_decision_applied: false,
            target_operation_id: expectedApprovalDecision.target_operation_id,
            approval_id: expectedApprovalDecision.approval_id,
            decision: expectedApprovalDecision.decision,
          }
        : {
            phase: "expired",
            expires_at: Number.isFinite(deadline) ? new Date(deadline).toISOString() : null,
            error: {
              code: "OWNMESH_E_OPERATION_EXPIRED",
              message: "operation expired before a device result arrived",
              retryable: true,
            },
          };
      // applyMcpOperationResult is the single binding/CAS implementation. It
      // checks operation, correlation, device and terminal-status races before
      // writing; a stale snapshot can therefore never overwrite a completion.
      const applied = await applyMcpOperationResult(store, {
        operationId,
        correlationId: pending.correlation_id,
        deviceId: this.deviceId,
        expectedApprovalDecision,
        payload: {
          operation_contract: OPERATION_CONTRACT_V1,
          operation_id: operationId,
          status: "failed",
          result: approvalDecisionResult,
          error: {
            code: "OWNMESH_E_OPERATION_EXPIRED",
            message: "operation expired before a device result arrived",
            retryable: true,
          },
        },
      });
      // A terminal race is benign and must preserve the winner. Every other
      // binding failure is a corrupt/substituted room snapshot: fail closed
      // instead of silently accepting or redirecting the expiry transition.
      if (!applied.ok && applied.error !== "cas_conflict") {
        throw new Error(`operation_expiry_reconcile_${applied.error}`);
      }
    }
  }

  /** Await queued persistence (tests / explicit checkpoints). */
  async flushPersist(): Promise<void> {
    await this.ready;
    await this.persistChain;
    await this.persistNow();
  }

  /** True when restore/persist failed — refuse ops/upgrade. */
  get isStorageBroken(): boolean {
    return this.storageBroken;
  }

  /** Close every live socket and clear session maps (fail closed). */
  private failClosedAll(reason: string, code = 1013): void {
    for (const [socket, sid] of [...this.wsSessions]) {
      try {
        socket.close(code, reason);
      } catch {
        /* already closed */
      }
      this.router.unregisterSession(sid);
      this.wsSessions.delete(socket);
    }
    // Drop in-flight work so half-success cannot occur without DB/credentials.
    this.router.pending.clear();
    // Avoid re-entrant persist when storage is already known-broken.
    if (!this.storageBroken) {
      this.queuePersist();
    }
  }

  private refuseIfStorageBroken(): Response | null {
    if (!this.storageBroken) return null;
    this.failClosedAll("storage unavailable", 1013);
    return json({ error: "storage_unavailable" }, { status: 503 });
  }

  /**
   * Re-check device active + every session credential (revoked/expires_at) via store.
   * DB missing → fail closed (close all WS). No half-success path.
   */
  private async revalidateCredentials(opts?: {
    /** When set, require this session to remain valid after recheck. */
    requireSessionId?: string;
  }): Promise<{ ok: true } | { ok: false; error: string; status: number }> {
    if (!this.env.DB) {
      this.storageBroken = true;
      this.failClosedAll("storage unavailable", 1013);
      return { ok: false, error: "storage_unavailable", status: 503 };
    }
    try {
      const store = createStore(this.env);
      const device = await store.getDevice(this.deviceId);
      if (!device || device.revoked || device.status !== "active") {
        this.failClosedAll("device not active", 1008);
        return { ok: false, error: "device_not_active", status: 403 };
      }
      this.devicePublicKey = device.public_key;

      for (const [socket, sid] of [...this.wsSessions]) {
        const session = this.router.sessions.get(sid);
        let valid = false;
        try {
          valid =
            Boolean(session?.auth_hash) &&
            (await store.validateDeviceSession(session!.auth_hash!, session!.role, this.deviceId));
        } catch {
          // D1/session lookup failure: fail closed for every live socket.
          this.storageBroken = true;
          this.failClosedAll("storage unavailable", 1013);
          return { ok: false, error: "storage_unavailable", status: 503 };
        }
        if (!valid) {
          try {
            socket.close(1008, "authorization revoked");
          } catch {
            /* closed */
          }
          this.router.unregisterSession(sid);
          this.wsSessions.delete(socket);
        }
      }

      if (opts?.requireSessionId && !this.router.sessions.has(opts.requireSessionId)) {
        return { ok: false, error: "authorization_revoked", status: 401 };
      }
      return { ok: true };
    } catch {
      // store.getDevice / createStore throw must not leak from DO handlers.
      this.storageBroken = true;
      this.failClosedAll("storage unavailable", 1013);
      return { ok: false, error: "storage_unavailable", status: 503 };
    }
  }

  /**
   * Persist a coarse last-seen marker once an Agent has completed proof+ready.
   * This deliberately runs only after accepted connections, never per
   * heartbeat or status probe; unchanged reconnects are D1-throttled by the
   * store.
   */
  private async recordAuthenticatedAgentConnection(
    metadata: NonNullable<HandleMessageResult["authenticated_agent"]>,
  ): Promise<void> {
    if (!this.env.DB) throw new Error("storage_unavailable");
    const store = createStore(this.env);
    const updated = await store.recordDeviceReadyConnection(this.deviceId, {
      ...metadata,
      last_seen_at: nowIso(),
    });
    if (!updated) throw new Error("device_not_active");
    if (metadata.workspaces) {
      await store.syncDeviceWorkspaces(this.deviceId, metadata.workspaces);
    }
  }

  /**
   * Verify that the immutable bound action still names the current, durable
   * OAuth credential epoch.  A signed internal context authenticates the
   * router caller, but it must never revive an operation authorized under a
   * rotated or revoked principal credential.
   */
  private async credentialGenerationCurrent(
    payload: Record<string, unknown>,
    expected?: { principal_id: string; tenant_id: string },
  ): Promise<"ok" | "binding_mismatch" | "credential_generation_mismatch" | "storage_unavailable"> {
    if (!this.env.DB) return "storage_unavailable";
    const binding = boundPrincipalAuthority(payload);
    if (!binding) return "binding_mismatch";
    if (
      expected &&
      (binding.principal_id !== expected.principal_id || binding.tenant_id !== expected.tenant_id)
    ) return "binding_mismatch";
    try {
      // #162: one shared decision with the Worker-side gates in mcp.ts.
      // Authority is removed by revocation and refresh-family reuse, not by
      // reissuing a token.
      const current = await createStore(this.env).getPrincipal(binding.principal_id);
      return boundPrincipalAuthorityCurrent(binding, current)
        ? "ok"
        : "credential_generation_mismatch";
    } catch {
      return "storage_unavailable";
    }
  }

  private async workspaceAuthorityCurrent(
    store: ControlPlaneStore,
    payload: Record<string, unknown>,
    operation: McpOperationRecord | null,
  ): Promise<WorkspaceAuthorityResult> {
    const binding = workspaceAuthorityBinding(payload);
    if (!binding) return "binding_mismatch";
    if (!operation) return "binding_mismatch";
    if (binding.workspace_id === null) {
      return operation.workspace_id !== null ? "binding_mismatch" : "ok";
    }
    if (
      operation.device_id !== this.deviceId ||
      operation.workspace_id !== binding.workspace_id ||
      operation.action?.workspace_id !== binding.workspace_id ||
      operation.action?.workspace_version !== binding.version
    ) return "binding_mismatch";

    // workspace.add establishes the first device-local generation. Cancellation
    // controls must remain deliverable after a remap so they can only reduce
    // side effects; neither exception grants access to workspace content.
    if (operation.tool === "ownmesh_workspace_add" ||
        operation.tool === "ownmesh_cancel_operation" ||
        operation.tool === "__transfer_cancel_control") return "ok";
    try {
      const workspace = await store.getWorkspace(this.deviceId, binding.workspace_id);
      return workspace?.active && workspace.local_generation && workspace.version === binding.version
        ? "ok"
        : "workspace_authority_changed";
    } catch {
      return "storage_unavailable";
    }
  }

  /**
   * Recheck every persisted request immediately before reconnect delivery.
   * Invalidated authority becomes a terminal durable result and is removed
   * before any Agent socket is sent a frame.
   */
  private async redeliverCurrentPending(
    sessionId: string,
    agentPendingCorrelations: string[] = [],
  ): Promise<void> {
    if (!this.env.DB) throw new Error("storage_unavailable");
    const store = createStore(this.env);
    let removed = false;
    for (const pending of [...this.router.pending.values()]) {
      if (pending.live_only) continue;
      const operationId =
        typeof pending.payload.operation_id === "string"
          ? pending.payload.operation_id
          : pending.correlation_id;

      // The control-plane target state is authoritative at reconnect. In
      // particular, cancel_requested is a durable fence written before the
      // cancel signal is routed; never resurrect that original request from a
      // DeviceRoom pending snapshot.
      const operation = await store.getMcpOperation(operationId);
      if (operation && OPERATION_DISPATCH_FENCE_STATUSES.has(operation.status)) {
        this.router.pending.delete(pending.correlation_id);
        removed = true;
        continue;
      }

      const workspaceCheck = await this.workspaceAuthorityCurrent(store, pending.payload, operation);
      if (workspaceCheck === "storage_unavailable") throw new Error("storage_unavailable");
      if (workspaceCheck !== "ok") {
        this.router.pending.delete(pending.correlation_id);
        removed = true;
        await store.updateMcpOperation(
          operationId,
          {
            status: "failed",
            summary: "workspace authority changed before device delivery",
            data: {
              error: {
                code: "OWNMESH_E_WORKSPACE_AUTHORITY_CHANGED",
                message: "workspace mapping changed before device delivery",
                retryable: false,
              },
            },
            approval_required: false,
          },
          ["pending", "running", "approval_required", "cancel_requested"],
        );
        continue;
      }

      const check = await this.credentialGenerationCurrent(pending.payload);
      if (check === "ok") continue;
      if (check === "storage_unavailable") throw new Error("storage_unavailable");
      // #162: same bounded reason and retry contract as the Worker-side gates.
      const reason = await boundAuthorityInvalidationReason(store, pending.payload);
      this.router.pending.delete(pending.correlation_id);
      removed = true;
      await store.updateMcpOperation(
        operationId,
        {
          status: "failed",
          summary: authorityInvalidationSummary(reason, "delivery"),
          data: { error: authorityInvalidationError(reason, "delivery") },
          approval_required: false,
        },
        ["pending", "running", "approval_required", "cancel_requested"],
      );
    }
    // Persist removals before delivery; otherwise hibernation could resurrect
    // an invalid pending operation after a successful generation check.
    if (removed) await this.persistNow();
    await this.reconcileAgentPending(sessionId, agentPendingCorrelations);
    const redelivered = this.router.redeliverPendingToAgent(sessionId);
    if (redelivered > 0) await this.persistNow();
  }

  /**
   * Return only D1-authoritative terminal/fenced correlations reported by this
   * authenticated Agent. Missing, foreign-device and non-terminal operations
   * are intentionally omitted: the Agent must never purge unconfirmed work.
   */
  private async reconcileAgentPending(
    sessionId: string,
    correlations: string[],
  ): Promise<void> {
    if (!this.env.DB || correlations.length === 0) return;
    const store = createStore(this.env);
    const terminalCorrelations: string[] = [];
    for (const correlation of correlations) {
      const operation = await store.getMcpOperation(correlation);
      if (
        operation?.device_id === this.deviceId &&
        OPERATION_DISPATCH_FENCE_STATUSES.has(operation.status)
      ) {
        terminalCorrelations.push(correlation);
      }
    }
    if (terminalCorrelations.length === 0) return;
    const envelope = this.router.nextEnvelope("operation.reconcile", {
      terminal_correlations: terminalCorrelations,
    });
    // A failed send is safe: the Agent reports the still-durable correlations
    // again on its next authenticated ready handshake.
    this.router.sendToSession(sessionId, JSON.stringify(envelope));
  }

  async fetch(request: Request): Promise<Response> {
    await this.ready;
    const url = new URL(request.url);
    const deviceId =
      url.searchParams.get("device_id") ||
      url.pathname.split("/").filter(Boolean).pop() ||
      this.deviceId;
    if (deviceId && deviceId !== "unknown") {
      this.deviceId = deviceId;
      this.router.deviceId = deviceId;
    }

    if (url.pathname.endsWith("/status") || url.pathname === "/status") {
      if (this.storageBroken) {
        return json({ error: "storage_unavailable", hibernation: true }, { status: 503 });
      }
      const expired = this.router.pruneExpiredPending();
      if (expired.length > 0) {
        try {
          await this.reconcileExpiredPending(expired);
          await this.persistNow();
        } catch {
          this.storageBroken = true;
          this.failClosedAll("storage unavailable", 1013);
          return json({ error: "storage_unavailable", hibernation: true }, { status: 503 });
        }
      }
      return json({
        ...this.router.status(),
        hibernation: true,
        network_outbound_from_do: false,
        websockets: this.state.getWebSockets().length,
      });
    }

    if (url.pathname.endsWith("/operation") && request.method === "POST") {
      const broken = this.refuseIfStorageBroken();
      if (broken) return broken;
      // Read body once so method/path/body_sha256 bind matches exact bytes sent.
      // Enforce the application byte cap before allocating/parsing JSON.
      const clHeader = request.headers.get("content-length");
      if (clHeader != null && clHeader !== "") {
        const n = Number(clHeader);
        if (Number.isFinite(n) && n > MAX_PAYLOAD_BYTES) {
          return json(
            { error: "payload_too_large", max_bytes: MAX_PAYLOAD_BYTES },
            { status: 413 },
          );
        }
      }
      const rawBody = await readTextLimited(request, MAX_PAYLOAD_BYTES);
      if (rawBody === null) {
        return json(
          { error: "payload_too_large", max_bytes: MAX_PAYLOAD_BYTES },
          { status: 413 },
        );
      }
      const bodySha256 = await sha256Hex(rawBody);
      // Canonical internal path (Worker mints path:"/operation").
      const opPath = "/operation";
      // Signed short-lived internal context only — constant edge header is never authority.
      // Crypto + method/path/body bind here; replay is room-level durable (not process-local).
      const opCtx = await verifyInternalContext(
        this.env.SESSION_SECRET,
        request.headers.get(internalContextHeaderName()),
        {
          op: "operation",
          device_id: this.deviceId,
          method: "POST",
          path: opPath,
          body_sha256: bodySha256,
          // Room DO storage is the replay authority across hibernation.
          replayGuard: null,
        },
      );
      if (!opCtx.ok) return json({ error: opCtx.error }, { status: opCtx.status });
      // Important op: DB missing fails closed for existing WS too (no half-success).
      const security = await this.revalidateCredentials();
      if (!security.ok) {
        return json({ error: security.error }, { status: security.status });
      }
      // Binding: caller must be device owner or explicit tenant member (same tenant).
      if (this.env.DB) {
        try {
          const storeForBind = createStore(this.env);
          const boundDevice = await storeForBind.getDevice(this.deviceId);
          if (boundDevice) {
            if (boundDevice.tenant_id !== opCtx.claims.tenant_id) {
              return json({ error: "binding_mismatch" }, { status: 403 });
            }
            const allowed = await storeForBind.canOperateDevice(
              this.deviceId,
              opCtx.claims.principal_id,
              opCtx.claims.tenant_id,
            );
            if (!allowed) {
              return json({ error: "binding_mismatch" }, { status: 403 });
            }
          }
        } catch {
          // D1 bind lookup throw: tear down existing WS, refuse op.
          this.storageBroken = true;
          this.failClosedAll("storage unavailable", 1013);
          return json({ error: "storage_unavailable" }, { status: 503 });
        }
      }
      let body: {
        type: string;
        payload?: Record<string, unknown>;
        correlation_id?: string;
        expires_at?: string;
      };
      try {
        body = JSON.parse(rawBody) as typeof body;
      } catch {
        return json({ error: "bad_json" }, { status: 400 });
      }
      // Optional correlation bind when claim carries one.
      if (
        opCtx.claims.correlation_id &&
        body.correlation_id &&
        opCtx.claims.correlation_id !== body.correlation_id
      ) {
        return json({ error: "binding_mismatch" }, { status: 403 });
      }
      const generationCheck = await this.credentialGenerationCurrent(body.payload || {}, {
        principal_id: opCtx.claims.principal_id,
        tenant_id: opCtx.claims.tenant_id,
      });
      if (generationCheck !== "ok") {
        if (generationCheck === "storage_unavailable") {
          this.storageBroken = true;
          this.failClosedAll("storage unavailable", 1013);
          return json({ error: "storage_unavailable" }, { status: 503 });
        }
        return json({ error: generationCheck }, { status: 403 });
      }

      // ---- Explicit durable ordering (output-gate compatible) ----
      // 0) reject known nonce  1) prepare pending+seq  2) consume nonce
      // 3) persistNow  4) dispatch send
      // Never send to any agent before durable persist succeeds.
      // Pre-check avoids prepare/rollback clobbering an already-durable pending entry.
      if (this.router.hasInternalNonce(opCtx.claims.nonce)) {
        return json({ error: "replay" }, { status: 401 });
      }
      const correlationId =
        body.correlation_id || opCtx.claims.correlation_id || randomId("op_");

      const correlationTombstone = `correlation:${correlationId}`;
      if (this.router.hasInternalNonce(correlationTombstone)) {
        if (!this.router.consumeInternalNonce(opCtx.claims.nonce, opCtx.claims.exp)) {
          return json({ error: "replay" }, { status: 401 });
        }
        try {
          await this.persistNow();
        } catch {
          this.router.releaseInternalNonce(opCtx.claims.nonce);
          return json({ error: "storage_unavailable" }, { status: 503 });
        }
        return json({
          status: "routed_to_device",
          detail: { correlation_id: correlationId, deduplicated: true, completed: true },
        });
      }

      // Re-read the authoritative control-plane state at the final routing
      // boundary. This closes the race where cancellation wins after a Worker
      // claim but before DeviceRoom accepts/sends the original operation.
      const operationId =
        typeof body.payload?.operation_id === "string"
          ? body.payload.operation_id
          : correlationId;
      try {
        const store = createStore(this.env);
        const operation = await store.getMcpOperation(operationId);
        if (operation) {
          if (
            operation.device_id !== this.deviceId ||
            operation.principal_id !== opCtx.claims.principal_id ||
            operation.tenant_id !== opCtx.claims.tenant_id
          ) {
            return json({ error: "binding_mismatch" }, { status: 403 });
          }
          if (OPERATION_DISPATCH_FENCE_STATUSES.has(operation.status)) {
            if (!this.router.consumeInternalNonce(opCtx.claims.nonce, opCtx.claims.exp)) {
              return json({ error: "replay" }, { status: 401 });
            }
            this.router.pending.delete(correlationId);
            try {
              // Persist the nonce and pending removal before acknowledging the
              // fence, so hibernation cannot resurrect the request.
              await this.persistNow();
            } catch {
              this.router.releaseInternalNonce(opCtx.claims.nonce);
              return json({ error: "storage_unavailable" }, { status: 503 });
            }
            return json({
              status: "rejected",
              detail: {
                code: "OWNMESH_E_OPERATION_DISPATCH_FENCED",
                operation_id: operationId,
                operation_status: operation.status,
              },
            });
          }
          const workspaceCheck = await this.workspaceAuthorityCurrent(store, body.payload || {}, operation);
          if (workspaceCheck === "storage_unavailable") throw new Error("storage_unavailable");
          if (workspaceCheck !== "ok") {
            await store.updateMcpOperation(
              operationId,
              {
                status: "failed",
                summary: "workspace authority changed before device delivery",
                data: {
                  error: {
                    code: "OWNMESH_E_WORKSPACE_AUTHORITY_CHANGED",
                    message: "workspace mapping changed before device delivery",
                    retryable: false,
                  },
                },
                approval_required: false,
              },
              ["pending", "running", "approval_required"],
            );
            if (!this.router.consumeInternalNonce(opCtx.claims.nonce, opCtx.claims.exp)) {
              return json({ error: "replay" }, { status: 401 });
            }
            this.router.pending.delete(correlationId);
            await this.persistNow();
            return json({
              status: "rejected",
              detail: {
                code: "OWNMESH_E_WORKSPACE_AUTHORITY_CHANGED",
                operation_id: operationId,
              },
            });
          }
        }
      } catch {
        this.storageBroken = true;
        this.failClosedAll("storage unavailable", 1013);
        return json({ error: "storage_unavailable" }, { status: 503 });
      }

      const existingPending = this.router.pending.get(correlationId);
      if (existingPending) {
        // Stable correlation_id is the external idempotency key (notably for
        // approval outbox lease recovery). Never dispatch the same decision
        // twice after a Worker crash between DO delivery and D1 finalization.
        if (
          existingPending.type !== body.type ||
          JSON.stringify(existingPending.payload) !== JSON.stringify(body.payload || {})
        ) {
          return json({ error: "correlation_conflict" }, { status: 409 });
        }
        if (!this.router.consumeInternalNonce(opCtx.claims.nonce, opCtx.claims.exp)) {
          return json({ error: "replay" }, { status: 401 });
        }
        try {
          await this.persistNow();
        } catch {
          this.router.releaseInternalNonce(opCtx.claims.nonce);
          return json({ error: "storage_unavailable" }, { status: 503 });
        }
        return json({
          status: "routed_to_device",
          detail: { correlation_id: correlationId, deduplicated: true },
        });
      }
      const prep = this.router.prepareInjectOperation({
        type: body.type,
        payload: body.payload || {},
        correlation_id: correlationId,
        expires_at:
          typeof body.expires_at === "string" && body.expires_at.trim() !== ""
            ? String(body.expires_at)
            : undefined,
      });
      if (!prep.ok) {
        return json(prep.result, {
          status:
            prep.result.status === "device_offline"
              ? 503
              : prep.result.status === "rejected"
                ? 429
                : 200,
        });
      }

      // Room-level nonce consume atomically with prepared pending (same persist).
      if (!this.router.consumeInternalNonce(opCtx.claims.nonce, opCtx.claims.exp)) {
        this.router.rollbackPreparedInject(prep.prepared);
        return json({ error: "replay" }, { status: 401 });
      }

      try {
        // Barrier: pending + seqOut + consumed nonce must hit DO storage first.
        await this.persistNow();
      } catch {
        // persistNow fail-closes sockets/pending; drop in-memory nonce staging too.
        this.router.releaseInternalNonce(opCtx.claims.nonce);
        this.router.rollbackPreparedInject(prep.prepared);
        return json({ error: "storage_unavailable" }, { status: 503 });
      }

      // 4) Dispatch only after durable persist — no operation half-success.
      const result = this.router.dispatchPreparedInject(prep.prepared);
      if (result.status === "device_offline") {
        // Send path found no live recipient after persist — clear durable pending.
        try {
          await this.persistNow();
        } catch {
          return json({ error: "storage_unavailable" }, { status: 503 });
        }
        return json(result, { status: 503 });
      }
      return json(result, {
        status: result.status === "rejected" ? 429 : 200,
      });
    }

    if (url.pathname.endsWith("/live-operation") && request.method === "POST") {
      const broken = this.refuseIfStorageBroken();
      if (broken) return broken;
      const rawBody = await readTextLimited(request, MAX_PAYLOAD_BYTES);
      if (rawBody === null) return json({ error: "payload_too_large", max_bytes: MAX_PAYLOAD_BYTES }, { status: 413 });
      const bodySha256 = await sha256Hex(rawBody);
      const opCtx = await verifyInternalContext(this.env.SESSION_SECRET, request.headers.get(internalContextHeaderName()), {
        op: "live_operation", device_id: this.deviceId, method: "POST", path: "/live-operation", body_sha256: bodySha256, replayGuard: null,
      });
      if (!opCtx.ok) return json({ error: opCtx.error }, { status: opCtx.status });
      const security = await this.revalidateCredentials();
      if (!security.ok) return json({ error: security.error }, { status: security.status });
      try {
        const store = createStore(this.env);
        const device = await store.getDevice(this.deviceId);
        if (!device || device.tenant_id !== opCtx.claims.tenant_id
          || !(await store.canOperateDevice(this.deviceId, opCtx.claims.principal_id, opCtx.claims.tenant_id))) {
          return json({ error: "binding_mismatch" }, { status: 403 });
        }
      } catch {
        this.storageBroken = true;
        this.failClosedAll("storage unavailable", 1013);
        return json({ error: "storage_unavailable" }, { status: 503 });
      }
      let body: { type?: unknown; payload?: unknown; correlation_id?: unknown; expires_at?: unknown };
      try { body = JSON.parse(rawBody) as typeof body; } catch { return json({ error: "bad_json" }, { status: 400 }); }
      const payload = body.payload && typeof body.payload === "object" && !Array.isArray(body.payload)
        ? body.payload as Record<string, unknown> : null;
      const correlationId = typeof body.correlation_id === "string" ? body.correlation_id : "";
      // This is deliberately not a generic bypass of durable delivery: only a
      // ticket-bearing transfer.start may cross this socket-only boundary.
      if (body.type !== "operation.request" || !payload || payload.capability !== "transfer.start"
        || payload.operation_id !== correlationId || !correlationId
        || (opCtx.claims.correlation_id && opCtx.claims.correlation_id !== correlationId)) {
        return json({ error: "binding_mismatch" }, { status: 403 });
      }
      const generationCheck = await this.credentialGenerationCurrent(payload, {
        principal_id: opCtx.claims.principal_id,
        tenant_id: opCtx.claims.tenant_id,
      });
      if (generationCheck !== "ok") {
        if (generationCheck === "storage_unavailable") {
          this.storageBroken = true;
          this.failClosedAll("storage unavailable", 1013);
          return json({ error: "storage_unavailable" }, { status: 503 });
        }
        return json({ error: generationCheck }, { status: 403 });
      }
      if (this.router.hasInternalNonce(opCtx.claims.nonce) || this.router.pending.has(correlationId)) {
        return json({ status: "dispatch_uncertain", detail: { reason: "dispatch_uncertain", error: "live_operation_already_observed" } }, { status: 409 });
      }
      const recipients = [...this.router.sessions.entries()].filter(([, session]) => this.router.isRemoteRoutingAgent(session));
      if (recipients.length !== 1) {
        return json({ status: "device_offline", detail: { reason: recipients.length === 0 ? "no_ready_agent" : "multiple_ready_agents" } }, { status: 503 });
      }
      const expiresAt = typeof body.expires_at === "string" && body.expires_at.trim() !== "" ? body.expires_at : undefined;
      const now = Date.now();
      const expiresMs = expiresAt ? Date.parse(expiresAt) : NaN;
      if (!Number.isFinite(expiresMs) || expiresMs <= now || expiresMs > now + LIVE_TRANSFER_TOMBSTONE_MAX_TTL_MS) {
        return json({ error: "binding_mismatch" }, { status: 403 });
      }
      // Do not let repeated fresh generations accumulate correlation tombstones.
      // Persist any prune before admitting a new live operation, otherwise a
      // hibernation between requests could resurrect them and evade the cap.
      const pruned = this.router.pruneExpiredPending(now);
      if (pruned.length > 0) {
        try {
          await this.reconcileExpiredPending(pruned);
          await this.persistNow();
        } catch {
          return json({ error: "storage_unavailable" }, { status: 503 });
        }
      }
      if (this.router.pending.size >= MAX_PENDING_OPERATIONS) {
        return json({ status: "rejected", detail: { code: "OWNMESH_E_PENDING_LIMIT" } }, { status: 429 });
      }
      const [sessionId] = recipients[0]!;
      const envelope = this.router.nextEnvelope("operation.request", payload, correlationId, expiresAt ? { expiresAt } : undefined);
      // Persist a correlation-only tombstone before sending. It permits the
      // eventual Agent result to CAS into D1, but contains no bearer, JTI,
      // ephemeral proof, ciphertext, or raw transfer request and is skipped on
      // every reconnect/hibernation replay.
      this.router.pending.set(correlationId, {
        correlation_id: correlationId, type: "transfer.start", from_session: "", created_at: Date.now(),
        payload: { operation_id: correlationId, capability: "transfer.start" },
        // The result can legitimately arrive after the 60s connection ticket
        // expires; expiry is the already bound transfer operation deadline.
        expires_at: expiresAt, live_only: true,
      });
      if (!this.router.consumeInternalNonce(opCtx.claims.nonce, opCtx.claims.exp)) {
        this.router.pending.delete(correlationId);
        return json({ error: "replay" }, { status: 401 });
      }
      try { await this.persistNow(); } catch {
        this.router.pending.delete(correlationId);
        this.router.releaseInternalNonce(opCtx.claims.nonce);
        return json({ error: "storage_unavailable" }, { status: 503 });
      }
      if (!this.router.sendToSession(sessionId, JSON.stringify(envelope))) {
        // A false return is a definite local non-delivery, so remove the
        // tombstone before returning offline. Never retry the raw body; the
        // coordinator will fence and mint a fresh generation.
        this.router.pending.delete(correlationId);
        try { await this.persistNow(); } catch {
          return json({ error: "storage_unavailable" }, { status: 503 });
        }
        return json({ status: "device_offline", detail: { reason: "reconnecting" } }, { status: 503 });
      }
      return json({ status: "routed_to_device", detail: { correlation_id: correlationId, live_only: true } });
    }

    if (request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      const broken = this.refuseIfStorageBroken();
      if (broken) return broken;
      // Signed short-lived internal context only — constant edge header is never authority.
      const roleHint = (url.searchParams.get("role") || "agent") as SessionRole;
      const wsPath = url.pathname || "/ws";
      const wsCtx = await verifyInternalContext(
        this.env.SESSION_SECRET,
        request.headers.get(internalContextHeaderName()),
        {
          op: "ws",
          device_id: this.deviceId,
          role: roleHint,
          // Room DO storage is the replay authority; process-local guard is not.
          replayGuard: null,
          // Method/path enforced below when the signed claim carries them.
        },
      );
      if (!wsCtx.ok) return json({ error: wsCtx.error }, { status: wsCtx.status });
      // WS upgrade requires method+path claims (Worker always mints both).
      if (!wsCtx.claims.method || !wsCtx.claims.path) {
        return json({ error: "binding_mismatch" }, { status: 403 });
      }
      // When claims include method/path, enforce exact match (defense in depth).
      if (wsCtx.claims.method && wsCtx.claims.method.toUpperCase() !== request.method.toUpperCase()) {
        return json({ error: "binding_mismatch" }, { status: 403 });
      }
      if (wsCtx.claims.path && wsCtx.claims.path !== wsPath) {
        return json({ error: "binding_mismatch" }, { status: 403 });
      }
      const origin = request.headers.get("origin") || "";
      const allowedOrigins = new Set([
        request.headers.get("x-ownmesh-allowed-origin") || "",
        this.env.OAUTH_ISSUER ? new URL(this.env.OAUTH_ISSUER).origin : "",
        ...(this.env.OWNMESH_ALLOWED_ORIGINS || "").split(",").map((v) => v.trim()).filter(Boolean),
      ]);
      if (!origin || !allowedOrigins.has(origin)) return json({ error: "origin_not_allowed" }, { status: 403 });
      if (!this.env.DB) {
        // Fail closed: refuse upgrade and tear down any lingering sockets.
        this.storageBroken = true;
        this.failClosedAll("storage unavailable", 1013);
        return json({ error: "storage_unavailable" }, { status: 503 });
      }
      const role = (url.searchParams.get("role") || "agent") as SessionRole;
      if (role !== "agent" && role !== "client") return json({ error: "invalid_role" }, { status: 403 });
      const token = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") || "";
      // All D1/store reads for upgrade must not leak throws past fetch().
      let devicePublicKey = "";
      let clientScope: string | undefined;
      try {
        const store = createStore(this.env);
        const device = await store.getDevice(this.deviceId);
        if (!device || device.revoked || device.status !== "active") {
          return json({ error: "device_not_active" }, { status: 403 });
        }
        if (device.tenant_id !== wsCtx.claims.tenant_id) {
          return json({ error: "binding_mismatch" }, { status: 403 });
        }
        if (role === "agent") {
          // Agent enrollment remains owner-bound: the device credential principal
          // must match the device owner and the signed internal-context claims.
          if (
            device.principal_id !== wsCtx.claims.principal_id ||
            device.tenant_id !== wsCtx.claims.tenant_id
          ) {
            return json({ error: "binding_mismatch" }, { status: 403 });
          }
          const credential = token ? await store.getDeviceCredential(token) : null;
          if (!credential || credential.device_id !== this.deviceId) {
            return json({ error: "invalid_device_credential" }, { status: 401 });
          }
        } else {
          const access = token ? await store.getAccess(token) : null;
          if (!access || access.tenant_id !== device.tenant_id) {
            return json({ error: "unauthorized" }, { status: 401 });
          }
          const allowed = await store.canOperateDevice(
            this.deviceId,
            access.principal,
            access.tenant_id,
          );
          if (!allowed || access.principal !== wsCtx.claims.principal_id) {
            return json({ error: "unauthorized" }, { status: 401 });
          }
          clientScope = access.scope;
        }
        devicePublicKey = device.public_key;
      } catch {
        this.storageBroken = true;
        this.failClosedAll("storage unavailable", 1013);
        return json({ error: "storage_unavailable" }, { status: 503 });
      }
      this.devicePublicKey = devicePublicKey;

      // Reject excess WS before nonce consume / accept — never evict live guards.
      if (!this.router.canAdmitNewGuardSession()) {
        return json(
          { error: "guard_session_limit", code: "OWNMESH_E_GUARD_SESSION_LIMIT" },
          { status: 503 },
        );
      }

      // Durable nonce before accepting the socket (same persist as session guard).
      if (!this.router.consumeInternalNonce(wsCtx.claims.nonce, wsCtx.claims.exp)) {
        return json({ error: "replay" }, { status: 401 });
      }

      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
      // Hibernation API — critical: acceptWebSocket not accept()
      // https://developers.cloudflare.com/durable-objects/best-practices/websockets/
      this.state.acceptWebSocket(server, [role, this.deviceId]);
      const sessionId = randomId(role === "agent" ? "ags_" : "cls_");
      const attachment: SessionAttachment = {
        role,
        device_id: this.deviceId,
        session_id: sessionId,
        connected_at: Date.now(),
        phase: "connected",
        auth_hash: await sha256Hex(token),
        scope: role === "client" ? clientScope : undefined,
        lastSeq: 0,
      };
      server.serializeAttachment(attachment);
      const admitted = this.router.registerSession(attachment);
      if (!admitted) {
        // Defensive: capacity raced or changed — roll back without touching live peers.
        this.router.releaseInternalNonce(wsCtx.claims.nonce);
        try {
          server.close(1013, "guard session limit");
        } catch {
          /* ignore */
        }
        return json(
          { error: "guard_session_limit", code: "OWNMESH_E_GUARD_SESSION_LIMIT" },
          { status: 503 },
        );
      }
      this.wsSessions.set(server, sessionId);
      try {
        // Persist nonce + ingress guard before returning 101 (no accept half-success).
        await this.persistNow();
      } catch {
        this.router.releaseInternalNonce(wsCtx.claims.nonce);
        try {
          server.close(1013, "storage unavailable");
        } catch {
          /* ignore */
        }
        this.wsSessions.delete(server);
        this.router.unregisterSession(sessionId);
        return json({ error: "storage_unavailable" }, { status: 503 });
      }
      return new Response(null, { status: 101, webSocket: client });
    }

    return json({ error: "expected websocket or /status or /operation" }, { status: 400 });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    await this.ready;
    if (this.storageBroken) {
      try {
        ws.close(1013, "storage unavailable");
      } catch {
        /* closed */
      }
      const sid = this.wsSessions.get(ws);
      if (sid) {
        this.router.unregisterSession(sid);
        this.wsSessions.delete(ws);
      }
      this.failClosedAll("storage unavailable", 1013);
      return;
    }
    const sessionId = this.wsSessions.get(ws) ||
      (ws.deserializeAttachment() as SessionAttachment | null)?.session_id;
    if (!sessionId) return;
    // Re-hydrate session map after hibernation.
    if (!this.router.sessions.has(sessionId)) {
      const att = ws.deserializeAttachment() as SessionAttachment | null;
      if (att) {
        const admitted = this.router.registerSession(att);
        if (!admitted) {
          try {
            ws.close(1013, "guard session limit");
          } catch {
            /* closed */
          }
          this.wsSessions.delete(ws);
          return;
        }
        this.wsSessions.set(ws, att.session_id);
        this.deviceId = att.device_id;
        this.router.deviceId = att.device_id;
      }
    }

    // Important ops + every frame: DB missing or revoked credential → fail closed.
    const security = await this.revalidateCredentials({ requireSessionId: sessionId });
    if (!security.ok) {
      // revalidateCredentials already closed sockets when appropriate.
      if (this.wsSessions.has(ws) || this.router.sessions.has(sessionId)) {
        try {
          ws.close(security.status === 503 ? 1013 : 1008, security.error);
        } catch {
          /* closed */
        }
        this.router.unregisterSession(sessionId);
        this.wsSessions.delete(ws);
      }
      return;
    }

    // Reject oversized frames before decoding/parsing JSON.
    let text: string;
    if (typeof message === "string") {
      text = message;
      if (new TextEncoder().encode(text).byteLength > MAX_PAYLOAD_BYTES) {
        try {
          ws.close(1009, "payload too large");
        } catch {
          /* closed */
        }
        this.router.unregisterSession(sessionId);
        this.wsSessions.delete(ws);
        return;
      }
    } else {
      // Hibernation API delivers binary frames as ArrayBuffer.
      const raw = message as ArrayBuffer;
      if (raw.byteLength > MAX_PAYLOAD_BYTES) {
        try {
          ws.close(1009, "payload too large");
        } catch {
          /* closed */
        }
        this.router.unregisterSession(sessionId);
        this.wsSessions.delete(ws);
        return;
      }
      text = new TextDecoder().decode(raw);
    }

    // Pre-parse type so we can force an extra credential check on critical ops
    // (revalidate already ran; this documents the acceptance gate explicitly).
    let critical = false;
    try {
      const preview = JSON.parse(text) as { type?: string };
      critical =
        preview?.type === "operation.request" ||
        preview?.type === "operation.result" ||
        preview?.type === "operation.event" ||
        preview?.type === "operation.progress" ||
        preview?.type === "proof" ||
        // #146: a registry refresh mutates durable device state.
        preview?.type === "workspace.registry" ||
        preview?.type === "ready";
    } catch {
      /* handleMessage will reject malformed JSON */
    }
    if (critical) {
      const again = await this.revalidateCredentials({ requireSessionId: sessionId });
      if (!again.ok) {
        try {
          ws.close(again.status === 503 ? 1013 : 1008, again.error);
        } catch {
          /* closed */
        }
        this.router.unregisterSession(sessionId);
        this.wsSessions.delete(ws);
        return;
      }
    }

    if (this.storageBroken) {
      try {
        ws.close(1013, "storage unavailable");
      } catch {
        /* closed */
      }
      this.router.unregisterSession(sessionId);
      this.wsSessions.delete(ws);
      return;
    }

    // Reconcile expiry before the router's ingress guards can prune it. This
    // keeps active-message, alarm, and hibernation-restart paths equivalent.
    const expiredBeforeMessage = this.router.pruneExpiredPending();
    if (expiredBeforeMessage.length > 0) {
      try {
        await this.reconcileExpiredPending(expiredBeforeMessage);
        await this.persistNow();
      } catch {
        this.storageBroken = true;
        this.failClosedAll("storage unavailable", 1013);
        return;
      }
    }

    const result = await this.router.handleMessage(sessionId, text);
    const updatedAttachment = this.router.sessions.get(sessionId);
    if (updatedAttachment) {
      const guard = this.router.ingressGuards.get(sessionId);
      if (guard) updatedAttachment.lastSeq = guard.lastSeq;
      ws.serializeAttachment(updatedAttachment);
    }

    if (result.ok && result.authenticated_agent) {
      try {
        await this.recordAuthenticatedAgentConnection(result.authenticated_agent);
      } catch {
        // A concurrent revoke or D1 failure means this connection no longer
        // has an authoritative identity. Do not leave a ready socket live.
        this.storageBroken = true;
        this.failClosedAll("storage unavailable", 1013);
        return;
      }
    }

    // #146: persist the incremental registry refresh. Fail-closed on storage
    // errors so the agent cannot assume a generation the store never saw.
    if (result.ok && result.workspace_registry_sync) {
      if (!this.env.DB) {
        this.storageBroken = true;
        this.failClosedAll("storage unavailable", 1013);
        return;
      }
      try {
        const store = createStore(this.env);
        await store.syncDeviceWorkspaces(
          this.deviceId,
          result.workspace_registry_sync.workspaces,
        );
      } catch {
        this.storageBroken = true;
        this.failClosedAll("storage unavailable", 1013);
        return;
      }
    }

    // Pending TTL/expiry must reach D1 before Agent outbox reconciliation, so
    // an expired correlation is an authoritative terminal tombstone on this
    // same reconnect rather than requiring a second connection.
    if (result.ok && result.expired_pending && result.expired_pending.length > 0) {
      try {
        await this.reconcileExpiredPending(result.expired_pending);
      } catch {
        this.storageBroken = true;
        this.failClosedAll("storage unavailable", 1013);
        return;
      }
    }

    if (result.ok && result.agent_ready_session_id) {
      try {
        await this.redeliverCurrentPending(
          result.agent_ready_session_id,
          result.agent_pending_correlations || [],
        );
      } catch {
        this.storageBroken = true;
        this.failClosedAll("storage unavailable", 1013);
        return;
      }
    }

    // operation.result: bind + CAS-persist BEFORE forward/pending removal.
    if (result.ok && result.mcp_result) {
      const corr = result.mcp_result.correlation_id;
      if (!this.env.DB) {
        this.storageBroken = true;
        this.failClosedAll("storage unavailable", 1013);
        return;
      }
      try {
        const store = createStore(this.env);
        const pending = corr ? this.router.pending.get(corr) : undefined;
        const expectedApprovalDecision = approvalDecisionBindingFromPayload(pending?.payload);
        const applied = await applyMcpOperationResult(store, {
          operationId: result.mcp_result.operation_id,
          correlationId: corr,
          payload: result.mcp_result.payload,
          deviceId: this.deviceId,
          expectedApprovalDecision,
          issuer: this.env.OAUTH_ISSUER,
        });
        if (!applied.ok) {
          // Unknown/mismatched/CAS loss — do not forward or drop pending.
          try {
            const err = this.router.nextEnvelope(
              "error",
              {
                code: "OWNMESH_E_RESULT_REJECTED",
                message: applied.error,
              },
              corr,
            );
            ws.send(JSON.stringify(err));
          } catch {
            /* socket may be gone */
          }
          try {
            await this.persistNow();
          } catch {
            return;
          }
          return;
        }
        // Durable CAS succeeded (or room-only) — now forward and clear pending.
        if (corr && result.deferred_forward) {
          this.router.finalizeOperationResult(corr, result.deferred_forward);
        }
      } catch (err) {
        // Store write failure: fail closed, no success forward.
        this.storageBroken = true;
        const detail = err instanceof Error ? err.message : String(err);
        this.failClosedAll(`storage unavailable: ${detail}`.slice(0, 120), 1013);
        return;
      }
    }

    // Room-state barrier before any deferred operation.request agent/client send.
    try {
      await this.persistNow();
    } catch {
      // Persist failure: zero agent sends, roll back staged pending, fail closed.
      if (result.deferred_dispatch) {
        this.router.rollbackDeferredDispatch(result.deferred_dispatch);
      }
      // persistNow already invoked failClosedAll (1013).
      return;
    }

    // operation.request: dispatch only after durable pending/seq persist succeeded.
    if (result.ok && result.deferred_dispatch) {
      this.router.finalizeDeferredDispatch(result.deferred_dispatch);
      // Offline fallback may have cleared pending — keep durable snapshot aligned.
      if (result.deferred_dispatch.pending_key && !this.router.pending.has(result.deferred_dispatch.pending_key)) {
        try {
          await this.persistNow();
        } catch {
          return;
        }
      }
    }

    // Close decision stays in the DO; router remains pure/testable.
    if (result.close) {
      try {
        ws.close(result.closeCode || 1008, result.closeReason || "protocol error");
      } catch {
        /* already closed */
      }
      this.router.unregisterSession(sessionId);
      this.wsSessions.delete(ws);
      try {
        await this.persistNow();
      } catch {
        return;
      }
    }
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    await this.ready;
    try {
      const sessionId = this.wsSessions.get(ws);
      if (sessionId) {
        this.router.unregisterSession(sessionId);
        this.wsSessions.delete(ws);
        try {
          await this.persistNow();
        } catch {
          // persistNow already fail-closed sockets/pending.
        }
      }
      try {
        ws.close(code, reason);
      } catch {
        /* already closed */
      }
    } catch {
      // Never leak storage/D1 errors from hibernation close handler.
      try {
        this.storageBroken = true;
        this.failClosedAll("storage unavailable", 1013);
      } catch {
        /* ignore secondary failures */
      }
    }
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    await this.ready;
    try {
      const sessionId = this.wsSessions.get(ws);
      if (sessionId) {
        this.router.unregisterSession(sessionId);
        this.wsSessions.delete(ws);
        try {
          await this.persistNow();
        } catch {
          // persistNow already fail-closed sockets/pending.
        }
      }
    } catch {
      // Never leak storage/D1 errors from hibernation error handler.
      try {
        this.storageBroken = true;
        this.failClosedAll("storage unavailable", 1013);
      } catch {
        /* ignore secondary failures */
      }
    }
  }

  /** Wake from idle at the nearest persisted pending deadline. */
  async alarm(): Promise<void> {
    await this.ready;
    if (this.storageBroken) return;
    const expired = this.router.pruneExpiredPending();
    try {
      await this.reconcileExpiredPending(expired);
      await this.persistNow();
    } catch {
      this.storageBroken = true;
      this.failClosedAll("storage unavailable", 1013);
    }
  }
}

/** Bound checks for hibernation snapshots (serialized bytes, guards, pending payloads). */
export function assertRoomStateBounds(state: PersistedRoomState): void {
  const enc = new TextEncoder();
  const serialized = enc.encode(JSON.stringify(state)).byteLength;
  if (serialized > MAX_SERIALIZED_STATE_BYTES) {
    throw new Error("room_state_too_large");
  }
  const guardCount = Object.keys(state.ingressGuards || {}).length;
  if (guardCount > MAX_GUARD_SESSIONS) {
    throw new Error("guard_session_limit");
  }
  let pendingBytes = 0;
  for (const p of state.pending || []) {
    pendingBytes += enc.encode(JSON.stringify(p?.payload || {})).byteLength;
  }
  if (pendingBytes > MAX_PENDING_PAYLOAD_BYTES) {
    throw new Error("pending_payload_limit");
  }
  if ((state.pending || []).length > MAX_PENDING_OPERATIONS) {
    throw new Error("pending_count_limit");
  }
  const nonceCount = Object.keys(state.consumedNonces || {}).length;
  if (nonceCount > INTERNAL_CONTEXT_REPLAY_MAX) {
    throw new Error("nonce_replay_limit");
  }
}

export type ApplyMcpOperationResultOutcome =
  | { ok: true; record: McpOperationRecord; room_only?: false }
  | { ok: true; record: null; room_only: true }
  | { ok: false; error: string };

/**
 * The two Agent preflight operations are internal coordinator messages, never
 * public MCP tools.  The expectation is written by the control plane when it
 * creates each exact-bound operation.  Keeping it under this private key also
 * makes a generic operation.result incapable of turning into a transfer proof.
 */
type TransferPreflightExpectation = Pick<
  TransferServerBinding,
  "transfer_id" | "tenant_id" | "plan_sha256" | "epoch" | "fence"
> & {
  role: "source" | "destination";
  device_id: string;
  workspace_id: string;
  session_nonce: string;
  coordinator_request_id: string;
  workspace_version: number;
  /** Rust preflight proof wire field; milliseconds. */
  expires_at: number;
};

function transferPreflightExpectation(op: McpOperationRecord): TransferPreflightExpectation | null {
  const value = op.data.__transfer_preflight_expectation;
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const raw = value as Record<string, unknown>;
  const allowed = [
    "role", "transfer_id", "tenant_id", "plan_sha256", "epoch", "fence", "expires_at",
    "device_id", "workspace_id", "session_nonce", "coordinator_request_id", "workspace_version",
  ];
  if (Object.keys(raw).some((key) => !allowed.includes(key))) return null;
  const text = (key: string) => typeof raw[key] === "string" && raw[key].length > 0 ? raw[key] as string : null;
  const integer = (key: string) => typeof raw[key] === "number" && Number.isSafeInteger(raw[key]) ? raw[key] as number : null;
  const role = text("role");
  const expected: TransferPreflightExpectation = {
    role: role === "source" || role === "destination" ? role : "source",
    transfer_id: text("transfer_id") || "", tenant_id: text("tenant_id") || "",
    plan_sha256: text("plan_sha256") || "", epoch: integer("epoch") ?? 0,
    fence: integer("fence") ?? 0, expires_at: integer("expires_at") ?? 0,
    device_id: text("device_id") || "", workspace_id: text("workspace_id") || "",
    session_nonce: text("session_nonce") || "", coordinator_request_id: text("coordinator_request_id") || "",
    workspace_version: integer("workspace_version") ?? 0,
  };
  if (!role || expected.device_id !== op.device_id || expected.tenant_id !== op.tenant_id
    || expected.workspace_id !== op.workspace_id || expected.workspace_version < 1
    || expected.epoch < 1 || expected.fence < 1 || expected.expires_at <= Date.now()
    // The source Agent is the authority that hashes the pinned source file.
    // Its preflight starts with no server-known plan hash; every other path
    // requires the already CAS-bound hash.
    || !((expected.role === "source" && expected.plan_sha256 === "") || /^[a-f0-9]{64}$/.test(expected.plan_sha256))) return null;
  return expected;
}

function sanitizeTransferPreflightResult(
  op: McpOperationRecord,
  payload: Record<string, unknown>,
): { data: Record<string, unknown> } | { error: string } {
  const expected = transferPreflightExpectation(op);
  if (!expected) return { error: "transfer_preflight_expectation_invalid" };
  const result = payload.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    return { error: "transfer_preflight_result_invalid" };
  }
  const raw = result as Record<string, unknown>;
  const allowed = ["transfer_preflight", "operation_id", "coordinator_request_id", "principal_id", "workspace_version", "source_plan"];
  if (Object.keys(raw).some((key) => !allowed.includes(key))) return { error: "transfer_preflight_result_unknown_field" };
  if (raw.operation_id !== op.operation_id || raw.coordinator_request_id !== expected.coordinator_request_id
    || raw.principal_id !== op.principal_id || raw.workspace_version !== expected.workspace_version) {
    return { error: "transfer_preflight_correlation_mismatch" };
  }
  const reply = parseTransferPreflightResult(raw.transfer_preflight, expected);
  if (!reply) return { error: "transfer_preflight_proof_mismatch" };
  let sourcePlan: Record<string, unknown> | undefined;
  if (expected.role === "source") {
    const plan = raw.source_plan;
    if (!plan || typeof plan !== "object" || Array.isArray(plan)) return { error: "transfer_preflight_source_plan_missing" };
    const p = plan as Record<string, unknown>;
    if (Object.keys(p).some((key) => !["plan_id", "sha256", "size_bytes"].includes(key))
      || typeof p.plan_id !== "string" || p.plan_id.length === 0 || p.plan_id.length > 256
      || typeof p.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(p.sha256)
      || typeof p.size_bytes !== "number" || !Number.isSafeInteger(p.size_bytes) || p.size_bytes < 0) {
      return { error: "transfer_preflight_source_plan_invalid" };
    }

    sourcePlan = { plan_id: p.plan_id, sha256: p.sha256, size_bytes: p.size_bytes };
  } else if (raw.source_plan !== undefined) {
    return { error: "transfer_preflight_destination_source_plan_forbidden" };
  }
  // Store only the bounded proof metadata.  This deliberately excludes the
  // raw operation payload and gives the ticket coordinator no byte channel.
  return {
    data: {
      transfer_preflight: reply,
      operation_id: op.operation_id,
      coordinator_request_id: expected.coordinator_request_id,
      principal_id: op.principal_id,
      workspace_version: expected.workspace_version,
      ...(sourcePlan ? { source_plan: sourcePlan } : {}),
    },
  };
}

/** Accept only the exact bounded destination artifact page contract.  This is
 * a distinct capability from fs.read: the Agent chooses the immutable plan
 * path, and the control plane retains at most one 64 KiB user-requested page. */
async function sanitizeTransferArtifactResult(
  op: McpOperationRecord,
  payload: Record<string, unknown>,
): Promise<{ data: Record<string, unknown> } | { error: string }> {
  const result = payload.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) return { error: "transfer_artifact_result_invalid" };
  const raw = result as Record<string, unknown>;
  const allowed = ["plan_id", "offset", "bytes", "total_bytes", "next_offset", "truncated", "encoding", "content_base64", "page_sha256", "sha256"];
  if (Object.keys(raw).some((key) => !allowed.includes(key))) return { error: "transfer_artifact_result_unknown_field" };
  const actionFacts = op.action?.facts;
  const expectedPlan = actionFacts && typeof actionFacts === "object" && !Array.isArray(actionFacts)
    ? (actionFacts as Record<string, unknown>).plan_id
    : undefined;
  const expectedOffset = op.data.offset;
  const expectedMax = op.data.max_bytes;
  const expectedSha256 = op.data.expected_sha256;
  const expectedTotalBytes = op.data.expected_total_bytes;
  if (typeof expectedPlan !== "string" || typeof expectedOffset !== "number" || typeof expectedMax !== "number"
    || typeof expectedSha256 !== "string" || !/^[a-f0-9]{64}$/.test(expectedSha256)
    || typeof expectedTotalBytes !== "number" || !Number.isSafeInteger(expectedTotalBytes) || expectedTotalBytes < 0
    || raw.plan_id !== expectedPlan || raw.offset !== expectedOffset || raw.encoding !== "base64"
    || typeof raw.content_base64 !== "string" || typeof raw.page_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(raw.page_sha256)
    || raw.sha256 !== expectedSha256
    || typeof raw.bytes !== "number" || !Number.isSafeInteger(raw.bytes) || raw.bytes < 0 || raw.bytes > 65536 || raw.bytes > expectedMax
    || raw.total_bytes !== expectedTotalBytes || raw.total_bytes < raw.bytes
    || typeof raw.truncated !== "boolean") return { error: "transfer_artifact_result_binding_mismatch" };
  let page: Uint8Array;
  try {
    // A 64 KiB decoded page has at most 87,384 canonical base64 characters.
    if (raw.content_base64.length > 87384) return { error: "transfer_artifact_page_overflow" };
    const binary = atob(raw.content_base64);
    page = Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
    if (btoa(binary) !== raw.content_base64) return { error: "transfer_artifact_base64_noncanonical" };
  } catch { return { error: "transfer_artifact_base64_invalid" }; }
  if (page.byteLength !== raw.bytes || await sha256Hex(page) !== raw.page_sha256) return { error: "transfer_artifact_page_hash_mismatch" };
  const next = raw.next_offset;
  if (raw.truncated) {
    // A nonterminal empty page would create a non-progressing public cursor.
    if (raw.bytes < 1 || typeof next !== "number" || !Number.isSafeInteger(next) || next !== expectedOffset + raw.bytes || next >= raw.total_bytes) return { error: "transfer_artifact_cursor_invalid" };
  } else if (next !== null || expectedOffset + raw.bytes !== raw.total_bytes) return { error: "transfer_artifact_terminal_cursor_invalid" };
  return { data: { plan_id: raw.plan_id, offset: raw.offset, bytes: raw.bytes, total_bytes: raw.total_bytes, next_offset: raw.next_offset, truncated: raw.truncated, encoding: raw.encoding, content_base64: raw.content_base64, page_sha256: raw.page_sha256, sha256: raw.sha256 } };
}

/** transfer.start is another bearer boundary.  Persist only a small exact
 * admission/completion receipt; never allow the generic result column to turn
 * into a ticket, key, ciphertext, or chunk storage channel. */
function sanitizeTransferStartResult(
  op: McpOperationRecord,
  payload: Record<string, unknown>,
): { data: Record<string, unknown> } | { error: string } {
  const result = payload.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) return { error: "transfer_start_result_invalid" };
  const raw = result as Record<string, unknown>;
  const allowed = ["transfer_id", "plan_id", "role", "plan_sha256", "epoch", "fence", "admitted", "completed", "published", "artifact_sha256"];
  if (Object.keys(raw).some((key) => !allowed.includes(key))) return { error: "transfer_start_result_unknown_field" };
  const facts = op.action?.facts;
  const fact = facts && typeof facts === "object" && !Array.isArray(facts) ? facts as Record<string, unknown> : {};
  const role = op.tool === "__transfer_start_source" ? "source" : op.tool === "__transfer_start_destination" ? "destination" : "";
  if (!role || raw.role !== role || typeof raw.transfer_id !== "string" || raw.transfer_id !== fact.transfer_id
    || typeof raw.plan_id !== "string" || raw.plan_id.length === 0 || raw.plan_id.length > 256
    || typeof raw.plan_sha256 !== "string" || raw.plan_sha256 !== fact.plan_sha256 || !/^[a-f0-9]{64}$/.test(raw.plan_sha256)
    || raw.epoch !== fact.epoch || raw.fence !== fact.fence || typeof raw.admitted !== "boolean"
    || (raw.completed !== undefined && typeof raw.completed !== "boolean")
    || (raw.published !== undefined && (typeof raw.published !== "boolean" || role !== "destination"))
    || (raw.artifact_sha256 !== undefined && (typeof raw.artifact_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(raw.artifact_sha256)))
    || (raw.published === true && (raw.completed !== true || raw.artifact_sha256 !== fact.content_sha256))) return { error: "transfer_start_result_binding_mismatch" };
  return { data: { transfer_id: raw.transfer_id, plan_id: raw.plan_id, role: raw.role, plan_sha256: raw.plan_sha256, epoch: raw.epoch, fence: raw.fence, admitted: raw.admitted, ...(raw.completed !== undefined ? { completed: raw.completed } : {}), ...(raw.published !== undefined ? { published: raw.published } : {}), ...(raw.artifact_sha256 !== undefined ? { artifact_sha256: raw.artifact_sha256 } : {}) } };
}

/** A generic cancel acknowledgement is not by itself proof that an in-flight
 * transfer was stopped.  Keep only the target-bound booleans needed by the
 * transfer coordinator and drop any unbounded diagnostic payload. */
function sanitizeTransferCancelControlResult(
  op: McpOperationRecord,
  payload: Record<string, unknown>,
): { data: Record<string, unknown> } | { error: string } {
  const result = payload.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) return { error: "transfer_cancel_result_invalid" };
  const raw = result as Record<string, unknown>;
  const expectedTarget = op.data.target_operation_id;
  if (typeof expectedTarget !== "string" || expectedTarget.length === 0
    || raw.target_operation_id !== expectedTarget
    || typeof raw.cancelled !== "boolean"
    || typeof raw.signal_delivered !== "boolean") return { error: "transfer_cancel_result_binding_mismatch" };
  return { data: { target_operation_id: expectedTarget, cancelled: raw.cancelled, signal_delivered: raw.signal_delivered } };
}

function sanitizeTransferSourceCleanupResult(
  op: McpOperationRecord,
  payload: Record<string, unknown>,
): { data: Record<string, unknown> } | { error: string } {
  const result = payload.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) return { error: "transfer_source_cleanup_result_invalid" };
  const raw = result as Record<string, unknown>;
  const expectedPlan = op.data.plan_id;
  const allowed = ["plan_id", "cancelled", "source_only", "replayed", "state"];
  if (Object.keys(raw).some((key) => !allowed.includes(key))
    || typeof expectedPlan !== "string" || raw.plan_id !== expectedPlan
    || raw.cancelled !== true || raw.source_only !== true
    || (raw.replayed !== undefined && typeof raw.replayed !== "boolean")
    || (raw.state !== undefined && typeof raw.state !== "string")) {
    return { error: "transfer_source_cleanup_result_binding_mismatch" };
  }
  return { data: { plan_id: expectedPlan, cleaned: true, source_only: true } };
}

/** Internal transfer coordination is not a diagnostic channel.  The device can
 * report an ordinary completion only through the tool-specific validators
 * above; every other outcome uses these fixed summaries and bounded data. */
function isInternalTransferTool(tool: string): boolean {
  return tool === "__transfer_start_source"
    || tool === "__transfer_start_destination"
    || tool === "__transfer_preflight_source"
    || tool === "__transfer_preflight_source_final"
    || tool === "__transfer_preflight_destination"
    || tool === "__transfer_artifact_get"
    || tool === "__transfer_cancel_control"
    || tool === "__transfer_source_cleanup";
}

function internalTransferFailureSummary(tool: string, status: string): string {
  const needsApproval = status === "approval_required";
  if (tool === "__transfer_preflight_source" || tool === "__transfer_preflight_source_final" || tool === "__transfer_preflight_destination") {
    return needsApproval ? "transfer preflight requires approval" : "transfer preflight failed";
  }
  if (tool === "__transfer_artifact_get") {
    return needsApproval ? "transfer artifact request requires approval" : "transfer artifact request failed";
  }
  if (tool === "__transfer_cancel_control") {
    return needsApproval ? "transfer cancellation control requires approval" : "transfer cancellation control failed";
  }
  if (tool === "__transfer_source_cleanup") {
    return needsApproval ? "transfer source cleanup requires approval" : "transfer source cleanup failed";
  }
  return needsApproval ? "transfer start requires approval" : "transfer start failed";
}

function approvalUrlFromIssuer(issuer: string | undefined, operationId: string): string | undefined {
  const base = (issuer || "").replace(/\/$/, "");
  if (!base || !/^https?:\/\//i.test(base)) return undefined;
  return `${base}/approve?operation_id=${encodeURIComponent(operationId)}`;
}

async function applyWorkspaceActivationSideEffects(
  store: ControlPlaneStore,
  op: McpOperationRecord,
  data: Record<string, unknown>,
  status: string,
): Promise<Record<string, unknown>> {
  if (!op.device_id) return data;
  const deviceId = op.device_id;
  const reservedId = parseWorkspaceId(op.workspace_id);
  const resultId = parseWorkspaceId(data.id);
  const resultMatchesReservation = !reservedId || !resultId || resultId === reservedId;
  const workspaceId = reservedId || resultId;

  if (status === "completed") {
    if (
      resultMatchesReservation &&
      (op.tool === "ownmesh_workspace_add" ||
        op.tool === "ownmesh_workspace_update" ||
        op.tool === "ownmesh_workspace_show")
    ) {
      const generation = parseWorkspaceGeneration(data.generation);
      if (workspaceId && generation) {
        await store.observeWorkspaceGeneration(deviceId, workspaceId, generation);
      }
    }
    if (op.tool === "ownmesh_workspace_list" && Array.isArray(data.workspaces)) {
      for (const entry of data.workspaces) {
        if (!entry || typeof entry !== "object") continue;
        const row = entry as Record<string, unknown>;
        const id = parseWorkspaceId(row.id);
        const generation = parseWorkspaceGeneration(row.generation);
        if (id && generation) {
          await store.observeWorkspaceGeneration(deviceId, id, generation);
        }
      }
    }
    if (op.tool === "ownmesh_workspace_remove" && workspaceId) {
      await store.deactivateWorkspace(deviceId, workspaceId);
    }
    const enforcement =
      typeof data.workspace_root_enforcement === "boolean"
        ? data.workspace_root_enforcement
        : typeof data.enforce_workspace === "boolean"
          ? data.enforce_workspace
          : undefined;
    if (
      enforcement !== undefined &&
      (op.tool === "ownmesh_workspace_list" ||
        op.tool === "ownmesh_policy_show" ||
        op.tool === "ownmesh_policy_preset")
    ) {
      await store.recordObservedWorkspaceEnforcement(deviceId, enforcement);
    }
  }

  if (
    status === "failed" &&
    op.tool === "ownmesh_workspace_remove" &&
    workspaceId
  ) {
    const existing = await store.getWorkspace(deviceId, workspaceId);
    if (existing && !existing.local_generation) {
      await store.deactivateWorkspace(deviceId, workspaceId);
    }
  }

  const device = await store.getDevice(deviceId);
  if (op.tool === "ownmesh_workspace_list") {
    const records = new Map<string, WorkspaceRecord>();
    if (Array.isArray(data.workspaces)) {
      for (const entry of data.workspaces) {
        if (!entry || typeof entry !== "object") continue;
        const id = (entry as { id?: string }).id;
        if (typeof id === "string") {
          const record = await store.getWorkspace(deviceId, id);
          if (record) records.set(id, record);
        }
      }
    }
    return annotateWorkspaceList(data, records, device?.enforce_workspace);
  }
  if (
    op.tool === "ownmesh_workspace_add" ||
    op.tool === "ownmesh_workspace_update" ||
    op.tool === "ownmesh_workspace_show" ||
    op.tool === "ownmesh_workspace_remove"
  ) {
    const record = workspaceId ? await store.getWorkspace(deviceId, workspaceId) : null;
    return annotateWorkspaceRecord(data, record);
  }
  if (op.tool === "ownmesh_policy_show" || op.tool === "ownmesh_policy_preset") {
    return annotatePolicyObservation(data, device?.enforce_workspace);
  }
  return data;
}

/**
 * Map a device-originated operation.result onto authoritative mcp_operations state.
 * Single runtime helper (DeviceRoom DO); mcp.ts must not duplicate this.
 *
 * Binds operation_id + correlation_id + device_id to the store row and applies a
 * CAS status transition. Unknown/mismatched results are rejected. Store errors throw
 * (caller fail-closes). Room-only pending (no store row, no operation_id) is allowed.
 */
export async function applyMcpOperationResult(
  store: ControlPlaneStore,
  opts: {
    operationId?: string;
    correlationId?: string;
    payload: Record<string, unknown>;
    deviceId?: string;
    expectedApprovalDecision?: ApprovalDecisionBinding | null;
    issuer?: string;
  },
): Promise<ApplyMcpOperationResultOutcome> {
  const payloadOpId = opts.payload.operation_id != null ? String(opts.payload.operation_id) : undefined;
  const wantOpId = opts.operationId || payloadOpId;

  let op: McpOperationRecord | null = null;
  if (wantOpId) {
    op = await store.getMcpOperation(wantOpId);
  }
  if (!op && opts.correlationId) {
    op = await store.getMcpOperationByCorrelation(opts.correlationId);
  }
  if (!op && payloadOpId && payloadOpId !== wantOpId) {
    op = await store.getMcpOperation(payloadOpId);
  }

  // No store row: allow room-only routing when no operation_id was claimed, or when
  // the device completed a control cancel / approval.decision request that was never
  // claimed into D1. Approval decisions apply their execution result onto the
  // *target* MCP operation (the original ask), not the decision notification id.
  if (!op) {
    if (wantOpId) {
      const incoming = opts.payload;
      const resultObj =
        incoming.result && typeof incoming.result === "object"
          ? (incoming.result as Record<string, unknown>)
          : undefined;
      const looksLikeCancelControl =
        resultObj != null &&
        (Object.prototype.hasOwnProperty.call(resultObj, "cancelled") ||
          Object.prototype.hasOwnProperty.call(resultObj, "signal_delivered") ||
          Object.prototype.hasOwnProperty.call(resultObj, "target_operation_id"));
      const incomingStatus = String(incoming.status || "completed");
      if (
        looksLikeCancelControl &&
        (incomingStatus === "completed" || incomingStatus === "failed" || incomingStatus === "denied")
      ) {
        // Approval decision: fold only an exact-bound Agent result onto the
        // original MCP operation. A device-side rejection/failure is terminal
        // too; leaving the target pending would make a delivered decision hang.
        const approvalDecisionApplied = resultObj?.approval_decision_applied;
        const approvalDecision = String(resultObj?.decision || "").toLowerCase();
        if (
          resultObj &&
          typeof approvalDecisionApplied === "boolean" &&
          (approvalDecision === "approve" || approvalDecision === "deny") &&
          resultObj.target_operation_id != null &&
          String(resultObj.target_operation_id).trim() !== ""
        ) {
          const expected = opts.expectedApprovalDecision;
          if (
            !expected ||
            expected.target_operation_id !== String(resultObj.target_operation_id) ||
            expected.decision !== approvalDecision ||
            expected.approval_id !== String(resultObj.approval_id || "")
          ) {
            return { ok: false, error: "approval_decision_binding_mismatch" };
          }
          const targetId = String(resultObj.target_operation_id);
          const target = await store.getMcpOperation(targetId);
          if (!target) {
            return { ok: false, error: "unknown_operation" };
          }
          if (opts.deviceId && target.device_id && opts.deviceId !== target.device_id) {
            return { ok: false, error: "device_mismatch" };
          }
          const targetData = target.data || {};
          if (
            targetData.approval_decision !== expected.decision ||
            targetData.approval_transaction_id !== expected.transaction_id ||
            targetData.approval_device_id !== expected.approval_id
          ) {
            return { ok: false, error: "approval_decision_target_binding_mismatch" };
          }
          const decision = approvalDecision;
          let targetStatus = "completed";
          if (approvalDecisionApplied === false || incomingStatus === "failed") {
            targetStatus = "failed";
          } else if (decision === "deny") targetStatus = "denied";
          else if (resultObj.state === "denied") targetStatus = "denied";
          const execData = targetStatus === "failed"
            ? {
                error:
                  incoming.error && typeof incoming.error === "object"
                    ? incoming.error
                    : { code: "OWNMESH_E_APPROVAL_DECISION_FAILED", message: "device rejected the approval decision" },
              }
            : resultObj.result && typeof resultObj.result === "object"
              ? (resultObj.result as Record<string, unknown>)
              : { ...(resultObj as Record<string, unknown>) };
          const updatedTarget = await store.updateMcpOperation(
            target.operation_id,
            {
              status: targetStatus,
              summary:
                targetStatus === "denied"
                  ? "human denied via control-plane recovery approval"
                  : targetStatus === "failed"
                    ? String(
                        (incoming.error as { message?: unknown } | undefined)?.message ||
                          "approved execution failed",
                      )
                    : "human approved; device executed deferred operation",
              data: {
                ...(target.data || {}),
                approval_decision: decision || targetStatus,
                approval_decision_applied: approvalDecisionApplied,
                approval_id:
                  resultObj.approval_id != null
                    ? String(resultObj.approval_id)
                    : target.approval_id,
                execution: execData,
              },
              approval_required: false,
              approval_id:
                resultObj.approval_id != null
                  ? String(resultObj.approval_id)
                  : target.approval_id,
            },
            ["pending", "running", "approval_required", "cancel_requested"],
          );
          if (!updatedTarget) {
            // Target may already be terminal (deny finalize raced) — accept as room-only.
            const cur = await store.getMcpOperation(targetId);
            if (cur && ["completed", "failed", "denied", "cancelled"].includes(cur.status)) {
              return { ok: true, record: cur };
            }
            return { ok: false, error: "cas_conflict" };
          }
          return { ok: true, record: updatedTarget };
        }
        // Cancel control or non-applied decision ack: room-only when completed.
        if (incomingStatus === "completed") {
          return { ok: true, record: null, room_only: true };
        }
        return { ok: false, error: "unknown_operation" };
      }
      return { ok: false, error: "unknown_operation" };
    }
    return { ok: true, record: null, room_only: true };
  }

  // Strict bind: operation_id
  if (opts.operationId && opts.operationId !== op.operation_id) {
    return { ok: false, error: "operation_id_mismatch" };
  }
  if (payloadOpId && payloadOpId !== op.operation_id) {
    return { ok: false, error: "operation_id_mismatch" };
  }

  // Strict bind: correlation_id when both sides present
  if (opts.correlationId && op.correlation_id && opts.correlationId !== op.correlation_id) {
    return { ok: false, error: "correlation_mismatch" };
  }
  // When both operationId and correlationId provided, they must resolve to the same row.
  if (opts.operationId && opts.correlationId) {
    const byCorr = await store.getMcpOperationByCorrelation(opts.correlationId);
    if (byCorr && byCorr.operation_id !== op.operation_id) {
      return { ok: false, error: "correlation_mismatch" };
    }
    if (op.correlation_id && op.correlation_id !== opts.correlationId) {
      return { ok: false, error: "correlation_mismatch" };
    }
  }

  // Strict bind: device
  if (opts.deviceId) {
    if (!op.device_id || opts.deviceId !== op.device_id) {
      return { ok: false, error: "device_mismatch" };
    }
  }

  // A workspace-bound operation may only complete with the same selected root.
  // New absolute Full Access operations are explicitly bound to null; legacy
  // rows without the version field remain readable during rolling deployment.
  const workspaceBoundResultTool = new Set([
    "ownmesh_system_diagnose",
    "ownmesh_fs_list", "ownmesh_list_files", "ownmesh_fs_stat", "ownmesh_fs_read", "ownmesh_read_file",
    "ownmesh_fs_write", "ownmesh_write_file", "ownmesh_fs_patch", "ownmesh_fs_delete",
    "ownmesh_command_run", "ownmesh_run_command", "ownmesh_command_shell", "ownmesh_run_shell",
    "ownmesh_git_status", "ownmesh_git_diff",
  ]).has(op.tool);
  const canonicalWorkspaceAction =
    op.action && typeof op.action === "object" && !Array.isArray(op.action)
      ? (op.action as Record<string, unknown>)
      : null;
  const workspaceContractPresent =
    canonicalWorkspaceAction !== null &&
    Object.prototype.hasOwnProperty.call(canonicalWorkspaceAction, "workspace_version");
  const rawResultStatus = String(opts.payload.status || "completed");
  const completesWithResult = rawResultStatus === "completed" || rawResultStatus === "ok";
  if (workspaceBoundResultTool && completesWithResult &&
    (op.workspace_id !== null || workspaceContractPresent)) {
    const result =
      opts.payload.result && typeof opts.payload.result === "object"
        ? (opts.payload.result as Record<string, unknown>)
        : null;
    const expectedWorkspaceVersion = canonicalWorkspaceAction?.workspace_version;
    const validVersion = op.workspace_id === null
      ? expectedWorkspaceVersion === null
      : Number.isSafeInteger(expectedWorkspaceVersion) && Number(expectedWorkspaceVersion) > 0;
    if (!result || result.workspace_id !== op.workspace_id ||
      (workspaceContractPresent &&
        (!validVersion || result.workspace_version !== expectedWorkspaceVersion))) {
      return { ok: false, error: "workspace_result_mismatch" };
    }
  }

  const payload = opts.payload;
  let status = String(payload.status || "completed");
  if (payload.decision === "deny") status = "denied";
  if (status === "ok") status = "completed";
  // Device policy ask is reported as a failed operation.result with a stable code
  // (operation.result has no approval_required status in ownmesh.operation/1.0).
  const errObj =
    payload.error && typeof payload.error === "object"
      ? (payload.error as Record<string, unknown>)
      : undefined;
  const errCode = errObj?.code != null ? String(errObj.code) : "";
  const errDetails =
    errObj?.details && typeof errObj.details === "object"
      ? (errObj.details as Record<string, unknown>)
      : undefined;
  if (
    errCode === "OWNMESH_E_APPROVAL_REQUIRED" ||
    payload.approval_required === true ||
    errDetails?.approval_required === true
  ) {
    status = "approval_required";
  }
  const terminal = new Set([
    "completed",
    "failed",
    "denied",
    "cancelled",
    "device_offline",
    "approval_required",
  ]);
  // Include cancel_requested so a delayed device terminal result still CAS-succeeds.
  const fromStatuses = ["pending", "running", "approval_required", "cancel_requested"];
  if (!terminal.has(status)) {
    // Non-terminal result: advance pending → running only.
    status = op.status === "pending" ? "running" : op.status;
  }

  let safeSummary: string | undefined;
  const internalTransferTool = isInternalTransferTool(op.tool);
  const systemDiagnosisTool = op.tool === "ownmesh_system_diagnose";
  let data =
    payload.result && typeof payload.result === "object"
      ? (payload.result as Record<string, unknown>)
      : { ...payload };
  if (systemDiagnosisTool) {
    const device = op.device_id ? await store.getDevice(op.device_id) : null;
    if (!device) return { ok: false, error: "diagnosis_device_missing" };
    // This is the durable async result path. Apply the same allowlist as the
    // immediate MCP path before any Agent result can enter operation storage.
    data = normalizeSystemDiagnosis(
      status === "completed" ? data : null,
      device,
      "online",
    );
    safeSummary = status === "completed"
      ? "system diagnosis completed"
      : "system diagnosis unavailable";
  }
  if (op.tool === "__transfer_preflight_source" || op.tool === "__transfer_preflight_source_final" || op.tool === "__transfer_preflight_destination") {
    // A failed preflight carries only the normal bounded error envelope; a
    // completed preflight must pass the exact metadata/proof correlation gate.
    // In particular, never copy a generic Agent result (which could contain
    // chunk bytes) into the durable operation row.
    if (status === "completed") {
      const sanitized = sanitizeTransferPreflightResult(op, payload);
      if ("error" in sanitized) return { ok: false, error: sanitized.error };
      data = sanitized.data;
    } else {
      data = {};
      safeSummary = internalTransferFailureSummary(op.tool, status);
    }
  }
  if (op.tool === "__transfer_artifact_get") {
    if (status === "completed") {
      const sanitized = await sanitizeTransferArtifactResult(op, payload);
      if ("error" in sanitized) return { ok: false, error: sanitized.error };
      data = sanitized.data;
    } else {
      // Errors remain the normal bounded error envelope, never a byte channel.
      data = {};
      safeSummary = internalTransferFailureSummary(op.tool, status);
    }
  }
  if (op.tool === "__transfer_start_source" || op.tool === "__transfer_start_destination") {
    if (status === "completed") {
      const sanitized = sanitizeTransferStartResult(op, payload);
      if ("error" in sanitized) return { ok: false, error: sanitized.error };
      data = sanitized.data;
    } else {
      // The coordinator needs only these two stable codes to advance epoch
      // and fence after a real Agent/Room disconnect. Never retain the Agent
      // message, details, ticket, keys, paths, or byte-shaped diagnostics.
      const code = errCode === "OWNMESH_E_TRANSFER_RECONNECT"
        || errCode === "OWNMESH_E_TRANSFER_SESSION_LOST"
        || errCode === "OWNMESH_E_TRANSFER_CLEANUP_PENDING" ? errCode : "";
      // An approval must not retain the Agent-provided approval payload. It is
      // a terminal coordinator state; the durable status bit is sufficient.
      data = status !== "approval_required" && code ? { error: { code } } : {};
      safeSummary = code && status !== "approval_required"
        ? "transfer start requires a fresh connection proof"
        : internalTransferFailureSummary(op.tool, status);
    }
  }
  if (op.tool === "__transfer_cancel_control") {
    if (status === "completed") {
      const sanitized = sanitizeTransferCancelControlResult(op, payload);
      if ("error" in sanitized) return { ok: false, error: sanitized.error };
      data = sanitized.data;
    } else {
      data = {};
      safeSummary = internalTransferFailureSummary(op.tool, status);
    }
  }
  if (op.tool === "__transfer_source_cleanup") {
    if (status === "completed") {
      const sanitized = sanitizeTransferSourceCleanupResult(op, payload);
      if ("error" in sanitized) return { ok: false, error: sanitized.error };
      data = sanitized.data;
    } else {
      data = {};
      safeSummary = internalTransferFailureSummary(op.tool, status);
    }
  }
  if (
    status === "approval_required" && errDetails &&
    !internalTransferTool && !systemDiagnosisTool
  ) {
    Object.assign(data, {
      approval_required: true,
      approval_id: errDetails.approval_id ?? payload.approval_id,
      reason: errDetails.reason ?? errObj?.message,
      error: errObj,
    });
  }

  if (op.device_id && (status === "completed" || status === "failed")) {
    data = await applyWorkspaceActivationSideEffects(store, op, data, status);
  }

  const approvalUrlValue =
    status === "approval_required"
      ? approvalUrlFromIssuer(opts.issuer, op.operation_id)
      : op.approval_url;

  // Internal transfer tools may not make a durable row into a bearer or
  // diagnostics channel through an approval id or session id either. Preserve
  // only a pre-existing authoritative value; never copy Agent input.
  const approvalId = internalTransferTool
    ? op.approval_id
    : (errDetails?.approval_id != null ? String(errDetails.approval_id) : undefined) ||
      (payload.approval_id ? String(payload.approval_id) : undefined) ||
      op.approval_id;

  // Preserve continuation cursors on the durable row so clients can page after a
  // large result is bounded by the store (never silently drop next_offset).
  let nextCursor =
    typeof data.next_cursor === "string"
      ? data.next_cursor
      : op.next_cursor ?? null;
  if (
    (nextCursor == null || nextCursor === "") &&
    data.next_offset !== undefined &&
    data.next_offset !== null &&
    `${data.next_offset}` !== ""
  ) {
    nextCursor = `off_${String(data.next_offset)}`;
  }
  const truncatedFlag =
    data.truncated === true || data.durable_truncated === true || op.truncated === true;

  const updated = await store.updateMcpOperation(
    op.operation_id,
    {
      status,
      summary: String(
        safeSummary ||
          payload.summary ||
          (errDetails?.reason != null ? String(errDetails.reason) : undefined) ||
          (errObj?.message != null ? String(errObj.message) : undefined) ||
          payload.reason ||
          op.summary ||
          status,
      ),
      data,
      truncated: truncatedFlag,
      next_cursor: nextCursor,
      approval_required: status === "approval_required",
      approval_url: approvalUrlValue,
      approval_id: approvalId,
      session_id: internalTransferTool || systemDiagnosisTool
        ? op.session_id
        : payload.session_id != null ? String(payload.session_id) : op.session_id,
    },
    fromStatuses,
  );
  if (!updated) {
    return { ok: false, error: "cas_conflict" };
  }
  return { ok: true, record: updated };
}
