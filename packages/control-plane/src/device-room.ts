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
import { createStore, type ControlPlaneStore, type McpOperationRecord } from "./store.ts";

export const PROTOCOL = "ownmesh.device/1.0";
/** Independent operation payload contract (must match Rust/TS schema packages). */
export const OPERATION_CONTRACT_V1 = "ownmesh.operation/1.0";
/** Default operation.request lifetime when the caller does not supply expires_at. */
export const OPERATION_REQUEST_TTL_MS = 60_000;

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
    capability === "filesystem.read" ||
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
};

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
};

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
    this.pruneAll();
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
      this.pending.set(p.correlation_id, {
        correlation_id: p.correlation_id,
        type: String(p.type || ""),
        from_session: String(p.from_session || ""),
        created_at: Number(p.created_at) || 0,
        payload: p.payload && typeof p.payload === "object" ? { ...p.payload } : {},
      });
    }
    this.consumedNonces.clear();
    for (const [nonce, exp] of Object.entries(state.consumedNonces || {})) {
      if (typeof nonce === "string" && nonce && Number.isFinite(exp)) {
        this.consumedNonces.set(nonce, Number(exp));
      }
    }
    this.pruneAll();
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
  pruneAll(now = Date.now()): { seen: number; pending: number } {
    let seen = 0;
    for (const guard of this.ingressGuards.values()) {
      seen += pruneSeenMessageIds(guard, now);
    }
    const pending = this.pruneExpiredPending(now);
    return { seen, pending };
  }

  pruneExpiredPending(now = Date.now()): number {
    let removed = 0;
    for (const [key, p] of [...this.pending]) {
      if (!Number.isFinite(p.created_at) || now - p.created_at > PENDING_TTL_MS) {
        this.pending.delete(key);
        removed++;
      }
    }
    // Hard cap: drop oldest first.
    if (this.pending.size > MAX_PENDING_OPERATIONS) {
      const ordered = [...this.pending.entries()].sort((a, b) => a[1].created_at - b[1].created_at);
      const overflow = this.pending.size - MAX_PENDING_OPERATIONS;
      for (let i = 0; i < overflow; i++) {
        this.pending.delete(ordered[i]![0]);
        removed++;
      }
    }
    return removed;
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
        att.phase = "ready";
        att.remote_routing_enabled = msg.payload.remote_routing_enabled === true;
        this.sessions.set(sessionId, att);
        const ack = this.nextEnvelope(
          "ready.ack",
          { ok: true },
          msg.correlation_id,
        );
        this.sendToSession(sessionId, JSON.stringify(ack));
        void this.audit.append({
          kind: "device.ready",
          summary: "agent ready",
          device_id: this.deviceId,
          meta: {
            capabilities: msg.payload,
            remote_routing_enabled: att.remote_routing_enabled === true,
          },
        });
        return { ok: true };
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
    const addBytes = new TextEncoder().encode(JSON.stringify(payload)).byteLength;
    if (this.totalPendingPayloadBytes() + addBytes > MAX_PENDING_PAYLOAD_BYTES) {
      return {
        ok: false,
        result: { status: "rejected", detail: { code: "OWNMESH_E_PENDING_PAYLOAD_LIMIT" } },
      };
    }
    // Fail closed on offline before mutating pending/seq (no half-prepared state).
    // Only agents that advertised remote_routing_enabled=true count as ready for E2.
    let readyAgents = 0;
    for (const session of this.sessions.values()) {
      if (this.isRemoteRoutingAgent(session)) readyAgents++;
    }
    if (readyAgents === 0) {
      return {
        ok: false,
        result: { status: "device_offline", detail: { code: "OWNMESH_E_DEVICE_OFFLINE" } },
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
    if (n === 0) {
      this.pending.delete(prepared.correlation_id);
      this.notifyStateChange();
      return { status: "device_offline", detail: { code: "OWNMESH_E_DEVICE_OFFLINE" } };
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

  status(): { device_id: string; sessions: number; pending: number; agents: number; clients: number } {
    this.pruneExpiredPending();
    let agents = 0;
    let clients = 0;
    for (const s of this.sessions.values()) {
      if (s.role === "agent") agents++;
      else clients++;
    }
    return {
      device_id: this.deviceId,
      sessions: this.sessions.size,
      pending: this.pending.size,
      agents,
      clients,
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
    } catch (err) {
      this.storageBroken = true;
      this.failClosedAll("storage unavailable", 1013);
      throw err instanceof Error ? err : new Error("storage_persist_failed");
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
      // Binding: principal/tenant on the device must match signed claims when device is known.
      if (this.env.DB) {
        try {
          const storeForBind = createStore(this.env);
          const boundDevice = await storeForBind.getDevice(this.deviceId);
          if (
            boundDevice &&
            (boundDevice.principal_id !== opCtx.claims.principal_id ||
              boundDevice.tenant_id !== opCtx.claims.tenant_id)
          ) {
            return json({ error: "binding_mismatch" }, { status: 403 });
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
        if (
          device.principal_id !== wsCtx.claims.principal_id ||
          device.tenant_id !== wsCtx.claims.tenant_id
        ) {
          return json({ error: "binding_mismatch" }, { status: 403 });
        }
        if (role === "agent") {
          const credential = token ? await store.getDeviceCredential(token) : null;
          if (!credential || credential.device_id !== this.deviceId) {
            return json({ error: "invalid_device_credential" }, { status: 401 });
          }
        } else {
          const access = token ? await store.getAccess(token) : null;
          if (
            !access ||
            access.principal !== device.principal_id ||
            access.tenant_id !== device.tenant_id
          ) {
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

    const result = await this.router.handleMessage(sessionId, text);
    const updatedAttachment = this.router.sessions.get(sessionId);
    if (updatedAttachment) {
      const guard = this.router.ingressGuards.get(sessionId);
      if (guard) updatedAttachment.lastSeq = guard.lastSeq;
      ws.serializeAttachment(updatedAttachment);
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
        const applied = await applyMcpOperationResult(store, {
          operationId: result.mcp_result.operation_id,
          correlationId: corr,
          payload: result.mcp_result.payload,
          deviceId: this.deviceId,
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
      } catch {
        // Store write failure: fail closed, no success forward.
        this.storageBroken = true;
        this.failClosedAll("storage unavailable", 1013);
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

  // No store row: allow room-only routing only when no operation_id was claimed.
  if (!op) {
    if (wantOpId) return { ok: false, error: "unknown_operation" };
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

  const data =
    payload.result && typeof payload.result === "object"
      ? (payload.result as Record<string, unknown>)
      : { ...payload };
  if (status === "approval_required" && errDetails) {
    Object.assign(data, {
      approval_required: true,
      approval_id: errDetails.approval_id ?? payload.approval_id,
      reason: errDetails.reason ?? errObj?.message,
      error: errObj,
    });
  }

  const approvalId =
    (errDetails?.approval_id != null ? String(errDetails.approval_id) : undefined) ||
    (payload.approval_id ? String(payload.approval_id) : undefined) ||
    op.approval_id;

  const updated = await store.updateMcpOperation(
    op.operation_id,
    {
      status,
      summary: String(
        payload.summary ||
          (errDetails?.reason != null ? String(errDetails.reason) : undefined) ||
          (errObj?.message != null ? String(errObj.message) : undefined) ||
          payload.reason ||
          op.summary ||
          status,
      ),
      data,
      approval_required: status === "approval_required",
      approval_id: approvalId,
      session_id: payload.session_id != null ? String(payload.session_id) : op.session_id,
    },
    fromStatuses,
  );
  if (!updated) {
    return { ok: false, error: "cas_conflict" };
  }
  return { ok: true, record: updated };
}
