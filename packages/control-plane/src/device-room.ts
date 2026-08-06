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
 * Protocol envelopes: ownmesh.device/1.0 (OWNMESH_SPECIFICATION §21).
 */

import { json, nowIso, randomId, randomToken, requireScope, sha256Hex, verifyEd25519Hex } from "./util.ts";
import { createStore } from "./store.ts";

export const PROTOCOL = "ownmesh.device/1.0";

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

export type HandleMessageResult = {
  ok: boolean;
  error?: string;
  /** When true, DeviceRoom.webSocketMessage should gracefully close the socket. */
  close?: boolean;
  closeCode?: number;
  closeReason?: string;
};

type SessionIngressGuard = {
  lastSeq: number;
  seenMessageIds: Set<string>;
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
  seqOut = 0;
  audit: AuditSink;
  /** outbound send by session_id */
  sendToSession: (sessionId: string, data: string) => boolean;
  /** broadcast to all sessions with role */
  sendToRole: (role: SessionRole, data: string) => number;
  verifyProof: (deviceId: string, message: string, signature: string) => boolean | Promise<boolean>;

  constructor(
    deviceId: string,
    opts: {
      audit?: AuditSink;
      sendToSession: (sessionId: string, data: string) => boolean;
      sendToRole: (role: SessionRole, data: string) => number;
      verifyProof?: (deviceId: string, message: string, signature: string) => boolean | Promise<boolean>;
    },
  ) {
    this.deviceId = deviceId;
    this.audit = opts.audit || { append: () => undefined };
    this.sendToSession = opts.sendToSession;
    this.sendToRole = opts.sendToRole;
    this.verifyProof = opts.verifyProof || (() => false);
  }

  registerSession(att: SessionAttachment): void {
    this.sessions.set(att.session_id, { ...att, phase: att.phase || "connected" });
    if (!this.ingressGuards.has(att.session_id)) {
      this.ingressGuards.set(att.session_id, { lastSeq: 0, seenMessageIds: new Set() });
    }
  }

  unregisterSession(sessionId: string): void {
    this.sessions.delete(sessionId);
    this.ingressGuards.delete(sessionId);
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
    const guard = this.ingressGuards.get(sessionId) || { lastSeq: 0, seenMessageIds: new Set<string>() };
    if (!this.ingressGuards.has(sessionId)) this.ingressGuards.set(sessionId, guard);

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

    guard.seenMessageIds.add(messageId);
    // Bound memory: keep a rolling window of recent ids.
    if (guard.seenMessageIds.size > 4096) {
      const first = guard.seenMessageIds.values().next().value;
      if (first !== undefined) guard.seenMessageIds.delete(first);
    }
    guard.lastSeq = seq;
    return null;
  }

  nextEnvelope(
    type: string,
    payload: Record<string, unknown>,
    correlationId?: string,
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
    return env;
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
          meta: { capabilities: msg.payload },
        });
        return { ok: true };
      }
      case "operation.request": {
        if (att.role !== "client") return { ok: false, error: "invalid_role" };
        const operation = String(msg.payload.op || "");
        const requiredScope = operation.startsWith("ownmesh_fs_write") ? "ownmesh.write"
          : operation.startsWith("ownmesh_command") || operation === "ownmesh_cancel_operation" ? "ownmesh.exec"
          : operation.startsWith("ownmesh_session") ? "ownmesh.session"
          : operation.startsWith("ownmesh_fs_") || operation.startsWith("ownmesh_profile") ? "ownmesh.read"
          : "";
        if (!requiredScope || !requireScope(att.scope || "", requiredScope)) return { ok: false, error: "insufficient_scope" };
        // Client -> ready agent
        const pendingKey = msg.correlation_id || msg.message_id;
        this.pending.set(pendingKey, {
          correlation_id: pendingKey,
          type: String(msg.payload.op || msg.type),
          from_session: sessionId,
          created_at: Date.now(),
          payload: msg.payload,
        });
        let n = 0;
        for (const [sid, session] of this.sessions) {
          if (session.role === "agent" && session.phase === "ready" && this.sendToSession(sid, JSON.stringify(msg))) n++;
        }
        void this.audit.append({
          kind: "operation.route",
          summary: "operation.request routed to agent",
          device_id: this.deviceId,
          meta: {
            correlation_id: msg.correlation_id,
            agent_recipients: n,
            op: msg.payload.op,
          },
        });
        if (n === 0) {
          this.pending.delete(pendingKey);
          const offline = this.nextEnvelope(
            "operation.result",
            {
              status: "device_offline",
              code: "OWNMESH_E_DEVICE_OFFLINE",
            },
            pendingKey,
          );
          this.sendToSession(sessionId, JSON.stringify(offline));
        }
        return { ok: true };
      }
      case "operation.result":
      case "operation.event":
      case "operation.progress": {
        if (att.role !== "agent" || att.phase !== "ready") return { ok: false, error: "invalid_state" };
        // Agent -> waiting clients (or all clients)
        const corr = msg.correlation_id;
        if (!corr || !this.pending.has(corr)) return { ok: false, error: "unknown_correlation" };
        const p = this.pending.get(corr)!;
        this.sendToSession(p.from_session, JSON.stringify(msg));
        if (msg.type === "operation.result") this.pending.delete(corr);
        void this.audit.append({
          kind: "operation.result",
          summary: msg.type,
          device_id: this.deviceId,
          meta: { correlation_id: corr, from: att.role },
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
   * HTTP-side injection of an operation (from Worker MCP path).
   * Returns whether an agent received it.
   */
  injectOperation(op: {
    type: string;
    payload: Record<string, unknown>;
    correlation_id: string;
    from_session?: string;
  }): { status: string; detail?: unknown } {
    const from = op.from_session || "http_client";
    if (!this.sessions.has(from)) {
      this.registerSession({
        role: "client",
        device_id: this.deviceId,
        session_id: from,
        connected_at: Date.now(),
        phase: "connected",
      });
    }
    const env = this.nextEnvelope(
      "operation.request",
      { op: op.type, ...op.payload },
      op.correlation_id,
    );
    this.pending.set(op.correlation_id, {
      correlation_id: op.correlation_id,
      type: op.type,
      from_session: from,
      created_at: Date.now(),
      payload: op.payload,
    });
    let n = 0;
    for (const [sid, session] of this.sessions) {
      if (session.role === "agent" && session.phase === "ready" && this.sendToSession(sid, JSON.stringify(env))) n++;
    }
    void this.audit.append({
      kind: "operation.route",
      summary: "http inject operation",
      device_id: this.deviceId,
      meta: { correlation_id: op.correlation_id, agent_recipients: n, op: op.type },
    });
    if (n === 0) {
      this.pending.delete(op.correlation_id);
      return { status: "device_offline", detail: { code: "OWNMESH_E_DEVICE_OFFLINE" } };
    }
    return { status: "routed_to_device", detail: { recipients: n, correlation_id: op.correlation_id } };
  }

  status(): { device_id: string; sessions: number; pending: number; agents: number; clients: number } {
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
    this.router.registerSession({
      role,
      device_id: this.router.deviceId,
      session_id: sid,
      connected_at: Date.now(),
      phase: "connected",
      scope: role === "client" ? scope : undefined,
    });
    return sid;
  }

  async send(sessionId: string, envelope: DeviceEnvelope | Record<string, unknown>): Promise<HandleMessageResult> {
    return this.router.handleMessage(sessionId, JSON.stringify(envelope));
  }

  /** Send a raw WS text frame (for malformed / oversized guard tests). */
  async sendRaw(sessionId: string, raw: string): Promise<HandleMessageResult> {
    return this.router.handleMessage(sessionId, raw);
  }

  drain(sessionId: string): string[] {
    const box = this.inboxes.get(sessionId) || [];
    this.inboxes.set(sessionId, []);
    return box;
  }
}

/**
 * Durable Object class — hibernation-friendly WebSocket device room.
 * Exported from the Worker module.
 */
export class DeviceRoom {
  state: DurableObjectState;
  env: { DB?: D1Database; OAUTH_ISSUER?: string; OWNMESH_ALLOWED_ORIGINS?: string };
  router: DeviceRoomRouter;
  /** ws -> session_id */
  wsSessions = new Map<WebSocket, string>();
  deviceId: string;
  devicePublicKey = "";

  constructor(state: DurableObjectState, env: { DB?: D1Database; OAUTH_ISSUER?: string; OWNMESH_ALLOWED_ORIGINS?: string }) {
    this.state = state;
    this.env = env;
    this.deviceId = "unknown";
    this.router = this.buildRouter("unknown");

    // Restore hibernated sockets.
    // https://developers.cloudflare.com/durable-objects/examples/websocket-hibernation-server/
    for (const ws of this.state.getWebSockets()) {
      const att = ws.deserializeAttachment() as SessionAttachment | null;
      if (att) {
        this.wsSessions.set(ws, att.session_id);
        if (att.device_id) this.deviceId = att.device_id;
        this.router.registerSession(att);
      }
    }
    if (this.deviceId !== "unknown") {
      this.router.deviceId = this.deviceId;
    }

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
    });
  }

  async fetch(request: Request): Promise<Response> {
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
      return json({
        ...this.router.status(),
        hibernation: true,
        network_outbound_from_do: false,
        websockets: this.state.getWebSockets().length,
      });
    }

    if (url.pathname.endsWith("/operation") && request.method === "POST") {
      if (request.headers.get("x-ownmesh-edge-authorized") !== "1") return json({ error: "unauthorized" }, { status: 401 });
      if (!this.env.DB) return json({ error: "storage_unavailable" }, { status: 503 });
      const operationDevice = await createStore(this.env).getDevice(this.deviceId);
      if (!operationDevice || operationDevice.revoked || operationDevice.status !== "active") return json({ error: "device_not_active" }, { status: 403 });
      const body = (await request.json()) as {
        type: string;
        payload?: Record<string, unknown>;
        correlation_id?: string;
      };
      const result = this.router.injectOperation({
        type: body.type,
        payload: body.payload || {},
        correlation_id: body.correlation_id || randomId("op_"),
      });
      return json(result, { status: result.status === "device_offline" ? 503 : 200 });
    }

    if (request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      if (request.headers.get("x-ownmesh-edge-authorized") !== "1") return json({ error: "unauthorized" }, { status: 401 });
      const origin = request.headers.get("origin") || "";
      const allowedOrigins = new Set([
        request.headers.get("x-ownmesh-allowed-origin") || "",
        this.env.OAUTH_ISSUER ? new URL(this.env.OAUTH_ISSUER).origin : "",
        ...(this.env.OWNMESH_ALLOWED_ORIGINS || "").split(",").map((v) => v.trim()).filter(Boolean),
      ]);
      if (!origin || !allowedOrigins.has(origin)) return json({ error: "origin_not_allowed" }, { status: 403 });
      if (!this.env.DB) return json({ error: "storage_unavailable" }, { status: 503 });
      const role = (url.searchParams.get("role") || "agent") as SessionRole;
      if (role !== "agent" && role !== "client") return json({ error: "invalid_role" }, { status: 403 });
      const token = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") || "";
      const store = createStore(this.env);
      const device = await store.getDevice(this.deviceId);
      if (!device || device.revoked || device.status !== "active") return json({ error: "device_not_active" }, { status: 403 });
      if (role === "agent") {
        const credential = token ? await store.getDeviceCredential(token) : null;
        if (!credential || credential.device_id !== this.deviceId) return json({ error: "invalid_device_credential" }, { status: 401 });
      } else {
        const access = token ? await store.getAccess(token) : null;
        if (!access || access.principal !== device.principal_id || access.tenant_id !== device.tenant_id) return json({ error: "unauthorized" }, { status: 401 });
      }
      this.devicePublicKey = device.public_key;
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
        scope: role === "client" ? (await store.getAccess(token))?.scope : undefined,
      };
      server.serializeAttachment(attachment);
      this.wsSessions.set(server, sessionId);
      this.router.registerSession(attachment);
      return new Response(null, { status: 101, webSocket: client });
    }

    return json({ error: "expected websocket or /status or /operation" }, { status: 400 });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const sessionId = this.wsSessions.get(ws) ||
      (ws.deserializeAttachment() as SessionAttachment | null)?.session_id;
    if (!sessionId) return;
    // Re-hydrate session map after hibernation.
    if (!this.router.sessions.has(sessionId)) {
      const att = ws.deserializeAttachment() as SessionAttachment | null;
      if (att) {
        this.wsSessions.set(ws, att.session_id);
        this.router.registerSession(att);
        this.deviceId = att.device_id;
        this.router.deviceId = att.device_id;
      }
    }
    if (this.env.DB) {
      const sessionStore = createStore(this.env);
      for (const [socket, sid] of [...this.wsSessions]) {
        const session = this.router.sessions.get(sid);
        const valid = Boolean(session?.auth_hash) && await sessionStore.validateDeviceSession(session!.auth_hash!, session!.role, this.deviceId);
        if (!valid) {
          try { socket.close(1008, "authorization revoked"); } catch { /* closed */ }
          this.router.unregisterSession(sid);
          this.wsSessions.delete(socket);
        }
      }
      if (!this.router.sessions.has(sessionId)) return;
    }
    if (!this.devicePublicKey && this.env.DB) {
      const device = await createStore(this.env).getDevice(this.deviceId);
      if (!device || device.revoked || device.status !== "active") {
        try { ws.close(1008, "device not active"); } catch { /* closed */ }
        return;
      }
      this.devicePublicKey = device.public_key;
    }
    const text = typeof message === "string" ? message : new TextDecoder().decode(message);
    const result = await this.router.handleMessage(sessionId, text);
    const updatedAttachment = this.router.sessions.get(sessionId);
    if (updatedAttachment) ws.serializeAttachment(updatedAttachment);
    // Close decision stays in the DO; router remains pure/testable.
    if (result.close) {
      try {
        ws.close(result.closeCode || 1008, result.closeReason || "protocol error");
      } catch {
        /* already closed */
      }
      this.router.unregisterSession(sessionId);
      this.wsSessions.delete(ws);
    }
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    const sessionId = this.wsSessions.get(ws);
    if (sessionId) {
      this.router.unregisterSession(sessionId);
      this.wsSessions.delete(ws);
    }
    try {
      ws.close(code, reason);
    } catch {
      /* already closed */
    }
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    const sessionId = this.wsSessions.get(ws);
    if (sessionId) {
      this.router.unregisterSession(sessionId);
      this.wsSessions.delete(ws);
    }
  }
}
