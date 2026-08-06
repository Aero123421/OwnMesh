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

import { json, nowIso, randomId, randomToken } from "./util.ts";

export const PROTOCOL = "ownmesh.device/1.0";

export type SessionRole = "agent" | "client";

export type SessionAttachment = {
  role: SessionRole;
  device_id: string;
  session_id: string;
  connected_at: number;
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

/**
 * Pure routing logic — unit-tested without Workers runtime.
 * DeviceRoom DO delegates to this for message handling.
 */
export class DeviceRoomRouter {
  deviceId: string;
  /** session_id -> attachment */
  sessions = new Map<string, SessionAttachment>();
  /** WebSocket tag or mock id -> session_id (set by adapter) */
  pending = new Map<string, PendingOperation>();
  seqOut = 0;
  audit: AuditSink;
  /** outbound send by session_id */
  sendToSession: (sessionId: string, data: string) => boolean;
  /** broadcast to all sessions with role */
  sendToRole: (role: SessionRole, data: string) => number;

  constructor(
    deviceId: string,
    opts: {
      audit?: AuditSink;
      sendToSession: (sessionId: string, data: string) => boolean;
      sendToRole: (role: SessionRole, data: string) => number;
    },
  ) {
    this.deviceId = deviceId;
    this.audit = opts.audit || { append: () => undefined };
    this.sendToSession = opts.sendToSession;
    this.sendToRole = opts.sendToRole;
  }

  registerSession(att: SessionAttachment): void {
    this.sessions.set(att.session_id, att);
  }

  unregisterSession(sessionId: string): void {
    this.sessions.delete(sessionId);
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
  handleMessage(sessionId: string, raw: string): { ok: boolean; error?: string } {
    const att = this.sessions.get(sessionId);
    if (!att) return { ok: false, error: "unknown_session" };

    let msg: DeviceEnvelope;
    try {
      msg = JSON.parse(raw) as DeviceEnvelope;
    } catch {
      return { ok: false, error: "bad_json" };
    }
    if (msg.protocol !== PROTOCOL) {
      const err = this.nextEnvelope("error", {
        code: "OWNMESH_E_UNSUPPORTED_PROTOCOL",
        message: `expected ${PROTOCOL}`,
      });
      this.sendToSession(sessionId, JSON.stringify(err));
      return { ok: false, error: "bad_protocol" };
    }
    if (msg.device_id && msg.device_id !== this.deviceId) {
      return { ok: false, error: "device_mismatch" };
    }

    switch (msg.type) {
      case "hello": {
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
        const accepted = this.nextEnvelope(
          "accepted",
          {
            selected_protocol: PROTOCOL,
            session_parameters: {
              heartbeat_sec: 30,
              max_payload_bytes: 1_000_000,
            },
          },
          msg.correlation_id,
        );
        this.sendToSession(sessionId, JSON.stringify(accepted));
        return { ok: true };
      }
      case "ready": {
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
        // Client -> agent
        this.pending.set(msg.correlation_id || msg.message_id, {
          correlation_id: msg.correlation_id || msg.message_id,
          type: String(msg.payload.op || msg.type),
          from_session: sessionId,
          created_at: Date.now(),
          payload: msg.payload,
        });
        const n = this.sendToRole("agent", JSON.stringify(msg));
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
          const offline = this.nextEnvelope(
            "operation.result",
            {
              status: "device_offline",
              code: "OWNMESH_E_DEVICE_OFFLINE",
            },
            msg.correlation_id || msg.message_id,
          );
          this.sendToSession(sessionId, JSON.stringify(offline));
        }
        return { ok: true };
      }
      case "operation.result":
      case "operation.event":
      case "operation.progress": {
        // Agent -> waiting clients (or all clients)
        const corr = msg.correlation_id;
        if (corr && this.pending.has(corr)) {
          const p = this.pending.get(corr)!;
          this.sendToSession(p.from_session, JSON.stringify(msg));
          if (msg.type === "operation.result") this.pending.delete(corr);
        } else {
          this.sendToRole("client", JSON.stringify(msg));
        }
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
      default: {
        // Fan-out unknown types to the other role.
        const target: SessionRole = att.role === "agent" ? "client" : "agent";
        this.sendToRole(target, JSON.stringify(msg));
        return { ok: true };
      }
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
    const n = this.sendToRole("agent", JSON.stringify(env));
    void this.audit.append({
      kind: "operation.route",
      summary: "http inject operation",
      device_id: this.deviceId,
      meta: { correlation_id: op.correlation_id, agent_recipients: n, op: op.type },
    });
    if (n === 0) {
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

  constructor(deviceId: string) {
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
    });
  }

  connect(role: SessionRole, sessionId?: string): string {
    const sid = sessionId || randomId(role === "agent" ? "ags_" : "cls_");
    this.inboxes.set(sid, []);
    this.router.registerSession({
      role,
      device_id: this.router.deviceId,
      session_id: sid,
      connected_at: Date.now(),
    });
    return sid;
  }

  send(sessionId: string, envelope: DeviceEnvelope | Record<string, unknown>): void {
    this.router.handleMessage(sessionId, JSON.stringify(envelope));
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
  env: { DB?: D1Database };
  router: DeviceRoomRouter;
  /** ws -> session_id */
  wsSessions = new Map<WebSocket, string>();
  deviceId: string;

  constructor(state: DurableObjectState, env: { DB?: D1Database }) {
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

    if (request.headers.get("Upgrade") === "websocket") {
      const role = (url.searchParams.get("role") || "agent") as SessionRole;
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
    const text =
      typeof message === "string" ? message : new TextDecoder().decode(message);
    this.router.handleMessage(sessionId, text);
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
