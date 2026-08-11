/**
 * Focused coverage: WS operation.request deferred dispatch.
 * Router stages pending only; DeviceRoom persists then sends; persist fail = zero sends + fail closed.
 * Harness remains immediate.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import {
  DeviceRoom,
  DeviceRoomHarness,
  DeviceRoomRouter,
  PROTOCOL,
  ROOM_STATE_STORAGE_KEY,
  type DeviceEnvelope,
  type PersistedRoomState,
  type SessionAttachment,
} from "./device-room.ts";
import {
  DEFAULT_TENANT,
  SqlStore,
  type DeviceRecord,
  type SqlDatabase,
  type SqlStatement,
} from "./store.ts";
import { randomId, sha256Hex } from "./util.ts";

const SESSION_SECRET = "test-device-room-defer-dispatch-secret";
const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, "..", "migrations");

const sessionSeq = new Map<string, number>();

function nextSeq(sessionKey: string): number {
  const n = (sessionSeq.get(sessionKey) || 0) + 1;
  sessionSeq.set(sessionKey, n);
  return n;
}

function envFor(
  sessionId: string,
  type: string,
  deviceId: string,
  payload: Record<string, unknown> = {},
  correlation?: string,
  opts?: { seq?: number; message_id?: string },
): DeviceEnvelope {
  const e: DeviceEnvelope = {
    protocol: PROTOCOL,
    message_id: opts?.message_id || randomId("msg_"),
    type,
    device_id: deviceId,
    seq: opts?.seq ?? nextSeq(sessionId),
    sent_at: new Date().toISOString(),
    payload,
  };
  if (correlation) e.correlation_id = correlation;
  return e;
}

function openSqliteAdapter(): { adapter: SqlDatabase; store: SqlStore } {
  const db = new DatabaseSync(":memory:");
  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort();
  for (const f of files) {
    db.exec(readFileSync(join(migrationsDir, f), "utf8"));
  }
  type SqlVal = null | number | string | bigint | Uint8Array;
  let batchTail: Promise<void> = Promise.resolve();
  const adapter: SqlDatabase = {
    prepare(query: string): SqlStatement {
      const stmt = db.prepare(query);
      let bound: SqlVal[] = [];
      const api: SqlStatement = {
        bind(...values: unknown[]) {
          bound = values.map((v) => (v === undefined ? null : (v as SqlVal)));
          return api;
        },
        async first<T>(colName?: string) {
          const row = stmt.get(...bound) as Record<string, unknown> | undefined;
          if (!row) return null;
          if (colName) return (row[colName] as T) ?? null;
          return row as T;
        },
        async run() {
          const info = stmt.run(...bound) as { changes: number };
          return { success: true, meta: { changes: info.changes }, results: [] };
        },
        async all<T>() {
          const rows = stmt.all(...bound) as T[];
          return { results: rows };
        },
      };
      return api;
    },
    exec(query: string) {
      db.exec(query);
    },
    async batch<T>(statements: SqlStatement[]): Promise<T[]> {
      const run = async (): Promise<T[]> => {
        db.exec("BEGIN IMMEDIATE");
        try {
          const results: unknown[] = [];
          for (const statement of statements) results.push(await statement.run());
          db.exec("COMMIT");
          return results as T[];
        } catch (error) {
          db.exec("ROLLBACK");
          throw error;
        }
      };
      const result = batchTail.then(run, run);
      batchTail = result.then(
        () => undefined,
        () => undefined,
      );
      return result;
    },
  };
  return { adapter, store: new SqlStore(adapter, "sqlite") };
}

async function seedActiveDevice(
  store: SqlStore,
  deviceId: string,
): Promise<{ token: string; device: DeviceRecord; clientAccessToken: string }> {
  await store.ensureBootstrap();
  const device: DeviceRecord = {
    id: deviceId,
    tenant_id: DEFAULT_TENANT,
    principal_id: "prin_dev",
    name: "test-device",
    hostname: "host",
    os: "test",
    arch: "x64",
    agent_version: "0",
    protocol_version: PROTOCOL,
    public_key: "ab".repeat(32),
    revoked: false,
    created_at: new Date().toISOString(),
    status: "active",
  };
  await store.putDevice(device);
  const issued = await store.issueDeviceCredential(device);
  // Client WS sessions validate via OAuth access-token hash (not device credential).
  const clientTok = await store.issueTokens(
    "client_ownmesh_cli",
    "prin_dev",
    "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session",
  );
  return { token: issued.token, device, clientAccessToken: clientTok.access_token };
}

type MockSocket = {
  attachment: SessionAttachment | null;
  closed: { code: number; reason: string } | null;
  sent: string[];
  send(data: string): void;
  close(code?: number, reason?: string): void;
  serializeAttachment(att: unknown): void;
  deserializeAttachment(): SessionAttachment | null;
};

function mockSocket(att: SessionAttachment | null = null): MockSocket {
  const s: MockSocket = {
    attachment: att,
    closed: null,
    sent: [],
    send(data: string) {
      if (s.closed) throw new Error("closed");
      s.sent.push(data);
    },
    close(code = 1000, reason = "") {
      s.closed = { code, reason };
    },
    serializeAttachment(attValue: unknown) {
      s.attachment = attValue as SessionAttachment;
    },
    deserializeAttachment() {
      return s.attachment;
    },
  };
  return s;
}

function mockDOState(opts?: {
  sockets?: MockSocket[];
  storage?: Map<string, unknown>;
}): DurableObjectState {
  const map = opts?.storage || new Map<string, unknown>();
  const sockets = opts?.sockets || [];
  return {
    id: { toString: () => "do_defer", equals: () => false, name: undefined } as DurableObjectId,
    storage: {
      get: async (key: string) => map.get(key),
      put: async (key: string, value: unknown) => {
        map.set(key, structuredClone(value));
      },
      delete: async (key: string) => map.delete(key),
      list: async () => new Map(map),
      deleteAll: async () => {
        map.clear();
      },
      transaction: async (fn: (txn: unknown) => Promise<unknown>) => fn({}),
      getAlarm: async () => null,
      setAlarm: async () => undefined,
      deleteAlarm: async () => undefined,
      sync: async () => undefined,
      sql: undefined,
    },
    getWebSockets: () => sockets as unknown as WebSocket[],
    acceptWebSocket: (ws: WebSocket) => {
      sockets.push(ws as unknown as MockSocket);
    },
    setWebSocketAutoResponse: () => undefined,
    getWebSocketAutoResponse: () => null,
    getWebSocketAutoResponseTimestamp: () => null,
    setHibernatableWebSocketEventTimeout: () => undefined,
    getHibernatableWebSocketEventTimeout: () => null,
    getTags: () => [],
    abort: () => undefined,
    waitUntil: () => undefined,
    blockConcurrencyWhile: async <T>(fn: () => Promise<T>) => fn(),
  } as unknown as DurableObjectState;
}

// ---------------------------------------------------------------------------
// Router: no direct sends on operation.request
// ---------------------------------------------------------------------------

test("router operation.request stages pending and returns deferred_dispatch without sending", async () => {
  const deviceId = "dev_defer_router_01ab";
  const sent: Array<{ sid: string; data: string }> = [];
  const router = new DeviceRoomRouter(deviceId, {
    sendToSession: (sid, data) => {
      sent.push({ sid, data });
      return true;
    },
    sendToRole: () => 0,
  });
  router.registerSession({
    role: "agent",
    device_id: deviceId,
    session_id: "ags_r1",
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
  });
  router.registerSession({
    role: "client",
    device_id: deviceId,
    session_id: "cls_r1",
    connected_at: Date.now(),
    phase: "connected",
    scope: "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session",
  });

  const corr = "op_defer_router_01";
  const result = await router.handleMessage(
    "cls_r1",
    JSON.stringify(
      envFor("cls_r1", "operation.request", deviceId, { op: "ownmesh_fs_list", path: "/" }, corr, {
        seq: 1,
        message_id: "m_defer_r1",
      }),
    ),
  );

  assert.equal(result.ok, true);
  assert.ok(result.deferred_dispatch, "must return deferred_dispatch");
  assert.equal(result.deferred_dispatch!.pending_key, corr);
  assert.deepEqual(result.deferred_dispatch!.recipients, ["ags_r1"]);
  assert.equal(router.pending.has(corr), true);
  assert.equal(sent.length, 0, "handleMessage must not send any frames");

  // Finalize delivers exactly once.
  const n = router.finalizeDeferredDispatch(result.deferred_dispatch!);
  assert.equal(n, 1);
  assert.equal(sent.length, 1);
  assert.equal(sent[0]!.sid, "ags_r1");
  assert.equal((JSON.parse(sent[0]!.data) as DeviceEnvelope).type, "operation.request");
});

test("router operation.request offline defers device_offline without pending", async () => {
  const deviceId = "dev_defer_offline_01";
  const sent: string[] = [];
  const router = new DeviceRoomRouter(deviceId, {
    sendToSession: (_sid, data) => {
      sent.push(data);
      return true;
    },
    sendToRole: () => 0,
  });
  router.registerSession({
    role: "client",
    device_id: deviceId,
    session_id: "cls_off",
    connected_at: Date.now(),
    phase: "connected",
    scope: "ownmesh.read",
  });

  const corr = "op_defer_off_01";
  const result = await router.handleMessage(
    "cls_off",
    JSON.stringify(
      envFor("cls_off", "operation.request", deviceId, { op: "ownmesh_fs_list", path: "/" }, corr, {
        seq: 1,
        message_id: "m_off_1",
      }),
    ),
  );
  assert.equal(result.ok, true);
  assert.ok(result.deferred_dispatch);
  assert.equal(result.deferred_dispatch!.pending_key, undefined);
  assert.equal(router.pending.has(corr), false);
  assert.equal(sent.length, 0, "offline frame must not send until finalize");

  router.finalizeDeferredDispatch(result.deferred_dispatch!);
  assert.equal(sent.length, 1);
  const frame = JSON.parse(sent[0]!) as DeviceEnvelope;
  assert.equal(frame.type, "operation.result");
  assert.equal(frame.payload.status, "device_offline");
});

// ---------------------------------------------------------------------------
// Harness: still immediate
// ---------------------------------------------------------------------------

test("DeviceRoomHarness still dispatches deferred operation.request immediately", async () => {
  const deviceId = "dev_defer_harness_01";
  const room = new DeviceRoomHarness(deviceId, () => true);
  const agent = room.connect("agent");
  const client = room.connect("client");
  room.router.sessions.get(agent)!.phase = "ready";
  room.router.sessions.get(agent)!.remote_routing_enabled = true;

  const corr = randomId("op_");
  const result = await room.send(
    client,
    envFor(client, "operation.request", deviceId, { op: "ownmesh_fs_list", path: "/" }, corr),
  );
  assert.equal(result.ok, true);
  assert.ok(result.deferred_dispatch, "result still carries deferred_dispatch metadata");
  const agentInbox = room.drain(agent).map((s) => JSON.parse(s) as DeviceEnvelope);
  assert.equal(agentInbox.length, 1);
  assert.equal(agentInbox[0]!.type, "operation.request");
  assert.equal(agentInbox[0]!.correlation_id, corr);
  assert.equal(room.router.pending.has(corr), true);
});

// ---------------------------------------------------------------------------
// DeviceRoom.webSocketMessage: persist barrier
// ---------------------------------------------------------------------------

test("webSocketMessage: no agent send before persist; send after durable pending", async () => {
  const deviceId = "dev_defer_ws_ok_01ab";
  const { adapter, store } = openSqliteAdapter();
  const { token, clientAccessToken } = await seedActiveDevice(store, deviceId);
  const agentAuthHash = await sha256Hex(token);
  const clientAuthHash = await sha256Hex(clientAccessToken);

  const map = new Map<string, unknown>();
  const events: string[] = [];
  const state = mockDOState({ storage: map });
  const origPut = state.storage.put.bind(state.storage);
  (state.storage as { put: (k: string, v: unknown) => Promise<void> }).put = async (k, v) => {
    events.push(`put:${k}`);
    return origPut(k, v);
  };

  const agentAtt: SessionAttachment = {
    role: "agent",
    device_id: deviceId,
    session_id: "ags_defer_ok",
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
    auth_hash: agentAuthHash,
    lastSeq: 0,
  };
  const clientAtt: SessionAttachment = {
    role: "client",
    device_id: deviceId,
    session_id: "cls_defer_ok",
    connected_at: Date.now(),
    phase: "connected",
    scope: "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session",
    auth_hash: clientAuthHash,
    lastSeq: 0,
  };
  const agentSock = mockSocket(agentAtt);
  const clientSock = mockSocket(clientAtt);

  const room = new DeviceRoom(state, {
    DB: adapter as unknown as D1Database,
    SESSION_SECRET,
  });
  await room.ready;
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;
  room.wsSessions.set(agentSock as unknown as WebSocket, agentAtt.session_id);
  room.wsSessions.set(clientSock as unknown as WebSocket, clientAtt.session_id);
  room.router.registerSession(agentAtt);
  room.router.registerSession(clientAtt);

  // Intercept sendToSession to observe order vs durable storage.
  const baseSend = room.router.sendToSession.bind(room.router);
  room.router.sendToSession = (sid, data) => {
    events.push(`send:${sid}`);
    const snap = map.get(ROOM_STATE_STORAGE_KEY) as PersistedRoomState | undefined;
    assert.ok(snap, "storage must hold room state before any deferred send");
    assert.ok(
      snap.pending.some((p) => p.correlation_id === "op_defer_ws_ok"),
      "pending must be durable before agent send",
    );
    return baseSend(sid, data);
  };

  const corr = "op_defer_ws_ok";
  await room.webSocketMessage(
    clientSock as unknown as WebSocket,
    JSON.stringify(
      envFor(
        clientAtt.session_id,
        "operation.request",
        deviceId,
        { op: "ownmesh_fs_list", path: "/w" },
        corr,
        { seq: 1, message_id: "m_defer_ws_ok" },
      ),
    ),
  );

  const putIdx = events.findIndex((e) => e.startsWith("put:"));
  const sendIdx = events.findIndex((e) => e.startsWith("send:"));
  assert.ok(putIdx >= 0, "must persist");
  assert.ok(sendIdx >= 0, "must send after persist");
  assert.ok(putIdx < sendIdx, "persist must precede any agent send");
  assert.equal(room.router.pending.has(corr), true);
  assert.equal(agentSock.sent.length, 1);
  assert.equal((JSON.parse(agentSock.sent[0]!) as DeviceEnvelope).type, "operation.request");
  assert.equal(clientSock.closed, null);
});

test("webSocketMessage: persist failure fail-closed with zero agent frames", async () => {
  const deviceId = "dev_defer_ws_fail_01";
  const { adapter, store } = openSqliteAdapter();
  const { token, clientAccessToken } = await seedActiveDevice(store, deviceId);
  const agentAuthHash = await sha256Hex(token);
  const clientAuthHash = await sha256Hex(clientAccessToken);

  const map = new Map<string, unknown>();
  let failPut = false;
  const state = mockDOState({ storage: map });
  const origPut = state.storage.put.bind(state.storage);
  (state.storage as { put: (k: string, v: unknown) => Promise<void> }).put = async (k, v) => {
    if (failPut) throw new Error("quota_exceeded");
    return origPut(k, v);
  };

  const agentAtt: SessionAttachment = {
    role: "agent",
    device_id: deviceId,
    session_id: "ags_defer_fail",
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
    auth_hash: agentAuthHash,
    lastSeq: 0,
  };
  const clientAtt: SessionAttachment = {
    role: "client",
    device_id: deviceId,
    session_id: "cls_defer_fail",
    connected_at: Date.now(),
    phase: "connected",
    scope: "ownmesh.read",
    auth_hash: clientAuthHash,
    lastSeq: 0,
  };
  const agentSock = mockSocket(agentAtt);
  const clientSock = mockSocket(clientAtt);

  const room = new DeviceRoom(state, {
    DB: adapter as unknown as D1Database,
    SESSION_SECRET,
  });
  await room.ready;
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;
  room.wsSessions.set(agentSock as unknown as WebSocket, agentAtt.session_id);
  room.wsSessions.set(clientSock as unknown as WebSocket, clientAtt.session_id);
  room.router.registerSession(agentAtt);
  room.router.registerSession(clientAtt);

  let sendCount = 0;
  room.router.sendToSession = () => {
    sendCount += 1;
    return true;
  };

  // Seed a durable baseline so only the request-path put fails.
  failPut = false;
  await room.flushPersist();

  failPut = true;
  const corr = "op_defer_ws_fail";
  await room.webSocketMessage(
    clientSock as unknown as WebSocket,
    JSON.stringify(
      envFor(
        clientAtt.session_id,
        "operation.request",
        deviceId,
        { op: "ownmesh_fs_list", path: "/" },
        corr,
        { seq: 1, message_id: "m_defer_ws_fail" },
      ),
    ),
  );

  assert.equal(sendCount, 0, "must not send any agent frames on persist failure");
  assert.equal(room.router.pending.has(corr), false, "staged pending rolled back / cleared");
  assert.equal(room.isStorageBroken, true);
  // failClosedAll pattern: sockets closed with 1013
  assert.ok(clientSock.closed, "client socket fail-closed");
  assert.equal(clientSock.closed!.code, 1013);
  assert.ok(agentSock.closed, "agent socket fail-closed");
  assert.equal(agentSock.closed!.code, 1013);
  assert.equal(agentSock.sent.length, 0);
});
