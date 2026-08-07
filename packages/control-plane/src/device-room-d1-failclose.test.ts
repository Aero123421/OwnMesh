/**
 * D1/store throw → DeviceRoom fail-closed (existing WS 1013 + 503 storage_unavailable).
 *
 * Covers production DeviceRoom.fetch / webSocketMessage / webSocketClose / webSocketError
 * paths so uncaught store exceptions cannot leave live sockets behind.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import {
  DeviceRoom,
  PROTOCOL,
  type DeviceEnvelope,
  type SessionAttachment,
} from "./device-room.ts";
import {
  DEFAULT_TENANT,
  SqlStore,
  type DeviceRecord,
  type SqlDatabase,
  type SqlStatement,
} from "./store.ts";
import { internalDoHeaders, randomId, sha256Hex } from "./util.ts";

const SESSION_SECRET = "test-device-room-d1-failclose-secret";
const ISSUER = "https://cp.test";
const PRINCIPAL_ID = "prin_dev";

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

async function operationHeaders(
  deviceId: string,
  body: unknown,
  extra?: { principal_id?: string; tenant_id?: string; correlation_id?: string },
): Promise<{ headers: Headers; bodyText: string }> {
  const bodyText = JSON.stringify(body);
  const body_sha256 = await sha256Hex(bodyText);
  const headers = await internalDoHeaders(SESSION_SECRET, {
    op: "operation",
    device_id: deviceId,
    principal_id: extra?.principal_id || PRINCIPAL_ID,
    tenant_id: extra?.tenant_id || DEFAULT_TENANT,
    correlation_id: extra?.correlation_id,
    method: "POST",
    path: "/operation",
    body_sha256,
  });
  return { headers, bodyText };
}

/** Adapt node:sqlite to the D1-like SqlDatabase interface. */
function openSqliteAdapter(): { db: DatabaseSync; adapter: SqlDatabase; store: SqlStore } {
  const db = new DatabaseSync(":memory:");
  for (const f of readdirSync(migrationsDir).filter((x) => x.endsWith(".sql")).sort()) {
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
          return { results: stmt.all(...bound) as T[] };
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
  return { db, adapter, store: new SqlStore(adapter, "sqlite") };
}

/** Adapter that throws on every prepare (simulates D1 hard failure). */
function throwingAdapter(message = "d1_unavailable"): SqlDatabase {
  return {
    prepare(): SqlStatement {
      throw new Error(message);
    },
    async batch(): Promise<never> {
      throw new Error(message);
    },
  };
}

/**
 * Working adapter that can flip to throw on selected SQL (result CAS path).
 * Seed with the live store first, then enable throws.
 */
function poisonableAdapter(base: SqlDatabase): {
  adapter: SqlDatabase;
  throwOn: (pred: (query: string) => boolean) => void;
  throwAll: () => void;
} {
  let pred: ((query: string) => boolean) | null = null;
  const realPrepare = base.prepare.bind(base);
  const realBatch = base.batch?.bind(base);
  const adapter: SqlDatabase = {
    prepare(query: string): SqlStatement {
      if (pred?.(query)) throw new Error("d1_poison");
      return realPrepare(query);
    },
    exec(query: string) {
      return base.exec?.(query);
    },
    async batch<T>(statements: SqlStatement[]): Promise<T[]> {
      if (pred?.("__batch__")) throw new Error("d1_poison");
      if (!realBatch) throw new Error("batch_unsupported");
      return realBatch(statements);
    },
  };
  return {
    adapter,
    throwOn(next) {
      pred = next;
    },
    throwAll() {
      pred = () => true;
    },
  };
}

async function seedActiveDevice(
  store: SqlStore,
  deviceId: string,
): Promise<{ token: string; device: DeviceRecord }> {
  await store.ensureBootstrap();
  const device: DeviceRecord = {
    id: deviceId,
    tenant_id: DEFAULT_TENANT,
    principal_id: PRINCIPAL_ID,
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
  return { token: issued.token, device };
}

type MockSocket = {
  attachment: SessionAttachment | null;
  closed: { code: number; reason: string } | null;
  sent: string[];
  readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  serializeAttachment(att: unknown): void;
  deserializeAttachment(): SessionAttachment | null;
  accept?(): void;
};

function mockSocket(att: SessionAttachment | null = null): MockSocket {
  const s: MockSocket = {
    attachment: att,
    closed: null,
    sent: [],
    readyState: 1,
    send(data: string) {
      if (s.closed) throw new Error("closed");
      s.sent.push(data);
    },
    close(code = 1000, reason = "") {
      s.closed = { code, reason };
      s.readyState = 3;
    },
    serializeAttachment(attValue: unknown) {
      s.attachment = attValue as SessionAttachment;
    },
    deserializeAttachment() {
      return s.attachment;
    },
    accept() {
      /* no-op */
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
    id: { toString: () => "do_test", equals: () => false, name: undefined } as DurableObjectId,
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

function installWebSocketPairGlobal(): void {
  const g = globalThis as typeof globalThis & {
    WebSocketPair?: new () => { 0: MockSocket; 1: MockSocket };
    WebSocketRequestResponsePair?: new (req: string, res: string) => unknown;
  };
  if (!g.WebSocketPair) {
    g.WebSocketPair = class WebSocketPair {
      0: MockSocket;
      1: MockSocket;
      constructor() {
        this[0] = mockSocket();
        this[1] = mockSocket();
      }
    };
  }
  if (!g.WebSocketRequestResponsePair) {
    g.WebSocketRequestResponsePair = class WebSocketRequestResponsePair {
      constructor(_req: string, _res: string) {
        /* no-op */
      }
    };
  }
}

function attachLiveAgent(
  room: DeviceRoom,
  deviceId: string,
  sessionId: string,
  authHash: string,
): MockSocket {
  const att: SessionAttachment = {
    role: "agent",
    device_id: deviceId,
    session_id: sessionId,
    connected_at: Date.now(),
    phase: "ready",
    auth_hash: authHash,
    lastSeq: 0,
  };
  const sock = mockSocket(att);
  room.wsSessions.set(sock as unknown as WebSocket, sessionId);
  room.router.registerSession(att);
  return sock;
}

function assertFailClosed(
  room: DeviceRoom,
  sock: MockSocket,
  label: string,
): void {
  assert.equal(room.isStorageBroken, true, `${label}: storageBroken`);
  assert.ok(sock.closed, `${label}: existing socket closed`);
  assert.equal(sock.closed!.code, 1013, `${label}: close code 1013`);
  assert.equal(room.wsSessions.size, 0, `${label}: wsSessions cleared`);
}

// ---------------------------------------------------------------------------
// /operation — store throw
// ---------------------------------------------------------------------------

test("D1 throw on /operation: failClosedAll existing WS + 503 storage_unavailable + storageBroken", async () => {
  const deviceId = "dev_d1_op_fail_01ab";
  const { store } = openSqliteAdapter();
  const { token } = await seedActiveDevice(store, deviceId);
  const authHash = await sha256Hex(token);

  const room = new DeviceRoom(mockDOState({ storage: new Map() }), {
    DB: throwingAdapter("d1_op_boom") as unknown as D1Database,
    SESSION_SECRET,
    OAUTH_ISSUER: ISSUER,
  });
  await room.ready;
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;
  const sock = attachLiveAgent(room, deviceId, "ags_d1_op", authHash);
  room.router.pending.set("op_half", {
    correlation_id: "op_half",
    type: "ownmesh_fs_list",
    from_session: "cls_x",
    created_at: Date.now(),
    payload: {},
  });

  const payload = { type: "ownmesh_fs_list", correlation_id: "op_d1_fail", payload: { path: "/" } };
  const { headers, bodyText } = await operationHeaders(deviceId, payload, {
    correlation_id: "op_d1_fail",
  });
  const res = await room.fetch(
    new Request("https://device-room/operation?device_id=" + deviceId, {
      method: "POST",
      headers,
      body: bodyText,
    }),
  );
  assert.equal(res.status, 503);
  assert.equal(((await res.json()) as { error: string }).error, "storage_unavailable");
  assertFailClosed(room, sock, "/operation");
  assert.equal(room.router.pending.size, 0, "pending cleared on fail-closed");
});

// ---------------------------------------------------------------------------
// /ws upgrade — store throw
// ---------------------------------------------------------------------------

test("D1 throw on /ws upgrade: failClosedAll existing WS + 503 storage_unavailable + storageBroken", async () => {
  installWebSocketPairGlobal();
  const deviceId = "dev_d1_ws_fail_01ab";
  const { store } = openSqliteAdapter();
  const { token } = await seedActiveDevice(store, deviceId);
  const authHash = await sha256Hex(token);

  const room = new DeviceRoom(mockDOState({ storage: new Map() }), {
    DB: throwingAdapter("d1_ws_boom") as unknown as D1Database,
    SESSION_SECRET,
    OAUTH_ISSUER: ISSUER,
  });
  await room.ready;
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;
  const sock = attachLiveAgent(room, deviceId, "ags_d1_ws", authHash);

  const headers = await internalDoHeaders(
    SESSION_SECRET,
    {
      op: "ws",
      device_id: deviceId,
      principal_id: PRINCIPAL_ID,
      tenant_id: DEFAULT_TENANT,
      role: "agent",
      method: "GET",
      path: "/ws",
    },
    {
      Upgrade: "websocket",
      origin: ISSUER,
      authorization: `Bearer ${token}`,
      "x-ownmesh-allowed-origin": ISSUER,
    },
  );

  let status: number | null = null;
  let body: { error?: string } = {};
  try {
    const res = await room.fetch(
      new Request(`https://device-room/ws?device_id=${encodeURIComponent(deviceId)}&role=agent`, {
        headers,
      }),
    );
    status = res.status;
    try {
      body = (await res.json()) as { error?: string };
    } catch {
      body = {};
    }
  } catch (err) {
    // Node undici rejects status 101; D1 throw path must not reach 101.
    const msg = err instanceof Error ? err.message : String(err);
    if (/status.*101|range of 200 to 599/i.test(msg)) {
      status = 101;
    } else {
      throw err;
    }
  }
  assert.equal(status, 503, "upgrade must refuse with 503, not accept");
  assert.equal(body.error, "storage_unavailable");
  assertFailClosed(room, sock, "/ws upgrade");
});

// ---------------------------------------------------------------------------
// operation.result recording — store throw
// ---------------------------------------------------------------------------

test("D1 throw on operation.result CAS: failClosedAll + storageBroken, no success forward", async () => {
  const deviceId = "dev_d1_res_fail_01a";
  const base = openSqliteAdapter();
  const { token } = await seedActiveDevice(base.store, deviceId);
  const authHash = await sha256Hex(token);
  const opId = randomId("op_");
  const corr = randomId("cor_");
  await base.store.putMcpOperation({
    operation_id: opId,
    tenant_id: DEFAULT_TENANT,
    principal_id: PRINCIPAL_ID,
    device_id: deviceId,
    tool: "ownmesh_fs_list",
    status: "pending",
    summary: "routed",
    data: {},
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: corr,
    policy_authority: "ownmesh_device",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  const poison = poisonableAdapter(base.adapter);
  // Reads (getDevice / validate / getMcpOperation) succeed; CAS UPDATE throws.
  poison.throwOn((q) => /UPDATE\s+mcp_operations/i.test(q));

  const room = new DeviceRoom(mockDOState({ storage: new Map() }), {
    DB: poison.adapter as unknown as D1Database,
    SESSION_SECRET,
    OAUTH_ISSUER: ISSUER,
  });
  await room.ready;
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;

  const clientId = "cls_d1_res";
  const agentId = "ags_d1_res";
  const clientInbox: string[] = [];
  room.router.sendToSession = (sid, data) => {
    if (sid === clientId) clientInbox.push(data);
    return true;
  };
  room.router.registerSession({
    role: "client",
    device_id: deviceId,
    session_id: clientId,
    connected_at: Date.now(),
    phase: "connected",
    scope: "ownmesh.read",
  });
  const sock = attachLiveAgent(room, deviceId, agentId, authHash);
  room.router.pending.set(corr, {
    correlation_id: corr,
    type: "ownmesh_fs_list",
    from_session: clientId,
    created_at: Date.now(),
    payload: { operation_id: opId },
  });

  await room.webSocketMessage(
    sock as unknown as WebSocket,
    JSON.stringify(
      envFor(
        agentId,
        "operation.result",
        deviceId,
        { status: "completed", operation_id: opId },
        corr,
        { seq: 1, message_id: "m_d1_res" },
      ),
    ),
  );

  assertFailClosed(room, sock, "operation.result");
  assert.ok(
    !clientInbox.some((m) => (JSON.parse(m) as DeviceEnvelope).type === "operation.result"),
    "must not forward success result after D1 CAS throw",
  );
  // Authoritative row stays non-terminal (CAS never applied).
  assert.equal((await base.store.getMcpOperation(opId))?.status, "pending");
});

// ---------------------------------------------------------------------------
// webSocketClose / webSocketError — storage throw must not leak
// ---------------------------------------------------------------------------

test("webSocketClose/webSocketError: persist throw is swallowed and fail-closes", async () => {
  const deviceId = "dev_d1_close_fail01";
  const { adapter, store } = openSqliteAdapter();
  const { token } = await seedActiveDevice(store, deviceId);
  const authHash = await sha256Hex(token);

  const map = new Map<string, unknown>();
  const state = mockDOState({ storage: map });
  let failPut = false;
  const origPut = state.storage.put.bind(state.storage);
  (state.storage as { put: (k: string, v: unknown) => Promise<void> }).put = async (k, v) => {
    if (failPut) throw new Error("quota_exceeded");
    return origPut(k, v);
  };

  const room = new DeviceRoom(state, {
    DB: adapter as unknown as D1Database,
    SESSION_SECRET,
  });
  await room.ready;
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;

  const sockClose = attachLiveAgent(room, deviceId, "ags_close", authHash);
  const sockPeer = attachLiveAgent(room, deviceId, "ags_peer", authHash);
  failPut = true;

  // Must not throw out of the hibernation handler.
  await room.webSocketClose(sockClose as unknown as WebSocket, 1000, "bye");
  assert.equal(room.isStorageBroken, true, "close persist failure marks storageBroken");
  assert.ok(sockPeer.closed, "peer sockets fail-closed on persist failure");
  assert.equal(sockPeer.closed!.code, 1013);

  // Fresh room for error path
  const map2 = new Map<string, unknown>();
  const state2 = mockDOState({ storage: map2 });
  let failPut2 = false;
  const origPut2 = state2.storage.put.bind(state2.storage);
  (state2.storage as { put: (k: string, v: unknown) => Promise<void> }).put = async (k, v) => {
    if (failPut2) throw new Error("quota_exceeded");
    return origPut2(k, v);
  };
  const room2 = new DeviceRoom(state2, {
    DB: adapter as unknown as D1Database,
    SESSION_SECRET,
  });
  await room2.ready;
  room2.deviceId = deviceId;
  room2.router.deviceId = deviceId;
  const sockErr = attachLiveAgent(room2, deviceId, "ags_err", authHash);
  const sockErrPeer = attachLiveAgent(room2, deviceId, "ags_err_peer", authHash);
  failPut2 = true;
  await room2.webSocketError(sockErr as unknown as WebSocket);
  assert.equal(room2.isStorageBroken, true, "error persist failure marks storageBroken");
  assert.ok(sockErrPeer.closed, "peer sockets fail-closed on error-handler persist failure");
  assert.equal(sockErrPeer.closed!.code, 1013);
});

// ---------------------------------------------------------------------------
// webSocketMessage revalidateCredentials throw (getDevice) — no leak
// ---------------------------------------------------------------------------

test("webSocketMessage: store.getDevice throw fail-closes without uncaught rejection", async () => {
  const deviceId = "dev_d1_msg_fail_01a";
  const { store } = openSqliteAdapter();
  const { token } = await seedActiveDevice(store, deviceId);
  const authHash = await sha256Hex(token);

  const room = new DeviceRoom(mockDOState({ storage: new Map() }), {
    DB: throwingAdapter("d1_msg_boom") as unknown as D1Database,
    SESSION_SECRET,
  });
  await room.ready;
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;
  const sock = attachLiveAgent(room, deviceId, "ags_msg", authHash);

  await room.webSocketMessage(
    sock as unknown as WebSocket,
    JSON.stringify(envFor("ags_msg", "ping", deviceId, {}, undefined, { seq: 1, message_id: "p1" })),
  );
  assertFailClosed(room, sock, "webSocketMessage revalidate");
});
