/**
 * Internal WS upgrade context must bind method+path claims.
 *
 * - Worker mints GET + /ws into the signed context
 * - DeviceRoom rejects missing method/path claims
 * - DeviceRoom rejects method/path mismatches (existing conditional check)
 *
 * Uses production DeviceRoom.fetch + signInternalContext / internalDoHeaders.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import worker, { __setTestStore, DeviceRoom } from "./index.ts";
import {
  PROTOCOL,
  type SessionAttachment,
} from "./device-room.ts";
import {
  DEFAULT_TENANT,
  MemoryStore,
  SqlStore,
  type DeviceRecord,
  type SqlDatabase,
  type SqlStatement,
} from "./store.ts";
import {
  internalContextHeaderName,
  internalDoHeaders,
  signInternalContext,
  verifyInternalContext,
  InternalContextReplayGuard,
} from "./util.ts";

const SESSION_SECRET = "test-ws-context-bind-secret";
const ISSUER = "https://cp.test";
const PRINCIPAL_ID = "prin_dev";

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, "..", "migrations");

/** Adapt node:sqlite to the D1-like SqlDatabase interface. */
function openSqliteAdapter(): { adapter: SqlDatabase; store: SqlStore } {
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
  return { adapter, store: new SqlStore(adapter, "sqlite") };
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

async function fetchWsUpgrade(
  room: DeviceRoom,
  deviceId: string,
  headers: Headers,
  opts?: { method?: string; path?: string },
): Promise<{ status: number; body: { error?: string } }> {
  const method = opts?.method ?? "GET";
  const path = opts?.path ?? "/ws";
  let status: number | null = null;
  let body: { error?: string } = {};
  try {
    const res = await room.fetch(
      new Request(
        `https://device-room${path}?device_id=${encodeURIComponent(deviceId)}&role=agent`,
        { method, headers },
      ),
    );
    status = res.status;
    try {
      body = (await res.json()) as { error?: string };
    } catch {
      body = {};
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (/status.*101|range of 200 to 599/i.test(msg)) {
      status = 101;
    } else {
      throw err;
    }
  }
  assert.ok(status !== null, "upgrade must produce a status");
  return { status: status as number, body };
}

async function wsHeaders(
  deviceId: string,
  token: string,
  claims: {
    method?: string;
    path?: string;
    role?: string;
  },
): Promise<Headers> {
  return internalDoHeaders(
    SESSION_SECRET,
    {
      op: "ws",
      device_id: deviceId,
      principal_id: PRINCIPAL_ID,
      tenant_id: DEFAULT_TENANT,
      role: claims.role ?? "agent",
      method: claims.method,
      path: claims.path,
    },
    {
      Upgrade: "websocket",
      origin: ISSUER,
      authorization: `Bearer ${token}`,
      "x-ownmesh-allowed-origin": ISSUER,
    },
  );
}

async function makeRoom(deviceId: string, adapter: SqlDatabase): Promise<DeviceRoom> {
  installWebSocketPairGlobal();
  const room = new DeviceRoom(mockDOState({ storage: new Map() }), {
    DB: adapter as unknown as D1Database,
    SESSION_SECRET,
    OAUTH_ISSUER: ISSUER,
  });
  await room.ready;
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;
  return room;
}

// ---------------------------------------------------------------------------
// DO: claim absence rejected
// ---------------------------------------------------------------------------

test("WS upgrade rejects internal context missing method claim", async () => {
  const deviceId = "dev_ws_bind_nomethod01";
  const { adapter, store } = openSqliteAdapter();
  const { token } = await seedActiveDevice(store, deviceId);
  const room = await makeRoom(deviceId, adapter);

  // Sign without method (path present) — DO must refuse before upgrade.
  const headers = await wsHeaders(deviceId, token, { path: "/ws" });
  const { status, body } = await fetchWsUpgrade(room, deviceId, headers);
  assert.notEqual(status, 101, "must not accept WS without method claim");
  assert.equal(status, 403);
  assert.equal(body.error, "binding_mismatch");
});

test("WS upgrade rejects internal context missing path claim", async () => {
  const deviceId = "dev_ws_bind_nopath_01ab";
  const { adapter, store } = openSqliteAdapter();
  const { token } = await seedActiveDevice(store, deviceId);
  const room = await makeRoom(deviceId, adapter);

  const headers = await wsHeaders(deviceId, token, { method: "GET" });
  const { status, body } = await fetchWsUpgrade(room, deviceId, headers);
  assert.notEqual(status, 101, "must not accept WS without path claim");
  assert.equal(status, 403);
  assert.equal(body.error, "binding_mismatch");
});

test("WS upgrade rejects internal context missing both method and path claims", async () => {
  const deviceId = "dev_ws_bind_nobind_01ab";
  const { adapter, store } = openSqliteAdapter();
  const { token } = await seedActiveDevice(store, deviceId);
  const room = await makeRoom(deviceId, adapter);

  const headers = await wsHeaders(deviceId, token, {});
  const { status, body } = await fetchWsUpgrade(room, deviceId, headers);
  assert.notEqual(status, 101);
  assert.equal(status, 403);
  assert.equal(body.error, "binding_mismatch");
});

// ---------------------------------------------------------------------------
// DO: claim mismatch rejected (existing conditional check)
// ---------------------------------------------------------------------------

test("WS upgrade rejects method claim mismatch", async () => {
  const deviceId = "dev_ws_bind_badmeth01";
  const { adapter, store } = openSqliteAdapter();
  const { token } = await seedActiveDevice(store, deviceId);
  const room = await makeRoom(deviceId, adapter);

  // Claim says POST but Request is GET (default WS upgrade).
  const headers = await wsHeaders(deviceId, token, { method: "POST", path: "/ws" });
  const { status, body } = await fetchWsUpgrade(room, deviceId, headers);
  assert.notEqual(status, 101);
  assert.equal(status, 403);
  assert.equal(body.error, "binding_mismatch");
});

test("WS upgrade rejects path claim mismatch", async () => {
  const deviceId = "dev_ws_bind_badpath01";
  const { adapter, store } = openSqliteAdapter();
  const { token } = await seedActiveDevice(store, deviceId);
  const room = await makeRoom(deviceId, adapter);

  const headers = await wsHeaders(deviceId, token, { method: "GET", path: "/operation" });
  const { status, body } = await fetchWsUpgrade(room, deviceId, headers);
  assert.notEqual(status, 101);
  assert.equal(status, 403);
  assert.equal(body.error, "binding_mismatch");
});

// ---------------------------------------------------------------------------
// Positive: bound context accepted past binding gate
// ---------------------------------------------------------------------------

test("WS upgrade accepts matching GET+/ws claims (binding gate)", async () => {
  const deviceId = "dev_ws_bind_ok_01abcd";
  const { adapter, store } = openSqliteAdapter();
  const { token } = await seedActiveDevice(store, deviceId);
  const room = await makeRoom(deviceId, adapter);

  const headers = await wsHeaders(deviceId, token, { method: "GET", path: "/ws" });
  const { status, body } = await fetchWsUpgrade(room, deviceId, headers);
  // 101 = accepted; anything else must not be binding_mismatch.
  if (status !== 101) {
    assert.notEqual(body.error, "binding_mismatch", `unexpected bind failure: ${body.error}`);
  }
  // With valid device + credential + origin + DB, upgrade should complete.
  assert.equal(status, 101, "matching method/path claims must pass binding gate");
});

// ---------------------------------------------------------------------------
// Worker mint: method+path signed into internal WS context
// ---------------------------------------------------------------------------

test("Worker WS mint signs method=GET and path=/ws into internal context", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const deviceId = "dev_ws_mint_bind_01ab";
  const device = {
    id: deviceId,
    tenant_id: DEFAULT_TENANT,
    principal_id: PRINCIPAL_ID,
    name: "agent",
    hostname: "agent",
    os: "x",
    arch: "x",
    agent_version: "x",
    protocol_version: PROTOCOL,
    public_key: "ab".repeat(32),
    revoked: false,
    created_at: new Date().toISOString(),
    status: "active" as const,
  };
  await store.putDevice(device);
  const credential = await store.issueDeviceCredential(device);
  __setTestStore(store);

  let capturedToken: string | null = null;
  let capturedMethod = "";
  let capturedPath = "";
  const roomNs = {
    idFromName: () => ({}) as DurableObjectId,
    get: () =>
      ({
        fetch: async (req: Request) => {
          capturedMethod = req.method;
          capturedPath = new URL(req.url).pathname;
          capturedToken = req.headers.get(internalContextHeaderName());
          return new Response(null, { status: 204 });
        },
      }) as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;

  const res = await worker.fetch(
    new Request(`https://cp.test/v1/devices/${deviceId}/ws?role=agent`, {
      // method omitted → Request defaults to GET (same as real WS clients)
      headers: {
        upgrade: "websocket",
        origin: ISSUER,
        authorization: `Bearer ${credential.token}`,
      },
    }),
    {
      DEVICE_ROOM: roomNs,
      SESSION_SECRET,
      OAUTH_ISSUER: ISSUER,
    },
    {} as ExecutionContext,
  );
  assert.equal(res.status, 204);
  assert.equal(capturedMethod, "GET");
  assert.equal(capturedPath, "/ws");
  assert.ok(capturedToken, "signed internal context must be attached");

  const verified = await verifyInternalContext(SESSION_SECRET, capturedToken, {
    op: "ws",
    device_id: deviceId,
    principal_id: PRINCIPAL_ID,
    tenant_id: DEFAULT_TENANT,
    role: "agent",
    method: "GET",
    path: "/ws",
    replayGuard: new InternalContextReplayGuard(),
  });
  assert.equal(verified.ok, true, "Worker mint must include verifiable method+path claims");
  if (verified.ok) {
    assert.equal(verified.claims.method, "GET");
    assert.equal(verified.claims.path, "/ws");
  }

  __setTestStore(null);
});

test("signInternalContext retains method/path claims for ws op", async () => {
  const token = await signInternalContext(SESSION_SECRET, {
    op: "ws",
    device_id: "dev_ws_sign_claim_01",
    principal_id: PRINCIPAL_ID,
    tenant_id: DEFAULT_TENANT,
    role: "agent",
    method: "GET",
    path: "/ws",
  });
  const verified = await verifyInternalContext(SESSION_SECRET, token, {
    op: "ws",
    device_id: "dev_ws_sign_claim_01",
    method: "GET",
    path: "/ws",
    replayGuard: new InternalContextReplayGuard(),
  });
  assert.equal(verified.ok, true);
  if (verified.ok) {
    assert.equal(verified.claims.method, "GET");
    assert.equal(verified.claims.path, "/ws");
  }
});
