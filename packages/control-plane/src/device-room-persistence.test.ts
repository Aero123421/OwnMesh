/**
 * DeviceRoom hibernation persistence, pending/seen TTL+limit prune,
 * DB-missing fail-closed, and per-op credential revalidation.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import {
  applyMcpOperationResult,
  assertRoomStateBounds,
  DeviceRoom,
  DeviceRoomHarness,
  DeviceRoomRouter,
  MAX_GUARD_SESSIONS,
  MAX_PENDING_OPERATIONS,
  MAX_PENDING_PAYLOAD_BYTES,
  MAX_SEEN_MESSAGE_IDS,
  MAX_SERIALIZED_STATE_BYTES,
  LIVE_TRANSFER_TOMBSTONE_MAX_TTL_MS,
  PENDING_TTL_MS,
  PROTOCOL,
  ROOM_STATE_STORAGE_KEY,
  SEEN_MESSAGE_ID_TTL_MS,
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
import { internalDoHeaders, randomId, sha256Hex } from "./util.ts";

/** Mint internal DO /operation headers with method/path/body bind. */
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
    principal_id: extra?.principal_id || "prin_dev",
    tenant_id: extra?.tenant_id || DEFAULT_TENANT,
    correlation_id: extra?.correlation_id,
    method: "POST",
    path: "/operation",
    body_sha256,
  });
  return { headers, bodyText };
}

/** Mint the stricter one-shot internal context used for ticket-bearing starts. */
async function liveOperationHeaders(
  deviceId: string,
  body: unknown,
  correlationId: string,
): Promise<{ headers: Headers; bodyText: string }> {
  const bodyText = JSON.stringify(body);
  const body_sha256 = await sha256Hex(bodyText);
  const headers = await internalDoHeaders(SESSION_SECRET, {
    op: "live_operation",
    device_id: deviceId,
    principal_id: "prin_dev",
    tenant_id: DEFAULT_TENANT,
    correlation_id: correlationId,
    method: "POST",
    path: "/live-operation",
    body_sha256,
  });
  return { headers, bodyText };
}

const SESSION_SECRET = "test-device-room-session-secret";

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
  opts?: { seq?: number; message_id?: string; expires_at?: string },
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
  if (opts?.expires_at) e.expires_at = opts.expires_at;
  return e;
}

/** Adapt node:sqlite to the D1-like SqlDatabase interface (same as persistence tests). */
function openSqliteAdapter(): { db: DatabaseSync; adapter: SqlDatabase; store: SqlStore } {
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
  return { db, adapter, store: new SqlStore(adapter, "sqlite") };
}

async function seedActiveDevice(
  store: SqlStore,
  deviceId: string,
): Promise<{ token: string; device: DeviceRecord }> {
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
  return { token: issued.token, device };
}

// ---------------------------------------------------------------------------
// Router export/import (hibernation restore without workerd)
// ---------------------------------------------------------------------------

test("exportState/importState restores lastSeq, seenMessageIds, pending across hibernation", async () => {
  const deviceId = "dev_persist_room_01ab";
  const room = new DeviceRoomHarness(deviceId, () => true);
  const agent = room.connect("agent");
  const client = room.connect("client");
  room.router.sessions.get(agent)!.phase = "ready";
  room.router.sessions.get(agent)!.remote_routing_enabled = true;

  await room.send(agent, envFor(agent, "ping", deviceId, {}, undefined, { seq: 3, message_id: "mid_a" }));
  await room.send(agent, envFor(agent, "ping", deviceId, {}, undefined, { seq: 7, message_id: "mid_b" }));

  const corr = randomId("op_");
  await room.send(
    client,
    envFor(client, "operation.request", deviceId, { op: "ownmesh_fs_list", path: "/" }, corr),
  );
  assert.equal(room.router.pending.has(corr), true);
  assert.equal(room.router.ingressGuards.get(agent)!.lastSeq, 7);
  assert.equal(room.router.ingressGuards.get(agent)!.seenMessageIds.has("mid_a"), true);
  assert.equal(room.router.ingressGuards.get(agent)!.seenMessageIds.has("mid_b"), true);

  const snap = room.router.exportState();
  assert.equal(snap.v, 1);
  assert.ok(snap.pending.some((p) => p.correlation_id === corr));
  assert.equal(snap.ingressGuards[agent]?.lastSeq, 7);

  const woken = new DeviceRoomHarness(deviceId, () => true);
  woken.router.importState(snap);
  woken.router.registerSession({
    role: "agent",
    device_id: deviceId,
    session_id: agent,
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
  });
  woken.router.registerSession({
    role: "client",
    device_id: deviceId,
    session_id: client,
    connected_at: Date.now(),
    phase: "connected",
    scope: "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session",
  });

  assert.equal(woken.router.ingressGuards.get(agent)!.lastSeq, 7);
  assert.equal(woken.router.ingressGuards.get(agent)!.seenMessageIds.has("mid_a"), true);
  assert.equal(woken.router.pending.has(corr), true);

  const dup = await woken.send(
    agent,
    envFor(agent, "ping", deviceId, {}, undefined, { seq: 8, message_id: "mid_a" }),
  );
  assert.equal(dup.error, "duplicate_message_id");
  const badSeq = await woken.send(
    agent,
    envFor(agent, "ping", deviceId, {}, undefined, { seq: 7, message_id: "mid_c" }),
  );
  assert.equal(badSeq.error, "bad_seq");
  const ok = await woken.send(
    agent,
    envFor(agent, "ping", deviceId, {}, undefined, { seq: 8, message_id: "mid_c" }),
  );
  assert.equal(ok.ok, true);

  // Explicit seq > restored lastSeq (global sessionSeq may be stale across harnesses).
  const delivered = await woken.send(
    agent,
    envFor(agent, "operation.result", deviceId, { status: "completed" }, corr, {
      seq: 9,
      message_id: "mid_result",
    }),
  );
  assert.equal(delivered.ok, true, delivered.error);
  const clientInbox = woken.drain(client).map((s) => JSON.parse(s) as DeviceEnvelope);
  assert.ok(clientInbox.some((m) => m.type === "operation.result" && m.correlation_id === corr));
  assert.equal(woken.router.pending.has(corr), false);
});

test("seenMessageIds TTL and hard cap are force-pruned", () => {
  const router = new DeviceRoomRouter("dev_seen_prune_01", {
    sendToSession: () => true,
    sendToRole: () => 0,
  });
  router.registerSession({
    role: "agent",
    device_id: "dev_seen_prune_01",
    session_id: "ags_1",
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
  });
  const guard = router.ingressGuards.get("ags_1")!;
  const now = Date.now();

  guard.seenMessageIds.set("old_1", now - SEEN_MESSAGE_ID_TTL_MS - 1);
  guard.seenMessageIds.set("old_2", now - SEEN_MESSAGE_ID_TTL_MS - 5000);
  guard.seenMessageIds.set("fresh", now);

  for (let i = 0; i < MAX_SEEN_MESSAGE_IDS + 50; i++) {
    guard.seenMessageIds.set(`cap_${i}`, now - (MAX_SEEN_MESSAGE_IDS + 50 - i));
  }

  const removed = router.pruneAll(now);
  assert.ok(removed.seen > 0);
  assert.ok(!guard.seenMessageIds.has("old_1"));
  assert.ok(!guard.seenMessageIds.has("old_2"));
  assert.ok(guard.seenMessageIds.size <= MAX_SEEN_MESSAGE_IDS);
  assert.ok(
    guard.seenMessageIds.has(`cap_${MAX_SEEN_MESSAGE_IDS + 49}`) || guard.seenMessageIds.has("fresh"),
  );
});

test("pending TTL and hard cap are force-pruned", () => {
  const router = new DeviceRoomRouter("dev_pend_prune_01", {
    sendToSession: () => true,
    sendToRole: () => 0,
  });
  const now = Date.now();
  router.pending.set("expired_op", {
    correlation_id: "expired_op",
    type: "ownmesh_fs_list",
    from_session: "cls_1",
    created_at: now - PENDING_TTL_MS - 1,
    payload: {},
  });
  router.pending.set("live_op", {
    correlation_id: "live_op",
    type: "ownmesh_fs_list",
    from_session: "cls_1",
    created_at: now,
    payload: {},
  });
  for (let i = 0; i < MAX_PENDING_OPERATIONS + 10; i++) {
    router.pending.set(`flood_${i}`, {
      correlation_id: `flood_${i}`,
      type: "ownmesh_fs_list",
      from_session: "cls_1",
      created_at: now - i,
      payload: {},
    });
  }

  const removed = router.pruneExpiredPending(now);
  assert.ok(removed.length > 0);
  assert.equal(router.pending.has("expired_op"), false);
  assert.ok(router.pending.size <= MAX_PENDING_OPERATIONS);
  assert.ok(router.pending.size > 0);
});

test("operation.request rejects when pending hard cap reached", async () => {
  const deviceId = "dev_pend_limit_01ab";
  const room = new DeviceRoomHarness(deviceId);
  const agent = room.connect("agent");
  const client = room.connect("client");
  room.router.sessions.get(agent)!.phase = "ready";
  room.router.sessions.get(agent)!.remote_routing_enabled = true;
  const now = Date.now();
  for (let i = 0; i < MAX_PENDING_OPERATIONS; i++) {
    room.router.pending.set(`fill_${i}`, {
      correlation_id: `fill_${i}`,
      type: "ownmesh_fs_list",
      from_session: client,
      created_at: now,
      payload: {},
    });
  }
  const denied = await room.send(
    client,
    envFor(client, "operation.request", deviceId, { op: "ownmesh_fs_list", path: "/" }, randomId("op_")),
  );
  assert.equal(denied.ok, false);
  assert.equal(denied.error, "pending_limit");
});

// ---------------------------------------------------------------------------
// DeviceRoom DO storage mock
// ---------------------------------------------------------------------------

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

test("DeviceRoom persists lastSeq/seen/pending to storage and restores on new instance", async () => {
  const deviceId = "dev_do_persist_01abc";
  const { adapter } = openSqliteAdapter();
  const storage = new Map<string, unknown>();
  const env = { DB: adapter as unknown as D1Database };

  const room1 = new DeviceRoom(mockDOState({ storage }), env);
  await room1.ready;
  room1.deviceId = deviceId;
  room1.router.deviceId = deviceId;

  room1.router.registerSession({
    role: "agent",
    device_id: deviceId,
    session_id: "ags_p1",
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
  });
  room1.router.registerSession({
    role: "client",
    device_id: deviceId,
    session_id: "cls_p1",
    connected_at: Date.now(),
    phase: "connected",
    scope: "ownmesh.read",
  });

  // Drive guard + pending mutations through the router.
  // injectOperation drops pending when no live agent socket can receive — seed pending
  // directly so the storage round-trip is independent of WS wiring.
  const agent = "ags_p1";
  await room1.router.handleMessage(
    agent,
    JSON.stringify(envFor(agent, "ping", deviceId, {}, undefined, { seq: 4, message_id: "persist_mid" })),
  );
  room1.router.pending.set("op_persist_1", {
    correlation_id: "op_persist_1",
    type: "ownmesh_fs_list",
    from_session: "cls_p1",
    created_at: Date.now(),
    payload: { path: "/" },
  });
  await room1.flushPersist();

  const stored = storage.get(ROOM_STATE_STORAGE_KEY) as PersistedRoomState;
  assert.ok(stored);
  assert.equal(stored.v, 1);
  assert.equal(stored.ingressGuards["ags_p1"]?.lastSeq, 4);
  assert.ok(stored.ingressGuards["ags_p1"]?.seenMessageIds.some((e) => e.id === "persist_mid"));
  assert.ok(stored.pending.some((p) => p.correlation_id === "op_persist_1"));

  // Hibernate wake: fresh DO instance, same storage blob
  const room2 = new DeviceRoom(mockDOState({ storage }), env);
  await room2.ready;
  assert.equal(room2.router.ingressGuards.get("ags_p1")?.lastSeq, 4);
  assert.equal(room2.router.ingressGuards.get("ags_p1")?.seenMessageIds.has("persist_mid"), true);
  assert.equal(room2.router.pending.has("op_persist_1"), true);
});

test("authenticated ready refreshes bounded metadata without heartbeat writes", async () => {
  const deviceId = "dev_ready_metadata_01";
  const { adapter, store } = openSqliteAdapter();
  const { token } = await seedActiveDevice(store, deviceId);
  const authHash = await sha256Hex(token);
  const sessionId = "ags_ready_metadata";
  const socket = mockSocket({
    role: "agent",
    device_id: deviceId,
    session_id: sessionId,
    connected_at: Date.now(),
    // This phase is only reachable after proof; the real transport performs
    // the signature exchange before it can send ready.
    phase: "proven",
    auth_hash: authHash,
    lastSeq: 0,
  });
  const room = new DeviceRoom(mockDOState({ sockets: [socket] }), {
    DB: adapter as unknown as D1Database,
  });
  await room.ready;

  await room.webSocketMessage(
    socket as unknown as WebSocket,
    JSON.stringify(envFor(sessionId, "ready", deviceId, {
      agent_version: "2.3.4",
      protocol_version: "payload-is-not-authoritative",
      remote_routing_enabled: false,
    })),
  );
  const refreshed = await store.getDevice(deviceId);
  assert.equal(refreshed?.agent_version, "2.3.4");
  assert.equal(refreshed?.protocol_version, PROTOCOL);
  assert.ok(refreshed?.last_seen_at);
  const lastSeen = refreshed!.last_seen_at;

  await room.webSocketMessage(
    socket as unknown as WebSocket,
    JSON.stringify(envFor(sessionId, "ping", deviceId, {}, undefined, { seq: 2 })),
  );
  assert.equal((await store.getDevice(deviceId))?.last_seen_at, lastSeen);

  const throttled = await store.recordDeviceReadyConnection(deviceId, {
    agent_version: "2.3.4",
    protocol_version: PROTOCOL,
    last_seen_at: new Date(Date.parse(lastSeen!) + 1).toISOString(),
  });
  assert.equal(throttled?.last_seen_at, lastSeen, "rapid unchanged reconnects do not rewrite last_seen");

  const stale = await store.recordDeviceReadyConnection(deviceId, {
    agent_version: "1.0.0-stale",
    protocol_version: "ownmesh.device/stale",
    last_seen_at: new Date(Date.parse(lastSeen!) - 1).toISOString(),
  });
  assert.equal(stale?.agent_version, "2.3.4", "an older ready observation cannot replace newer metadata");
  assert.equal(stale?.protocol_version, PROTOCOL);
});

test("hibernated expired pending operation converges in D1 on DeviceRoom restart", async () => {
  const originalNow = Date.now;
  let now = 1_800_000_000_000;
  (Date as unknown as { now: () => number }).now = () => now;
  try {
    const { adapter, store } = openSqliteAdapter();
    const deviceId = "dev_expiry_reconcile_01";
    await seedActiveDevice(store, deviceId);
    const operationId = "op_expiry_reconcile_01";
    const expiresAt = new Date(now + 60_000).toISOString();
    await store.putMcpOperation({
      operation_id: operationId,
      tenant_id: DEFAULT_TENANT,
      principal_id: "prin_dev",
      device_id: deviceId,
      tool: "ownmesh_fs_write",
      status: "pending",
      summary: "routed",
      data: {},
      truncated: false,
      next_cursor: null,
      approval_required: false,
      warnings: [],
      correlation_id: operationId,
      expires_at: expiresAt,
      policy_authority: "ownmesh_device",
      created_at: new Date(now).toISOString(),
      updated_at: new Date(now).toISOString(),
    });

    const storage = new Map<string, unknown>();
    storage.set(ROOM_STATE_STORAGE_KEY, {
      v: 1,
      device_id: deviceId,
      seqOut: 0,
      ingressGuards: {},
      pending: [{
        correlation_id: operationId,
        type: "ownmesh_fs_write",
        from_session: "http_client",
        created_at: now,
        expires_at: expiresAt,
        payload: { operation_id: operationId, path: "must-not-be-persisted.txt" },
      }],
    } satisfies PersistedRoomState,
    );

    // Wake a new instance two hours later, as happens after idle hibernation.
    now += 2 * 60 * 60 * 1000;
    assert.equal(Date.now(), now);
    const beforeRestart = await store.getMcpOperation(operationId);
    assert.equal(beforeRestart?.correlation_id, operationId);
    assert.equal(beforeRestart?.device_id, deviceId);
    const room = new DeviceRoom(mockDOState({ storage }), {
      DB: adapter as unknown as D1Database,
      SESSION_SECRET,
    });
    await room.ready;

    // This is intentionally the expected end state. Before the fix there is no
    // alarm/restart reconciliation, so this assertion fails with `pending`.
    assert.equal(room.isStorageBroken, false);
    assert.equal(room.deviceId, deviceId);
    assert.equal(room.router.pending.has(operationId), false);
    const expiredRecord = await store.getMcpOperation(operationId);
    assert.equal(expiredRecord?.status, "failed");
    assert.deepEqual(expiredRecord?.data, {
      phase: "expired",
      expires_at: expiresAt,
      error: {
        code: "OWNMESH_E_OPERATION_EXPIRED",
        message: "operation expired before a device result arrived",
        retryable: true,
      },
    }, "expiry receipt remains bounded and contains no pending payload");
  } finally {
    (Date as unknown as { now: () => number }).now = originalNow;
  }
});

test("DeviceRoom alarm uses the same expiry reconciliation after an idle deadline", async () => {
  const originalNow = Date.now;
  let now = 1_800_050_000_000;
  (Date as unknown as { now: () => number }).now = () => now;
  try {
    const { adapter, store } = openSqliteAdapter();
    const deviceId = "dev_expiry_alarm_01";
    const operationId = "op_expiry_alarm_01";
    const expiresAt = new Date(now + 60_000).toISOString();
    await seedActiveDevice(store, deviceId);
    await store.putMcpOperation({
      operation_id: operationId, tenant_id: DEFAULT_TENANT, principal_id: "prin_dev", device_id: deviceId,
      tool: "ownmesh_command_shell", status: "pending", summary: "routed", data: {}, truncated: false,
      next_cursor: null, approval_required: false, warnings: [], correlation_id: operationId, expires_at: expiresAt,
      policy_authority: "ownmesh_device", created_at: new Date(now).toISOString(), updated_at: new Date(now).toISOString(),
    });
    const storage = new Map<string, unknown>();
    storage.set(ROOM_STATE_STORAGE_KEY, {
      v: 1, device_id: deviceId, seqOut: 0, ingressGuards: {},
      pending: [{ correlation_id: operationId, type: "ownmesh_command_shell", from_session: "http_client", created_at: now, expires_at: expiresAt, payload: { operation_id: operationId, command: "secret command" } }],
    } satisfies PersistedRoomState);
    const room = new DeviceRoom(mockDOState({ storage }), { DB: adapter as unknown as D1Database, SESSION_SECRET });
    await room.ready;
    now += 2 * 60 * 60 * 1000;
    await room.alarm();
    assert.equal((await store.getMcpOperation(operationId))?.status, "failed");
    assert.equal(room.router.pending.has(operationId), false);
  } finally {
    (Date as unknown as { now: () => number }).now = originalNow;
  }
});

test("expired room snapshot cannot overwrite a concurrently terminal D1 operation", async () => {
  const originalNow = Date.now;
  let now = 1_800_100_000_000;
  (Date as unknown as { now: () => number }).now = () => now;
  try {
    const { adapter, store } = openSqliteAdapter();
    const deviceId = "dev_expiry_terminal_cas";
    await seedActiveDevice(store, deviceId);
    const operationId = "op_expiry_terminal_cas";
    const expiresAt = new Date(now + 60_000).toISOString();
    await store.putMcpOperation({
      operation_id: operationId, tenant_id: DEFAULT_TENANT, principal_id: "prin_dev", device_id: deviceId,
      tool: "ownmesh_session_list", status: "completed", summary: "completed first", data: { entries: [] },
      truncated: false, next_cursor: null, approval_required: false, warnings: [], correlation_id: operationId,
      expires_at: expiresAt, policy_authority: "ownmesh_device", created_at: new Date(now).toISOString(), updated_at: new Date(now).toISOString(),
    });
    const storage = new Map<string, unknown>();
    storage.set(ROOM_STATE_STORAGE_KEY, {
      v: 1, device_id: deviceId, seqOut: 0, ingressGuards: {},
      pending: [{ correlation_id: operationId, type: "ownmesh_session_list", from_session: "http_client", created_at: now, expires_at: expiresAt, payload: { operation_id: operationId } }],
    } satisfies PersistedRoomState);

    now += 2 * 60 * 60 * 1000;
    const room = new DeviceRoom(mockDOState({ storage }), { DB: adapter as unknown as D1Database, SESSION_SECRET });
    await room.ready;
    const record = await store.getMcpOperation(operationId);
    assert.equal(record?.status, "completed");
    assert.deepEqual(record?.data, { entries: [] });
    assert.equal(room.router.pending.has(operationId), false);
  } finally {
    (Date as unknown as { now: () => number }).now = originalNow;
  }
});

test("env.DB missing fails closed: /operation 503 and existing WS closed", async () => {
  const deviceId = "dev_no_db_fail_01ab";
  const att: SessionAttachment = {
    role: "agent",
    device_id: deviceId,
    session_id: "ags_nodb",
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
    auth_hash: "deadbeef",
    lastSeq: 1,
  };
  const sock = mockSocket(att);
  const room = new DeviceRoom(mockDOState({ sockets: [sock] }), {
    SESSION_SECRET,
    /* no DB */
  });
  await room.ready;
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;
  // Constructor restored hibernated socket into maps
  assert.ok(room.wsSessions.size >= 1 || room.router.sessions.has("ags_nodb"));
  // Ensure maps are populated even if getWebSockets path differed
  room.wsSessions.set(sock as unknown as WebSocket, "ags_nodb");
  room.router.registerSession(att);
  room.router.pending.set("op_half", {
    correlation_id: "op_half",
    type: "ownmesh_fs_list",
    from_session: "cls_x",
    created_at: Date.now(),
    payload: {},
  });

  const opBodyPayload = { type: "ownmesh_fs_list", correlation_id: "op_new" };
  const { headers: opHeaders, bodyText: opBodyText } = await operationHeaders(deviceId, opBodyPayload, {
    correlation_id: "op_new",
  });
  const opRes = await room.fetch(
    new Request("https://device-room/operation?device_id=" + deviceId, {
      method: "POST",
      headers: opHeaders,
      body: opBodyText,
    }),
  );
  assert.equal(opRes.status, 503);
  const opBody = (await opRes.json()) as { error: string };
  assert.equal(opBody.error, "storage_unavailable");
  // Existing WS must be closed — no half-success
  assert.ok(sock.closed);
  assert.equal(room.wsSessions.size, 0);
  assert.equal(room.router.sessions.size, 0);
  assert.equal(room.router.pending.size, 0);

  // webSocketMessage also fail-closed
  const sock2 = mockSocket({ ...att, session_id: "ags_nodb2" });
  room.wsSessions.set(sock2 as unknown as WebSocket, "ags_nodb2");
  room.router.registerSession({ ...att, session_id: "ags_nodb2" });
  await room.webSocketMessage(
    sock2 as unknown as WebSocket,
    JSON.stringify(envFor("ags_nodb2", "ping", deviceId, {}, undefined, { seq: 2 })),
  );
  assert.ok(sock2.closed);
  assert.equal(room.router.sessions.has("ags_nodb2"), false);
});

test("revoked / expired device credential is rejected on important ops", async () => {
  const deviceId = "dev_cred_reval_01abc";
  const { adapter, store, db } = openSqliteAdapter();
  const { token } = await seedActiveDevice(store, deviceId);
  const authHash = await sha256Hex(token);

  const att: SessionAttachment = {
    role: "agent",
    device_id: deviceId,
    session_id: "ags_cred",
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
    auth_hash: authHash,
    lastSeq: 0,
  };
  const sock = mockSocket(att);
  const storage = new Map<string, unknown>();
  const room = new DeviceRoom(mockDOState({ sockets: [sock], storage }), {
    DB: adapter as unknown as D1Database,
  });
  await room.ready;
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;
  room.wsSessions.set(sock as unknown as WebSocket, "ags_cred");
  room.router.registerSession(att);

  // Sanity: valid credential accepts ping
  await room.webSocketMessage(
    sock as unknown as WebSocket,
    JSON.stringify(envFor("ags_cred", "ping", deviceId, {}, undefined, { seq: 1, message_id: "ok1" })),
  );
  assert.equal(sock.closed, null);
  assert.ok(room.router.sessions.has("ags_cred"));

  // Revoke credential in store (authoritative)
  db.prepare(`UPDATE device_credentials SET revoked = 1 WHERE credential_hash = ?`).run(authHash);

  await room.webSocketMessage(
    sock as unknown as WebSocket,
    JSON.stringify(
      envFor(
        "ags_cred",
        "operation.result",
        deviceId,
        { status: "completed" },
        "missing_corr",
        { seq: 2, message_id: "opres1" },
      ),
    ),
  );
  assert.ok(sock.closed, "socket must close on revoked credential");
  assert.equal(room.router.sessions.has("ags_cred"), false);

  // Expired credential path
  const { token: token2 } = await seedActiveDevice(store, deviceId + "_b");
  const hash2 = await sha256Hex(token2);
  const deviceB = deviceId + "_b";
  const att2: SessionAttachment = {
    role: "agent",
    device_id: deviceB,
    session_id: "ags_exp",
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
    auth_hash: hash2,
    lastSeq: 0,
  };
  const sock2 = mockSocket(att2);
  const room2 = new DeviceRoom(mockDOState({ sockets: [sock2] }), {
    DB: adapter as unknown as D1Database,
    SESSION_SECRET,
  });
  await room2.ready;
  room2.deviceId = deviceB;
  room2.router.deviceId = deviceB;
  room2.wsSessions.set(sock2 as unknown as WebSocket, "ags_exp");
  room2.router.registerSession(att2);

  db.prepare(
    `UPDATE device_credentials SET expires_at = ? WHERE credential_hash = ?`,
  ).run(new Date(Date.now() - 60_000).toISOString(), hash2);

  const expPayload = {
    type: "ownmesh_fs_list",
    correlation_id: "op_exp",
    payload: {
      operation_id: "op_exp",
      capability: "fs.list",
      authorization: {
        bound_action: {
          principal_id: "prin_dev",
          tenant_id: DEFAULT_TENANT,
          principal_credential_generation: 1,
        },
      },
    },
  };
  const { headers: expHeaders, bodyText: expBody } = await operationHeaders(deviceB, expPayload, {
    correlation_id: "op_exp",
  });
  const opRes = await room2.fetch(
    new Request("https://device-room/operation?device_id=" + deviceB, {
      method: "POST",
      headers: expHeaders,
      body: expBody,
    }),
  );
  // Device itself still active → operation may proceed at device level, but agent session must be torn down
  assert.ok(sock2.closed, "expired agent session closed during revalidation");
  // inject may return device_offline once agent session dropped
  assert.ok([200, 503].includes(opRes.status));
  if (opRes.status === 200) {
    const body = (await opRes.json()) as { status: string };
    // Without ready agent after close → offline
    assert.ok(body.status === "device_offline" || body.status === "routed_to_device");
  }
});

test("attachment lastSeq mirrors guard and survives register after import", () => {
  const router = new DeviceRoomRouter("dev_att_seq_01", {
    sendToSession: () => true,
    sendToRole: () => 0,
  });
  const snap: PersistedRoomState = {
    v: 1,
    seqOut: 2,
    ingressGuards: {
      ags_x: { lastSeq: 9, seenMessageIds: [{ id: "m1", at: Date.now() }] },
    },
    pending: [],
  };
  router.importState(snap);
  router.registerSession({
    role: "agent",
    device_id: "dev_att_seq_01",
    session_id: "ags_x",
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
    lastSeq: 5, // attachment stale — must not rewind storage
  });
  assert.equal(router.ingressGuards.get("ags_x")!.lastSeq, 9);
});

// ---------------------------------------------------------------------------
// Storage fail-closed + bounds + operation.result CAS-before-forward
// ---------------------------------------------------------------------------

test("storage restore error fails closed: refuse /operation and close sockets", async () => {
  const deviceId = "dev_restore_fail_01ab";
  const att: SessionAttachment = {
    role: "agent",
    device_id: deviceId,
    session_id: "ags_rf",
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
    auth_hash: "ab".repeat(32),
    lastSeq: 1,
  };
  const sock = mockSocket(att);
  const map = new Map<string, unknown>();
  const state = mockDOState({ sockets: [sock], storage: map });
  // Break storage.get after construction wiring — inject throwing storage.
  (state as { storage: { get: unknown } }).storage.get = async () => {
    throw new Error("disk_io");
  };
  const room = new DeviceRoom(state, { SESSION_SECRET });
  await room.ready;
  assert.equal(room.isStorageBroken, true);
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;
  room.wsSessions.set(sock as unknown as WebSocket, "ags_rf");
  room.router.registerSession(att);

  const payload = { type: "ownmesh_fs_list", correlation_id: "op_rf" };
  const { headers, bodyText } = await operationHeaders(deviceId, payload, { correlation_id: "op_rf" });
  const res = await room.fetch(
    new Request("https://device-room/operation?device_id=" + deviceId, {
      method: "POST",
      headers,
      body: bodyText,
    }),
  );
  assert.equal(res.status, 503);
  assert.equal(((await res.json()) as { error: string }).error, "storage_unavailable");
  assert.ok(sock.closed, "existing sockets closed on fail-closed");
});

test("persist failure fails closed: no success response after storage put error", async () => {
  const deviceId = "dev_persist_fail_01a";
  const { adapter, store } = openSqliteAdapter();
  await seedActiveDevice(store, deviceId);
  const map = new Map<string, unknown>();
  let failPut = false;
  const state = mockDOState({ storage: map });
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

  // Seed a ready agent so inject is not offline.
  room.router.registerSession({
    role: "agent",
    device_id: deviceId,
    session_id: "ags_pf",
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
  });
  // Force send success without real WS.
  room.router.sendToSession = () => true;

  failPut = true;
  const payload = {
    type: "ownmesh_fs_list",
    correlation_id: "op_pf",
    payload: {
      operation_id: "op_pf",
      capability: "fs.list",
      authorization: {
        bound_action: {
          principal_id: "prin_dev",
          tenant_id: DEFAULT_TENANT,
          principal_credential_generation: 1,
        },
      },
      arguments: { path: "/" },
    },
  };
  const { headers, bodyText } = await operationHeaders(deviceId, payload, { correlation_id: "op_pf" });
  const res = await room.fetch(
    new Request("https://device-room/operation?device_id=" + deviceId, {
      method: "POST",
      headers,
      body: bodyText,
    }),
  );
  assert.equal(res.status, 503);
  assert.equal(((await res.json()) as { error: string }).error, "storage_unavailable");
  assert.equal(room.isStorageBroken, true);
});

test("assertRoomStateBounds enforces serialized bytes, guard sessions, pending payload bytes", () => {
  assert.throws(
    () =>
      assertRoomStateBounds({
        v: 1,
        seqOut: 0,
        ingressGuards: Object.fromEntries(
          Array.from({ length: MAX_GUARD_SESSIONS + 1 }, (_, i) => [
            `s${i}`,
            { lastSeq: 0, seenMessageIds: [] },
          ]),
        ),
        pending: [],
      }),
    /guard_session_limit/,
  );

  // Payload-only over budget with compact envelope (may surface as pending or serialized).
  const hugePayload = { blob: "x".repeat(MAX_PENDING_PAYLOAD_BYTES + 1) };
  assert.throws(
    () =>
      assertRoomStateBounds({
        v: 1,
        seqOut: 0,
        ingressGuards: {},
        pending: [
          {
            correlation_id: "c1",
            type: "t",
            from_session: "s",
            created_at: Date.now(),
            payload: hugePayload,
          },
        ],
      }),
    /pending_payload_limit|room_state_too_large/,
  );

  // Explicit pending-payload path: keep serialized under cap if possible by checking helper order.
  // Direct unit of the pending-byte counter used by inject/request gates:
  const routerBound = new DeviceRoomRouter("dev_bound_unit", {
    sendToSession: () => true,
    sendToRole: () => 0,
  });
  routerBound.pending.set("p1", {
    correlation_id: "p1",
    type: "t",
    from_session: "s",
    created_at: Date.now(),
    payload: { blob: "x".repeat(MAX_PENDING_PAYLOAD_BYTES + 10) },
  });
  assert.ok(routerBound.totalPendingPayloadBytes() > MAX_PENDING_PAYLOAD_BYTES);

  // Serialized size: many small pending entries past byte budget.
  const many: PersistedRoomState["pending"] = [];
  const piece = { pad: "y".repeat(8_000) };
  for (let i = 0; i < 200; i++) {
    many.push({
      correlation_id: `c_${i}`,
      type: "t",
      from_session: "s",
      created_at: Date.now(),
      payload: piece,
    });
  }
  const fat: PersistedRoomState = { v: 1, seqOut: 0, ingressGuards: {}, pending: many };
  const fatBytes = new TextEncoder().encode(JSON.stringify(fat)).byteLength;
  if (fatBytes > MAX_SERIALIZED_STATE_BYTES) {
    assert.throws(() => assertRoomStateBounds(fat), /room_state_too_large|pending/);
  } else {
    // Still exercise the helper on a valid small state.
    assertRoomStateBounds({ v: 1, seqOut: 0, ingressGuards: {}, pending: [] });
  }
});

test("pending payload byte budget rejects inject beyond TTL/count caps", () => {
  const router = new DeviceRoomRouter("dev_pay_bound_01", {
    sendToSession: () => true,
    sendToRole: () => 0,
  });
  router.registerSession({
    role: "agent",
    device_id: "dev_pay_bound_01",
    session_id: "ags_pb",
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
  });
  const fat = { blob: "z".repeat(Math.floor(MAX_PENDING_PAYLOAD_BYTES / 2) + 100) };
  const r1 = router.injectOperation({
    type: "ownmesh_fs_list",
    payload: fat,
    correlation_id: "c_pay_1",
  });
  assert.equal(r1.status, "routed_to_device");
  const r2 = router.injectOperation({
    type: "ownmesh_fs_list",
    payload: fat,
    correlation_id: "c_pay_2",
  });
  assert.equal(r2.status, "rejected");
  assert.equal((r2.detail as { code: string }).code, "OWNMESH_E_PENDING_PAYLOAD_LIMIT");
  assert.ok(router.totalPendingPayloadBytes() <= MAX_PENDING_PAYLOAD_BYTES);
});

test("credential rotation terminally removes a pending operation before Agent redelivery", async () => {
  const { adapter, store } = openSqliteAdapter();
  const deviceId = "dev_generation_redelivery_01";
  await seedActiveDevice(store, deviceId);
  const operationId = "op_generation_redelivery_01";
  const generation = (await store.getPrincipal("prin_dev"))!.credential_generation;
  const boundAction = {
    capability: "fs.list",
    action: "fs.list",
    tool: "ownmesh_fs_list",
    device_id: deviceId,
    principal_id: "prin_dev",
    tenant_id: DEFAULT_TENANT,
    principal_credential_generation: generation,
    facts: { path: "/" },
  };
  await store.putMcpOperation({
    operation_id: operationId,
    tenant_id: DEFAULT_TENANT,
    principal_id: "prin_dev",
    device_id: deviceId,
    tool: "ownmesh_fs_list",
    status: "pending",
    summary: "awaiting redelivery",
    data: {},
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: operationId,
    action: boundAction,
    policy_authority: "ownmesh_device",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });
  const room = new DeviceRoom(mockDOState(), {
    DB: adapter as unknown as D1Database,
    SESSION_SECRET,
  });
  await room.ready;
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;
  const agentId = "ags_generation_redelivery";
  room.router.registerSession({
    role: "agent", device_id: deviceId, session_id: agentId,
    connected_at: Date.now(), phase: "ready", remote_routing_enabled: true,
  });
  let sends = 0;
  room.router.sendToSession = () => {
    sends += 1;
    return true;
  };
  room.router.pending.set(operationId, {
    correlation_id: operationId,
    type: "ownmesh_fs_list",
    from_session: "http_client",
    created_at: Date.now(),
    payload: {
      operation_id: operationId,
      capability: "fs.list",
      authorization: { bound_action: boundAction },
    },
  });

  await store.advancePrincipalCredentialGeneration("prin_dev");
  await (room as unknown as { redeliverCurrentPending(sessionId: string): Promise<void> })
    .redeliverCurrentPending(agentId);

  assert.equal(sends, 0);
  assert.equal(room.router.pending.has(operationId), false);
  assert.equal((await store.getMcpOperation(operationId))?.status, "failed");
});

test("operation.result CAS binds op+correlation+device before forward; mismatch rejected", async () => {
  const { adapter, store } = openSqliteAdapter();
  await store.ensureBootstrap();
  const deviceId = "dev_cas_result_01abc";
  await seedActiveDevice(store, deviceId);
  const opId = randomId("op_");
  const corr = randomId("cor_");
  await store.putMcpOperation({
    operation_id: opId,
    tenant_id: DEFAULT_TENANT,
    principal_id: "prin_dev",
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

  // Mismatch device rejected
  const badDev = await applyMcpOperationResult(store, {
    operationId: opId,
    correlationId: corr,
    payload: { status: "completed", operation_id: opId },
    deviceId: "dev_other_ffffffff",
  });
  assert.equal(badDev.ok, false);

  // Unknown op rejected
  const unknown = await applyMcpOperationResult(store, {
    operationId: "op_missing_zzzz",
    correlationId: corr,
    payload: { status: "completed", operation_id: "op_missing_zzzz" },
    deviceId,
  });
  assert.equal(unknown.ok, false);

  // Correlation mismatch rejected
  const badCorr = await applyMcpOperationResult(store, {
    operationId: opId,
    correlationId: "cor_wrong",
    payload: { status: "completed", operation_id: opId },
    deviceId,
  });
  assert.equal(badCorr.ok, false);
  assert.equal((await store.getMcpOperation(opId))?.status, "pending");

  // Happy path CAS
  const ok = await applyMcpOperationResult(store, {
    operationId: opId,
    correlationId: corr,
    payload: { status: "completed", operation_id: opId, result: { entries: [] } },
    deviceId,
  });
  assert.equal(ok.ok, true);
  assert.equal((await store.getMcpOperation(opId))?.status, "completed");

  // Second terminal CAS fails closed (no resurrection)
  const again = await applyMcpOperationResult(store, {
    operationId: opId,
    correlationId: corr,
    payload: { status: "failed", operation_id: opId },
    deviceId,
  });
  assert.equal(again.ok, false);
  assert.equal((await store.getMcpOperation(opId))?.status, "completed");

  // DeviceRoom path: CAS before finalize (pending remains on reject)
  const storage = new Map<string, unknown>();
  const room = new DeviceRoom(mockDOState({ storage }), {
    DB: adapter as unknown as D1Database,
    SESSION_SECRET,
  });
  await room.ready;
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;
  const clientId = "cls_cas";
  const agentId = "ags_cas";
  const clientInbox: string[] = [];
  room.router.registerSession({
    role: "client",
    device_id: deviceId,
    session_id: clientId,
    connected_at: Date.now(),
    phase: "connected",
    scope: "ownmesh.read",
  });
  room.router.registerSession({
    role: "agent",
    device_id: deviceId,
    session_id: agentId,
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
    auth_hash: "ab".repeat(32),
  });
  room.router.sendToSession = (sid, data) => {
    if (sid === clientId) clientInbox.push(data);
    return true;
  };
  const corr2 = randomId("cor_");
  const opId2 = randomId("op_");
  await store.putMcpOperation({
    operation_id: opId2,
    tenant_id: DEFAULT_TENANT,
    principal_id: "prin_dev",
    device_id: deviceId,
    tool: "ownmesh_fs_list",
    status: "pending",
    summary: "routed",
    data: {},
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: corr2,
    policy_authority: "ownmesh_device",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });
  room.router.pending.set(corr2, {
    correlation_id: corr2,
    type: "ownmesh_fs_list",
    from_session: clientId,
    created_at: Date.now(),
    payload: { operation_id: opId2 },
  });

  // Mismatched operation_id on result — router rejects before deferred forward
  const mismatch = await room.router.handleMessage(
    agentId,
    JSON.stringify(
      envFor(
        agentId,
        "operation.result",
        deviceId,
        { status: "completed", operation_id: "op_other" },
        corr2,
        { seq: 1, message_id: "m_mis" },
      ),
    ),
  );
  assert.equal(mismatch.error, "operation_id_mismatch");
  assert.equal(room.router.pending.has(corr2), true);
  assert.equal(clientInbox.length, 0);

  // Valid result via webSocketMessage: needs mock socket + credential
  const { token } = await seedActiveDevice(store, deviceId);
  const authHash = await sha256Hex(token);
  // Re-bind agent with valid auth
  room.router.sessions.get(agentId)!.auth_hash = authHash;
  const sock = mockSocket({
    role: "agent",
    device_id: deviceId,
    session_id: agentId,
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
    auth_hash: authHash,
    lastSeq: 1,
  });
  room.wsSessions.set(sock as unknown as WebSocket, agentId);

  await room.webSocketMessage(
    sock as unknown as WebSocket,
    JSON.stringify(
      envFor(
        agentId,
        "operation.result",
        deviceId,
        { status: "completed", operation_id: opId2, result: { ok: true } },
        corr2,
        { seq: 2, message_id: "m_ok" },
      ),
    ),
  );
  assert.equal((await store.getMcpOperation(opId2))?.status, "completed");
  assert.equal(room.router.pending.has(corr2), false, "pending removed only after CAS");
  assert.ok(
    clientInbox.some((m) => (JSON.parse(m) as DeviceEnvelope).type === "operation.result"),
    "client receives result only after CAS",
  );
});

test("live transfer tombstone survives hibernation without bearer replay or storage", async () => {
  const deviceId = "dev_live_ticket_01";
  const rawBearer = "ticket.live-secret.jti-123";
  const rawCiphertext = "ciphertext-live-transfer-bytes";
  const delivered: string[] = [];
  const router = new DeviceRoomRouter(deviceId, {
    sendToSession: (sid, raw) => { if (sid === "ags_live") delivered.push(raw); return true; },
    sendToRole: () => 0,
  });
  router.registerSession({ role: "agent", device_id: deviceId, session_id: "ags_live", connected_at: Date.now(), phase: "ready", remote_routing_enabled: true });
  router.pending.set("op_live", {
    correlation_id: "op_live", type: "transfer.start", from_session: "", created_at: Date.now(),
    payload: { operation_id: "op_live", capability: "transfer.start" }, expires_at: new Date(Date.now() + 60_000).toISOString(), live_only: true,
  });
  const snapshot = router.exportState();
  const stored = JSON.stringify(snapshot);
  for (const forbidden of [rawBearer, rawCiphertext, "ephemeral", "bearer.secret", "raw-transfer-bytes"]) {
    assert.equal(stored.includes(forbidden), false, `durable state leaked ${forbidden}`);
  }
  const resumed = new DeviceRoomRouter(deviceId, { sendToSession: () => true, sendToRole: () => 0 });
  resumed.importState(snapshot);
  resumed.registerSession({ role: "agent", device_id: deviceId, session_id: "ags_live", connected_at: Date.now(), phase: "ready", remote_routing_enabled: true });
  assert.equal(resumed.redeliverPendingToAgent("ags_live"), 0, "live ticket must never be hibernation-replayed");
  const result = await resumed.handleMessage("ags_live", JSON.stringify(envFor("ags_live", "operation.result", deviceId, { operation_id: "op_live", status: "completed", result: {} }, "op_live")));
  assert.equal(result.ok, true, "delayed authenticated result still correlates");
  assert.ok(delivered.length === 0);
});

test("live-operation sends raw ticket once but persists only a redacted tombstone", async () => {
  const deviceId = "dev_live_do_boundary_01";
  const { adapter, store } = openSqliteAdapter();
  const { token } = await seedActiveDevice(store, deviceId);
  const authHash = await sha256Hex(token);
  const storage = new Map<string, unknown>();
  const att: SessionAttachment = {
    role: "agent", device_id: deviceId, session_id: "ags_live_boundary", connected_at: Date.now(),
    phase: "ready", remote_routing_enabled: true, auth_hash: authHash, lastSeq: 0,
  };
  const socket = mockSocket(att);
  const room = new DeviceRoom(mockDOState({ sockets: [socket], storage }), {
    DB: adapter as unknown as D1Database, SESSION_SECRET,
  });
  await room.ready;
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;
  room.wsSessions.set(socket as unknown as WebSocket, att.session_id);
  room.router.registerSession(att);

  const makeLiveBody = (correlationId: string, ticket: string) => ({
    type: "operation.request",
    correlation_id: correlationId,
    expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    payload: {
      operation_id: correlationId, capability: "transfer.start",
      authorization: {
        bound_action: {
          principal_id: "prin_dev",
          tenant_id: DEFAULT_TENANT,
          principal_credential_generation: 1,
        },
      },
      arguments: {
        ticket, jti: `jti-${ticket}`, ephemeral_public_key: `ephemeral-${ticket}`,
        relay_ciphertext: `cipher-${ticket}`,
      },
    },
  });
  const callLive = async (correlationId: string, ticket: string) => {
    const { headers, bodyText } = await liveOperationHeaders(deviceId, makeLiveBody(correlationId, ticket), correlationId);
    return room.fetch(new Request(`https://device-room/live-operation?device_id=${deviceId}`, {
      method: "POST", headers, body: bodyText,
    }));
  };

  const noAgent = new DeviceRoom(mockDOState({ storage: new Map() }), {
    DB: adapter as unknown as D1Database, SESSION_SECRET,
  });
  await noAgent.ready;
  noAgent.deviceId = deviceId;
  noAgent.router.deviceId = deviceId;
  const offline = await (async () => {
    const correlationId = "op_live_offline";
    const { headers, bodyText } = await liveOperationHeaders(deviceId, makeLiveBody(correlationId, "ticket-offline"), correlationId);
    return noAgent.fetch(new Request(`https://device-room/live-operation?device_id=${deviceId}`, { method: "POST", headers, body: bodyText }));
  })();
  assert.equal(offline.status, 503);
  assert.equal(((await offline.json()) as { status: string }).status, "device_offline");

  // An overdue prior live tombstone must reconcile its matching D1 operation
  // before this new generation is admitted and persisted.
  const expiredLiveId = "op_live_expired_before_next";
  await store.putMcpOperation({
    operation_id: expiredLiveId, tenant_id: DEFAULT_TENANT, principal_id: "prin_dev", device_id: deviceId,
    tool: "__transfer_start_source", status: "pending", summary: "routed", data: {}, truncated: false,
    next_cursor: null, approval_required: false, warnings: [], correlation_id: expiredLiveId,
    expires_at: new Date(Date.now() - 1).toISOString(), policy_authority: "ownmesh_device",
    created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
  });
  room.router.pending.set(expiredLiveId, {
    correlation_id: expiredLiveId, type: "transfer.start", from_session: "", created_at: Date.now(),
    expires_at: new Date(Date.now() - 1).toISOString(), live_only: true,
    payload: { operation_id: expiredLiveId, capability: "transfer.start" },
  });

  const marker = "ticket-live-boundary-secret";
  const delivered = await callLive("op_live_delivered", marker);
  assert.equal(delivered.status, 200);
  assert.equal(((await delivered.json()) as { status: string }).status, "routed_to_device");
  assert.equal((await store.getMcpOperation(expiredLiveId))?.status, "failed");
  assert.equal(room.router.pending.has(expiredLiveId), false);
  assert.equal(socket.sent.length, 1, "the ready exact Agent receives the one live request");
  assert.ok(socket.sent[0]!.includes(marker));

  const persisted = JSON.stringify(storage.get(ROOM_STATE_STORAGE_KEY));
  for (const forbidden of [marker, `jti-${marker}`, `ephemeral-${marker}`, `cipher-${marker}`]) {
    assert.equal(persisted.includes(forbidden), false, `DO persisted raw live field: ${forbidden}`);
  }
  const hibernated = new DeviceRoom(mockDOState({ storage }), {
    DB: adapter as unknown as D1Database, SESSION_SECRET,
  });
  await hibernated.ready;
  hibernated.deviceId = deviceId;
  hibernated.router.deviceId = deviceId;
  hibernated.router.registerSession({ ...att, session_id: "ags_live_after_hibernate" });
  assert.equal(hibernated.router.redeliverPendingToAgent("ags_live_after_hibernate"), 0, "hibernation never replays a live bearer");

  // A closed socket is a definite non-delivery, so its tombstone is removed
  // before the offline response and cannot consume room capacity.
  socket.close(1006, "closed before live send");
  const sendFalseMarker = "ticket-send-false-secret";
  const sendFalse = await callLive("op_live_send_false", sendFalseMarker);
  assert.equal(sendFalse.status, 503);
  assert.equal(((await sendFalse.json()) as { status: string }).status, "device_offline");
  const afterFalse = JSON.stringify(storage.get(ROOM_STATE_STORAGE_KEY));
  assert.equal(afterFalse.includes(sendFalseMarker), false);
  assert.equal(room.router.pending.has("op_live_send_false"), false);

  // A persist failure precedes socket dispatch. The live request is therefore
  // non-successful and its bearer never crosses either durable or socket state.
  const failingStorage = new Map<string, unknown>();
  const failingSocket = mockSocket({ ...att, session_id: "ags_live_persist_fail" });
  const failingState = mockDOState({ sockets: [failingSocket], storage: failingStorage });
  (failingState.storage as unknown as { put: (key: string, value: unknown) => Promise<void> }).put = async () => {
    throw new Error("live_tombstone_persist_failed");
  };
  const persistFailRoom = new DeviceRoom(failingState, { DB: adapter as unknown as D1Database, SESSION_SECRET });
  await persistFailRoom.ready;
  persistFailRoom.deviceId = deviceId;
  persistFailRoom.router.deviceId = deviceId;
  persistFailRoom.wsSessions.set(failingSocket as unknown as WebSocket, "ags_live_persist_fail");
  persistFailRoom.router.registerSession({ ...att, session_id: "ags_live_persist_fail" });
  const persistFailMarker = "ticket-persist-failure-secret";
  const persistFailCorrelation = "op_live_persist_fail";
  const persistFailHeaders = await liveOperationHeaders(
    deviceId, makeLiveBody(persistFailCorrelation, persistFailMarker), persistFailCorrelation,
  );
  const persistFail = await persistFailRoom.fetch(new Request(`https://device-room/live-operation?device_id=${deviceId}`, {
    method: "POST", headers: persistFailHeaders.headers, body: persistFailHeaders.bodyText,
  }));
  assert.equal(persistFail.status, 503);
  assert.equal(((await persistFail.json()) as { error: string }).error, "storage_unavailable");
  assert.equal(failingSocket.sent.length, 0, "no live bearer send may precede durable tombstone persistence");
  assert.equal(JSON.stringify(failingStorage).includes(persistFailMarker), false);
});

test("live transfer tombstones retain only until operation expiry and remain bounded", () => {
  const deviceId = "dev_live_tombstone_bounds_01";
  const router = new DeviceRoomRouter(deviceId, { sendToSession: () => true, sendToRole: () => 0 });
  const now = Date.now();
  router.pending.set("long_running", {
    correlation_id: "long_running", type: "transfer.start", from_session: "", payload: { operation_id: "long_running", capability: "transfer.start" },
    created_at: now - PENDING_TTL_MS - 1, expires_at: new Date(now + LIVE_TRANSFER_TOMBSTONE_MAX_TTL_MS).toISOString(), live_only: true,
  });
  router.pending.set("expired", {
    correlation_id: "expired", type: "transfer.start", from_session: "", payload: { operation_id: "expired", capability: "transfer.start" },
    created_at: now, expires_at: new Date(now - 1).toISOString(), live_only: true,
  });
  router.pruneExpiredPending(now);
  assert.equal(router.pending.has("long_running"), true, "long transfer result remains correlatable past normal dispatch TTL");
  assert.equal(router.pending.has("expired"), false, "operation deadline clears live correlation tombstone");

  for (let i = 0; i < MAX_PENDING_OPERATIONS + 8; i++) {
    router.pending.set(`live_${i}`, {
      correlation_id: `live_${i}`, type: "transfer.start", from_session: "", payload: { operation_id: `live_${i}`, capability: "transfer.start" },
      created_at: now + i, expires_at: new Date(now + LIVE_TRANSFER_TOMBSTONE_MAX_TTL_MS).toISOString(), live_only: true,
    });
  }
  router.pruneExpiredPending(now);
  assert.ok(router.pending.size <= MAX_PENDING_OPERATIONS, "live-only correlation state is hard bounded");
});

test("transfer preflight results are exact-correlated metadata only", async () => {
  const { store } = openSqliteAdapter();
  await store.ensureBootstrap();
  const deviceId = "dev_preflight_source_01";
  await seedActiveDevice(store, deviceId);
  const opId = randomId("op_");
  const correlationId = randomId("cor_");
  const expiresAt = Date.now() + 30_000;
  const expected = {
    role: "source",
    transfer_id: "xfer_preflight_1",
    tenant_id: DEFAULT_TENANT,
    plan_sha256: "a".repeat(64),
    epoch: 1,
    fence: 1,
    expires_at: expiresAt,
    device_id: deviceId,
    workspace_id: "ws_source",
    session_nonce: "nonce_preflight_1",
    coordinator_request_id: "coord_preflight_1",
    workspace_version: 7,
  };
  await store.putMcpOperation({
    operation_id: opId,
    tenant_id: DEFAULT_TENANT,
    principal_id: "prin_dev",
    device_id: deviceId,
    tool: "__transfer_preflight_source",
    status: "pending",
    summary: "transfer source preflight",
    data: { __transfer_preflight_expectation: expected },
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: correlationId,
    workspace_id: "ws_source",
    policy_authority: "ownmesh_device",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });
  const proof = {
    role: "source",
    transfer_id: expected.transfer_id,
    tenant_id: expected.tenant_id,
    device_id: deviceId,
    workspace_id: expected.workspace_id,
    plan_sha256: expected.plan_sha256,
    epoch: 1,
    fence: 1,
    session_nonce: expected.session_nonce,
    expires_at: expiresAt,
    ephemeral_public_key: "11".repeat(32),
    ephemeral_signature: "22".repeat(64),
  };
  const rejected = await applyMcpOperationResult(store, {
    operationId: opId,
    correlationId,
    deviceId,
    payload: {
      operation_id: opId,
      status: "completed",
      result: {
        transfer_preflight: { ...proof, ciphertext_base64: "must-not-persist" },
        operation_id: opId,
        coordinator_request_id: expected.coordinator_request_id,
        principal_id: "prin_dev",
        workspace_version: expected.workspace_version,
      },
    },
  });
  assert.deepEqual(rejected, { ok: false, error: "transfer_preflight_proof_mismatch" });
  assert.equal((await store.getMcpOperation(opId))?.status, "pending");

  const accepted = await applyMcpOperationResult(store, {
    operationId: opId,
    correlationId,
    deviceId,
    payload: {
      operation_id: opId,
      status: "completed",
      result: {
        transfer_preflight: proof,
        operation_id: opId,
        coordinator_request_id: expected.coordinator_request_id,
        principal_id: "prin_dev",
        workspace_version: expected.workspace_version,
        source_plan: { plan_id: "xfer_local_1", sha256: "b".repeat(64), size_bytes: 1 },
      },
    },
  });
  assert.equal(accepted.ok, true);
  const saved = await store.getMcpOperation(opId);
  assert.equal(saved?.status, "completed");
  assert.deepEqual(saved?.data, {
    transfer_preflight: proof,
    operation_id: opId,
    coordinator_request_id: expected.coordinator_request_id,
    principal_id: "prin_dev",
    workspace_version: expected.workspace_version,
    source_plan: { plan_id: "xfer_local_1", sha256: "b".repeat(64), size_bytes: 1 },
  });
});

test("transfer artifact results are bounded, hash-checked, and exact-plan bound", async () => {
  const { store } = openSqliteAdapter(); await store.ensureBootstrap();
  const deviceId = "dev_artifact_destination_01"; await seedActiveDevice(store, deviceId);
  const opId = randomId("op_"); const correlationId = randomId("cor_");
  await store.putMcpOperation({
    operation_id: opId, tenant_id: DEFAULT_TENANT, principal_id: "prin_dev", device_id: deviceId,
    tool: "__transfer_artifact_get", status: "pending", summary: "artifact", data: { transfer_id: "xfer_1", offset: 0, max_bytes: 65536, expected_sha256: "c".repeat(64), expected_total_bytes: 3 },
    truncated: false, next_cursor: null, approval_required: false, warnings: [], correlation_id: correlationId,
    workspace_id: "ws_destination", action: { facts: { plan_id: "plan_destination" } }, policy_authority: "ownmesh_device",
    created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
  });
  const bytes = new TextEncoder().encode("abc"); const content_base64 = btoa("abc");
  const page_sha256 = await sha256Hex(bytes);
  const base = { plan_id: "plan_destination", offset: 0, bytes: 3, total_bytes: 3, next_offset: null, truncated: false, encoding: "base64", content_base64, page_sha256, sha256: "c".repeat(64) };
  const tampered = await applyMcpOperationResult(store, { operationId: opId, correlationId, deviceId, payload: { operation_id: opId, status: "completed", result: { ...base, page_sha256: "d".repeat(64) } } });
  assert.deepEqual(tampered, { ok: false, error: "transfer_artifact_page_hash_mismatch" });
  assert.equal((await store.getMcpOperation(opId))?.status, "pending");
  const accepted = await applyMcpOperationResult(store, { operationId: opId, correlationId, deviceId, payload: { operation_id: opId, status: "completed", result: base } });
  assert.equal(accepted.ok, true); assert.equal((await store.getMcpOperation(opId))?.data.content_base64, content_base64);

  const mismatchId = randomId("op_");
  await store.putMcpOperation({ operation_id: mismatchId, tenant_id: DEFAULT_TENANT, principal_id: "prin_dev", device_id: deviceId, tool: "__transfer_artifact_get", status: "pending", summary: "artifact mismatch", data: { offset: 0, max_bytes: 65536, expected_sha256: "c".repeat(64), expected_total_bytes: 3 }, truncated: false, next_cursor: null, approval_required: false, warnings: [], correlation_id: mismatchId, workspace_id: "ws_destination", action: { facts: { plan_id: "plan_destination" } }, policy_authority: "ownmesh_device", created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  const mismatchedDigest = await applyMcpOperationResult(store, { operationId: mismatchId, correlationId: mismatchId, deviceId, payload: { operation_id: mismatchId, status: "completed", result: { ...base, sha256: "d".repeat(64) } } });
  assert.deepEqual(mismatchedDigest, { ok: false, error: "transfer_artifact_result_binding_mismatch" });

  const overflowId = randomId("op_");
  await store.putMcpOperation({ operation_id: overflowId, tenant_id: DEFAULT_TENANT, principal_id: "prin_dev", device_id: deviceId, tool: "__transfer_artifact_get", status: "pending", summary: "artifact overflow", data: { offset: 0, max_bytes: 65536, expected_sha256: "c".repeat(64), expected_total_bytes: 65537 }, truncated: false, next_cursor: null, approval_required: false, warnings: [], correlation_id: overflowId, workspace_id: "ws_destination", action: { facts: { plan_id: "plan_destination" } }, policy_authority: "ownmesh_device", created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  const tooMany = new Uint8Array(65537); const overflow = await applyMcpOperationResult(store, { operationId: overflowId, correlationId: overflowId, deviceId, payload: { operation_id: overflowId, status: "completed", result: { ...base, bytes: 65537, total_bytes: 65537, content_base64: btoa(String.fromCharCode(...tooMany)), page_sha256: "e".repeat(64) } } });
  assert.deepEqual(overflow, { ok: false, error: "transfer_artifact_result_binding_mismatch" });
});

test("transfer start receipts reject bearer/byte fields and require exact immutable bindings", async () => {
  const { store } = openSqliteAdapter(); await store.ensureBootstrap();
  const deviceId = "dev_start_destination_01"; await seedActiveDevice(store, deviceId);
  const opId = randomId("op_"); const correlationId = randomId("cor_");
  const facts = { transfer_id: "xfer_start_1", plan_sha256: "a".repeat(64), content_sha256: "b".repeat(64), epoch: 2, fence: 3 };
  await store.putMcpOperation({ operation_id: opId, tenant_id: DEFAULT_TENANT, principal_id: "prin_dev", device_id: deviceId, tool: "__transfer_start_destination", status: "pending", summary: "start", data: {}, truncated: false, next_cursor: null, approval_required: false, warnings: [], correlation_id: correlationId, workspace_id: "ws_destination", action: { facts }, policy_authority: "ownmesh_device", created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  const receipt = { transfer_id: facts.transfer_id, plan_id: "plan_destination", role: "destination", plan_sha256: facts.plan_sha256, epoch: 2, fence: 3, admitted: true, completed: true, published: true, artifact_sha256: facts.content_sha256 };
  const rejected = await applyMcpOperationResult(store, { operationId: opId, correlationId, deviceId, payload: { operation_id: opId, status: "completed", result: { ...receipt, ticket: "must-not-store" } } });
  assert.deepEqual(rejected, { ok: false, error: "transfer_start_result_unknown_field" });
  const wrongArtifact = await applyMcpOperationResult(store, { operationId: opId, correlationId, deviceId, payload: { operation_id: opId, status: "completed", result: { ...receipt, artifact_sha256: "c".repeat(64) } } });
  assert.deepEqual(wrongArtifact, { ok: false, error: "transfer_start_result_binding_mismatch" });
  const accepted = await applyMcpOperationResult(store, { operationId: opId, correlationId, deviceId, payload: { operation_id: opId, status: "completed", result: receipt } });
  assert.equal(accepted.ok, true); assert.deepEqual((await store.getMcpOperation(opId))?.data, receipt);

  const reconnectId = randomId("op_");
  await store.putMcpOperation({ operation_id: reconnectId, tenant_id: DEFAULT_TENANT, principal_id: "prin_dev", device_id: deviceId, tool: "__transfer_start_destination", status: "pending", summary: "start", data: {}, truncated: false, next_cursor: null, approval_required: false, warnings: [], correlation_id: reconnectId, workspace_id: "ws_destination", action: { facts }, policy_authority: "ownmesh_device", created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  const reconnect = await applyMcpOperationResult(store, { operationId: reconnectId, correlationId: reconnectId, deviceId, payload: { operation_id: reconnectId, status: "failed", error: { code: "OWNMESH_E_TRANSFER_RECONNECT", message: "bearer distinctive-ticket-secret", details: { ciphertext_base64: "must-not-persist" } } } });
  assert.equal(reconnect.ok, true);
  const storedReconnect = await store.getMcpOperation(reconnectId);
  assert.deepEqual(storedReconnect?.data, { error: { code: "OWNMESH_E_TRANSFER_RECONNECT" } });
  assert.equal(storedReconnect?.summary, "transfer start requires a fresh connection proof");
  assert.equal(JSON.stringify(storedReconnect).includes("distinctive-ticket-secret"), false);
  assert.equal(JSON.stringify(storedReconnect).includes("must-not-persist"), false);

  const cleanupPendingId = randomId("op_");
  await store.putMcpOperation({ operation_id: cleanupPendingId, tenant_id: DEFAULT_TENANT, principal_id: "prin_dev", device_id: deviceId, tool: "__transfer_start_source", status: "pending", summary: "start", data: {}, truncated: false, next_cursor: null, approval_required: false, warnings: [], correlation_id: cleanupPendingId, workspace_id: "ws_source", action: { facts }, policy_authority: "ownmesh_device", created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  const cleanupPending = await applyMcpOperationResult(store, { operationId: cleanupPendingId, correlationId: cleanupPendingId, deviceId, payload: { operation_id: cleanupPendingId, status: "failed", error: { code: "OWNMESH_E_TRANSFER_CLEANUP_PENDING", message: "distinctive-cleanup-path", details: { path: "must-not-persist" } } } });
  assert.equal(cleanupPending.ok, true);
  assert.deepEqual((await store.getMcpOperation(cleanupPendingId))?.data, { error: { code: "OWNMESH_E_TRANSFER_CLEANUP_PENDING" } });
});

test("transfer cancel controls persist only target-bound cleanup proof", async () => {
  const { store } = openSqliteAdapter(); await store.ensureBootstrap();
  const deviceId = "dev_cancel_destination_01"; await seedActiveDevice(store, deviceId);
  const opId = randomId("op_"); const target = "op_transfer_destination";
  await store.putMcpOperation({ operation_id: opId, tenant_id: DEFAULT_TENANT, principal_id: "prin_dev", device_id: deviceId, tool: "__transfer_cancel_control", status: "pending", summary: "cancel", data: { target_operation_id: target }, truncated: false, next_cursor: null, approval_required: false, warnings: [], correlation_id: opId, workspace_id: "ws_destination", policy_authority: "ownmesh_device", created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  const substituted = await applyMcpOperationResult(store, { operationId: opId, correlationId: opId, deviceId, payload: { operation_id: opId, status: "completed", result: { target_operation_id: "op_other", cancelled: true, signal_delivered: true } } });
  assert.deepEqual(substituted, { ok: false, error: "transfer_cancel_result_binding_mismatch" });
  const accepted = await applyMcpOperationResult(store, { operationId: opId, correlationId: opId, deviceId, payload: { operation_id: opId, status: "completed", result: { target_operation_id: target, cancelled: false, signal_delivered: false, note: "Agent restarted" } } });
  assert.equal(accepted.ok, true);
  assert.deepEqual((await store.getMcpOperation(opId))?.data, { target_operation_id: target, cancelled: false, signal_delivered: false });
});

test("source cleanup persists only an exact plan-bound completion receipt", async () => {
  const { store } = openSqliteAdapter(); await store.ensureBootstrap();
  const deviceId = "dev_cleanup_source_01"; await seedActiveDevice(store, deviceId);
  const opId = randomId("op_"); const planId = "xfer_source_cleanup_01";
  await store.putMcpOperation({ operation_id: opId, tenant_id: DEFAULT_TENANT, principal_id: "prin_dev", device_id: deviceId, tool: "__transfer_source_cleanup", status: "pending", summary: "cleanup", data: { plan_id: planId }, truncated: false, next_cursor: null, approval_required: false, warnings: [], correlation_id: opId, workspace_id: "ws_source", policy_authority: "ownmesh_device", created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  const substituted = await applyMcpOperationResult(store, { operationId: opId, correlationId: opId, deviceId, payload: { operation_id: opId, status: "completed", result: { plan_id: "xfer_other", cancelled: true, source_only: true } } });
  assert.deepEqual(substituted, { ok: false, error: "transfer_source_cleanup_result_binding_mismatch" });
  const injected = await applyMcpOperationResult(store, { operationId: opId, correlationId: opId, deviceId, payload: { operation_id: opId, status: "completed", result: { plan_id: planId, cancelled: true, source_only: true, path: "secret/path" } } });
  assert.deepEqual(injected, { ok: false, error: "transfer_source_cleanup_result_binding_mismatch" });
  const accepted = await applyMcpOperationResult(store, { operationId: opId, correlationId: opId, deviceId, payload: { operation_id: opId, status: "completed", result: { plan_id: planId, cancelled: true, source_only: true } } });
  assert.equal(accepted.ok, true);
  assert.deepEqual((await store.getMcpOperation(opId))?.data, { plan_id: planId, cleaned: true, source_only: true });
});

test("internal transfer errors and approvals never persist Agent diagnostics", async () => {
  const { db, store } = openSqliteAdapter(); await store.ensureBootstrap();
  const deviceId = "dev_transfer_redaction_01"; await seedActiveDevice(store, deviceId);
  const tools = [
    "__transfer_start_source",
    "__transfer_start_destination",
    "__transfer_preflight_source",
    "__transfer_preflight_source_final",
    "__transfer_preflight_destination",
    "__transfer_artifact_get",
    "__transfer_cancel_control",
    "__transfer_source_cleanup",
  ];
  const modes = [
    { name: "approval", status: "failed", approval: true },
    // The wire protocol normally uses failed, but a malformed literal error
    // must not turn this durable row into a diagnostics sink either.
    { name: "error", status: "error", approval: false },
  ];
  const secrets: string[] = [];
  for (const tool of tools) {
    for (const mode of modes) {
      const operationId = randomId("op_");
      const marker = `distinctive-${tool.slice(11)}-${mode.name}-${operationId}`;
      secrets.push(marker);
      await store.putMcpOperation({
        operation_id: operationId, tenant_id: DEFAULT_TENANT, principal_id: "prin_dev", device_id: deviceId,
        tool, status: "pending", summary: "internal transfer", data: { safe: true },
        truncated: false, next_cursor: null, approval_required: false, warnings: [], correlation_id: operationId,
        workspace_id: "ws_destination", policy_authority: "ownmesh_device",
        created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
      });
      const applied = await applyMcpOperationResult(store, {
        operationId, correlationId: operationId, deviceId,
        payload: {
          operation_id: operationId, status: mode.status, approval_required: mode.approval,
          summary: `${marker}-summary`, reason: `${marker}-reason`, approval_id: `${marker}-approval-id`,
          session_id: `${marker}-session`,
          result: { ticket: `${marker}-ticket`, path: `${marker}-path`, bytes: `${marker}-bytes` },
          error: {
            code: mode.approval ? "OWNMESH_E_APPROVAL_REQUIRED" : "OWNMESH_E_TRANSFER_UNSAFE",
            message: `${marker}-message`,
            details: {
              approval_required: mode.approval, approval_id: `${marker}-details-approval-id`,
              reason: `${marker}-details-reason`, ticket: `${marker}-details-ticket`,
              path: `${marker}-details-path`, bytes: `${marker}-details-bytes`, ciphertext: `${marker}-details-ciphertext`,
            },
          },
        },
      });
      assert.equal(applied.ok, true);
      const stored = await store.getMcpOperation(operationId);
      assert.ok(stored);
      assert.equal(stored.approval_id ?? null, null);
      assert.equal(stored.session_id ?? null, null);
      assert.equal(stored.summary.includes(marker), false);
      assert.equal(JSON.stringify(stored).includes(marker), false);
    }
  }
  // Check the actual SQLite representation, rather than only the decoded
  // record, so a future serialization path cannot hide a re-persisted field.
  const raw = db.prepare("SELECT summary, data_json, approval_id, session_id FROM mcp_operations").all() as Record<string, unknown>[];
  const serialized = JSON.stringify(raw);
  for (const marker of secrets) assert.equal(serialized.includes(marker), false, marker);
});

test("operation.result store write failure fails closed without forward", async () => {
  const deviceId = "dev_result_store_fail";
  const { adapter, store } = openSqliteAdapter();
  const { token } = await seedActiveDevice(store, deviceId);
  const authHash = await sha256Hex(token);
  const opId = randomId("op_");
  const corr = randomId("cor_");
  await store.putMcpOperation({
    operation_id: opId,
    tenant_id: DEFAULT_TENANT,
    principal_id: "prin_dev",
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

  // Store that throws on updateMcpOperation
  const brokenStore = Object.create(store) as SqlStore;
  brokenStore.updateMcpOperation = async () => {
    throw new Error("d1_write_failed");
  };

  // Direct helper surfaces throw to caller
  await assert.rejects(
    () =>
      applyMcpOperationResult(brokenStore, {
        operationId: opId,
        correlationId: corr,
        payload: { status: "completed", operation_id: opId },
        deviceId,
      }),
    /d1_write_failed/,
  );

  // Room still has pending after throw path simulated at DO layer:
  const storage = new Map<string, unknown>();
  const room = new DeviceRoom(mockDOState({ storage }), {
    DB: adapter as unknown as D1Database,
    SESSION_SECRET,
  });
  await room.ready;
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;
  const clientId = "cls_sf";
  const agentId = "ags_sf";
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
  room.router.registerSession({
    role: "agent",
    device_id: deviceId,
    session_id: agentId,
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
    auth_hash: authHash,
  });
  room.router.pending.set(corr, {
    correlation_id: corr,
    type: "ownmesh_fs_list",
    from_session: clientId,
    created_at: Date.now(),
    payload: { operation_id: opId },
  });
  const sock = mockSocket({
    role: "agent",
    device_id: deviceId,
    session_id: agentId,
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
    auth_hash: authHash,
    lastSeq: 0,
  });
  room.wsSessions.set(sock as unknown as WebSocket, agentId);

  // Monkeypatch create path: break env.DB batch after ready by swapping store via
  // a poison adapter that throws on mcp_operations UPDATE.
  const poison = openSqliteAdapter();
  await seedActiveDevice(poison.store, deviceId);
  await poison.store.putMcpOperation({
    operation_id: opId,
    tenant_id: DEFAULT_TENANT,
    principal_id: "prin_dev",
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
  // Replace prepare to throw on UPDATE mcp_operations
  const realPrepare = poison.adapter.prepare.bind(poison.adapter);
  poison.adapter.prepare = (query: string) => {
    if (/UPDATE\s+mcp_operations/i.test(query)) {
      throw new Error("d1_write_failed");
    }
    return realPrepare(query);
  };
  const room2 = new DeviceRoom(mockDOState({ storage: new Map() }), {
    DB: poison.adapter as unknown as D1Database,
    SESSION_SECRET,
  });
  await room2.ready;
  room2.deviceId = deviceId;
  room2.router.deviceId = deviceId;
  room2.router.sendToSession = (sid, data) => {
    if (sid === clientId) clientInbox.push(data);
    return true;
  };
  room2.router.registerSession({
    role: "client",
    device_id: deviceId,
    session_id: clientId,
    connected_at: Date.now(),
    phase: "connected",
    scope: "ownmesh.read",
  });
  // Valid credential on poison store
  const { token: t2 } = await seedActiveDevice(poison.store, deviceId);
  const hash2 = await sha256Hex(t2);
  room2.router.registerSession({
    role: "agent",
    device_id: deviceId,
    session_id: agentId,
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
    auth_hash: hash2,
  });
  room2.router.pending.set(corr, {
    correlation_id: corr,
    type: "ownmesh_fs_list",
    from_session: clientId,
    created_at: Date.now(),
    payload: { operation_id: opId },
  });
  const sock2 = mockSocket({
    role: "agent",
    device_id: deviceId,
    session_id: agentId,
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
    auth_hash: hash2,
    lastSeq: 0,
  });
  room2.wsSessions.set(sock2 as unknown as WebSocket, agentId);
  const beforeInbox = clientInbox.length;
  await room2.webSocketMessage(
    sock2 as unknown as WebSocket,
    JSON.stringify(
      envFor(
        agentId,
        "operation.result",
        deviceId,
        { status: "completed", operation_id: opId },
        corr,
        { seq: 1, message_id: "m_fail" },
      ),
    ),
  );
  // Fail closed: no client forward of success result
  const newClientMsgs = clientInbox.slice(beforeInbox).map((m) => JSON.parse(m) as DeviceEnvelope);
  assert.ok(
    !newClientMsgs.some((m) => m.type === "operation.result"),
    "must not forward result when store write fails",
  );
});
