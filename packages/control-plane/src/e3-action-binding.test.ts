/**
 * E3 exact-action binding: server payload_hash + idempotency mismatch + atomic claim.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import {
  bindCanonicalAction,
  buildCanonicalAction,
  buildDeviceOperation,
  buildDispatchOutbox,
  handleMcp,
  needsDispatchRedelivery,
  normalizeCommandEnv,
  readDispatchOutbox,
  sanitizeMcpArgs,
  stripDispatchOutbox,
  withDispatchOutbox,
  MCP_MAX_OUTPUT_BYTES,
  MCP_MAX_TIMEOUT_MS,
  DISPATCH_OUTBOX_KEY,
  type OperationRouter,
} from "./mcp.ts";
import {
  MemoryStore,
  SqlStore,
  MCP_OPS_MAX_DATA_JSON_BYTES,
  MCP_OPS_MAX_PER_TENANT,
  MCP_OPS_RESULT_TTL_MS,
  MCP_OPS_TOMBSTONE_TTL_MS,
  boundMcpOperationRecord,
  type SqlDatabase,
  type SqlStatement,
} from "./store.ts";
import { hashCanonicalAction, nowIso } from "./util.ts";

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, "..", "migrations");

function adaptSqlite(db: DatabaseSync): SqlDatabase {
  type SqlVal = null | number | string | bigint | Uint8Array;
  return {
    prepare(query: string): SqlStatement {
      const stmt = db.prepare(query);
      let bound: SqlVal[] = [];
      const api: SqlStatement = {
        bind(...values: unknown[]) {
          bound = values.map((v) => (v === undefined ? null : (v as SqlVal)));
          return api;
        },
        async first<T = Record<string, unknown>>(colName?: string) {
          const row = stmt.get(...bound) as Record<string, unknown> | undefined;
          if (!row) return null;
          if (colName) return (row[colName] as T) ?? null;
          return row as T;
        },
        async run() {
          const info = stmt.run(...bound) as { changes: number };
          return { success: true, meta: { changes: Number(info.changes || 0) } };
        },
        async all<T = Record<string, unknown>>() {
          return { results: stmt.all(...bound) as T[] };
        },
      };
      return api;
    },
    exec(query: string) {
      db.exec(query);
    },
    async batch<T = unknown>(statements: SqlStatement[]) {
      const out: T[] = [];
      for (const s of statements) out.push((await s.run()) as T);
      return out;
    },
  };
}

function openSqlStore(): SqlStore {
  const db = new DatabaseSync(":memory:");
  for (const f of readdirSync(migrationsDir).filter((x) => x.endsWith(".sql")).sort()) {
    db.exec(readFileSync(join(migrationsDir, f), "utf8"));
  }
  return new SqlStore(adaptSqlite(db), "sqlite");
}

async function seedAuthed(store: MemoryStore | SqlStore, principal = "prin_dev") {
  await store.ensureBootstrap();
  await store.ensurePrincipal(principal, "Dev", "human", "ten_default");
  await store.putClient({
    client_id: "client_mcp",
    tenant_id: "ten_default",
    client_name: "MCP test",
    redirect_uris: ["https://cp.test/cb"],
    created_at: nowIso(),
  });
  return store.issueTokens(
    "client_mcp",
    principal,
    "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device",
  );
}

async function putActiveDevice(store: MemoryStore | SqlStore, id: string, principal = "prin_dev") {
  await store.putDevice({
    id,
    tenant_id: "ten_default",
    principal_id: principal,
    name: id,
    hostname: id,
    os: "test",
    arch: "x64",
    agent_version: "1",
    protocol_version: "ownmesh.device/1.0",
    public_key: "ab".repeat(32),
    revoked: false,
    created_at: new Date().toISOString(),
    status: "active",
  });
}

test("canonical action hash is stable and content-digest based", async () => {
  const a = await buildCanonicalAction({
    toolName: "ownmesh_fs_write",
    args: { path: "a.txt", content: "hello", device_id: "dev_x" },
    deviceId: "dev_x",
    principalId: "prin_a",
    tenantId: "ten_a",
    oauthClientId: "client_mcp",
  });
  const b = await buildCanonicalAction({
    toolName: "ownmesh_fs_write",
    args: { path: "a.txt", content: "hello", device_id: "dev_x" },
    deviceId: "dev_x",
    principalId: "prin_a",
    tenantId: "ten_a",
    oauthClientId: "client_mcp",
  });
  assert.equal(await hashCanonicalAction(a), await hashCanonicalAction(b));
  assert.equal((a.facts as { content_sha256: string }).content_sha256.length, 64);
  assert.equal((a.facts as { content?: string }).content, undefined);
  assert.equal(a.oauth_client_id, "client_mcp");

  const c = await buildCanonicalAction({
    toolName: "ownmesh_fs_write",
    args: { path: "a.txt", content: "HELLO", device_id: "dev_x" },
    deviceId: "dev_x",
    principalId: "prin_a",
    tenantId: "ten_a",
    oauthClientId: "client_mcp",
  });
  assert.notEqual(await hashCanonicalAction(a), await hashCanonicalAction(c));
});

test("bindCanonicalAction includes operation_id, expires_at, claim_version", async () => {
  const base = await buildCanonicalAction({
    toolName: "ownmesh_fs_write",
    args: { path: "a.txt", content: "hello" },
    deviceId: "dev_x",
    principalId: "prin_a",
    tenantId: "ten_a",
    oauthClientId: "client_a",
  });
  const expiresAt = "2030-01-01T00:00:00.000Z";
  const bound = await bindCanonicalAction(base, {
    operationId: "op_bind1",
    expiresAt,
    claimVersion: 1,
  });
  assert.equal(bound.bound.operation_id, "op_bind1");
  assert.equal(bound.bound.expires_at, expiresAt);
  assert.equal(bound.bound.claim_version, 1);
  assert.equal(bound.payload_hash.length, 64);
  assert.notEqual(bound.payload_hash, await hashCanonicalAction(base));
});

test("buildDeviceOperation always sets server payload_hash and wire binding fields", async () => {
  const expiresAt = new Date(Date.now() + 60_000).toISOString();
  const op = await buildDeviceOperation({
    toolName: "ownmesh_command_run",
    args: {
      program: "echo",
      args: ["x"],
      payload_hash: "0".repeat(64),
      allow: true,
      timeout_ms: 999_999_999,
      max_output_bytes: 50_000_000,
    },
    operationId: "op_test1",
    deviceId: "dev_1",
    principalId: "prin_1",
    tenantId: "ten_1",
    expiresAt,
    claimVersion: 1,
    oauthClientId: "client_mcp",
  });
  assert.equal(typeof op.payload_hash, "string");
  assert.equal(op.payload_hash.length, 64);
  assert.notEqual(op.payload_hash, "0".repeat(64));
  assert.equal(op.payload.payload_hash, op.payload_hash);
  // Authorization binding is on the wire so the Agent can recompute/verify.
  const auth = op.payload.authorization as { bound_action: Record<string, unknown> };
  assert.ok(auth && typeof auth.bound_action === "object");
  assert.equal(auth.bound_action.operation_id, "op_test1");
  assert.equal(auth.bound_action.expires_at, expiresAt);
  assert.equal(auth.bound_action.claim_version, 1);
  assert.equal(auth.bound_action.oauth_client_id, "client_mcp");
  assert.equal(await hashCanonicalAction(auth.bound_action), op.payload_hash);
  assert.equal(op.expires_at, expiresAt);
  assert.equal(op.claim_version, 1);
  assert.equal(op.oauth_client_id, "client_mcp");
  assert.equal(op.payload.expires_at, undefined);
  assert.equal((op.payload.arguments as Record<string, unknown>).allow, undefined);
  // Unsanitized build keeps raw numbers; sanitizeMcpArgs is applied at handleMcp.
  assert.equal(typeof (op.payload.arguments as Record<string, unknown>).timeout_ms, "number");
});

test("sanitizeMcpArgs enforces hard ceilings", () => {
  const out = sanitizeMcpArgs({
    timeout_ms: 9_999_999,
    max_output_bytes: 99_999_999,
    max_entries: 50_000,
    max_bytes: 9_000_000,
  });
  assert.equal(out.timeout_ms, MCP_MAX_TIMEOUT_MS);
  assert.equal(out.max_output_bytes, MCP_MAX_OUTPUT_BYTES);
  assert.equal(out.max_entries, 500);
  assert.equal(out.max_bytes, 512_000);
});

test("MCP idempotency mismatch fails closed without routing", async () => {
  const store = new MemoryStore();
  const tok = await seedAuthed(store);
  const deviceId = "dev_e3bind";
  await putActiveDevice(store, deviceId);
  await store.issueDeviceCredential((await store.getDevice(deviceId))!, 3_600_000);

  let routed = 0;
  const router: OperationRouter = {
    async routeToDevice() {
      routed += 1;
      return { status: "routed_to_device" };
    },
  };

  const firstAction = await buildCanonicalAction({
    toolName: "ownmesh_fs_write",
    args: { path: "x.txt", content: "v1" },
    deviceId,
    principalId: "prin_dev",
    tenantId: "ten_default",
    oauthClientId: "client_mcp",
  });
  const firstHash = await hashCanonicalAction(firstAction);
  const bound = await bindCanonicalAction(firstAction, {
    operationId: "op_prior_e3",
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    claimVersion: 1,
  });
  await store.putMcpOperation({
    operation_id: "op_prior_e3",
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: deviceId,
    tool: "ownmesh_fs_write",
    status: "completed",
    summary: "prior",
    data: { ok: true },
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: "op_prior_e3",
    payload_hash: bound.payload_hash,
    idempotency_key: "idem_e3_1",
    claim_version: 1,
    action: firstAction,
    policy_authority: "ownmesh_device",
    created_at: nowIso(),
    updated_at: nowIso(),
  });
  assert.equal(firstHash.length, 64);

  const call = async (content: string, id: number) => {
    const res = await handleMcp(
      new Request("https://cp.test/mcp", {
        method: "POST",
        headers: {
          authorization: `Bearer ${tok.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id,
          method: "tools/call",
          params: {
            name: "ownmesh_fs_write",
            arguments: {
              device_id: deviceId,
              path: "x.txt",
              content,
              async: true,
              idempotency_key: "idem_e3_1",
            },
          },
        }),
      }),
      store,
      new URL("https://cp.test/mcp"),
      router,
    );
    const body = (await res.json()) as {
      result?: { structuredContent?: Record<string, unknown> };
    };
    return body.result?.structuredContent || {};
  };

  const mismatch = await call("v2-different", 2);
  assert.equal(mismatch.status, "failed");
  const err = (mismatch.data as { error?: { code?: string } } | undefined)?.error;
  assert.equal(err?.code, "OWNMESH_E_IDEMPOTENCY_MISMATCH");
  assert.equal(routed, 0);

  const same = await call("v1", 3);
  assert.equal(same.operation_id, "op_prior_e3");
  assert.equal(same.status, "completed");
  assert.equal(routed, 0);
});

test("concurrent identical idempotency keys claim one owner (MemoryStore)", async () => {
  const store = new MemoryStore();
  const tok = await seedAuthed(store);
  const deviceId = "dev_e3race_m";
  await putActiveDevice(store, deviceId);
  await store.issueDeviceCredential((await store.getDevice(deviceId))!, 3_600_000);

  let routed = 0;
  const router: OperationRouter = {
    async routeToDevice() {
      routed += 1;
      return { status: "routed_to_device" };
    },
  };

  const call = (id: number) =>
    handleMcp(
      new Request("https://cp.test/mcp", {
        method: "POST",
        headers: {
          authorization: `Bearer ${tok.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id,
          method: "tools/call",
          params: {
            name: "ownmesh_fs_write",
            arguments: {
              device_id: deviceId,
              path: "race.txt",
              content: "same-body",
              async: true,
              idempotency_key: "idem_race_same",
            },
          },
        }),
      }),
      store,
      new URL("https://cp.test/mcp"),
      router,
    );

  const [r1, r2] = await Promise.all([call(1), call(2)]);
  const b1 = (await r1.json()) as { result?: { structuredContent?: Record<string, unknown> } };
  const b2 = (await r2.json()) as { result?: { structuredContent?: Record<string, unknown> } };
  const s1 = b1.result?.structuredContent || {};
  const s2 = b2.result?.structuredContent || {};
  assert.equal(s1.operation_id, s2.operation_id);
  assert.equal(routed, 1);
});

test("concurrent differing actions with same key: one owner, one mismatch (SqlStore)", async () => {
  const store = openSqlStore();
  const tok = await seedAuthed(store);
  const deviceId = "dev_e3race_s";
  await putActiveDevice(store, deviceId);
  await store.issueDeviceCredential((await store.getDevice(deviceId))!, 3_600_000);

  let routed = 0;
  const router: OperationRouter = {
    async routeToDevice() {
      routed += 1;
      return { status: "routed_to_device" };
    },
  };

  const call = (content: string, id: number) =>
    handleMcp(
      new Request("https://cp.test/mcp", {
        method: "POST",
        headers: {
          authorization: `Bearer ${tok.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id,
          method: "tools/call",
          params: {
            name: "ownmesh_fs_write",
            arguments: {
              device_id: deviceId,
              path: "race.txt",
              content,
              async: true,
              idempotency_key: "idem_race_diff",
            },
          },
        }),
      }),
      store,
      new URL("https://cp.test/mcp"),
      router,
    );

  const [r1, r2] = await Promise.all([call("body-a", 1), call("body-b", 2)]);
  const b1 = (await r1.json()) as { result?: { structuredContent?: Record<string, unknown> } };
  const b2 = (await r2.json()) as { result?: { structuredContent?: Record<string, unknown> } };
  const s1 = b1.result?.structuredContent || {};
  const s2 = b2.result?.structuredContent || {};
  const statuses = [String(s1.status || ""), String(s2.status || "")].sort();
  // Exactly one routes (pending), the other is mismatch failed — never two routes.
  assert.equal(routed, 1);
  assert.ok(statuses.includes("pending") || statuses.includes("running"));
  assert.ok(
    statuses.includes("failed"),
    `expected one failed mismatch, got ${JSON.stringify([s1, s2])}`,
  );
  const failed = [s1, s2].find((s) => s.status === "failed");
  const err = (failed?.data as { error?: { code?: string } } | undefined)?.error;
  assert.equal(err?.code, "OWNMESH_E_IDEMPOTENCY_MISMATCH");
});

test("mutating tools reject missing idempotency_key before route", async () => {
  const store = new MemoryStore();
  const tok = await seedAuthed(store);
  const deviceId = "dev_e3_idem_req";
  await putActiveDevice(store, deviceId);
  await store.issueDeviceCredential((await store.getDevice(deviceId))!, 3_600_000);

  let routed = 0;
  const router: OperationRouter = {
    async routeToDevice() {
      routed += 1;
      return { status: "routed_to_device" };
    },
  };

  const res = await handleMcp(
    new Request("https://cp.test/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${tok.access_token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "ownmesh_fs_write",
          arguments: {
            device_id: deviceId,
            path: "x.txt",
            content: "no-key",
            async: true,
          },
        },
      }),
    }),
    store,
    new URL("https://cp.test/mcp"),
    router,
  );
  const body = (await res.json()) as {
    error?: { code?: number; message?: string; data?: { code?: string } };
  };
  assert.equal(routed, 0);
  assert.equal(body.error?.code, -32602);
  assert.match(String(body.error?.message || ""), /idempotency_key required/i);
  assert.equal(body.error?.data?.code, "OWNMESH_E_IDEMPOTENCY_KEY_REQUIRED");
});

test("command env is normalized into canonical action facts", async () => {
  const safe = sanitizeMcpArgs({
    program: "echo",
    env: { Z_LAST: "z", A_FIRST: "a", BAD: 1 as unknown as string },
  });
  // Malformed env (non-string) is dropped entirely.
  assert.equal(safe.env, undefined);

  const ok = sanitizeMcpArgs({
    program: "echo",
    env: { Z_LAST: "z", A_FIRST: "a" },
  });
  assert.deepEqual(ok.env, { A_FIRST: "a", Z_LAST: "z" });
  assert.equal(normalizeCommandEnv({ "BAD=KEY": "x" }), undefined);

  const canonical = await buildCanonicalAction({
    toolName: "ownmesh_command_run",
    args: { program: "echo", args: ["hi"], env: { B: "2", A: "1" } },
    deviceId: "dev_env",
    principalId: "prin_env",
    tenantId: "ten_env",
  });
  assert.deepEqual((canonical.facts as { env?: Record<string, string> }).env, {
    A: "1",
    B: "2",
  });

  const op = await buildDeviceOperation({
    toolName: "ownmesh_command_run",
    args: {
      program: "echo",
      args: ["hi"],
      env: { OWNMESH_E2_ENV: "bound-ok" },
      idempotency_key: "idem_env_bind",
    },
    operationId: "op_env_bind",
    deviceId: "dev_env",
    principalId: "prin_env",
    tenantId: "ten_env",
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
  const facts = (op.bound_action.facts as { env?: Record<string, string> }).env;
  assert.deepEqual(facts, { OWNMESH_E2_ENV: "bound-ok" });
  assert.equal(
    (op.payload.arguments as { env?: Record<string, string> }).env?.OWNMESH_E2_ENV,
    "bound-ok",
  );
});

test("durable MCP operation records bound oversized data and enforce tenant quota", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const huge = "x".repeat(MCP_OPS_MAX_DATA_JSON_BYTES + 1024);
  const bounded = boundMcpOperationRecord({
    operation_id: "op_bound_data",
    tenant_id: "ten_quota",
    principal_id: "prin_quota",
    tool: "ownmesh_fs_read",
    status: "completed",
    summary: "ok",
    data: { content: huge },
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    policy_authority: "ownmesh_device",
    created_at: nowIso(),
    updated_at: nowIso(),
  });
  assert.equal(bounded.truncated, true);
  assert.ok(bounded.warnings.includes("durable_result_truncated"));
  assert.notEqual((bounded.data as { content?: string }).content, huge);

  for (let i = 0; i < MCP_OPS_MAX_PER_TENANT; i++) {
    await store.putMcpOperation({
      operation_id: `op_q_${i}`,
      tenant_id: "ten_quota",
      principal_id: "prin_quota",
      device_id: "dev_q",
      tool: "ownmesh_fs_stat",
      status: "completed",
      summary: "fill",
      data: { i },
      truncated: false,
      next_cursor: null,
      approval_required: false,
      warnings: [],
      idempotency_key: `idem_q_${i}`,
      policy_authority: "ownmesh_device",
      created_at: nowIso(),
      updated_at: nowIso(),
    });
  }
  await assert.rejects(
    () =>
      store.putMcpOperation({
        operation_id: "op_q_overflow",
        tenant_id: "ten_quota",
        principal_id: "prin_quota",
        device_id: "dev_q",
        tool: "ownmesh_fs_stat",
        status: "pending",
        summary: "overflow",
        data: {},
        truncated: false,
        next_cursor: null,
        approval_required: false,
        warnings: [],
        idempotency_key: "idem_q_overflow",
        policy_authority: "ownmesh_device",
        created_at: nowIso(),
        updated_at: nowIso(),
      }),
    /mcp_operation_quota_exceeded/,
  );

  // Same-key claim still works under quota pressure (replay safety).
  const claim = await store.claimMcpOperationByIdempotency({
    operation_id: "op_q_0_retry",
    tenant_id: "ten_quota",
    principal_id: "prin_quota",
    device_id: "dev_q",
    tool: "ownmesh_fs_stat",
    status: "pending",
    summary: "retry",
    data: {},
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    idempotency_key: "idem_q_0",
    policy_authority: "ownmesh_device",
    created_at: nowIso(),
    updated_at: nowIso(),
  });
  assert.equal(claim.outcome, "existing");
  assert.equal(claim.op.operation_id, "op_q_0");
});

test("dispatch outbox: crash after claim before route is redelivered on retry", async () => {
  const store = new MemoryStore();
  const token = await seedAuthed(store);
  const deviceId = "dev_dispatch_outbox";
  await putActiveDevice(store, deviceId);

  let routeCalls = 0;
  const bodies: string[] = [];
  const router: OperationRouter = {
    async routeToDevice(_id, op) {
      routeCalls += 1;
      bodies.push(JSON.stringify(op.payload));
      return { status: "routed_to_device", detail: { recipients: 1 } };
    },
  };

  // Pre-seed an accepted claim with pending dispatch outbox (Worker died post-claim).
  const deviceOp = await buildDeviceOperation({
    toolName: "ownmesh_fs_write",
    args: {
      device_id: deviceId,
      path: "crash.txt",
      content: "after-crash",
      idempotency_key: "idem_crash_dispatch",
    },
    operationId: "op_crash_dispatch_1",
    deviceId,
    principalId: "prin_dev",
    tenantId: "ten_default",
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
    claimVersion: 1,
    oauthClientId: "client_mcp",
  });
  const outbox = buildDispatchOutbox(deviceOp);
  assert.equal(outbox.state, "pending");
  assert.equal(needsDispatchRedelivery({ status: "pending", data: withDispatchOutbox({}, outbox) }), true);

  await store.putMcpOperation({
    operation_id: deviceOp.correlation_id,
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: deviceId,
    tool: "ownmesh_fs_write",
    status: "pending",
    summary: "operation accepted (async)",
    data: withDispatchOutbox(
      {
        tool: "ownmesh_fs_write",
        payload_hash: deviceOp.payload_hash,
      },
      outbox,
    ),
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: deviceOp.correlation_id,
    payload_hash: deviceOp.payload_hash,
    idempotency_key: "idem_crash_dispatch",
    expires_at: deviceOp.expires_at,
    claim_version: 1,
    action: deviceOp.canonical_action,
    policy_authority: "ownmesh_device",
    created_at: nowIso(),
    updated_at: nowIso(),
  });

  const callWrite = async (id: number) =>
    handleMcp(
      new Request("https://cp.test/mcp", {
        method: "POST",
        headers: {
          authorization: `Bearer ${token.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id,
          method: "tools/call",
          params: {
            name: "ownmesh_fs_write",
            arguments: {
              device_id: deviceId,
              path: "crash.txt",
              content: "after-crash",
              async: true,
              idempotency_key: "idem_crash_dispatch",
            },
          },
        }),
      }),
      store,
      new URL("https://cp.test/mcp"),
      { routeToDevice: router.routeToDevice },
      { issuer: "https://cp.test" },
    );

  // Retry identical action — must redeliver the bound body exactly once path.
  const retry = await callWrite(1);
  const retryBody = (await retry.json()) as {
    result?: { structuredContent?: { operation_id?: string; data?: Record<string, unknown> } };
    error?: unknown;
  };
  assert.equal(retryBody.error, undefined);
  assert.equal(routeCalls, 1, "pending outbox must be redelivered on retry");
  assert.equal(bodies.length, 1);
  assert.match(bodies[0]!, /after-crash/);

  const sc = retryBody.result?.structuredContent;
  assert.equal(sc?.operation_id, "op_crash_dispatch_1");
  // Client must never see the internal outbox key.
  assert.equal(sc?.data?.[DISPATCH_OUTBOX_KEY], undefined);
  assert.equal(stripDispatchOutbox(sc?.data || {})[DISPATCH_OUTBOX_KEY], undefined);

  const stored = await store.getMcpOperation("op_crash_dispatch_1");
  const storedBox = readDispatchOutbox(stored?.data || {});
  assert.equal(storedBox?.state, "dispatched");

  // Second retry must NOT re-route (already dispatched).
  const retry2 = await callWrite(2);
  const retry2Body = (await retry2.json()) as { error?: unknown };
  assert.equal(retry2Body.error, undefined);
  assert.equal(routeCalls, 1, "dispatched outbox must not re-route");
});

test("idempotency tombstones are retained under quota until 30-day window closes", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const tenant = "ten_tomb";
  const principal = "prin_tomb";
  const device = "dev_tomb";
  const now = Date.now();

  // Fill tenant to capacity with completed ops aged >7d so they compact to tombstones.
  for (let i = 0; i < MCP_OPS_MAX_PER_TENANT; i++) {
    const created = new Date(now - MCP_OPS_RESULT_TTL_MS - 60_000).toISOString();
    await store.putMcpOperation({
      operation_id: `op_tomb_${i}`,
      tenant_id: tenant,
      principal_id: principal,
      device_id: device,
      tool: "ownmesh_fs_write",
      status: "completed",
      summary: "done",
      data: { i },
      truncated: false,
      next_cursor: null,
      approval_required: false,
      warnings: [],
      payload_hash: `ph_${i}`,
      idempotency_key: `idem_tomb_${i}`,
      action: { tool: "ownmesh_fs_write", i },
      policy_authority: "ownmesh_device",
      created_at: created,
      updated_at: created,
    });
  }

  // Trigger compaction via a same-tenant claim attempt that must fail closed on quota
  // without deleting unexpired tombstones.
  await assert.rejects(
    () =>
      store.putMcpOperation({
        operation_id: "op_tomb_overflow",
        tenant_id: tenant,
        principal_id: principal,
        device_id: device,
        tool: "ownmesh_fs_stat",
        status: "pending",
        summary: "no",
        data: {},
        truncated: false,
        next_cursor: null,
        approval_required: false,
        warnings: [],
        idempotency_key: "idem_tomb_overflow",
        policy_authority: "ownmesh_device",
        created_at: nowIso(),
        updated_at: nowIso(),
      }),
    /mcp_operation_quota_exceeded/,
  );

  // Original key still resolves (tombstone retained inside 30d window).
  const existing = await store.getMcpOperationByIdempotency({
    principalId: principal,
    tenantId: tenant,
    deviceId: device,
    idempotencyKey: "idem_tomb_0",
  });
  assert.ok(existing, "unexpired idempotency receipt must survive quota pressure");
  assert.ok(
    existing.status === "tombstone" || existing.status === "completed",
    `status=${existing.status}`,
  );
  assert.equal(existing.idempotency_key, "idem_tomb_0");

  // Same-key claim still returns the owner rather than minting a new side effect.
  const claim = await store.claimMcpOperationByIdempotency({
    operation_id: "op_tomb_0_retry",
    tenant_id: tenant,
    principal_id: principal,
    device_id: device,
    tool: "ownmesh_fs_write",
    status: "pending",
    summary: "retry",
    data: {},
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    idempotency_key: "idem_tomb_0",
    action: { tool: "ownmesh_fs_write", i: 0 },
    policy_authority: "ownmesh_device",
    created_at: nowIso(),
    updated_at: nowIso(),
  });
  assert.equal(claim.outcome, "existing");
  assert.equal(claim.op.operation_id, "op_tomb_0");

  // Hard-expired tombstone (>30d) may be deleted; prove window constant is authoritative.
  assert.ok(MCP_OPS_TOMBSTONE_TTL_MS > MCP_OPS_RESULT_TTL_MS);
});
