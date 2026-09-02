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
  hashSemanticIdempotencyAction,
  handleMcp,
  needsDispatchRedelivery,
  normalizeCommandEnv,
  readDispatchOutbox,
  sanitizeMcpArgs,
  stripDispatchOutbox,
  withDispatchOutbox,
  MCP_MAX_OUTPUT_BYTES,
  MCP_MAX_READ_BYTES,
  MCP_MAX_TIMEOUT_MS,
  MCP_MAX_TIMEOUT_MS_DEFAULT,
  MCP_MAX_TIMEOUT_MS_HARD_CEILING,
  parseMcpMaxTimeoutMs,
  DISPATCH_OUTBOX_KEY,
  type OperationRouter,
} from "./mcp.ts";
import {
  MemoryStore,
  SqlStore,
  MCP_OPS_MAX_DATA_JSON_BYTES,
  MCP_OPS_MAX_DISPATCH_OUTBOX_BYTES,
  MCP_OPS_MAX_PER_TENANT,
  MCP_OPS_MAX_PER_TENANT_DEFAULT,
  MCP_OPS_MAX_PER_TENANT_HARD_CEILING,
  MCP_OPS_QUOTA_PRESSURE_RATIO,
  MCP_OPS_RESULT_TTL_MS,
  MCP_OPS_TOMBSTONE_TTL_MS,
  parseMcpOpsMaxPerTenant,
  boundClientVisibleOperationData,
  boundMcpOperationRecord,
  type SqlDatabase,
  type SqlStatement,
} from "./store.ts";
import { hashCanonicalAction, nowIso } from "./util.ts";
import { applyMcpOperationResult } from "./device-room.ts";
import { __test } from "./index.ts";

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

function openSqlStore(opts?: { mcpOpsMaxPerTenant?: number }): SqlStore {
  const db = new DatabaseSync(":memory:");
  for (const f of readdirSync(migrationsDir).filter((x) => x.endsWith(".sql")).sort()) {
    db.exec(readFileSync(join(migrationsDir, f), "utf8"));
  }
  return new SqlStore(adaptSqlite(db), "sqlite", opts);
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
    principalCredentialGeneration: 1,
    principalRevocationEpoch: 1,
    oauthClientId: "client_mcp",
  });
  const b = await buildCanonicalAction({
    toolName: "ownmesh_fs_write",
    args: { path: "a.txt", content: "hello", device_id: "dev_x" },
    deviceId: "dev_x",
    principalId: "prin_a",
    tenantId: "ten_a",
    principalCredentialGeneration: 1,
    principalRevocationEpoch: 1,
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
    principalCredentialGeneration: 1,
    principalRevocationEpoch: 1,
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
    principalCredentialGeneration: 1,
    principalRevocationEpoch: 1,
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

test("principal credential generation is durable, rotates on credential changes, and binds public device operations", async () => {
  for (const store of [new MemoryStore(), openSqlStore()] as const) {
    const token = await seedAuthed(store);
    const principal = await store.getPrincipal("prin_dev");
    assert.equal(principal?.credential_generation, 1);

    const rotated = await store.rotateRefresh(token.refresh_token);
    assert.equal(rotated.ok, true);
    if (!rotated.ok) continue;
    assert.equal((await store.getPrincipal("prin_dev"))?.credential_generation, 2);

    await store.revokeToken(rotated.token.access_token);
    const current = await store.getPrincipal("prin_dev");
    assert.equal(current?.credential_generation, 3);
    const readiness = await store.schemaReadiness();
    assert.equal(readiness.checks.principals_credential_generation, true);

    const before = await buildCanonicalAction({
      toolName: "ownmesh_fs_list", args: { path: "/" }, deviceId: "dev_credential",
      principalId: "prin_dev", tenantId: "ten_default", principalCredentialGeneration: 2, principalRevocationEpoch: 1,
    });
    const after = await buildCanonicalAction({
      toolName: "ownmesh_fs_list", args: { path: "/" }, deviceId: "dev_credential",
      principalId: "prin_dev", tenantId: "ten_default", principalCredentialGeneration: 3, principalRevocationEpoch: 1,
    });
    assert.notEqual(await hashCanonicalAction(before), await hashCanonicalAction(after));
    assert.equal(
      await hashSemanticIdempotencyAction(before),
      await hashSemanticIdempotencyAction(after),
    );

    const fresh = await store.issueTokens(
      "client_mcp", "prin_dev", "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device",
    );
    const deviceId = `dev_credential_${store.kind}`;
    await putActiveDevice(store, deviceId);
    await store.issueDeviceCredential((await store.getDevice(deviceId))!, 3_600_000);
    let routed: Record<string, unknown> | undefined;
    const response = await handleMcp(
      new Request("https://cp.test/mcp", {
        method: "POST",
        headers: { authorization: `Bearer ${fresh.access_token}`, "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0", id: `credential-${store.kind}`, method: "tools/call",
          params: {
            name: "ownmesh_fs_list",
            arguments: { device_id: deviceId, workspace_id: null, path: "/" },
          },
        }),
      }),
      store,
      new URL("https://cp.test/mcp"),
      {
        async routeToDevice(_deviceId, operation) {
          routed = operation.payload;
          return { status: "routed_to_device" };
        },
      },
    );
    assert.equal(response.status, 200);
    const bound = ((routed?.authorization as { bound_action?: Record<string, unknown> })?.bound_action);
    assert.equal(bound?.principal_credential_generation, 3);
    assert.equal(routed?.payload_hash, await hashCanonicalAction(bound!));
  }
});

// #162: the E3 redelivery gate spans real wall-clock time, so it is the gate a
// routine 15-minute rotation actually crosses. A refresh must not terminate a
// queued operation; a revocation still must.
test("idempotency retry survives a routine refresh and still dies on revocation", async () => {
  const store = new MemoryStore();
  const tok = await seedAuthed(store);
  const deviceId = "dev_e3_rotation_retry";
  await putActiveDevice(store, deviceId);
  await store.issueDeviceCredential((await store.getDevice(deviceId))!, 3_600_000);

  let routed = 0;
  const router: OperationRouter = {
    async routeToDevice() {
      routed += 1;
      return { status: "dispatch_uncertain" };
    },
  };
  const call = async (idempotencyKey: string, id: number, accessToken: string) => {
    const response = await handleMcp(
      new Request("https://cp.test/mcp", {
        method: "POST",
        headers: {
          authorization: `Bearer ${accessToken}`,
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
              workspace_id: null,
              path: "/rotation.txt",
              content: "same semantic action",
              async: true,
              idempotency_key: idempotencyKey,
            },
          },
        }),
      }),
      store,
      new URL("https://cp.test/mcp"),
      router,
    );
    const body = (await response.json()) as {
      result?: { structuredContent?: Record<string, unknown> };
    };
    return body.result?.structuredContent || {};
  };

  const first = await call("idem_rotation_stable", 1, tok.access_token);
  const firstId = String(first.operation_id);
  assert.match(firstId, /^op_/);
  assert.equal(routed, 1);
  const bound = await store.getMcpOperation(firstId);
  assert.equal(bound?.action?.principal_credential_generation, 1);
  assert.equal(bound?.action?.principal_revocation_epoch, 1);

  // A real refresh rotation: the issuance generation advances, the revocation
  // epoch does not.
  const rotated = await store.rotateRefresh(tok.refresh_token);
  assert.equal(rotated.ok, true);
  if (!rotated.ok) return;
  const after = (await store.getPrincipal("prin_dev"))!;
  assert.equal(after.credential_generation, 2);
  assert.equal(after.revocation_epoch, 1);

  // The retry converges on the original operation and stays deliverable. It is
  // the *same* bound body being redelivered exactly once per retry (the first
  // route returned dispatch_uncertain), never a second execution.
  const refreshed = await call("idem_rotation_stable", 2, rotated.token.access_token);
  assert.equal(refreshed.operation_id, firstId);
  assert.equal(refreshed.status, "pending", "a routine refresh must not terminate a queued op");
  assert.equal(routed, 2, "the original bound body is redelivered, not re-executed");
  const stillBound = await store.getMcpOperation(firstId);
  assert.equal(stillBound?.action?.principal_credential_generation, 1);
  assert.equal(stillBound?.action?.principal_revocation_epoch, 1);

  // Revocation is a withdrawal of authority and still terminates it.
  assert.equal(await store.advancePrincipalRevocationEpoch("prin_dev", "explicit_revocation"), 2);
  const revokedRetry = await call("idem_rotation_stable", 3, rotated.token.access_token);
  assert.equal(revokedRetry.operation_id, firstId);
  assert.equal(revokedRetry.status, "failed");
  const error = (revokedRetry.data as { error?: Record<string, unknown> } | undefined)?.error;
  assert.equal(error?.code, "OWNMESH_E_PRINCIPAL_CREDENTIAL_GENERATION_MISMATCH");
  assert.equal(error?.retryable, false);
  // The bounded reason survives the public compaction, not just the durable row.
  assert.equal((error?.details as { reason?: string } | undefined)?.reason, "explicit_revocation");
  assert.equal(routed, 2, "a revoked operation is never dispatched again");
  assert.equal(
    (await store.getMcpOperation(firstId))?.action?.principal_revocation_epoch,
    1,
    "the old operation is never rebound to the new epoch",
  );

  // Recovery is a *fresh* request under the current authority, never a retry of
  // the old binding: a new key mints a distinct operation bound to the new
  // epoch, and that one does dispatch.
  const fresh = await call("idem_rotation_fresh", 4, rotated.token.access_token);
  const freshId = String(fresh.operation_id);
  assert.notEqual(freshId, firstId, "a fresh key must not converge on the terminated operation");
  assert.equal(routed, 3);
  assert.equal((await store.getMcpOperation(freshId))?.action?.principal_revocation_epoch, 2);
});

test("idempotency retry cannot redeliver an outbox after cancel_requested wins", async () => {
  const store = new MemoryStore();
  const tok = await seedAuthed(store);
  const deviceId = "dev_e3_cancelled_retry";
  await putActiveDevice(store, deviceId);
  await store.issueDeviceCredential((await store.getDevice(deviceId))!, 3_600_000);

  let routed = 0;
  const call = async (id: number) => {
    const response = await handleMcp(
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
              workspace_id: null,
              path: "/cancelled-retry.txt",
              content: "must not be redelivered",
              async: true,
              idempotency_key: "idem_cancelled_retry",
            },
          },
        }),
      }),
      store,
      new URL("https://cp.test/mcp"),
      {
        async routeToDevice() {
          routed += 1;
          return { status: "dispatch_uncertain" };
        },
      },
    );
    const body = (await response.json()) as {
      result?: { structuredContent?: Record<string, unknown> };
    };
    return body.result?.structuredContent || {};
  };

  const first = await call(1);
  const operationId = String(first.operation_id);
  assert.equal(first.status, "pending");
  assert.equal(routed, 1);
  assert.equal(readDispatchOutbox((await store.getMcpOperation(operationId))?.data || {})?.state, "pending");
  assert.ok(await store.updateMcpOperation(
    operationId,
    { status: "cancel_requested", summary: "cancel requested; device signal pending" },
    ["pending"],
  ));

  const retry = await call(2);
  assert.equal(retry.operation_id, operationId);
  assert.equal(retry.status, "cancel_requested");
  assert.equal(routed, 1, "cancel_requested must fence Worker outbox redelivery");
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
    principalCredentialGeneration: 1,
    principalRevocationEpoch: 1,
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
  assert.equal(out.max_bytes, MCP_MAX_READ_BYTES);
});

test("sanitizeMcpArgs strips hidden session command/cwd and client authority", () => {
  const out = sanitizeMcpArgs(
    {
      device_id: "dev_x",
      workspace_id: "ws_default",
      idempotency_key: "k1",
      program: "/bin/sh",
      args: ["-c", "touch /tmp/x"],
      // Not in ownmesh_session_open schema — must never reach the device.
      command: ["/bin/sh", "-c", "touch /tmp/ownmesh-policy-bypass"],
      cwd: "/tmp",
      allow: true,
      skip_approval: true,
      force_allow: true,
      async: true,
    },
    "ownmesh_session_open",
  );
  assert.equal(out.program, "/bin/sh");
  assert.deepEqual(out.args, ["-c", "touch /tmp/x"]);
  assert.equal(out.command, undefined);
  assert.equal(out.cwd, undefined);
  assert.equal(out.allow, undefined);
  assert.equal(out.skip_approval, undefined);
  assert.equal(out.force_allow, undefined);
  assert.equal(out.async, true);
  assert.equal(out.workspace_id, "ws_default");
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
    args: { workspace_id: null, path: "/x.txt", content: "v1" },
    deviceId,
    principalId: "prin_dev",
    tenantId: "ten_default",
    principalCredentialGeneration: 1,
    principalRevocationEpoch: 1,
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
              workspace_id: null,
              path: "/x.txt",
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
              workspace_id: null,
              path: "/race.txt",
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
              workspace_id: null,
              path: "/race.txt",
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
            workspace_id: null,
            path: "/x.txt",
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
    principalCredentialGeneration: 1,
    principalRevocationEpoch: 1,
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
    principalCredentialGeneration: 1,
    principalRevocationEpoch: 1,
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
  const quotaCap = 8;
  const store = new MemoryStore({ mcpOpsMaxPerTenant: quotaCap });
  await store.ensureBootstrap();
  const huge = "x".repeat(MCP_OPS_MAX_DATA_JSON_BYTES + 1024);
  const bounded = boundMcpOperationRecord({
    operation_id: "op_bound_data",
    tenant_id: "ten_quota",
    principal_id: "prin_quota",
    tool: "ownmesh_fs_read",
    status: "completed",
    summary: "ok",
    data: {
      content: huge,
      encoding: "utf-8",
      path: "big.txt",
      sha256: "abc",
      next_offset: 160000,
      returned_bytes: 160000,
      total_bytes: 512000,
      truncated: true,
    },
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
  // Cursor / integrity facts must survive durable truncation.
  assert.equal((bounded.data as { next_offset?: number }).next_offset, 160000);
  assert.equal((bounded.data as { sha256?: string }).sha256, "abc");
  assert.equal((bounded.data as { path?: string }).path, "big.txt");
  assert.equal(bounded.next_cursor, "off_160000");

  for (let i = 0; i < quotaCap; i++) {
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
      workspace_id: null,
      path: "/crash.txt",
      content: "after-crash",
      idempotency_key: "idem_crash_dispatch",
    },
    operationId: "op_crash_dispatch_1",
    deviceId,
    principalId: "prin_dev",
    tenantId: "ten_default",
    principalCredentialGeneration: 1,
    principalRevocationEpoch: 1,
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
              workspace_id: null,
              path: "/crash.txt",
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

test("get_operation leases and redelivers dispatch_uncertain without original tool retry", async () => {
  const store = new MemoryStore();
  const token = await seedAuthed(store);
  const deviceId = "dev_poll_redelivery";
  await putActiveDevice(store, deviceId);
  const deviceOp = await buildDeviceOperation({
    toolName: "ownmesh_fs_write",
    args: {
      device_id: deviceId,
      workspace_id: null,
      path: "/poll-redelivery.txt",
      content: "exact-once",
      idempotency_key: "idem_poll_redelivery",
    },
    operationId: "op_poll_redelivery",
    deviceId,
    principalId: "prin_dev",
    tenantId: "ten_default",
    principalCredentialGeneration: 1,
    principalRevocationEpoch: 1,
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
    claimVersion: 1,
    oauthClientId: "client_mcp",
  });
  await store.putMcpOperation({
    operation_id: "op_poll_redelivery",
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: deviceId,
    tool: "ownmesh_fs_write",
    status: "pending",
    summary: "dispatch_uncertain",
    data: withDispatchOutbox({ dispatch: "uncertain" }, buildDispatchOutbox(deviceOp)),
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: "op_poll_redelivery",
    payload_hash: deviceOp.payload_hash,
    idempotency_key: "idem_poll_redelivery",
    expires_at: deviceOp.expires_at,
    claim_version: 1,
    action: deviceOp.canonical_action,
    policy_authority: "ownmesh_device",
    created_at: nowIso(),
    updated_at: nowIso(),
  });

  let routeCalls = 0;
  const router: OperationRouter = {
    async routeToDevice(_id, operation) {
      routeCalls += 1;
      assert.equal(operation.correlation_id, "op_poll_redelivery");
      return { status: "routed_to_device" };
    },
  };
  await store.putClient({
    client_id: "client_observer",
    tenant_id: "ten_default",
    client_name: "Observer",
    redirect_uris: ["https://cp.test/observer"],
    created_at: nowIso(),
  });
  const observer = await store.issueTokens("client_observer", "prin_dev", "ownmesh.read");
  const poll = (accessToken = token.access_token) => handleMcp(
    new Request("https://cp.test/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${accessToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "ownmesh_get_operation",
          arguments: { operation_id: "op_poll_redelivery" },
        },
      }),
    }),
    store,
    new URL("https://cp.test/mcp"),
    router,
    { issuer: "https://cp.test" },
  );

  const observed = await poll(observer.access_token);
  assert.equal(observed.status, 200);
  assert.equal(routeCalls, 0, "a different read-only OAuth client cannot trigger redelivery");

  const first = await poll();
  assert.equal(first.status, 200);
  assert.equal(routeCalls, 1);
  assert.equal(readDispatchOutbox((await store.getMcpOperation("op_poll_redelivery"))?.data)?.state, "dispatched");
  await poll();
  assert.equal(routeCalls, 1, "dispatched receipt must suppress status-poll amplification");
});

test("dispatch_uncertain: timeout keeps pending outbox; delayed result finalizes; retry does not rerun", async () => {
  const store = new MemoryStore();
  const token = await seedAuthed(store);
  const deviceId = "dev_dispatch_uncertain";
  await putActiveDevice(store, deviceId);

  const TEST_SECRET = "test-session-secret-dispatch-uncertain-01";
  let acceptCount = 0;
  // Delayed accept: Worker race times out before the DO HTTP response returns,
  // but the body is treated as potentially durable (post-send).
  const delayedRoom = {
    idFromName: () => ({}) as DurableObjectId,
    get: () =>
      ({
        fetch: async () => {
          acceptCount += 1;
          await new Promise((r) => setTimeout(r, 40));
          return Response.json({
            status: "routed_to_device",
            detail: { recipients: 1, accepted_after_ms: 40 },
          });
        },
      }) as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;

  const router: OperationRouter = {
    routeToDevice: (id, op) =>
      __test.routeToDeviceRoom(
        {
          DEVICE_ROOM: delayedRoom,
          SESSION_SECRET: TEST_SECRET,
          OWNMESH_DEVICE_ROUTE_TIMEOUT_MS: "5",
        },
        id,
        op,
        { principal_id: "prin_dev", tenant_id: "ten_default" },
      ),
  };

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
              workspace_id: null,
              path: "/uncertain.txt",
              content: "once-only",
              async: true,
              idempotency_key: "idem_uncertain_dispatch",
            },
          },
        }),
      }),
      store,
      new URL("https://cp.test/mcp"),
      { routeToDevice: router.routeToDevice },
      { issuer: "https://cp.test" },
    );

  const first = await callWrite(1);
  const firstBody = (await first.json()) as {
    result?: {
      structuredContent?: {
        status?: string;
        operation_id?: string;
        summary?: string;
        correlation_id?: string;
        data?: { dispatch?: string };
      };
    };
    error?: unknown;
  };
  assert.equal(firstBody.error, undefined);
  const sc = firstBody.result?.structuredContent;
  assert.equal(sc?.status, "pending");
  assert.equal(sc?.summary, "dispatch_uncertain");
  assert.equal(sc?.data?.dispatch, "uncertain");
  assert.ok(sc?.operation_id);
  assert.ok(acceptCount >= 1, "DO fetch must have been initiated before timeout");

  const opId = sc!.operation_id!;
  const storedPending = await store.getMcpOperation(opId);
  assert.equal(storedPending?.status, "pending");
  const boxPending = readDispatchOutbox(storedPending?.data || {});
  assert.equal(boxPending?.state, "pending", "uncertain must not mark outbox dispatched");
  assert.equal(needsDispatchRedelivery(storedPending!), true);

  // Delayed agent completion must still CAS-finalize the pending operation.
  const applied = await applyMcpOperationResult(store, {
    operationId: opId,
    correlationId: storedPending!.correlation_id,
    deviceId,
    payload: {
      operation_id: opId,
      status: "completed",
      summary: "write completed after uncertain dispatch",
      result: {
        path: "/uncertain.txt",
        bytes_written: 9,
        workspace_id: null,
        workspace_version: null,
      },
    },
  });
  assert.equal(applied.ok, true);
  if (applied.ok && applied.record) {
    assert.equal(applied.record.status, "completed");
  }
  assert.equal((await store.getMcpOperation(opId))?.status, "completed");

  // Identical idempotent retry must replay completed receipt — no second side effect.
  const acceptsBeforeRetry = acceptCount;
  const retry = await callWrite(2);
  const retryBody = (await retry.json()) as {
    result?: { structuredContent?: { status?: string; operation_id?: string } };
    error?: unknown;
  };
  assert.equal(retryBody.error, undefined);
  assert.equal(retryBody.result?.structuredContent?.status, "completed");
  assert.equal(retryBody.result?.structuredContent?.operation_id, opId);
  assert.equal(
    acceptCount,
    acceptsBeforeRetry,
    "completed ops must not redeliver / re-accept on same idempotency key",
  );
});

test("dispatch_uncertain: pending outbox is redelivered on identical retry", async () => {
  const store = new MemoryStore();
  const token = await seedAuthed(store);
  const deviceId = "dev_uncertain_redeliver";
  await putActiveDevice(store, deviceId);

  let routeCalls = 0;
  const statuses: string[] = [];
  const router: OperationRouter = {
    async routeToDevice(_id, _op) {
      routeCalls += 1;
      if (routeCalls === 1) {
        statuses.push("dispatch_uncertain");
        return {
          status: "dispatch_uncertain",
          detail: { error: "device_room_fetch_timeout", timeout_ms: 5 },
        };
      }
      statuses.push("routed_to_device");
      return { status: "routed_to_device", detail: { recipients: 1 } };
    },
  };

  const callList = async (id: number) =>
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
            name: "ownmesh_fs_list",
            arguments: {
              device_id: deviceId,
              workspace_id: null,
              path: "/",
              async: true,
              idempotency_key: "idem_uncertain_redeliver",
            },
          },
        }),
      }),
      store,
      new URL("https://cp.test/mcp"),
      { routeToDevice: router.routeToDevice },
      { issuer: "https://cp.test" },
    );

  const first = await callList(1);
  const firstBody = (await first.json()) as {
    result?: { structuredContent?: { status?: string; operation_id?: string } };
  };
  assert.equal(firstBody.result?.structuredContent?.status, "pending");
  const opId = firstBody.result!.structuredContent!.operation_id!;
  assert.equal(readDispatchOutbox((await store.getMcpOperation(opId))?.data || {})?.state, "pending");

  const retry = await callList(2);
  const retryBody = (await retry.json()) as {
    result?: { structuredContent?: { status?: string; operation_id?: string } };
  };
  assert.equal(retryBody.result?.structuredContent?.operation_id, opId);
  assert.equal(routeCalls, 2, "pending uncertain outbox must redeliver");
  assert.deepEqual(statuses, ["dispatch_uncertain", "routed_to_device"]);
  assert.equal(readDispatchOutbox((await store.getMcpOperation(opId))?.data || {})?.state, "dispatched");
});

test("idempotency tombstones are retained under quota until 30-day window closes", async () => {
  const quotaCap = 8;
  const store = new MemoryStore({ mcpOpsMaxPerTenant: quotaCap });
  await store.ensureBootstrap();
  const tenant = "ten_tomb";
  const principal = "prin_tomb";
  const device = "dev_tomb";
  const now = Date.now();

  // Fill tenant to capacity with completed ops aged >7d so they compact to tombstones.
  for (let i = 0; i < quotaCap; i++) {
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

/**
 * P0-B review (lazy tombstone expiry): a tombstone older than the 30-day
 * idempotency window must be hard-deleted before the existing-row lookup, so a
 * same-key retry is dispatched as a fresh operation instead of returning the
 * stale tombstone as `existing` forever. Both store implementations previously
 * returned the existing row before running quota cleanup, which could block
 * reuse of an expired key indefinitely.
 */
test("expired idempotency tombstones are hard-deleted so the key becomes reusable", async () => {
  for (const store of [new MemoryStore(), openSqlStore()] as const) {
    await store.ensureBootstrap();
    const tenant = `ten_expired_${store.kind}`;
    const principal = "prin_expired";
    const device = "dev_expired";
    const ancient = new Date(Date.now() - MCP_OPS_RESULT_TTL_MS - 60_000).toISOString();

    // Completed op bound to the key, aged past the result TTL so the next
    // quota pass compacts it to an idempotency tombstone.
    await store.putMcpOperation({
      operation_id: "op_expired_1",
      tenant_id: tenant,
      principal_id: principal,
      device_id: device,
      tool: "ownmesh_fs_write",
      status: "completed",
      summary: "done",
      data: {},
      truncated: false,
      next_cursor: null,
      approval_required: false,
      warnings: [],
      payload_hash: "ph_expired_1",
      idempotency_key: "idem_expired_1",
      action: { tool: "ownmesh_fs_write" },
      policy_authority: "ownmesh_device",
      created_at: ancient,
      updated_at: ancient,
    });
    // Trigger quota compaction to a tombstone with a same-tenant fresh op.
    await store.putMcpOperation({
      operation_id: "op_expired_trigger",
      tenant_id: tenant,
      principal_id: principal,
      device_id: device,
      tool: "ownmesh_fs_stat",
      status: "pending",
      summary: "trigger",
      data: {},
      truncated: false,
      next_cursor: null,
      approval_required: false,
      warnings: [],
      idempotency_key: "idem_expired_trigger",
      policy_authority: "ownmesh_device",
      created_at: nowIso(),
      updated_at: nowIso(),
    });
    const tombstone = await store.getMcpOperation("op_expired_1");
    assert.ok(tombstone, `${store.kind}: op must still exist as a tombstone`);
    assert.equal(tombstone.status, "tombstone");
    // Age the tombstone past the 30-day hard-delete window.
    await store.updateMcpOperation("op_expired_1", {
      updated_at: new Date(Date.now() - MCP_OPS_TOMBSTONE_TTL_MS - 60_000).toISOString(),
    });
    // Same-key claim must now mint a FRESH operation, not return the stale
    // tombstone as `existing` forever.
    const claim = await store.claimMcpOperationByIdempotency({
      operation_id: "op_expired_retry",
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
      idempotency_key: "idem_expired_1",
      action: { tool: "ownmesh_fs_write" },
      policy_authority: "ownmesh_device",
      created_at: nowIso(),
      updated_at: nowIso(),
    });
    assert.equal(
      claim.outcome,
      "created",
      `${store.kind}: an expired tombstone must not block key reuse forever`,
    );
    assert.equal(claim.op.operation_id, "op_expired_retry");
    // The old tombstone is gone.
    assert.equal(await store.getMcpOperation("op_expired_1"), null);
  }
});

test("MCP_MAX_TIMEOUT_MS env parsing fails closed to the documented default", () => {
  assert.equal(parseMcpMaxTimeoutMs(undefined), MCP_MAX_TIMEOUT_MS_DEFAULT);
  assert.equal(parseMcpMaxTimeoutMs(""), MCP_MAX_TIMEOUT_MS_DEFAULT);
  assert.equal(parseMcpMaxTimeoutMs("nope"), MCP_MAX_TIMEOUT_MS_DEFAULT);
  assert.equal(parseMcpMaxTimeoutMs(0), MCP_MAX_TIMEOUT_MS_DEFAULT);
  assert.equal(parseMcpMaxTimeoutMs(-4), MCP_MAX_TIMEOUT_MS_DEFAULT);
  assert.equal(parseMcpMaxTimeoutMs("8"), 8);
  assert.equal(parseMcpMaxTimeoutMs(8), 8);
  assert.equal(parseMcpMaxTimeoutMs(String(MCP_MAX_TIMEOUT_MS_HARD_CEILING + 1)), MCP_MAX_TIMEOUT_MS_HARD_CEILING);
  assert.equal(MCP_MAX_TIMEOUT_MS, MCP_MAX_TIMEOUT_MS_DEFAULT);
});

test("sanitizeMcpArgs clamps timeout_ms to the operator-configured ceiling", () => {
  const defaulted = sanitizeMcpArgs({ timeout_ms: 999_999_999 }, "ownmesh_command_run");
  assert.equal(defaulted.timeout_ms, MCP_MAX_TIMEOUT_MS_DEFAULT);
  const raised = sanitizeMcpArgs(
    { timeout_ms: 999_999_999 },
    "ownmesh_command_run",
    { maxTimeoutMs: MCP_MAX_TIMEOUT_MS_HARD_CEILING },
  );
  assert.equal(raised.timeout_ms, MCP_MAX_TIMEOUT_MS_HARD_CEILING);
});

test("MCP_OPS_MAX_PER_TENANT env parsing fails closed to the documented default", () => {
  assert.equal(parseMcpOpsMaxPerTenant(undefined), MCP_OPS_MAX_PER_TENANT_DEFAULT);
  assert.equal(parseMcpOpsMaxPerTenant(""), MCP_OPS_MAX_PER_TENANT_DEFAULT);
  assert.equal(parseMcpOpsMaxPerTenant("nope"), MCP_OPS_MAX_PER_TENANT_DEFAULT);
  assert.equal(parseMcpOpsMaxPerTenant(0), MCP_OPS_MAX_PER_TENANT_DEFAULT);
  assert.equal(parseMcpOpsMaxPerTenant(-4), MCP_OPS_MAX_PER_TENANT_DEFAULT);
  assert.equal(parseMcpOpsMaxPerTenant("8"), 8);
  assert.equal(parseMcpOpsMaxPerTenant(8), 8);
  assert.equal(parseMcpOpsMaxPerTenant(String(MCP_OPS_MAX_PER_TENANT_HARD_CEILING + 1)), MCP_OPS_MAX_PER_TENANT_HARD_CEILING);
  assert.equal(MCP_OPS_MAX_PER_TENANT, MCP_OPS_MAX_PER_TENANT_DEFAULT);
  assert.equal(MCP_OPS_QUOTA_PRESSURE_RATIO, 0.6);
});

test("configured tenant quota is the cap used by both stores", async () => {
  const quotaCap = 3;
  for (const store of [
    new MemoryStore({ mcpOpsMaxPerTenant: quotaCap }),
    openSqlStore({ mcpOpsMaxPerTenant: quotaCap }),
  ] as const) {
    await store.ensureBootstrap();
    const tenant = `ten_cfg_${store.kind}`;
    assert.equal(store.mcpOpsMaxPerTenant(), quotaCap);
    for (let i = 0; i < quotaCap; i++) {
      await store.putMcpOperation({
        operation_id: `op_cfg_${store.kind}_${i}`,
        tenant_id: tenant,
        principal_id: "prin_cfg",
        device_id: "dev_cfg",
        tool: "ownmesh_fs_stat",
        status: "completed",
        summary: "fill",
        data: { i },
        truncated: false,
        next_cursor: null,
        approval_required: false,
        warnings: [],
        idempotency_key: `idem_cfg_${i}`,
        policy_authority: "ownmesh_device",
        created_at: nowIso(),
        updated_at: nowIso(),
      });
    }
    const quota = await store.getMcpOperationQuota(tenant);
    assert.equal(quota.rows, quotaCap);
    assert.equal(quota.limit, quotaCap);
    assert.equal(quota.status, "critical");
    await assert.rejects(
      () =>
        store.putMcpOperation({
          operation_id: `op_cfg_${store.kind}_overflow`,
          tenant_id: tenant,
          principal_id: "prin_cfg",
          device_id: "dev_cfg",
          tool: "ownmesh_fs_stat",
          status: "pending",
          summary: "overflow",
          data: {},
          truncated: false,
          next_cursor: null,
          approval_required: false,
          warnings: [],
          idempotency_key: "idem_cfg_overflow",
          policy_authority: "ownmesh_device",
          created_at: nowIso(),
          updated_at: nowIso(),
        }),
      /mcp_operation_quota_exceeded/,
    );
  }
});

test("keyless terminal rows are hard-deleted at result TTL instead of tombstoned", async () => {
  for (const store of [new MemoryStore(), openSqlStore()] as const) {
    await store.ensureBootstrap();
    const tenant = `ten_keyless_${store.kind}`;
    const ancient = new Date(Date.now() - MCP_OPS_RESULT_TTL_MS - 60_000).toISOString();
    await store.putMcpOperation({
      operation_id: "op_keyless_old",
      tenant_id: tenant,
      principal_id: "prin_keyless",
      device_id: "dev_keyless",
      tool: "ownmesh_fs_read",
      status: "completed",
      summary: "read page",
      data: { content: "x" },
      truncated: false,
      next_cursor: null,
      approval_required: false,
      warnings: [],
      idempotency_key: null,
      policy_authority: "ownmesh_device",
      created_at: ancient,
      updated_at: ancient,
    });
    await store.putMcpOperation({
      operation_id: "op_keyed_old",
      tenant_id: tenant,
      principal_id: "prin_keyless",
      device_id: "dev_keyless",
      tool: "ownmesh_fs_write",
      status: "completed",
      summary: "write",
      data: {},
      truncated: false,
      next_cursor: null,
      approval_required: false,
      warnings: [],
      idempotency_key: "idem_keyed_old",
      payload_hash: "ph_keyed",
      policy_authority: "ownmesh_device",
      created_at: ancient,
      updated_at: ancient,
    });
    await store.putMcpOperation({
      operation_id: "op_keyless_trigger",
      tenant_id: tenant,
      principal_id: "prin_keyless",
      device_id: "dev_keyless",
      tool: "ownmesh_fs_stat",
      status: "pending",
      summary: "trigger compact",
      data: {},
      truncated: false,
      next_cursor: null,
      approval_required: false,
      warnings: [],
      idempotency_key: "idem_keyless_trigger",
      policy_authority: "ownmesh_device",
      created_at: nowIso(),
      updated_at: nowIso(),
    });
    assert.equal(
      await store.getMcpOperation("op_keyless_old"),
      null,
      `${store.kind}: keyless terminal row must not occupy a tombstone slot`,
    );
    const keyed = await store.getMcpOperation("op_keyed_old");
    assert.ok(keyed, `${store.kind}: keyed receipt must remain`);
    assert.equal(keyed.status, "tombstone");
    assert.equal(keyed.idempotency_key, "idem_keyed_old");
  }
});

test("legacy keyless tombstones are purged on compact", async () => {
  for (const store of [new MemoryStore(), openSqlStore()] as const) {
    await store.ensureBootstrap();
    const tenant = `ten_legacy_ts_${store.kind}`;
    await store.putMcpOperation({
      operation_id: "op_legacy_keyless_ts",
      tenant_id: tenant,
      principal_id: "prin_legacy",
      device_id: "dev_legacy",
      tool: "ownmesh_fs_read",
      status: "tombstone",
      summary: "tombstone: result TTL expired; idempotency retained",
      data: { tombstone: true },
      truncated: true,
      next_cursor: null,
      approval_required: false,
      warnings: ["durable_result_tombstoned"],
      idempotency_key: null,
      policy_authority: "ownmesh_device",
      created_at: nowIso(),
      updated_at: nowIso(),
    });
    const quota = await store.getMcpOperationQuota(tenant);
    assert.equal(quota.rows, 0, `${store.kind}: keyless tombstone must be dropped immediately`);
    assert.equal(await store.getMcpOperation("op_legacy_keyless_ts"), null);
  }
});

test("dispatch outbox survives large write claim (~300 KiB) and redelivers after crash", async () => {
  const store = new MemoryStore();
  const token = await seedAuthed(store);
  const deviceId = "dev_large_outbox";
  await putActiveDevice(store, deviceId);

  const largeContent = "L".repeat(300 * 1024);
  let routeCalls = 0;
  let lastBody = "";
  const router: OperationRouter = {
    async routeToDevice(_id, op) {
      routeCalls += 1;
      lastBody = JSON.stringify(op.payload ?? op);
      return { status: "routed_to_device", detail: { recipients: 1 } };
    },
  };

  const deviceOp = await buildDeviceOperation({
    toolName: "ownmesh_fs_write",
    args: {
      device_id: deviceId,
      workspace_id: null,
      path: "/large.bin.txt",
      content: largeContent,
      idempotency_key: "idem_large_outbox",
    },
    operationId: "op_large_outbox_1",
    deviceId,
    principalId: "prin_dev",
    tenantId: "ten_default",
    principalCredentialGeneration: 1,
    principalRevocationEpoch: 1,
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
    claimVersion: 1,
    oauthClientId: "client_mcp",
  });
  const outbox = buildDispatchOutbox(deviceOp);
  const outboxBytes = new TextEncoder().encode(JSON.stringify(outbox)).byteLength;
  assert.ok(
    outboxBytes > MCP_OPS_MAX_DATA_JSON_BYTES,
    `expected outbox > client data budget (${outboxBytes} > ${MCP_OPS_MAX_DATA_JSON_BYTES})`,
  );
  assert.ok(
    outboxBytes <= MCP_OPS_MAX_DISPATCH_OUTBOX_BYTES,
    `outbox must fit dispatch ceiling (${outboxBytes} <= ${MCP_OPS_MAX_DISPATCH_OUTBOX_BYTES})`,
  );

  // Simulate claim-then-crash: pending outbox stored without ever routing.
  await store.putMcpOperation({
    operation_id: "op_large_outbox_1",
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
    correlation_id: "op_large_outbox_1",
    payload_hash: deviceOp.payload_hash,
    idempotency_key: "idem_large_outbox",
    expires_at: deviceOp.expires_at,
    claim_version: 1,
    action: deviceOp.canonical_action,
    policy_authority: "ownmesh_device",
    created_at: nowIso(),
    updated_at: nowIso(),
  });

  const storedAfterClaim = await store.getMcpOperation("op_large_outbox_1");
  const boxAfterClaim = readDispatchOutbox(storedAfterClaim?.data || {});
  assert.equal(boxAfterClaim?.state, "pending");
  assert.ok(
    JSON.stringify(boxAfterClaim?.body || {}).includes(largeContent.slice(0, 64)),
    "pending outbox must retain large content for redelivery",
  );

  const retry = await handleMcp(
    new Request("https://cp.test/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token.access_token}`,
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
            workspace_id: null,
            path: "/large.bin.txt",
            content: largeContent,
            async: true,
            idempotency_key: "idem_large_outbox",
          },
        },
      }),
    }),
    store,
    new URL("https://cp.test/mcp"),
    { routeToDevice: router.routeToDevice },
    { issuer: "https://cp.test" },
  );
  const retryBody = (await retry.json()) as { error?: unknown };
  assert.equal(retryBody.error, undefined);
  assert.equal(routeCalls, 1, "large pending outbox must redeliver once");
  assert.match(lastBody, /LLLL/);

  const storedAfter = await store.getMcpOperation("op_large_outbox_1");
  const boxAfter = readDispatchOutbox(storedAfter?.data || {});
  assert.equal(boxAfter?.state, "dispatched");
});

test("boundClientVisibleOperationData preserves command exit_code and list cursor", () => {
  const oversized = {
    stdout: "o".repeat(MCP_OPS_MAX_DATA_JSON_BYTES),
    stderr: "e".repeat(1024),
    exit_code: 0,
    timed_out: false,
    truncated: true,
    next_cursor: "v1:abc.def",
  };
  const bounded = boundClientVisibleOperationData(
    oversized,
    new TextEncoder().encode(JSON.stringify(oversized)).byteLength,
  );
  assert.equal(bounded.exit_code, 0);
  assert.equal(bounded.next_cursor, "v1:abc.def");
  assert.equal(bounded.truncated, true);
  assert.ok(typeof bounded.stdout_preview === "string");
});

test("cancel claim: concurrent retries share one outbox and redeliver once path", async () => {
  const store = new MemoryStore();
  const token = await seedAuthed(store);
  const deviceId = "dev_cancel_claim";
  await putActiveDevice(store, deviceId);

  await store.putMcpOperation({
    operation_id: "op_target_long",
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: deviceId,
    tool: "ownmesh_command_run",
    status: "running",
    summary: "running",
    data: {},
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: "op_target_long",
    workspace_id: "ws_target",
    action: { workspace_id: "ws_target", workspace_version: 7 },
    policy_authority: "ownmesh_device",
    created_at: nowIso(),
    updated_at: nowIso(),
  });

  let routes = 0;
  const router: OperationRouter = {
    async routeToDevice(_id, op) {
      routes += 1;
      const payload = (op as { payload?: Record<string, unknown> }).payload || {};
      const args = (payload.arguments || {}) as Record<string, unknown>;
      assert.equal(args.target_operation_id, "op_target_long");
      assert.equal(Object.prototype.hasOwnProperty.call(payload, "workspace_id"), false);
      const bound = (payload.authorization as { bound_action: Record<string, unknown> }).bound_action;
      assert.equal(bound.workspace_id, null);
      assert.equal(bound.workspace_version, null);
      return { status: "routed_to_device" };
    },
  };

  const callCancel = (id: number) =>
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
            name: "ownmesh_cancel_operation",
            arguments: { operation_id: "op_target_long" },
          },
        }),
      }),
      store,
      new URL("https://cp.test/mcp"),
      { routeToDevice: router.routeToDevice },
      { issuer: "https://cp.test" },
    );

  const first = await callCancel(1);
  const firstBody = (await first.json()) as {
    result?: { structuredContent?: { status?: string; data?: { cancel_operation_id?: string } } };
  };
  assert.equal(firstBody.result?.structuredContent?.status, "cancel_requested");
  const cancelOpId = firstBody.result?.structuredContent?.data?.cancel_operation_id;
  assert.ok(cancelOpId);
  assert.equal(routes, 1);
  assert.equal((await store.getMcpOperation("op_target_long"))?.status, "cancel_requested");

  const second = await callCancel(2);
  const secondBody = (await second.json()) as {
    result?: { structuredContent?: { status?: string; data?: { cancel_operation_id?: string } } };
  };
  assert.equal(secondBody.result?.structuredContent?.status, "cancel_requested");
  assert.equal(secondBody.result?.structuredContent?.data?.cancel_operation_id, cancelOpId);
  assert.equal(routes, 1, "second cancel must not mint a second device route");

  const cancelRow = await store.getMcpOperation(cancelOpId!);
  assert.ok(cancelRow);
  assert.equal(cancelRow?.idempotency_key, "cancel:op_target_long");
  assert.equal(cancelRow?.workspace_id, null);
  assert.equal(cancelRow?.action?.workspace_id, null);
  assert.equal(readDispatchOutbox(cancelRow?.data || {})?.state, "dispatched");
});
