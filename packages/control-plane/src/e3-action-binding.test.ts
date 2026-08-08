/**
 * E3 exact-action binding: server payload_hash + idempotency mismatch.
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  buildCanonicalAction,
  buildDeviceOperation,
  handleMcp,
  type OperationRouter,
} from "./mcp.ts";
import { MemoryStore } from "./store.ts";
import { hashCanonicalAction, nowIso } from "./util.ts";

async function seedAuthed(store: MemoryStore, principal = "prin_dev") {
  await store.ensureBootstrap();
  await store.ensurePrincipal(principal, "Dev", "human", "ten_default");
  return store.issueTokens(
    "client_mcp",
    principal,
    "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device",
  );
}

async function putActiveDevice(store: MemoryStore, id: string, principal = "prin_dev") {
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
  });
  const b = await buildCanonicalAction({
    toolName: "ownmesh_fs_write",
    args: { path: "a.txt", content: "hello", device_id: "dev_x" },
    deviceId: "dev_x",
    principalId: "prin_a",
    tenantId: "ten_a",
  });
  assert.equal(await hashCanonicalAction(a), await hashCanonicalAction(b));
  assert.equal((a.facts as { content_sha256: string }).content_sha256.length, 64);
  assert.equal((a.facts as { content?: string }).content, undefined);

  const c = await buildCanonicalAction({
    toolName: "ownmesh_fs_write",
    args: { path: "a.txt", content: "HELLO", device_id: "dev_x" },
    deviceId: "dev_x",
    principalId: "prin_a",
    tenantId: "ten_a",
  });
  assert.notEqual(await hashCanonicalAction(a), await hashCanonicalAction(c));
});

test("buildDeviceOperation always sets server payload_hash and strips client hash", async () => {
  const op = await buildDeviceOperation({
    toolName: "ownmesh_command_run",
    args: {
      program: "echo",
      args: ["x"],
      payload_hash: "0".repeat(64),
      allow: true,
    },
    operationId: "op_test1",
    deviceId: "dev_1",
    principalId: "prin_1",
    tenantId: "ten_1",
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
  assert.equal(typeof op.payload_hash, "string");
  assert.equal(op.payload_hash.length, 64);
  assert.notEqual(op.payload_hash, "0".repeat(64));
  assert.equal(op.payload.payload_hash, op.payload_hash);
  assert.equal((op.payload.arguments as Record<string, unknown>).allow, undefined);
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

  const firstHash = await hashCanonicalAction(
    await buildCanonicalAction({
      toolName: "ownmesh_fs_write",
      args: { path: "x.txt", content: "v1" },
      deviceId,
      principalId: "prin_dev",
      tenantId: "ten_default",
    }),
  );
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
    payload_hash: firstHash,
    idempotency_key: "idem_e3_1",
    claim_version: 1,
    action: { path: "x.txt" },
    policy_authority: "ownmesh_device",
    created_at: nowIso(),
    updated_at: nowIso(),
  });

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
