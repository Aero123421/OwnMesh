/**
 * Batch approval inbox, v2 set commitment, per-op consume, and deny-all.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { handleApprove } from "./mcp.ts";
import { MemoryStore, type McpOperationRecord } from "./store.ts";
import { randomId } from "./util.ts";
import worker, { __setTestStore } from "./index.ts";
import { approvalSetCommitment } from "./owner-auth.ts";

const ctx = {} as ExecutionContext;
const ISSUER = "https://cp.test";

function authProvider(fresh = true): Fetcher {
  return {
    fetch: async (request: Request) =>
      Response.json({
        principal_id: "prin_dev",
        tenant_id: "ten_default",
        display_name: "Dev User",
        fresh,
        purpose: request.headers.get("x-ownmesh-auth-purpose"),
        operation_id: request.headers.get("x-ownmesh-operation-id"),
        commitment: request.headers.get("x-ownmesh-approval-commitment"),
      }),
  } as unknown as Fetcher;
}

async function seed(store: MemoryStore) {
  await store.ensureBootstrap();
  await store.putDevice({
    id: "dev_batch_approval_01abcd",
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    name: "batch",
    hostname: "batch",
    os: "test",
    arch: "x64",
    agent_version: "1.0.0",
    protocol_version: "ownmesh.device/1.0",
    public_key: "pk",
    status: "active",
    revoked: false,
    created_at: new Date().toISOString(),
  });
}

function pendingOp(opId: string, hash: string): McpOperationRecord {
  const now = new Date().toISOString();
  return {
    operation_id: opId,
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: "dev_batch_approval_01abcd",
    tool: "ownmesh_fs_write",
    status: "approval_required",
    summary: "needs human",
    data: { tool: "ownmesh_fs_write" },
    truncated: false,
    next_cursor: null,
    approval_required: true,
    approval_url: `${ISSUER}/approve?operation_id=${opId}`,
    warnings: [],
    correlation_id: randomId("cor_"),
    policy_authority: "ownmesh_device",
    payload_hash: hash,
    created_at: now,
    updated_at: now,
  };
}

function cookieFrom(response: Response, name: string): string {
  const header = response.headers.getSetCookie?.().join(",") || response.headers.get("set-cookie") || "";
  for (const part of header.split(/,(?=\s*[^;]+=)/)) {
    const token = part.trim();
    if (token.startsWith(`${name}=`)) return token.split(";", 1)[0]!;
  }
  return "";
}

test("GET /approve lists pending ops without a presence cookie", async () => {
  const store = new MemoryStore();
  await seed(store);
  const opId = randomId("op_");
  await store.putMcpOperation(pendingOp(opId, "a".repeat(64)));
  const listed = await handleApprove(new Request(`${ISSUER}/approve`), store, {
    issuer: ISSUER,
    principal: { id: "prin_dev", tenant_id: "ten_default" },
    originAllowed: true,
  });
  assert.equal(listed.status, 200);
  const html = await listed.text();
  assert.match(html, /Review pending operations/);
  assert.match(html, new RegExp(opId));
  assert.match(html, /Deny all pending/);
});

test("deny-all consumes each pending op once without a passkey assertion", async () => {
  const store = new MemoryStore();
  await seed(store);
  const first = randomId("op_");
  const second = randomId("op_");
  await store.putMcpOperation(pendingOp(first, "a".repeat(64)));
  await store.putMcpOperation(pendingOp(second, "b".repeat(64)));
  const inbox = await handleApprove(new Request(`${ISSUER}/approve`), store, {
    issuer: ISSUER,
    principal: { id: "prin_dev", tenant_id: "ten_default" },
    originAllowed: true,
  });
  assert.equal(inbox.status, 200);
  const csrf = cookieFrom(inbox, "__Host-ownmesh_approve_list");
  assert.match(csrf, /^__Host-ownmesh_approve_list=csrf_/);
  const html = await inbox.text();
  const token = html.match(/name="csrf_token" value="([^"]+)"/)?.[1];
  assert.ok(token);

  const deliveries: string[] = [];
  const denied = await handleApprove(
    new Request(`${ISSUER}/approve`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        origin: ISSUER,
        cookie: csrf,
      },
      body: JSON.stringify({ decision: "deny_all", csrf_token: token }),
    }),
    store,
    {
      issuer: ISSUER,
      principal: { id: "prin_dev", tenant_id: "ten_default" },
      originAllowed: true,
      routeToDevice: async (_deviceId, operation) => {
        deliveries.push(String(
          (operation.payload.arguments as { target_operation_id?: string } | undefined)?.target_operation_id,
        ));
        return { status: "routed_to_device" };
      },
    },
  );
  assert.equal(denied.status, 200, await denied.clone().text());
  const body = await denied.json() as { ok?: boolean; decision?: string; results?: Array<{ ok: boolean }> };
  assert.equal(body.ok, true);
  assert.equal(body.decision, "deny_all");
  assert.equal(body.results?.every((row) => row.ok), true);
  assert.equal(deliveries.sort().join(","), [first, second].sort().join(","));
});

test("batch GET fails closed without a payload hash; POST consumes each selected op once", async () => {
  const store = new MemoryStore();
  await seed(store);
  const first = "op_batch_aaa";
  const second = "op_batch_bbb";
  await store.putMcpOperation(pendingOp(first, "a".repeat(64)));
  await store.putMcpOperation({
    ...pendingOp(second, ""),
    payload_hash: undefined,
  });
  const missingHash = await handleApprove(
    new Request(`${ISSUER}/approve?ids=${first}&ids=${second}`),
    store,
    { issuer: ISSUER, principal: { id: "prin_dev", tenant_id: "ten_default" } },
  );
  assert.equal(missingHash.status, 400);
  assert.equal(((await missingHash.json()) as { error?: string }).error, "invalid_request");

  await store.putMcpOperation({
    ...pendingOp("op_batch_ccc", "c".repeat(64)),
    operation_id: "op_batch_ccc",
  });
  // Replace the hash-less row by using a third valid op instead of mutating Maps.
  const ids = `${ISSUER}/approve?ids=${first}&ids=op_batch_ccc`;
  const page = await handleApprove(new Request(ids), store, {
    issuer: ISSUER,
    principal: { id: "prin_dev", tenant_id: "ten_default" },
  });
  assert.equal(page.status, 200, await page.clone().text());
  const pageHtml = await page.text();
  assert.match(pageHtml, /Review the exact selected set/);
  const csrf = pageHtml.match(/name="csrf_token" value="([^"]+)"/)?.[1];
  const txIds = [...pageHtml.matchAll(/name="transaction_id" value="([^"]+)"/g)].map((match) => match[1]!);
  assert.equal(txIds.length, 2);
  assert.ok(csrf);

  const deliveries: string[] = [];
  const posted = await handleApprove(
    new Request(ids, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        origin: ISSUER,
      },
      body: JSON.stringify({
        decision: "approve",
        csrf_token: csrf,
        transaction_ids: txIds,
        payload_hash: "f".repeat(64),
        commitment: "e".repeat(64),
      }),
    }),
    store,
    {
      issuer: ISSUER,
      principal: { id: "prin_dev", tenant_id: "ten_default" },
      originAllowed: true,
      routeToDevice: async (_deviceId, operation) => {
        deliveries.push(String(
          (operation.payload.arguments as { target_operation_id?: string } | undefined)?.target_operation_id,
        ));
        return { status: "routed_to_device" };
      },
    },
  );
  assert.equal(posted.status, 200, await posted.clone().text());
  const body = await posted.json() as { ok?: boolean; results?: Array<{ ok: boolean }> };
  assert.equal(body.ok, true);
  assert.equal(deliveries.sort().join(","), [first, "op_batch_ccc"].sort().join(","));
});

test("worker batch approve requires AUTH_PROVIDER fresh attestation bound to the commitment", async () => {
  const store = new MemoryStore();
  await seed(store);
  const first = "op_fresh_aaa";
  const second = "op_fresh_bbb";
  await store.putMcpOperation(pendingOp(first, "a".repeat(64)));
  await store.putMcpOperation(pendingOp(second, "b".repeat(64)));
  __setTestStore(store);
  try {
    const stale = await worker.fetch(
      new Request(`${ISSUER}/approve?ids=${second}&ids=${first}`),
      { OAUTH_ISSUER: ISSUER, AUTH_PROVIDER: authProvider(false) },
      ctx,
    );
    assert.equal(stale.status, 401);
    assert.equal(((await stale.json()) as { error?: string }).error, "fresh_authentication_required");

    let providerRequest: Request | undefined;
    const provider = {
      fetch: async (request: Request) => {
        providerRequest = request;
        return Response.json({
          principal_id: "prin_dev",
          tenant_id: "ten_default",
          fresh: true,
        });
      },
    } as unknown as Fetcher;
    const fresh = await worker.fetch(
      new Request(`${ISSUER}/approve?ids=${second}&ids=${first}`),
      { OAUTH_ISSUER: ISSUER, AUTH_PROVIDER: provider },
      ctx,
    );
    assert.equal(fresh.status, 200, await fresh.clone().text());
    const expected = await approvalSetCommitment([
      { operation_id: first, payload_hash: "a".repeat(64) },
      { operation_id: second, payload_hash: "b".repeat(64) },
    ]);
    assert.equal(providerRequest?.headers.get("x-ownmesh-auth-purpose"), "approve");
    assert.equal(providerRequest?.headers.get("x-ownmesh-require-fresh"), "true");
    assert.equal(providerRequest?.headers.get("x-ownmesh-approval-commitment"), expected);
    assert.equal(providerRequest?.headers.get("x-ownmesh-operation-id"), null);
  } finally {
    __setTestStore(null);
  }
});
