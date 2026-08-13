/**
 * routeToDeviceRoom HTTP status normalization + MCP failed (not pending) mapping.
 *
 * DO /operation returns non-2xx for revoked/storage/limit paths; the control plane
 * must never surface those as routed_to_device / pending.
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  handleMcp,
  OperationTracker,
  createHarnessRouter,
} from "./mcp.ts";
import { MemoryStore } from "./store.ts";
import { __test } from "./index.ts";

const TEST_SECRET = "test-session-secret-route-status-normalize-01";

function stubDeviceRoom(
  respond: (req: Request) => Response | Promise<Response>,
): DurableObjectNamespace {
  return {
    idFromName: () => ({}) as DurableObjectId,
    get: () =>
      ({
        fetch: async (req: Request) => respond(req),
      }) as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;
}

async function route(
  respond: (req: Request) => Response | Promise<Response>,
  deviceId = "dev_route_status_norm01",
) {
  return __test.routeToDeviceRoom(
    {
      DEVICE_ROOM: stubDeviceRoom(respond),
      SESSION_SECRET: TEST_SECRET,
    },
    deviceId,
    {
      type: "ownmesh_fs_list",
      payload: { path: "/" },
      correlation_id: "corr_route_status_norm",
    },
    { principal_id: "prin_dev", tenant_id: "ten_default" },
  );
}

async function authed(scope = "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device") {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const tok = await store.issueTokens("client_route_norm", "prin_dev", scope);
  return { store, token: tok.access_token };
}

function rpc(method: string, params?: Record<string, unknown>, token?: string): Request {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  if (token) headers.authorization = `Bearer ${token}`;
  return new Request("https://cp.test/mcp", {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
}

async function callTool(
  store: MemoryStore,
  token: string,
  name: string,
  args: Record<string, unknown>,
  router?: Parameters<typeof handleMcp>[3],
) {
  const deviceId = typeof args.device_id === "string" ? args.device_id : "";
  if (deviceId && !(await store.getDevice(deviceId))) {
    await store.putDevice({
      id: deviceId,
      tenant_id: "ten_default",
      principal_id: "prin_dev",
      name: deviceId,
      hostname: deviceId,
      os: "test",
      arch: "test",
      agent_version: "test",
      protocol_version: "ownmesh.device/1.0",
      public_key: "ab".repeat(32),
      revoked: false,
      created_at: new Date().toISOString(),
      status: "active",
    });
  }
  const res = await handleMcp(
    rpc("tools/call", { name, arguments: args }, token),
    store,
    new URL("https://cp.test/mcp"),
    router,
    { issuer: "https://cp.test", tracker: new OperationTracker() },
  );
  const body = (await res.json()) as {
    result?: {
      content: { type: string; text: string }[];
      structuredContent?: Record<string, unknown>;
      isError?: boolean;
    };
    error?: { code: number; message: string; data?: unknown };
  };
  return { res, body };
}

// ---------------------------------------------------------------------------
// routeToDeviceRoom — DO HTTP status normalization
// ---------------------------------------------------------------------------

test("routeToDeviceRoom: DO 403 device_not_active → rejected with http_status", async () => {
  const routed = await route(
    () => Response.json({ error: "device_not_active" }, { status: 403 }),
  );
  assert.equal(routed.status, "rejected");
  assert.notEqual(routed.status, "routed_to_device");
  assert.notEqual(routed.status, "pending");
  const detail = (routed.detail || {}) as {
    http_status?: number;
    error?: string;
    upstream?: { error?: string };
  };
  assert.equal(detail.http_status, 403);
  assert.equal(detail.error, "device_not_active");
  assert.equal(detail.upstream?.error, "device_not_active");
});

test("routeToDeviceRoom: DO 403 binding_mismatch → rejected with http_status", async () => {
  const routed = await route(
    () => Response.json({ error: "binding_mismatch" }, { status: 403 }),
  );
  assert.equal(routed.status, "rejected");
  const detail = (routed.detail || {}) as { http_status?: number; error?: string };
  assert.equal(detail.http_status, 403);
  assert.equal(detail.error, "binding_mismatch");
});

test("routeToDeviceRoom: DO 503 storage_unavailable → unavailable with http_status", async () => {
  const routed = await route(
    () => Response.json({ error: "storage_unavailable" }, { status: 503 }),
  );
  assert.equal(routed.status, "unavailable");
  assert.notEqual(routed.status, "routed_to_device");
  assert.notEqual(routed.status, "pending");
  const detail = (routed.detail || {}) as {
    http_status?: number;
    error?: string;
    upstream?: { error?: string };
  };
  assert.equal(detail.http_status, 503);
  assert.equal(detail.error, "storage_unavailable");
  assert.equal(detail.upstream?.error, "storage_unavailable");
});

test("routeToDeviceRoom: DO 429 rejected body → unavailable (never pending/routed)", async () => {
  const routed = await route(() =>
    Response.json(
      { status: "rejected", detail: { code: "OWNMESH_E_PENDING_LIMIT" } },
      { status: 429 },
    ),
  );
  assert.equal(routed.status, "unavailable");
  assert.notEqual(routed.status, "routed_to_device");
  assert.notEqual(routed.status, "pending");
  const detail = (routed.detail || {}) as {
    http_status?: number;
    error?: string;
    upstream_detail?: { code?: string };
  };
  assert.equal(detail.http_status, 429);
  assert.ok(detail.error);
  assert.equal(detail.upstream_detail?.code, "OWNMESH_E_PENDING_LIMIT");
});

test("routeToDeviceRoom: non-2xx non-JSON body → unavailable (unparseable)", async () => {
  const routed = await route(
    () => new Response("not-json-at-all", { status: 502, headers: { "content-type": "text/plain" } }),
  );
  assert.equal(routed.status, "unavailable");
  const detail = (routed.detail || {}) as { http_status?: number; error?: string };
  assert.equal(detail.http_status, 502);
  assert.ok(detail.error);
});

test("routeToDeviceRoom: 2xx status-less error body → unavailable (not routed)", async () => {
  const routed = await route(
    () => Response.json({ error: "weird_error_without_status" }, { status: 200 }),
  );
  assert.equal(routed.status, "unavailable");
  assert.notEqual(routed.status, "routed_to_device");
  const detail = (routed.detail || {}) as { http_status?: number; error?: string };
  assert.equal(detail.http_status, 200);
  assert.equal(detail.error, "weird_error_without_status");
});

test("routeToDeviceRoom: 2xx routed_to_device unchanged", async () => {
  const routed = await route(
    () => Response.json({ status: "routed_to_device", detail: { ok: true } }, { status: 200 }),
  );
  assert.equal(routed.status, "routed_to_device");
  const detail = (routed.detail || {}) as { ok?: boolean };
  assert.equal(detail.ok, true);
});

// ---------------------------------------------------------------------------
// MCP — rejected / unavailable must be failed envelopes, never pending
// ---------------------------------------------------------------------------

test("MCP: router rejected (DO 403 shape) → failed, not pending", async () => {
  const { store, token } = await authed();
  const deviceId = "dev_mcp_rejected_403_01";
  const router = createHarnessRouter({
    inject: () => ({
      status: "rejected",
      detail: {
        http_status: 403,
        error: "device_not_active",
        upstream: { error: "device_not_active" },
      },
    }),
  });

  const call = await callTool(
    store,
    token,
    "ownmesh_fs_list",
    { device_id: deviceId, workspace_id: null, path: "/" },
    router,
  );
  const sc = call.body.result!.structuredContent!;
  assert.equal(sc.status, "failed");
  assert.notEqual(sc.status, "pending");
  assert.notEqual(sc.status, "approval_required");
  assert.equal(sc.approval_required, false);
  assert.equal(call.body.result!.isError, true);
  assert.equal(
    (sc.data as { error: { code: string } }).error.code,
    "OWNMESH_E_DEVICE_ROOM_UNAVAILABLE",
  );
  assert.equal(
    ((sc.data as { error: { details: { http_status?: number } } }).error.details || {})
      .http_status,
    403,
  );
});

test("MCP: router unavailable from DO 503 storage → failed, not pending", async () => {
  const { store, token } = await authed();
  const deviceId = "dev_mcp_unavail_503_01";
  const router = createHarnessRouter({
    inject: () => ({
      status: "unavailable",
      detail: {
        http_status: 503,
        error: "storage_unavailable",
        upstream: { error: "storage_unavailable" },
      },
    }),
  });

  const call = await callTool(
    store,
    token,
    "ownmesh_fs_read",
    { device_id: deviceId, workspace_id: null, path: "/a" },
    router,
  );
  const sc = call.body.result!.structuredContent!;
  assert.equal(sc.status, "failed");
  assert.notEqual(sc.status, "pending");
  assert.equal(
    (sc.data as { error: { code: string } }).error.code,
    "OWNMESH_E_DEVICE_ROOM_UNAVAILABLE",
  );
  assert.equal(
    ((sc.data as { error: { details: { error?: string } } }).error.details || {}).error,
    "storage_unavailable",
  );
});

test("MCP: router unavailable from DO 429 → failed, not pending", async () => {
  const { store, token } = await authed();
  const deviceId = "dev_mcp_unavail_429_01";
  const router = createHarnessRouter({
    inject: () => ({
      status: "unavailable",
      detail: {
        http_status: 429,
        error: "rejected",
        upstream_detail: { code: "OWNMESH_E_PENDING_LIMIT" },
      },
    }),
  });

  // Mutating tool must also fail closed (not approval/pending fallthrough).
  const call = await callTool(
    store,
    token,
    "ownmesh_fs_write",
    { device_id: deviceId, workspace_id: null, path: "/x.txt", content: "data", idempotency_key: "idem_route_write" },
    router,
  );
  const sc = call.body.result!.structuredContent!;
  assert.equal(sc.status, "failed");
  assert.notEqual(sc.status, "pending");
  assert.notEqual(sc.status, "approval_required");
  assert.equal(sc.approval_required, false);
  assert.equal(call.body.result!.isError, true);
  assert.equal(
    (sc.data as { error: { code: string } }).error.code,
    "OWNMESH_E_DEVICE_ROOM_UNAVAILABLE",
  );
});

test("MCP end-to-end: routeToDeviceRoom 403 stub → failed via real router path", async () => {
  const { store, token } = await authed();
  const deviceId = "dev_mcp_e2e_403_01";
  await store.putDevice({
    id: deviceId,
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    name: deviceId,
    hostname: deviceId,
    os: "test",
    arch: "test",
    agent_version: "test",
    protocol_version: "ownmesh.device/1.0",
    public_key: "ab".repeat(32),
    revoked: false,
    created_at: new Date().toISOString(),
    status: "active",
  });

  const room = stubDeviceRoom(() =>
    Response.json({ error: "device_not_active" }, { status: 403 }),
  );

  const router = {
    routeToDevice: (
      id: string,
      operation: { type: string; payload: Record<string, unknown>; correlation_id: string },
    ) =>
      __test.routeToDeviceRoom(
        { DEVICE_ROOM: room, SESSION_SECRET: TEST_SECRET },
        id,
        operation,
        { principal_id: "prin_dev", tenant_id: "ten_default" },
      ),
  };

  const call = await callTool(
    store,
    token,
    "ownmesh_fs_list",
    { device_id: deviceId, workspace_id: null, path: "/" },
    router,
  );
  const sc = call.body.result!.structuredContent!;
  assert.equal(sc.status, "failed");
  assert.notEqual(sc.status, "pending");
  assert.equal(
    (sc.data as { error: { code: string } }).error.code,
    "OWNMESH_E_DEVICE_ROOM_UNAVAILABLE",
  );
  const details = (sc.data as { error: { details: { http_status?: number; error?: string } } })
    .error.details;
  assert.equal(details.http_status, 403);
  assert.equal(details.error, "device_not_active");
});
