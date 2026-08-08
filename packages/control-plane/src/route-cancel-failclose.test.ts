/**
 * routeToDeviceRoom fetch-throw fail-close + MCP cancel route-gated cancel_requested
 * + delayed terminal result acceptance from cancel_requested.
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  handleMcp,
  OperationTracker,
} from "./mcp.ts";
import { MemoryStore } from "./store.ts";
import { applyMcpOperationResult } from "./device-room.ts";
import { __test } from "./index.ts";
import { randomId } from "./util.ts";

const TEST_SECRET = "test-session-secret-route-cancel-failclose-01";

function throwingDeviceRoom(message = "do_stub_boom"): DurableObjectNamespace {
  return {
    idFromName: () => ({}) as DurableObjectId,
    get: () =>
      ({
        fetch: async () => {
          throw new Error(message);
        },
      }) as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;
}

function hangingDeviceRoom(): DurableObjectNamespace {
  return {
    idFromName: () => ({}) as DurableObjectId,
    get: () =>
      ({
        fetch: () => new Promise<Response>(() => {}),
      }) as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;
}

async function seedAuthed(scope = "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device") {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const tok = await store.issueTokens("client_route_cancel", "prin_dev", scope);
  return { store, token: tok.access_token, access: tok };
}

function rpc(name: string, args: Record<string, unknown>, token: string): Request {
  return new Request("https://cp.test/mcp", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name, arguments: args },
    }),
  });
}

async function putActiveDevice(store: MemoryStore, deviceId: string) {
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

async function putRunningOp(
  store: MemoryStore,
  opts: { opId: string; deviceId?: string | null; status?: string },
) {
  const corr = randomId("cor_");
  await store.putMcpOperation({
    operation_id: opts.opId,
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: opts.deviceId === null ? undefined : opts.deviceId || "dev_cancel_fc_01abcdef",
    tool: "ownmesh_command_run",
    status: opts.status || "running",
    summary: "running",
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
  return corr;
}

// ---------------------------------------------------------------------------
// routeToDeviceRoom — post-send throw/timeout → dispatch_uncertain (never throws)
// ---------------------------------------------------------------------------

test("routeToDeviceRoom: stub.fetch throw → dispatch_uncertain (not thrown)", async () => {
  const routed = await __test.routeToDeviceRoom(
    {
      DEVICE_ROOM: throwingDeviceRoom("simulated_do_crash"),
      SESSION_SECRET: TEST_SECRET,
    },
    "dev_route_throw_01abcdef",
    {
      type: "ownmesh_fs_list",
      payload: { path: "/" },
      correlation_id: "corr_route_throw",
    },
    { principal_id: "prin_dev", tenant_id: "ten_default" },
  );
  assert.equal(routed.status, "dispatch_uncertain");
  assert.notEqual(routed.status, "routed_to_device");
  assert.notEqual(routed.status, "failed");
  const detail = (routed.detail || {}) as { error?: string; message?: string };
  assert.equal(detail.error, "device_room_fetch_failed");
  assert.match(String(detail.message || ""), /simulated_do_crash/);
});

test("routeToDeviceRoom: unresolved stub fetch → dispatch_uncertain timeout", async () => {
  const routed = await __test.routeToDeviceRoom(
    {
      DEVICE_ROOM: hangingDeviceRoom(),
      SESSION_SECRET: TEST_SECRET,
      OWNMESH_DEVICE_ROUTE_TIMEOUT_MS: "5",
    },
    "dev_route_timeout_01abcdef",
    {
      type: "ownmesh_fs_list",
      payload: { path: "/" },
      correlation_id: "corr_route_timeout",
    },
    { principal_id: "prin_dev", tenant_id: "ten_default" },
  );
  assert.equal(routed.status, "dispatch_uncertain");
  const detail = (routed.detail || {}) as {
    error?: string;
    timeout_ms?: number;
    note?: string;
  };
  assert.equal(detail.error, "device_room_fetch_timeout");
  assert.equal(detail.timeout_ms, 5);
  assert.match(String(detail.note || ""), /may already be durable/i);
});

// ---------------------------------------------------------------------------
// DO stub throw/timeout → durable pending (not terminal failed)
// ---------------------------------------------------------------------------

test("DO stub fetch throw → MCP op stays pending (dispatch_uncertain)", async () => {
  const { store, token } = await seedAuthed();
  const deviceId = "dev_throw_cas_fail_01ab";
  await putActiveDevice(store, deviceId);

  const room = throwingDeviceRoom("do_fetch_exploded");
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

  const res = await handleMcp(
    rpc("ownmesh_fs_list", { device_id: deviceId, path: "/" }, token),
    store,
    new URL("https://cp.test/mcp"),
    router,
    { issuer: "https://cp.test", tracker: new OperationTracker() },
  );
  const body = (await res.json()) as {
    result?: {
      structuredContent?: {
        status?: string;
        operation_id?: string;
        summary?: string;
        data?: { dispatch?: string; route?: { status?: string; detail?: { error?: string } } };
      };
    };
  };
  const sc = body.result?.structuredContent;
  assert.ok(sc);
  assert.equal(sc!.status, "pending");
  assert.equal(sc!.summary, "dispatch_uncertain");
  assert.equal(sc!.data?.dispatch, "uncertain");
  assert.equal(sc!.data?.route?.status, "dispatch_uncertain");
  assert.equal(sc!.data?.route?.detail?.error, "device_room_fetch_failed");

  const opId = sc!.operation_id!;
  const stored = await store.getMcpOperation(opId);
  assert.ok(stored);
  assert.equal(stored!.status, "pending");
  assert.notEqual(stored!.status, "failed");
});

// ---------------------------------------------------------------------------
// ownmesh_cancel_operation — route success only → cancel_requested
// ---------------------------------------------------------------------------

test("cancel: successful device route → cancel_requested (not cancelled)", async () => {
  const { store, token } = await seedAuthed();
  const deviceId = "dev_cancel_ok_01abcdef";
  const opId = randomId("op_");
  await putActiveDevice(store, deviceId);
  await putRunningOp(store, { opId, deviceId });

  const routed: string[] = [];
  const res = await handleMcp(
    rpc("ownmesh_cancel_operation", { operation_id: opId }, token),
    store,
    new URL("https://cp.test/mcp"),
    {
      routeToDevice: async (id, op) => {
        routed.push(`${id}:${op.type}`);
        return { status: "routed_to_device" };
      },
    },
    { tracker: new OperationTracker() },
  );
  const body = (await res.json()) as {
    result?: { structuredContent?: { status?: string; summary?: string } };
  };
  assert.equal(body.result?.structuredContent?.status, "cancel_requested");
  assert.equal((await store.getMcpOperation(opId))?.status, "cancel_requested");
  assert.ok(
    routed[0]?.includes("cancel") || routed[0]?.includes("ownmesh_cancel_operation"),
    `cancel route type should be cancel action, got ${routed[0]}`,
  );
});

test("cancel: no device_id → direct cancelled", async () => {
  const { store, token } = await seedAuthed();
  const opId = randomId("op_");
  await putRunningOp(store, { opId, deviceId: null });

  const res = await handleMcp(
    rpc("ownmesh_cancel_operation", { operation_id: opId }, token),
    store,
    new URL("https://cp.test/mcp"),
    {
      routeToDevice: async () => {
        throw new Error("must_not_route_without_device");
      },
    },
    { tracker: new OperationTracker() },
  );
  const body = (await res.json()) as {
    result?: { structuredContent?: { status?: string } };
  };
  assert.equal(body.result?.structuredContent?.status, "cancelled");
  assert.equal((await store.getMcpOperation(opId))?.status, "cancelled");
});

test("cancel: route rejected → original state kept + error envelope", async () => {
  const { store, token } = await seedAuthed();
  const deviceId = "dev_cancel_rej_01abcdef";
  const opId = randomId("op_");
  await putActiveDevice(store, deviceId);
  await putRunningOp(store, { opId, deviceId, status: "running" });

  const res = await handleMcp(
    rpc("ownmesh_cancel_operation", { operation_id: opId }, token),
    store,
    new URL("https://cp.test/mcp"),
    {
      routeToDevice: async () => ({
        status: "rejected",
        detail: { http_status: 403, error: "device_not_active" },
      }),
    },
    { tracker: new OperationTracker() },
  );
  const body = (await res.json()) as {
    result?: {
      structuredContent?: {
        status?: string;
        summary?: string;
        data?: {
          error?: { code?: string };
          previous?: { status?: string };
          route_status?: string;
        };
      };
      isError?: boolean;
    };
  };
  const sc = body.result!.structuredContent!;
  assert.equal(sc.status, "failed");
  assert.equal(body.result!.isError, true);
  assert.equal(sc.data?.error?.code, "OWNMESH_E_CANCEL_ROUTE_FAILED");
  assert.equal(sc.data?.route_status, "rejected");
  assert.equal(sc.data?.previous?.status, "running");
  // Store must remain at original running — never cancelled / cancel_requested.
  assert.equal((await store.getMcpOperation(opId))?.status, "running");
});

test("cancel: route throw → original state kept + error envelope", async () => {
  const { store, token } = await seedAuthed();
  const deviceId = "dev_cancel_thr_01abcdef";
  const opId = randomId("op_");
  await putActiveDevice(store, deviceId);
  await putRunningOp(store, { opId, deviceId, status: "pending" });

  const res = await handleMcp(
    rpc("ownmesh_cancel_operation", { operation_id: opId }, token),
    store,
    new URL("https://cp.test/mcp"),
    {
      routeToDevice: async () => {
        throw new Error("cancel_route_network_down");
      },
    },
    { tracker: new OperationTracker() },
  );
  const body = (await res.json()) as {
    result?: {
      structuredContent?: {
        status?: string;
        summary?: string;
        data?: {
          error?: { code?: string; message?: string };
          previous?: { status?: string };
        };
      };
      isError?: boolean;
    };
  };
  const sc = body.result!.structuredContent!;
  assert.equal(sc.status, "failed");
  assert.equal(body.result!.isError, true);
  assert.equal(sc.data?.error?.code, "OWNMESH_E_CANCEL_ROUTE_FAILED");
  assert.match(String(sc.data?.error?.message || ""), /cancel_route_network_down/);
  assert.equal(sc.data?.previous?.status, "pending");
  assert.equal((await store.getMcpOperation(opId))?.status, "pending");
});

test("cancel: uncertain route (DO throw via routeToDeviceRoom) keeps running", async () => {
  const { store, token } = await seedAuthed();
  const deviceId = "dev_cancel_unavail_01ab";
  const opId = randomId("op_");
  await putActiveDevice(store, deviceId);
  await putRunningOp(store, { opId, deviceId, status: "running" });

  const room = throwingDeviceRoom("cancel_do_down");
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

  const res = await handleMcp(
    rpc("ownmesh_cancel_operation", { operation_id: opId }, token),
    store,
    new URL("https://cp.test/mcp"),
    router,
    { tracker: new OperationTracker() },
  );
  const body = (await res.json()) as {
    result?: {
      structuredContent?: {
        status?: string;
        data?: { error?: { code?: string }; route_status?: string };
      };
    };
  };
  assert.equal(body.result?.structuredContent?.status, "failed");
  assert.equal(
    body.result?.structuredContent?.data?.error?.code,
    "OWNMESH_E_CANCEL_ROUTE_FAILED",
  );
  // Cancel is only cancel_requested after confirmed route; uncertain ≠ confirmed.
  assert.equal(body.result?.structuredContent?.data?.route_status, "dispatch_uncertain");
  assert.equal((await store.getMcpOperation(opId))?.status, "running");
});

test("cancel: timed-out DO route keeps original state + explicit timeout error", async () => {
  const { store, token } = await seedAuthed();
  const deviceId = "dev_cancel_timeout_01ab";
  const opId = randomId("op_");
  await putActiveDevice(store, deviceId);
  await putRunningOp(store, { opId, deviceId, status: "approval_required" });

  const res = await handleMcp(
    rpc("ownmesh_cancel_operation", { operation_id: opId }, token),
    store,
    new URL("https://cp.test/mcp"),
    {
      routeToDevice: (id, operation) =>
        __test.routeToDeviceRoom(
          {
            DEVICE_ROOM: hangingDeviceRoom(),
            SESSION_SECRET: TEST_SECRET,
            OWNMESH_DEVICE_ROUTE_TIMEOUT_MS: "5",
          },
          id,
          operation,
          { principal_id: "prin_dev", tenant_id: "ten_default" },
        ),
    },
    { tracker: new OperationTracker() },
  );
  const body = (await res.json()) as {
    result?: {
      structuredContent?: {
        status?: string;
        data?: {
          error?: { code?: string; details?: { error?: string; timeout_ms?: number } };
          previous?: { status?: string };
          route_status?: string;
        };
      };
    };
  };
  const sc = body.result?.structuredContent;
  assert.equal(sc?.status, "failed");
  assert.equal(sc?.data?.error?.code, "OWNMESH_E_CANCEL_ROUTE_FAILED");
  assert.equal(sc?.data?.error?.details?.error, "device_room_fetch_timeout");
  assert.equal(sc?.data?.error?.details?.timeout_ms, 5);
  assert.equal(sc?.data?.route_status, "dispatch_uncertain");
  assert.equal(sc?.data?.previous?.status, "approval_required");
  assert.equal((await store.getMcpOperation(opId))?.status, "approval_required");
});

// ---------------------------------------------------------------------------
// applyMcpOperationResult — cancel_requested accepts delayed terminal
// ---------------------------------------------------------------------------

test("applyMcpOperationResult: cancel_requested accepts delayed cancelled", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const deviceId = "dev_delay_term_01abcdef";
  const opId = randomId("op_");
  const corr = randomId("cor_");
  await store.putMcpOperation({
    operation_id: opId,
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: deviceId,
    tool: "ownmesh_command_run",
    status: "cancel_requested",
    summary: "cancel requested on device",
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

  const applied = await applyMcpOperationResult(store, {
    operationId: opId,
    correlationId: corr,
    payload: { status: "cancelled", operation_id: opId, summary: "cancelled on device" },
    deviceId,
  });
  assert.equal(applied.ok, true);
  assert.equal((await store.getMcpOperation(opId))?.status, "cancelled");
});

test("applyMcpOperationResult: cancel_requested accepts delayed completed/failed", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const deviceId = "dev_delay_term_02abcdef";

  for (const terminal of ["completed", "failed"] as const) {
    const opId = randomId("op_");
    const corr = randomId("cor_");
    await store.putMcpOperation({
      operation_id: opId,
      tenant_id: "ten_default",
      principal_id: "prin_dev",
      device_id: deviceId,
      tool: "ownmesh_fs_list",
      status: "cancel_requested",
      summary: "cancel requested on device",
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

    const applied = await applyMcpOperationResult(store, {
      operationId: opId,
      correlationId: corr,
      payload: { status: terminal, operation_id: opId, result: { late: true } },
      deviceId,
    });
    assert.equal(applied.ok, true, `expected CAS ok for terminal=${terminal}`);
    assert.equal((await store.getMcpOperation(opId))?.status, terminal);
  }
});

test("applyMcpOperationResult: approval_decision_applied folds onto target operation", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const deviceId = "dev_apr_fold_01abcdef01";
  const targetOpId = randomId("op_");
  const decisionOpId = randomId("op_");
  await store.putMcpOperation({
    operation_id: targetOpId,
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: deviceId,
    tool: "ownmesh_fs_write",
    status: "pending",
    summary: "human approved; routing decision to device",
    data: { approval_decision: "approve" },
    truncated: false,
    next_cursor: null,
    approval_required: false,
    approval_id: "apr_device_1",
    warnings: [],
    correlation_id: targetOpId,
    policy_authority: "ownmesh_device",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  const applied = await applyMcpOperationResult(store, {
    // decision notification id has no store row
    operationId: decisionOpId,
    correlationId: decisionOpId,
    deviceId,
    payload: {
      status: "completed",
      operation_id: decisionOpId,
      result: {
        approval_decision_applied: true,
        decision: "approve",
        target_operation_id: targetOpId,
        approval_id: "apr_device_1",
        result: { written: true, path: "ask.txt" },
      },
    },
  });
  assert.equal(applied.ok, true);
  assert.ok(applied.ok && applied.record);
  assert.equal(applied.record!.operation_id, targetOpId);
  assert.equal(applied.record!.status, "completed");
  assert.equal(applied.record!.approval_required, false);
  assert.equal((applied.record!.data as { execution?: { written?: boolean } }).execution?.written, true);
  assert.equal((await store.getMcpOperation(targetOpId))?.status, "completed");
});

test("applyMcpOperationResult: approval_decision deny folds onto target", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const deviceId = "dev_apr_fold_02abcdef02";
  const targetOpId = randomId("op_");
  const decisionOpId = randomId("op_");
  await store.putMcpOperation({
    operation_id: targetOpId,
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: deviceId,
    tool: "ownmesh_fs_write",
    status: "approval_required",
    summary: "waiting",
    data: {},
    truncated: false,
    next_cursor: null,
    approval_required: true,
    approval_id: "apr_device_2",
    warnings: [],
    correlation_id: targetOpId,
    policy_authority: "ownmesh_device",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  const applied = await applyMcpOperationResult(store, {
    operationId: decisionOpId,
    correlationId: decisionOpId,
    deviceId,
    payload: {
      status: "completed",
      operation_id: decisionOpId,
      result: {
        approval_decision_applied: true,
        decision: "deny",
        target_operation_id: targetOpId,
        approval_id: "apr_device_2",
        state: "denied",
      },
    },
  });
  assert.equal(applied.ok, true);
  assert.equal((await store.getMcpOperation(targetOpId))?.status, "denied");
});
