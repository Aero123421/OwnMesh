import assert from "node:assert/strict";
import test from "node:test";
import { buildTicketlessTransferStartOutbox, finalTransferPlanHash, handleMcp, MCP_TOOLS, OperationTracker, type OperationRouter, type TransferPlanMeta } from "./mcp.ts";
import { MemoryStore } from "./store.ts";

function request(token: string, name: string, args: Record<string, unknown>): Request {
  return new Request("https://cp.test/mcp", { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }) });
}

async function fixture() {
  const store = new MemoryStore(); await store.ensureBootstrap();
  const token = await store.issueTokens("client_transfer", "prin_dev", "ownmesh.read ownmesh.write");
  for (const id of ["dev_source", "dev_destination"]) await store.putDevice({ id, tenant_id: "ten_default", principal_id: "prin_dev", name: id, hostname: id, os: "test", arch: "test", agent_version: "test", protocol_version: "ownmesh.device/1.0", public_key: "ab".repeat(32), revoked: false, created_at: new Date().toISOString(), status: "active" });
  await store.putWorkspace({ workspace_id: "ws_source", tenant_id: "ten_default", device_id: "dev_source", owner_principal_id: "prin_dev", version: 1, active: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  await store.putWorkspace({ workspace_id: "ws_destination", tenant_id: "ten_default", device_id: "dev_destination", owner_principal_id: "prin_dev", version: 1, active: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  const routed: Array<{ deviceId: string; operation: Record<string, unknown> }> = [];
  const router: OperationRouter = { async routeToDevice(deviceId, operation) { routed.push({ deviceId, operation: operation as unknown as Record<string, unknown> }); return { status: "routed_to_device" }; } };
  return { store, token: token.access_token, router, routed };
}

async function invoke(f: Awaited<ReturnType<typeof fixture>>, name: string, args: Record<string, unknown>) {
  const response = await handleMcp(request(f.token, name, args), f.store, new URL("https://cp.test/mcp"), f.router, { tracker: new OperationTracker() });
  return await response.json() as { result?: { structuredContent?: { operation_id: string; data: Record<string, unknown> } }; error?: { message: string } };
}

test("public transfer tools have strict schemas and plan stores no payload material", async () => {
  for (const name of ["ownmesh_transfer_plan", "ownmesh_transfer_send", "ownmesh_transfer_get", "ownmesh_transfer_list", "ownmesh_transfer_status", "ownmesh_transfer_cancel"]) assert.ok(MCP_TOOLS.some((tool) => tool.name === name));
  const f = await fixture();
  const result = await invoke(f, "ownmesh_transfer_plan", { source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", source_path: "in/a.bin", destination_path: "out/a.bin", idempotency_key: "xfer-1" });
  const content = result.result!.structuredContent!;
  const serialized = JSON.stringify(content.data);
  assert.match(content.operation_id, /^op_/);
  assert.equal(serialized.includes("ticket"), false);
  assert.equal(serialized.includes("ciphertext"), false);
  assert.equal(serialized.includes("source_path"), false);
  const rejected = await invoke(f, "ownmesh_transfer_plan", { source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", source_path: "/absolute", destination_path: "out/a.bin", idempotency_key: "xfer-2" });
  assert.equal(rejected.error?.message, "invalid transfer plan arguments");
  const unknown = await invoke(f, "ownmesh_transfer_plan", { source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", source_path: "in/a.bin", destination_path: "out/a.bin", idempotency_key: "xfer-3", overwrite: true });
  assert.equal(unknown.error?.message, "unknown transfer argument");
});

test("send dispatches only source authenticated preflight and cancel fences state", async () => {
  const f = await fixture();
  const plan = await invoke(f, "ownmesh_transfer_plan", { source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", source_path: "in/a.bin", destination_path: "out/a.bin", idempotency_key: "xfer-1" });
  const transferId = plan.result!.structuredContent!.operation_id;
  const sent = await invoke(f, "ownmesh_transfer_send", { transfer_id: transferId, idempotency_key: "send-1" });
  assert.equal(f.routed.length, 1);
  assert.equal(f.routed[0].deviceId, "dev_source");
  assert.equal(((f.routed[0].operation.payload as Record<string, unknown>).capability), "transfer.preflight_source");
  assert.equal(JSON.stringify(sent.result!.structuredContent!.data).includes("ticket"), false);
  const cancelled = await invoke(f, "ownmesh_transfer_cancel", { transfer_id: transferId, idempotency_key: "cancel-1" });
  const transfer = cancelled.result!.structuredContent!.data.transfer as Record<string, unknown>;
  assert.equal(transfer.state, "cancelled");
  assert.equal(transfer.fence, 2);
});

test("status CAS-reconciles both durable transfer.start results", async () => {
  const f = await fixture();
  const created = await invoke(f, "ownmesh_transfer_plan", { source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", source_path: "in/a.bin", destination_path: "out/a.bin", idempotency_key: "reconcile-plan" });
  const transferId = created.result!.structuredContent!.operation_id;
  const parent = await f.store.getMcpOperation(transferId);
  assert.ok(parent);
  const meta = parent.data.__ownmesh_transfer_plan as Record<string, unknown>;
  const sourceId = "op_start_source"; const destinationId = "op_start_destination";
  await f.store.updateMcpOperation(transferId, { status: "running", data: { __ownmesh_transfer_plan: { ...meta, state: "sending", source_start_operation_id: sourceId, destination_start_operation_id: destinationId, pair_generation: 1 } } });
  for (const [operation_id, device_id] of [[sourceId, "dev_source"], [destinationId, "dev_destination"]] as const) {
    await f.store.putMcpOperation({ ...parent, operation_id, correlation_id: operation_id, device_id, tool: "__transfer_start", status: "completed", summary: "finished", data: device_id === "dev_destination" ? { plan_id: "plan_destination" } : { plan_id: "plan_source" }, idempotency_key: operation_id, created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  }
  const status = await invoke(f, "ownmesh_transfer_status", { transfer_id: transferId });
  assert.equal((status.result!.structuredContent!.data.transfer as Record<string, unknown>).state, "completed");
  const listed = await invoke(f, "ownmesh_transfer_list", {});
  const transfers = listed.result!.structuredContent!.data.transfers as Array<Record<string, unknown>>;
  assert.equal(transfers.find((entry) => entry.operation_id === transferId)?.state, "completed");
});

test("uncertain start route recovery fences and creates a fresh preflight generation", async () => {
  const f = await fixture();
  const created = await invoke(f, "ownmesh_transfer_plan", { source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", source_path: "in/a.bin", destination_path: "out/a.bin", idempotency_key: "recovery-plan" });
  const transferId = created.result!.structuredContent!.operation_id;
  const parent = await f.store.getMcpOperation(transferId); assert.ok(parent);
  const meta = parent.data.__ownmesh_transfer_plan as Record<string, unknown>;
  await f.store.updateMcpOperation(transferId, { status: "running", data: { __ownmesh_transfer_plan: { ...meta, state: "sending", source_start_operation_id: "op_old_source", destination_start_operation_id: "op_old_destination", source_start_routed: true, destination_start_routed: false, pair_generation: 1 } } });
  for (const operation_id of ["op_old_source", "op_old_destination"]) await f.store.putMcpOperation({ ...parent, operation_id, correlation_id: operation_id, device_id: operation_id.endsWith("source") ? "dev_source" : "dev_destination", tool: "__transfer_start", status: "pending", summary: "old generation", data: {}, idempotency_key: operation_id, created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  const recovered = await invoke(f, "ownmesh_transfer_send", { transfer_id: transferId, idempotency_key: "send-recovery" });
  const transfer = recovered.result!.structuredContent!.data.transfer as Record<string, unknown>;
  assert.equal(transfer.state, "source_preflight"); assert.equal(transfer.epoch, 2); assert.equal(transfer.fence, 2);
  assert.equal(f.routed.at(-1)!.deviceId, "dev_source");
});

test("crash before either start route is also recovered with fresh proofs", async () => {
  const f = await fixture();
  const created = await invoke(f, "ownmesh_transfer_plan", { source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", source_path: "in/a.bin", destination_path: "out/a.bin", idempotency_key: "prepared-crash-plan" });
  const transferId = created.result!.structuredContent!.operation_id;
  const parent = await f.store.getMcpOperation(transferId); assert.ok(parent);
  const meta = parent.data.__ownmesh_transfer_plan as Record<string, unknown>;
  await f.store.updateMcpOperation(transferId, { status: "running", data: { __ownmesh_transfer_plan: { ...meta, state: "sending", source_start_operation_id: "op_prepared_source", destination_start_operation_id: "op_prepared_destination", source_start_routed: false, destination_start_routed: false, pair_generation: 7 } } });
  for (const operation_id of ["op_prepared_source", "op_prepared_destination"]) await f.store.putMcpOperation({ ...parent, operation_id, correlation_id: operation_id, device_id: operation_id.endsWith("source") ? "dev_source" : "dev_destination", tool: "__transfer_start", status: "pending", summary: "prepared only", data: {}, idempotency_key: operation_id, created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  const recovered = await invoke(f, "ownmesh_transfer_send", { transfer_id: transferId, idempotency_key: "send-prepared-recovery" });
  const transfer = recovered.result!.structuredContent!.data.transfer as Record<string, unknown>;
  assert.equal(transfer.epoch, 2); assert.equal(transfer.fence, 2); assert.equal(transfer.state, "source_preflight");
  assert.equal(((f.routed[0].operation.payload as Record<string, unknown>).capability), "transfer.preflight_source");
});

test("integrity failure is terminal and never rekeys a transfer", async () => {
  const f = await fixture();
  const created = await invoke(f, "ownmesh_transfer_plan", { source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", source_path: "in/a.bin", destination_path: "out/a.bin", idempotency_key: "terminal-plan" });
  const transferId = created.result!.structuredContent!.operation_id;
  const parent = await f.store.getMcpOperation(transferId); assert.ok(parent);
  const meta = parent.data.__ownmesh_transfer_plan as Record<string, unknown>;
  await f.store.updateMcpOperation(transferId, { status: "running", data: { __ownmesh_transfer_plan: { ...meta, state: "sending", source_start_operation_id: "op_bad_source", destination_start_operation_id: "op_bad_destination", source_start_routed: true, destination_start_routed: true } } });
  await f.store.putMcpOperation({ ...parent, operation_id: "op_bad_source", correlation_id: "op_bad_source", device_id: "dev_source", tool: "__transfer_start", status: "failed", summary: "bad hash", data: { error: { code: "integrity_hash_mismatch" } }, idempotency_key: "op_bad_source", created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  await f.store.putMcpOperation({ ...parent, operation_id: "op_bad_destination", correlation_id: "op_bad_destination", device_id: "dev_destination", tool: "__transfer_start", status: "pending", summary: "waiting", data: {}, idempotency_key: "op_bad_destination", created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  const result = await invoke(f, "ownmesh_transfer_send", { transfer_id: transferId, idempotency_key: "send-terminal" });
  const transfer = result.result!.structuredContent!.data.transfer as Record<string, unknown>;
  assert.equal(transfer.state, "failed"); assert.equal(transfer.epoch, 1); assert.equal(f.routed.length, 0);
});

test("source reply loss after authenticated destination publication converges without rekey", async () => {
  const f = await fixture();
  const created = await invoke(f, "ownmesh_transfer_plan", { source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", source_path: "in/a.bin", destination_path: "out/a.bin", idempotency_key: "published-loss-plan" });
  const transferId = created.result!.structuredContent!.operation_id;
  const parent = await f.store.getMcpOperation(transferId); assert.ok(parent);
  const meta = parent.data.__ownmesh_transfer_plan as Record<string, unknown>;
  await f.store.updateMcpOperation(transferId, { status: "running", data: { __ownmesh_transfer_plan: { ...meta, state: "sending", source_start_operation_id: "op_lost_source", destination_start_operation_id: "op_published_destination", source_start_routed: true, destination_start_routed: true } } });
  await f.store.putMcpOperation({ ...parent, operation_id: "op_lost_source", correlation_id: "op_lost_source", device_id: "dev_source", tool: "__transfer_start_source", status: "failed", summary: "finish ack lost", data: { error: { code: "OWNMESH_E_TRANSFER_SESSION_LOST" } }, idempotency_key: "op_lost_source", created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  await f.store.putMcpOperation({ ...parent, operation_id: "op_published_destination", correlation_id: "op_published_destination", device_id: "dev_destination", tool: "__transfer_start_destination", status: "completed", summary: "published", data: { transfer_id: transferId, plan_id: "plan_destination", role: "destination", published: true, completed: true, artifact_sha256: "d".repeat(64) }, idempotency_key: "op_published_destination", created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  const status = await invoke(f, "ownmesh_transfer_status", { transfer_id: transferId });
  const transfer = status.result!.structuredContent!.data.transfer as Record<string, unknown>;
  assert.equal(transfer.state, "completed"); assert.equal(transfer.epoch, 1); assert.equal(f.routed.length, 0);
});

test("cancel fans out exact generic cancel controls and never retries them as a send", async () => {
  const f = await fixture();
  const created = await invoke(f, "ownmesh_transfer_plan", { source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", source_path: "in/a.bin", destination_path: "out/a.bin", idempotency_key: "cancel-plan" });
  const transferId = created.result!.structuredContent!.operation_id;
  const parent = await f.store.getMcpOperation(transferId); assert.ok(parent);
  const meta = parent.data.__ownmesh_transfer_plan as Record<string, unknown>;
  await f.store.updateMcpOperation(transferId, { status: "running", data: { __ownmesh_transfer_plan: { ...meta, state: "sending", source_start_operation_id: "op_cancel_source", destination_start_operation_id: "op_cancel_destination", source_start_routed: true, destination_start_routed: true } } });
  const result = await invoke(f, "ownmesh_transfer_cancel", { transfer_id: transferId, idempotency_key: "cancel-key" });
  const transfer = result.result!.structuredContent!.data.transfer as Record<string, unknown>;
  assert.equal(transfer.state, "cancelling"); assert.equal(f.routed.length, 2);
  assert.deepEqual(f.routed.map((entry) => (entry.operation.payload as Record<string, unknown>).capability), ["operation.cancel", "operation.cancel"]);
  assert.deepEqual(f.routed.map((entry) => ((entry.operation.payload as Record<string, unknown>).arguments as Record<string, unknown>).target_operation_id).sort(), ["op_cancel_destination", "op_cancel_source"]);
  const cancelling = await f.store.getMcpOperation(transferId); assert.ok(cancelling);
  const cancelMeta = cancelling.data.__ownmesh_transfer_plan as Record<string, unknown>;
  for (const controlId of [cancelMeta.source_cancel_operation_id, cancelMeta.destination_cancel_operation_id]) {
    assert.equal(typeof controlId, "string"); await f.store.updateMcpOperation(controlId as string, { status: "completed", summary: "cancelled receipt" }, ["pending"]);
  }
  const settled = await invoke(f, "ownmesh_transfer_status", { transfer_id: transferId });
  assert.equal((settled.result!.structuredContent!.data.transfer as Record<string, unknown>).state, "cancelled");
  const repeat = await invoke(f, "ownmesh_transfer_cancel", { transfer_id: transferId, idempotency_key: "cancel-key" });
  assert.equal((repeat.result!.structuredContent!.data.transfer as Record<string, unknown>).state, "cancelled"); assert.equal(f.routed.length, 2, "cancel receipt polling must not route controls again");
});

test("completed transfer artifact get is destination-bound and page-bounded", async () => {
  const f = await fixture();
  const created = await invoke(f, "ownmesh_transfer_plan", { source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", source_path: "in/a.bin", destination_path: "out/a.bin", idempotency_key: "artifact-plan" });
  const transferId = created.result!.structuredContent!.operation_id;
  const parent = await f.store.getMcpOperation(transferId); assert.ok(parent);
  const meta = parent.data.__ownmesh_transfer_plan as Record<string, unknown>;
  await f.store.updateMcpOperation(transferId, { status: "completed", data: { __ownmesh_transfer_plan: { ...meta, state: "completed", destination_plan_id: "plan_destination" } } });
  const get = await invoke(f, "ownmesh_transfer_get", { transfer_id: transferId, offset: 65536, max_bytes: 65536 });
  assert.match(get.result!.structuredContent!.operation_id, /^op_/);
  assert.equal(f.routed.length, 1); assert.equal(f.routed[0].deviceId, "dev_destination");
  const payload = f.routed[0].operation.payload as Record<string, unknown>;
  assert.equal(payload.capability, "transfer.artifact_get");
  assert.deepEqual(payload.arguments && { plan_id: (payload.arguments as Record<string, unknown>).plan_id, offset: (payload.arguments as Record<string, unknown>).offset, max_bytes: (payload.arguments as Record<string, unknown>).max_bytes }, { plan_id: "plan_destination", offset: 65536, max_bytes: 65536 });
  const tooLarge = await invoke(f, "ownmesh_transfer_get", { transfer_id: transferId, max_bytes: 65537 });
  assert.equal(tooLarge.error?.message, "invalid artifact page arguments");
});

test("final transfer-plan digest is the Rust length-prefixed golden vector", async () => {
  // Generated from ownmesh-transfer::TransferPlan::from_verified with the
  // same fixture. This catches JSON/UTF-16/order/expiry drift across the
  // Worker and Agent implementations.
  const meta: TransferPlanMeta = {
    transfer_id: "op_transfer", tenant_id: "ten_a", principal_id: "prin_a",
    source_device_id: "dev_s", destination_device_id: "dev_d",
    source_workspace_id: "ws_s", destination_workspace_id: "ws_d",
    source_path: "in/a.bin", destination_path: "out/a.bin",
    source_workspace_version: 1, destination_workspace_version: 1,
    epoch: 1, fence: 1, ttl_seconds: 3600, expires_at: new Date(1_700_000_000_000).toISOString(), state: "ready",
  };
  assert.equal(await finalTransferPlanHash(meta, "a".repeat(64), "b".repeat(64), 7), "5b337e7db7ac9f39f8c32dc2a9612893fd469a6222e10cd89cff9a2fd56d5fa8");
});

test("final transfer-plan digest uses UTF-8 byte lengths for Japanese and emoji paths", async () => {
  // Independently generated from the Rust canonical byte stream. UTF-16 code
  // unit lengths would produce a different digest for every non-ASCII field.
  const meta: TransferPlanMeta = {
    transfer_id: "op_転送😀", tenant_id: "ten_東京", principal_id: "prin_😀",
    source_device_id: "dev_源", destination_device_id: "dev_先",
    source_workspace_id: "ws_入力", destination_workspace_id: "ws_出力",
    source_path: "入力/😀.bin", destination_path: "出力/📦.bin",
    source_workspace_version: 1, destination_workspace_version: 1,
    epoch: 1, fence: 1, ttl_seconds: 3600, expires_at: new Date(1_700_000_000_000).toISOString(), state: "ready",
  };
  assert.equal(await finalTransferPlanHash(meta, "a".repeat(64), "b".repeat(64), 7), "0756a7508b6e927c63b8e58542d64c2a5b8e25821c69d00c926d154f575de23c");
});

test("durable transfer-start outbox recursively excludes bearer, JTI, and ephemeral fields", () => {
  const stored = buildTicketlessTransferStartOutbox({
    type: "operation.request", correlation_id: "op_start", payload: {
      arguments: { transfer_id: "xfer", ticket: "bearer.secret", jti: "jti_secret", source_ephemeral_public_key: "11".repeat(32), destination_ephemeral_signature: "22".repeat(64) },
    },
  });
  const forbidden = (value: unknown): boolean => {
    if (!value || typeof value !== "object") return false;
    return Object.entries(value as Record<string, unknown>).some(([key, child]) => /ticket|jti|ephemeral/i.test(key) || forbidden(child));
  };
  assert.equal(forbidden(stored), false);
  assert.equal(JSON.stringify(stored).includes("bearer.secret"), false);
  assert.equal(stored.non_redeliverable, true);
});
