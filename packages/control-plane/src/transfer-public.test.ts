import assert from "node:assert/strict";
import test from "node:test";
import { buildTicketlessTransferStartOutbox, finalTransferPlanHash, handleMcp, MCP_TOOLS, OperationTracker, transferGrantPayloadHash, transferStartAuditedFacts, type OperationRouter, type TransferPlanMeta } from "./mcp.ts";
import { MemoryStore } from "./store.ts";
import { canonicalTransferEphemeralProof, type TransferTicketClaims } from "./transfer-room.ts";

const hex = (bytes: Uint8Array) => [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

function request(token: string, name: string, args: Record<string, unknown>): Request {
  return new Request("https://cp.test/mcp", { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }) });
}

async function fixture(store = new MemoryStore()) {
  await store.ensureBootstrap();
  const token = await store.issueTokens("client_transfer", "prin_dev", "ownmesh.read ownmesh.write");
  const foreign = await store.issueTokens("client_transfer_foreign", "prin_foreign", "ownmesh.read ownmesh.write");
  for (const id of ["dev_source", "dev_destination"]) await store.putDevice({ id, tenant_id: "ten_default", principal_id: "prin_dev", name: id, hostname: id, os: "test", arch: "test", agent_version: "test", protocol_version: "ownmesh.device/1.0", public_key: "ab".repeat(32), revoked: false, created_at: new Date().toISOString(), status: "active" });
  await store.putWorkspace({ workspace_id: "ws_source", tenant_id: "ten_default", device_id: "dev_source", owner_principal_id: "prin_dev", version: 1, active: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  await store.putWorkspace({ workspace_id: "ws_destination", tenant_id: "ten_default", device_id: "dev_destination", owner_principal_id: "prin_dev", version: 1, active: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  const routed: Array<{ deviceId: string; operation: Record<string, unknown> }> = [];
  const liveRouted: Array<{ deviceId: string; operation: Record<string, unknown> }> = [];
  const roomTerminalized: Array<Record<string, unknown>> = [];
  const router: OperationRouter = {
    async routeToDevice(deviceId, operation) { routed.push({ deviceId, operation: operation as unknown as Record<string, unknown> }); return { status: "routed_to_device" }; },
    async routeLiveToDevice(deviceId, operation) { liveRouted.push({ deviceId, operation: operation as unknown as Record<string, unknown> }); return { status: "routed_to_device" }; },
  };
  return { store, token: token.access_token, foreignToken: foreign.access_token, router, routed, liveRouted, roomTerminalized };
}

async function invoke(f: Awaited<ReturnType<typeof fixture>>, name: string, args: Record<string, unknown>, token = f.token) {
  const response = await handleMcp(request(token, name, args), f.store, new URL("https://cp.test/mcp"), f.router, { tracker: new OperationTracker(), transferTicketSecret: "transfer-public-test-secret", terminalizeTransferRoom: async (control) => { f.roomTerminalized.push(control); return true; } });
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
  const payload = f.routed[0].operation.payload as Record<string, unknown>;
  assert.equal(payload.capability, "transfer.preflight_source");
  assert.equal((payload.arguments as Record<string, unknown>).session_nonce, `nonce_${transferId}`);
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
  const foreign = await invoke(f, "ownmesh_transfer_status", { transfer_id: transferId }, f.foreignToken);
  assert.equal(foreign.error?.message, "transfer_not_available");
  assert.equal((await f.store.getMcpOperation(transferId))?.status, "running", "foreign status must not reconcile another principal's transfer");
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

test("source reply loss after destination publication completes only after exact source cleanup", async () => {
  const f = await fixture();
  const created = await invoke(f, "ownmesh_transfer_plan", { source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", source_path: "in/a.bin", destination_path: "out/a.bin", idempotency_key: "published-loss-plan" });
  const transferId = created.result!.structuredContent!.operation_id;
  const parent = await f.store.getMcpOperation(transferId); assert.ok(parent);
  const meta = parent.data.__ownmesh_transfer_plan as Record<string, unknown>;
  await f.store.updateMcpOperation(transferId, { status: "running", data: { __ownmesh_transfer_plan: { ...meta, state: "sending", plan_sha256: "a".repeat(64), source_plan_id: "plan_source", source_sha256: "d".repeat(64), source_size_bytes: 7, source_start_operation_id: "op_lost_source", destination_start_operation_id: "op_published_destination", source_start_routed: true, destination_start_routed: true } } });
  await f.store.putMcpOperation({ ...parent, operation_id: "op_lost_source", correlation_id: "op_lost_source", device_id: "dev_source", tool: "__transfer_start_source", status: "failed", summary: "finish ack lost", data: { error: { code: "OWNMESH_E_TRANSFER_SESSION_LOST" } }, idempotency_key: "op_lost_source", created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  await f.store.putMcpOperation({ ...parent, operation_id: "op_published_destination", correlation_id: "op_published_destination", device_id: "dev_destination", tool: "__transfer_start_destination", status: "completed", summary: "published", data: { transfer_id: transferId, plan_id: "plan_destination", role: "destination", published: true, completed: true, artifact_sha256: "d".repeat(64) }, idempotency_key: "op_published_destination", created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  const pending = await invoke(f, "ownmesh_transfer_status", { transfer_id: transferId });
  const pendingTransfer = pending.result!.structuredContent!.data.transfer as Record<string, unknown>;
  assert.equal(pendingTransfer.state, "source_cleanup"); assert.equal(pendingTransfer.epoch, 1);
  assert.equal(f.roomTerminalized.length, 1);
  assert.deepEqual(f.roomTerminalized[0], { transfer_id: transferId, plan_sha256: "a".repeat(64), epoch: 1, fence: 1, artifact_sha256: "d".repeat(64) });
  assert.equal((f.routed.at(-1)!.operation.payload as Record<string, unknown>).capability, "operation.cancel");
  let current = await f.store.getMcpOperation(transferId); assert.ok(current);
  let currentMeta = current.data.__ownmesh_transfer_plan as TransferPlanMeta;
  assert.equal(typeof currentMeta.source_cleanup_control_operation_id, "string");
  await f.store.updateMcpOperation(currentMeta.source_cleanup_control_operation_id!, {
    status: "completed", summary: "source task already gone",
    data: { target_operation_id: "op_lost_source", cancelled: false, signal_delivered: false },
  }, ["pending"]);

  const cleaning = await invoke(f, "ownmesh_transfer_status", { transfer_id: transferId });
  assert.equal((cleaning.result!.structuredContent!.data.transfer as Record<string, unknown>).state, "source_cleanup");
  const cleanupPayload = f.routed.at(-1)!.operation.payload as Record<string, unknown>;
  assert.equal(cleanupPayload.capability, "transfer.source_cleanup");
  current = await f.store.getMcpOperation(transferId); assert.ok(current);
  currentMeta = current.data.__ownmesh_transfer_plan as TransferPlanMeta;
  assert.equal(typeof currentMeta.source_cleanup_operation_id, "string");
  await f.store.updateMcpOperation(currentMeta.source_cleanup_operation_id!, {
    status: "completed", summary: "source custody cleaned",
    data: { plan_id: "plan_source", cleaned: true, source_only: true },
  }, ["pending"]);
  const completed = await invoke(f, "ownmesh_transfer_status", { transfer_id: transferId });
  const completedTransfer = completed.result!.structuredContent!.data.transfer as Record<string, unknown>;
  assert.equal(completedTransfer.state, "completed"); assert.equal(completedTransfer.epoch, 1);
});

test("parallel published-cleanup reconciliation claims one control and one cleanup under delayed storage", async () => {
  const store = new MemoryStore();
  // Force every durable operation to yield so status polls observe the same
  // parent snapshot before one of their CAS writes wins.
  const delay = () => new Promise<void>((resolve) => setTimeout(resolve, 2));
  const update = store.updateMcpOperation.bind(store);
  store.updateMcpOperation = async (...args) => { await delay(); return update(...args); };
  const claim = store.claimMcpOperationByIdempotency.bind(store);
  store.claimMcpOperationByIdempotency = async (...args) => { await delay(); return claim(...args); };
  const f = await fixture(store);
  const created = await invoke(f, "ownmesh_transfer_plan", { source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", source_path: "in/a.bin", destination_path: "out/a.bin", idempotency_key: "parallel-cleanup-plan" });
  const transferId = created.result!.structuredContent!.operation_id;
  const parent = await f.store.getMcpOperation(transferId); assert.ok(parent);
  const original = parent.data.__ownmesh_transfer_plan as Record<string, unknown>;
  const sourceStart = "op_parallel_lost_source";
  await f.store.updateMcpOperation(transferId, {
    status: "running",
    data: { __ownmesh_transfer_plan: {
      ...original, state: "source_cleanup", room_terminalized: true,
      plan_sha256: "a".repeat(64), source_sha256: "b".repeat(64), source_size_bytes: 9,
      source_plan_id: "plan_parallel_source", destination_plan_id: "plan_parallel_destination",
      source_start_operation_id: sourceStart, source_start_routed: true,
    } },
  });
  await f.store.putMcpOperation({ ...parent, operation_id: sourceStart, correlation_id: sourceStart, device_id: "dev_source", tool: "__transfer_start", status: "failed", summary: "lost finish acknowledgement", data: {}, idempotency_key: sourceStart, created_at: new Date().toISOString(), updated_at: new Date().toISOString() });

  const first = await Promise.all(Array.from({ length: 12 }, () => invoke(f, "ownmesh_transfer_status", { transfer_id: transferId })));
  for (const result of first) assert.equal(result.error, undefined, "parallel status must not surface a 5xx");
  assert.equal(f.routed.filter((entry) => (entry.operation.payload as Record<string, unknown>).capability === "operation.cancel").length, 1);
  let current = await f.store.getMcpOperation(transferId); assert.ok(current);
  let currentMeta = current.data.__ownmesh_transfer_plan as TransferPlanMeta;
  const controlId = currentMeta.source_cleanup_control_operation_id;
  assert.equal(typeof controlId, "string", "CAS winner id is retained on the parent");
  await f.store.updateMcpOperation(controlId!, { status: "completed", summary: "source start already stopped", data: { target_operation_id: sourceStart, cancelled: false, signal_delivered: false } }, ["pending"]);

  const second = await Promise.all(Array.from({ length: 12 }, () => invoke(f, "ownmesh_transfer_status", { transfer_id: transferId })));
  for (const result of second) assert.equal(result.error, undefined, "parallel cleanup status must not surface a 5xx");
  assert.equal(f.routed.filter((entry) => (entry.operation.payload as Record<string, unknown>).capability === "transfer.source_cleanup").length, 1);
  current = await f.store.getMcpOperation(transferId); assert.ok(current);
  currentMeta = current.data.__ownmesh_transfer_plan as TransferPlanMeta;
  const cleanupId = currentMeta.source_cleanup_operation_id;
  assert.equal(typeof cleanupId, "string", "cleanup claim winner id is retained on the parent");
  assert.ok((currentMeta.cleanup_generation || 0) >= 2, "cleanup parent CAS generation advances monotonically");
  await f.store.updateMcpOperation(cleanupId!, { status: "completed", summary: "source custody cleaned", data: { plan_id: "plan_parallel_source", cleaned: true, source_only: true } }, ["pending"]);
  const converged = await invoke(f, "ownmesh_transfer_status", { transfer_id: transferId });
  assert.equal((converged.result!.structuredContent!.data.transfer as Record<string, unknown>).state, "completed");
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
  for (const [controlId, target] of [[cancelMeta.source_cancel_operation_id, "op_cancel_source"], [cancelMeta.destination_cancel_operation_id, "op_cancel_destination"]]) {
    assert.equal(typeof controlId, "string"); await f.store.updateMcpOperation(controlId as string, { status: "completed", summary: "cancelled receipt", data: { target_operation_id: target, cancelled: true, signal_delivered: true } }, ["pending"]);
  }
  const settled = await invoke(f, "ownmesh_transfer_status", { transfer_id: transferId });
  assert.equal((settled.result!.structuredContent!.data.transfer as Record<string, unknown>).state, "cancelled");
  const repeat = await invoke(f, "ownmesh_transfer_cancel", { transfer_id: transferId, idempotency_key: "cancel-key" });
  assert.equal((repeat.result!.structuredContent!.data.transfer as Record<string, unknown>).state, "cancelled"); assert.equal(f.routed.length, 2, "cancel receipt polling must not route controls again");
});

test("concurrent public sends claim one start pair and cancel targets only that generation", async () => {
  const f = await fixture();
  const created = await invoke(f, "ownmesh_transfer_plan", { source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", source_path: "in/a.bin", destination_path: "out/a.bin", idempotency_key: "concurrent-plan" });
  const transferId = created.result!.structuredContent!.operation_id;
  const parent = await f.store.getMcpOperation(transferId); assert.ok(parent);
  const original = parent.data.__ownmesh_transfer_plan as TransferPlanMeta;
  const sourceKey = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const destinationKey = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  if (!("publicKey" in sourceKey) || !("publicKey" in destinationKey)) throw new Error("Ed25519 unavailable");
  const sourcePublicKey = hex(new Uint8Array(await crypto.subtle.exportKey("raw", sourceKey.publicKey) as ArrayBuffer));
  const destinationPublicKey = hex(new Uint8Array(await crypto.subtle.exportKey("raw", destinationKey.publicKey) as ArrayBuffer));
  const sourceDevice = await f.store.getDevice("dev_source"); const destinationDevice = await f.store.getDevice("dev_destination");
  assert.ok(sourceDevice); assert.ok(destinationDevice);
  await f.store.putDevice({ ...sourceDevice, public_key: sourcePublicKey });
  await f.store.putDevice({ ...destinationDevice, public_key: destinationPublicKey });
  const planSha256 = "a".repeat(64); const sourceSha256 = "b".repeat(64);
  const sourcePreflightId = "op_concurrent_source_preflight"; const destinationPreflightId = "op_concurrent_destination_preflight";
  const expiresAt = Date.parse(original.expires_at);
  const sourceReply = {
    role: "source" as const, transfer_id: transferId, tenant_id: original.tenant_id, device_id: original.source_device_id,
    workspace_id: original.source_workspace_id, plan_sha256: planSha256, epoch: original.epoch, fence: original.fence,
    session_nonce: `nonce_${transferId}`, expires_at: expiresAt, ephemeral_public_key: "11".repeat(32), ephemeral_signature: "",
  };
  const destinationReply = {
    role: "destination" as const, transfer_id: transferId, tenant_id: original.tenant_id, device_id: original.destination_device_id,
    workspace_id: original.destination_workspace_id, plan_sha256: planSha256, epoch: original.epoch, fence: original.fence,
    session_nonce: `nonce_${transferId}`, expires_at: expiresAt, ephemeral_public_key: "22".repeat(32), ephemeral_signature: "",
  };
  const proofClaims = (role: "source" | "destination"): TransferTicketClaims => ({
    v: 1, jti: "proof_only", session_nonce: `nonce_${transferId}`, transfer_id: transferId, tenant_id: original.tenant_id,
    principal_id: original.principal_id, device_id: role === "source" ? original.source_device_id : original.destination_device_id, role,
    source_device_id: original.source_device_id, destination_device_id: original.destination_device_id,
    source_workspace_id: original.source_workspace_id, destination_workspace_id: original.destination_workspace_id,
    plan_sha256: planSha256, epoch: original.epoch, fence: original.fence, max_bytes: 3,
    ticket_exp: Date.now() + 30_000, transfer_expires_at: expiresAt,
    source_device_public_key: sourcePublicKey, destination_device_public_key: destinationPublicKey,
    source_ephemeral_public_key: sourceReply.ephemeral_public_key, destination_ephemeral_public_key: destinationReply.ephemeral_public_key,
    source_ephemeral_signature: sourceReply.ephemeral_signature, destination_ephemeral_signature: destinationReply.ephemeral_signature,
  });
  sourceReply.ephemeral_signature = hex(new Uint8Array(await crypto.subtle.sign("Ed25519", sourceKey.privateKey, canonicalTransferEphemeralProof(proofClaims("source"), "source"))));
  destinationReply.ephemeral_signature = hex(new Uint8Array(await crypto.subtle.sign("Ed25519", destinationKey.privateKey, canonicalTransferEphemeralProof(proofClaims("destination"), "destination"))));
  const ready: TransferPlanMeta = {
    ...original, state: "destination_preflight", plan_sha256: planSha256, source_sha256: sourceSha256, source_size_bytes: 3,
    source_plan_id: "plan_concurrent_source", source_preflight_operation_id: sourcePreflightId,
    destination_preflight_operation_id: destinationPreflightId, send_idempotency_key: "concurrent-send",
  };
  await f.store.updateMcpOperation(transferId, { status: "pending", data: { __ownmesh_transfer_plan: ready } });
  for (const [operation_id, device_id, tool, reply] of [
    [sourcePreflightId, "dev_source", "__transfer_preflight_source_final", sourceReply],
    [destinationPreflightId, "dev_destination", "__transfer_preflight_destination", destinationReply],
  ] as const) {
    await f.store.putMcpOperation({ ...parent, operation_id, correlation_id: operation_id, device_id, tool, status: "completed", summary: "authenticated preflight", data: { transfer_preflight: reply }, idempotency_key: operation_id, created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  }

  const sends = await Promise.all([
    invoke(f, "ownmesh_transfer_send", { transfer_id: transferId, idempotency_key: "concurrent-send" }),
    invoke(f, "ownmesh_transfer_send", { transfer_id: transferId, idempotency_key: "concurrent-send" }),
  ]);
  assert.ok(sends.every((result) => !result.error));
  assert.equal(f.liveRouted.length, 2, "only one source/destination start pair may be delivered live");
  const activeIds = f.liveRouted.map((entry) => entry.operation.correlation_id as string).sort();
  const claimed = await f.store.getMcpOperation(transferId); assert.ok(claimed);
  const claimedMeta = claimed.data.__ownmesh_transfer_plan as TransferPlanMeta;
  assert.equal(claimedMeta.pair_generation, 1);
  assert.deepEqual([claimedMeta.source_start_operation_id, claimedMeta.destination_start_operation_id].sort(), activeIds);

  const cancelled = await invoke(f, "ownmesh_transfer_cancel", { transfer_id: transferId, idempotency_key: "cancel-concurrent" });
  assert.equal((cancelled.result!.structuredContent!.data.transfer as Record<string, unknown>).state, "cancelling");
  assert.deepEqual(f.routed.map((entry) => ((entry.operation.payload as Record<string, unknown>).arguments as Record<string, unknown>).target_operation_id).sort(), activeIds);
  const cancelling = await f.store.getMcpOperation(transferId); assert.ok(cancelling);
  const cancelMeta = cancelling.data.__ownmesh_transfer_plan as TransferPlanMeta;
  for (const [controlId, target] of [[cancelMeta.source_cancel_operation_id, claimedMeta.source_start_operation_id], [cancelMeta.destination_cancel_operation_id, claimedMeta.destination_start_operation_id]]) {
    assert.equal(typeof controlId, "string"); assert.equal(typeof target, "string");
    await f.store.updateMcpOperation(controlId!, { status: "completed", summary: "cleanup proven", data: { target_operation_id: target, cancelled: true, signal_delivered: true } }, ["pending"]);
  }
  const settled = await invoke(f, "ownmesh_transfer_status", { transfer_id: transferId });
  assert.equal((settled.result!.structuredContent!.data.transfer as Record<string, unknown>).state, "cancelled");
});

test("cancel remains unresolved when a restarted Agent cannot prove durable cleanup", async () => {
  const f = await fixture();
  const created = await invoke(f, "ownmesh_transfer_plan", { source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", source_path: "in/a.bin", destination_path: "out/a.bin", idempotency_key: "cancel-uncertain-plan" });
  const transferId = created.result!.structuredContent!.operation_id;
  const parent = await f.store.getMcpOperation(transferId); assert.ok(parent);
  const meta = parent.data.__ownmesh_transfer_plan as Record<string, unknown>;
  await f.store.updateMcpOperation(transferId, { status: "running", data: { __ownmesh_transfer_plan: { ...meta, state: "sending", source_start_operation_id: "op_restarted_source", destination_start_operation_id: "op_restarted_destination", source_start_routed: true, destination_start_routed: true } } });
  const result = await invoke(f, "ownmesh_transfer_cancel", { transfer_id: transferId, idempotency_key: "cancel-uncertain-key" });
  assert.equal((result.result!.structuredContent!.data.transfer as Record<string, unknown>).state, "cancelling");
  const cancelling = await f.store.getMcpOperation(transferId); assert.ok(cancelling);
  const cancelMeta = cancelling.data.__ownmesh_transfer_plan as Record<string, unknown>;
  for (const [controlId, target] of [[cancelMeta.source_cancel_operation_id, "op_restarted_source"], [cancelMeta.destination_cancel_operation_id, "op_restarted_destination"]]) {
    await f.store.updateMcpOperation(controlId as string, { status: "completed", data: { target_operation_id: target, cancelled: false, signal_delivered: false } }, ["pending"]);
  }
  const status = await invoke(f, "ownmesh_transfer_status", { transfer_id: transferId });
  assert.equal((status.result!.structuredContent!.data.transfer as Record<string, unknown>).state, "cancelling");
});

test("completed transfer artifact get is destination-bound and page-bounded", async () => {
  const f = await fixture();
  const created = await invoke(f, "ownmesh_transfer_plan", { source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", source_path: "in/a.bin", destination_path: "out/a.bin", idempotency_key: "artifact-plan" });
  const transferId = created.result!.structuredContent!.operation_id;
  const parent = await f.store.getMcpOperation(transferId); assert.ok(parent);
  const meta = parent.data.__ownmesh_transfer_plan as Record<string, unknown>;
  await f.store.updateMcpOperation(transferId, { status: "completed", data: { __ownmesh_transfer_plan: { ...meta, state: "completed", destination_plan_id: "plan_destination", source_sha256: "a".repeat(64), source_size_bytes: 131072 } } });
  const get = await invoke(f, "ownmesh_transfer_get", { transfer_id: transferId, offset: 65536, max_bytes: 65536 });
  assert.match(get.result!.structuredContent!.operation_id, /^op_/);
  assert.equal(f.routed.length, 1); assert.equal(f.routed[0].deviceId, "dev_destination");
  const payload = f.routed[0].operation.payload as Record<string, unknown>;
  assert.equal(payload.capability, "transfer.artifact_get");
  assert.equal(Object.hasOwn(payload.arguments as Record<string, unknown>, "idempotency_key"), false);
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

test("durable plan grant identity survives epoch/fence advance but binds immutable custody", async () => {
  const meta: TransferPlanMeta = {
    transfer_id: "op_resume", tenant_id: "ten_a", principal_id: "prin_a",
    source_device_id: "dev_s", destination_device_id: "dev_d",
    source_workspace_id: "ws_s", destination_workspace_id: "ws_d",
    source_path: "in/a.bin", destination_path: "out/a.bin",
    source_workspace_version: 1, destination_workspace_version: 1,
    epoch: 1, fence: 1, ttl_seconds: 3600, expires_at: new Date(1_900_000_000_000).toISOString(), state: "sending",
  };
  const first = await transferGrantPayloadHash(meta, "a".repeat(64), 7);
  assert.equal(await transferGrantPayloadHash({ ...meta, epoch: 2, fence: 2 }, "a".repeat(64), 7), first);
  assert.notEqual(await transferGrantPayloadHash({ ...meta, destination_path: "out/other.bin" }, "a".repeat(64), 7), first);
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

test("transfer start audited facts exclude live bearer and duplicate workspace routing", () => {
  assert.deepEqual(transferStartAuditedFacts({
    action: "transfer.start", ticket: "live-only", workspace_id: "ws_destination", transfer_id: "xfer_1",
    destination_workspace_id: "ws_destination", epoch: 1, fence: 2,
  }), {
    transfer_id: "xfer_1", destination_workspace_id: "ws_destination", epoch: 1, fence: 2,
  });
});
