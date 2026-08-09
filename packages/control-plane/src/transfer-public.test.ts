import assert from "node:assert/strict";
import test from "node:test";
import { finalTransferPlanHash, handleMcp, MCP_TOOLS, OperationTracker, type OperationRouter, type TransferPlanMeta } from "./mcp.ts";
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
    epoch: 1, fence: 1, expires_at: new Date(1_700_000_000_000).toISOString(), state: "ready",
  };
  assert.equal(await finalTransferPlanHash(meta, "a".repeat(64), "b".repeat(64), 7), "5b337e7db7ac9f39f8c32dc2a9612893fd469a6222e10cd89cff9a2fd56d5fa8");
});
