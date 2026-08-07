import assert from "node:assert/strict";
import test from "node:test";
import worker, { __setTestStore } from "./index.ts";
import { DeviceRoomHarness } from "./device-room.ts";
import { handleAuthorize, handleDeviceVerification, handleRegister, handleToken } from "./oauth.ts";
import { handleMcp, OperationTracker } from "./mcp.ts";
import { MemoryStore, createStore } from "./store.ts";
import { requireScope, sha256Hex } from "./util.ts";

const ctx = {} as ExecutionContext;

async function tokenStore(principal = "prin_dev", scope = "ownmesh.read ownmesh.device") {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const token = await store.issueTokens("client_test", principal, scope);
  return { store, token };
}

function rpc(name: string, args: Record<string, unknown>, token: string) {
  return new Request("https://cp.test/mcp", {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
  });
}

test("production OAuth defaults reject unknown clients, implicit login_hint, auto consent, and DCR", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const unknown = await handleAuthorize(new Request(
    "https://cp.test/oauth/authorize?response_type=code&client_id=unknown&redirect_uri=https%3A%2F%2Fclient.test%2Fcb&code_challenge=x&code_challenge_method=S256&login_hint=attacker&auto=1",
  ), store, "https://cp.test");
  assert.equal(unknown.status, 401);
  assert.equal(await store.getClient("unknown"), null);

  await store.putClient({ client_id: "known", tenant_id: "ten_default", client_name: "known", redirect_uris: ["https://client.test/cb"], created_at: new Date().toISOString() });
  const noIdentity = await handleAuthorize(new Request(
    "https://cp.test/oauth/authorize?response_type=code&client_id=known&redirect_uri=https%3A%2F%2Fclient.test%2Fcb&code_challenge=x&code_challenge_method=S256&login_hint=attacker&auto=1",
  ), store, "https://cp.test");
  assert.equal(noIdentity.status, 401);
  const noAutoConsent = await handleAuthorize(new Request(
    "https://cp.test/oauth/authorize?response_type=code&client_id=known&redirect_uri=https%3A%2F%2Fclient.test%2Fcb&code_challenge=x&code_challenge_method=S256&auto=1",
  ), store, "https://cp.test", { principal: { id: "prin_dev", tenant_id: "ten_default" } });
  assert.equal(noAutoConsent.status, 200);
  assert.equal(noAutoConsent.headers.get("location"), null);
  const registration = await handleRegister(new Request("https://cp.test/oauth/register", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["https://client.test/cb"] }),
  }), store);
  assert.equal(registration.status, 403);

  __setTestStore(store);
  const authProvider = { fetch: async () => Response.json({ principal_id: "prin_dev", tenant_id: "ten_default" }) } as unknown as Fetcher;
  const workerUnknown = await worker.fetch(new Request(
    "https://cp.test/oauth/authorize?response_type=code&client_id=still_unknown&redirect_uri=https%3A%2F%2Fclient.test%2Fcb&code_challenge=x&code_challenge_method=S256",
  ), { AUTH_PROVIDER: authProvider }, ctx);
  assert.equal(workerUnknown.status, 401);
  assert.equal(await store.getClient("still_unknown"), null);
  __setTestStore(null);
});

test("worker reports missing auth provider and missing production D1 without falling back", async () => {
  __setTestStore(new MemoryStore());
  const auth = await worker.fetch(new Request(
    "https://cp.test/oauth/authorize?response_type=code&client_id=x&redirect_uri=https%3A%2F%2Fx.test%2Fcb&code_challenge=x&code_challenge_method=S256",
  ), {}, ctx);
  assert.equal(auth.status, 503);
  assert.equal((await auth.json() as { error: string }).error, "auth_provider_unavailable");
  __setTestStore(null);
  assert.throws(() => createStore({}), /D1 binding/);
  const unavailable = await worker.fetch(new Request("https://cp.test/v1/audit"), {}, ctx);
  assert.equal(unavailable.status, 503);
});

test("device verification requires authenticated one-time CSRF transaction and binds snapshots", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  await store.putClient({ client_id: "cli", tenant_id: "ten_default", client_name: "cli", redirect_uris: [], created_at: new Date().toISOString() });
  await store.putDeviceCode({ device_code: "dcode_secret", user_code: "BCDF-GHJK", client_id: "cli", scope: "ownmesh.read", verification_uri: "https://cp.test/oauth/device", interval_sec: 5, expires_at: Date.now() + 60_000, status: "pending" });
  const unauth = await handleDeviceVerification(new Request("https://cp.test/oauth/device?user_code=BCDF-GHJK"), store);
  assert.equal(unauth.status, 401);
  const principal = { id: "prin_dev", tenant_id: "ten_default" };
  const page = await handleDeviceVerification(new Request("https://cp.test/oauth/device?user_code=BCDF-GHJK"), store, { principal });
  const html = await page.text();
  const tx = /name="transaction_id" value="([^"]+)"/.exec(html)?.[1];
  const csrf = /name="csrf_token" value="([^"]+)"/.exec(html)?.[1];
  assert.ok(tx && csrf);
  const post = (csrfToken: string) => handleDeviceVerification(new Request("https://cp.test/oauth/device", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ transaction_id: tx!, csrf_token: csrfToken, decision: "approve" }),
  }), store, { principal });
  assert.equal((await post("wrong")).status, 400);
  assert.equal((await post(csrf!)).status, 200);
  assert.equal((await post(csrf!)).status, 400);

  const exchange = () => handleToken(new Request("https://cp.test/oauth/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: "dcode_secret", client_id: "cli" }),
  }), store);
  const results = await Promise.all([exchange(), exchange()]);
  assert.deepEqual(results.map((r) => r.status).sort(), [200, 400]);

  await store.putDeviceCode({ device_code: "dcode_changed", user_code: "LMNP-QRST", client_id: "cli", scope: "ownmesh.read", verification_uri: "https://cp.test/oauth/device", interval_sec: 5, expires_at: Date.now() + 60_000, status: "pending" });
  const changedPage = await handleDeviceVerification(new Request("https://cp.test/oauth/device?user_code=LMNP-QRST"), store, { principal });
  const changedHtml = await changedPage.text();
  const changedTx = /name="transaction_id" value="([^"]+)"/.exec(changedHtml)![1]!;
  const changedCsrf = /name="csrf_token" value="([^"]+)"/.exec(changedHtml)![1]!;
  store.deviceCodes.get("dcode_changed")!.scope = "ownmesh.exec";
  const changed = await handleDeviceVerification(new Request("https://cp.test/oauth/device", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ transaction_id: changedTx, csrf_token: changedCsrf, decision: "approve" }),
  }), store, { principal });
  assert.equal(changed.status, 400);
});

test("DeviceRoom rejects out-of-order proof/ready and only routes to ready agents", async () => {
  const room = new DeviceRoomHarness("dev_state", () => true);
  const agent = room.connect("agent");
  const earlyReady = await room.send(agent, { protocol: "ownmesh.device/1.0", message_id: "m1", type: "ready", device_id: "dev_state", seq: 1, sent_at: new Date().toISOString(), payload: {} });
  assert.equal(earlyReady.error, "invalid_state");
  const route = room.router.injectOperation({ type: "read", payload: {}, correlation_id: "c1" });
  assert.equal(route.status, "device_offline");
});

test("agent connect enforces Origin, active registration, role, and device credential", async () => {
  const { store } = await tokenStore();
  const device = { id: "dev_connect", tenant_id: "ten_default", principal_id: "prin_dev", name: "agent", hostname: "agent", os: "x", arch: "x", agent_version: "x", protocol_version: "ownmesh.device/1.0", public_key: "ab".repeat(32), revoked: false, created_at: new Date().toISOString(), status: "active" as const };
  await store.putDevice(device);
  const credential = await store.issueDeviceCredential(device);
  assert.equal(await store.validateDeviceSession(await sha256Hex(credential.token), "agent", device.id), true);
  __setTestStore(store);
  const room = { idFromName: () => ({}) as DurableObjectId, get: () => ({ fetch: async () => new Response(null, { status: 204 }) }) as unknown as DurableObjectStub } as unknown as DurableObjectNamespace;
  const base = "https://cp.test/agent/connect?device_id=dev_connect&role=agent";
  const noOrigin = await worker.fetch(new Request(base, { headers: { upgrade: "websocket", authorization: `Bearer ${credential.token}` } }), { DEVICE_ROOM: room, SESSION_SECRET: "test-session-secret-p0", OAUTH_ISSUER: "https://cp.test" }, ctx);
  assert.equal(noOrigin.status, 403);
  const badCredential = await worker.fetch(new Request(base, { headers: { upgrade: "websocket", origin: "https://cp.test", authorization: "Bearer bad" } }), { DEVICE_ROOM: room, SESSION_SECRET: "test-session-secret-p0", OAUTH_ISSUER: "https://cp.test" }, ctx);
  assert.equal(badCredential.status, 401);
  const badRole = await worker.fetch(new Request(base.replace("role=agent", "role=admin"), { headers: { upgrade: "websocket", origin: "https://cp.test", authorization: `Bearer ${credential.token}` } }), { DEVICE_ROOM: room, SESSION_SECRET: "test-session-secret-p0", OAUTH_ISSUER: "https://cp.test" }, ctx);
  assert.equal(badRole.status, 403);
  await store.revokeDevice(device.id, device.principal_id);
  assert.equal(await store.validateDeviceSession(await sha256Hex(credential.token), "agent", device.id), false);
  const revokedReconnect = await worker.fetch(new Request(base, { headers: { upgrade: "websocket", origin: "https://cp.test", authorization: `Bearer ${credential.token}` } }), { DEVICE_ROOM: room, SESSION_SECRET: "test-session-secret-p0", OAUTH_ISSUER: "https://cp.test" }, ctx);
  assert.equal(revokedReconnect.status, 403);
  __setTestStore(null);
});

test("production device proof endpoint rejects fake Ed25519 and leaves device pending", async () => {
  const { store, token } = await tokenStore();
  const device = { id: "dev_bad_proof", tenant_id: "ten_default", principal_id: "prin_dev", name: "d", hostname: "d", os: "x", arch: "x", agent_version: "x", protocol_version: "ownmesh.device/1.0", public_key: "ab".repeat(32), revoked: false, created_at: new Date().toISOString(), status: "pending" as const };
  await store.putDevice(device);
  await store.putEnrollmentChallenge({ id: "ch_bad", device_id: device.id, nonce: "n", message: `ownmesh-device-challenge:n:${device.id}`, expires_at: new Date(Date.now() + 60_000).toISOString(), consumed: false });
  __setTestStore(store);
  const response = await worker.fetch(new Request("https://cp.test/v1/devices/enroll/proof", {
    method: "POST", headers: { authorization: `Bearer ${token.access_token}`, "content-type": "application/json" },
    body: JSON.stringify({ device_id: device.id, challenge_id: "ch_bad", signature: "00".repeat(64) }),
  }), {}, ctx);
  assert.equal(response.status, 400);
  assert.equal((await store.getDevice(device.id))?.status, "pending");
  __setTestStore(null);
});

test("MCP rejects foreign, pending, and revoked devices before routing", async () => {
  const { store, token } = await tokenStore();
  for (const [id, principal, status, revoked] of [
    ["dev_foreign", "other", "active", false],
    ["dev_pending", "prin_dev", "pending", false],
    ["dev_revoked", "prin_dev", "revoked", true],
  ] as const) {
    await store.putDevice({ id, tenant_id: "ten_default", principal_id: principal, name: id, hostname: id, os: "x", arch: "x", agent_version: "x", protocol_version: "ownmesh.device/1.0", public_key: "ab".repeat(32), revoked, created_at: new Date().toISOString(), status });
    const response = await handleMcp(rpc("ownmesh_fs_read", { device_id: id, path: "/x" }, token.access_token), store, new URL("https://cp.test/mcp"), { routeToDevice: async () => { throw new Error("must not route"); } });
    assert.equal((await response.json() as { error: { message: string } }).error.message, "device_not_available");
  }
  __setTestStore(store);
  const workerResponse = await worker.fetch(rpc("ownmesh_fs_read", { device_id: "dev_pending", path: "/x" }, token.access_token), {}, ctx);
  assert.equal((await workerResponse.json() as { error: { message: string } }).error.message, "device_not_available");
  __setTestStore(null);
});

test("operation lookup/cancel is principal-bound", async () => {
  const store = new MemoryStore();
  const owner = await store.issueTokens("c", "owner", "ownmesh.read");
  const attacker = await store.issueTokens("c", "attacker", "ownmesh.read ownmesh.exec");
  const tracker = new OperationTracker();
  tracker.put({ operation_id: "op_secret", status: "pending", summary: "secret", data: {}, truncated: false, next_cursor: null, approval_required: false, warnings: [], policy_authority: "ownmesh_device", tool: "x", principal: "owner", tenant_id: "ten_default", created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  for (const name of ["ownmesh_get_operation", "ownmesh_cancel_operation"]) {
    const response = await handleMcp(rpc(name, { operation_id: "op_secret" }, attacker.access_token), store, new URL("https://cp.test/mcp"), undefined, { tracker });
    const text = JSON.stringify(await response.json());
    assert.match(text, /unknown operation|not found/i);
  }
  assert.equal(tracker.get("op_secret")?.status, "pending");
  assert.ok(owner.access_token);
});

test("audit and approval routes authenticate and approval handler is live", async () => {
  const { store, token } = await tokenStore();
  __setTestStore(store);
  assert.equal((await worker.fetch(new Request("https://cp.test/v1/audit"), {}, ctx)).status, 401);
  const audit = await worker.fetch(new Request("https://cp.test/v1/audit", { headers: { authorization: `Bearer ${token.access_token}` } }), {}, ctx);
  assert.equal(audit.status, 200);
  assert.equal((await worker.fetch(new Request("https://cp.test/approve"), {}, ctx)).status, 401);
  const approval = await worker.fetch(new Request("https://cp.test/approve", { headers: { authorization: `Bearer ${token.access_token}` } }), {}, ctx);
  assert.equal(approval.status, 400);
  assert.deepEqual(await approval.json(), {
    error: "invalid_request",
    error_description: "operation_id required",
  });
  __setTestStore(null);
});

test("write scope does not escalate to exec/session and wildcard CORS is absent", async () => {
  assert.equal(requireScope("ownmesh.write", "ownmesh.exec"), false);
  assert.equal(requireScope("ownmesh.write", "ownmesh.session"), false);
  __setTestStore(new MemoryStore());
  const options = await worker.fetch(new Request("https://cp.test/mcp", { method: "OPTIONS", headers: { origin: "https://evil.test" } }), {}, ctx);
  assert.equal(options.status, 405);
  assert.notEqual(options.headers.get("access-control-allow-origin"), "*");
  __setTestStore(null);
});
