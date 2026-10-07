import assert from "node:assert/strict";
import test from "node:test";
import { handleDevices } from "./oauth.ts";
import { handleChatGptConnector } from "./owner-auth.ts";
import { handleApprove, handleMcp } from "./mcp.ts";
import worker, { __setTestStore } from "./index.ts";
import { MemoryStore } from "./store.ts";
import { MAX_REQUEST_BODY_BYTES } from "./util.ts";

const ISSUER = "https://cp.test";

async function boundedResponse(request: Request, pending: Promise<Response>): Promise<Response> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const response = await Promise.race([
    pending,
    new Promise<null>((resolve) => { timer = setTimeout(() => resolve(null), 1000); }),
  ]);
  clearTimeout(timer);
  if (response === null) {
    // Release an abandoned tee sibling so the regression fixture leaves no
    // outstanding cancellation promise when run against the old implementation.
    void request.body?.cancel().catch(() => {});
    assert.fail("oversized body rejection stalled on an unread Request clone");
  }
  return response;
}

/** A finite stream proves rejection/cancellation before draining the tail. */
function oversizedRequest(path: string, limit: number, headers: HeadersInit): {
  request: Request;
  cancelled: () => boolean;
} {
  let wasCancelled = false;
  let sent = false;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (!sent) {
        sent = true;
        controller.enqueue(new TextEncoder().encode("x".repeat(limit + 1)));
      } else {
        controller.enqueue(new TextEncoder().encode("tail"));
        controller.close();
      }
    },
    cancel() { wasCancelled = true; },
  }, { highWaterMark: 0 });
  return {
    request: new Request(`${ISSUER}${path}`, {
      method: "POST", headers, body, duplex: "half",
    } as RequestInit),
    cancelled: () => wasCancelled,
  };
}

for (const contentLength of [undefined, "1", String(MAX_REQUEST_BODY_BYTES + 1)]) {
  test(`device bodies enforce actual bytes before parsing (Content-Length ${contentLength ?? "absent"})`, async () => {
    const store = new MemoryStore();
    await store.ensureBootstrap();
    const token = await store.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.device");
    for (const path of ["/v1/devices/enroll", "/v1/devices/enroll/proof", "/v1/devices/revoke?id=dev_target"]) {
      const headers = new Headers({ authorization: `Bearer ${token.access_token}`, "content-type": "application/json" });
      if (contentLength) headers.set("content-length", contentLength);
      const { request, cancelled } = oversizedRequest(path, MAX_REQUEST_BODY_BYTES, headers);
      const result = await handleDevices(request, store, new URL(request.url));
      assert.equal(result.status, 413, path);
      if (contentLength !== String(MAX_REQUEST_BODY_BYTES + 1)) assert.equal(cancelled(), true, path);
      assert.match(result.headers.get("cache-control") || "", /no-store/);
    }
    assert.deepEqual(await store.listDevices("prin_dev"), []);
    assert.deepEqual(await store.listAudit("ten_default", 50), []);
  });

  test(`connector form cancels above 8 KiB (Content-Length ${contentLength ?? "absent"})`, async () => {
    const store = new MemoryStore();
    await store.ensureBootstrap();
    const headers = new Headers({ origin: ISSUER, "content-type": "application/x-www-form-urlencoded" });
    if (contentLength) headers.set("content-length", contentLength);
    const { request, cancelled } = oversizedRequest("/connect/chatgpt", 8 * 1024, headers);
    const result = await handleChatGptConnector(request, store, ISSUER, {
      id: "prin_owner", tenant_id: "ten_default", display_name: "Owner",
    });
    assert.equal(result.status, 413);
    if (contentLength !== String(MAX_REQUEST_BODY_BYTES + 1)) assert.equal(cancelled(), true);
    assert.match(result.headers.get("cache-control") || "", /no-store/);
  });

  for (const contentType of ["application/json", "application/x-www-form-urlencoded", "multipart/form-data; boundary=test-boundary"]) {
    test(`approval ${contentType} enforces bytes (Content-Length ${contentLength ?? "absent"})`, async () => {
      const store = new MemoryStore();
      await store.ensureBootstrap();
      const headers = new Headers({ origin: ISSUER, "content-type": contentType });
      if (contentLength) headers.set("content-length", contentLength);
      const { request, cancelled } = oversizedRequest("/approve", MAX_REQUEST_BODY_BYTES, headers);
      let routed = false;
      const result = await handleApprove(request, store, {
        issuer: ISSUER, principal: { id: "prin_dev", tenant_id: "ten_default" }, originAllowed: true,
        routeToDevice: async () => { routed = true; return { status: "routed_to_device" }; },
      });
      assert.equal(result.status, 413);
      if (contentLength !== String(MAX_REQUEST_BODY_BYTES + 1)) assert.equal(cancelled(), true);
      assert.equal(routed, false);
      assert.deepEqual(await store.listAudit("ten_default", 50), []);
    });
  }
}

test("device enrollment rejects null and malformed JSON without state changes", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const token = await store.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.device");
  for (const path of ["/v1/devices/enroll", "/v1/devices/enroll/proof"]) {
    for (const body of ["null", "[]", "{"]) {
      const request = new Request(`${ISSUER}${path}`, {
        method: "POST", headers: { authorization: `Bearer ${token.access_token}` }, body,
      });
      const result = await handleDevices(request, store, new URL(request.url));
      assert.equal(result.status, 400, `${path}: ${body}`);
    }
  }
  assert.deepEqual(await store.listDevices("prin_dev"), []);
});

test("oversized revoke cannot fall back to the query id; bounded legacy bodies still revoke", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const token = await store.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.device");
  const path = "/v1/devices/revoke?id=dev_target";
  const headers = { authorization: `Bearer ${token.access_token}`, "content-type": "application/json" };
  const putDevice = () => store.putDevice({
    id: "dev_target", tenant_id: "ten_default", principal_id: "prin_dev",
    name: "Target", labels: [], hostname: "desk.local", os: "linux", arch: "x64",
    agent_version: "1", protocol_version: "ownmesh.device/1.0", public_key: "ab".repeat(32),
    revoked: false, created_at: new Date().toISOString(), status: "active",
  });
  await putDevice();
  const { request, cancelled } = oversizedRequest(path, MAX_REQUEST_BODY_BYTES, headers);
  assert.equal((await handleDevices(request, store, new URL(request.url))).status, 413);
  assert.equal(cancelled(), true);
  assert.equal((await store.getDevice("dev_target"))?.revoked, false);
  assert.deepEqual(await store.listAudit("ten_default", 50), []);
  for (const body of ["", "{"]) {
    await putDevice();
    const bounded = new Request(`${ISSUER}${path}`, { method: "POST", headers, body });
    const response = await handleDevices(bounded, store, new URL(bounded.url));
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ok: true });
    assert.equal((await store.getDevice("dev_target"))?.revoked, true);
  }
});

test("MCP streamed overflow completes rejection without an unread body clone", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const { request, cancelled } = oversizedRequest("/mcp", MAX_REQUEST_BODY_BYTES, {
    "content-type": "application/json", "mcp-method": "server/discover",
  });
  const response = await boundedResponse(request, handleMcp(request, store, new URL(request.url)));
  assert.equal(response.status, 400);
  assert.equal(cancelled(), true);
  assert.deepEqual(await store.listAudit("ten_default", 50), []);
});

test("authorize streamed overflow returns 413 before browser authentication", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  __setTestStore(store);
  try {
    const { request, cancelled } = oversizedRequest("/oauth/authorize", MAX_REQUEST_BODY_BYTES, {
      origin: ISSUER, "content-type": "application/x-www-form-urlencoded",
    });
    let authenticated = false;
    const response = await boundedResponse(request, worker.fetch(request, {
      OAUTH_ISSUER: ISSUER,
      AUTH_PROVIDER: {
        fetch: async () => { authenticated = true; return new Response("{}"); },
        connect: () => { throw new Error("unexpected authentication socket"); },
      },
    }, {} as ExecutionContext));
    assert.equal(response.status, 413);
    assert.equal(cancelled(), true);
    assert.equal(authenticated, false);
    assert.deepEqual(await store.listAudit("ten_default", 50), []);
  } finally {
    __setTestStore(null);
  }
});
