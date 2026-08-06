/**
 * (H) Dynamic Client Registration security contract:
 * - no unauthenticated / default-tenant registration
 * - Bearer access token with ownmesh.device required
 * - client bound to token tenant
 * - redirect_uris: https or loopback http only
 */
import assert from "node:assert/strict";
import test from "node:test";
import { handleRegister, isAllowedDcrRedirectUri } from "./oauth.ts";
import { DEFAULT_TENANT, MemoryStore } from "./store.ts";

async function deviceToken(
  store: MemoryStore,
  opts: { principal?: string; tenant?: string; scope?: string } = {},
) {
  const principal = opts.principal || "prin_dcr";
  const tenant = opts.tenant || DEFAULT_TENANT;
  const scope = opts.scope || "ownmesh.device";
  await store.ensureBootstrap();
  await store.ensurePrincipal(principal, principal, "user", tenant);
  return store.issueTokens("client_ownmesh_cli", principal, scope);
}

function registerReq(body: unknown, token?: string): Request {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (token) headers.authorization = "Bearer " + token;
  return new Request("https://cp.test/oauth/register", {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

test("DCR unauthenticated denied even when flag enabled", async () => {
  const store = new MemoryStore();
  const res = await handleRegister(
    registerReq({
      client_name: "noauth",
      redirect_uris: ["https://client.test/cb"],
    }),
    store,
    { allowDynamicRegistration: true },
  );
  assert.ok(res.status >= 400 && res.status < 500, "expected 4xx, got " + res.status);
  assert.equal(res.status, 401);
  const body = (await res.json()) as { error?: string };
  assert.equal(body.error, "unauthorized");
});

test("DCR invalid bearer denied", async () => {
  const store = new MemoryStore();
  const res = await handleRegister(
    registerReq(
      { client_name: "badtok", redirect_uris: ["https://client.test/cb"] },
      "atk_not_real",
    ),
    store,
    { allowDynamicRegistration: true },
  );
  assert.equal(res.status, 401);
  const body = (await res.json()) as { error?: string };
  assert.equal(body.error, "invalid_token");
});

test("DCR wrong scope denied", async () => {
  const store = new MemoryStore();
  const tok = await deviceToken(store, { scope: "ownmesh.read" });
  const res = await handleRegister(
    registerReq(
      { client_name: "wrongscope", redirect_uris: ["https://client.test/cb"] },
      tok.access_token,
    ),
    store,
    { allowDynamicRegistration: true },
  );
  assert.equal(res.status, 403);
  const body = (await res.json()) as { error?: string };
  assert.equal(body.error, "insufficient_scope");
});

test("DCR disabled flag stays 403 registration_disabled", async () => {
  const store = new MemoryStore();
  const tok = await deviceToken(store);
  const res = await handleRegister(
    registerReq(
      { client_name: "off", redirect_uris: ["https://client.test/cb"] },
      tok.access_token,
    ),
    store,
    { allowDynamicRegistration: false },
  );
  assert.equal(res.status, 403);
  const body = (await res.json()) as { error?: string };
  assert.equal(body.error, "registration_disabled");
});

test("DCR binds client to token tenant (never implicit DEFAULT_TENANT)", async () => {
  const store = new MemoryStore();
  const tenant = "ten_acme_dcr";
  assert.notEqual(tenant, DEFAULT_TENANT);
  const tok = await deviceToken(store, {
    principal: "prin_acme",
    tenant,
    scope: "ownmesh.device ownmesh.read",
  });
  assert.equal(tok.tenant_id, tenant);

  const res = await handleRegister(
    registerReq(
      {
        client_name: "Acme App",
        redirect_uris: ["https://acme.example/oauth/callback"],
      },
      tok.access_token,
    ),
    store,
    { allowDynamicRegistration: true },
  );
  assert.equal(res.status, 201);
  const body = (await res.json()) as { client_id: string };
  assert.ok(body.client_id);
  const client = await store.getClient(body.client_id);
  assert.ok(client);
  assert.equal(client!.tenant_id, tenant);
  assert.notEqual(client!.tenant_id, DEFAULT_TENANT);
  assert.equal(client!.client_name, "Acme App");
});

test("DCR redirect scheme policy: https and loopback http allowed", async () => {
  assert.equal(isAllowedDcrRedirectUri("https://chatgpt.com/connector/oauth/callback"), true);
  assert.equal(isAllowedDcrRedirectUri("http://127.0.0.1:8750/callback"), true);
  assert.equal(isAllowedDcrRedirectUri("http://localhost:3000/cb"), true);
  assert.equal(isAllowedDcrRedirectUri("http://[::1]:8080/cb"), true);
  // bare http://::1/... is not a valid URL; bracket form is required for IPv6

  assert.equal(isAllowedDcrRedirectUri("http://evil.example/cb"), false);
  assert.equal(isAllowedDcrRedirectUri("http://192.168.1.1/cb"), false);
  assert.equal(isAllowedDcrRedirectUri("custom://callback"), false);
  assert.equal(isAllowedDcrRedirectUri("ftp://127.0.0.1/x"), false);
  assert.equal(isAllowedDcrRedirectUri("not-a-url"), false);

  const store = new MemoryStore();
  const tok = await deviceToken(store);

  const badRemoteHttp = await handleRegister(
    registerReq(
      { redirect_uris: ["http://evil.example/cb"] },
      tok.access_token,
    ),
    store,
    { allowDynamicRegistration: true },
  );
  assert.equal(badRemoteHttp.status, 400);
  assert.equal(((await badRemoteHttp.json()) as { error: string }).error, "invalid_redirect_uri");

  const badScheme = await handleRegister(
    registerReq(
      { redirect_uris: ["myapp://oauth/callback"] },
      tok.access_token,
    ),
    store,
    { allowDynamicRegistration: true },
  );
  assert.equal(badScheme.status, 400);
  assert.equal(((await badScheme.json()) as { error: string }).error, "invalid_redirect_uri");

  const okHttps = await handleRegister(
    registerReq(
      { client_name: "https-ok", redirect_uris: ["https://app.example/cb"] },
      tok.access_token,
    ),
    store,
    { allowDynamicRegistration: true },
  );
  assert.equal(okHttps.status, 201);

  const okLoopback = await handleRegister(
    registerReq(
      {
        client_name: "loop-ok",
        redirect_uris: [
          "http://127.0.0.1:9/cb",
          "http://localhost/cb",
          "http://[::1]/cb",
        ],
      },
      tok.access_token,
    ),
    store,
    { allowDynamicRegistration: true },
  );
  assert.equal(okLoopback.status, 201);
});

test("DCR never creates client without authenticated principal", async () => {
  const store = new MemoryStore();
  // Unauthenticated registration must not mint a client_id even with the flag on.
  const res = await handleRegister(
    registerReq({
      client_name: "should-not-exist",
      redirect_uris: ["https://x.test/cb"],
    }),
    store,
    { allowDynamicRegistration: true },
  );
  assert.equal(res.status, 401);
  const body = (await res.json()) as { client_id?: string; error?: string };
  assert.equal(body.client_id, undefined);
  assert.equal(body.error, "unauthorized");
  // Successful path still works for comparison (auth + tenant bind).
  const tok = await deviceToken(store, { tenant: "ten_guard" });
  const ok = await handleRegister(
    registerReq(
      { client_name: "guarded", redirect_uris: ["https://ok.test/cb"] },
      tok.access_token,
    ),
    store,
    { allowDynamicRegistration: true },
  );
  assert.equal(ok.status, 201);
  const created = (await ok.json()) as { client_id: string };
  const client = await store.getClient(created.client_id);
  assert.equal(client!.tenant_id, "ten_guard");
});
