/**
 * (F+G) Cache-Control: no-store on sensitive OAuth/device/enrollment responses;
 * revoke audits only matched real tokens under their actual tenant.
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  handleAuthorize,
  handleDeviceAuthorization,
  handleDeviceVerification,
  handleDevices,
  handleRegister,
  handleRevoke,
  handleToken,
} from "./oauth.ts";
import { DEFAULT_TENANT, MemoryStore } from "./store.ts";
import { NO_STORE_CACHE_CONTROL, applyNoStore, html, json, sha256Hex } from "./util.ts";

function assertNoStore(res: Response, label: string): void {
  const cc = (res.headers.get("cache-control") || "").toLowerCase();
  assert.ok(
    cc.includes("no-store") && cc.includes("no-cache"),
    `${label}: expected no-store+no-cache, got ${JSON.stringify(cc)}`,
  );
  assert.equal(
    cc,
    NO_STORE_CACHE_CONTROL,
    `${label}: cache-control should be exactly "${NO_STORE_CACHE_CONTROL}"`,
  );
}

async function seedClient(store: MemoryStore, clientId = "client_hdr", tenantId = DEFAULT_TENANT) {
  await store.ensureBootstrap();
  await store.putClient({
    client_id: clientId,
    tenant_id: tenantId,
    client_name: "hdr-test",
    redirect_uris: ["http://127.0.0.1:8750/callback"],
    created_at: new Date().toISOString(),
  });
  return clientId;
}

test("util json/html applyNoStore sets no-store, no-cache", () => {
  const h = applyNoStore();
  assert.equal(h.get("cache-control"), NO_STORE_CACHE_CONTROL);
  assert.equal(h.get("pragma"), "no-cache");

  const res = json({ ok: true }, { noStore: true });
  assertNoStore(res, "json(noStore)");

  const page = html("<!doctype html><title>test</title>", { noStore: true });
  assertNoStore(page, "html(noStore)");
  assert.equal(page.headers.get("referrer-policy"), "same-origin");
  assert.match(page.headers.get("content-security-policy") || "", /img-src data:/);
});

test("sensitive OAuth endpoints set Cache-Control: no-store, no-cache", async () => {
  const store = new MemoryStore();
  const clientId = await seedClient(store);

  // /oauth/register (DCR requires a tenant-bound ownmesh.device bearer token)
  const registrationAdmin = await store.issueTokens(
    clientId,
    "prin_dev",
    "ownmesh.device",
  );
  const reg = await handleRegister(
    new Request("https://cp.test/oauth/register", {
      method: "POST",
      headers: {
        authorization: `Bearer ${registrationAdmin.access_token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        client_name: "c",
        redirect_uris: ["http://127.0.0.1:9/cb"],
      }),
    }),
    store,
    { allowDynamicRegistration: true },
  );
  assert.equal(reg.status, 201);
  assertNoStore(reg, "/oauth/register");

  // /oauth/token (error path is enough for header contract)
  const tok = await handleToken(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: "missing" }),
    }),
    store,
  );
  assert.equal(tok.status, 400);
  assertNoStore(tok, "/oauth/token");

  // /oauth/revoke
  const rev = await handleRevoke(
    new Request("https://cp.test/oauth/revoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: "unknown" }),
    }),
    store,
  );
  assert.equal(rev.status, 200);
  assertNoStore(rev, "/oauth/revoke");

  // /oauth/device_authorization
  const da = await handleDeviceAuthorization(
    new Request("https://cp.test/oauth/device_authorization", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: clientId, scope: "ownmesh.read" }),
    }),
    store,
    "https://cp.test",
  );
  assert.equal(da.status, 200);
  assertNoStore(da, "/oauth/device_authorization");

  // consent HTML (authorize GET)
  const authz = await handleAuthorize(
    new Request(
      "https://cp.test/oauth/authorize?response_type=code&client_id=" +
        encodeURIComponent(clientId) +
        "&redirect_uri=" +
        encodeURIComponent("http://127.0.0.1:8750/callback") +
        "&code_challenge=challenge_abc&code_challenge_method=S256&scope=ownmesh.read",
    ),
    store,
    "https://cp.test",
    { principal: { id: "prin_dev", tenant_id: DEFAULT_TENANT, display_name: "Dev" } },
  );
  assert.equal(authz.status, 200);
  assert.match(authz.headers.get("content-type") || "", /text\/html/);
  assert.equal(authz.headers.get("referrer-policy"), "same-origin");
  assert.match(await authz.clone().text(), /data:image\/svg\+xml;base64,/);
  assertNoStore(authz, "authorize consent HTML");

  // device verification HTML (entry form)
  const devForm = await handleDeviceVerification(
    new Request("https://cp.test/oauth/device"),
    store,
    { principal: { id: "prin_dev", tenant_id: DEFAULT_TENANT } },
  );
  assert.equal(devForm.status, 200);
  assertNoStore(devForm, "device verification entry HTML");

  // device verification consent HTML (with user_code)
  const daBody = (await da.clone().json()) as { user_code: string };
  const devConsent = await handleDeviceVerification(
    new Request(
      `https://cp.test/oauth/device?user_code=${encodeURIComponent(daBody.user_code)}`,
    ),
    store,
    { principal: { id: "prin_dev", tenant_id: DEFAULT_TENANT } },
  );
  assert.equal(devConsent.status, 200);
  assertNoStore(devConsent, "device verification consent HTML");
});

test("enrollment and proof responses set no-store", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const issued = await store.issueTokens(
    "client_ownmesh_cli",
    "prin_dev",
    "ownmesh.device ownmesh.read",
  );
  const keyPair = (await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const publicBytes = new Uint8Array(
    (await crypto.subtle.exportKey("raw", keyPair.publicKey)) as ArrayBuffer,
  );
  const publicKey = [...publicBytes].map((b) => b.toString(16).padStart(2, "0")).join("");

  const enrollRes = await handleDevices(
    new Request("https://cp.test/v1/devices/enroll", {
      method: "POST",
      headers: {
        authorization: `Bearer ${issued.access_token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        name: "desk",
        hostname: "desk.local",
        os: "windows",
        arch: "x64",
        agent_version: "1.0.1",
        protocol_version: "ownmesh.device/1.0",
        public_key: publicKey,
      }),
    }),
    store,
    new URL("https://cp.test/v1/devices/enroll"),
  );
  assert.equal(enrollRes.status, 201);
  assertNoStore(enrollRes, "/v1/devices/enroll");

  const body = (await enrollRes.json()) as {
    device_id: string;
    challenge: { id: string; message: string };
  };
  const signatureBytes = new Uint8Array(
    await crypto.subtle.sign(
      "Ed25519",
      keyPair.privateKey,
      new TextEncoder().encode(body.challenge.message),
    ),
  );
  const signature = [...signatureBytes].map((b) => b.toString(16).padStart(2, "0")).join("");

  const proofRes = await handleDevices(
    new Request("https://cp.test/v1/devices/enroll/proof", {
      method: "POST",
      headers: {
        authorization: `Bearer ${issued.access_token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        device_id: body.device_id,
        challenge_id: body.challenge.id,
        signature,
      }),
    }),
    store,
    new URL("https://cp.test/v1/devices/enroll/proof"),
  );
  assert.equal(proofRes.status, 200);
  assertNoStore(proofRes, "/v1/devices/enroll/proof");
});

test("store.lookupRevocableToken returns meta for access and refresh; null for unknown", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  await store.ensurePrincipal("prin_tenant_a", "A", "human", "ten_alpha");
  const tok = await store.issueTokens("client_a", "prin_tenant_a", "ownmesh.read offline_access");

  const byAccess = await store.lookupRevocableToken(tok.access_token);
  assert.deepEqual(byAccess, {
    tenant_id: "ten_alpha",
    principal_id: "prin_tenant_a",
    client_id: "client_a",
  });

  const byRefresh = await store.lookupRevocableToken(tok.refresh_token);
  assert.deepEqual(byRefresh, {
    tenant_id: "ten_alpha",
    principal_id: "prin_tenant_a",
    client_id: "client_a",
  });

  assert.equal(await store.lookupRevocableToken("atk_does_not_exist"), null);
  assert.equal(await store.lookupRevocableToken(""), null);
});

test("handleRevoke audits matched token under real tenant; unknown token is 200 with no audit", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  await store.ensurePrincipal("prin_tenant_b", "B", "human", "ten_bravo");
  const tok = await store.issueTokens("client_b", "prin_tenant_b", "ownmesh.read offline_access");

  // Matched access token
  const res1 = await handleRevoke(
    new Request("https://cp.test/oauth/revoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: tok.access_token }),
    }),
    store,
  );
  assert.equal(res1.status, 200);
  assertNoStore(res1, "revoke matched");
  assert.equal(await store.getAccess(tok.access_token), null);

  const auditsBravo = await store.listAudit("ten_bravo", 20);
  const revokeAudits = auditsBravo.filter((a) => a.kind === "oauth.revoke");
  assert.equal(revokeAudits.length, 1);
  assert.equal(revokeAudits[0]!.tenant_id, "ten_bravo");
  assert.equal(revokeAudits[0]!.principal_id, "prin_tenant_b");
  assert.equal(revokeAudits[0]!.meta?.client_id, "client_b");
  assert.equal(revokeAudits[0]!.meta?.token_prefix, tok.access_token.slice(0, 8));
  // Must not leak full token into audit meta
  assert.notEqual(revokeAudits[0]!.meta?.token_prefix, tok.access_token);
  const summary = revokeAudits[0]!.summary || "";
  assert.equal(summary.includes(tok.access_token), false);

  // Default tenant must not receive a spurious revoke audit for this token
  const defaultAudits = (await store.listAudit(DEFAULT_TENANT, 50)).filter(
    (a) => a.kind === "oauth.revoke",
  );
  assert.equal(defaultAudits.length, 0);

  // Unknown token: RFC 7009 200, no new audit row anywhere
  const before = store.audits.length;
  const res2 = await handleRevoke(
    new Request("https://cp.test/oauth/revoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: "atk_totally_unknown_value" }),
    }),
    store,
  );
  assert.equal(res2.status, 200);
  assertNoStore(res2, "revoke unknown");
  assert.equal(store.audits.length, before);
  assert.equal(
    store.audits.filter((a) => a.kind === "oauth.revoke").length,
    1,
    "only the matched revoke should be audited",
  );

  // Empty token: 200, no audit
  const beforeEmpty = store.audits.length;
  const res3 = await handleRevoke(
    new Request("https://cp.test/oauth/revoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    }),
    store,
  );
  assert.equal(res3.status, 200);
  assert.equal(store.audits.length, beforeEmpty);
});

test("handleRevoke audits refresh token match with tenant attribution", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  await store.ensurePrincipal("prin_tenant_c", "C", "human", "ten_charlie");
  const tok = await store.issueTokens(
    "client_c",
    "prin_tenant_c",
    "ownmesh.read offline_access",
  );

  const res = await handleRevoke(
    new Request("https://cp.test/oauth/revoke", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: tok.refresh_token }),
    }),
    store,
  );
  assert.equal(res.status, 200);

  const audits = (await store.listAudit("ten_charlie", 10)).filter(
    (a) => a.kind === "oauth.revoke",
  );
  assert.equal(audits.length, 1);
  assert.equal(audits[0]!.principal_id, "prin_tenant_c");
  assert.equal(audits[0]!.meta?.token_prefix, tok.refresh_token.slice(0, 8));
  // access should also be invalidated via refresh revoke
  assert.equal(await store.getAccess(tok.access_token), null);
});

test("lookupRevocableToken still resolves after revoke (meta retained for store API)", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const tok = await store.issueTokens("client_z", "prin_dev", "ownmesh.read");
  const before = await store.lookupRevocableToken(tok.access_token);
  assert.ok(before);
  await store.revokeToken(tok.access_token);
  const after = await store.lookupRevocableToken(tok.access_token);
  assert.deepEqual(after, before);
  // sha256 used only as smoke that util still works in this suite
  assert.equal((await sha256Hex("x")).length, 64);
});
