import assert from "node:assert/strict";
import test from "node:test";
import { __test, MCP_TOOLS } from "./index.ts";
import {
  handleAuthorize,
  handleRegister,
  handleToken,
  oauthMetadata,
} from "./oauth.ts";
import { MemoryStore } from "./store.ts";
import { verifyPkceS256 } from "./util.ts";

test("refresh token reuse is detected and family revoked", async () => {
  __test.reset();
  const first = await __test.issueTokens("client", "user1", "ownmesh.read offline_access");
  const body1 = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: first.refresh_token,
  });
  const res1 = await __test.handleOAuthToken(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body1,
    }),
  );
  assert.equal(res1.status, 200);
  const rotated = (await res1.json()) as { refresh_token: string; access_token: string };

  const resReuse = await __test.handleOAuthToken(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: first.refresh_token,
      }),
    }),
  );
  assert.equal(resReuse.status, 400);
  const err = (await resReuse.json()) as { error_description?: string };
  assert.match(err.error_description || "", /reuse/i);

  assert.equal(await __test.getAccess(first.access_token), null);
  assert.equal(await __test.getAccess(rotated.access_token), null);
});

test("revoke invalidates access token immediately", async () => {
  __test.reset();
  const tok = await __test.issueTokens("c", "u", "ownmesh.read");
  assert.ok(await __test.getAccess(tok.access_token));
  await __test.handleOAuthRevoke(
    new Request("https://cp.test/oauth/revoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: tok.access_token }),
    }),
  );
  assert.equal(await __test.getAccess(tok.access_token), null);
});

test("MCP catalog separates raw shell from structured command", () => {
  const names = MCP_TOOLS.map((t) => t.name);
  assert.ok(names.includes("ownmesh_command_run"));
  assert.ok(names.includes("ownmesh_command_shell"));
  assert.notEqual(
    MCP_TOOLS.find((t) => t.name === "ownmesh_command_run"),
    MCP_TOOLS.find((t) => t.name === "ownmesh_command_shell"),
  );
});

test("write scope required for exec tools helper", async () => {
  __test.reset();
  const readOnly = await __test.issueTokens("c", "u", "ownmesh.read");
  assert.equal(__test.requireScope(readOnly.scope, "ownmesh.exec"), false);
  const full = await __test.issueTokens("c", "u", "ownmesh.write ownmesh.exec");
  assert.equal(__test.requireScope(full.scope, "ownmesh.exec"), true);
});

test("redirect_uri exact match enforced on authorize", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  await store.putClient({
    client_id: "client_exact",
    tenant_id: "ten_default",
    client_name: "t",
    redirect_uris: ["http://127.0.0.1:8750/callback"],
    created_at: new Date().toISOString(),
  });

  const bad = await handleAuthorize(
    new Request(
      "https://cp.test/oauth/authorize?response_type=code&client_id=client_exact&redirect_uri=http://evil.example/cb&code_challenge=abc&code_challenge_method=S256&scope=ownmesh.read",
    ),
    store,
    "https://cp.test",
  );
  assert.equal(bad.status, 400);
  const body = (await bad.json()) as { error_description?: string };
  assert.match(body.error_description || "", /exact/i);

  const good = await handleAuthorize(
    new Request(
      "https://cp.test/oauth/authorize?response_type=code&client_id=client_exact&redirect_uri=http://127.0.0.1:8750/callback&code_challenge=abc&code_challenge_method=S256&scope=ownmesh.read&auto=1",
    ),
    store,
    "https://cp.test",
    { allowDevBypass: true },
  );
  assert.equal(good.status, 302);
  const loc = good.headers.get("location") || "";
  assert.ok(loc.startsWith("http://127.0.0.1:8750/callback"));
  assert.ok(new URL(loc).searchParams.get("code"));
});

test("authorization_code + PKCE S256 exchange", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const verifier = "0123456789012345678901234567890123456789013"; // 43+ chars
  // compute challenge
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(digest);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const challenge = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  assert.equal(await verifyPkceS256(verifier, challenge), true);

  await store.putClient({
    client_id: "client_pkce",
    tenant_id: "ten_default",
    client_name: "cli",
    redirect_uris: ["http://127.0.0.1:8750/callback"],
    created_at: new Date().toISOString(),
  });
  const authRes = await handleAuthorize(
    new Request(
      `https://cp.test/oauth/authorize?response_type=code&client_id=client_pkce&redirect_uri=${encodeURIComponent("http://127.0.0.1:8750/callback")}&code_challenge=${challenge}&code_challenge_method=S256&scope=ownmesh.read offline_access&auto=1`,
    ),
    store,
    "https://cp.test",
    { allowDevBypass: true },
  );
  const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;
  const tokRes = await handleToken(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: "http://127.0.0.1:8750/callback",
        client_id: "client_pkce",
        code_verifier: verifier,
      }),
    }),
    store,
  );
  assert.equal(tokRes.status, 200);
  const tok = (await tokRes.json()) as { access_token: string; refresh_token: string };
  assert.ok(tok.access_token.startsWith("atk_"));
  assert.ok(tok.refresh_token.startsWith("rtk_"));
});

test("ChatGPT authorization receives a rotating refresh token without offline_access", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const verifier = "chatgpt-pkce-verifier-012345678901234567890123456789";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  let binary = "";
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  const challenge = btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const clientId = "client_chatgpt_b6nceskp3dnc";
  const redirectUri = "https://chatgpt.com/connector/oauth/b6NcEskp3DnC";
  await store.putClient({
    client_id: clientId,
    tenant_id: "ten_default",
    client_name: "ChatGPT",
    redirect_uris: [redirectUri],
    created_at: new Date().toISOString(),
  });
  await store.putAuthCode({
    code: "code_chatgpt_refresh",
    client_id: clientId,
    principal_id: "prin_dev",
    redirect_uri: redirectUri,
    scope: "ownmesh.read",
    code_challenge: challenge,
    code_challenge_method: "S256",
    expires_at: Date.now() + 60_000,
    used: false,
  });

  const response = await handleToken(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: "code_chatgpt_refresh",
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: verifier,
      }),
    }),
    store,
  );
  assert.equal(response.status, 200);
  const token = (await response.json()) as { access_token: string; refresh_token?: string };
  assert.ok(token.access_token.startsWith("atk_"));
  assert.ok(token.refresh_token?.startsWith("rtk_"));
});

test("device authorization grant end-to-end", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const { handleDeviceAuthorization } = await import("./oauth.ts");
  await store.putClient({
    client_id: "client_ownmesh_cli", tenant_id: "ten_default", client_name: "cli",
    redirect_uris: [], created_at: new Date().toISOString(),
  });
  const issued = await handleDeviceAuthorization(
    new Request("https://cp.test/oauth/device_authorization", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ client_id: "client_ownmesh_cli", scope: "ownmesh.read" }),
    }),
    store,
    "https://cp.test",
  );
  assert.equal(issued.status, 200);
  const dc = (await issued.json()) as {
    device_code: string;
    user_code: string;
    interval: number;
  };
  assert.ok(dc.device_code);
  assert.match(dc.user_code, /^[A-Z]{4}-[A-Z]{4}$/);

  // pending
  const pending = await handleToken(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: dc.device_code,
        client_id: "client_ownmesh_cli",
      }),
    }),
    store,
  );
  assert.equal(pending.status, 400);
  assert.equal(((await pending.json()) as { error: string }).error, "authorization_pending");

  assert.equal(await store.approveDeviceCode(dc.user_code, "prin_dev"), true);

  const done = await handleToken(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: dc.device_code,
        client_id: "client_ownmesh_cli",
      }),
    }),
    store,
  );
  assert.equal(done.status, 200);
  const tok = (await done.json()) as { access_token: string; refresh_token?: string };
  assert.ok(await store.getAccess(tok.access_token));
  assert.equal(tok.refresh_token, undefined);
});

test("dynamic client registration returns policy", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  await store.ensurePrincipal("prin_dcr", "DCR User", "user", "ten_default");
  const tok = await store.issueTokens("client_ownmesh_cli", "prin_dcr", "ownmesh.device");
  const res = await handleRegister(
    new Request("https://cp.test/oauth/register", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${tok.access_token}`,
      },
      body: JSON.stringify({
        client_name: "ChatGPT",
        redirect_uris: ["https://chatgpt.com/connector/oauth/callback"],
      }),
    }),
    store,
    { allowDynamicRegistration: true },
  );
  assert.equal(res.status, 201);
  const body = (await res.json()) as {
    client_id: string;
    client_name: string;
    redirect_uris: string[];
    token_endpoint_auth_method: string;
    policy: { redirect_uri_match: string; dynamic_client_registration: string };
  };
  assert.ok(body.client_id);
  assert.equal(body.client_name, "ChatGPT");
  assert.deepEqual(body.redirect_uris, ["https://chatgpt.com/connector/oauth/callback"]);
  assert.equal(body.token_endpoint_auth_method, "none");
  assert.equal(body.policy.redirect_uri_match, "exact");
  assert.equal(body.policy.dynamic_client_registration, "supported");
  const stored = await store.getClient(body.client_id);
  assert.ok(stored);
  assert.equal(stored!.tenant_id, "ten_default");
  assert.equal(stored!.client_name, "ChatGPT");
});

test("AS metadata does not advertise client_secret_post", () => {
  const meta = oauthMetadata("https://cp.test") as {
    token_endpoint_auth_methods_supported: string[];
    registration_endpoint?: string;
  };
  assert.deepEqual(meta.token_endpoint_auth_methods_supported, ["none"]);
  assert.equal(
    meta.token_endpoint_auth_methods_supported.includes("client_secret_post"),
    false,
  );
  // Production default: DCR disabled → endpoint omitted from metadata.
  assert.equal(meta.registration_endpoint, undefined);
});

test("AS metadata advertises registration_endpoint only when DCR enabled", () => {
  const off = oauthMetadata("https://cp.test", { allowDynamicRegistration: false }) as {
    registration_endpoint?: string;
  };
  const on = oauthMetadata("https://cp.test", { allowDynamicRegistration: true }) as {
    registration_endpoint?: string;
  };
  assert.equal(off.registration_endpoint, undefined);
  assert.equal(on.registration_endpoint, "https://cp.test/oauth/register");
});

test("register rejects token_endpoint_auth_method=client_secret_post", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  await store.ensurePrincipal("prin_dcr2", "DCR User", "user", "ten_default");
  const tok = await store.issueTokens("client_ownmesh_cli", "prin_dcr2", "ownmesh.device");
  const res = await handleRegister(
    new Request("https://cp.test/oauth/register", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${tok.access_token}`,
      },
      body: JSON.stringify({
        client_name: "secret-client",
        redirect_uris: ["https://example.com/cb"],
        token_endpoint_auth_method: "client_secret_post",
      }),
    }),
    store,
    { allowDynamicRegistration: true },
  );
  assert.equal(res.status, 400);
  const body = (await res.json()) as { error: string };
  assert.equal(body.error, "invalid_client_metadata");
});

test("register accepts token_endpoint_auth_method=none (public client)", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  await store.ensurePrincipal("prin_dcr3", "DCR User", "user", "ten_default");
  const tok = await store.issueTokens("client_ownmesh_cli", "prin_dcr3", "ownmesh.device");
  const res = await handleRegister(
    new Request("https://cp.test/oauth/register", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${tok.access_token}`,
      },
      body: JSON.stringify({
        client_name: "public-client",
        redirect_uris: ["https://example.com/cb"],
        token_endpoint_auth_method: "none",
      }),
    }),
    store,
    { allowDynamicRegistration: true },
  );
  assert.equal(res.status, 201);
  const body = (await res.json()) as { token_endpoint_auth_method: string };
  assert.equal(body.token_endpoint_auth_method, "none");
});

test("token endpoint rejects body client_secret (client_secret_post)", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  await store.putClient({
    client_id: "client_pkce",
    tenant_id: "ten_default",
    client_name: "cli",
    redirect_uris: ["http://127.0.0.1:8750/callback"],
    created_at: new Date().toISOString(),
  });
  // Even with a valid-looking grant shape, client_secret must fail closed.
  const res = await handleToken(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: "ac_fake",
        redirect_uri: "http://127.0.0.1:8750/callback",
        client_id: "client_pkce",
        code_verifier: "0123456789012345678901234567890123456789013",
        client_secret: "super-secret",
      }),
    }),
    store,
  );
  assert.equal(res.status, 401);
  const body = (await res.json()) as { error: string };
  assert.equal(body.error, "invalid_client");
});

test("token endpoint rejects empty client_secret as present (not absent)", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  // Empty string must NOT be treated as "no secret" / public-client proof.
  const res = await handleToken(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: "rtk_whatever",
        client_id: "client_pkce",
        client_secret: "",
      }),
    }),
    store,
  );
  assert.equal(res.status, 401);
  const body = (await res.json()) as { error: string; error_description?: string };
  assert.equal(body.error, "invalid_client");
  assert.match(body.error_description || "", /client_secret/i);
});

test("token endpoint rejects Authorization: Basic (client_secret_basic)", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const basic = Buffer.from("client_pkce:super-secret").toString("base64");
  const res = await handleToken(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${basic}`,
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: "rtk_whatever",
        client_id: "client_pkce",
      }),
    }),
    store,
  );
  assert.equal(res.status, 401);
  const body = (await res.json()) as { error: string; error_description?: string };
  assert.equal(body.error, "invalid_client");
  assert.match(body.error_description || "", /basic|client_secret_basic/i);
});

test("token endpoint rejects token_endpoint_auth_method=client_secret_post", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const res = await handleToken(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: "rtk_whatever",
        token_endpoint_auth_method: "client_secret_post",
      }),
    }),
    store,
  );
  assert.equal(res.status, 401);
  const body = (await res.json()) as { error: string };
  assert.equal(body.error, "invalid_client");
});

test("AS metadata advertises only token_endpoint_auth_method none", () => {
  const meta = oauthMetadata("https://cp.test") as {
    token_endpoint_auth_methods_supported: string[];
  };
  assert.deepEqual(meta.token_endpoint_auth_methods_supported, ["none"]);
  assert.equal(meta.token_endpoint_auth_methods_supported.length, 1);
  for (const method of [
    "client_secret_post",
    "client_secret_basic",
    "client_secret_jwt",
    "private_key_jwt",
  ]) {
    assert.equal(
      meta.token_endpoint_auth_methods_supported.includes(method),
      false,
      `must not advertise ${method}`,
    );
  }
});
