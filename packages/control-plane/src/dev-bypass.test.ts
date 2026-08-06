/**
 * Dev auth bypass gate: flag + loopback request host + loopback issuer only.
 * Worker.fetch-level coverage — bypass must never activate remotely.
 */
import assert from "node:assert/strict";
import test from "node:test";
import worker, { __setTestStore } from "./index.ts";
import { MemoryStore } from "./store.ts";

const ctx = {} as ExecutionContext;

const LOOPBACK_ORIGIN = "http://127.0.0.1:8787";
const LOOPBACK_ISSUER = "http://127.0.0.1:8787";
const REMOTE_ORIGIN = "https://cp.example.com";
const REMOTE_ISSUER = "https://issuer.example.com";
const REDIRECT = "http://127.0.0.1:8750/callback";

function authorizeUrl(origin: string, extra: Record<string, string> = {}): string {
  const u = new URL(`${origin}/oauth/authorize`);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", "client_bypass");
  u.searchParams.set("redirect_uri", REDIRECT);
  u.searchParams.set("code_challenge", "abc");
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("scope", "ownmesh.read");
  u.searchParams.set("auto", "1");
  for (const [k, v] of Object.entries(extra)) u.searchParams.set(k, v);
  return u.toString();
}

async function withStore<T>(fn: (store: MemoryStore) => Promise<T>): Promise<T> {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  await store.putClient({
    client_id: "client_bypass",
    tenant_id: "ten_default",
    client_name: "bypass-test",
    redirect_uris: [REDIRECT],
    created_at: new Date().toISOString(),
  });
  __setTestStore(store);
  try {
    return await fn(store);
  } finally {
    __setTestStore(null);
  }
}

test("flag + loopback host + loopback issuer: authorize bypass works", async () => {
  await withStore(async () => {
    const res = await worker.fetch(
      new Request(authorizeUrl(LOOPBACK_ORIGIN), {
        headers: { "x-ownmesh-dev-principal": "prin_loopback" },
      }),
      { OWNMESH_DEV_AUTH_BYPASS: "true", OAUTH_ISSUER: LOOPBACK_ISSUER },
      ctx,
    );
    assert.equal(res.status, 302, "expected auto-consent redirect under full bypass gate");
    const loc = res.headers.get("location") || "";
    assert.ok(loc.startsWith(REDIRECT));
    assert.ok(new URL(loc).searchParams.get("code"));
  });
});

test("flag + loopback host + loopback issuer (via default origin): device GET works", async () => {
  await withStore(async (store) => {
    await store.putDeviceCode({
      device_code: "dc_loop",
      user_code: "ABCD-EFGH",
      client_id: "client_bypass",
      scope: "ownmesh.read",
      verification_uri: `${LOOPBACK_ORIGIN}/oauth/device`,
      interval_sec: 5,
      expires_at: Date.now() + 60_000,
      status: "pending",
    });
    // No OAUTH_ISSUER → issuer falls back to request origin (loopback).
    const res = await worker.fetch(
      new Request(`${LOOPBACK_ORIGIN}/oauth/device?user_code=ABCD-EFGH`),
      { OWNMESH_DEV_AUTH_BYPASS: "true" },
      ctx,
    );
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.match(html, /Authorize device|transaction_id|csrf_token/i);
  });
});

test("flag + loopback: dev bypass does not enable DCR", async () => {
  await withStore(async () => {
    const res = await worker.fetch(
      new Request(`${LOOPBACK_ORIGIN}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client_name: "dyn",
          redirect_uris: ["http://127.0.0.1:9999/cb"],
        }),
      }),
      { OWNMESH_DEV_AUTH_BYPASS: "true", OAUTH_ISSUER: LOOPBACK_ISSUER },
      ctx,
    );
    assert.equal(res.status, 403);
    assert.equal((await res.json() as { error: string }).error, "registration_disabled");
  });
});

test("flag + remote request host: bypass denied (authorize → 503)", async () => {
  await withStore(async () => {
    const res = await worker.fetch(
      new Request(authorizeUrl(REMOTE_ORIGIN), {
        headers: { "x-ownmesh-dev-principal": "prin_attacker", "login_hint": "ignored" },
      }),
      { OWNMESH_DEV_AUTH_BYPASS: "true", OAUTH_ISSUER: LOOPBACK_ISSUER },
      ctx,
    );
    assert.equal(res.status, 503);
    const body = (await res.json()) as { error?: string };
    assert.equal(body.error, "auth_provider_unavailable");
  });
});

test("flag + remote request host: login_hint / x-ownmesh-dev-principal not honored", async () => {
  await withStore(async () => {
    // Even with attacker-supplied principal headers, remote host must not bypass.
    const res = await worker.fetch(
      new Request(authorizeUrl(REMOTE_ORIGIN, { login_hint: "evil_principal" }), {
        headers: { "x-ownmesh-dev-principal": "evil_principal" },
      }),
      { OWNMESH_DEV_AUTH_BYPASS: "true", OAUTH_ISSUER: "http://localhost:8787" },
      ctx,
    );
    assert.equal(res.status, 503);
    assert.equal((await res.json() as { error: string }).error, "auth_provider_unavailable");
  });
});

test("flag + remote issuer: bypass denied even on loopback request host", async () => {
  await withStore(async () => {
    const res = await worker.fetch(
      new Request(authorizeUrl(LOOPBACK_ORIGIN), {
        headers: { "x-ownmesh-dev-principal": "prin_dev" },
      }),
      { OWNMESH_DEV_AUTH_BYPASS: "true", OAUTH_ISSUER: REMOTE_ISSUER },
      ctx,
    );
    assert.equal(res.status, 503);
    assert.equal((await res.json() as { error: string }).error, "auth_provider_unavailable");
  });
});

test("flag + remote issuer: device path denied", async () => {
  await withStore(async () => {
    const res = await worker.fetch(
      new Request(`${LOOPBACK_ORIGIN}/oauth/device`),
      { OWNMESH_DEV_AUTH_BYPASS: "true", OAUTH_ISSUER: REMOTE_ISSUER },
      ctx,
    );
    assert.equal(res.status, 503);
    assert.equal((await res.json() as { error: string }).error, "auth_provider_unavailable");
  });
});

test("flag + remote host: DCR not enabled by bypass", async () => {
  await withStore(async () => {
    const res = await worker.fetch(
      new Request(`${REMOTE_ORIGIN}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["https://client.test/cb"] }),
      }),
      { OWNMESH_DEV_AUTH_BYPASS: "true", OAUTH_ISSUER: LOOPBACK_ISSUER },
      ctx,
    );
    assert.equal(res.status, 403);
    assert.equal((await res.json() as { error: string }).error, "registration_disabled");
  });
});

test("no flag: loopback host+issuer still denied", async () => {
  await withStore(async () => {
    const res = await worker.fetch(
      new Request(authorizeUrl(LOOPBACK_ORIGIN), {
        headers: { "x-ownmesh-dev-principal": "prin_dev" },
      }),
      { OAUTH_ISSUER: LOOPBACK_ISSUER },
      ctx,
    );
    assert.equal(res.status, 503);
    assert.equal((await res.json() as { error: string }).error, "auth_provider_unavailable");
  });
});

test("no flag: DCR remains disabled on loopback", async () => {
  await withStore(async () => {
    const res = await worker.fetch(
      new Request(`${LOOPBACK_ORIGIN}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["http://127.0.0.1:9999/cb"] }),
      }),
      { OAUTH_ISSUER: LOOPBACK_ISSUER },
      ctx,
    );
    assert.equal(res.status, 403);
    assert.equal((await res.json() as { error: string }).error, "registration_disabled");
  });
});

test("flag + remote host falls through to AUTH_PROVIDER when bound", async () => {
  await withStore(async () => {
    const authProvider = {
      fetch: async () =>
        Response.json({ principal_id: "prin_real", tenant_id: "ten_default", display_name: "Real" }),
    } as unknown as Fetcher;
    const res = await worker.fetch(
      new Request(authorizeUrl(REMOTE_ORIGIN, { auto: "0" })),
      {
        OWNMESH_DEV_AUTH_BYPASS: "true",
        OAUTH_ISSUER: REMOTE_ISSUER,
        AUTH_PROVIDER: authProvider,
      },
      ctx,
    );
    // Bypass inactive → real AUTH_PROVIDER principal used; without auto/POST approve → consent HTML.
    assert.equal(res.status, 200);
    const ct = res.headers.get("content-type") || "";
    assert.match(ct, /text\/html/);
    const html = await res.text();
    assert.match(html, /Approve|OwnMesh/i);
    // Must not have auto-redirected as if bypass were on.
    assert.equal(res.headers.get("location"), null);
  });
});

test("localhost and ::1 hosts are accepted as loopback with flag", async () => {
  await withStore(async () => {
    for (const origin of ["http://localhost:8787", "http://[::1]:8787"]) {
      const res = await worker.fetch(
        new Request(authorizeUrl(origin)),
        { OWNMESH_DEV_AUTH_BYPASS: "true", OAUTH_ISSUER: origin },
        ctx,
      );
      assert.equal(res.status, 302, `expected bypass on ${origin}`);
    }
  });
});
