/**
 * Production-path security tests: worker.fetch against SqlStore on node:sqlite
 * with a transaction-capable batch adapter (same pattern as persistence-races).
 *
 * Covers authorize+consent-tx+PKCE, device-code, enroll→proof→activate with a
 * real WebCrypto Ed25519 keypair, and fail-closed security negatives.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import worker, { __setTestStore } from "./index.ts";
import { SqlStore, type SqlDatabase, type SqlStatement } from "./store.ts";
import { sha256Hex } from "./util.ts";

const ctx = {} as ExecutionContext;
const ISSUER = "https://cp.test";
const REDIRECT = "http://127.0.0.1:8750/callback";
const CLIENT = "client_ownmesh_cli";
const PRINCIPAL_ID = "prin_dev";
const TENANT_ID = "ten_default";

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, "..", "migrations");

/** Transaction-capable node:sqlite adapter (BEGIN IMMEDIATE + serialized batch). */
function openSqlStore(): SqlStore {
  const db = new DatabaseSync(":memory:");
  // Match D1 foreign-key enforcement so unprovisioned tenant INSERTs fail closed.
  db.exec("PRAGMA foreign_keys = ON");
  for (const file of readdirSync(migrationsDir).filter((f) => f.endsWith(".sql")).sort()) {
    db.exec(readFileSync(join(migrationsDir, file), "utf8"));
  }
  type V = null | number | string | bigint | Uint8Array;
  let batchTail: Promise<void> = Promise.resolve();
  const adapter: SqlDatabase = {
    prepare(query: string): SqlStatement {
      const statement = db.prepare(query);
      let values: V[] = [];
      const api: SqlStatement = {
        bind(...input: unknown[]) {
          values = input.map((v) => (v === undefined ? null : (v as V)));
          return api;
        },
        async first<T>(column?: string) {
          const row = statement.get(...values) as Record<string, unknown> | undefined;
          return row ? (column ? (row[column] as T) : (row as T)) : null;
        },
        async run() {
          const info = statement.run(...values) as { changes: number };
          return { success: true, meta: { changes: info.changes } };
        },
        async all<T>() {
          return { results: statement.all(...values) as T[] };
        },
      };
      return api;
    },
    async batch<T>(statements: SqlStatement[]): Promise<T[]> {
      const run = async (): Promise<T[]> => {
        db.exec("BEGIN IMMEDIATE");
        try {
          const results: unknown[] = [];
          for (const statement of statements) results.push(await statement.run());
          db.exec("COMMIT");
          return results as T[];
        } catch (error) {
          db.exec("ROLLBACK");
          throw error;
        }
      };
      const result = batchTail.then(run, run);
      batchTail = result.then(
        () => undefined,
        () => undefined,
      );
      return result;
    },
  };
  return new SqlStore(adapter, "sqlite");
}

function authProvider(
  principalId = PRINCIPAL_ID,
  tenantId = TENANT_ID,
): Fetcher {
  return {
    fetch: async () =>
      Response.json({
        principal_id: principalId,
        tenant_id: tenantId,
        display_name: principalId,
      }),
  } as unknown as Fetcher;
}

function env(_store: SqlStore, extra: Record<string, unknown> = {}) {
  return {
    AUTH_PROVIDER: authProvider(),
    OAUTH_ISSUER: ISSUER,
    ...extra,
  };
}

async function withStore<T>(fn: (store: SqlStore) => Promise<T>): Promise<T> {
  const store = openSqlStore();
  await store.ensureBootstrap();
  __setTestStore(store);
  try {
    return await fn(store);
  } finally {
    __setTestStore(null);
  }
}

async function makePkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = "0123456789012345678901234567890123456789013";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const bytes = new Uint8Array(digest);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const challenge = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return { verifier, challenge };
}

function parseConsentForm(html: string): { tx: string; csrf: string } {
  const tx = /name="transaction_id" value="([^"]+)"/.exec(html)?.[1];
  const csrf = /name="csrf_token" value="([^"]+)"/.exec(html)?.[1];
  assert.ok(tx && csrf, "consent form must include transaction_id and csrf_token");
  return { tx: tx!, csrf: csrf! };
}

async function ed25519Keypair(): Promise<{ publicKeyHex: string; privateKey: CryptoKey }> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const publicBytes = new Uint8Array(
    (await crypto.subtle.exportKey("raw", keyPair.publicKey)) as ArrayBuffer,
  );
  const publicKeyHex = [...publicBytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return { publicKeyHex, privateKey: keyPair.privateKey };
}

async function signHex(privateKey: CryptoKey, message: string): Promise<string> {
  const signatureBytes = new Uint8Array(
    await crypto.subtle.sign("Ed25519", privateKey, new TextEncoder().encode(message)),
  );
  return [...signatureBytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// Happy paths on SqlStore + worker
// ---------------------------------------------------------------------------

test("production-path: authorize consent-tx + PKCE exchange via worker + SqlStore", async () => {
  await withStore(async (store) => {
    const { verifier, challenge } = await makePkce();
    const e = env(store);

    const getRes = await worker.fetch(
      new Request(
        `${ISSUER}/oauth/authorize?response_type=code&client_id=${CLIENT}` +
          `&redirect_uri=${encodeURIComponent(REDIRECT)}` +
          `&code_challenge=${challenge}&code_challenge_method=S256` +
          `&scope=ownmesh.read%20offline_access&state=st_prod`,
      ),
      e,
      ctx,
    );
    assert.equal(getRes.status, 200);
    const { tx, csrf } = parseConsentForm(await getRes.text());

    const postRes = await worker.fetch(
      new Request(`${ISSUER}/oauth/authorize`, {
        method: "POST",
        headers: {
          origin: ISSUER,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          transaction_id: tx,
          csrf_token: csrf,
          decision: "approve",
          // attacker-controlled params must be ignored
          scope: "ownmesh.exec",
          redirect_uri: "https://evil.example/cb",
        }),
      }),
      e,
      ctx,
    );
    assert.equal(postRes.status, 302);
    const loc = new URL(postRes.headers.get("location")!);
    assert.equal(loc.origin + loc.pathname, REDIRECT);
    assert.equal(loc.searchParams.get("state"), "st_prod");
    const code = loc.searchParams.get("code");
    assert.ok(code?.startsWith("ac_"));

    const tokRes = await worker.fetch(
      new Request(`${ISSUER}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code!,
          redirect_uri: REDIRECT,
          client_id: CLIENT,
          code_verifier: verifier,
        }),
      }),
      e,
      ctx,
    );
    assert.equal(tokRes.status, 200);
    const tok = (await tokRes.json()) as {
      access_token: string;
      refresh_token?: string;
      token_type: string;
    };
    assert.ok(tok.access_token.startsWith("atk_"));
    assert.ok(tok.refresh_token?.startsWith("rtk_"));
    assert.ok(await store.getAccess(tok.access_token));
  });
});

test("production-path: device-code flow via worker + SqlStore (GET consent → POST approve → token)", async () => {
  await withStore(async (store) => {
    const e = env(store);

    const issued = await worker.fetch(
      new Request(`${ISSUER}/oauth/device_authorization`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ client_id: CLIENT, scope: "ownmesh.read" }),
      }),
      e,
      ctx,
    );
    assert.equal(issued.status, 200);
    const dc = (await issued.json()) as {
      device_code: string;
      user_code: string;
    };
    assert.ok(dc.device_code);
    assert.match(dc.user_code, /^[A-Z]{4}-[A-Z]{4}$/);

    const pending = await worker.fetch(
      new Request(`${ISSUER}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: dc.device_code,
          client_id: CLIENT,
        }),
      }),
      e,
      ctx,
    );
    assert.equal(pending.status, 400);
    assert.equal(((await pending.json()) as { error: string }).error, "authorization_pending");

    const page = await worker.fetch(
      new Request(`${ISSUER}/oauth/device?user_code=${encodeURIComponent(dc.user_code)}`),
      e,
      ctx,
    );
    assert.equal(page.status, 200);
    const { tx, csrf } = parseConsentForm(await page.text());

    const approve = await worker.fetch(
      new Request(`${ISSUER}/oauth/device`, {
        method: "POST",
        headers: {
          origin: ISSUER,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          transaction_id: tx,
          csrf_token: csrf,
          decision: "approve",
        }),
      }),
      e,
      ctx,
    );
    assert.equal(approve.status, 200);

    const done = await worker.fetch(
      new Request(`${ISSUER}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: dc.device_code,
          client_id: CLIENT,
        }),
      }),
      e,
      ctx,
    );
    assert.equal(done.status, 200);
    const tok = (await done.json()) as { access_token: string };
    assert.ok(await store.getAccess(tok.access_token));

    // Second poll must fail closed (code consumed)
    const reuse = await worker.fetch(
      new Request(`${ISSUER}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: dc.device_code,
          client_id: CLIENT,
        }),
      }),
      e,
      ctx,
    );
    assert.equal(reuse.status, 400);
  });
});

test("production-path: enroll → real Ed25519 proof → activate via worker + SqlStore", async () => {
  await withStore(async (store) => {
    const e = env(store);
    const human = await store.issueTokens(CLIENT, PRINCIPAL_ID, "ownmesh.device ownmesh.read");
    const { publicKeyHex, privateKey } = await ed25519Keypair();

    const enrollRes = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/enroll`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name: "prod-agent",
          hostname: "prod.local",
          os: "linux",
          arch: "x64",
          agent_version: "1.0.1",
          protocol_version: "ownmesh.device/1.0",
          public_key: publicKeyHex,
        }),
      }),
      e,
      ctx,
    );
    assert.equal(enrollRes.status, 201);
    const enrolled = (await enrollRes.json()) as {
      device_id: string;
      challenge: { id: string; message: string };
    };
    assert.match(enrolled.device_id, /^dev_/);
    assert.equal((await store.getDevice(enrolled.device_id))?.status, "pending");

    const signature = await signHex(privateKey, enrolled.challenge.message);
    const proofRes = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/enroll/proof`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          device_id: enrolled.device_id,
          challenge_id: enrolled.challenge.id,
          signature,
        }),
      }),
      e,
      ctx,
    );
    assert.equal(proofRes.status, 200);
    const proof = (await proofRes.json()) as {
      ok: boolean;
      status: string;
      device_credential: string;
    };
    assert.equal(proof.ok, true);
    assert.equal(proof.status, "active");
    assert.ok(proof.device_credential.startsWith("dcred_"));
    assert.equal((await store.getDevice(enrolled.device_id))?.status, "active");
    assert.ok(await store.getDeviceCredential(proof.device_credential));

    // Challenge one-time: reuse fails closed
    const reuse = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/enroll/proof`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          device_id: enrolled.device_id,
          challenge_id: enrolled.challenge.id,
          signature,
        }),
      }),
      e,
      ctx,
    );
    assert.ok(reuse.status === 409 || reuse.status === 400);
  });
});

// ---------------------------------------------------------------------------
// Security negatives (fail closed)
// ---------------------------------------------------------------------------

test("production-path negatives: bad Ed25519 signature leaves device pending", async () => {
  await withStore(async (store) => {
    const e = env(store);
    const human = await store.issueTokens(CLIENT, PRINCIPAL_ID, "ownmesh.device");
    const { publicKeyHex } = await ed25519Keypair();

    const enrollRes = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/enroll`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name: "bad-sig",
          hostname: "bad.local",
          os: "linux",
          arch: "x64",
          agent_version: "1.0.1",
          protocol_version: "ownmesh.device/1.0",
          public_key: publicKeyHex,
        }),
      }),
      e,
      ctx,
    );
    const enrolled = (await enrollRes.json()) as {
      device_id: string;
      challenge: { id: string };
    };

    const bad = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/enroll/proof`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          device_id: enrolled.device_id,
          challenge_id: enrolled.challenge.id,
          signature: "00".repeat(64),
        }),
      }),
      e,
      ctx,
    );
    assert.equal(bad.status, 400);
    assert.equal((await store.getDevice(enrolled.device_id))?.status, "pending");
  });
});

test("production-path negatives: CSRF replay rejected on authorize and device verification", async () => {
  await withStore(async (store) => {
    const e = env(store);
    const { challenge } = await makePkce();

    // --- authorize consent replay ---
    const getAuth = await worker.fetch(
      new Request(
        `${ISSUER}/oauth/authorize?response_type=code&client_id=${CLIENT}` +
          `&redirect_uri=${encodeURIComponent(REDIRECT)}` +
          `&code_challenge=${challenge}&code_challenge_method=S256&scope=ownmesh.read&state=s`,
      ),
      e,
      ctx,
    );
    const authForm = parseConsentForm(await getAuth.text());
    const approveOnce = () =>
      worker.fetch(
        new Request(`${ISSUER}/oauth/authorize`, {
          method: "POST",
          headers: {
            origin: ISSUER,
            "content-type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            transaction_id: authForm.tx,
            csrf_token: authForm.csrf,
            decision: "approve",
          }),
        }),
        e,
        ctx,
      );
    assert.equal((await approveOnce()).status, 302);
    assert.equal((await approveOnce()).status, 400);

    // wrong CSRF on a fresh tx
    const getAuth2 = await worker.fetch(
      new Request(
        `${ISSUER}/oauth/authorize?response_type=code&client_id=${CLIENT}` +
          `&redirect_uri=${encodeURIComponent(REDIRECT)}` +
          `&code_challenge=${challenge}&code_challenge_method=S256&scope=ownmesh.read`,
      ),
      e,
      ctx,
    );
    const authForm2 = parseConsentForm(await getAuth2.text());
    const wrongCsrf = await worker.fetch(
      new Request(`${ISSUER}/oauth/authorize`, {
        method: "POST",
        headers: {
          origin: ISSUER,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          transaction_id: authForm2.tx,
          csrf_token: "csrf_forged_token_value",
          decision: "approve",
        }),
      }),
      e,
      ctx,
    );
    assert.equal(wrongCsrf.status, 400);

    // --- device verification CSRF replay ---
    const da = await worker.fetch(
      new Request(`${ISSUER}/oauth/device_authorization`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ client_id: CLIENT, scope: "ownmesh.read" }),
      }),
      e,
      ctx,
    );
    const dc = (await da.json()) as { user_code: string };
    const page = await worker.fetch(
      new Request(`${ISSUER}/oauth/device?user_code=${encodeURIComponent(dc.user_code)}`),
      e,
      ctx,
    );
    const devForm = parseConsentForm(await page.text());
    const approveDev = () =>
      worker.fetch(
        new Request(`${ISSUER}/oauth/device`, {
          method: "POST",
          headers: {
            origin: ISSUER,
            "content-type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            transaction_id: devForm.tx,
            csrf_token: devForm.csrf,
            decision: "approve",
          }),
        }),
        e,
        ctx,
      );
    assert.equal((await approveDev()).status, 200);
    assert.equal((await approveDev()).status, 400);
  });
});

test("production-path negatives: expired authorize and device-verification transactions fail closed", async () => {
  await withStore(async (store) => {
    const e = env(store);

    // Expired authorize transaction (inserted directly; worker POST must reject)
    const csrfAuth = "csrf_expired_auth_token";
    const authTxId = "atz_expired_prod";
    await store.putAuthorizeTransaction({
      id: authTxId,
      csrf_hash: await sha256Hex(csrfAuth),
      principal_id: PRINCIPAL_ID,
      tenant_id: TENANT_ID,
      client_id: CLIENT,
      redirect_uri: REDIRECT,
      scope: "ownmesh.read",
      state: "expired",
      code_challenge: "ch_expired",
      code_challenge_method: "S256",
      expires_at: Date.now() - 1_000,
      consumed: false,
    });
    const expiredAuth = await worker.fetch(
      new Request(`${ISSUER}/oauth/authorize`, {
        method: "POST",
        headers: {
          origin: ISSUER,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          transaction_id: authTxId,
          csrf_token: csrfAuth,
          decision: "approve",
        }),
      }),
      e,
      ctx,
    );
    assert.equal(expiredAuth.status, 400);

    // Expired device verification transaction
    await store.putDeviceCode({
      device_code: "dcode_expired_vtx",
      user_code: "EXPD-CODE",
      client_id: CLIENT,
      scope: "ownmesh.read",
      verification_uri: `${ISSUER}/oauth/device`,
      interval_sec: 5,
      expires_at: Date.now() + 60_000,
      status: "pending",
    });
    const csrfDev = "csrf_expired_dev_token";
    const vtxId = "dvt_expired_prod";
    await store.putDeviceVerificationTransaction({
      id: vtxId,
      csrf_hash: await sha256Hex(csrfDev),
      user_code: "EXPD-CODE",
      principal_id: PRINCIPAL_ID,
      client_id: CLIENT,
      scope: "ownmesh.read",
      expires_at: Date.now() - 1_000,
      consumed: false,
    });
    const expiredDev = await worker.fetch(
      new Request(`${ISSUER}/oauth/device`, {
        method: "POST",
        headers: {
          origin: ISSUER,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          transaction_id: vtxId,
          csrf_token: csrfDev,
          decision: "approve",
        }),
      }),
      e,
      ctx,
    );
    assert.equal(expiredDev.status, 400);
    assert.equal((await store.getDeviceCode("dcode_expired_vtx"))?.status, "pending");
  });
});

test("production-path: AUTH_PROVIDER unknown tenant fails closed (401/403) on authorize + device; tenants unchanged", async () => {
  await withStore(async (store) => {
    const unknownTenant = "ten_unprovisioned_xyz";
    const unknownPrincipal = "prin_stranger";
    const e = env(store, {
      AUTH_PROVIDER: authProvider(unknownPrincipal, unknownTenant),
    });

    assert.equal(await store.tenantExists(TENANT_ID), true);
    assert.equal(await store.tenantExists(unknownTenant), false);

    const { challenge } = await makePkce();
    const authorizeRes = await worker.fetch(
      new Request(
        `${ISSUER}/oauth/authorize?response_type=code&client_id=${CLIENT}` +
          `&redirect_uri=${encodeURIComponent(REDIRECT)}` +
          `&code_challenge=${challenge}&code_challenge_method=S256` +
          `&scope=ownmesh.read%20offline_access&state=st_unknown_tenant`,
      ),
      e,
      ctx,
    );
    assert.ok(
      authorizeRes.status === 401 || authorizeRes.status === 403,
      `authorize must fail closed, got ${authorizeRes.status}`,
    );
    assert.notEqual(authorizeRes.status, 500);
    const authorizeBody = (await authorizeRes.json()) as { error?: string };
    assert.equal(authorizeBody.error, "unknown_tenant");

    const deviceRes = await worker.fetch(
      new Request(`${ISSUER}/oauth/device?user_code=ABCD-EFGH`),
      e,
      ctx,
    );
    assert.ok(
      deviceRes.status === 401 || deviceRes.status === 403,
      `device must fail closed, got ${deviceRes.status}`,
    );
    assert.notEqual(deviceRes.status, 500);
    const deviceBody = (await deviceRes.json()) as { error?: string };
    assert.equal(deviceBody.error, "unknown_tenant");

    // No tenant auto-created from provider claims.
    assert.equal(await store.tenantExists(unknownTenant), false);
    // Known principal must not have been inserted under the unknown tenant path either.
    assert.equal(await store.getPrincipal(unknownPrincipal), null);

    // Known tenant still works with the default AUTH_PROVIDER.
    const knownEnv = env(store);
    const knownPage = await worker.fetch(
      new Request(`${ISSUER}/oauth/device`),
      knownEnv,
      ctx,
    );
    assert.equal(knownPage.status, 200);
    assert.match(await knownPage.text(), /user_code|OwnMesh/i);
  });
});

test("production-path negatives: revoked device credential rejected on agent connect", async () => {
  await withStore(async (store) => {
    const e = env(store);
    const human = await store.issueTokens(CLIENT, PRINCIPAL_ID, "ownmesh.device ownmesh.read");
    const { publicKeyHex, privateKey } = await ed25519Keypair();

    const enrollRes = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/enroll`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name: "rev-agent",
          hostname: "rev.local",
          os: "linux",
          arch: "x64",
          agent_version: "1.0.1",
          protocol_version: "ownmesh.device/1.0",
          public_key: publicKeyHex,
        }),
      }),
      e,
      ctx,
    );
    const enrolled = (await enrollRes.json()) as {
      device_id: string;
      challenge: { id: string; message: string };
    };
    const signature = await signHex(privateKey, enrolled.challenge.message);
    const proofRes = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/enroll/proof`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          device_id: enrolled.device_id,
          challenge_id: enrolled.challenge.id,
          signature,
        }),
      }),
      e,
      ctx,
    );
    const proof = (await proofRes.json()) as { device_credential: string };
    assert.ok(proof.device_credential);

    const rev = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/revoke`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ id: enrolled.device_id }),
      }),
      e,
      ctx,
    );
    assert.equal(rev.status, 200);

    // Credential must not validate after revoke
    const hash = await sha256Hex(proof.device_credential);
    assert.equal(
      await store.validateDeviceSession(hash, "agent", enrolled.device_id),
      false,
    );

    // Agent connect must fail closed for revoked device
    const room = {
      idFromName: () => ({}) as DurableObjectId,
      get: () =>
        ({
          fetch: async () => new Response(null, { status: 204 }),
        }) as unknown as DurableObjectStub,
    } as unknown as DurableObjectNamespace;
    const connect = await worker.fetch(
      new Request(
        `${ISSUER}/agent/connect?device_id=${enrolled.device_id}&role=agent`,
        {
          headers: {
            upgrade: "websocket",
            origin: ISSUER,
            authorization: `Bearer ${proof.device_credential}`,
          },
        },
      ),
      { ...e, DEVICE_ROOM: room },
      ctx,
    );
    assert.ok(connect.status === 403 || connect.status === 401);
  });
});
