import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { fileURLToPath } from "node:url";
import worker, { __setTestStore } from "./index.ts";
import {
  chatGptOAuthPair,
  handleChatGptConnector,
  handleOwnerLogin,
  handleOwnerPasskeyOptions,
  handleOwnerPasskeyRegistrationOptions,
  ownerPrincipalFromRequest,
  sameOriginBrowserPost,
} from "./owner-auth.ts";
import { MemoryStore, SqlStore, type SqlDatabase, type SqlStatement } from "./store.ts";
import { sha256Hex } from "./util.ts";

const ISSUER = "https://ownmesh.example";
const OWNER_CODE = "own_0123456789abcdefghijklmnopqrstuv";
const SESSION_SECRET = "session-secret-with-at-least-thirty-two-bytes";
const CALLBACK = "https://chatgpt.com/connector/oauth/b6NcEskp3DnC";
const CLIENT_ID = "client_chatgpt_b6nceskp3dnc";
const CREDENTIAL_ID = "Y3JlZGVudGlhbF9vd25lcg";
const ctx = {} as ExecutionContext;

function sqlStore(): SqlStore {
  const db = new DatabaseSync(":memory:");
  const migrations = fileURLToPath(new URL("../migrations", import.meta.url));
  for (const name of readdirSync(migrations).sort()) {
    if (name.endsWith(".sql")) db.exec(readFileSync(join(migrations, name), "utf8"));
  }
  const adapter: SqlDatabase = {
    prepare(query: string): SqlStatement {
      const statement = db.prepare(query);
      let values: unknown[] = [];
      const sqliteValues = () => values.map((value) => {
        if (value instanceof ArrayBuffer) return new Uint8Array(value);
        if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "bigint" || value instanceof Uint8Array) {
          return value;
        }
        throw new TypeError("unsupported sqlite test binding");
      });
      return {
        bind(...next: unknown[]) { values = next; return this; },
        async first<T>(column?: string) {
          const row = statement.get(...sqliteValues()) as Record<string, unknown> | undefined;
          return row ? (column ? row[column] as T : row as T) : null;
        },
        async run<T>() {
          const result = statement.run(...sqliteValues());
          return { success: true, meta: { changes: Number(result.changes) }, results: [] as T[] };
        },
        async all<T>() { return { results: statement.all(...sqliteValues()) as T[] }; },
      };
    },
  };
  return new SqlStore(adapter, "sqlite");
}

async function env() {
  return {
    OAUTH_ISSUER: ISSUER,
    SESSION_SECRET,
    OWNER_TOKEN_HASH: await sha256Hex(OWNER_CODE),
  };
}

function jsonRequest(path: string, body: Record<string, unknown>): Request {
  return new Request(`${ISSUER}${path}`, {
    method: "POST",
    headers: { origin: ISSUER, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function ownerSessionCookie(): Promise<string> {
  const claims = {
    v: 1,
    sub: "prin_owner",
    tenant: "ten_default",
    aud: ISSUER,
    exp: Date.now() + 60_000,
    nonce: "0123456789abcdef0123456789abcdef",
  };
  const body = base64Url(new TextEncoder().encode(JSON.stringify(claims)));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(SESSION_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body)),
  );
  return `__Host-ownmesh_owner=${body}.${base64Url(signature)}`;
}

async function seedPasskey(store: MemoryStore): Promise<void> {
  await store.ensureBootstrap();
  await store.ensurePrincipal("prin_owner", "Owner", "human", "ten_default");
  assert.equal(await store.putInitialOwnerPasskey({
    credential_id: CREDENTIAL_ID,
    principal_id: "prin_owner",
    webauthn_user_id: "d2ViYXV0aG5fb3duZXJfaWQ",
    public_key: new Uint8Array(64).fill(7),
    counter: 0,
    transports: ["internal"],
    device_type: "multiDevice",
    backed_up: true,
    created_at: new Date().toISOString(),
  }), true);
}

test("one-time owner code claims exactly one passkey registration ceremony", async () => {
  const store = new MemoryStore();
  const authEnv = await env();
  const page = await handleOwnerLogin(new Request(`${ISSUER}/login`), store, ISSUER, authEnv);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Create owner passkey/);

  const denied = await handleOwnerPasskeyRegistrationOptions(
    jsonRequest("/auth/passkey/register/options", { owner_code: `${OWNER_CODE}x`, return_to: "/connect/chatgpt" }),
    store,
    ISSUER,
    authEnv,
  );
  assert.equal(denied.status, 401);

  const accepted = await handleOwnerPasskeyRegistrationOptions(
    jsonRequest("/auth/passkey/register/options", { owner_code: OWNER_CODE, return_to: "/connect/chatgpt" }),
    store,
    ISSUER,
    authEnv,
  );
  assert.equal(accepted.status, 200);
  assert.match(accepted.headers.get("set-cookie") || "", /__Host-ownmesh_passkey=owner_registration/);
  const result = await accepted.json() as { options: { rp: { id: string }; authenticatorSelection: { userVerification: string } } };
  assert.equal(result.options.rp.id, "ownmesh.example");
  assert.equal(result.options.authenticatorSelection.userVerification, "required");
  assert.equal(JSON.stringify([...store.ownerAuthChallenges.values()]).includes(OWNER_CODE), false);

  const concurrent = await handleOwnerPasskeyRegistrationOptions(
    jsonRequest("/auth/passkey/register/options", { owner_code: OWNER_CODE }),
    store,
    ISSUER,
    authEnv,
  );
  assert.equal(concurrent.status, 409);
});

test("registered owner signs in with only the stored passkey", async () => {
  const store = new MemoryStore();
  await seedPasskey(store);
  const authEnv = await env();
  const page = await handleOwnerLogin(new Request(`${ISSUER}/login`), store, ISSUER, authEnv);
  assert.match(await page.text(), /Sign in with passkey/);

  const options = await handleOwnerPasskeyOptions(
    jsonRequest("/auth/passkey/options", { return_to: "/connect/chatgpt" }),
    store,
    ISSUER,
    authEnv,
  );
  assert.equal(options.status, 200);
  const body = await options.json() as { options: { allowCredentials: Array<{ id: string }> } };
  assert.deepEqual(body.options.allowCredentials.map((item) => item.id), [CREDENTIAL_ID]);
  assert.equal(store.ownerAuthChallenges.size, 1);
});

test("SQL passkey challenge is one-time and initial credential is insert-once", async () => {
  const store = sqlStore();
  await store.ensureBootstrap();
  await store.ensurePrincipal("prin_owner", "Owner", "human", "ten_default");
  const challenge = {
    id: "owner_registration",
    kind: "register" as const,
    challenge: "0123456789abcdef0123456789abcdef",
    webauthn_user_id: "d2ViYXV0aG5fb3duZXJfaWQ",
    return_to: "/connect/chatgpt",
    expires_at: Date.now() + 60_000,
    created_at: new Date().toISOString(),
  };
  assert.equal(await store.putOwnerAuthChallenge(challenge), true);
  assert.equal(await store.putOwnerAuthChallenge(challenge), false);
  assert.equal((await store.takeOwnerAuthChallenge(challenge.id, "register"))?.challenge, challenge.challenge);
  assert.equal(await store.takeOwnerAuthChallenge(challenge.id, "register"), null);

  const passkey = {
    credential_id: CREDENTIAL_ID,
    principal_id: "prin_owner",
    webauthn_user_id: challenge.webauthn_user_id,
    public_key: new Uint8Array(64).fill(9),
    counter: 0,
    transports: ["internal"],
    device_type: "multiDevice" as const,
    backed_up: true,
    created_at: new Date().toISOString(),
  };
  assert.equal(await store.putInitialOwnerPasskey(passkey), true);
  assert.equal(await store.putInitialOwnerPasskey({ ...passkey, credential_id: `${CREDENTIAL_ID}x` }), false);
  assert.deepEqual((await store.getOwnerPasskey(CREDENTIAL_ID))?.public_key, passkey.public_key);
  assert.equal(await store.updateOwnerPasskeyUsage(CREDENTIAL_ID, 0, 1, "multiDevice", true), true);
  assert.equal(await store.updateOwnerPasskeyUsage(CREDENTIAL_ID, 0, 2, "multiDevice", true), false);
});

test("owner session is issuer-bound and rejects tampering", async () => {
  const authEnv = await env();
  const cookie = await ownerSessionCookie();
  assert.equal(
    (await ownerPrincipalFromRequest(new Request(`${ISSUER}/`, { headers: { cookie } }), authEnv, ISSUER))?.id,
    "prin_owner",
  );
  assert.equal(
    await ownerPrincipalFromRequest(new Request(`${ISSUER}/`, { headers: { cookie: `${cookie}x` } }), authEnv, ISSUER),
    null,
  );
});

test("browser POST origin fallback requires exact same-origin metadata", () => {
  assert.equal(
    sameOriginBrowserPost(new Request(`${ISSUER}/submit`, { headers: { origin: ISSUER } }), ISSUER),
    true,
  );
  assert.equal(
    sameOriginBrowserPost(new Request(`${ISSUER}/submit`, {
      headers: { "sec-fetch-site": "same-origin" },
    }), ISSUER),
    true,
  );
  assert.equal(
    sameOriginBrowserPost(new Request(`${ISSUER}/submit`, {
      headers: { referer: "https://evil.example/form", "sec-fetch-site": "cross-site" },
    }), ISSUER),
    false,
  );
  assert.equal(
    sameOriginBrowserPost(new Request(`${ISSUER}/submit`, {
      headers: { referer: `${ISSUER}/form` },
    }), ISSUER),
    true,
  );
  assert.equal(
    sameOriginBrowserPost(new Request(`${ISSUER}/submit`), ISSUER),
    false,
  );
});

test("authenticated owner registers only an exact ChatGPT callback pair", async () => {
  assert.equal(chatGptOAuthPair(CLIENT_ID, CALLBACK), true);
  assert.equal(chatGptOAuthPair(CLIENT_ID, "https://evil.example/connector/oauth/b6NcEskp3DnC"), false);
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const get = await handleChatGptConnector(
    new Request(`${ISSUER}/connect/chatgpt`),
    store,
    ISSUER,
    { id: "prin_owner", tenant_id: "ten_default", display_name: "Owner" },
  );
  const page = await get.text();
  const csrf = /name="csrf_token" value="([^"]+)"/.exec(page)?.[1] || "";
  const csrfCookie = (get.headers.get("set-cookie") || "").split(";", 1)[0]!;
  const crossSite = await handleChatGptConnector(
    new Request(`${ISSUER}/connect/chatgpt`, {
      method: "POST",
      headers: {
        referer: "https://evil.example/connect/chatgpt",
        "sec-fetch-site": "cross-site",
        cookie: csrfCookie,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ callback: CALLBACK, csrf_token: csrf }),
    }),
    store,
    ISSUER,
    { id: "prin_owner", tenant_id: "ten_default", display_name: "Owner" },
  );
  assert.equal(crossSite.status, 403);
  const post = await handleChatGptConnector(
    new Request(`${ISSUER}/connect/chatgpt`, {
      method: "POST",
      headers: {
        "sec-fetch-site": "same-origin",
        cookie: csrfCookie,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ callback: CALLBACK, csrf_token: csrf }),
    }),
    store,
    ISSUER,
    { id: "prin_owner", tenant_id: "ten_default", display_name: "Owner" },
  );
  assert.equal(post.status, 201);
  assert.deepEqual((await store.getClient(CLIENT_ID))?.redirect_uris, [CALLBACK]);
});

test("ChatGPT OAuth redirects to passkey login then accepts an owner session", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  __setTestStore(store);
  try {
    const authEnv = await env();
    const authorize = new URL(`${ISSUER}/oauth/authorize`);
    authorize.searchParams.set("response_type", "code");
    authorize.searchParams.set("client_id", CLIENT_ID);
    authorize.searchParams.set("redirect_uri", CALLBACK);
    authorize.searchParams.set("code_challenge", "challenge");
    authorize.searchParams.set("code_challenge_method", "S256");
    authorize.searchParams.set("scope", "ownmesh.read offline_access");
    authorize.searchParams.set("state", "state_1");

    const unauthenticated = await worker.fetch(new Request(authorize), authEnv, ctx);
    assert.equal(unauthenticated.status, 302);
    assert.equal(new URL(unauthenticated.headers.get("location")!).pathname, "/login");

    const consent = await worker.fetch(
      new Request(authorize, { headers: { cookie: await ownerSessionCookie() } }),
      authEnv,
      ctx,
    );
    assert.equal(consent.status, 200);
    assert.match(await consent.text(), /<title>OwnMesh Authorize<\/title>/);
    assert.deepEqual((await store.getClient(CLIENT_ID))?.redirect_uris, [CALLBACK]);
  } finally {
    __setTestStore(null);
  }
});
