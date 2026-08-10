import assert from "node:assert/strict";
import test from "node:test";
import worker, { __setTestStore } from "./index.ts";
import {
  chatGptOAuthPair,
  handleChatGptConnector,
  handleOwnerLogin,
  ownerPrincipalFromRequest,
} from "./owner-auth.ts";
import { MemoryStore } from "./store.ts";
import { sha256Hex } from "./util.ts";

const ISSUER = "https://ownmesh.example";
const OWNER_CODE = "own_0123456789abcdefghijklmnopqrstuv";
const SESSION_SECRET = "session-secret-with-at-least-thirty-two-bytes";
const CALLBACK = "https://chatgpt.com/connector/oauth/b6NcEskp3DnC";
const CLIENT_ID = "client_chatgpt_b6nceskp3dnc";
const ctx = {} as ExecutionContext;

async function env() {
  return {
    OAUTH_ISSUER: ISSUER,
    SESSION_SECRET,
    OWNER_TOKEN_HASH: await sha256Hex(OWNER_CODE),
  };
}

function form(values: Record<string, string>): URLSearchParams {
  return new URLSearchParams(values);
}

test("owner login issues a secure signed session and rejects tampering", async () => {
  const store = new MemoryStore();
  const authEnv = await env();
  const response = await handleOwnerLogin(
    new Request(`${ISSUER}/login`, {
      method: "POST",
      headers: {
        origin: ISSUER,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: form({ owner_code: OWNER_CODE, return_to: "/connect/chatgpt" }),
    }),
    store,
    ISSUER,
    authEnv,
  );
  assert.equal(response.status, 303);
  const setCookie = response.headers.get("set-cookie") || "";
  assert.match(setCookie, /__Host-ownmesh_owner=.*Secure; HttpOnly; SameSite=Lax/);
  const sessionCookie = setCookie.split(";", 1)[0]!;
  assert.equal(
    (await ownerPrincipalFromRequest(
      new Request(`${ISSUER}/`, { headers: { cookie: sessionCookie } }),
      authEnv,
      ISSUER,
    ))?.id,
    "prin_owner",
  );
  assert.equal(
    await ownerPrincipalFromRequest(
      new Request(`${ISSUER}/`, { headers: { cookie: `${sessionCookie}x` } }),
      authEnv,
      ISSUER,
    ),
    null,
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
  const post = await handleChatGptConnector(
    new Request(`${ISSUER}/connect/chatgpt`, {
      method: "POST",
      headers: {
        origin: ISSUER,
        cookie: csrfCookie,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: form({ callback: CALLBACK, csrf_token: csrf }),
    }),
    store,
    ISSUER,
    { id: "prin_owner", tenant_id: "ten_default", display_name: "Owner" },
  );
  assert.equal(post.status, 201);
  assert.deepEqual((await store.getClient(CLIENT_ID))?.redirect_uris, [CALLBACK]);
});

test("ChatGPT OAuth redirects to owner login then requires explicit consent", async () => {
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

    const login = await worker.fetch(
      new Request(`${ISSUER}/login`, {
        method: "POST",
        headers: {
          origin: ISSUER,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: form({ owner_code: OWNER_CODE, return_to: `${authorize.pathname}${authorize.search}` }),
      }),
      authEnv,
      ctx,
    );
    const sessionCookie = (login.headers.get("set-cookie") || "").split(";", 1)[0]!;
    const consent = await worker.fetch(
      new Request(authorize, { headers: { cookie: sessionCookie } }),
      authEnv,
      ctx,
    );
    assert.equal(consent.status, 200);
    const page = await consent.text();
    const transactionId = /name="transaction_id" value="([^"]+)"/.exec(page)?.[1] || "";
    const csrf = /name="csrf_token" value="([^"]+)"/.exec(page)?.[1] || "";
    assert.ok(transactionId && csrf);
    assert.ok(await store.getClient(CLIENT_ID));

    const approved = await worker.fetch(
      new Request(`${ISSUER}/oauth/authorize`, {
        method: "POST",
        headers: {
          origin: ISSUER,
          cookie: sessionCookie,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: form({ transaction_id: transactionId, csrf_token: csrf, decision: "approve" }),
      }),
      authEnv,
      ctx,
    );
    assert.equal(approved.status, 302);
    const callback = new URL(approved.headers.get("location")!);
    assert.equal(callback.origin, "https://chatgpt.com");
    assert.equal(callback.searchParams.get("state"), "state_1");
    assert.ok(callback.searchParams.get("code"));
  } finally {
    __setTestStore(null);
  }
});
