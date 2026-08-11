/**
 * Authorize consent GET→POST one-time transaction binding.
 * POST must issue codes only from the stored snapshot (CAS consume).
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { handleAuthorize, handleToken } from "./oauth.ts";
import {
  MemoryStore,
  SqlStore,
  type AuthorizeTransaction,
  type SqlDatabase,
  type SqlStatement,
} from "./store.ts";
import { sha256Hex, verifyPkceS256 } from "./util.ts";

const REDIRECT = "http://127.0.0.1:8750/callback";
const CLIENT = "client_consent";
const PRINCIPAL = { id: "prin_dev", tenant_id: "ten_default", display_name: "Dev" };
const OTHER = { id: "prin_other", tenant_id: "ten_default", display_name: "Other" };
const ISSUER = "https://cp.test";

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, "..", "migrations");

function openSqliteStore(): { db: DatabaseSync; store: SqlStore } {
  const db = new DatabaseSync(":memory:");
  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort();
  for (const f of files) db.exec(readFileSync(join(migrationsDir, f), "utf8"));

  type SqlVal = null | number | string | bigint | Uint8Array;
  const adapter: SqlDatabase = {
    prepare(query: string): SqlStatement {
      const stmt = db.prepare(query);
      let bound: SqlVal[] = [];
      const api: SqlStatement = {
        bind(...values: unknown[]) {
          bound = values.map((v) => (v === undefined ? null : (v as SqlVal)));
          return api;
        },
        async first<T>(colName?: string) {
          const row = stmt.get(...bound) as Record<string, unknown> | undefined;
          if (!row) return null;
          if (colName) return (row[colName] as T) ?? null;
          return row as T;
        },
        async run() {
          stmt.run(...bound);
          return { success: true, results: [] };
        },
        async all<T>() {
          return { results: stmt.all(...bound) as T[] };
        },
      };
      return api;
    },
    exec(query: string) {
      db.exec(query);
    },
  };
  return { db, store: new SqlStore(adapter, "sqlite") };
}

async function seedClient(store: MemoryStore | SqlStore, clientId = CLIENT, redirect = REDIRECT) {
  await store.ensureBootstrap();
  await store.putClient({
    client_id: clientId,
    tenant_id: "ten_default",
    client_name: "consent-test",
    redirect_uris: [redirect],
    created_at: new Date().toISOString(),
  });
}

function authzUrl(extra: Record<string, string> = {}): string {
  const p = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    code_challenge: "challenge_abc",
    code_challenge_method: "S256",
    scope: "ownmesh.read",
    state: "st_1",
    ...extra,
  });
  return `https://cp.test/oauth/authorize?${p}`;
}

function parseConsentForm(html: string): { tx: string; csrf: string } {
  const tx = /name="transaction_id" value="([^"]+)"/.exec(html)?.[1];
  const csrf = /name="csrf_token" value="([^"]+)"/.exec(html)?.[1];
  assert.ok(tx && csrf, "consent form must include transaction_id and csrf_token");
  return { tx: tx!, csrf: csrf! };
}

/** Simulate index.ts merging POST form fields into URL searchParams. */
function postDecision(
  fields: Record<string, string>,
  baseQuery: Record<string, string> = {},
): Request {
  const url = new URL("https://cp.test/oauth/authorize");
  for (const [k, v] of Object.entries(baseQuery)) url.searchParams.set(k, v);
  for (const [k, v] of Object.entries(fields)) url.searchParams.set(k, v);
  return new Request(url, { method: "POST" });
}

test("migration 0004 creates authorize_transactions (idempotent)", () => {
  const { db } = openSqliteStore();
  const names = (
    db.prepare(`SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`).all() as {
      name: string;
    }[]
  ).map((r) => r.name);
  assert.ok(names.includes("authorize_transactions"));
  // Re-apply 0004 must not throw (IF NOT EXISTS).
  const sql = readFileSync(join(migrationsDir, "0004_authorize_transactions.sql"), "utf8");
  db.exec(sql);
  const cols = (
    db.prepare(`PRAGMA table_info(authorize_transactions)`).all() as { name: string }[]
  ).map((c) => c.name);
  for (const need of [
    "id",
    "csrf_hash",
    "principal_id",
    "tenant_id",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
    "expires_at",
    "consumed",
    "created_at",
  ]) {
    assert.ok(cols.includes(need), `missing column ${need}`);
  }
});

test("GET consent issues one-time tx bound to full snapshot", async () => {
  const store = new MemoryStore();
  await seedClient(store);
  const page = await handleAuthorize(
    new Request(authzUrl()),
    store,
    ISSUER,
    { principal: PRINCIPAL },
  );
  assert.equal(page.status, 200);
  assert.match(
    page.headers.get("content-security-policy") || "",
    /form-action 'self' http:\/\/127\.0\.0\.1:8750(?:;| )/,
  );
  const html = await page.text();
  assert.match(html, /transaction_id/);
  assert.match(html, /csrf_token/);
  assert.match(html, /Authorize ChatGPT — OwnMesh/);
  assert.match(html, /OAuth 2\.1 \/ PKCE S256/);
  // Form must NOT re-submit raw OAuth params as hidden fields.
  assert.doesNotMatch(html, /name="redirect_uri"/);
  assert.doesNotMatch(html, /name="code_challenge"/);
  assert.doesNotMatch(html, /name="scope"/);
  assert.doesNotMatch(html, /name="client_id"/);

  const { tx } = parseConsentForm(html);
  const stored = store.authorizeTransactions.get(tx);
  assert.ok(stored);
  assert.equal(stored!.consumed, false);
  assert.equal(stored!.principal_id, PRINCIPAL.id);
  assert.equal(stored!.tenant_id, PRINCIPAL.tenant_id);
  assert.equal(stored!.client_id, CLIENT);
  assert.equal(stored!.redirect_uri, REDIRECT);
  assert.equal(stored!.scope, "ownmesh.read");
  assert.equal(stored!.state, "st_1");
  assert.equal(stored!.code_challenge, "challenge_abc");
  assert.equal(stored!.code_challenge_method, "S256");
  assert.ok(stored!.expires_at > Date.now());
  assert.ok(stored!.csrf_hash.length >= 32);
});

test("POST approve consumes snapshot and ignores altered params", async () => {
  const store = new MemoryStore();
  await seedClient(store);
  const page = await handleAuthorize(new Request(authzUrl()), store, ISSUER, { principal: PRINCIPAL });
  const { tx, csrf } = parseConsentForm(await page.text());

  const res = await handleAuthorize(
    postDecision(
      { transaction_id: tx, csrf_token: csrf, decision: "approve" },
      // Attacker tries to swap redirect/scope/challenge/client on POST:
      {
        redirect_uri: "https://evil.example/cb",
        scope: "ownmesh.exec",
        code_challenge: "swapped_challenge",
        client_id: "evil_client",
        state: "hijacked",
      },
    ),
    store,
    ISSUER,
    { principal: PRINCIPAL },
  );
  assert.equal(res.status, 302);
  const loc = new URL(res.headers.get("location")!);
  assert.equal(loc.origin + loc.pathname, REDIRECT);
  assert.equal(loc.searchParams.get("state"), "st_1"); // snapshot state, not hijacked
  const code = loc.searchParams.get("code");
  assert.ok(code?.startsWith("ac_"));

  const authCode = store.authCodes.get(code!);
  assert.ok(authCode);
  assert.equal(authCode!.redirect_uri, REDIRECT);
  assert.equal(authCode!.scope, "ownmesh.read");
  assert.equal(authCode!.code_challenge, "challenge_abc");
  assert.equal(authCode!.client_id, CLIENT);
  assert.equal(authCode!.principal_id, PRINCIPAL.id);

  // Replay rejected
  const replay = await handleAuthorize(
    postDecision({ transaction_id: tx, csrf_token: csrf, decision: "approve" }),
    store,
    ISSUER,
    { principal: PRINCIPAL },
  );
  assert.equal(replay.status, 400);
});

test("wrong csrf, wrong principal, expired tx all rejected", async () => {
  const store = new MemoryStore();
  await seedClient(store);
  await store.ensurePrincipal(OTHER.id, OTHER.display_name!, "human", OTHER.tenant_id);

  const page = await handleAuthorize(new Request(authzUrl()), store, ISSUER, { principal: PRINCIPAL });
  const { tx, csrf } = parseConsentForm(await page.text());

  const wrongCsrf = await handleAuthorize(
    postDecision({ transaction_id: tx, csrf_token: "csrf_wrong", decision: "approve" }),
    store,
    ISSUER,
    { principal: PRINCIPAL },
  );
  assert.equal(wrongCsrf.status, 400);

  const wrongPrincipal = await handleAuthorize(
    postDecision({ transaction_id: tx, csrf_token: csrf, decision: "approve" }),
    store,
    ISSUER,
    { principal: OTHER },
  );
  assert.equal(wrongPrincipal.status, 400);

  // Expire the stored tx
  const stored = store.authorizeTransactions.get(tx)!;
  stored.expires_at = Date.now() - 1;
  store.authorizeTransactions.set(tx, stored);
  const expired = await handleAuthorize(
    postDecision({ transaction_id: tx, csrf_token: csrf, decision: "approve" }),
    store,
    ISSUER,
    { principal: PRINCIPAL },
  );
  assert.equal(expired.status, 400);
  assert.equal(store.authCodes.size, 0);
});

test("scope-swap after GET is ignored; code uses GET snapshot only", async () => {
  const store = new MemoryStore();
  await seedClient(store);
  const page = await handleAuthorize(
    new Request(authzUrl({ scope: "ownmesh.read" })),
    store,
    ISSUER,
    { principal: PRINCIPAL },
  );
  const { tx, csrf } = parseConsentForm(await page.text());

  // Mutate nothing in store — attacker only changes POST params (scope swap).
  const res = await handleAuthorize(
    postDecision({
      transaction_id: tx,
      csrf_token: csrf,
      decision: "approve",
      scope: "ownmesh.exec ownmesh.write",
    }),
    store,
    ISSUER,
    { principal: PRINCIPAL },
  );
  assert.equal(res.status, 302);
  const code = new URL(res.headers.get("location")!).searchParams.get("code")!;
  assert.equal(store.authCodes.get(code)!.scope, "ownmesh.read");
});

test("deny consumes tx and redirects access_denied from snapshot", async () => {
  const store = new MemoryStore();
  await seedClient(store);
  const page = await handleAuthorize(new Request(authzUrl()), store, ISSUER, { principal: PRINCIPAL });
  const { tx, csrf } = parseConsentForm(await page.text());
  const deny = await handleAuthorize(
    postDecision({ transaction_id: tx, csrf_token: csrf, decision: "deny" }),
    store,
    ISSUER,
    { principal: PRINCIPAL },
  );
  assert.equal(deny.status, 302);
  const loc = new URL(deny.headers.get("location")!);
  assert.equal(loc.searchParams.get("error"), "access_denied");
  assert.equal(loc.searchParams.get("state"), "st_1");
  assert.equal(store.authorizeTransactions.get(tx)!.consumed, true);
  // Replay after deny also fails
  const replay = await handleAuthorize(
    postDecision({ transaction_id: tx, csrf_token: csrf, decision: "approve" }),
    store,
    ISSUER,
    { principal: PRINCIPAL },
  );
  assert.equal(replay.status, 400);
});

test("dev auto-approve path (auto=1 + allowDevBypass) still works", async () => {
  const store = new MemoryStore();
  await seedClient(store);
  const res = await handleAuthorize(
    new Request(authzUrl({ auto: "1" })),
    store,
    ISSUER,
    { allowDevBypass: true },
  );
  assert.equal(res.status, 302);
  assert.ok(new URL(res.headers.get("location")!).searchParams.get("code")?.startsWith("ac_"));
  // auto without bypass shows consent (no code)
  const noBypass = await handleAuthorize(
    new Request(authzUrl({ auto: "1" })),
    store,
    ISSUER,
    { principal: PRINCIPAL },
  );
  assert.equal(noBypass.status, 200);
  assert.equal(noBypass.headers.get("location"), null);
});

test("consent + PKCE exchange end-to-end", async () => {
  const store = new MemoryStore();
  await seedClient(store);
  const verifier = "0123456789012345678901234567890123456789013";
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(digest);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const challenge = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  assert.equal(await verifyPkceS256(verifier, challenge), true);

  const page = await handleAuthorize(
    new Request(authzUrl({ code_challenge: challenge, scope: "ownmesh.read offline_access" })),
    store,
    ISSUER,
    { principal: PRINCIPAL },
  );
  const { tx, csrf } = parseConsentForm(await page.text());
  const approved = await handleAuthorize(
    postDecision({ transaction_id: tx, csrf_token: csrf, decision: "approve" }),
    store,
    ISSUER,
    { principal: PRINCIPAL },
  );
  const code = new URL(approved.headers.get("location")!).searchParams.get("code")!;
  const tokRes = await handleToken(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT,
        client_id: CLIENT,
        code_verifier: verifier,
      }),
    }),
    store,
  );
  assert.equal(tokRes.status, 200);
});

test("SqlStore put/consume is CAS one-time (UPDATE RETURNING)", async () => {
  const { store } = openSqliteStore();
  await store.ensureBootstrap();
  const csrf = "csrf_sql_test_token";
  const tx: AuthorizeTransaction = {
    id: "atz_sql_1",
    csrf_hash: await sha256Hex(csrf),
    principal_id: "prin_dev",
    tenant_id: "ten_default",
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    scope: "ownmesh.read",
    state: "s",
    code_challenge: "ch",
    code_challenge_method: "S256",
    expires_at: Date.now() + 60_000,
    consumed: false,
  };
  await store.putAuthorizeTransaction(tx);

  const [a, b] = await Promise.all([
    store.consumeAuthorizeTransaction(tx.id, tx.csrf_hash, "prin_dev"),
    store.consumeAuthorizeTransaction(tx.id, tx.csrf_hash, "prin_dev"),
  ]);
  const wins = [a, b].filter(Boolean);
  assert.equal(wins.length, 1);
  assert.equal(wins[0]!.scope, "ownmesh.read");
  assert.equal(wins[0]!.redirect_uri, REDIRECT);
  assert.equal(await store.consumeAuthorizeTransaction(tx.id, tx.csrf_hash, "prin_dev"), null);
});

test("SqlStore authorize consent GET→POST round-trip", async () => {
  const { store } = openSqliteStore();
  await seedClient(store);
  const page = await handleAuthorize(new Request(authzUrl()), store, ISSUER, { principal: PRINCIPAL });
  const { tx, csrf } = parseConsentForm(await page.text());
  const res = await handleAuthorize(
    postDecision(
      { transaction_id: tx, csrf_token: csrf, decision: "approve" },
      { scope: "ownmesh.exec", redirect_uri: "https://evil.example/x" },
    ),
    store,
    ISSUER,
    { principal: PRINCIPAL },
  );
  assert.equal(res.status, 302);
  const loc = new URL(res.headers.get("location")!);
  assert.ok(loc.href.startsWith(REDIRECT));
  assert.ok(loc.searchParams.get("code"));
  // Concurrent-style second consume fails
  assert.equal(
    (
      await handleAuthorize(
        postDecision({ transaction_id: tx, csrf_token: csrf, decision: "approve" }),
        store,
        ISSUER,
        { principal: PRINCIPAL },
      )
    ).status,
    400,
  );
});
