import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { SqlStore, type SqlDatabase, type SqlStatement } from "./store.ts";
import { sha256Hex } from "./util.ts";

function openStore(): { store: SqlStore; db: DatabaseSync } {
  const db = new DatabaseSync(":memory:");
  const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "migrations");
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".sql")).sort()) db.exec(readFileSync(join(dir, file), "utf8"));
  type V = null | number | string | bigint | Uint8Array;
  let batchTail: Promise<void> = Promise.resolve();
  const adapter: SqlDatabase = { prepare(query: string): SqlStatement {
    const statement = db.prepare(query); let values: V[] = [];
    const api: SqlStatement = {
      bind(...input: unknown[]) { values = input.map((v) => v === undefined ? null : v as V); return api; },
      async first<T>(column?: string) { const row = statement.get(...values) as Record<string, unknown> | undefined; return row ? (column ? row[column] as T : row as T) : null; },
      async run() {
        const info = statement.run(...values) as { changes: number };
        return { success: true, meta: { changes: info.changes } };
      },
      async all<T>() { return { results: statement.all(...values) as T[] }; },
    }; return api;
  }, async batch<T>(statements: SqlStatement[]): Promise<T[]> {
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
    batchTail = result.then(() => undefined, () => undefined);
    return result;
  }};
  return { store: new SqlStore(adapter, "sqlite"), db };
}

function store(): SqlStore {
  return openStore().store;
}

test("SQL auth code CAS permits exactly one concurrent consumer", async () => {
  const s = store(); await s.ensureBootstrap();
  await s.putAuthCode({ code: "code", client_id: "client_ownmesh_cli", principal_id: "prin_dev", redirect_uri: "http://localhost/cb", scope: "ownmesh.read", code_challenge: "x", code_challenge_method: "S256", expires_at: Date.now() + 60_000, used: false });
  const results = await Promise.all([s.takeAuthCode("code"), s.takeAuthCode("code")]);
  assert.equal(results.filter(Boolean).length, 1);
});

test("SQL refresh CAS permits one rotation and treats the race as reuse", async () => {
  const s = store(); await s.ensureBootstrap();
  const initial = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read");
  const results = await Promise.all([s.rotateRefresh(initial.refresh_token), s.rotateRefresh(initial.refresh_token)]);
  assert.equal(results.filter((r) => r.ok).length, 1);
  assert.equal(results.filter((r) => !r.ok && r.error === "reuse").length, 1);
  const winner = results.find((r) => r.ok);
  const loser = results.find((r) => !r.ok);
  // Winner returned ok; loser's family revocation then invalidates the successor.
  if (winner?.ok) assert.equal(await s.getAccess(winner.token.access_token), null);
  assert.ok(loser && !loser.ok && loser.error === "reuse");
  // Replaying the original refresh remains reuse (ledger + revoked family).
  const replay = await s.rotateRefresh(initial.refresh_token);
  assert.equal(replay.ok, false);
  if (!replay.ok) assert.equal(replay.error, "reuse");
});

test("SQL refresh rotation never returns an already-revoked successor", async () => {
  const { store: s, db } = openStore();
  await s.ensureBootstrap();
  const initial = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read");
  // Pre-revoke the family only (token row still unused). Successor INSERT marks
  // revoked=1 via CASE WHEN EXISTS(revoked_refresh_families); rotateRefresh must
  // fail closed and must not return that successor as ok.
  db.prepare(
    `INSERT OR IGNORE INTO revoked_refresh_families (refresh_family, detected_at) VALUES (?, ?)`,
  ).run(initial.refresh_family, new Date().toISOString());
  const result = await s.rotateRefresh(initial.refresh_token);
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.error, "reuse");
  // No live access token from this rotation attempt.
  const live = db.prepare(
    `SELECT COUNT(*) AS n FROM oauth_tokens WHERE refresh_family = ? AND revoked = 0`,
  ).get(initial.refresh_family) as { n: number };
  assert.equal(Number(live.n), 0);
});

test("SQL enrollment challenge CAS activates once", async () => {
  const s = store(); await s.ensureBootstrap();
  await s.putDevice({ id: "dev_race", tenant_id: "ten_default", principal_id: "prin_dev", name: "d", hostname: "d", os: "x", arch: "x", agent_version: "x", protocol_version: "ownmesh.device/1.0", public_key: "ab".repeat(32), revoked: false, created_at: new Date().toISOString(), status: "pending" });
  await s.putEnrollmentChallenge({ id: "ch", device_id: "dev_race", nonce: "n", message: "m", expires_at: new Date(Date.now() + 60_000).toISOString(), consumed: false });
  const results = await Promise.all([s.activateDeviceAndIssueCredential("dev_race", "ch"), s.activateDeviceAndIssueCredential("dev_race", "ch")]);
  assert.equal(results.filter(Boolean).length, 1);
  const credential = results.find(Boolean)!;
  assert.ok(await s.getDeviceCredential(credential.token));
  assert.equal((await s.getDevice("dev_race"))?.status, "active");
});

test("SQL approved device code CAS permits exactly one concurrent consumer", async () => {
  const s = store(); await s.ensureBootstrap();
  await s.putDeviceCode({
    device_code: "dcode_race",
    user_code: "ABCD-EFGH",
    client_id: "client_ownmesh_cli",
    scope: "ownmesh.read",
    verification_uri: "https://cp.test/oauth/device",
    interval_sec: 5,
    expires_at: Date.now() + 60_000,
    status: "approved",
    principal_id: "prin_dev",
  });
  const results = await Promise.all([
    s.consumeApprovedDeviceCode("dcode_race", "client_ownmesh_cli"),
    s.consumeApprovedDeviceCode("dcode_race", "client_ownmesh_cli"),
  ]);
  assert.equal(results.filter(Boolean).length, 1);
  assert.equal((await s.getDeviceCode("dcode_race"))?.status, "consumed");
});

test("SQL device verification transaction CAS permits exactly one concurrent consumer", async () => {
  const s = store(); await s.ensureBootstrap();
  await s.putDeviceCode({
    device_code: "dcode_vtx",
    user_code: "WXYZ-UVST",
    client_id: "client_ownmesh_cli",
    scope: "ownmesh.read",
    verification_uri: "https://cp.test/oauth/device",
    interval_sec: 5,
    expires_at: Date.now() + 60_000,
    status: "pending",
  });
  await s.putDeviceVerificationTransaction({
    id: "vtx_race",
    csrf_hash: "csrf_hash_race",
    user_code: "WXYZ-UVST",
    principal_id: "prin_dev",
    client_id: "client_ownmesh_cli",
    scope: "ownmesh.read",
    expires_at: Date.now() + 60_000,
    consumed: false,
  });
  const results = await Promise.all([
    s.consumeDeviceVerificationTransaction("vtx_race", "csrf_hash_race", "prin_dev"),
    s.consumeDeviceVerificationTransaction("vtx_race", "csrf_hash_race", "prin_dev"),
  ]);
  assert.equal(results.filter(Boolean).length, 1);
  const winner = results.find(Boolean)!;
  assert.equal(winner.consumed, true);
  assert.equal(winner.user_code, "WXYZ-UVST");
  const dc = await s.getDeviceCode("dcode_vtx");
  assert.equal(dc?.status, "approved");
  assert.equal(dc?.principal_id, "prin_dev");
});

test("SQL store fails closed when db.batch is absent for atomic device paths", async () => {
  const db = new DatabaseSync(":memory:");
  const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "migrations");
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".sql")).sort()) {
    db.exec(readFileSync(join(dir, file), "utf8"));
  }
  type V = null | number | string | bigint | Uint8Array;
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
    // intentionally no batch
  };
  const s = new SqlStore(adapter, "sqlite");
  await s.ensureBootstrap();
  await assert.rejects(
    () => s.activateDeviceAndIssueCredential("dev_x", "ch_x"),
    /requires db\.batch/,
  );
  await assert.rejects(
    () => s.consumeDeviceVerificationTransaction("vtx", "csrf", "prin_dev"),
    /requires db\.batch/,
  );
  // rotateRefresh is also batch-atomic and must fail closed without db.batch.
  const issued = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read");
  await assert.rejects(
    () => s.rotateRefresh(issued.refresh_token),
    /requires db\.batch/,
  );
});

test("SQL refresh rotation batch is atomic: CAS winner only, single successor", async () => {
  const { store: s, db } = openStore(); await s.ensureBootstrap();
  const initial = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read offline_access");
  const [a, b] = await Promise.all([
    s.rotateRefresh(initial.refresh_token),
    s.rotateRefresh(initial.refresh_token),
  ]);
  const oks = [a, b].filter((r) => r.ok);
  const reuses = [a, b].filter((r) => !r.ok && r.error === "reuse");
  assert.equal(oks.length, 1, "exactly one concurrent rotation wins");
  assert.equal(reuses.length, 1, "loser observes reuse");
  const familyRows = db.prepare(
    `SELECT COUNT(*) AS total,
            SUM(CASE WHEN refresh_token_hash <> ? THEN 1 ELSE 0 END) AS successors
     FROM oauth_tokens WHERE refresh_family = ?`,
  ).get(await sha256Hex(initial.refresh_token), initial.refresh_family) as {
    total: number;
    successors: number;
  };
  assert.equal(Number(familyRows.total), 2, "old token plus exactly one successor");
  assert.equal(Number(familyRows.successors), 1, "CAS loser must not insert a successor");
  if (!oks[0]!.ok) return;
  // Winner's plaintext successor was returned only while unrevoked at return time;
  // after loser family-revocation it must not authorize.
  assert.equal(await s.getAccess(oks[0]!.token.access_token), null);
  // Original refresh cannot be rotated again.
  const again = await s.rotateRefresh(initial.refresh_token);
  assert.equal(again.ok, false);
  if (!again.ok) assert.equal(again.error, "reuse");
});
