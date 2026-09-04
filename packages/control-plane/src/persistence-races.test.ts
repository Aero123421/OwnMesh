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

test("SQL auth code CAS permits exactly one concurrent valid redemption", async () => {
  const { store: s, db } = openStore(); await s.ensureBootstrap();
  await s.putAuthCode({ code: "code", client_id: "client_ownmesh_cli", principal_id: "prin_dev", redirect_uri: "http://localhost/cb", scope: "ownmesh.read", code_challenge: "challenge", code_challenge_method: "S256", expires_at: Date.now() + 60_000, used: false });
  const input = { code: "code", clientId: "client_ownmesh_cli", redirectUri: "http://localhost/cb", codeChallenge: "challenge" };
  const results = await Promise.all([s.redeemAuthCode(input), s.redeemAuthCode(input)]);
  assert.equal(results.filter((result) => result.status === "redeemed").length, 1);
  assert.equal(results.filter((result) => result.status === "invalid_grant").length, 1);
  const tokenCount = db.prepare(
    `SELECT COUNT(*) AS n FROM oauth_tokens WHERE auth_code_hash IS NOT NULL`,
  ).get() as { n: number };
  assert.equal(Number(tokenCount.n), 1);
});



test("SQL token persistence failure rolls back authorization-code consumption", async () => {
  const { store: s, db } = openStore();
  await s.ensureBootstrap();
  await s.putAuthCode({
    code: "code_storage_retry",
    client_id: "client_ownmesh_cli",
    principal_id: "prin_dev",
    redirect_uri: "http://localhost/cb",
    scope: "ownmesh.read",
    code_challenge: "challenge",
    code_challenge_method: "S256",
    expires_at: Date.now() + 60_000,
    used: false,
  });
  db.exec(`CREATE TRIGGER fail_auth_code_token_insert
    BEFORE INSERT ON oauth_tokens
    WHEN NEW.auth_code_hash IS NOT NULL
    BEGIN SELECT RAISE(ABORT, 'injected token persistence failure'); END;`);
  const input = {
    code: "code_storage_retry",
    clientId: "client_ownmesh_cli",
    redirectUri: "http://localhost/cb",
    codeChallenge: "challenge",
  };
  await assert.rejects(() => s.redeemAuthCode(input), /token persistence failure/);
  const hash = await sha256Hex(input.code);
  const afterFailure = db.prepare(
    `SELECT used FROM oauth_auth_codes WHERE code_hash = ?`,
  ).get(hash) as { used: number };
  assert.equal(Number(afterFailure.used), 0);
  assert.equal(Number((db.prepare(
    `SELECT COUNT(*) AS n FROM oauth_tokens WHERE auth_code_hash = ?`,
  ).get(hash) as { n: number }).n), 0);

  db.exec("DROP TRIGGER fail_auth_code_token_insert");
  const retry = await s.redeemAuthCode(input);
  assert.equal(retry.status, "redeemed");
});

test("SQL auth code binding mismatch does not consume the code", async () => {
  const s = store(); await s.ensureBootstrap();
  await s.putAuthCode({ code: "code_retry", client_id: "client_ownmesh_cli", principal_id: "prin_dev", redirect_uri: "http://localhost/cb", scope: "ownmesh.read", code_challenge: "challenge", code_challenge_method: "S256", expires_at: Date.now() + 60_000, used: false });
  const wrong = await s.redeemAuthCode({ code: "code_retry", clientId: "wrong", redirectUri: "http://localhost/cb", codeChallenge: "challenge" });
  assert.equal(wrong.status, "invalid_grant");
  const correct = await s.redeemAuthCode({ code: "code_retry", clientId: "client_ownmesh_cli", redirectUri: "http://localhost/cb", codeChallenge: "challenge" });
  assert.equal(correct.status, "redeemed");
});

test("SQL refresh CAS converges duplicate rotations to the same successor token set", async () => {
  const s = store(); await s.ensureBootstrap();
  const initial = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read");
  const results = await Promise.all([s.rotateRefresh(initial.refresh_token), s.rotateRefresh(initial.refresh_token)]);
  assert.equal(results.every((r) => r.ok), true, "both duplicate rotations converge");
  const [a, b] = results;
  if (!a?.ok || !b?.ok) return;
  assert.equal(a.token.access_token, b.token.access_token);
  assert.equal(a.token.refresh_token, b.token.refresh_token);
  assert.notEqual(await s.getAccess(a.token.access_token), null);

  // Response-loss retry within the receipt TTL returns the same token set.
  const replay = await s.rotateRefresh(initial.refresh_token);
  assert.equal(replay.ok, true);
  if (replay.ok) assert.equal(replay.token.access_token, a.token.access_token);

  // After the family advances, replaying the original refresh is real reuse.
  const advanced = await s.rotateRefresh(a.token.refresh_token);
  assert.equal(advanced.ok, true);
  if (!advanced.ok) return;
  const reuse = await s.rotateRefresh(initial.refresh_token);
  assert.equal(reuse.ok, false);
  if (!reuse.ok) assert.equal(reuse.error, "reuse");
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
    user_code: "BCDF-GHJK",
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
    user_code: "WXZV-STPQ",
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
    user_code: "WXZV-STPQ",
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
  assert.equal(winner.user_code, "WXZV-STPQ");
  const dc = await s.getDeviceCode("dcode_vtx");
  assert.equal(dc?.status, "approved");
  assert.equal(dc?.principal_id, "prin_dev");
});

test("SQL device verification transaction records an explicit denial", async () => {
  const s = store(); await s.ensureBootstrap();
  await s.putDeviceCode({
    device_code: "dcode_denied",
    user_code: "DNCZ-DFGH",
    client_id: "client_ownmesh_cli",
    scope: "ownmesh.read",
    verification_uri: "https://cp.test/oauth/device",
    interval_sec: 5,
    expires_at: Date.now() + 60_000,
    status: "pending",
  });
  await s.putDeviceVerificationTransaction({
    id: "vtx_denied",
    csrf_hash: "csrf_hash_denied",
    user_code: "DNCZ-DFGH",
    principal_id: "prin_dev",
    client_id: "client_ownmesh_cli",
    scope: "ownmesh.read",
    expires_at: Date.now() + 60_000,
    consumed: false,
  });
  const tx = await s.consumeDeviceVerificationTransaction(
    "vtx_denied",
    "csrf_hash_denied",
    "prin_dev",
    "deny",
  );
  assert.equal(tx?.consumed, true);
  assert.equal((await s.getDeviceCode("dcode_denied"))?.status, "denied");
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

test("SQL expired refresh is invalid_grant and never reuse", async () => {
  const { store: s, db } = openStore(); await s.ensureBootstrap();
  const initial = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read offline_access");
  const hash = await sha256Hex(initial.refresh_token);
  db.prepare(`UPDATE oauth_tokens SET refresh_expires_at = ? WHERE refresh_token_hash = ?`).run(
    new Date(Date.now() - 1_000).toISOString(),
    hash,
  );
  const expired = await s.rotateRefresh(initial.refresh_token);
  assert.equal(expired.ok, false);
  if (!expired.ok) assert.equal(expired.error, "invalid_grant");

  // Rotate a live token, expire the used row, replay → still invalid_grant (not reuse).
  const live = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read offline_access");
  const rotated = await s.rotateRefresh(live.refresh_token);
  assert.equal(rotated.ok, true);
  const usedHash = await sha256Hex(live.refresh_token);
  db.prepare(`UPDATE oauth_tokens SET refresh_expires_at = ? WHERE refresh_token_hash = ?`).run(
    new Date(Date.now() - 1_000).toISOString(),
    usedHash,
  );
  const replay = await s.rotateRefresh(live.refresh_token);
  assert.equal(replay.ok, false);
  if (!replay.ok) assert.equal(replay.error, "invalid_grant");
});

test("SQL refresh rotation batch is atomic: duplicate retries converge and only one successor is persisted", async () => {
  const { store: s, db } = openStore(); await s.ensureBootstrap();
  const initial = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read offline_access");
  const [a, b] = await Promise.all([
    s.rotateRefresh(initial.refresh_token),
    s.rotateRefresh(initial.refresh_token),
  ]);
  assert.equal(a.ok && b.ok, true, "both duplicate rotations converge");
  if (!a.ok || !b.ok) return;
  assert.equal(a.token.access_token, b.token.access_token);
  assert.equal(a.token.refresh_token, b.token.refresh_token);
  const familyRows = db.prepare(
    `SELECT COUNT(*) AS total,
            SUM(CASE WHEN refresh_token_hash <> ? THEN 1 ELSE 0 END) AS successors
     FROM oauth_tokens WHERE refresh_family = ?`,
  ).get(await sha256Hex(initial.refresh_token), initial.refresh_family) as {
    total: number;
    successors: number;
  };
  assert.equal(Number(familyRows.total), 2, "old token plus exactly one successor");
  assert.equal(Number(familyRows.successors), 1, "CAS loser must not insert a second successor");
  assert.notEqual(await s.getAccess(a.token.access_token), null);

  // Response-loss retry within the receipt TTL returns the same token set.
  const replay = await s.rotateRefresh(initial.refresh_token);
  assert.equal(replay.ok, true);
  if (replay.ok) assert.equal(replay.token.access_token, a.token.access_token);

  // After the family advances, replaying the original refresh is real reuse.
  const advanced = await s.rotateRefresh(a.token.refresh_token);
  assert.equal(advanced.ok, true);
  if (!advanced.ok) return;
  const reuse = await s.rotateRefresh(initial.refresh_token);
  assert.equal(reuse.ok, false);
  if (!reuse.ok) assert.equal(reuse.error, "reuse");
});
