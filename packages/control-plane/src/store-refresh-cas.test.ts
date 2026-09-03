/** rotateRefresh lifetime enforcement + CAS winner-only successor (Memory + SQL). */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { MemoryStore, SqlStore, type SqlDatabase, type SqlStatement } from "./store.ts";
import { sha256Hex } from "./util.ts";

function openSql(): { store: SqlStore; db: DatabaseSync } {
  const db = new DatabaseSync(":memory:");
  const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "migrations");
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".sql")).sort()) {
    db.exec(readFileSync(join(dir, file), "utf8"));
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
  return { store: new SqlStore(adapter, "sqlite"), db };
}

test("Memory rotateRefresh: expired refresh is invalid_grant", async () => {
  const s = new MemoryStore();
  await s.ensureBootstrap();
  await s.putClient({
    client_id: "client_ownmesh_cli",
    tenant_id: "ten_default",
    client_name: "CLI",
    redirect_uris: ["http://localhost/cb"],
    created_at: new Date().toISOString(),
  });
  const tok = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read");
  // Force expiry on the issued row.
  const access = [...s.tokensByAccess.values()].find((t) => t.refresh_token === tok.refresh_token)!;
  access.refresh_expires_at = Date.now() - 1;
  s.tokensByAccess.set(access.access_token, access);

  const result = await s.rotateRefresh(tok.refresh_token);
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.error, "invalid_grant");
});

test("Memory rotateRefresh: expired access still rotates a live refresh token", async () => {
  const s = new MemoryStore();
  await s.ensureBootstrap();
  const tok = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read offline_access");
  const row = s.tokensByAccess.get(tok.access_token)!;
  row.expires_at = Date.now() - 1;
  row.refresh_expires_at = Date.now() + 60_000;

  const result = await s.rotateRefresh(tok.refresh_token);
  assert.equal(result.ok, true);
  if (result.ok) assert.ok(result.token.refresh_expires_at > row.refresh_expires_at);
});

test("Memory rotateRefresh: duplicate converges and real reuse still revokes family", async () => {
  const s = new MemoryStore();
  await s.ensureBootstrap();
  await s.putClient({
    client_id: "client_ownmesh_cli",
    tenant_id: "ten_default",
    client_name: "CLI",
    redirect_uris: ["http://localhost/cb"],
    created_at: new Date().toISOString(),
  });
  const tok = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read offline_access");
  const rotated = await s.rotateRefresh(tok.refresh_token);
  assert.equal(rotated.ok, true);
  if (!rotated.ok) return;

  // Duplicate retry within the receipt TTL converges to the same successor.
  const dup = await s.rotateRefresh(tok.refresh_token);
  assert.equal(dup.ok, true);
  if (dup.ok) {
    assert.equal(dup.token.access_token, rotated.token.access_token);
    assert.equal(dup.token.refresh_token, rotated.token.refresh_token);
  }

  // After the family advances, replaying the original refresh is real reuse.
  const advanced = await s.rotateRefresh(rotated.token.refresh_token);
  assert.equal(advanced.ok, true);
  if (!advanced.ok) return;
  const reuse = await s.rotateRefresh(tok.refresh_token);
  assert.equal(reuse.ok, false);
  if (!reuse.ok) assert.equal(reuse.error, "reuse");
});

test("Memory rotateRefresh: expired used refresh is invalid_grant not reuse", async () => {
  const s = new MemoryStore();
  await s.ensureBootstrap();
  await s.putClient({
    client_id: "client_ownmesh_cli",
    tenant_id: "ten_default",
    client_name: "CLI",
    redirect_uris: ["http://localhost/cb"],
    created_at: new Date().toISOString(),
  });
  const tok = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read offline_access");
  const rotated = await s.rotateRefresh(tok.refresh_token);
  assert.equal(rotated.ok, true);

  // Expire the prior (used) record, then present the old refresh again.
  const prior = [...s.tokensByAccess.values()].find((t) => t.refresh_token === tok.refresh_token)!;
  prior.refresh_expires_at = Date.now() - 1;
  s.tokensByAccess.set(prior.access_token, prior);

  const again = await s.rotateRefresh(tok.refresh_token);
  assert.equal(again.ok, false);
  if (!again.ok) assert.equal(again.error, "invalid_grant");
});

test("SQL rotateRefresh: expired refresh is invalid_grant", async () => {
  const { store: s, db } = openSql();
  await s.ensureBootstrap();
  const tok = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read offline_access");
  const hash = await sha256Hex(tok.refresh_token);
  db.prepare(`UPDATE oauth_tokens SET refresh_expires_at = ? WHERE refresh_token_hash = ?`).run(
    new Date(Date.now() - 60_000).toISOString(),
    hash,
  );
  const result = await s.rotateRefresh(tok.refresh_token);
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.error, "invalid_grant");
});

test("SQL rotateRefresh: expired access still rotates a live refresh token", async () => {
  const { store: s, db } = openSql();
  await s.ensureBootstrap();
  const tok = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read offline_access");
  const hash = await sha256Hex(tok.refresh_token);
  const shortRefreshDeadline = Date.now() + 60_000;
  db.prepare(
    `UPDATE oauth_tokens SET expires_at = ?, refresh_expires_at = ? WHERE refresh_token_hash = ?`,
  ).run(
    new Date(Date.now() - 60_000).toISOString(),
    new Date(shortRefreshDeadline).toISOString(),
    hash,
  );

  const result = await s.rotateRefresh(tok.refresh_token);
  assert.equal(result.ok, true);
  if (result.ok) assert.ok(result.token.refresh_expires_at > shortRefreshDeadline);
});

test("SQL rotateRefresh: duplicate rotations converge to one successor", async () => {
  const { store: s, db } = openSql();
  await s.ensureBootstrap();
  const initial = await s.issueTokens(
    "client_ownmesh_cli",
    "prin_dev",
    "ownmesh.read offline_access",
  );
  const results = await Promise.all([
    s.rotateRefresh(initial.refresh_token),
    s.rotateRefresh(initial.refresh_token),
  ]);
  assert.equal(results.every((r) => r.ok), true, "both duplicate rotations converge");
  const [a, b] = results;
  if (!a?.ok || !b?.ok) return;
  assert.equal(a.token.access_token, b.token.access_token);
  assert.equal(a.token.refresh_token, b.token.refresh_token);

  const familyRows = db
    .prepare(
      `SELECT COUNT(*) AS total,
              SUM(CASE WHEN refresh_token_hash <> ? THEN 1 ELSE 0 END) AS successors
       FROM oauth_tokens WHERE refresh_family = ?`,
    )
    .get(await sha256Hex(initial.refresh_token), initial.refresh_family) as {
    total: number;
    successors: number;
  };
  assert.equal(Number(familyRows.total), 2, "old + exactly one successor");
  assert.equal(Number(familyRows.successors), 1);

  // Response-loss retry within the receipt TTL returns the same token set.
  const replay = await s.rotateRefresh(initial.refresh_token);
  assert.equal(replay.ok, true);
  if (replay.ok) assert.equal(replay.token.access_token, a.token.access_token);
});

test("SQL rotateRefresh: expired used refresh is invalid_grant not reuse", async () => {
  const { store: s, db } = openSql();
  await s.ensureBootstrap();
  const tok = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read offline_access");
  const rotated = await s.rotateRefresh(tok.refresh_token);
  assert.equal(rotated.ok, true);

  const hash = await sha256Hex(tok.refresh_token);
  db.prepare(`UPDATE oauth_tokens SET refresh_expires_at = ? WHERE refresh_token_hash = ?`).run(
    new Date(Date.now() - 60_000).toISOString(),
    hash,
  );

  const again = await s.rotateRefresh(tok.refresh_token);
  assert.equal(again.ok, false);
  if (!again.ok) assert.equal(again.error, "invalid_grant");
});

test("Memory rotateRefresh: revokeToken(refresh) then rotate is invalid_grant, no reuse/family side effects", async () => {
  const s = new MemoryStore();
  await s.ensureBootstrap();
  await s.putClient({
    client_id: "client_ownmesh_cli",
    tenant_id: "ten_default",
    client_name: "CLI",
    redirect_uris: ["http://localhost/cb"],
    created_at: new Date().toISOString(),
  });
  const tok = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read offline_access");
  const family = tok.refresh_family;
  await s.revokeToken(tok.refresh_token);

  const result = await s.rotateRefresh(tok.refresh_token);
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.error, "invalid_grant");

  // No false family compromise from explicit revoke-then-rotate.
  assert.equal(s.compromisedRefreshFamilies.has(family), false);
  const siblings = [...s.tokensByAccess.values()].filter((t) => t.refresh_family === family);
  assert.ok(siblings.length >= 1);
  // The revoked row stays revoked; no extra family-wide cascade from rotateRefresh.
  for (const row of siblings) {
    if (row.refresh_token === tok.refresh_token) {
      assert.equal(row.revoked, true);
    }
  }
});

test("SQL rotateRefresh: revokeToken(refresh) then rotate is invalid_grant, no reuse/family side effects", async () => {
  const { store: s, db } = openSql();
  await s.ensureBootstrap();
  const tok = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read offline_access");
  const family = tok.refresh_family;
  const hash = await sha256Hex(tok.refresh_token);

  await s.revokeToken(tok.refresh_token);

  // Row is explicitly revoked but unused (no ledger, refresh_used=0).
  const pre = db
    .prepare(
      `SELECT revoked, refresh_used FROM oauth_tokens WHERE refresh_token_hash = ?`,
    )
    .get(hash) as { revoked: number; refresh_used: number };
  assert.equal(Number(pre.revoked), 1);
  assert.equal(Number(pre.refresh_used), 0);
  const ledgerPre = db
    .prepare(`SELECT 1 AS hit FROM used_refresh_tokens WHERE refresh_token_hash = ?`)
    .get(hash);
  assert.equal(ledgerPre, undefined);

  const result = await s.rotateRefresh(tok.refresh_token);
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.error, "invalid_grant");

  // No false reuse side effects: family not marked compromised, no ledger insert.
  const famRevoked = db
    .prepare(`SELECT 1 AS hit FROM revoked_refresh_families WHERE refresh_family = ?`)
    .get(family);
  assert.equal(famRevoked, undefined);
  const ledgerPost = db
    .prepare(`SELECT 1 AS hit FROM used_refresh_tokens WHERE refresh_token_hash = ?`)
    .get(hash);
  assert.equal(ledgerPost, undefined);
  const post = db
    .prepare(
      `SELECT revoked, refresh_used FROM oauth_tokens WHERE refresh_token_hash = ?`,
    )
    .get(hash) as { revoked: number; refresh_used: number };
  assert.equal(Number(post.revoked), 1);
  assert.equal(Number(post.refresh_used), 0);
});

test("SQL rotateRefresh: real reuse still revokes family after successful rotation", async () => {
  const { store: s, db } = openSql();
  await s.ensureBootstrap();
  const tok = await s.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read offline_access");
  const rotated = await s.rotateRefresh(tok.refresh_token);
  assert.equal(rotated.ok, true);
  if (!rotated.ok) return;

  // Advance the family past the duplicate-retry grace period.
  const advanced = await s.rotateRefresh(rotated.token.refresh_token);
  assert.equal(advanced.ok, true);
  if (!advanced.ok) return;

  // Replaying the original refresh after the family has advanced is real reuse.
  const reuse = await s.rotateRefresh(tok.refresh_token);
  assert.equal(reuse.ok, false);
  if (!reuse.ok) assert.equal(reuse.error, "reuse");

  const fam = db
    .prepare(`SELECT 1 AS hit FROM revoked_refresh_families WHERE refresh_family = ?`)
    .get(tok.refresh_family);
  assert.ok(fam, "family must be revoked on real reuse");
});

test("SQL rotateRefresh source has no cross-statement changes() gate", async () => {
  const src = readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "store.ts"),
    "utf8",
  );
  const classIdx = src.indexOf("export class SqlStore");
  const start = src.indexOf("async rotateRefresh(refreshToken: string)", classIdx);
  const end = src.indexOf("async revokeToken(token: string)", start);
  const body = src.slice(start, end);
  assert.equal(body.includes("changes() > 0"), false);
  assert.ok(body.includes("expires_at >"));
  assert.ok(body.includes("EXISTS ("));
});
