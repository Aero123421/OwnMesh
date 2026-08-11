/**
 * Invariant: standard provision must NOT include R2 or TURN bindings.
 * Spec §5.1 / checklist §4 / §12 fail-closed.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const wranglerPath = join(here, "..", "wrangler.jsonc");

function stripJsonc(raw: string): string {
  // strip // line comments and /* */ blocks roughly for test parse
  return raw
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "");
}

test("wrangler.jsonc has D1 + DeviceRoom and no R2/TURN bindings", () => {
  const raw = readFileSync(wranglerPath, "utf8");
  const cfg = JSON.parse(stripJsonc(raw)) as Record<string, unknown>;

  assert.equal(cfg.name, "ownmesh-control-plane");
  assert.equal(cfg.main, "src/index.ts");

  const d1 = cfg.d1_databases as { binding: string; database_name: string; migrations_dir: string }[];
  assert.ok(Array.isArray(d1) && d1.length >= 1);
  assert.equal(d1[0]!.binding, "DB");
  assert.equal(d1[0]!.database_name, "ownmesh");
  assert.equal(d1[0]!.migrations_dir, "migrations");
  assert.equal((d1[0] as { database_id?: string }).database_id, undefined);
  assert.equal(raw.includes("namaste114"), false);

  const dob = cfg.durable_objects as { bindings: { name: string; class_name: string }[] };
  assert.ok(dob.bindings.some((b) => b.name === "DEVICE_ROOM" && b.class_name === "DeviceRoom"));

  // Forbidden bindings / keys (structural — comments may mention them as denylist)
  assert.equal(cfg.r2_buckets, undefined);
  assert.equal(cfg.turn, undefined);
  assert.equal((cfg as { turn_servers?: unknown }).turn_servers, undefined);
  assert.equal((cfg as { services?: unknown }).services, undefined);

  const bindingNames = new Set<string>();
  for (const b of d1) bindingNames.add(b.binding);
  for (const b of dob.bindings) bindingNames.add(b.name);
  // No R2/TURN-style binding names present
  for (const name of bindingNames) {
    assert.equal(/r2|turn/i.test(name), false, `forbidden binding name: ${name}`);
  }
  // Top-level keys must not include r2/turn provision
  for (const key of Object.keys(cfg)) {
    assert.equal(/r2|turn/i.test(key), false, `forbidden wrangler key: ${key}`);
  }

  // Positive: migrations tag present
  const migrations = cfg.migrations as { tag: string; new_classes?: string[]; new_sqlite_classes?: string[] }[];
  assert.ok(migrations?.some((m) => m.tag === "v1"));
  const v1 = migrations.find((m) => m.tag === "v1")!;
  const classes = [...(v1.new_classes || []), ...(v1.new_sqlite_classes || [])];
  assert.ok(classes.includes("DeviceRoom"));

  const rateLimits = cfg.ratelimits as {
    name: string;
    namespace_id: string;
    simple: { limit: number; period: number };
  }[];
  assert.deepEqual(
    rateLimits.map((entry) => entry.name).sort(),
    ["AUTH_RATE_LIMITER", "MCP_RATE_LIMITER"],
  );
  assert.ok(rateLimits.every((entry) => entry.simple.period === 60));
});
