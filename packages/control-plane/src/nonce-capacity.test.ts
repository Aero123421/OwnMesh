/**
 * Nonce replay-map capacity: reject new nonces when full; never evict live entries.
 * Calls production helpers directly (rememberNonceInMap / pruneNonceExpMap).
 */
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  INTERNAL_CONTEXT_REPLAY_MAX,
  pruneNonceExpMap,
  rememberNonceInMap,
} from "./util.ts";

describe("nonce capacity — no live-entry eviction", () => {
  test("rememberNonceInMap rejects new nonce when full after expired prune; keeps all live entries", () => {
    const max = 4;
    const now = 1_000_000;
    const seen = new Map<string, number>();

    // Fill to capacity with live nonces.
    for (let i = 0; i < max; i++) {
      const ok = rememberNonceInMap(seen, `live_${i}`, now + 60_000, now, max);
      assert.equal(ok, true, `seed live_${i}`);
    }
    assert.equal(seen.size, max);

    const snapshot = new Map(seen);

    // At capacity: new nonce must be refused (no FIFO eviction of live entries).
    const accepted = rememberNonceInMap(seen, "new_at_cap", now + 60_000, now, max);
    assert.equal(accepted, false, "must reject when at capacity");
    assert.equal(seen.size, max, "size unchanged on capacity reject");
    assert.equal(seen.has("new_at_cap"), false);

    // Every previously live entry must still be present with the same exp.
    for (const [nonce, exp] of snapshot) {
      assert.equal(seen.has(nonce), true, `live entry retained: ${nonce}`);
      assert.equal(seen.get(nonce), exp, `exp unchanged: ${nonce}`);
    }

    // Replay of an existing live nonce still rejected.
    assert.equal(
      rememberNonceInMap(seen, "live_0", now + 60_000, now, max),
      false,
      "duplicate live nonce still rejected",
    );
    assert.equal(seen.size, max);
  });

  test("rememberNonceInMap accepts after expired entries free capacity (no live eviction)", () => {
    const max = 3;
    const now = 2_000_000;
    const seen = new Map<string, number>();

    assert.equal(rememberNonceInMap(seen, "exp_a", now + 100, now, max), true);
    assert.equal(rememberNonceInMap(seen, "exp_b", now + 200, now, max), true);
    assert.equal(rememberNonceInMap(seen, "live_c", now + 10_000, now, max), true);
    assert.equal(seen.size, max);

    // Still full before expiry window advances.
    assert.equal(rememberNonceInMap(seen, "new_blocked", now + 10_000, now, max), false);
    assert.equal(seen.has("live_c"), true);

    // After exp_a/exp_b expire, capacity frees via TTL prune only; live_c stays.
    const later = now + 500;
    assert.equal(rememberNonceInMap(seen, "new_ok", later + 10_000, later, max), true);
    assert.equal(seen.has("exp_a"), false);
    assert.equal(seen.has("exp_b"), false);
    assert.equal(seen.has("live_c"), true, "unexpired entry never evicted");
    assert.equal(seen.has("new_ok"), true);
    assert.equal(seen.size, 2);
  });

  test("pruneNonceExpMap removes only expired entries; never deletes live for capacity", () => {
    const max = 2;
    const now = 3_000_000;
    const seen = new Map<string, number>([
      ["expired_1", now - 1],
      ["live_1", now + 5_000],
      ["live_2", now + 6_000],
      ["live_3", now + 7_000], // over max intentionally
    ]);

    pruneNonceExpMap(seen, now, max);

    assert.equal(seen.has("expired_1"), false, "expired pruned");
    assert.equal(seen.has("live_1"), true);
    assert.equal(seen.has("live_2"), true);
    assert.equal(seen.has("live_3"), true, "over-cap live entries are NOT FIFO-evicted");
    assert.equal(seen.size, 3, "capacity excess left intact for caller reject path");
  });

  test("default INTERNAL_CONTEXT_REPLAY_MAX capacity reject without touching live set", () => {
    const now = 4_000_000;
    const seen = new Map<string, number>();
    const cap = 8; // smaller stand-in; production default is INTERNAL_CONTEXT_REPLAY_MAX

    for (let i = 0; i < cap; i++) {
      assert.equal(rememberNonceInMap(seen, `n_${i}`, now + 30_000, now, cap), true);
    }
    const keysBefore = [...seen.keys()];
    assert.equal(rememberNonceInMap(seen, "overflow", now + 30_000, now, cap), false);
    assert.deepEqual([...seen.keys()], keysBefore);
    assert.equal(typeof INTERNAL_CONTEXT_REPLAY_MAX, "number");
    assert.ok(INTERNAL_CONTEXT_REPLAY_MAX >= 1);
  });
});
