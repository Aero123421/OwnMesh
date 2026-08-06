/**
 * MAX_GUARD_SESSIONS admission + lastSeq integrity + pending payload vs DO state budget.
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  assertRoomStateBounds,
  DeviceRoomRouter,
  MAX_GUARD_SESSIONS,
  MAX_PENDING_PAYLOAD_BYTES,
  MAX_SERIALIZED_STATE_BYTES,
  ROOM_STATE_NON_PAYLOAD_RESERVE_BYTES,
  type PersistedRoomState,
  type SessionAttachment,
} from "./device-room.ts";

function makeAtt(sessionId: string, lastSeq = 0): SessionAttachment {
  return {
    role: "agent",
    device_id: "dev_guard_cap",
    session_id: sessionId,
    connected_at: Date.now(),
    phase: "ready",
    lastSeq,
  };
}

test("invariant: MAX_PENDING_PAYLOAD_BYTES + reserve cannot exceed serialized state max", () => {
  assert.ok(MAX_PENDING_PAYLOAD_BYTES > 0);
  assert.ok(ROOM_STATE_NON_PAYLOAD_RESERVE_BYTES > 0);
  assert.ok(
    MAX_PENDING_PAYLOAD_BYTES + ROOM_STATE_NON_PAYLOAD_RESERVE_BYTES <= MAX_SERIALIZED_STATE_BYTES,
    `pending budget ${MAX_PENDING_PAYLOAD_BYTES} + reserve ${ROOM_STATE_NON_PAYLOAD_RESERVE_BYTES} ` +
      `must fit under serialized cap ${MAX_SERIALIZED_STATE_BYTES}`,
  );
  // Stronger than the historical 2_000_000 payload budget which exceeded the 1 MiB DO state cap.
  assert.ok(MAX_PENDING_PAYLOAD_BYTES < MAX_SERIALIZED_STATE_BYTES);
  assert.ok(MAX_PENDING_PAYLOAD_BYTES <= MAX_SERIALIZED_STATE_BYTES - ROOM_STATE_NON_PAYLOAD_RESERVE_BYTES);
});

test("registering > MAX_GUARD_SESSIONS rejects excess without evicting live guards or rewinding lastSeq", () => {
  const sent: string[] = [];
  const router = new DeviceRoomRouter("dev_guard_cap", {
    sendToSession: () => true,
    sendToRole: () => 0,
    onStateChange: () => {
      sent.push("state");
    },
  });

  // Fill to capacity with live sessions, each with a distinct non-zero lastSeq.
  const liveIds: string[] = [];
  for (let i = 0; i < MAX_GUARD_SESSIONS; i++) {
    const sid = `ags_live_${i}`;
    liveIds.push(sid);
    const ok = router.registerSession(makeAtt(sid, 100 + i));
    assert.equal(ok, true, `admit live #${i}`);
  }
  assert.equal(router.ingressGuards.size, MAX_GUARD_SESSIONS);
  assert.equal(router.sessions.size, MAX_GUARD_SESSIONS);
  assert.equal(router.canAdmitNewGuardSession(), false);

  // Snapshot live lastSeq values before excess attempts.
  const lastSeqBefore = new Map<string, number>();
  for (const sid of liveIds) {
    lastSeqBefore.set(sid, router.ingressGuards.get(sid)!.lastSeq);
  }

  // Excess registrations must be rejected — no close/eviction of live guards.
  for (let i = 0; i < 5; i++) {
    const ok = router.registerSession(makeAtt(`ags_excess_${i}`, 0));
    assert.equal(ok, false, `excess #${i} must be rejected`);
  }

  assert.equal(router.ingressGuards.size, MAX_GUARD_SESSIONS);
  assert.equal(router.sessions.size, MAX_GUARD_SESSIONS);
  for (const sid of liveIds) {
    assert.ok(router.sessions.has(sid), `live session ${sid} must remain`);
    assert.ok(router.ingressGuards.has(sid), `live guard ${sid} must remain`);
    assert.equal(
      router.ingressGuards.get(sid)!.lastSeq,
      lastSeqBefore.get(sid),
      `lastSeq of live ${sid} must not reset/rewind`,
    );
  }

  // export/enforce must not drop live either.
  const snap = router.exportState();
  assert.equal(Object.keys(snap.ingressGuards).length, MAX_GUARD_SESSIONS);
  for (const sid of liveIds) {
    assert.equal(snap.ingressGuards[sid]?.lastSeq, lastSeqBefore.get(sid));
  }
});

test("detached guards may be pruned to admit a new session; live lastSeq untouched", () => {
  const router = new DeviceRoomRouter("dev_guard_detach", {
    sendToSession: () => true,
    sendToRole: () => 0,
  });

  // Seed MAX detached guards via import (no live sessions).
  const guards: PersistedRoomState["ingressGuards"] = {};
  for (let i = 0; i < MAX_GUARD_SESSIONS; i++) {
    guards[`ags_det_${i}`] = { lastSeq: i + 1, seenMessageIds: [] };
  }
  router.importState({ v: 1, seqOut: 0, ingressGuards: guards, pending: [] });
  assert.equal(router.ingressGuards.size, MAX_GUARD_SESSIONS);
  assert.equal(router.sessions.size, 0);
  assert.equal(router.canAdmitNewGuardSession(), true);

  // Attach one live session on a restored guard — must keep higher lastSeq.
  const keepId = "ags_det_50";
  assert.equal(router.ingressGuards.get(keepId)!.lastSeq, 51);
  assert.equal(router.registerSession(makeAtt(keepId, 3)), true);
  assert.equal(router.ingressGuards.get(keepId)!.lastSeq, 51, "must not rewind on reattach");
  assert.ok(router.sessions.has(keepId));

  // New session_id at cap: prunes a *detached* guard, never the live one.
  assert.equal(router.registerSession(makeAtt("ags_brand_new", 0)), true);
  assert.ok(router.sessions.has(keepId));
  assert.equal(router.ingressGuards.get(keepId)!.lastSeq, 51);
  assert.ok(router.ingressGuards.has("ags_brand_new"));
  assert.ok(router.ingressGuards.size <= MAX_GUARD_SESSIONS);
});

test("http inject auto-registration rejects at guard cap without touching live lastSeq", () => {
  const router = new DeviceRoomRouter("dev_guard_inject", {
    sendToSession: () => true,
    sendToRole: () => 0,
  });

  // One ready agent occupying a live slot + fill remaining with live clients.
  assert.equal(router.registerSession(makeAtt("ags_agent0", 42)), true);
  for (let i = 1; i < MAX_GUARD_SESSIONS; i++) {
    assert.equal(
      router.registerSession({
        role: "client",
        device_id: "dev_guard_inject",
        session_id: `cls_${i}`,
        connected_at: Date.now(),
        phase: "connected",
        lastSeq: 10 + i,
      }),
      true,
    );
  }
  const agentSeq = router.ingressGuards.get("ags_agent0")!.lastSeq;
  assert.equal(agentSeq, 42);

  // Default from_session "http_client" needs a new guard — must reject at cap.
  const r = router.injectOperation({
    type: "ownmesh_fs_list",
    payload: { path: "/" },
    correlation_id: "corr_guard_reject",
  });
  assert.equal(r.status, "rejected");
  assert.equal((r.detail as { code: string }).code, "OWNMESH_E_GUARD_SESSION_LIMIT");
  assert.equal(router.pending.has("corr_guard_reject"), false);
  assert.equal(router.sessions.has("http_client"), false);
  assert.equal(router.ingressGuards.has("http_client"), false);

  // Live agent lastSeq unchanged; no live eviction.
  assert.equal(router.ingressGuards.get("ags_agent0")!.lastSeq, 42);
  assert.equal(router.sessions.size, MAX_GUARD_SESSIONS);
  assert.equal(router.ingressGuards.size, MAX_GUARD_SESSIONS);
});

test("assertRoomStateBounds still enforces guard + pending payload caps (unchanged-or-stronger)", () => {
  assert.throws(
    () =>
      assertRoomStateBounds({
        v: 1,
        seqOut: 0,
        ingressGuards: Object.fromEntries(
          Array.from({ length: MAX_GUARD_SESSIONS + 1 }, (_, i) => [
            `s${i}`,
            { lastSeq: 0, seenMessageIds: [] },
          ]),
        ),
        pending: [],
      }),
    /guard_session_limit/,
  );

  const hugePayload = { blob: "x".repeat(MAX_PENDING_PAYLOAD_BYTES + 1) };
  assert.throws(
    () =>
      assertRoomStateBounds({
        v: 1,
        seqOut: 0,
        ingressGuards: {},
        pending: [
          {
            correlation_id: "c1",
            type: "t",
            from_session: "s",
            created_at: Date.now(),
            payload: hugePayload,
          },
        ],
      }),
    /pending_payload_limit|room_state_too_large/,
  );
});
