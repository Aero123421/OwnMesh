/**
 * DeviceRoom WS operation routing E2E on test harness
 * (mirrors hibernation DO message path without workerd).
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  DeviceRoomHarness,
  MAX_PAYLOAD_BYTES,
  PROTOCOL,
  type DeviceEnvelope,
} from "./device-room.ts";
import { randomId } from "./util.ts";

/** Per-session monotonic inbound seq counters (required once seq guard is active). */
const sessionSeq = new Map<string, number>();

function nextSeq(sessionKey: string): number {
  const n = (sessionSeq.get(sessionKey) || 0) + 1;
  sessionSeq.set(sessionKey, n);
  return n;
}

function env(
  type: string,
  deviceId: string,
  payload: Record<string, unknown> = {},
  correlation?: string,
  opts?: {
    sessionKey?: string;
    seq?: number;
    message_id?: string;
    expires_at?: string;
    sent_at?: string;
  },
): DeviceEnvelope {
  const sessionKey = opts?.sessionKey || "__default__";
  const e: DeviceEnvelope = {
    protocol: PROTOCOL,
    message_id: opts?.message_id || randomId("msg_"),
    type,
    device_id: deviceId,
    seq: opts?.seq ?? nextSeq(sessionKey),
    sent_at: opts?.sent_at || new Date().toISOString(),
    payload,
  };
  if (correlation) e.correlation_id = correlation;
  if (opts?.expires_at) e.expires_at = opts.expires_at;
  return e;
}

/** Bind env() seq counter to a concrete session id. */
function envFor(
  sessionId: string,
  type: string,
  deviceId: string,
  payload: Record<string, unknown> = {},
  correlation?: string,
  opts?: {
    seq?: number;
    message_id?: string;
    expires_at?: string;
    sent_at?: string;
  },
): DeviceEnvelope {
  return env(type, deviceId, payload, correlation, { ...opts, sessionKey: sessionId });
}

test("DeviceRoom routes operation.request agent <-> client over harness WS", async () => {
  const deviceId = "dev_roomroute01abcdef";
  // Controlled harness only; production DeviceRoom supplies real Ed25519 verification.
  const room = new DeviceRoomHarness(deviceId, () => true);
  const agent = room.connect("agent");
  const client = room.connect("client");

  // handshake
  await room.send(agent, envFor(agent, "hello", deviceId, { protocols: [PROTOCOL] }));
  const helloReplies = room.drain(agent).map((s) => JSON.parse(s) as DeviceEnvelope);
  assert.equal(helloReplies[0]?.type, "challenge");
  assert.ok(
    String(helloReplies[0]?.payload.message || "").includes("ownmesh-device-challenge"),
  );

  await room.send(
    agent,
    envFor(agent, "proof", deviceId, {
      signature: "01".repeat(64),
      connection_id: helloReplies[0]?.payload.connection_id,
    }),
  );
  assert.equal(
    (JSON.parse(room.drain(agent)[0]!) as DeviceEnvelope).type,
    "accepted",
  );

  await room.send(
    agent,
    envFor(agent, "ready", deviceId, {
      capabilities: ["filesystem.read", "filesystem.write", "command.run"],
      remote_routing_enabled: true,
    }),
  );
  assert.equal((JSON.parse(room.drain(agent)[0]!) as DeviceEnvelope).type, "ready.ack");

  // client operation -> agent
  const corr = randomId("op_");
  await room.send(
    client,
    envFor(
      client,
      "operation.request",
      deviceId,
      { op: "ownmesh_fs_list", path: "/workspace" },
      corr,
    ),
  );
  const agentInbox = room.drain(agent).map((s) => JSON.parse(s) as DeviceEnvelope);
  assert.equal(agentInbox.length, 1);
  assert.equal(agentInbox[0]!.type, "operation.request");
  assert.equal(agentInbox[0]!.correlation_id, corr);
  assert.equal(agentInbox[0]!.payload.operation_contract, "ownmesh.operation/1.0");
  assert.equal(agentInbox[0]!.payload.operation_id, corr);
  assert.equal(agentInbox[0]!.payload.capability, "filesystem.read");
  assert.equal(
    (agentInbox[0]!.payload.arguments as { action?: string } | undefined)?.action,
    "fs.list",
  );
  assert.ok(agentInbox[0]!.expires_at, "operation.request requires expires_at");

  // agent result -> client
  await room.send(
    agent,
    envFor(
      agent,
      "operation.result",
      deviceId,
      { status: "completed", entries: ["a.txt"] },
      corr,
    ),
  );
  const clientInbox = room.drain(client).map((s) => JSON.parse(s) as DeviceEnvelope);
  assert.equal(clientInbox.length, 1);
  assert.equal(clientInbox[0]!.type, "operation.result");
  assert.equal(clientInbox[0]!.payload.status, "completed");
  assert.deepEqual(clientInbox[0]!.payload.entries, ["a.txt"]);

  // audit metadata on router
  const st = room.router.status();
  assert.equal(st.device_id, deviceId);
  assert.equal(st.agents, 1);
  assert.equal(st.clients, 1);
  assert.equal(st.pending, 0);
});

test("DeviceRoom fails closed on unknown types and unmatched agent results", async () => {
  const room = new DeviceRoomHarness("dev_fail_closed", () => true);
  const agent = room.connect("agent");
  room.router.sessions.get(agent)!.phase = "ready";
  room.router.sessions.get(agent)!.remote_routing_enabled = true;
  const unknown = await room.send(agent, envFor(agent, "accepted", "dev_fail_closed", {}));
  assert.equal(unknown.error, "unsupported_message_type");
  const unmatched = await room.send(
    agent,
    envFor(agent, "operation.result", "dev_fail_closed", { status: "completed" }, "missing"),
  );
  assert.equal(unmatched.error, "unknown_correlation");
});

test("client WebSocket scope cannot bypass MCP write/exec authorization", async () => {
  const room = new DeviceRoomHarness("dev_scoped", () => true);
  const client = room.connect("client", undefined, "ownmesh.read");
  const denied = await room.send(
    client,
    envFor(client, "operation.request", "dev_scoped", { op: "ownmesh_fs_write", path: "/x" }, "c"),
  );
  assert.equal(denied.error, "insufficient_scope");
});

test("injectOperation reports device_offline without agent", () => {
  const room = new DeviceRoomHarness("dev_offline01abcdef01");
  room.connect("client");
  const r = room.router.injectOperation({
    type: "ownmesh_fs_read",
    payload: { path: "/x" },
    correlation_id: randomId("op_"),
  });
  assert.equal(r.status, "device_offline");
});

test("injectOperation routes to connected agent", () => {
  const deviceId = "dev_inject01abcdef01ab";
  const room = new DeviceRoomHarness(deviceId);
  const agent = room.connect("agent");
  room.router.sessions.get(agent)!.phase = "ready";
  room.router.sessions.get(agent)!.remote_routing_enabled = true;
  const corr = randomId("op_");
  const r = room.router.injectOperation({
    type: "ownmesh_fs_list",
    payload: { path: "/" },
    correlation_id: corr,
  });
  assert.equal(r.status, "routed_to_device");
  const msgs = room.drain(agent).map((s) => JSON.parse(s) as DeviceEnvelope);
  assert.equal(msgs[0]!.type, "operation.request");
  assert.equal(msgs[0]!.correlation_id, corr);
});

test("malformed JSON yields error envelope and close signal", async () => {
  const room = new DeviceRoomHarness("dev_badjson01abcdef01");
  const agent = room.connect("agent");
  const result = await room.sendRaw(agent, "{not-json");
  assert.equal(result.ok, false);
  assert.equal(result.error, "bad_json");
  assert.equal(result.close, true);
  assert.equal(result.closeCode, 1003);
  const inbox = room.drain(agent).map((s) => JSON.parse(s) as DeviceEnvelope);
  assert.equal(inbox.length, 1);
  assert.equal(inbox[0]!.type, "error");
  assert.equal(inbox[0]!.payload.code, "OWNMESH_E_BAD_JSON");
});

test("oversized payload yields error envelope and close signal", async () => {
  const room = new DeviceRoomHarness("dev_toolarge01abcdef0");
  const agent = room.connect("agent");
  // Build a frame just over the announced max without hanging the test runner.
  const pad = "x".repeat(MAX_PAYLOAD_BYTES + 1);
  const raw = `{"protocol":"${PROTOCOL}","message_id":"msg_big","type":"ping","device_id":"dev_toolarge01abcdef0","seq":1,"sent_at":"2020-01-01T00:00:00.000Z","payload":{"p":"${pad}"}}`;
  assert.ok(raw.length > MAX_PAYLOAD_BYTES);
  const result = await room.sendRaw(agent, raw);
  assert.equal(result.ok, false);
  assert.equal(result.error, "payload_too_large");
  assert.equal(result.close, true);
  assert.equal(result.closeCode, 1009);
  const inbox = room.drain(agent).map((s) => JSON.parse(s) as DeviceEnvelope);
  assert.equal(inbox.length, 1);
  assert.equal(inbox[0]!.type, "error");
  assert.equal(inbox[0]!.payload.code, "OWNMESH_E_PAYLOAD_TOO_LARGE");
});

test("expired expires_at envelope is rejected", async () => {
  const deviceId = "dev_expired01abcdef01";
  const room = new DeviceRoomHarness(deviceId);
  const agent = room.connect("agent");
  const result = await room.send(
    agent,
    envFor(agent, "hello", deviceId, { protocols: [PROTOCOL] }, undefined, {
      expires_at: new Date(Date.now() - 60_000).toISOString(),
    }),
  );
  assert.equal(result.ok, false);
  assert.equal(result.error, "envelope_expired");
  assert.notEqual(result.close, true);
  const inbox = room.drain(agent).map((s) => JSON.parse(s) as DeviceEnvelope);
  assert.equal(inbox[0]!.type, "error");
  assert.equal(inbox[0]!.payload.code, "OWNMESH_E_ENVELOPE_EXPIRED");
  // Session must remain usable after a rejected expired frame.
  const ok = await room.send(agent, envFor(agent, "hello", deviceId, { protocols: [PROTOCOL] }));
  assert.equal(ok.ok, true);
});

test("duplicate message_id per session is rejected", async () => {
  const deviceId = "dev_dupmsg01abcdef01a";
  const room = new DeviceRoomHarness(deviceId, () => true);
  const agent = room.connect("agent");
  const mid = randomId("msg_");
  const first = await room.send(
    agent,
    envFor(agent, "hello", deviceId, { protocols: [PROTOCOL] }, undefined, { message_id: mid }),
  );
  assert.equal(first.ok, true);
  room.drain(agent);
  const dup = await room.send(
    agent,
    envFor(agent, "ping", deviceId, {}, undefined, { message_id: mid }),
  );
  assert.equal(dup.ok, false);
  assert.equal(dup.error, "duplicate_message_id");
  const inbox = room.drain(agent).map((s) => JSON.parse(s) as DeviceEnvelope);
  assert.equal(inbox[0]!.type, "error");
  assert.equal(inbox[0]!.payload.code, "OWNMESH_E_DUPLICATE_MESSAGE");
});

test("non-monotonic seq per session is rejected", async () => {
  const deviceId = "dev_badseq01abcdef01ab";
  const room = new DeviceRoomHarness(deviceId);
  const agent = room.connect("agent");
  const first = await room.send(
    agent,
    envFor(agent, "ping", deviceId, {}, undefined, { seq: 5 }),
  );
  assert.equal(first.ok, true);
  room.drain(agent);
  // Same seq
  const same = await room.send(
    agent,
    envFor(agent, "ping", deviceId, {}, undefined, { seq: 5 }),
  );
  assert.equal(same.ok, false);
  assert.equal(same.error, "bad_seq");
  // Lower seq
  const lower = await room.send(
    agent,
    envFor(agent, "ping", deviceId, {}, undefined, { seq: 3 }),
  );
  assert.equal(lower.ok, false);
  assert.equal(lower.error, "bad_seq");
  const inbox = room.drain(agent).map((s) => JSON.parse(s) as DeviceEnvelope);
  assert.ok(inbox.every((m) => m.type === "error" && m.payload.code === "OWNMESH_E_BAD_SEQ"));
  // Higher seq still accepted
  const next = await room.send(
    agent,
    envFor(agent, "ping", deviceId, {}, undefined, { seq: 6 }),
  );
  assert.equal(next.ok, true);
});

test("operation.request clears pending when no ready agent", async () => {
  const deviceId = "dev_pendclear01abcdef";
  const room = new DeviceRoomHarness(deviceId);
  const client = room.connect("client");
  const corr = randomId("op_");
  const result = await room.send(
    client,
    envFor(
      client,
      "operation.request",
      deviceId,
      { op: "ownmesh_fs_list", path: "/" },
      corr,
    ),
  );
  assert.equal(result.ok, true);
  assert.equal(room.router.pending.has(corr), false);
  assert.equal(room.router.status().pending, 0);
  const inbox = room.drain(client).map((s) => JSON.parse(s) as DeviceEnvelope);
  assert.equal(inbox[0]!.type, "operation.result");
  assert.equal(inbox[0]!.payload.status, "device_offline");
});

test("injectOperation clears pending when no ready agent", () => {
  const room = new DeviceRoomHarness("dev_injectclear01abc");
  room.connect("client");
  const corr = randomId("op_");
  const r = room.router.injectOperation({
    type: "ownmesh_fs_read",
    payload: { path: "/x" },
    correlation_id: corr,
  });
  assert.equal(r.status, "device_offline");
  assert.equal(room.router.pending.has(corr), false);
  assert.equal(room.router.status().pending, 0);
});

test("router redelivers durable pending operation.request with fresh seq after DO-authorized ready", async () => {
  const deviceId = "dev_ready_redeliv_01ab";
  const room = new DeviceRoomHarness(deviceId, () => true);
  const agent1 = room.connect("agent");

  room.router.sessions.get(agent1)!.phase = "ready";
  room.router.sessions.get(agent1)!.remote_routing_enabled = true;

  const corr = randomId("op_");
  const payload = {
    operation_contract: "ownmesh.operation/1.0",
    operation_id: corr,
    capability: "filesystem.write",
    idempotency_key: "idem_redeliv",
    payload_hash: "a".repeat(64),
    arguments: { action: "fs.write", path: "x.txt", content: "v1" },
  };
  const prep = room.router.prepareInjectOperation({
    type: "fs.write",
    payload,
    correlation_id: corr,
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  });
  assert.equal(prep.ok, true);
  if (!prep.ok) return;
  const first = room.router.dispatchPreparedInject(prep.prepared);
  assert.equal(first.status, "routed_to_device");
  const firstFrames = room.drain(agent1);
  assert.equal(firstFrames.length, 1);
  const firstEnv = JSON.parse(firstFrames[0]!) as DeviceEnvelope;
  assert.equal(firstEnv.type, "operation.request");
  assert.equal(firstEnv.correlation_id, corr);
  const firstSeq = firstEnv.seq;

  // Simulate agent disconnect without result; pending remains durable.
  room.router.unregisterSession(agent1);

  // New agent reconnects and becomes ready. Production DeviceRoom first
  // revalidates the durable principal credential generation, then calls this
  // pure-router delivery primitive; the harness performs that final primitive.
  const agent2 = room.connect("agent");
  room.router.sessions.get(agent2)!.phase = "proven";
  await room.send(
    agent2,
    envFor(agent2, "ready", deviceId, {
      remote_routing_enabled: true,
      capabilities: ["filesystem.write"],
    }),
  );
  const afterReady = room.drain(agent2).map((s) => JSON.parse(s) as DeviceEnvelope);
  const ack = afterReady.find((e) => e.type === "ready.ack");
  assert.ok(ack, "expected ready.ack");
  assert.equal(afterReady.filter((e) => e.type === "operation.request").length, 0);
  assert.equal(room.router.redeliverPendingToAgent(agent2), 1);
  const redelivered = room.drain(agent2).map((s) => JSON.parse(s) as DeviceEnvelope)
    .filter((e) => e.type === "operation.request");
  assert.equal(redelivered.length, 1);
  assert.equal(redelivered[0]!.correlation_id, corr);
  assert.ok(
    Number(redelivered[0]!.seq) > Number(firstSeq),
    "redelivery must use a fresh advancing seq",
  );
  assert.equal(redelivered[0]!.payload.operation_id, corr);
  assert.ok(room.router.pending.has(corr), "pending stays until terminal result");
});
