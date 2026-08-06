/**
 * DeviceRoom WS operation routing E2E on test harness
 * (mirrors hibernation DO message path without workerd).
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  DeviceRoomHarness,
  PROTOCOL,
  type DeviceEnvelope,
} from "./device-room.ts";
import { randomId } from "./util.ts";

function env(
  type: string,
  deviceId: string,
  payload: Record<string, unknown> = {},
  correlation?: string,
): DeviceEnvelope {
  const e: DeviceEnvelope = {
    protocol: PROTOCOL,
    message_id: randomId("msg_"),
    type,
    device_id: deviceId,
    seq: 1,
    sent_at: new Date().toISOString(),
    payload,
  };
  if (correlation) e.correlation_id = correlation;
  return e;
}

test("DeviceRoom routes operation.request agent <-> client over harness WS", () => {
  const deviceId = "dev_roomroute01abcdef";
  const room = new DeviceRoomHarness(deviceId);
  const agent = room.connect("agent");
  const client = room.connect("client");

  // handshake
  room.send(agent, env("hello", deviceId, { protocols: [PROTOCOL] }));
  const helloReplies = room.drain(agent).map((s) => JSON.parse(s) as DeviceEnvelope);
  assert.equal(helloReplies[0]?.type, "challenge");
  assert.ok(
    String(helloReplies[0]?.payload.message || "").includes("ownmesh-device-challenge"),
  );

  room.send(
    agent,
    env("proof", deviceId, {
      signature: "00".repeat(64),
      connection_id: helloReplies[0]?.payload.connection_id,
    }),
  );
  assert.equal(
    (JSON.parse(room.drain(agent)[0]!) as DeviceEnvelope).type,
    "accepted",
  );

  room.send(agent, env("ready", deviceId, { capabilities: ["fs", "exec"] }));
  assert.equal((JSON.parse(room.drain(agent)[0]!) as DeviceEnvelope).type, "ready.ack");

  // client operation -> agent
  const corr = randomId("op_");
  room.send(
    client,
    env(
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
  assert.equal(agentInbox[0]!.payload.op, "ownmesh_fs_list");

  // agent result -> client
  room.send(
    agent,
    env(
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
