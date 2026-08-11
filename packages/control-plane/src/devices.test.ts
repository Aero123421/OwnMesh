/** Device enroll / proof / revoke server contract (cli-auth-09 consumes this). */
import assert from "node:assert/strict";
import test from "node:test";
import { handleDevices } from "./oauth.ts";
import { MemoryStore } from "./store.ts";

async function authedStore() {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const tok = await store.issueTokens(
    "client_ownmesh_cli",
    "prin_dev",
    "ownmesh.device ownmesh.read offline_access",
  );
  return { store, token: tok.access_token };
}

test("enroll returns challenge shape then proof + revoke persist", async () => {
  const { store, token } = await authedStore();
  const keyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const publicBytes = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey) as ArrayBuffer);
  const publicKey = [...publicBytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  const enrollRes = await handleDevices(
    new Request("https://cp.test/v1/devices/enroll", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        name: "desk",
        labels: [" work ", "work", "gpu"],
        hostname: "desk.local",
        os: "windows",
        arch: "x64",
        agent_version: "1.0.1",
        protocol_version: "ownmesh.device/1.0",
        public_key: publicKey,
      }),
    }),
    store,
    new URL("https://cp.test/v1/devices/enroll"),
  );
  assert.equal(enrollRes.status, 201);
  const body = (await enrollRes.json()) as {
    device_id: string;
    enrollment_token: string;
    challenge: { id: string; nonce: string; message: string; expires_at: string };
    connect_path: string;
  };
  assert.match(body.device_id, /^dev_/);
  assert.ok(body.enrollment_token);
  assert.match(body.challenge.id, /^ech_/);
  assert.equal(
    body.challenge.message,
    `ownmesh-device-challenge:${body.challenge.nonce}:${body.device_id}`,
  );
  assert.equal(body.connect_path, "/agent/connect");

  const signatureBytes = new Uint8Array(await crypto.subtle.sign(
    "Ed25519", keyPair.privateKey, new TextEncoder().encode(body.challenge.message),
  ));
  const signature = [...signatureBytes].map((b) => b.toString(16).padStart(2, "0")).join("");

  const invalidProof = await handleDevices(
    new Request("https://cp.test/v1/devices/enroll/proof", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ device_id: body.device_id, challenge_id: body.challenge.id, signature: "00".repeat(64) }),
    }),
    store,
    new URL("https://cp.test/v1/devices/enroll/proof"),
  );
  assert.equal(invalidProof.status, 400);
  assert.equal((await store.getDevice(body.device_id))?.status, "pending");

  const proofRes = await handleDevices(
    new Request("https://cp.test/v1/devices/enroll/proof", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        device_id: body.device_id,
        challenge_id: body.challenge.id,
        signature,
      }),
    }),
    store,
    new URL("https://cp.test/v1/devices/enroll/proof"),
  );
  assert.equal(proofRes.status, 200);
  const proof = (await proofRes.json()) as { ok: boolean; status: string };
  assert.equal(proof.ok, true);
  assert.equal(proof.status, "active");

  // challenge cannot be reused
  const reuse = await handleDevices(
    new Request("https://cp.test/v1/devices/enroll/proof", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        device_id: body.device_id,
        challenge_id: body.challenge.id,
        signature,
      }),
    }),
    store,
    new URL("https://cp.test/v1/devices/enroll/proof"),
  );
  assert.equal(reuse.status, 409);

  const list = await handleDevices(
    new Request("https://cp.test/v1/devices", {
      headers: { authorization: `Bearer ${token}` },
    }),
    store,
    new URL("https://cp.test/v1/devices"),
  );
  const listed = (await list.json()) as { devices: { id: string; labels: string[] }[] };
  assert.equal(listed.devices.length, 1);
  assert.deepEqual(listed.devices[0]!.labels, ["work", "gpu"]);

  const rev = await handleDevices(
    new Request("https://cp.test/v1/devices/revoke", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ id: body.device_id }),
    }),
    store,
    new URL("https://cp.test/v1/devices/revoke"),
  );
  assert.equal(((await rev.json()) as { ok: boolean }).ok, true);
  assert.equal((await store.listDevices("prin_dev")).length, 0);
});

test("PATCH device metadata is exact, normalized, owner-bound, and fail-closed", async () => {
  const { store, token } = await authedStore();
  await store.putDevice({
    id: "dev_metadata",
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    name: "old name",
    labels: [],
    hostname: "desk.local",
    os: "linux",
    arch: "x64",
    agent_version: "1",
    protocol_version: "ownmesh.device/1.0",
    public_key: "ab".repeat(32),
    revoked: false,
    created_at: new Date().toISOString(),
    status: "active",
  });

  const patch = await handleDevices(
    new Request("https://cp.test/v1/devices/dev_metadata", {
      method: "PATCH",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ name: "  Workstation  ", labels: [" dev ", "dev", "gpu"] }),
    }),
    store,
    new URL("https://cp.test/v1/devices/dev_metadata"),
  );
  assert.equal(patch.status, 200);
  const updated = (await patch.json()) as { device: { name: string; labels: string[] } };
  assert.equal(updated.device.name, "Workstation");
  assert.deepEqual(updated.device.labels, ["dev", "gpu"]);
  assert.deepEqual((await store.getDevice("dev_metadata"))?.labels, ["dev", "gpu"]);

  const invalid = await handleDevices(
    new Request("https://cp.test/v1/devices/dev_metadata", {
      method: "PATCH",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ labels: ["bad\u0000label"] }),
    }),
    store,
    new URL("https://cp.test/v1/devices/dev_metadata"),
  );
  assert.equal(invalid.status, 400);
  assert.deepEqual(await invalid.json(), { error: "invalid_request", field: "labels" });

  const extra = await handleDevices(
    new Request("https://cp.test/v1/devices/dev_metadata", {
      method: "PATCH",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ name: "ignored", role: "admin" }),
    }),
    store,
    new URL("https://cp.test/v1/devices/dev_metadata"),
  );
  assert.equal(extra.status, 400);
  assert.equal((await store.getDevice("dev_metadata"))?.name, "Workstation");

  await store.ensurePrincipal("prin_foreign", "Foreign", "human", "ten_default");
  const foreignToken = await store.issueTokens(
    "client_ownmesh_cli",
    "prin_foreign",
    "ownmesh.device",
  );
  const foreign = await handleDevices(
    new Request("https://cp.test/v1/devices/dev_metadata", {
      method: "PATCH",
      headers: {
        authorization: `Bearer ${foreignToken.access_token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ name: "stolen" }),
    }),
    store,
    new URL("https://cp.test/v1/devices/dev_metadata"),
  );
  const foreignBody = await foreign.text();
  const missing = await handleDevices(
    new Request("https://cp.test/v1/devices/dev_missing", {
      method: "PATCH",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ name: "missing" }),
    }),
    store,
    new URL("https://cp.test/v1/devices/dev_missing"),
  );
  assert.equal(foreign.status, 404);
  assert.equal(missing.status, 404);
  assert.equal(foreignBody, await missing.text());
  assert.equal((await store.getDevice("dev_metadata"))?.name, "Workstation");
});
