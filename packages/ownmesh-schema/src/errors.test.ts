import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  isSchemaErrorCode,
  parseEnvelope,
  validateEnvelopeExpiry,
  fuzzParseEnvelope,
  negotiateProtocol,
  parseProtocolVersion,
} from "./envelope.ts";
import {
  errorExitCode,
  parseDeviceId,
  parseAnyId,
  SchemaError,
} from "./ids.ts";
import { checkExpiryAt } from "./time.ts";

describe("error taxonomy", () => {
  it("maps executable identity drift to fresh authorization", () => {
    assert.equal(errorExitCode("OWNMESH_E_EXECUTABLE_IDENTITY_DRIFT"), 4);
    const error = new SchemaError(
      "OWNMESH_E_EXECUTABLE_IDENTITY_DRIFT",
      "request must be re-authorized",
    );
    assert.equal(error.retryable, false);
  });

  it("rejects unknown and invalid ids", () => {
    assert.throws(
      () => parseAnyId("foo_bar"),
      (e: unknown) => isSchemaErrorCode(e, "OWNMESH_E_INVALID_ID"),
    );
    assert.throws(
      () => parseDeviceId("ten_example"),
      (e: unknown) => {
        assert.ok(e instanceof SchemaError);
        assert.equal(e.code, "OWNMESH_E_INVALID_ID");
        assert.equal(errorExitCode(e.code), 2);
        return true;
      },
    );
    assert.throws(
      () => parseDeviceId("dev_"),
      (e: unknown) => isSchemaErrorCode(e, "OWNMESH_E_INVALID_ID"),
    );
    assert.throws(
      () => parseDeviceId("dev_has space"),
      (e: unknown) => isSchemaErrorCode(e, "OWNMESH_E_INVALID_ID"),
    );
  });

  it("rejects expired timestamps", () => {
    assert.throws(
      () => checkExpiryAt("2020-01-01T00:00:00Z", "2026-01-01T00:00:00Z", 0),
      (e: unknown) => {
        assert.ok(e instanceof SchemaError);
        assert.equal(e.code, "OWNMESH_E_EXPIRED");
        assert.equal(errorExitCode(e.code), 6);
        return true;
      },
    );
  });

  it("rejects bad envelopes with taxonomy codes", () => {
    assert.throws(
      () => parseEnvelope(""),
      (e: unknown) => isSchemaErrorCode(e, "OWNMESH_E_BAD_ENVELOPE"),
    );
    assert.throws(
      () => parseEnvelope("{"),
      (e: unknown) => isSchemaErrorCode(e, "OWNMESH_E_BAD_ENVELOPE"),
    );
    assert.throws(
      () =>
        parseEnvelope(
          JSON.stringify({
            protocol: "ownmesh.device/9.9",
            message_id: "msg_x",
            type: "t",
            device_id: "dev_x",
            seq: 0,
            sent_at: "2026-08-06T00:00:00Z",
            payload: {},
          }),
        ),
      (e: unknown) => isSchemaErrorCode(e, "OWNMESH_E_UNSUPPORTED_PROTOCOL"),
    );
    assert.throws(
      () =>
        parseEnvelope(
          JSON.stringify({
            protocol: "ownmesh.device/1.0",
            message_id: "msg_x",
            type: "t",
            device_id: "not_a_device",
            seq: 0,
            sent_at: "2026-08-06T00:00:00Z",
            payload: {},
          }),
        ),
      (e: unknown) => isSchemaErrorCode(e, "OWNMESH_E_BAD_ENVELOPE"),
    );
  });

  it("rejects expired envelope", () => {
    const env = parseEnvelope(
      JSON.stringify({
        protocol: "ownmesh.device/1.0",
        message_id: "msg_x",
        type: "t",
        device_id: "dev_x",
        seq: 0,
        sent_at: "2026-08-06T00:00:00Z",
        expires_at: "2026-08-06T00:01:00Z",
        payload: {},
      }),
    );
    assert.throws(
      () => validateEnvelopeExpiry(env, "2026-08-06T00:05:00Z", 0),
      (e: unknown) => isSchemaErrorCode(e, "OWNMESH_E_EXPIRED"),
    );
  });

  it("fuzz entry never throws", () => {
    fuzzParseEnvelope("");
    fuzzParseEnvelope("{");
    fuzzParseEnvelope(new Uint8Array([0xff, 0xfe, 0x00]));
  });

  it("version negotiation", () => {
    const selected = negotiateProtocol(
      [parseProtocolVersion("ownmesh.device/1.0")],
      [parseProtocolVersion("ownmesh.device/1.0")],
    );
    assert.deepEqual(selected, { major: 1, minor: 0 });
    assert.throws(
      () =>
        negotiateProtocol(
          [parseProtocolVersion("ownmesh.device/2.0")],
          [parseProtocolVersion("ownmesh.device/1.0")],
        ),
      (e: unknown) => isSchemaErrorCode(e, "OWNMESH_E_UNSUPPORTED_PROTOCOL"),
    );
  });
});
