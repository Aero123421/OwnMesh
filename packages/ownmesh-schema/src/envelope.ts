/** Device protocol envelope parse / serialize (specification §21.3 / §21.6). */

import {
  parseDeviceId,
  parseMessageId,
  SchemaError,
  type ErrorCode,
} from "./ids.ts";
import { checkExpiryAt } from "./time.ts";
import type { ProtocolEnvelope } from "./types.ts";

export const PROTOCOL_DEVICE_V1 = "ownmesh.device/1.0";

export interface ProtocolVersion {
  major: number;
  minor: number;
}

export const CURRENT_PROTOCOL_VERSION: ProtocolVersion = { major: 1, minor: 0 };

export function parseProtocolVersion(raw: string): ProtocolVersion {
  const stripped = raw.startsWith("ownmesh.device/")
    ? raw.slice("ownmesh.device/".length)
    : raw.startsWith("ownmesh.device")
      ? raw.slice("ownmesh.device".length).replace(/^\//, "")
      : raw;
  const parts = stripped.split(".");
  if (parts.length < 1 || parts.length > 2 || parts[0] === "") {
    throw new SchemaError(
      "OWNMESH_E_UNSUPPORTED_PROTOCOL",
      `invalid protocol version '${raw}'`,
    );
  }
  const major = Number(parts[0]);
  const minor = Number(parts[1] ?? "0");
  if (!Number.isInteger(major) || !Number.isInteger(minor) || major < 0 || minor < 0) {
    throw new SchemaError(
      "OWNMESH_E_UNSUPPORTED_PROTOCOL",
      `invalid protocol version '${raw}'`,
    );
  }
  return { major, minor };
}

export function protocolVersionToWire(v: ProtocolVersion): string {
  return `ownmesh.device/${v.major}.${v.minor}`;
}

export function negotiateProtocol(
  offered: ProtocolVersion[],
  supported: ProtocolVersion[],
): ProtocolVersion {
  if (offered.length === 0 || supported.length === 0) {
    throw new SchemaError(
      "OWNMESH_E_UNSUPPORTED_PROTOCOL",
      "no protocol versions to negotiate",
    );
  }
  let best: ProtocolVersion | undefined;
  for (const offer of offered) {
    for (const local of supported) {
      if (offer.major !== local.major) continue;
      if (offer.major === local.major && offer.minor === local.minor) {
        if (!best || offer.major > best.major || (offer.major === best.major && offer.minor > best.minor)) {
          best = offer;
        }
      }
    }
  }
  if (!best) {
    throw new SchemaError(
      "OWNMESH_E_UNSUPPORTED_PROTOCOL",
      "no compatible protocol version",
    );
  }
  return best;
}

export function parseEnvelope(raw: string | unknown): ProtocolEnvelope {
  let value: unknown;
  if (typeof raw === "string") {
    if (raw.length === 0) {
      throw new SchemaError("OWNMESH_E_BAD_ENVELOPE", "envelope is empty");
    }
    try {
      value = JSON.parse(raw) as unknown;
    } catch (e) {
      throw new SchemaError(
        "OWNMESH_E_BAD_ENVELOPE",
        `invalid envelope JSON: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  } else {
    value = raw;
  }

  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new SchemaError("OWNMESH_E_BAD_ENVELOPE", "envelope must be a JSON object");
  }

  const obj = value as Record<string, unknown>;

  if (obj.protocol !== PROTOCOL_DEVICE_V1) {
    throw new SchemaError(
      "OWNMESH_E_UNSUPPORTED_PROTOCOL",
      `unsupported protocol '${String(obj.protocol)}', expected '${PROTOCOL_DEVICE_V1}'`,
    );
  }

  if (typeof obj.message_id !== "string") {
    throw new SchemaError("OWNMESH_E_BAD_ENVELOPE", "message_id is required");
  }
  if (typeof obj.type !== "string" || obj.type.trim() === "") {
    throw new SchemaError("OWNMESH_E_BAD_ENVELOPE", "type is required");
  }
  if (typeof obj.device_id !== "string") {
    throw new SchemaError("OWNMESH_E_BAD_ENVELOPE", "device_id is required");
  }
  if (typeof obj.seq !== "number" || !Number.isInteger(obj.seq) || obj.seq < 0) {
    throw new SchemaError("OWNMESH_E_BAD_ENVELOPE", "seq must be a non-negative integer");
  }
  if (typeof obj.sent_at !== "string") {
    throw new SchemaError("OWNMESH_E_BAD_ENVELOPE", "sent_at is required");
  }
  if (obj.payload === null || typeof obj.payload !== "object" || Array.isArray(obj.payload)) {
    throw new SchemaError("OWNMESH_E_BAD_ENVELOPE", "payload must be a JSON object");
  }

  let messageId: string;
  let deviceId: string;
  try {
    messageId = parseMessageId(obj.message_id);
    deviceId = parseDeviceId(obj.device_id);
  } catch (e) {
    if (e instanceof SchemaError && e.code === "OWNMESH_E_INVALID_ID") {
      throw new SchemaError("OWNMESH_E_BAD_ENVELOPE", e.message);
    }
    throw e;
  }

  const envelope: ProtocolEnvelope = {
    protocol: PROTOCOL_DEVICE_V1,
    message_id: messageId,
    type: obj.type,
    device_id: deviceId,
    seq: obj.seq,
    sent_at: obj.sent_at,
    payload: obj.payload as Record<string, unknown>,
  };

  if (obj.correlation_id !== undefined && obj.correlation_id !== null) {
    if (typeof obj.correlation_id !== "string") {
      throw new SchemaError("OWNMESH_E_BAD_ENVELOPE", "correlation_id must be a string");
    }
    envelope.correlation_id = obj.correlation_id;
  }

  if (obj.expires_at !== undefined && obj.expires_at !== null) {
    if (typeof obj.expires_at !== "string") {
      throw new SchemaError("OWNMESH_E_BAD_ENVELOPE", "expires_at must be a string");
    }
    envelope.expires_at = obj.expires_at;
  }

  return envelope;
}

export function serializeEnvelope(env: ProtocolEnvelope): string {
  return `${JSON.stringify(env, null, 2)}\n`;
}

export function validateEnvelopeExpiry(
  env: ProtocolEnvelope,
  nowIso: string,
  skewMs?: number,
): void {
  if (env.expires_at) {
    try {
      checkExpiryAt(env.expires_at, nowIso, skewMs);
    } catch (e) {
      if (e instanceof SchemaError && e.code === "OWNMESH_E_EXPIRED") {
        throw new SchemaError(
          "OWNMESH_E_EXPIRED",
          `envelope ${env.message_id}: ${e.message}`,
        );
      }
      throw e;
    }
  }
}

export function fuzzParseEnvelope(data: Uint8Array | string): void {
  try {
    const text = typeof data === "string" ? data : new TextDecoder("utf-8", { fatal: false }).decode(data);
    parseEnvelope(text);
  } catch {
    // intentional: fuzz entry never throws to caller
  }
}

export function isSchemaErrorCode(e: unknown, code: ErrorCode): boolean {
  return e instanceof SchemaError && e.code === code;
}
