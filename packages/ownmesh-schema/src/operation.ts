/** Versioned operation payload contract carried by device protocol envelopes. */

import { parseEnvelope } from "./envelope.ts";
import {
  parseOperationId,
  parseWorkspaceId,
  SchemaError,
} from "./ids.ts";
import type { ProtocolEnvelope } from "./types.ts";

export const OPERATION_CONTRACT_V1 = "ownmesh.operation/1.0" as const;

export type OperationContract = typeof OPERATION_CONTRACT_V1;
export type OperationProgressStatus = "queued" | "pending_approval" | "running";
export type OperationResultStatus =
  | "completed"
  | "failed"
  | "cancelled"
  | "timed_out"
  | "device_offline";

export interface OperationError {
  code: string;
  message: string;
  retryable: boolean;
  details?: unknown;
}

export interface OperationRequestPayload {
  operation_contract: OperationContract;
  operation_id: string;
  capability: string;
  workspace_id?: string;
  idempotency_key: string;
  arguments: Record<string, unknown>;
}

export interface OperationProgressPayload {
  operation_contract: OperationContract;
  operation_id: string;
  status: OperationProgressStatus;
  progress_seq: number;
  summary?: string;
  details?: Record<string, unknown>;
}

export interface OperationEventPayload {
  operation_contract: OperationContract;
  operation_id: string;
  event_seq: number;
  event_type: string;
  data: Record<string, unknown>;
}

export interface OperationResultPayload {
  operation_contract: OperationContract;
  operation_id: string;
  status: OperationResultStatus;
  result?: Record<string, unknown>;
  error?: OperationError;
}

type OperationEnvelopeBase = Omit<
  ProtocolEnvelope,
  "type" | "payload" | "correlation_id"
> & {
  correlation_id: string;
};

export type OperationPayload =
  | OperationRequestPayload
  | OperationProgressPayload
  | OperationEventPayload
  | OperationResultPayload;

export type OperationEnvelope =
  | (OperationEnvelopeBase & { type: "operation.request"; payload: OperationRequestPayload })
  | (OperationEnvelopeBase & { type: "operation.progress"; payload: OperationProgressPayload })
  | (OperationEnvelopeBase & { type: "operation.event"; payload: OperationEventPayload })
  | (OperationEnvelopeBase & { type: "operation.result"; payload: OperationResultPayload });

const ENVELOPE_KEYS = new Set([
  "protocol",
  "message_id",
  "type",
  "device_id",
  "correlation_id",
  "seq",
  "sent_at",
  "expires_at",
  "payload",
]);

function bad(message: string): never {
  throw new SchemaError("OWNMESH_E_BAD_ENVELOPE", message);
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    bad(`${label} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function assertExactKeys(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  label: string,
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) bad(`${label} contains unknown field '${key}'`);
  }
}

function requiredString(value: unknown, label: string, maxLength?: number): string {
  if (typeof value !== "string" || value.trim() === "") bad(`${label} must be a non-empty string`);
  if (maxLength !== undefined && Array.from(value).length > maxLength) {
    bad(`${label} exceeds ${maxLength} characters`);
  }
  return value;
}

function optionalString(value: unknown, label: string, maxLength?: number): string | undefined {
  if (value === undefined) return undefined;
  return requiredString(value, label, maxLength);
}

function rfc3339(value: unknown, label: string): string {
  const raw = requiredString(value, label);
  const parts = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$/.exec(raw);
  if (!parts) bad(`${label} must be an RFC3339 timestamp`);
  const [, yearRaw, monthRaw, dayRaw, hourRaw, minuteRaw, secondRaw, offsetHourRaw, offsetMinuteRaw] = parts;
  const year = Number(yearRaw);
  const month = Number(monthRaw);
  const day = Number(dayRaw);
  const hour = Number(hourRaw);
  const minute = Number(minuteRaw);
  const second = Number(secondRaw);
  const offsetHour = offsetHourRaw === undefined ? 0 : Number(offsetHourRaw);
  const offsetMinute = offsetMinuteRaw === undefined ? 0 : Number(offsetMinuteRaw);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > daysInMonth[month - 1]! ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59
  ) {
    bad(`${label} must be an RFC3339 timestamp`);
  }
  return raw;
}

function nonNegativeInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    bad(`${label} must be a non-negative safe integer`);
  }
  return value;
}

function operationId(value: unknown): string {
  try {
    return parseOperationId(requiredString(value, "operation_id"));
  } catch (error) {
    if (error instanceof SchemaError) bad(error.message);
    throw error;
  }
}

function workspaceId(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  try {
    return parseWorkspaceId(requiredString(value, "workspace_id"));
  } catch (error) {
    if (error instanceof SchemaError) bad(error.message);
    throw error;
  }
}

function assertContract(payload: Record<string, unknown>): void {
  if (payload.operation_contract !== OPERATION_CONTRACT_V1) {
    bad(
      `unsupported operation_contract '${String(payload.operation_contract)}', expected '${OPERATION_CONTRACT_V1}'`,
    );
  }
}

function parseRequest(payload: Record<string, unknown>): OperationRequestPayload {
  assertExactKeys(
    payload,
    new Set([
      "operation_contract",
      "operation_id",
      "capability",
      "workspace_id",
      "idempotency_key",
      "arguments",
    ]),
    "operation.request payload",
  );
  assertContract(payload);
  const parsed: OperationRequestPayload = {
    operation_contract: OPERATION_CONTRACT_V1,
    operation_id: operationId(payload.operation_id),
    capability: requiredString(payload.capability, "capability", 128),
    idempotency_key: requiredString(payload.idempotency_key, "idempotency_key", 256),
    arguments: asRecord(payload.arguments, "arguments"),
  };
  const workspace = workspaceId(payload.workspace_id);
  if (workspace !== undefined) parsed.workspace_id = workspace;
  return parsed;
}

function parseProgress(payload: Record<string, unknown>): OperationProgressPayload {
  assertExactKeys(
    payload,
    new Set(["operation_contract", "operation_id", "status", "progress_seq", "summary", "details"]),
    "operation.progress payload",
  );
  assertContract(payload);
  if (!new Set(["queued", "pending_approval", "running"]).has(String(payload.status))) {
    bad("invalid operation.progress status");
  }
  const parsed: OperationProgressPayload = {
    operation_contract: OPERATION_CONTRACT_V1,
    operation_id: operationId(payload.operation_id),
    status: payload.status as OperationProgressStatus,
    progress_seq: nonNegativeInteger(payload.progress_seq, "progress_seq"),
  };
  const summary = optionalString(payload.summary, "summary", 1024);
  if (summary !== undefined) parsed.summary = summary;
  if (payload.details !== undefined) parsed.details = asRecord(payload.details, "details");
  return parsed;
}

function parseEvent(payload: Record<string, unknown>): OperationEventPayload {
  assertExactKeys(
    payload,
    new Set(["operation_contract", "operation_id", "event_seq", "event_type", "data"]),
    "operation.event payload",
  );
  assertContract(payload);
  return {
    operation_contract: OPERATION_CONTRACT_V1,
    operation_id: operationId(payload.operation_id),
    event_seq: nonNegativeInteger(payload.event_seq, "event_seq"),
    event_type: requiredString(payload.event_type, "event_type", 128),
    data: asRecord(payload.data, "data"),
  };
}

function parseError(value: unknown): OperationError {
  const error = asRecord(value, "error");
  assertExactKeys(error, new Set(["code", "message", "retryable", "details"]), "error");
  if (typeof error.retryable !== "boolean") bad("error.retryable must be a boolean");
  const parsed: OperationError = {
    code: requiredString(error.code, "error.code", 128),
    message: requiredString(error.message, "error.message", 4096),
    retryable: error.retryable,
  };
  if (error.details !== undefined) parsed.details = error.details;
  return parsed;
}

function parseResult(payload: Record<string, unknown>): OperationResultPayload {
  assertExactKeys(
    payload,
    new Set(["operation_contract", "operation_id", "status", "result", "error"]),
    "operation.result payload",
  );
  assertContract(payload);
  const statuses = new Set(["completed", "failed", "cancelled", "timed_out", "device_offline"]);
  if (!statuses.has(String(payload.status))) bad("invalid operation.result status");
  const status = payload.status as OperationResultStatus;
  const parsed: OperationResultPayload = {
    operation_contract: OPERATION_CONTRACT_V1,
    operation_id: operationId(payload.operation_id),
    status,
  };
  if (status === "completed") {
    if (payload.error !== undefined) bad("completed operation.result forbids error");
    parsed.result = asRecord(payload.result, "result");
    return parsed;
  }
  if (payload.result !== undefined) bad(`${status} operation.result forbids result`);
  if (status === "failed" || status === "timed_out" || status === "device_offline") {
    parsed.error = parseError(payload.error);
  } else if (payload.error !== undefined) {
    parsed.error = parseError(payload.error);
  }
  return parsed;
}

/** Parse an operation envelope and enforce its versioned payload/correlation contract. */
export function parseOperationEnvelope(raw: string | unknown): OperationEnvelope {
  let value: unknown = raw;
  if (typeof raw === "string") {
    try {
      value = JSON.parse(raw) as unknown;
    } catch (error) {
      bad(`invalid envelope JSON: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  const original = asRecord(value, "envelope");
  assertExactKeys(original, ENVELOPE_KEYS, "operation envelope");
  const envelope = parseEnvelope(original);
  if (!envelope.correlation_id) bad("operation envelope requires correlation_id");
  nonNegativeInteger(envelope.seq, "seq");
  rfc3339(original.sent_at, "sent_at");
  if (Object.hasOwn(original, "expires_at")) {
    rfc3339(original.expires_at, "expires_at");
  }

  const payloadObject = asRecord(envelope.payload, `${envelope.type} payload`);
  let payload: OperationPayload;
  switch (envelope.type) {
    case "operation.request":
      if (!envelope.expires_at) bad("operation.request requires expires_at");
      payload = parseRequest(payloadObject);
      break;
    case "operation.progress":
      payload = parseProgress(payloadObject);
      break;
    case "operation.event":
      payload = parseEvent(payloadObject);
      break;
    case "operation.result":
      payload = parseResult(payloadObject);
      break;
    default:
      bad(`unsupported operation envelope type '${envelope.type}'`);
  }
  if (envelope.correlation_id !== payload.operation_id) {
    bad("correlation_id must equal payload operation_id");
  }
  return { ...envelope, type: envelope.type, payload } as OperationEnvelope;
}

/** Serialize only after re-validating the complete typed contract. */
export function serializeOperationEnvelope(envelope: OperationEnvelope): string {
  const validated = parseOperationEnvelope(envelope);
  return `${JSON.stringify(validated, null, 2)}\n`;
}
