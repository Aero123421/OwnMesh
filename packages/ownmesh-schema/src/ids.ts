/** Stable OwnMesh identifiers: `{prefix}_{body}`. */

export const MAX_ID_LEN = 128;

export type IdKind =
  | "tenant"
  | "principal"
  | "membership"
  | "device"
  | "workspace"
  | "capability_grant"
  | "policy_rule"
  | "approval"
  | "operation"
  | "session"
  | "audit_event"
  | "message"
  | "cursor"
  | "policy";

export const ID_PREFIX: Record<IdKind, string> = {
  tenant: "ten_",
  principal: "prin_",
  membership: "mem_",
  device: "dev_",
  workspace: "ws_",
  capability_grant: "grant_",
  policy_rule: "rule_",
  approval: "apr_",
  operation: "op_",
  session: "sess_",
  audit_event: "aud_",
  message: "msg_",
  cursor: "cur_",
  policy: "pol_",
};

export class SchemaError extends Error {
  readonly code: ErrorCode;
  readonly retryable: boolean;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "SchemaError";
    this.code = code;
    this.retryable = errorRetryable(code);
  }
}

export type ErrorCode =
  | "OWNMESH_E_INVALID_ID"
  | "OWNMESH_E_INVALID_ARGUMENT"
  | "OWNMESH_E_SCHEMA_VALIDATION"
  | "OWNMESH_E_BAD_ENVELOPE"
  | "OWNMESH_E_UNSUPPORTED_PROTOCOL"
  | "OWNMESH_E_CONFIG"
  | "OWNMESH_E_AUTHENTICATION"
  | "OWNMESH_E_AUTHORIZATION"
  | "OWNMESH_E_POLICY_DENIED"
  | "OWNMESH_E_EXECUTABLE_IDENTITY_DRIFT"
  | "OWNMESH_E_DEVICE_OFFLINE"
  | "OWNMESH_E_TIMEOUT"
  | "OWNMESH_E_CANCELLED"
  | "OWNMESH_E_EXPIRED"
  | "OWNMESH_E_CONFLICT"
  | "OWNMESH_E_STALE_SNAPSHOT"
  | "OWNMESH_E_CONTROLLER_CONFLICT"
  | "OWNMESH_E_SESSION_NOT_CONTROLLER"
  | "OWNMESH_E_PROFILE_UNAVAILABLE"
  | "OWNMESH_E_INTERNAL";

export type ExitCode = 0 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;

export function errorExitCode(code: ErrorCode): ExitCode {
  switch (code) {
    case "OWNMESH_E_INVALID_ID":
    case "OWNMESH_E_INVALID_ARGUMENT":
    case "OWNMESH_E_SCHEMA_VALIDATION":
    case "OWNMESH_E_BAD_ENVELOPE":
    case "OWNMESH_E_UNSUPPORTED_PROTOCOL":
    case "OWNMESH_E_CONFIG":
      return 2;
    case "OWNMESH_E_AUTHENTICATION":
      return 3;
    case "OWNMESH_E_AUTHORIZATION":
    case "OWNMESH_E_POLICY_DENIED":
    case "OWNMESH_E_EXECUTABLE_IDENTITY_DRIFT":
      return 4;
    case "OWNMESH_E_DEVICE_OFFLINE":
      return 5;
    case "OWNMESH_E_TIMEOUT":
    case "OWNMESH_E_CANCELLED":
    case "OWNMESH_E_EXPIRED":
      return 6;
    case "OWNMESH_E_CONFLICT":
    case "OWNMESH_E_STALE_SNAPSHOT":
    case "OWNMESH_E_CONTROLLER_CONFLICT":
    case "OWNMESH_E_SESSION_NOT_CONTROLLER":
      return 7;
    case "OWNMESH_E_PROFILE_UNAVAILABLE":
      return 8;
    case "OWNMESH_E_INTERNAL":
      return 9;
  }
}

export function errorRetryable(code: ErrorCode): boolean {
  return (
    code === "OWNMESH_E_DEVICE_OFFLINE" ||
    code === "OWNMESH_E_TIMEOUT" ||
    code === "OWNMESH_E_CONFLICT" ||
    code === "OWNMESH_E_INTERNAL"
  );
}

const BODY_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

function validateBody(body: string): void {
  if (!BODY_RE.test(body)) {
    throw new SchemaError(
      "OWNMESH_E_INVALID_ID",
      `id body is empty or contains illegal characters: ${JSON.stringify(body)}`,
    );
  }
}

export function parsePrefixedId(raw: string, kind: IdKind): string {
  if (raw.length === 0) {
    throw new SchemaError("OWNMESH_E_INVALID_ID", "id must not be empty");
  }
  if (raw.length > MAX_ID_LEN) {
    throw new SchemaError(
      "OWNMESH_E_INVALID_ID",
      `id exceeds maximum length of ${MAX_ID_LEN}`,
    );
  }
  const prefix = ID_PREFIX[kind];
  if (!raw.startsWith(prefix)) {
    throw new SchemaError(
      "OWNMESH_E_INVALID_ID",
      `expected ${kind} id with prefix '${prefix}', got '${raw}'`,
    );
  }
  validateBody(raw.slice(prefix.length));
  return raw;
}

export function parseAnyId(raw: string): { kind: IdKind; id: string } {
  const entry = (Object.entries(ID_PREFIX) as [IdKind, string][]).find(([, p]) =>
    raw.startsWith(p),
  );
  if (!entry) {
    throw new SchemaError("OWNMESH_E_INVALID_ID", `unknown id prefix in '${raw}'`);
  }
  const [kind] = entry;
  return { kind, id: parsePrefixedId(raw, kind) };
}

export const parseTenantId = (raw: string): string => parsePrefixedId(raw, "tenant");
export const parsePrincipalId = (raw: string): string => parsePrefixedId(raw, "principal");
export const parseMembershipId = (raw: string): string => parsePrefixedId(raw, "membership");
export const parseDeviceId = (raw: string): string => parsePrefixedId(raw, "device");
export const parseWorkspaceId = (raw: string): string => parsePrefixedId(raw, "workspace");
export const parseGrantId = (raw: string): string => parsePrefixedId(raw, "capability_grant");
export const parseRuleId = (raw: string): string => parsePrefixedId(raw, "policy_rule");
export const parseApprovalId = (raw: string): string => parsePrefixedId(raw, "approval");
export const parseOperationId = (raw: string): string => parsePrefixedId(raw, "operation");
export const parseSessionId = (raw: string): string => parsePrefixedId(raw, "session");
export const parseAuditEventId = (raw: string): string => parsePrefixedId(raw, "audit_event");
export const parseMessageId = (raw: string): string => parsePrefixedId(raw, "message");
export const parsePolicyId = (raw: string): string => parsePrefixedId(raw, "policy");
export const parseCursor = (raw: string): string => parsePrefixedId(raw, "cursor");
