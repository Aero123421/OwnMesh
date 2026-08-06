/** Domain entity TypeScript types (mirrors Rust `ownmesh-domain`). */

export type EntityStatus = "active" | "disabled" | "pending" | "revoked";
export type AuthMode = "cloudflare_access" | "generic_oidc" | "development";
export type PrincipalType = "human" | "oauth_client" | "device" | "local_ipc" | "service";
export type MembershipRole = "owner" | "admin" | "member" | "auditor";
export type DeviceOs = "windows" | "macos" | "linux" | "unknown";
export type WorkspaceMode = "read_write" | "read_only";
export type PolicyDecision = "allow" | "ask" | "deny";
export type OperationClass =
  | "elevated"
  | "writes_outside_workspace"
  | "reads_sensitive_location"
  | "writes_sensitive_location"
  | "external_data_transfer"
  | "raw_shell"
  | "system_persistence_change"
  | "package_install"
  | "service_change"
  | "user_account_change"
  | "destructive_file_change"
  | "public_or_open_world_effect";
export type ApprovalState = "pending" | "approved" | "denied" | "expired" | "cancelled";
export type ApprovalScope =
  | "once"
  | "operation_retry"
  | "session"
  | "workspace"
  | "device"
  | "principal"
  | "always"
  | "deny_once"
  | "deny_always";
export type OperationStatus =
  | "queued"
  | "pending_approval"
  | "running"
  | "completed"
  | "failed"
  | "cancelled"
  | "timed_out";
export type SessionType = "process" | "terminal" | "profile" | "local_shell";
export type SessionState =
  | "starting"
  | "running"
  | "waiting_input"
  | "waiting_approval"
  | "completed"
  | "failed"
  | "cancelled"
  | "detached"
  | "orphaned"
  | "unreachable";

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  status: EntityStatus;
  created_at: string;
  default_policy_id?: string;
  auth_mode: AuthMode;
}

export interface Principal {
  id: string;
  tenant_id: string;
  type: PrincipalType;
  external_subject?: string;
  display_name: string;
  status: EntityStatus;
  created_at: string;
}

export interface Membership {
  id: string;
  tenant_id: string;
  principal_id: string;
  role: MembershipRole;
  status: EntityStatus;
  created_at: string;
}

export interface Device {
  id: string;
  tenant_id: string;
  owner_principal_id: string;
  name: string;
  hostname: string;
  os: DeviceOs;
  arch: string;
  agent_version: string;
  protocol_version: string;
  public_key: string;
  labels?: string[];
  status: EntityStatus;
  last_seen_at?: string;
  created_at: string;
  revoked_at?: string;
}

export interface Workspace {
  id: string;
  device_id: string;
  name: string;
  canonical_path: string;
  mode: WorkspaceMode;
  policy_id?: string;
  created_at: string;
}

export interface CapabilityGrant {
  id: string;
  tenant_id: string;
  principal_id: string;
  capability: string;
  device_id?: string;
  workspace_id?: string;
  session_id?: string;
  status: EntityStatus;
  created_at: string;
  created_by: string;
  expires_at?: string;
  note?: string;
}

export interface PolicyRule {
  id: string;
  policy_id?: string;
  priority: number;
  decision: PolicyDecision;
  principal_ids?: string[];
  device_ids?: string[];
  workspace_ids?: string[];
  capabilities?: string[];
  path_globs?: string[];
  executables?: string[];
  elevated?: boolean;
  raw_shell?: boolean;
  operation_classes?: OperationClass[];
  description?: string;
  expires_at?: string;
}

export interface Approval {
  id: string;
  tenant_id: string;
  operation_id: string;
  requester_principal_id: string;
  approver_principal_id?: string;
  state: ApprovalState;
  scope?: ApprovalScope;
  created_at: string;
  decided_at?: string;
  expires_at?: string;
  note?: string;
}

export interface Operation {
  id: string;
  tenant_id: string;
  requester_principal_id: string;
  device_id: string;
  workspace_id?: string;
  capability: string;
  status: OperationStatus;
  idempotency_key?: string;
  approval_state: ApprovalState;
  created_at: string;
  started_at?: string;
  finished_at?: string;
  result_summary?: Record<string, unknown>;
}

export interface Session {
  session_id: string;
  session_type: SessionType;
  device_id: string;
  workspace_id?: string;
  profile_id?: string;
  state: SessionState;
  created_by: string;
  created_at: string;
  controller_principal?: string;
  controller_lease_version?: number;
  controller_lease_expires_at?: string;
  last_event_seq?: number;
  native_session_id?: string;
  process_id?: number;
}

export interface AuditEvent {
  id: string;
  tenant_id: string;
  event_type: string;
  created_at: string;
  actor_principal_id?: string;
  device_id?: string;
  operation_id?: string;
  session_id?: string;
  payload_hash?: string;
  metadata?: Record<string, unknown>;
}

export interface ErrorBody {
  code: string;
  message: string;
  retryable: boolean;
  operation_id?: string;
  details?: Record<string, unknown>;
}

export interface ErrorEnvelope {
  error: ErrorBody;
}

export interface PageRequest {
  cursor?: string;
  limit?: number;
}

export interface Page<T> {
  items: T[];
  next_cursor?: string;
  truncated?: boolean;
}

/** Shared log cursor (provider-local offset). */
export interface LogCursor {
  provider: string;
  offset: number;
}

export interface LogLine {
  line_no: number;
  text: string;
  cursor_after: LogCursor;
}

export interface LogPage {
  lines: LogLine[];
  next_cursor?: LogCursor;
  exhausted: boolean;
}

export type LogProviderId =
  | "audit"
  | "file"
  | "windows_event"
  | "journald"
  | "docker"
  | "process"
  | (string & {});

export interface GitStatusEntry {
  code: string;
  path: string;
  orig_path?: string;
}

/** Entry-offset pagination (same idea as log pages). */
export interface GitStatusPage {
  repo_root: string;
  branch?: string;
  upstream?: string;
  clean: boolean;
  entries: GitStatusEntry[];
  next_cursor?: number;
  exhausted: boolean;
}

/** Line-offset unified diff page. */
export interface GitDiffPage {
  repo_root: string;
  staged: boolean;
  lines: string[];
  next_cursor?: number;
  exhausted: boolean;
  truncated: boolean;
}

export interface ProtocolEnvelope {
  protocol: string;
  message_id: string;
  type: string;
  device_id: string;
  correlation_id?: string | null;
  seq: number;
  sent_at: string;
  expires_at?: string | null;
  payload: Record<string, unknown>;
}
