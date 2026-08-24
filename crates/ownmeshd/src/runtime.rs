//! Policy-gated operation runtime for ownmeshd.
//!
//! Flow: classify facts → evaluate policy (+ grants / lockdown) →
//! allow execute | ask enqueue | deny. Completed results are journaled by
//! idempotency key so duplicate operations are not re-executed.

#![allow(
    clippy::doc_markdown,
    clippy::io_other_error,
    clippy::map_unwrap_or,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    clippy::unnested_or_patterns,
    clippy::unused_async,
    clippy::unused_self
)]

#[path = "broker_runtime.rs"]
mod broker_runtime;
#[path = "review_manifest.rs"]
mod review_manifest;
#[path = "runtime_fs.rs"]
mod runtime_fs;
#[path = "runtime_session.rs"]
mod runtime_session;
#[path = "runtime_transfer.rs"]
mod runtime_transfer;
#[path = "runtime_workspace.rs"]
mod runtime_workspace;
#[path = "structured_adapter.rs"]
mod structured_adapter;
#[cfg(target_os = "linux")]
use broker_runtime::load_linux_broker_client;
#[cfg(target_os = "macos")]
use broker_runtime::load_macos_broker_client;
#[cfg(windows)]
use broker_runtime::load_windows_broker_client;
#[cfg(windows)]
use ownmesh_broker_client::{
    build_cancel_intent_v2, connect_and_cancel_v2_windows, connect_and_execute_v2_windows,
    read_submitted_execute_v2_windows, submit_execute_v2_windows,
};
use ownmesh_broker_client::{
    compute_execute_intent_mac_v2, BrokerV2ClientError, ExecutablePinV2, ExecuteIntentV2,
    OperationFactsV2, BROKER_PROTOCOL_V2, DEFAULT_CAPABILITY_TTL_SECS,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use ownmesh_broker_client::{connect_and_execute_v2, connect_and_execute_v2_cancellable};
use ownmesh_config::{load_policy, save_policy, OwnMeshPaths, PolicyFile};
use ownmesh_exec::{
    classify_from_request_in_dir, pin_executable, prepare_executable,
    prepare_executable_with_interpreter, resolve_executable_invocation_path,
    resolve_executable_path, run_prepared_command_cancellable, verify_executable_pin, CommandKind,
    ExecutablePin, IdempotencyJournal, RunRequest, RunResult, HARD_MAX_TIMEOUT_MS,
};
use ownmesh_fs::{
    git_diff, git_head_oid, git_status, looks_sensitive, GitDiffOpts, GitStatusOpts, WorkspaceRoot,
};
use ownmesh_ipc::{
    app_error, canonicalize_principal_key, is_credentialed_client_principal, is_human_os_principal,
    methods, read_management_credential, ClientIdentity, Endpoint, IpcBus, IpcError, IpcResult,
    MethodHandler, RevokedClients,
};
use ownmesh_logs::{
    register_builtin_providers, BuiltinProviderConfig, LogCursor, LogError, LogRegistry,
};
#[cfg(test)]
use ownmesh_policy::TemporaryGrant;
use ownmesh_policy::{
    canonical_bounded_tool, evaluate_with_grants, full_access_has_no_hidden_restrictive_rules,
    preset_document, temporary_grant_from_facts, temporary_grant_requires_operation_binding,
    AccessPreset, BoundedToolGrant, BoundedToolGrantType, Decision, ExecutableIdentityBinding,
    OperationFacts, PolicyDocument, PolicyRule, StoredGrant, MAX_BOUNDED_TOOL_GRANT_TTL_SECS,
    MAX_BOUNDED_TOOL_GRANT_USES, TAG_READS_SENSITIVE_LOCATION, TAG_WRITES_SENSITIVE_LOCATION,
};
use ownmesh_profiles::{
    official_adapter_spec, parse_adapter_event_page, AdapterDialect, NativeResume, ProfileRegistry,
    ProfileStatus,
};
use ownmesh_session::{PtyCommand, PtySize};
use ownmesh_session::{
    SessionKind, SessionManager, SessionState, SidecarHostBinding, StreamKind as SessionStreamKind,
};
use ownmesh_session_host::{
    default_shell_command, HostIoMode, LiveHost, OwnerSpool, SupervisorBinding, SupervisorClient,
    SupervisorCommand, SupervisorEnv, SupervisorSpawnRequest,
};
use ownmesh_transfer::{
    JournalLimits, JournalState, JournalStore, PartFileSink, PlanLimits, SourceCleanupBinding,
    TransferBinding, TransferChunk, TransferError, TransferGrant, TransferPlan, TransferReceiver,
    TransferSender, MAX_CHUNK_BYTES,
};
use ownmesh_transition_journal as session_transition_journal;
use ownmesh_transition_journal::{
    SessionTransitionJournal, TransitionKind, TransitionPhase, TransitionRecord, TransitionTarget,
};
use review_manifest::{
    ResultKind, ReviewCommand, ReviewManifest, ReviewManifestStore, ReviewPhase, ReviewResultChunk,
    ReviewResultStore, TestRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use structured_adapter::StructuredAdapterDriver;
use tokio::sync::{watch, Mutex};
use uuid::Uuid;

/// Session IPC method names (owned here; ipc crate methods table is ms1-stable).
pub mod session_methods {
    pub const OPEN: &str = "session.open";
    pub const LIST: &str = "session.list";
    pub const SHOW: &str = "session.show";
    pub const ATTACH: &str = "session.attach";
    pub const CLAIM: &str = "session.claim";
    pub const RENEW: &str = "session.renew";
    pub const DETACH: &str = "session.detach";
    pub const RELEASE: &str = "session.release";
    pub const GIVE: &str = "session.give";
    pub const CLOSE: &str = "session.close";
    pub const TERMINATE: &str = "session.terminate";
    pub const REPLAY: &str = "session.replay";
    pub const PUSH_OUTPUT: &str = "session.push_output";
    pub const WRITE: &str = "session.write";
    pub const RESIZE: &str = "session.resize";
}

/// Extra ops methods (owned here; keeps ownmesh-ipc ms1 method table stable).
pub mod ops_methods {
    pub const GIT_STATUS: &str = "ops.git.status";
    pub const GIT_DIFF: &str = "ops.git.diff";
    pub const REVIEW_START: &str = "ops.review.start";
    pub const REVIEW_SHOW: &str = "ops.review.show";
    pub const REVIEW_PAGE: &str = "ops.review.page";
    pub const LOGS_LIST_PROVIDERS: &str = "ops.logs.list_providers";
    pub const WORKSPACE_LIST: &str = "ops.workspace.list";
    pub const WORKSPACE_SHOW: &str = "ops.workspace.show";
    pub const WORKSPACE_ADD: &str = "ops.workspace.add";
    pub const WORKSPACE_UPDATE: &str = "ops.workspace.update";
    pub const WORKSPACE_REMOVE: &str = "ops.workspace.remove";
    pub const SYSTEM_DIAGNOSE: &str = "ops.system.diagnose";
}

const LOCAL_PRINCIPAL: &str = "prin_local";
const DEFAULT_GRANT_SECS: i64 = 3600;
const OP_JOURNAL_STATE_FIELD: &str = "__ownmesh_operation_state";
const OP_JOURNAL_IN_PROGRESS: &str = "in_progress";

fn review_page_limit() -> usize {
    48 * 1024
}

/// Keep the JSON-encoded spool well below its owner-only file cap. Results are
/// bytes serialized as JSON arrays, so the raw byte ceiling cannot be the disk
/// ceiling. A visible terminal chunk records any omitted tail.
const REVIEW_CAPTURE_BYTES: usize = 160 * 1024;
const REVIEW_CONTENT_BYTES: usize = 140 * 1024;

fn append_review_result(
    chunks: &mut Vec<ReviewResultChunk>,
    kind: ResultKind,
    test_index: Option<u8>,
    bytes: Vec<u8>,
) {
    if chunks.len() >= 60 {
        return;
    }
    let used: usize = chunks.iter().map(|chunk| chunk.bytes.len()).sum();
    // Reserve terminal/system space so aggregate truncation can never be silent.
    let room = REVIEW_CONTENT_BYTES.saturating_sub(used);
    if room == 0 {
        return;
    }
    let take = bytes.len().min(room);
    for part in bytes[..take].chunks(64 * 1024) {
        chunks.push(ReviewResultChunk {
            kind: kind.clone(),
            test_index,
            bytes: part.to_vec(),
        });
    }
    if take < bytes.len() {
        append_review_system(
            chunks,
            format!(
                "review output truncated: omitted {} bytes",
                bytes.len() - take
            ),
        );
    }
}

fn append_review_system(chunks: &mut Vec<ReviewResultChunk>, text: String) {
    if chunks.len() >= 64 {
        return;
    }
    let used: usize = chunks.iter().map(|chunk| chunk.bytes.len()).sum();
    let room = REVIEW_CAPTURE_BYTES.saturating_sub(used);
    if room == 0 {
        return;
    }
    let bytes = text.into_bytes();
    chunks.push(ReviewResultChunk {
        kind: ResultKind::System,
        test_index: None,
        bytes: bytes[..bytes.len().min(room).min(64 * 1024)].to_vec(),
    });
}

fn format_run_summary(label: &str, result: &RunResult) -> String {
    format!(
        "{label}: exit={:?} timeout={} truncated={} duration_ms={}",
        result.exit_code, result.timed_out, result.truncated, result.duration_ms
    )
}

/// Pending or decided approval tied to a deferred operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub id: String,
    pub operation_id: String,
    pub capability: String,
    pub state: String,
    pub reason: String,
    pub created_at_unix: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at_unix: Option<i64>,
    /// Absolute unix expiry inherited from the remote MCP operation (when any).
    /// Recovery approvals after this instant fail closed and never execute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<i64>,
    /// Server-computed payload_hash of the original exact action (when remote).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_payload_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule_id: Option<String>,
    /// Authenticated principal that enqueued the deferred operation (server-assigned).
    #[serde(default)]
    pub requester_principal: String,
    /// Policy facts snapshot captured at enqueue (capability/kind/program/path/…).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facts: Option<OperationFacts>,
    /// Serialized original request params.
    pub request: PendingRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Principal that decided the approval (human OS user only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by_principal: Option<String>,
}

/// Deferred request body stored until approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum PendingRequest {
    Exec(Box<ExecParams>),
    FsList(FsListParams),
    FsStat(FsStatParams),
    FsRead(FsReadParams),
    FsWrite(FsWriteParams),
    FsDelete(FsDeleteParams),
    LogsQuery(LogsQueryParams),
    GitStatus(GitStatusParams),
    GitDiff(GitDiffParams),
    SystemDiagnose(SystemDiagnoseParams),
    AdminPolicyPreset(AdminPolicyPresetParams),
    AdminPolicyRuleAdd(AdminPolicyRuleAddParams),
    AdminPolicyRuleRemove(AdminPolicyRuleRemoveParams),
    AdminDaemonUnlock(AdminDaemonUnlockParams),
    AdminTokenRevoke(AdminTokenRevokeParams),
    AdminApprovalBridge(AdminApprovalBridgeParams),
    AdminGrantsMint(AdminGrantsMintParams),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemDiagnoseParams {
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminPolicyPresetParams {
    pub name: String,
    #[serde(default)]
    pub delegate_remote_mcp: Option<bool>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminPolicyRuleAddParams {
    pub id: String,
    pub decision: Decision,
    pub capability: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub when_elevated: Option<bool>,
    #[serde(default)]
    pub when_kind: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub program_equals: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub idempotency_key: String,
}

impl AdminPolicyRuleAddParams {
    fn rule(&self) -> PolicyRule {
        PolicyRule {
            id: self.id.clone(),
            decision: self.decision,
            priority: self.priority,
            capability: self.capability.clone(),
            when_elevated: self.when_elevated,
            when_kind: self.when_kind.clone(),
            path_prefix: self.path_prefix.clone(),
            program_equals: self.program_equals.clone(),
            when_tag: None,
            description: self.description.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminPolicyRuleRemoveParams {
    pub id: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminDaemonUnlockParams {
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminTokenRevokeParams {
    pub principal: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminApprovalBridgeParams {
    pub approval_id: String,
    pub decision: String,
    #[serde(default)]
    pub temporary_grant: bool,
    #[serde(default)]
    pub grant_seconds: Option<i64>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminGrantsMintParams {
    pub tools: Vec<String>,
    pub ttl_seconds: i64,
    #[serde(default)]
    pub max_uses: Option<u32>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    pub idempotency_key: String,
    /// Server-stamped at enqueue from the verified remote principal.
    /// Client-supplied values are overwritten and never treated as authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    /// Server-stamped at enqueue from the verified remote device id.
    /// Client-supplied values are overwritten and never treated as authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecParams {
    #[serde(default)]
    pub kind: Option<String>,
    /// Server-computed policy classification persisted with deferred approvals.
    /// Client values are always overwritten in `handle_exec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_kind: Option<String>,
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    /// Registered device workspace id (cwd context / audit; confinement gate).
    #[serde(default)]
    pub workspace_id: Option<String>,
    /// Optional bounded environment overlay (exact-action / policy fact).
    /// Keys/values are validated before spawn; never trusted as authority alone.
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub max_output_bytes: Option<usize>,
    #[serde(default)]
    pub elevated: bool,
    /// MCP `detach: true`: no wall-clock process timeout; concurrent jobs are bounded.
    #[serde(default)]
    pub detach: bool,
    /// Server-computed executable identity pin (device/inode/digest). Client values overwritten.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_pin: Option<ExecutablePin>,
    /// Server-computed pin of the *invocation* path (resolved but not
    /// canonicalized, e.g. `~/.cargo/bin/cargo` for a rustup proxy symlink).
    /// Proxy executables dispatch on their argv[0] filename, so the spawn
    /// must keep the invocation path while identity pinning uses the
    /// canonical backing path; the two pins together catch a retargeted
    /// symlink between approval and spawn (P0-B review). Client values
    /// overwritten; absent for raw-shell/legacy requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_pin: Option<ExecutablePin>,
    /// Server-computed identity of the platform shell used for raw-shell
    /// requests. The command text remains in `program`; the prepared shell
    /// object is the only image authorized to interpret it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_pin: Option<ExecutablePin>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsListParams {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub max_entries: Option<usize>,
    /// Stable name-ordered exclusive lower-bound cursor from a prior page.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Registered device workspace id (default when omitted).
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsStatParams {
    pub path: String,
    #[serde(default)]
    pub hash: bool,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsReadParams {
    pub path: String,
    #[serde(default)]
    pub max_bytes: Option<u64>,
    /// Byte offset for bounded range reads (E2).
    #[serde(default)]
    pub offset: Option<u64>,
    /// Exact byte continuation token returned by a prior read (`off_N`).
    ///
    /// The control plane forwards MCP cursors unchanged, so the daemon owns
    /// validation and normalization into `offset` before policy/IO execution.
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsWriteParams {
    pub path: String,
    /// UTF-8 text body (binary via base64 can land later).
    pub content: String,
    /// When set, refuse the write unless the current file hash matches (fs.patch).
    #[serde(default)]
    pub expected_sha256: Option<String>,
    /// Patch format: `replace` (default whole-file) or `unified` (bounded unified diff).
    /// When omitted, content that looks like a unified diff is applied as unified.
    #[serde(default)]
    pub patch_format: Option<String>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsDeleteParams {
    pub path: String,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone)]
struct TransferAuthority {
    tenant_id: String,
    principal_id: String,
    device_id: String,
    operation_id: String,
    payload_sha256: String,
    expires_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogsQueryParams {
    #[serde(default = "default_log_provider")]
    pub provider: String,
    #[serde(default)]
    pub cursor_offset: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    /// Windows Event Log channel (default Application).
    #[serde(default)]
    pub channel: Option<String>,
    /// journald `--unit` filter.
    #[serde(default)]
    pub unit: Option<String>,
    /// Docker/Podman container name or id.
    #[serde(default)]
    pub container: Option<String>,
}

const MAX_LOG_QUERY_LIMIT: usize = 200;

fn default_log_provider() -> String {
    "audit".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitStatusParams {
    /// Workspace-relative path to the repository (default: workspace root).
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub cursor: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitDiffParams {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub pathspec: Option<String>,
    #[serde(default)]
    pub staged: bool,
    #[serde(default)]
    pub cursor: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub max_bytes: Option<usize>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditEntry {
    id: String,
    event_type: String,
    created_at_unix: i64,
    capability: Option<String>,
    operation_id: Option<String>,
    decision: Option<String>,
    detail: String,
}

/// One registered device-local workspace root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceEntry {
    pub id: String,
    /// Absolute filesystem root for this workspace.
    pub root: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Opaque, device-local mapping generation. It changes whenever this id is
    /// rebound to another root and is the only mapping fact sent off-device.
    #[serde(default)]
    pub generation: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RemoteWorkspaceRegistration {
    pub id: String,
    pub generation: String,
}

fn new_workspace_generation() -> String {
    format!("wsg_{}", Uuid::new_v4().simple())
}

fn valid_workspace_generation(value: &str) -> bool {
    value.len() == 36
        && value.starts_with("wsg_")
        && value[4..]
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkspaceRegistryFile {
    schema_version: u32,
    workspaces: Vec<WorkspaceEntry>,
}

/// Shared daemon operation state.
#[allow(clippy::struct_excessive_bools)]
pub struct DaemonRuntime {
    paths: OwnMeshPaths,
    policy: PolicyDocument,
    /// User-authored bounded overlay persisted in policy.toml. Kept separate
    /// from built-in preset rules so preset replacement and rule removal are exact.
    custom_policy_rules: Vec<PolicyRule>,
    /// Explicit local setup choice: authenticated, exact-bound remote MCP
    /// invocation may satisfy a policy Ask. Defaults fail-closed to false.
    delegate_remote_mcp: bool,
    grants: Vec<StoredGrant>,
    pub(crate) approvals: HashMap<String, ApprovalRecord>,
    /// Completed operation results keyed by client idempotency key.
    op_journal: HashMap<String, Value>,
    /// Set when `op-journal.json` could not be loaded/compacted/persisted.
    /// Side-effect operations are refused; reads stay up. Never treated as a
    /// healthy empty journal.
    op_journal_degraded: Option<String>,
    exec_journal: IdempotencyJournal,
    lockdown: bool,
    revoked_clients: RevokedClients,
    audit: Vec<AuditEntry>,
    /// Default workspace root (also present as id=`ws_default` in the registry).
    #[allow(dead_code)]
    workspace_root: PathBuf,
    /// Device-owned workspace registry (id → root). Selection is authoritative
    /// for restricted modes; Full Access still uses the selected root as cwd/context.
    workspaces: Vec<WorkspaceEntry>,
    #[allow(dead_code)]
    workspaces_path: PathBuf,
    enforce_workspace: bool,
    log_path: PathBuf,
    sessions: SessionManager,
    sessions_path: PathBuf,
    /// Process-local live PTY hosts keyed by session id (not persisted).
    /// Metadata/leases survive restart; live hosts are re-created only on open.
    live_hosts: HashMap<String, LiveHost>,
    /// Dedicated local-only proxy for remote/cloud PTY sessions. Local CLI
    /// compatibility keeps the legacy embedded host path until fully migrated.
    supervisor: Option<SupervisorClient>,
    transition_journal: SessionTransitionJournal,
    /// Bounded health state for transition-journal recovery (P0-A). Records
    /// that expired with the session still present and non-terminal are
    /// retained fail-closed and surfaced here instead of poisoning unrelated
    /// future sessions.
    transition_recovery_health: TransitionRecoveryHealth,
    review_manifests: ReviewManifestStore,
    review_results: ReviewResultStore,
    transition_recovery_running: bool,
    /// Optional cancel signal for the currently executing remote command.
    /// Lives only for the duration of `dispatch_cancellable`.
    active_cancel: Option<watch::Receiver<bool>>,
    /// Remote MCP/control-plane operation id for the active dispatch (when any).
    /// Ask/allow receipts must echo this id so DeviceRoom correlation binding holds.
    active_remote_operation_id: Option<String>,
    /// Bound expiry (unix seconds) of the active remote operation, if any.
    active_remote_expires_at_unix: Option<i64>,
    /// Server payload_hash of the active remote exact action, if any.
    active_remote_payload_hash: Option<String>,
    /// Verified Agent device identity for the active remote dispatch only.
    /// This is never populated from MCP arguments or local IPC parameters.
    active_remote_device_id: Option<String>,
    /// Verified remote caller key. Never copied from command parameters.
    active_remote_principal: Option<String>,
    /// Server-derived credential generation bound into the exact remote action.
    /// Missing is intentionally not synthesized or hashed.
    active_remote_principal_credential_generation: Option<u64>,
    /// Owner-only immutable plans and receiver progress.  The sender itself is
    /// intentionally ephemeral; after a restart the authenticated caller must
    /// reopen it at the durable receiver cursor.
    transfer_store: JournalStore,
    transfer_senders: HashMap<String, TransferSender>,
    /// Last returned chunk gives an at-least-once caller a bounded replay window
    /// without advancing the source stream twice after a lost response.
    transfer_last_chunks: HashMap<String, (u64, String)>,
    /// Process-local destination streams. The durable journal remains the
    /// authority; this cache only preserves the rolling hash and generation
    /// part handle between contiguous chunks so an N-chunk transfer does not
    /// rehash its entire prefix N times. It is bounded by the immutable-plan
    /// quota and disappears naturally on restart.
    transfer_receivers: HashMap<String, CachedDestinationTransfer>,
    #[cfg(test)]
    op_journal_persist_fault: AtomicUsize,
    #[cfg(test)]
    op_journal_write_fault: AtomicUsize,
    #[cfg(test)]
    approvals_persist_fault: AtomicUsize,
    #[cfg(test)]
    sessions_persist_fault: AtomicUsize,
    #[cfg(test)]
    transfer_journal_persist_fault: AtomicUsize,
    #[cfg(test)]
    transfer_receiver_rebuilds: AtomicUsize,
}

const MAX_CACHED_DESTINATION_TRANSFERS: usize = 256;
/// Concurrent detached `command.run` jobs per daemon. Fail-closed when full.
const MAX_DETACHED_COMMANDS: usize = 4;
static DETACHED_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

struct DetachedCommandGuard;

impl Drop for DetachedCommandGuard {
    fn drop(&mut self) {
        DETACHED_IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
    }
}

fn journal_degraded_error(reason: &str) -> IpcError {
    IpcError::Remote {
        code: app_error::CONFLICT,
        message: format!(
            "OWNMESH_E_JOURNAL_DEGRADED: side effects are refused because the op-journal could not be loaded ({reason}). Repair locally with `ownmesh doctor --repair-journal --i-understand-replay-risk` then restart ownmeshd"
        ),
    }
}

fn pending_request_is_journal_read_only(request: &PendingRequest) -> bool {
    matches!(
        request,
        PendingRequest::FsList(_)
            | PendingRequest::FsStat(_)
            | PendingRequest::FsRead(_)
            | PendingRequest::LogsQuery(_)
            | PendingRequest::GitStatus(_)
            | PendingRequest::GitDiff(_)
            | PendingRequest::SystemDiagnose(_)
    )
}

fn acquire_detached_slot() -> IpcResult<DetachedCommandGuard> {
    loop {
        let n = DETACHED_IN_FLIGHT.load(Ordering::SeqCst);
        if n >= MAX_DETACHED_COMMANDS {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!(
                    "detached command cap reached ({MAX_DETACHED_COMMANDS}); wait for an in-flight detached job to finish or cancel one"
                ),
            });
        }
        if DETACHED_IN_FLIGHT
            .compare_exchange(n, n + 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Ok(DetachedCommandGuard);
        }
    }
}

struct CachedDestinationTransfer {
    epoch: u64,
    fence: u64,
    receiver: TransferReceiver,
    sink: PartFileSink,
}

impl CachedDestinationTransfer {
    fn matches(&self, epoch: u64, fence: u64, journal: &ownmesh_transfer::TransferJournal) -> bool {
        self.epoch == epoch && self.fence == fence && self.receiver.journal() == journal
    }
}

impl DaemonRuntime {
    /// Bootstrap runtime from discovered / test paths.
    pub fn open(paths: &OwnMeshPaths) -> Result<Self, String> {
        paths.ensure_layout().map_err(|e| e.to_string())?;
        // Fail closed: recover any interrupted config+policy journal before policy is consumed.
        // load_policy performs mandatory recovery under the exclusive transaction lock.
        let journal_path = paths.state_dir.join("idempotency-journal.json");
        let exec_journal = IdempotencyJournal::open(&journal_path).map_err(|e| e.to_string())?;
        let policy_file = load_policy(paths).map_err(|e| {
            format!("policy load failed (refusing startup; config+policy journal preserved on recovery failure): {e}")
        })?;
        let policy = policy_from_file(&policy_file);
        let custom_policy_rules = policy_file.rules.clone();
        let delegate_remote_mcp = policy_file.delegate_remote_mcp;
        let enforce_workspace = matches!(
            policy.preset,
            AccessPreset::WorkspaceOnly | AccessPreset::Recommended
        );
        let workspace_root = paths.state_dir.join("workspace");
        std::fs::create_dir_all(&workspace_root).map_err(|e| e.to_string())?;
        let workspaces_path = paths.state_dir.join("workspaces.json");
        let workspaces = load_or_init_workspaces(&workspaces_path, &workspace_root)?;
        let log_path = paths.state_dir.join("logs").join("audit.log");
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        if !log_path.exists() {
            std::fs::write(&log_path, b"").map_err(|e| e.to_string())?;
        }
        let (op_journal, op_journal_degraded) =
            match load_op_journal(&paths.state_dir.join("op-journal.json")) {
                Ok(journal) => (journal, None),
                Err(reason) => (HashMap::new(), Some(reason)),
            };
        let grants = load_grants(&paths.state_dir.join("grants.json"))?;
        let approvals = load_approvals(&paths.state_dir.join("approvals.json"))?;
        let lockdown = paths.state_dir.join("lockdown.flag").exists();
        let revoked_clients = Arc::new(RwLock::new(load_revoked(
            &paths.state_dir.join("revoked-clients.json"),
        )?));
        let sessions_path = paths.state_dir.join("sessions").join("sessions.json");
        let transition_journal =
            SessionTransitionJournal::open(paths.state_dir.join("session-transitions"))?;
        let review_manifests = ReviewManifestStore::open(paths.state_dir.join("reviews"))?;
        let review_results =
            ReviewResultStore::open(paths.state_dir.join("reviews").join("results"))?;
        let mut sessions = SessionManager::load_from_path(&sessions_path).map_err(|e| {
            format!(
                "failed to load sessions from {}: {e}",
                sessions_path.display()
            )
        })?;
        let had_sessions = !sessions.list().is_empty();
        let _ = sessions.mark_hosts_detached_after_restart();
        let _ = reconcile_dead_persistent_sessions(
            &mut sessions,
            &paths.state_dir.join("session-supervisor"),
        );
        if had_sessions {
            sessions.save_to_path(&sessions_path).map_err(|e| {
                format!(
                    "failed to persist restarted sessions to {}: {e}",
                    sessions_path.display()
                )
            })?;
        }
        let transfer_store =
            JournalStore::open(paths.state_dir.join("transfers"), JournalLimits::default())
                .map_err(|error| format!("open transfer state: {error}"))?;
        transfer_store
            .cleanup_expired(Self::now() as u64)
            .map_err(|error| format!("cleanup transfer state: {error}"))?;
        Ok(Self {
            paths: paths.clone(),
            policy,
            custom_policy_rules,
            delegate_remote_mcp,
            grants,
            approvals,
            op_journal,
            op_journal_degraded,
            exec_journal,
            lockdown,
            revoked_clients,
            audit: Vec::new(),
            workspace_root,
            workspaces,
            workspaces_path,
            enforce_workspace,
            log_path,
            sessions,
            sessions_path,
            live_hosts: HashMap::new(),
            supervisor: None,
            transition_journal,
            transition_recovery_health: TransitionRecoveryHealth::default(),
            review_manifests,
            review_results,
            transition_recovery_running: false,
            active_cancel: None,
            active_remote_operation_id: None,
            active_remote_expires_at_unix: None,
            active_remote_payload_hash: None,
            active_remote_device_id: None,
            active_remote_principal: None,
            active_remote_principal_credential_generation: None,
            transfer_store,
            transfer_senders: HashMap::new(),
            transfer_last_chunks: HashMap::new(),
            transfer_receivers: HashMap::new(),
            #[cfg(test)]
            op_journal_persist_fault: AtomicUsize::new(0),
            #[cfg(test)]
            op_journal_write_fault: AtomicUsize::new(0),
            #[cfg(test)]
            approvals_persist_fault: AtomicUsize::new(0),
            #[cfg(test)]
            sessions_persist_fault: AtomicUsize::new(0),
            #[cfg(test)]
            transfer_journal_persist_fault: AtomicUsize::new(0),
            #[cfg(test)]
            transfer_receiver_rebuilds: AtomicUsize::new(0),
        })
    }

    /// Shared handle used by the IPC server for hello/dispatch revocation checks.
    #[must_use]
    pub fn revoked_clients_handle(&self) -> RevokedClients {
        Arc::clone(&self.revoked_clients)
    }

    fn is_client_revoked(&self, principal_key: &str) -> bool {
        let principal_key = canonicalize_principal_key(principal_key);
        if principal_key.is_empty() {
            return true;
        }
        self.revoked_clients
            .read()
            .map(|guard| {
                guard
                    .iter()
                    .any(|stored| canonicalize_principal_key(stored) == principal_key)
            })
            // A poisoned revocation lock must never re-enable a revoked principal.
            .unwrap_or(true)
    }

    fn persist_sessions(&self) -> IpcResult<()> {
        #[cfg(test)]
        self.maybe_inject_persist_fault(&self.sessions_persist_fault, "session")?;
        self.sessions
            .save_to_path(&self.sessions_path)
            .map_err(|e| IpcError::Remote {
                code: app_error::INTERNAL,
                message: format!("session persist failed: {e}"),
            })
    }

    fn persist_op_journal(&self) -> IpcResult<()> {
        if let Some(reason) = &self.op_journal_degraded {
            return Err(journal_degraded_error(reason));
        }
        #[cfg(test)]
        self.maybe_inject_persist_fault(&self.op_journal_persist_fault, "op journal")?;
        // Completed entries are compacted to exact-once receipts before
        // durable persistence (P0-B): large stdout/file bodies are never
        // retained in durable state when a compact receipt is sufficient.
        // In-progress/uncertain markers are never compacted.
        let durable = op_journal_durable_view(&self.op_journal);
        let encoded = serde_json::to_vec_pretty(&durable).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: format!("failed to serialize op journal: {e}"),
        })?;
        if encoded.len() > MAX_OP_JOURNAL_FILE_BYTES {
            return Err(IpcError::Remote {
                code: app_error::INTERNAL,
                message: format!(
                    "op journal exceeds {MAX_OP_JOURNAL_FILE_BYTES} durable byte budget"
                ),
            });
        }
        if self.op_journal.len() > MAX_OP_JOURNAL_ENTRIES {
            return Err(IpcError::Remote {
                code: app_error::INTERNAL,
                message: format!("op journal exceeds {MAX_OP_JOURNAL_ENTRIES} entry budget"),
            });
        }
        let primary = self.paths.state_dir.join("op-journal.json");
        // P0-B review: remove a stale backup *before* the compacted write so
        // a crash between the write and the cleanup cannot leave a legacy
        // large-body copy on disk while the daemon is stopped. The primary is
        // authoritative and the write recreates it from the in-memory durable
        // view, so the stale duplicate can be removed first. When the primary
        // is missing (external removal while the daemon runs) the backup is
        // the only durable copy of the exact-once receipts, so it is kept
        // until the write succeeds (fail-closed: never destroy the only copy
        // before a replacement is durable).
        //
        // P0-B review: the stale backup may hold the pre-compaction legacy
        // journal with large stdout/file bodies. This persist must fail
        // closed (rolling back the in-memory mutation in `store_idempotent`/
        // `begin_idempotent`) instead of claiming compaction succeeded while
        // the sensitive copy remains on disk — the same fail-closed contract
        // as the load path (which starts degraded read-only). The operator resolves the
        // lock/permission and retries; doctor surfaces the backup while it
        // exists.
        if primary.exists() {
            remove_stale_op_journal_backup_fallible(&primary).map_err(|e| IpcError::Remote {
                code: app_error::INTERNAL,
                message: format!(
                    "failed to remove stale op journal backup {} before writing the compacted \
primary: {e}; remove or repair the backup (it may hold a legacy large-body journal) and \
retry — refusing the persist rather than claiming compaction succeeded while the copy remains",
                    stale_op_journal_backup_path(&primary).display(),
                ),
            })?;
        }
        // P0-B review: fault injection point *after* the stale-backup removal
        // and *before* the write, so a test can prove the removal happens
        // before the write (a crash between the write and the cleanup cannot
        // leave a legacy large-body copy behind).
        #[cfg(test)]
        self.maybe_inject_persist_fault(&self.op_journal_write_fault, "op journal write")?;
        write_op_journal(&primary, &durable).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: format!("failed to persist op journal: {e}"),
        })?;
        // The no-backup writer never creates a `.bak`, so any `op-journal.json.bak`
        // left by an older version (or a crash between its backup copy and cleanup)
        // is now stale by definition. Retry its removal on every successful persist
        // so a transient lock (Windows file handle, antivirus scan) does not retain
        // the pre-compaction large-body journal indefinitely (P0-B review). A
        // lingering backup is surfaced by doctor while it exists.
        remove_stale_op_journal_backup(&primary);
        Ok(())
    }

    /// Estimate of the durable (compacted) op-journal size in bytes.
    ///
    /// P0-B: the estimate must match the durable file exactly — the same
    /// pretty-serialized view `persist_op_journal` writes — so eviction and
    /// diagnostics never under-report pressure against the real
    /// [`MAX_OP_JOURNAL_FILE_BYTES`] budget. A per-entry sum that omits JSON
    /// framing and pretty-print overhead would let the real file hit the
    /// hard cap while the estimate still reports headroom, refusing new
    /// side-effect operations without evicting eligible old receipts first.
    fn op_journal_durable_byte_estimate(&self) -> usize {
        let durable = op_journal_durable_view(&self.op_journal);
        serde_json::to_vec_pretty(&durable)
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX)
    }

    /// Bounded lifecycle for terminal receipts (P0-B): when at capacity,
    /// evict only completed entries older than [`OP_JOURNAL_COMPLETED_TTL_SECS`].
    /// In-progress/uncertain markers are never evicted. Persist failure rolls
    /// back the in-memory eviction so the durable file stays authoritative.
    fn evict_expired_completed_op_journal_entries(&mut self) -> IpcResult<usize> {
        let now = Self::now();
        let snapshot = self.op_journal.clone();
        let before = self.op_journal.len();
        self.op_journal.retain(|_, value| {
            if op_journal_entry_state(value) != OpJournalEntryState::Completed {
                // Exact-once marker or unknown state: never pruned, regardless
                // of age (fail-closed: an uncertain outcome must not become
                // retriable).
                return true;
            }
            match value
                .get(OP_JOURNAL_COMPLETED_UNIX_FIELD)
                .and_then(Value::as_i64)
            {
                Some(stamp) if stamp > 0 => {
                    now.saturating_sub(stamp) < OP_JOURNAL_COMPLETED_TTL_SECS
                }
                // Unknown age (legacy) — keep fail-closed.
                _ => true,
            }
        });
        let evicted = before - self.op_journal.len();
        if evicted == 0 {
            return Ok(0);
        }
        if let Err(e) = self.persist_op_journal() {
            self.op_journal = snapshot;
            return Err(e);
        }
        Ok(evicted)
    }

    /// Make durable room before reserving a new idempotency key: evict only
    /// old completed receipts; if nothing is evictable the caller's capacity
    /// check fails closed (no new side effects accepted).
    ///
    /// P0-B review (near-capacity behavior): eviction must trigger BEFORE the
    /// incoming in-progress marker is inserted, not only when the journal is
    /// already at the byte cap. Inserting the marker can otherwise push the
    /// serialized durable file over `MAX_OP_JOURNAL_FILE_BYTES` and make
    /// `persist_op_journal` refuse the operation even though expired completed
    /// receipts were evictable — refusing new side effects safely, but
    /// defeating the bounded-lifecycle intent (long-lived normal operation
    /// should stay away from the cap by pruning old terminal receipts). The
    /// projected size is the same pretty-serialized durable view the writer
    /// persists, plus the new marker entry, so the estimate never under-reports
    /// against the real budget.
    fn maybe_make_op_journal_room(&mut self, key: &str, operation_id: &str) -> IpcResult<()> {
        // Project the durable view with the incoming in-progress marker
        // inserted. The marker is the exact shape `begin_idempotent` writes
        // (including the real operation_id), so the projection is
        // byte-accurate against the writer's serialization.
        let mut projected = self.op_journal.clone();
        projected.insert(
            key.to_string(),
            json!({
                OP_JOURNAL_STATE_FIELD: OP_JOURNAL_IN_PROGRESS,
                "operation_id": operation_id,
            }),
        );
        let projected_bytes = serde_json::to_vec_pretty(&op_journal_durable_view(&projected))
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX);
        let at_byte_cap = projected_bytes >= MAX_OP_JOURNAL_FILE_BYTES;
        if self.op_journal.len() < MAX_OP_JOURNAL_ENTRIES && !at_byte_cap {
            return Ok(());
        }
        self.evict_expired_completed_op_journal_entries()?;
        Ok(())
    }

    fn persist_approvals(&self) -> IpcResult<()> {
        #[cfg(test)]
        self.maybe_inject_persist_fault(&self.approvals_persist_fault, "approvals")?;
        write_json(
            &self.paths.state_dir.join("approvals.json"),
            &self.approvals,
        )
        .map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: format!("failed to persist approvals: {e}"),
        })
    }

    #[cfg(test)]
    fn maybe_inject_persist_fault(&self, countdown: &AtomicUsize, target: &str) -> IpcResult<()> {
        let decremented = countdown.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
            if remaining > 0 {
                Some(remaining - 1)
            } else {
                None
            }
        });
        if matches!(decremented, Ok(1)) {
            return Err(IpcError::Remote {
                code: app_error::INTERNAL,
                message: format!("fault-injected {target} persist failure"),
            });
        }
        Ok(())
    }

    fn persist_grants(&self) -> IpcResult<()> {
        write_json(&self.paths.state_dir.join("grants.json"), &self.grants).map_err(|e| {
            IpcError::Remote {
                code: app_error::INTERNAL,
                message: format!("failed to persist grants: {e}"),
            }
        })
    }

    fn persist_lockdown(&self) -> IpcResult<()> {
        let flag = self.paths.state_dir.join("lockdown.flag");
        if self.lockdown {
            // Atomic create/replace so a failed write cannot leave a torn flag.
            ownmesh_config::atomic_write(&flag, b"1").map_err(|e| IpcError::Remote {
                code: app_error::INTERNAL,
                message: format!("failed to persist lockdown flag: {e}"),
            })
        } else {
            match std::fs::remove_file(&flag) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("failed to clear lockdown flag: {e}"),
                }),
            }
        }
    }

    fn persist_revoked(&self) -> IpcResult<()> {
        let guard = self.revoked_clients.read().map_err(|_| IpcError::Remote {
            code: app_error::INTERNAL,
            message: "revoked clients lock poisoned".into(),
        })?;
        let mut canonical = HashSet::with_capacity(guard.len());
        for stored in guard.iter() {
            let principal = canonicalize_principal_key(stored);
            if principal.is_empty() {
                return Err(IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: "revoked clients contain an empty canonical principal".into(),
                });
            }
            canonical.insert(principal);
        }
        let mut list: Vec<String> = canonical.into_iter().collect();
        list.sort();
        write_json(&self.paths.state_dir.join("revoked-clients.json"), &list).map_err(|e| {
            IpcError::Remote {
                code: app_error::INTERNAL,
                message: format!("failed to persist revoked clients: {e}"),
            }
        })
    }

    /// Commit session manager mutations; restore `snapshot` if disk persist fails.
    fn commit_sessions(&mut self, snapshot: SessionManager) -> IpcResult<()> {
        if let Err(e) = self.persist_sessions() {
            self.sessions = snapshot;
            return Err(e);
        }
        Ok(())
    }

    /// Clear only persistent-session records whose stored process identity is
    /// provably gone.  Identity probe failures and legacy rows without a
    /// birth witness remain visible rather than being falsely terminalized.
    fn reconcile_dead_persistent_sessions(&mut self) -> IpcResult<usize> {
        let snapshot = self.sessions.clone();
        let reconciled = reconcile_dead_persistent_sessions(
            &mut self.sessions,
            &self.paths.state_dir.join("session-supervisor"),
        );
        if reconciled == 0 {
            return Ok(0);
        }
        self.commit_sessions(snapshot)?;
        Ok(reconciled)
    }

    fn close_persistent_session_record(&mut self, session_id: &str) -> IpcResult<()> {
        let snapshot = self.sessions.clone();
        self.sessions.close(session_id).map_err(session_err)?;
        self.sessions
            .set_sidecar_host_binding(session_id, None)
            .map_err(session_err)?;
        self.sessions
            .set_host_pid(session_id, None)
            .map_err(session_err)?;
        self.commit_sessions(snapshot)
    }

    /// Expire stale controller leases and persist demotions before session auth.
    ///
    /// Returns the clock sample used for subsequent lease checks. Persist failure
    /// rolls back in-memory demotions (fix-5 transaction convention).
    fn prepare_session_access(&mut self) -> IpcResult<i64> {
        let now = Self::now();
        let has_stale = self
            .sessions
            .list()
            .iter()
            .any(|info| info.controller.as_ref().is_some_and(|c| !c.is_active(now)));
        if !has_stale {
            return Ok(now);
        }
        let snapshot = self.sessions.clone();
        let n = self.sessions.expire_stale_leases(now);
        debug_assert!(n > 0, "stale lease detected but expire removed none");
        self.commit_sessions(snapshot)?;
        Ok(now)
    }

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Run the documented, bounded structured child bootstrap through the
    /// persistent supervisor.  The child owns no network listener; stdout is
    /// drained solely through the owner-only sidecar spool.
    async fn bootstrap_structured_adapter(
        supervisor: &SupervisorClient,
        binding: &SupervisorBinding,
        dialect: AdapterDialect,
        prompt: Option<&str>,
        native_session_id: Option<&str>,
        cwd: &str,
    ) -> IpcResult<Option<String>> {
        let mut driver = StructuredAdapterDriver::new(dialect, prompt, native_session_id, cwd)
            .map_err(|message| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message,
            })?;
        for request in driver.start().map_err(|message| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message,
        })? {
            supervisor
                .write(binding, request)
                .await
                .map_err(|err| IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: format!("structured adapter bootstrap write failed: {err}"),
                })?;
        }
        if driver.is_open_ready() {
            return Ok(driver.native_session_id().map(str::to_owned));
        }

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut cursor = 0_u64;
        let mut partial = Vec::new();
        while tokio::time::Instant::now() < deadline {
            let page = supervisor
                .drain_stream(binding, cursor, 64 * 1024, "stdout")
                .await
                .map_err(|err| IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: format!("structured adapter bootstrap drain failed: {err}"),
                })?;
            cursor = page.next_offset.unwrap_or(page.total_bytes);
            if page.bytes.is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                continue;
            }
            partial.extend_from_slice(&page.bytes);
            if partial.len() > structured_adapter::MAX_STRUCTURED_FRAME_BYTES {
                return Err(IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: "structured adapter emitted an overlong bootstrap record".into(),
                });
            }
            while let Some(end) = partial.iter().position(|byte| *byte == b'\n') {
                let record: Vec<_> = partial.drain(..=end).collect();
                for request in driver
                    .on_record(&record)
                    .map_err(|message| IpcError::Remote {
                        code: app_error::CONFLICT,
                        message,
                    })?
                {
                    supervisor
                        .write(binding, request)
                        .await
                        .map_err(|err| IpcError::Remote {
                            code: app_error::CONFLICT,
                            message: format!("structured adapter follow-up write failed: {err}"),
                        })?;
                }
                if driver.is_open_ready() {
                    return Ok(driver.native_session_id().map(str::to_owned));
                }
            }
        }
        Err(IpcError::Remote {
            code: app_error::CONFLICT,
            message: "structured adapter bootstrap timed out".into(),
        })
    }

    fn new_id(prefix: &str) -> String {
        format!("{prefix}{}", Uuid::new_v4().simple())
    }

    fn append_audit(
        &mut self,
        event_type: &str,
        capability: Option<&str>,
        operation_id: Option<&str>,
        decision: Option<&str>,
        detail: impl Into<String>,
    ) {
        let entry = AuditEntry {
            id: Self::new_id("aud_"),
            event_type: event_type.into(),
            created_at_unix: Self::now(),
            capability: capability.map(str::to_owned),
            operation_id: operation_id.map(str::to_owned),
            decision: decision.map(str::to_owned),
            detail: detail.into(),
        };
        let line = serde_json::to_string(&entry).unwrap_or_else(|_| "{}".into());
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .and_then(|mut f| {
                use std::io::Write;
                writeln!(f, "{line}")
            });
        self.audit.push(entry);
    }

    /// Resolve a registered workspace root by id (default → `ws_default`).
    ///
    /// Restricted modes pin and authorize against the selected root only.
    /// Unknown ids fail closed (never fall back to another tenant/device root).
    /// Ids follow the domain `ws_...` shape so they round-trip through the
    /// operation envelope `WorkspaceId` type.
    fn canonical_workspace_id(workspace_id: Option<&str>) -> IpcResult<String> {
        let raw = workspace_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("ws_default");
        // Accept legacy bare "default" as an alias for the built-in root.
        let id = if raw == "default" { "ws_default" } else { raw };
        if id.len() > 128
            || !id.starts_with("ws_")
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("invalid workspace_id: {id} (expected ws_... )"),
            });
        }
        Ok(id.to_owned())
    }

    /// Select the root used for a path operation without silently attributing
    /// an absolute Full Access path to `ws_default`. Relative local IPC keeps
    /// its single-workspace compatibility; multiple roots require a choice.
    fn workspace_id_for_path(
        &self,
        workspace_id: Option<&str>,
        path: &str,
    ) -> IpcResult<Option<String>> {
        if workspace_id.is_some_and(|id| !id.trim().is_empty()) {
            return Self::canonical_workspace_id(workspace_id).map(Some);
        }
        if Path::new(path).is_absolute() {
            if self.enforce_workspace {
                return Err(IpcError::Remote {
                    code: app_error::POLICY_DENIED,
                    message: "absolute paths without workspace_id require Full Access".into(),
                });
            }
            return Ok(None);
        }
        if self.workspaces.len() != 1 {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "workspace_id is required when more than one workspace is registered"
                    .into(),
            });
        }
        Self::canonical_workspace_id(
            self.workspaces
                .first()
                .map(|workspace| workspace.id.as_str()),
        )
        .map(Some)
    }

    fn workspace_for(&self, workspace_id: Option<&str>) -> IpcResult<WorkspaceRoot> {
        let id = Self::canonical_workspace_id(workspace_id)?;
        let entry = self
            .workspaces
            .iter()
            .find(|w| w.id == id || (id == "ws_default" && w.id == "default"))
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("unknown workspace_id: {id}"),
            })?;
        if !entry.root.exists() {
            std::fs::create_dir_all(&entry.root).map_err(|e| IpcError::Remote {
                code: app_error::INTERNAL,
                message: format!("workspace root missing and create failed: {e}"),
            })?;
        }
        WorkspaceRoot::new(&entry.root, self.enforce_workspace).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })
    }

    /// Id plus opaque local-generation registry advertised after the Agent has
    /// authenticated. Paths and labels remain device-local; the control plane
    /// uses this bounded snapshot only to scope custody to this exact device and
    /// preflight workspace policy.
    pub fn remote_workspace_registry(&self) -> (bool, Vec<RemoteWorkspaceRegistration>) {
        let mut registrations = self
            .workspaces
            .iter()
            .map(|workspace| RemoteWorkspaceRegistration {
                id: if workspace.id == "default" {
                    "ws_default".to_owned()
                } else {
                    workspace.id.clone()
                },
                generation: workspace.generation.clone(),
            })
            .collect::<Vec<_>>();
        registrations.sort_by(|a, b| a.id.cmp(&b.id));
        registrations.dedup_by(|a, b| a.id == b.id);
        (self.enforce_workspace, registrations)
    }

    /// Register or update a workspace root (device-local). Roots must be absolute
    /// existing directories. Does not cross-tenant; ownership is the device itself.
    pub fn upsert_workspace(&mut self, entry: WorkspaceEntry) -> IpcResult<WorkspaceEntry> {
        let id = entry.id.trim();
        if id.is_empty()
            || id.len() > 128
            || !id.starts_with("ws_")
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "invalid workspace id (expected ws_...)".into(),
            });
        }
        let root = if entry.root.is_absolute() {
            entry.root.clone()
        } else {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "workspace root must be absolute".into(),
            });
        };
        std::fs::create_dir_all(&root).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })?;
        let stored = WorkspaceEntry {
            id: id.to_owned(),
            root,
            label: entry.label.clone(),
            generation: String::new(),
        };
        if let Some(slot) = self.workspaces.iter_mut().find(|w| w.id == stored.id) {
            let generation = if slot.root == stored.root {
                slot.generation.clone()
            } else {
                new_workspace_generation()
            };
            *slot = WorkspaceEntry {
                generation,
                ..stored.clone()
            };
        } else {
            if self.workspaces.len() >= 64 {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "workspace registry full (max 64)".into(),
                });
            }
            self.workspaces.push(WorkspaceEntry {
                generation: new_workspace_generation(),
                ..stored.clone()
            });
        }
        self.persist_workspaces()?;
        self.workspaces
            .iter()
            .find(|workspace| workspace.id == id)
            .cloned()
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INTERNAL,
                message: "workspace persistence lost the updated entry".into(),
            })
    }

    fn persist_workspaces(&self) -> IpcResult<()> {
        let file = WorkspaceRegistryFile {
            schema_version: 1,
            workspaces: self.workspaces.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })?;
        if bytes.len() > 256 * 1024 {
            return Err(IpcError::Remote {
                code: app_error::INTERNAL,
                message: "workspaces.json exceeds 256 KiB budget".into(),
            });
        }
        let tmp = self.workspaces_path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })?;
        std::fs::rename(&tmp, &self.workspaces_path).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })?;
        Ok(())
    }

    fn check_lockdown(&self, method: &str) -> IpcResult<()> {
        // Local recovery methods remain available during lockdown.
        const ALLOWED: &[&str] = &[
            methods::DAEMON_UNLOCK,
            methods::ADMIN_DAEMON_UNLOCK_REQUEST,
            methods::DAEMON_LOCKDOWN,
            methods::APPROVAL_LIST,
            methods::APPROVAL_SHOW,
            methods::APPROVAL_APPROVE,
            methods::APPROVAL_DENY,
            methods::POLICY_SHOW,
            methods::POLICY_VALIDATE,
            methods::STATUS,
            methods::PING,
            methods::GRANTS_LIST,
            methods::GRANTS_SHOW,
            ops_methods::SYSTEM_DIAGNOSE,
        ];
        if self.lockdown && !ALLOWED.contains(&method) {
            return Err(IpcError::Remote {
                code: app_error::LOCKDOWN,
                message: "emergency lockdown active; run `ownmesh unlock` locally".into(),
            });
        }
        Ok(())
    }

    fn check_journal_degraded(&self, method: &str) -> IpcResult<()> {
        const ALLOWED: &[&str] = &[
            methods::DAEMON_UNLOCK,
            methods::ADMIN_DAEMON_UNLOCK_REQUEST,
            methods::APPROVAL_LIST,
            methods::APPROVAL_SHOW,
            methods::POLICY_SHOW,
            methods::POLICY_VALIDATE,
            methods::POLICY_EXPLAIN,
            methods::STATUS,
            methods::PING,
            methods::OPS_FS_LIST,
            methods::OPS_FS_STAT,
            methods::OPS_FS_READ,
            methods::OPS_LOGS_QUERY,
            methods::PROFILE_LIST,
            methods::PROFILE_SCAN,
            methods::PROFILE_SHOW,
            methods::TRANSFER_STATUS,
            methods::TRANSFER_LIST,
            methods::GRANTS_LIST,
            methods::GRANTS_SHOW,
            methods::GRANTS_REVOKE,
            ops_methods::SYSTEM_DIAGNOSE,
            ops_methods::GIT_STATUS,
            ops_methods::GIT_DIFF,
            ops_methods::WORKSPACE_LIST,
            ops_methods::WORKSPACE_SHOW,
            ops_methods::LOGS_LIST_PROVIDERS,
            ops_methods::REVIEW_SHOW,
            ops_methods::REVIEW_PAGE,
            session_methods::LIST,
            session_methods::SHOW,
        ];
        let Some(reason) = &self.op_journal_degraded else {
            return Ok(());
        };
        if ALLOWED.contains(&method) {
            return Ok(());
        }
        Err(journal_degraded_error(reason))
    }

    fn check_pending_request_lockdown(&self, request: &PendingRequest) -> IpcResult<()> {
        if matches!(request, PendingRequest::AdminDaemonUnlock(_)) && !self.lockdown {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "device is not in emergency lockdown".into(),
            });
        }
        if self.lockdown
            && !matches!(
                request,
                PendingRequest::AdminDaemonUnlock(_) | PendingRequest::SystemDiagnose(_)
            )
        {
            return Err(IpcError::Remote {
                code: app_error::LOCKDOWN,
                message: "emergency lockdown active; only a bound admin unlock may execute".into(),
            });
        }
        Ok(())
    }

    fn enqueue_bound_admin_request(
        &mut self,
        capability: &str,
        reason: &str,
        request: PendingRequest,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let operation_id = self
            .active_remote_operation_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "admin request requires an exact-bound control-plane operation".into(),
            })?
            .to_owned();
        let payload_hash = self
            .active_remote_payload_hash
            .as_deref()
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "admin request requires a verified payload hash".into(),
            })?
            .to_ascii_lowercase();
        let expires_at = self
            .active_remote_expires_at_unix
            .filter(|expiry| *expiry >= Self::now())
            .ok_or_else(|| IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "admin request authorization is missing or expired".into(),
            })?;
        if self
            .active_remote_device_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
            || self.active_remote_principal_credential_generation.is_none()
        {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "admin request lacks verified device or credential-generation binding"
                    .into(),
            });
        }
        let requester_principal = canonicalize_principal_key(client.principal_key());
        if requester_principal.is_empty()
            || self.active_remote_principal.as_deref() != Some(requester_principal.as_str())
        {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "admin requester does not match the verified remote principal".into(),
            });
        }
        if let Some(existing) = self
            .approvals
            .values()
            .find(|record| record.operation_id == operation_id)
        {
            if existing.state == "pending"
                && existing.target_payload_hash.as_deref() == Some(&payload_hash)
            {
                return Ok(json!({
                    "approval_required": true,
                    "operation_id": operation_id,
                    "approval_id": existing.id,
                    "reason": existing.reason,
                    "replayed": true,
                }));
            }
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "admin operation already exists with different or terminal state".into(),
            });
        }

        let approval_id = Self::new_id("apr_");
        let facts = OperationFacts {
            capability: capability.to_owned(),
            kind: "admin".into(),
            ..Default::default()
        };
        let record = ApprovalRecord {
            id: approval_id.clone(),
            operation_id: operation_id.clone(),
            capability: capability.to_owned(),
            state: "pending".into(),
            reason: reason.to_owned(),
            created_at_unix: Self::now(),
            decided_at_unix: None,
            expires_at_unix: Some(expires_at),
            target_payload_hash: Some(payload_hash),
            matched_rule_id: None,
            requester_principal,
            facts: Some(facts),
            request,
            result: None,
            decided_by_principal: None,
        };
        let snapshot = self.approvals.clone();
        self.approvals.insert(approval_id.clone(), record);
        if let Err(error) = self.persist_approvals() {
            self.approvals = snapshot;
            return Err(error);
        }
        self.append_audit(
            "admin.approval_enqueued",
            Some(capability),
            Some(&operation_id),
            Some("ask"),
            format!("approval {approval_id}"),
        );
        Ok(json!({
            "approval_required": true,
            "operation_id": operation_id,
            "approval_id": approval_id,
            "reason": reason,
            "replayed": false,
        }))
    }

    fn approval_target_preview(target: &ApprovalRecord) -> Value {
        fn bounded(value: &str, max_chars: usize) -> String {
            value.chars().take(max_chars).collect()
        }

        let facts = target.facts.as_ref();
        json!({
            "approval_id": bounded(&target.id, 128),
            "operation_id": bounded(&target.operation_id, 256),
            "capability": bounded(&target.capability, 128),
            "reason": bounded(&target.reason, 512),
            "kind": facts.map(|value| bounded(&value.kind, 128)).unwrap_or_default(),
            "program": facts.and_then(|value| value.program.as_deref()).map(|value| bounded(value, 512)),
            "path": facts.and_then(|value| value.path.as_deref()).map(|value| bounded(value, 1_024)),
            "elevated": facts.is_some_and(|value| value.elevated),
            "workspace_relative": facts.is_some_and(|value| value.workspace_relative),
        })
    }

    fn evaluate(
        &self,
        facts: &OperationFacts,
        principal_id: &str,
    ) -> ownmesh_policy::PolicyVerdict {
        let principal = if principal_id.trim().is_empty() {
            LOCAL_PRINCIPAL
        } else {
            principal_id
        };
        evaluate_with_grants(
            &self.policy,
            facts,
            &self.grants,
            Self::now(),
            principal,
            self.active_remote_device_id.as_deref(),
        )
    }

    fn consume_bounded_grant_use(
        &mut self,
        verdict: &ownmesh_policy::PolicyVerdict,
    ) -> IpcResult<()> {
        if verdict.decision != Decision::Allow {
            return Ok(());
        }
        let Some(grant_id) = verdict.matched_rule_id.as_deref() else {
            return Ok(());
        };
        let Some(index) = self
            .grants
            .iter()
            .position(|grant| grant.as_bounded_tool().is_some_and(|g| g.id == grant_id))
        else {
            return Ok(());
        };
        let needs_count = self.grants[index]
            .as_bounded_tool()
            .is_some_and(|g| g.max_uses.is_some());
        if !needs_count {
            return Ok(());
        }
        let snapshot = self.grants.clone();
        if let Some(grant) = self.grants[index].as_bounded_tool_mut() {
            grant.uses = grant.uses.saturating_add(1);
        }
        if let Err(e) = self.persist_grants() {
            self.grants = snapshot;
            return Err(e);
        }
        Ok(())
    }

    fn lookup_idempotent(&mut self, key: Option<&String>) -> IpcResult<Option<Value>> {
        let Some(key) = key else {
            return Ok(None);
        };
        let Some(entry) = self.op_journal.get(key) else {
            return Ok(None);
        };
        // Fail closed: only provably-completed entries may be replayed as
        // receipts. An in-progress marker and any unknown/forward-version
        // state are both uncertain — replaying them as completed could hide
        // an unfinished side effect (P0-B).
        if is_op_journal_uncertain(entry) {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!(
                    "idempotency key {key} has an in-progress or uncertain outcome; retry refused"
                ),
            });
        }
        // Retention-window synchronization (P0-B / control plane): the
        // control plane hard-deletes its idempotency tombstones after
        // `MCP_OPS_TOMBSTONE_TTL_MS` (30 days) and then dispatches a retry as
        // a *new* operation. A completed receipt older than the same window
        // must therefore not be replayed — the caller expects a fresh
        // operation, and returning the stale receipt would silently replace
        // it. Eviction normally happens at capacity; this lookup enforces the
        // same documented window on the replay path so a long-lived daemon
        // cannot return a stale device/operation receipt after the CP window
        // closed. Only completed receipts may expire; in-progress/uncertain
        // markers are never aged out (fail-closed: an uncertain outcome must
        // not become retriable).
        if op_journal_entry_state(entry) == OpJournalEntryState::Completed {
            let now = Self::now();
            let expired = entry
                .get(OP_JOURNAL_COMPLETED_UNIX_FIELD)
                .and_then(Value::as_i64)
                .is_some_and(|stamp| {
                    stamp > 0 && now.saturating_sub(stamp) >= OP_JOURNAL_COMPLETED_TTL_SECS
                });
            if expired {
                // Best-effort removal of the expired receipt; a persist
                // failure is not fatal for correctness (the in-memory copy is
                // authoritative and the next persist rewrites the file), but
                // the lookup must not return it.
                let snapshot = self.op_journal.clone();
                self.op_journal.remove(key);
                if let Err(e) = self.persist_op_journal() {
                    self.op_journal = snapshot;
                    eprintln!(
                        "warning: failed to persist op journal after expiring receipt {key}: {e}"
                    );
                }
                return Ok(None);
            }
        }
        Ok(Some(entry.clone()))
    }

    /// Persist the non-retriable marker before invoking an external operation.
    /// A failed write restores the prior in-memory map and no operation has run.
    fn begin_idempotent(&mut self, key: Option<&String>, operation_id: &str) -> IpcResult<()> {
        let Some(key) = key else {
            return Ok(());
        };
        if self.op_journal.contains_key(key) {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!("idempotency key {key} is already reserved"),
            });
        }
        // Bounded lifecycle: make durable room by evicting only old completed
        // receipts before refusing a new side-effect operation (P0-B). The new
        // marker's serialized size is included in the pressure projection so a
        // near-capacity journal evicts eligible receipts instead of letting the
        // marker push the durable file over the byte budget.
        self.maybe_make_op_journal_room(key, operation_id)?;
        if self.op_journal.len() >= MAX_OP_JOURNAL_ENTRIES {
            return Err(IpcError::Remote {
                code: app_error::JOURNAL_CAPACITY,
                message: format!(
                    "op journal at capacity ({MAX_OP_JOURNAL_ENTRIES}) with no evictable completed \
receipts; refuse new idempotency key (run `ownmesh doctor` for journal pressure)"
                ),
            });
        }
        let snapshot = self.op_journal.clone();
        self.op_journal.insert(
            key.clone(),
            json!({
                OP_JOURNAL_STATE_FIELD: OP_JOURNAL_IN_PROGRESS,
                "operation_id": operation_id,
            }),
        );
        if let Err(e) = self.persist_op_journal() {
            self.op_journal = snapshot;
            return Err(e);
        }
        Ok(())
    }

    /// Replace an already durable in-progress marker with the completed result.
    /// On failure, memory is restored to the marker snapshot; the atomic writer
    /// leaves that same non-retriable marker durable on disk.
    ///
    /// P0-B: after the compact receipt is durably persisted, the in-memory
    /// entry is replaced by that same receipt so full result bodies are never
    /// retained indefinitely in memory either (the caller already holds the
    /// full result for the immediate response; replay returns the receipt).
    fn store_idempotent(&mut self, key: Option<&String>, value: &Value) -> IpcResult<()> {
        let Some(k) = key else {
            return Ok(());
        };
        let snapshot = self.op_journal.clone();
        let mut stored = value.clone();
        // Stamp completion time so the bounded lifecycle can evict old
        // terminal receipts at capacity without ever touching in-progress
        // markers (P0-B). The field is additive for replay consumers.
        if let Some(object) = stored.as_object_mut() {
            object.insert(OP_JOURNAL_COMPLETED_UNIX_FIELD.into(), json!(Self::now()));
        }
        self.op_journal.insert(k.clone(), stored);
        if let Err(e) = self.persist_op_journal() {
            self.op_journal = snapshot;
            return Err(e);
        }
        // In-memory compaction mirrors the durable file: completed entries
        // become exact-once receipts; uncertain entries stay verbatim.
        if let Some(receipt) = op_journal_durable_view(&self.op_journal).remove(k.as_str()) {
            self.op_journal.insert(k.clone(), receipt);
        }
        Ok(())
    }

    /// Reconcile a durable in-progress marker with a terminal, definitive
    /// failure outcome (#142). The dispatch finished with a non-retryable
    /// error, so leaving the marker in place would strand the caller's
    /// idempotency key forever and keep doctor reporting an uncertain
    /// in-flight mutation. The marker becomes a compact *failed* receipt:
    /// replaying the same key still cannot re-run a side effect — it replays
    /// the stored failure.
    ///
    /// Safety envelope (ADR 0010 unchanged): only this operation's own
    /// in-progress marker is reconciled (the `operation_id` must match);
    /// completed receipts and unknown/forward-version states stay untouched;
    /// a crash between reserve and terminal result still leaves the
    /// exact-once in-progress marker for operator reconciliation. Returns
    /// `Ok(true)` only when a marker was actually reconciled.
    fn fail_idempotent(
        &mut self,
        key: Option<&String>,
        operation_id: &str,
        error_code: i64,
        error_message: &str,
    ) -> IpcResult<bool> {
        let Some(key) = key else {
            return Ok(false);
        };
        let Some(entry) = self.op_journal.get(key) else {
            return Ok(false);
        };
        if op_journal_entry_state(entry) != OpJournalEntryState::InProgress {
            return Ok(false);
        }
        if entry.get("operation_id").and_then(Value::as_str) != Some(operation_id) {
            return Ok(false);
        }
        let receipt = json!({
            "durable_receipt": true,
            "status": "failed",
            "operation_id": operation_id,
            "error": {
                "code": error_code,
                "message": bounded_journal_error_message(error_message),
                "retryable": false,
            },
        });
        self.store_idempotent(Some(key), &receipt)?;
        Ok(true)
    }

    /// Transport entry point for [`Self::fail_idempotent`]: reconcile the
    /// caller's reserved journal key after a remote dispatch produced a
    /// terminal failed/cancelled device result (#142). Recomputes the same
    /// principal-namespaced journal key the admission path reserved.
    pub fn reconcile_failed_idempotent(
        &mut self,
        idempotency_key: &str,
        principal_key: &str,
        operation_id: &str,
        error_code: i64,
        error_message: &str,
    ) -> bool {
        let requester_principal = canonicalize_principal_key(principal_key);
        let journal_key = principal_journal_key(&requester_principal, idempotency_key);
        matches!(
            self.fail_idempotent(Some(&journal_key), operation_id, error_code, error_message,),
            Ok(true)
        )
    }

    async fn gate_and_run(
        &mut self,
        facts: OperationFacts,
        idempotency_key: Option<String>,
        request: PendingRequest,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let requester_principal = canonicalize_principal_key(client.principal_key());
        // Namespace receipts by principal so one MCP caller cannot replay another's
        // local side-effect journal entry via a colliding idempotency_key.
        let journal_key = idempotency_key
            .as_ref()
            .map(|k| principal_journal_key(&requester_principal, k));
        if let Some(prev) = self.lookup_idempotent(journal_key.as_ref())? {
            // A reconciled terminal failure (#142) replays as the same
            // definitive error — never as a new attempt and never disguised
            // as a completed result. The stored JSON-RPC code/message are the
            // exact pair the first attempt produced.
            if prev.get("status").and_then(Value::as_str) == Some("failed") {
                let error = prev.get("error").cloned().unwrap_or_else(|| json!({}));
                return Err(IpcError::Remote {
                    code: error
                        .get("code")
                        .and_then(Value::as_i64)
                        .unwrap_or(app_error::INTERNAL),
                    message: error
                        .get("message")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .unwrap_or_else(|| "operation previously failed".into()),
                });
            }
            let mut replayed = prev;
            if let Some(obj) = replayed.as_object_mut() {
                obj.insert("replayed".into(), json!(true));
            }
            return Ok(replayed);
        }

        let mut facts = facts;
        // Always bind the grant tool from the pending request. A stale or
        // caller-supplied facts.tool must not lift a different capability.
        facts.tool = pending_request_tool(&request).map(str::to_owned);

        let mut verdict = self.evaluate(&facts, &requester_principal);
        // ChatGPT does not provide a cryptographic confirmation attestation.
        // A user may nevertheless configure the local device to treat the
        // authenticated, canonical-payload-bound MCP invocation itself as the
        // confirmation UI. This narrowly converts only a policy Ask; it cannot
        // bypass Deny, local lockdown, binding/expiry verification or custody.
        let delegated_remote = self.delegate_remote_mcp
            && self.active_remote_operation_id.is_some()
            && self.active_remote_payload_hash.is_some()
            && self
                .active_remote_expires_at_unix
                .is_some_and(|expiry| expiry >= Self::now());
        if delegated_remote && verdict.decision == Decision::Ask {
            verdict.decision = Decision::Allow;
            verdict.reason = format!("{}; remote MCP delegation configured", verdict.reason);
        }
        self.consume_bounded_grant_use(&verdict)?;
        // Prefer the control-plane operation id when present so Ask/Allow results
        // keep DeviceRoom correlation/operation_id binding. Local IPC keeps a
        // freshly minted id.
        let operation_id = self
            .active_remote_operation_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| Self::new_id("op_"));
        self.append_audit(
            "policy.evaluate",
            Some(&facts.capability),
            Some(&operation_id),
            Some(decision_str(verdict.decision)),
            &verdict.reason,
        );

        match verdict.decision {
            Decision::Deny => {
                self.append_audit(
                    "operation.denied",
                    Some(&facts.capability),
                    Some(&operation_id),
                    Some("deny"),
                    &verdict.reason,
                );
                Err(IpcError::Remote {
                    code: app_error::POLICY_DENIED,
                    message: format!("policy denied: {}", verdict.reason),
                })
            }
            Decision::Ask => {
                if let Some(reason) = &self.op_journal_degraded {
                    return Err(journal_degraded_error(reason));
                }
                let approval_id = Self::new_id("apr_");
                let rec = ApprovalRecord {
                    id: approval_id.clone(),
                    operation_id: operation_id.clone(),
                    capability: facts.capability.clone(),
                    state: "pending".into(),
                    reason: verdict.reason.clone(),
                    created_at_unix: Self::now(),
                    decided_at_unix: None,
                    // Inherit remote exact-action expiry/hash so delayed recovery
                    // cannot approve a stale deferred request after the original
                    // MCP operation window closed.
                    expires_at_unix: self.active_remote_expires_at_unix,
                    target_payload_hash: self.active_remote_payload_hash.clone(),
                    matched_rule_id: verdict.matched_rule_id.clone(),
                    requester_principal: requester_principal.clone(),
                    facts: Some(facts.clone()),
                    request,
                    result: None,
                    decided_by_principal: None,
                };
                let approvals_snapshot = self.approvals.clone();
                self.approvals.insert(approval_id.clone(), rec);
                if let Err(e) = self.persist_approvals() {
                    self.approvals = approvals_snapshot;
                    return Err(e);
                }
                self.append_audit(
                    "approval.enqueued",
                    Some(&facts.capability),
                    Some(&operation_id),
                    Some("ask"),
                    format!("approval {approval_id}"),
                );
                Ok(json!({
                    "approval_required": true,
                    "operation_id": operation_id,
                    "approval_id": approval_id,
                    "reason": verdict.reason,
                    "matched_rule_id": verdict.matched_rule_id,
                    "replayed": false,
                }))
            }
            Decision::Allow => {
                if self.op_journal_degraded.is_some()
                    && pending_request_is_journal_read_only(&request)
                {
                    let result = self.execute_request(&request).await?;
                    return Ok(json!({
                        "approval_required": false,
                        "operation_id": operation_id,
                        "result": result,
                        "replayed": false,
                        "decision": "allow",
                        "reason": verdict.reason,
                    }));
                }
                if let Some(reason) = &self.op_journal_degraded {
                    return Err(journal_degraded_error(reason));
                }
                self.begin_idempotent(journal_key.as_ref(), &operation_id)?;
                // A crash between this reserve and a terminal outcome must
                // keep the exact-once marker (ADR 0010). But a definitive
                // execution error is itself terminal: reconcile the marker
                // into a compact failed receipt so the key replays the same
                // failure instead of being stranded as an eternal in_progress
                // marker (#142).
                let executed = self.execute_request(&request).await;
                let result = match executed {
                    Ok(result) => result,
                    Err(error) => {
                        let (code, message) = match &error {
                            IpcError::Remote { code, message } => (*code, message.clone()),
                            _ => (app_error::INTERNAL, error.to_string()),
                        };
                        if let Err(reconcile_error) = self.fail_idempotent(
                            journal_key.as_ref(),
                            &operation_id,
                            code,
                            &message,
                        ) {
                            eprintln!(
                                "warning: failed to persist terminal failure receipt \
                                 {operation_id}: {reconcile_error:?}"
                            );
                        }
                        self.append_audit(
                            "operation.failed",
                            Some(&facts.capability),
                            Some(&operation_id),
                            Some("allow"),
                            "execution returned a terminal error; journal marker reconciled",
                        );
                        return Err(error);
                    }
                };
                let body = json!({
                    "approval_required": false,
                    "operation_id": operation_id,
                    "result": result,
                    "replayed": false,
                    "decision": "allow",
                    "reason": verdict.reason,
                });
                self.store_idempotent(journal_key.as_ref(), &body)?;
                self.append_audit(
                    "operation.completed",
                    Some(&facts.capability),
                    Some(&operation_id),
                    Some("allow"),
                    "executed",
                );
                Ok(body)
            }
        }
    }

    async fn execute_request(&mut self, request: &PendingRequest) -> IpcResult<Value> {
        match request {
            // `op_journal` is the transaction marker for runtime operations. Using
            // the lower-level exec journal as well would create two independent
            // commit points and could poison a key before any process was spawned.
            PendingRequest::Exec(p) => self.execute_exec(p, false).await,
            PendingRequest::FsList(p) => self.execute_fs_list(p),
            PendingRequest::FsStat(p) => self.execute_fs_stat(p),
            PendingRequest::FsRead(p) => self.execute_fs_read(p),
            PendingRequest::FsWrite(p) => self.execute_fs_write(p),
            PendingRequest::FsDelete(p) => self.execute_fs_delete(p),
            PendingRequest::LogsQuery(p) => self.execute_logs_query(p),
            PendingRequest::GitStatus(p) => self.execute_git_status(p),
            PendingRequest::GitDiff(p) => self.execute_git_diff(p),
            PendingRequest::SystemDiagnose(p) => self.execute_system_diagnose(p).await,
            PendingRequest::AdminPolicyPreset(p) => self.execute_admin_policy_preset(p),
            PendingRequest::AdminPolicyRuleAdd(p) => self.execute_admin_policy_rule_add(p),
            PendingRequest::AdminPolicyRuleRemove(p) => self.execute_admin_policy_rule_remove(p),
            PendingRequest::AdminDaemonUnlock(_) => {
                if !self.lockdown {
                    return Err(IpcError::Remote {
                        code: app_error::CONFLICT,
                        message: "device is not in emergency lockdown".into(),
                    });
                }
                self.handle_unlock()
            }
            PendingRequest::AdminTokenRevoke(p) => {
                self.handle_token_revoke(Some(json!({ "principal": p.principal })))
            }
            PendingRequest::AdminGrantsMint(p) => self.execute_admin_grants_mint(p),
            PendingRequest::AdminApprovalBridge(_) => Err(IpcError::Remote {
                code: app_error::INTERNAL,
                message: "approval bridge requires the authenticated approval executor".into(),
            }),
        }
    }

    async fn execute_exec(&mut self, p: &ExecParams, use_exec_journal: bool) -> IpcResult<Value> {
        let cwd = p.cwd.as_deref().map(Path::new);
        let kind = CommandKind::parse_requested(p.kind.as_deref());
        let prepared = match kind {
            CommandKind::Structured => {
                let invocation = p.invocation_pin.as_ref().ok_or_else(|| IpcError::Remote {
                    code: app_error::EXECUTABLE_IDENTITY_DRIFT,
                    message: "OWNMESH_E_EXECUTABLE_IDENTITY_DRIFT: structured invocation pin is missing; request must be re-authorized".into(),
                })?;
                let backing = p.executable_pin.as_ref().ok_or_else(|| IpcError::Remote {
                    code: app_error::EXECUTABLE_IDENTITY_DRIFT,
                    message: "OWNMESH_E_EXECUTABLE_IDENTITY_DRIFT: structured backing pin is missing; request must be re-authorized".into(),
                })?;
                prepare_executable_with_interpreter(
                    Path::new(&p.program),
                    invocation,
                    backing,
                    p.shell_pin.as_ref(),
                    Some(&self.paths.runtime_dir),
                )
            }
            CommandKind::RawShell => {
                let shell = p.shell_pin.as_ref().ok_or_else(|| IpcError::Remote {
                    code: app_error::EXECUTABLE_IDENTITY_DRIFT,
                    message: "OWNMESH_E_EXECUTABLE_IDENTITY_DRIFT: raw-shell interpreter pin is missing; request must be re-authorized".into(),
                })?;
                prepare_executable(
                    Path::new(&shell.path),
                    shell,
                    shell,
                    Some(&self.paths.runtime_dir),
                )
            }
        }
        .map_err(|_| IpcError::Remote {
            code: app_error::EXECUTABLE_IDENTITY_DRIFT,
            message: "OWNMESH_E_EXECUTABLE_IDENTITY_DRIFT: invocation identity changed; request must be re-authorized".into(),
        })?;
        // Re-classify only after preparation has bound the exact approved
        // invocation/backing object. Never substitute a canonical backing for
        // a drifted proxy; any such drift has already returned the typed error.
        let current_kind =
            classify_from_request_in_dir(p.kind.as_deref(), &p.program, &p.args, cwd);
        let approved_kind = CommandKind::parse_requested(p.policy_kind.as_deref());
        if current_kind != approved_kind {
            return Err(IpcError::Remote {
                code: app_error::EXECUTABLE_IDENTITY_DRIFT,
                message: "OWNMESH_E_EXECUTABLE_IDENTITY_DRIFT: command classification changed; request must be re-authorized".into(),
            });
        }

        let _detached_guard = if p.detach {
            Some(acquire_detached_slot()?)
        } else {
            None
        };

        // Elevated execution has no local fallback.  Only the custody-attested
        // Linux v2 broker path below may spawn with privilege.
        if p.elevated {
            let mut result = self.try_broker_elevated(p).await?;
            result
                .as_object_mut()
                .expect("broker result serializes as an object")
                .insert("workspace_id".into(), json!(p.workspace_id));
            if p.detach {
                result
                    .as_object_mut()
                    .expect("broker result serializes as an object")
                    .insert("detached".into(), json!(true));
            }
            return Ok(result);
        }
        // Spawn mode follows the client request shape (argv vs shell-string).
        // Policy already used server-side classification in handle_exec.
        // Hard ceilings are enforced here even if a caller bypasses MCP schema.
        // Detached commands have no wall-clock kill; cancel still process-tree kills.
        let timeout_ms = if p.detach {
            None
        } else {
            Some(p.timeout_ms.unwrap_or(30_000).clamp(1, HARD_MAX_TIMEOUT_MS))
        };
        // Keep a single durable hop under the control-plane data_json budget
        // (~256 KiB) after JSON framing. Larger captures require an explicit
        // smaller max or a future spool cursor — never one giant unbounded JSON.
        let max_output_bytes = p.max_output_bytes.unwrap_or(128 * 1024).clamp(1, 200_000);
        let env = sanitize_exec_env(&p.env)?;
        let req = RunRequest {
            kind,
            program: p.program.clone(),
            args: p.args.clone(),
            cwd: p.cwd.as_ref().map(PathBuf::from),
            env,
            stdin: None,
            timeout_ms,
            max_output_bytes,
            idempotency_key: p.idempotency_key.clone(),
        };
        // Approved operations are journaled by `op_journal` as part of the approval
        // transaction. Do not also mutate `exec_journal`, which cannot participate in
        // that transaction's in-memory rollback.
        let cancel = self.active_cancel.clone();
        let result: RunResult = if use_exec_journal {
            Box::pin(run_prepared_command_cancellable(
                &req,
                prepared,
                Some(&mut self.exec_journal),
                cancel,
            ))
            .await
        } else {
            Box::pin(run_prepared_command_cancellable(
                &req, prepared, None, cancel,
            ))
            .await
        }
        .map_err(|e| {
            let code = match &e {
                ownmesh_exec::ExecError::Cancelled => app_error::CONFLICT,
                ownmesh_exec::ExecError::ExecutableFormat(_) => app_error::EXECUTABLE_FORMAT,
                _ => app_error::INTERNAL,
            };
            IpcError::Remote {
                code,
                message: e.to_string(),
            }
        })?;
        let mut value = serde_json::to_value(result).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })?;
        value
            .as_object_mut()
            .expect("command result serializes as an object")
            .insert("workspace_id".into(), json!(p.workspace_id));
        if p.detach {
            value
                .as_object_mut()
                .expect("command result serializes as an object")
                .insert("detached".into(), json!(true));
        }
        Ok(value)
    }

    async fn try_broker_elevated(&self, p: &ExecParams) -> IpcResult<Value> {
        #[cfg(target_os = "linux")]
        {
            return self.try_unix_broker_elevated(p).await;
        }
        #[cfg(target_os = "macos")]
        {
            return self.try_unix_broker_elevated(p).await;
        }
        #[cfg(windows)]
        {
            return self.try_windows_broker_elevated(p).await;
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            let _ = p;
            Err(IpcError::Remote {
                code: app_error::INTERNAL,
                message: "unsupported: elevated execution has no native broker implementation on this platform".into(),
            })
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn try_unix_broker_elevated(&self, p: &ExecParams) -> IpcResult<Value> {
        let running_image = std::env::current_exe().map_err(|_| IpcError::Remote {
            code: app_error::INTERNAL,
            message: "elevated execution cannot resolve the running daemon image (fail-closed)"
                .into(),
        })?;
        // Re-read every custody artifact immediately before the authority-bearing
        // write. Startup state is never sufficient: service/socket/config/key
        // replacement and daemon image drift must take elevation offline.
        #[cfg(target_os = "linux")]
        let loaded = load_linux_broker_client(&running_image);
        #[cfg(target_os = "macos")]
        let loaded = load_macos_broker_client(&running_image);
        let broker = loaded.map_err(|_| IpcError::Remote {
            code: app_error::INTERNAL,
            message: "unsupported: elevated execution requires a custody-attested installed native broker; broker unavailable or custody validation failed (fail-closed; no local exec)".into(),
        })?;
        let execute = self.build_broker_execute_intent(p, &broker.secret)?;
        let response = if let Some(mut cancel) = self.active_cancel.clone() {
            connect_and_execute_v2_cancellable(
                &broker.endpoint,
                &broker.secret,
                &execute,
                &mut cancel,
            )
            .await
        } else {
            connect_and_execute_v2(&broker.endpoint, &execute).await
        }
        .map_err(Self::broker_client_error)?;
        // The strict client already correlates the request id. Keep the check
        // here as a second guard before a broker response becomes a completed
        // outer operation receipt.
        if response.request_id != execute.request_id {
            return Err(IpcError::Remote {
                code: app_error::INTERNAL,
                message: "broker response request-id mismatch; outcome remains uncertain".into(),
            });
        }
        // A response is not committed into the outer operation journal until
        // the installed record, secret, verify key, socket and daemon image
        // are attested again. A post-send failure is intentionally uncertain,
        // so the caller cannot replay a possibly completed privileged command.
        #[cfg(target_os = "linux")]
        let reloaded = load_linux_broker_client(&running_image);
        #[cfg(target_os = "macos")]
        let reloaded = load_macos_broker_client(&running_image);
        let reattested = reloaded.map_err(|_| IpcError::Remote {
            code: app_error::CONFLICT,
            message: "broker custody changed after execution; outcome is uncertain and must not be retried".into(),
        })?;
        if reattested.endpoint != broker.endpoint
            || reattested.verify_key != broker.verify_key
            || reattested.trusted_executable != broker.trusted_executable
        {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "broker trust identity changed after execution; outcome is uncertain and must not be retried".into(),
            });
        }
        Self::broker_response_value(response)
    }

    #[cfg(windows)]
    async fn try_windows_broker_elevated(&self, p: &ExecParams) -> IpcResult<Value> {
        let running_image = std::env::current_exe().map_err(|_| IpcError::Remote {
            code: app_error::INTERNAL,
            message:
                "elevated execution cannot resolve the running Windows daemon image (fail-closed)"
                    .into(),
        })?;
        // This loader accepts only the fixed ProgramData/ProgramFiles custody
        // set, requires this process to be the LocalSystem OwnMeshDaemon SCM
        // service, and reconstructs no endpoint from caller input.
        let broker = load_windows_broker_client(&running_image).map_err(|_| IpcError::Remote {
            code: app_error::INTERNAL,
            message: "unsupported: elevated execution requires the fixed LocalSystem Windows broker custody installation; broker unavailable or custody validation failed (fail-closed; no local exec)".into(),
        })?;
        let execute = self.build_broker_execute_intent(p, &broker.secret)?;
        let response = self
            .execute_windows_broker_with_cancel(&broker, &execute)
            .await
            .map_err(Self::broker_client_error)?;
        if response.request_id != execute.request_id {
            return Err(IpcError::Remote {
                code: app_error::INTERNAL,
                message: "broker response request-id mismatch; outcome remains uncertain".into(),
            });
        }
        // The pipe client revalidates its broker server handle after the
        // response. Rebuild the complete daemon+broker custody boundary as a
        // second, independent post-response fence before journaling success.
        let reattested = load_windows_broker_client(&running_image).map_err(|_| IpcError::Remote {
            code: app_error::CONFLICT,
            message: "Windows broker or daemon custody changed after execution; outcome is uncertain and must not be retried".into(),
        })?;
        if reattested.endpoint != broker.endpoint
            || reattested.trust != broker.trust
            || reattested.trusted_executable != broker.trusted_executable
        {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "Windows broker trust identity changed after execution; outcome is uncertain and must not be retried".into(),
            });
        }
        Self::broker_response_value(response)
    }

    #[cfg(windows)]
    async fn execute_windows_broker_with_cancel(
        &self,
        broker: &broker_runtime::WindowsBrokerClient,
        execute: &ExecuteIntentV2,
    ) -> Result<ownmesh_broker_client::BrokerResponseV2, BrokerV2ClientError> {
        let Some(mut cancel) = self.active_cancel.clone() else {
            return connect_and_execute_v2_windows(&broker.endpoint, &broker.trust, execute).await;
        };
        if *cancel.borrow_and_update() {
            return Err(BrokerV2ClientError::ExecutionUncertain(
                "Windows broker execution was cancelled before submission; outer operation must not retry automatically".into(),
            ));
        }
        let (mut connection, request_id) =
            submit_execute_v2_windows(&broker.endpoint, &broker.trust, execute).await?;
        let mut execute_result = Box::pin(read_submitted_execute_v2_windows(
            &mut connection,
            &request_id,
            execute.facts.timeout_ms,
        ));
        let mut cancel_channel_open = true;
        loop {
            tokio::select! {
                biased;
                response = &mut execute_result => return response,
                changed = cancel.changed(), if cancel_channel_open => {
                    if changed.is_err() {
                        // A dropped sender is not a cancellation request. More
                        // importantly, `changed()` would remain immediately
                        // ready with Err and starve the execute response.
                        cancel_channel_open = false;
                        continue;
                    }
                    if !*cancel.borrow_and_update() {
                        continue;
                    }
                    // Cancellation gets its own verified pipe connection and a
                    // freshly MACed, target-fenced intent. Its result cannot
                    // replace the execute receipt; only the original response
                    // can prove success. If that delivery is busy, rejected,
                    // or times out, dropping this original pipe is the
                    // mandatory broker-side disconnect fence; no retry occurs.
                    let cancel_intent = build_cancel_intent_v2(&broker.secret, execute, Self::now());
                    let mut cancel_delivery = Box::pin(tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        connect_and_cancel_v2_windows(
                            &broker.endpoint,
                            &broker.trust,
                            &cancel_intent,
                        ),
                    ));
                    tokio::select! {
                        biased;
                        response = &mut execute_result => return response,
                        _ = &mut cancel_delivery => {
                            // Drop the read future before its borrowed
                            // connection. This closes the exact execute
                            // pipe and forces the broker to fence the Job,
                            // even when the independent Cancel pipe was
                            // rejected by bounded admission.
                            drop(execute_result);
                            drop(connection);
                            return Err(BrokerV2ClientError::ExecutionUncertain(
                                "local cancellation closed the original Windows execute pipe; broker outcome is non-retriable".into(),
                            ));
                        }
                    }
                }
            }
        }
    }

    fn broker_response_value(
        response: ownmesh_broker_client::BrokerResponseV2,
    ) -> IpcResult<Value> {
        if !response.ok {
            return Err(IpcError::Remote {
                code: if response.cancelled || response.timed_out {
                    app_error::CONFLICT
                } else {
                    app_error::INTERNAL
                },
                message: format!(
                    "privileged broker rejected execution: {}",
                    response
                        .error
                        .as_deref()
                        .unwrap_or("unknown broker failure")
                ),
            });
        }
        // Keep the normal command result contract for successful privileged
        // execution. The broker's `ok` is an execution receipt, not a second
        // policy decision, and a false receipt never becomes a successful
        // outer operation result.
        serde_json::to_value(json!({
            "exit_code": response.exit_code,
            "stdout": response.stdout,
            "stderr": response.stderr,
            "timed_out": response.timed_out,
            "cancelled": response.cancelled,
            "duration_ms": response.duration_ms,
            "truncated": response.truncated,
            "replayed": false,
        }))
        .map_err(|error| IpcError::Remote {
            code: app_error::INTERNAL,
            message: format!("serialize bounded broker response: {error}"),
        })
    }

    fn build_broker_execute_intent(
        &self,
        p: &ExecParams,
        secret: &ownmesh_broker_client::BrokerSecret,
    ) -> IpcResult<ExecuteIntentV2> {
        let operation_id = self
            .active_remote_operation_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| broker_binding_error("remote operation id is required"))?;
        let payload_hash = self
            .active_remote_payload_hash
            .as_deref()
            .filter(|value| is_lower_sha256(value))
            .ok_or_else(|| broker_binding_error("server exact payload hash is required"))?;
        let device_id = self
            .active_remote_device_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| broker_binding_error("verified remote device id is required"))?;
        let principal = self
            .active_remote_principal
            .as_deref()
            .ok_or_else(|| broker_binding_error("verified remote principal is required"))?;
        let (tenant_id, principal_id) = split_remote_principal(principal)
            .ok_or_else(|| broker_binding_error("verified remote principal shape is invalid"))?;
        let principal_credential_generation = self
            .active_remote_principal_credential_generation
            .filter(|generation| *generation > 0)
            .ok_or_else(|| {
                broker_binding_error(
                    "server-derived principal credential generation is required for elevation",
                )
            })?;
        let expires_at_unix = self
            .active_remote_expires_at_unix
            .filter(|expiry| *expiry > Self::now())
            .ok_or_else(|| broker_binding_error("unexpired remote operation is required"))?;
        let executable = p.executable_pin.as_ref().ok_or_else(|| {
            broker_binding_error("server-pinned structured executable is required for elevation")
        })?;
        if executable.policy_kind != CommandKind::Structured.as_str() {
            return Err(broker_binding_error(
                "elevated raw-shell execution is unsupported by the secure broker",
            ));
        }
        // The broker intentionally stages a held executable and currently does
        // not accept a cwd handoff.  A nonempty overlay would reintroduce a
        // loader/PATH confused deputy, so v2 likewise accepts only empty env.
        if p.cwd.is_some() {
            return Err(broker_binding_error(
                "elevated cwd handoff is unsupported by the secure broker",
            ));
        }
        if !p.env.is_empty() {
            return Err(broker_binding_error(
                "elevated environment overlays are unsupported by the secure broker",
            ));
        }
        verify_executable_pin(Path::new(&executable.path), executable).map_err(|error| {
            broker_binding_error(&format!(
                "executable identity changed before privileged handoff: {error}"
            ))
        })?;
        let now = Self::now();
        let issued_at_unix = now;
        let expires_at_unix = expires_at_unix.min(now.saturating_add(DEFAULT_CAPABILITY_TTL_SECS));
        if expires_at_unix <= issued_at_unix {
            return Err(broker_binding_error(
                "remote operation expires before broker handoff",
            ));
        }
        let timeout_ms = p.timeout_ms.unwrap_or(30_000).clamp(1, HARD_MAX_TIMEOUT_MS);
        let max_output_bytes = p.max_output_bytes.unwrap_or(128 * 1024).clamp(1, 200_000);
        let workspace_id = p
            .workspace_id
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| broker_binding_error("server-bound workspace id is required"))?;
        let facts = OperationFactsV2 {
            operation: operation_id.to_owned(),
            remote_payload_sha256: payload_hash.to_owned(),
            principal_id: principal_id.to_owned(),
            tenant_id: tenant_id.to_owned(),
            principal_credential_generation,
            timeout_ms,
            max_output_bytes,
            device_id: device_id.to_owned(),
            workspace_id: workspace_id.to_owned(),
            argv: std::iter::once(executable.path.clone())
                .chain(p.args.iter().cloned())
                .collect(),
            canonical_cwd: None,
            sanitized_env: BTreeMap::new(),
            executable: ExecutablePinV2 {
                canonical_path: executable.path.clone(),
                image_sha256: executable.content_sha256.clone(),
                image_len: executable.len,
            },
        };
        let mut execute = ExecuteIntentV2 {
            protocol_version: BROKER_PROTOCOL_V2,
            request_id: Self::new_id("breq_"),
            operation_id: operation_id.to_owned(),
            nonce: Self::new_id("bnonce_"),
            issued_at_unix,
            expires_at_unix,
            facts,
            mac: String::new(),
        };
        execute.mac = compute_execute_intent_mac_v2(secret, &execute);
        Ok(execute)
    }

    fn broker_client_error(error: BrokerV2ClientError) -> IpcError {
        let code = match error {
            // The Execute frame may have reached the broker. The durable outer
            // in-progress marker deliberately remains, preventing a retry from
            // spawning the same privileged action twice.
            BrokerV2ClientError::ExecutionUncertain(_) => app_error::CONFLICT,
            _ => app_error::INTERNAL,
        };
        IpcError::Remote {
            code,
            message: format!("privileged broker execution failed: {error}"),
        }
    }

    fn process_log_path(&self) -> PathBuf {
        self.paths.state_dir.join("logs").join("process.log")
    }

    fn build_log_registry(&self, p: &LogsQueryParams) -> LogRegistry {
        let mut reg = LogRegistry::new();
        let process_log = self.process_log_path();
        // Ensure process log exists so the provider can page empty results.
        if let Some(parent) = process_log.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if !process_log.exists() {
            let _ = std::fs::write(&process_log, b"");
        }
        register_builtin_providers(
            &mut reg,
            &BuiltinProviderConfig {
                file_id: "audit".into(),
                file_path: self.log_path.clone(),
                windows_channel: p.channel.clone().unwrap_or_else(|| "Application".into()),
                journald_unit: p.unit.clone(),
                docker_container: p.container.clone(),
                process_id: "process".into(),
                process_log_path: Some(process_log),
            },
        );
        reg
    }

    fn execute_logs_query(&self, p: &LogsQueryParams) -> IpcResult<Value> {
        let limit = p.limit.unwrap_or(100);
        if !(1..=MAX_LOG_QUERY_LIMIT).contains(&limit) {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("log query limit must be between 1 and {MAX_LOG_QUERY_LIMIT}"),
            });
        }
        let reg = self.build_log_registry(p);
        let provider = reg.get(&p.provider).map_err(|e| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: e.to_string(),
        })?;
        let cursor = p.cursor_offset.map(|offset| LogCursor {
            provider: p.provider.clone(),
            offset,
        });
        let page = provider
            .query(cursor.as_ref(), limit)
            .map_err(|e| match e {
                LogError::Unavailable(msg) => IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: msg,
                },
                other => IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: other.to_string(),
                },
            })?;
        serde_json::to_value(page).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })
    }

    fn execute_git_status(&self, p: &GitStatusParams) -> IpcResult<Value> {
        let ws = self.workspace_for(p.workspace_id.as_deref())?;
        let page = git_status(
            &ws,
            &GitStatusOpts {
                path: PathBuf::from(&p.path),
                cursor: p.cursor,
                limit: p.limit.unwrap_or(100),
            },
        )
        .map_err(fs_err)?;
        let mut value = serde_json::to_value(page).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })?;
        value
            .as_object_mut()
            .expect("git status serializes as an object")
            .insert("workspace_id".into(), json!(p.workspace_id));
        Ok(value)
    }

    fn execute_git_diff(&self, p: &GitDiffParams) -> IpcResult<Value> {
        let ws = self.workspace_for(p.workspace_id.as_deref())?;
        let page = git_diff(
            &ws,
            &GitDiffOpts {
                path: PathBuf::from(&p.path),
                pathspec: p.pathspec.clone(),
                staged: p.staged,
                cursor: p.cursor,
                limit: p.limit.unwrap_or(200),
                max_bytes: p.max_bytes.unwrap_or(256 * 1024),
            },
        )
        .map_err(fs_err)?;
        let mut value = serde_json::to_value(page).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })?;
        value
            .as_object_mut()
            .expect("git diff serializes as an object")
            .insert("workspace_id".into(), json!(p.workspace_id));
        Ok(value)
    }

    async fn handle_exec(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let mut p: ExecParams = parse_params(params)?;
        // Never trust client-supplied pins / policy classification.
        p.executable_pin = None;
        p.invocation_pin = None;
        p.shell_pin = None;
        p.policy_kind = None;
        if p.elevated
            && (self.policy.preset != AccessPreset::FullAccess
                || !full_access_has_no_hidden_restrictive_rules(&self.policy))
        {
            return Err(IpcError::Remote {
                code: app_error::POLICY_DENIED,
                message: "elevated execution requires the Full Access preset".into(),
            });
        }
        if p.program.trim().is_empty() {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "program is required".into(),
            });
        }
        // Restricted presets (workspace_only / recommended) cannot confine arbitrary
        // process trees to registered workspace roots. Interpreters and absolute-path
        // args escape cwd binding. Fail closed until OS-level confinement exists;
        // filesystem.* tools remain the confined path. full_user_access / full_access
        // intentionally allow user-scoped commands.
        if self.enforce_workspace {
            return Err(IpcError::Remote {
                code: app_error::POLICY_DENIED,
                message: format!(
                    "command.run denied under {} until OS process confinement is available; \
use filesystem.* tools within a registered workspace, or switch access mode to \
full_user_access/full_access for arbitrary commands",
                    preset_name(self.policy.preset)
                ),
            });
        }
        // Resolve argv executables once, before classification, and persist that exact
        // canonical path with approvals/execution. Raw-shell command strings are not paths.
        // Bind optional cwd to the selected workspace root as context when provided.
        if let Some(ws_id) = p.workspace_id.clone() {
            let ws = self.workspace_for(Some(ws_id.as_str()))?;
            if p.elevated {
                // v2 binds the workspace as exact authorization/audit context,
                // but the current broker safely stages only executables and
                // deliberately rejects a cwd handoff. Do not silently turn a
                // selected workspace into a different privileged cwd.
                if p.cwd.is_some() {
                    return Err(broker_binding_error(
                        "elevated cwd handoff is unsupported by the secure broker",
                    ));
                }
            } else if let Some(cwd) = p.cwd.as_deref() {
                let resolved = ws.resolve(Path::new(cwd)).map_err(fs_err)?;
                p.cwd = Some(resolved.to_string_lossy().into_owned());
            } else {
                p.cwd = Some(ws.root().to_string_lossy().into_owned());
            }
        }
        let cwd = p.cwd.as_deref().map(Path::new);
        let requested_kind = CommandKind::parse_requested(p.kind.as_deref());
        let mut structured_unresolvable = false;
        let mut pinned_invocation: Option<(PathBuf, PathBuf)> = None;
        if matches!(requested_kind, CommandKind::Structured) {
            // P1-D review: resolve every structured program to its exact
            // launchable path. The old code silently fell back to the bare
            // name when resolution failed, and the Unix spawn path then ran
            // `Command::new(program)` — an OS PATH lookup that can disagree
            // with profile detection/review pinning/session launch and spawn
            // a different binary than the one authorized (detect-ready then
            // spawn-bare-name inconsistency, TOCTOU).
            //
            // P0-B review: retain the *invocation* path (resolved but not
            // canonicalized) separately from the canonical backing path used
            // for identity pinning. Proxy executables (rustup's `cargo`,
            // version-manager node wrappers that are symlinks to a real
            // binary) dispatch on their argv[0] filename: canonicalizing
            // `cargo` to the rustup binary would spawn rustup with cargo's
            // args and fail. Review pinning already keeps both paths
            // (`invocation_pin`/`pin`); generic `command.run` must not
            // disagree with review execution about resolution semantics.
            let invocation = resolve_executable_invocation_path(&p.program, cwd);
            let backing = resolve_executable_path(&p.program, cwd);
            match (invocation, backing) {
                (Some(invocation), Some(backing)) => {
                    // `p.program` keeps the invocation filename so the spawn
                    // preserves proxy semantics; both paths are pinned below
                    // so a retargeted symlink between approval and spawn is
                    // caught by revalidation before execution.
                    p.program = invocation.to_string_lossy().into_owned();
                    pinned_invocation = Some((invocation, backing));
                }
                _ => structured_unresolvable = true,
            }
        }
        // Reclassify on the server so direct shells, resolved shell symlinks, and
        // all `env` indirection cannot bypass raw_shell rules.
        let kind = classify_from_request_in_dir(p.kind.as_deref(), &p.program, &p.args, cwd);
        p.policy_kind = Some(kind.as_str().to_owned());
        // P1-D review: a program classified Structured that never resolved to
        // a launchable file must fail closed here instead of reaching the
        // spawner as a bare name. Classification of the unresolved name runs
        // first so a shell binary (even one not installed, e.g. `/bin/zsh` on
        // a minimal host) is still denied as raw_shell by policy, never
        // silently admitted as structured; only genuinely structured programs
        // are rejected with the resolution error.
        if matches!(kind, CommandKind::Structured) && structured_unresolvable {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!(
                    "structured program `{}` could not be resolved to a launchable \
regular executable (searched PATH and the deterministic user-local bins); pass an absolute \
path or install the tool so detection and execution agree",
                    p.program
                ),
            });
        }
        // P0-B review: pin the canonical backing path for identity and the
        // invocation path for argv[0]-driven proxy dispatch. A structured
        // program that resolved but is *not* a native binary (shell/script
        // payload) was reclassified raw above and skips this block.
        if let Some((invocation, backing)) = pinned_invocation {
            p.executable_pin =
                Some(
                    pin_executable(Path::new(&backing), kind).map_err(|e| IpcError::Remote {
                        code: app_error::POLICY_DENIED,
                        message: format!("unable to pin executable identity: {e}"),
                    })?,
                );
            p.invocation_pin = Some(pin_executable(Path::new(&invocation), kind).map_err(|e| {
                IpcError::Remote {
                    code: app_error::POLICY_DENIED,
                    message: format!("unable to pin invocation identity: {e}"),
                }
            })?);
        } else if matches!(requested_kind, CommandKind::Structured)
            && matches!(kind, CommandKind::Structured)
        {
            let program_path = Path::new(&p.program);
            if program_path.is_absolute() {
                p.executable_pin =
                    Some(
                        pin_executable(program_path, kind).map_err(|e| IpcError::Remote {
                            code: app_error::POLICY_DENIED,
                            message: format!("unable to pin structured executable identity: {e}"),
                        })?,
                    );
            }
        }
        if matches!(kind, CommandKind::RawShell) {
            #[cfg(windows)]
            let shell_path = PathBuf::from(ownmesh_exec::windows_system_cmd_exe(
                std::env::var("SystemRoot").ok().as_deref(),
            ));
            #[cfg(not(windows))]
            let shell_path = PathBuf::from("/bin/sh");
            p.shell_pin = Some(pin_executable(&shell_path, CommandKind::RawShell).map_err(
                |error| IpcError::Remote {
                    code: app_error::POLICY_DENIED,
                    message: format!("unable to pin raw-shell interpreter identity: {error}"),
                },
            )?);
        }
        // Facts carry only server-computed pin identity — never client digests.
        let facts = OperationFacts {
            capability: "command.run".into(),
            kind: kind.as_str().to_string(),
            program: Some(p.program.clone()),
            elevated: p.elevated,
            path: p.cwd.clone(),
            workspace_relative: false,
            workspace_id: p.workspace_id.clone(),
            executable_identity: p
                .executable_pin
                .as_ref()
                .or(p.shell_pin.as_ref())
                .map(executable_identity_from_pin),
            invocation_identity: p
                .invocation_pin
                .as_ref()
                .or(p.shell_pin.as_ref())
                .map(executable_identity_from_pin),
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::Exec(Box::new(p)), client)
            .await
    }

    fn transfer_error(error: TransferError) -> IpcError {
        let code = match error {
            TransferError::InvalidBinding(_)
            | TransferError::InvalidPlan(_)
            | TransferError::ChunkTooLarge
            | TransferError::MalformedChunk
            | TransferError::ChunkHashMismatch
            | TransferError::Overflow => app_error::INVALID_PARAMS,
            TransferError::PlatformUnsupported => app_error::PLATFORM_UNSUPPORTED,
            TransferError::DestinationExists
            | TransferError::DestinationMissing
            | TransferError::DestinationHashMismatch { .. }
            | TransferError::Replay
            | TransferError::Gap
            | TransferError::SourceChanged
            | TransferError::HashMismatch
            | TransferError::StaleFence
            | TransferError::Terminal
            | TransferError::LeaseBusy => app_error::CONFLICT,
            _ => app_error::INTERNAL,
        };
        IpcError::Remote {
            code,
            message: error.to_string(),
        }
    }

    fn ensure_destination_cache_capacity(&self, plan_id: &str) -> Result<(), TransferError> {
        if !self.transfer_receivers.contains_key(plan_id)
            && self.transfer_receivers.len() >= MAX_CACHED_DESTINATION_TRANSFERS
        {
            return Err(TransferError::JournalQuotaExceeded);
        }
        Ok(())
    }

    fn rebuild_destination_transfer(
        &self,
        plan: TransferPlan,
        journal: ownmesh_transfer::TransferJournal,
        epoch: u64,
        fence: u64,
    ) -> Result<CachedDestinationTransfer, TransferError> {
        let sink =
            PartFileSink::create(&self.transfer_store, &plan, epoch, journal.bytes_received())?;
        #[cfg(test)]
        self.transfer_receiver_rebuilds
            .fetch_add(1, Ordering::SeqCst);
        let receiver = TransferReceiver::resume_from_part(plan, journal, sink.path())?;
        Ok(CachedDestinationTransfer {
            epoch,
            fence,
            receiver,
            sink,
        })
    }

    /// Derive every transfer authority fact from the authenticated remote
    /// dispatch.  In particular no transfer RPC parameter can nominate a
    /// principal, tenant, device, consent, payload hash, expiry, relay, or
    /// overwrite behavior.
    fn transfer_authority(&self, client: &ClientIdentity) -> IpcResult<TransferAuthority> {
        let Some(operation_id) = self.active_remote_operation_id.as_deref() else {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "transfer requires an authenticated remote operation binding".into(),
            });
        };
        let Some(payload_sha256) = self.active_remote_payload_hash.as_deref() else {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "transfer requires a verified remote payload hash".into(),
            });
        };
        let Some(device_id) = self.active_remote_device_id.as_deref() else {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "transfer requires a verified remote device identity".into(),
            });
        };
        let Some(expires_at) = self.active_remote_expires_at_unix else {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "transfer requires a verified remote expiry".into(),
            });
        };
        let expires_at_unix = u64::try_from(expires_at).map_err(|_| IpcError::Remote {
            code: app_error::UNAUTHORIZED,
            message: "transfer remote expiry is invalid".into(),
        })?;
        if expires_at_unix <= Self::now() as u64 {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "transfer remote grant has expired".into(),
            });
        }
        let mut parts = client.principal_key().split(':');
        let (Some("client"), Some("remote"), Some(tenant_id), Some(principal_id), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "transfer caller is not a verified remote principal".into(),
            });
        };
        if tenant_id.is_empty() || principal_id.is_empty() || device_id.is_empty() {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "transfer binding identity is empty".into(),
            });
        }
        Ok(TransferAuthority {
            tenant_id: tenant_id.to_owned(),
            principal_id: principal_id.to_owned(),
            device_id: device_id.to_owned(),
            operation_id: operation_id.to_owned(),
            payload_sha256: payload_sha256.to_owned(),
            expires_at_unix,
        })
    }

    fn verify_local_transfer_identity(
        plan: &TransferPlan,
        authority: &TransferAuthority,
        role: Option<&str>,
    ) -> IpcResult<()> {
        let binding = plan.binding();
        if binding.tenant_id != authority.tenant_id
            || binding.source_principal_id != authority.principal_id
            || binding.destination_principal_id != authority.principal_id
        {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "transfer plan is not bound to this authenticated local device/principal"
                    .into(),
            });
        }
        let local = match role {
            Some("source") => binding.source_device_id == authority.device_id,
            Some("destination") => binding.destination_device_id == authority.device_id,
            None => {
                binding.source_device_id == authority.device_id
                    || binding.destination_device_id == authority.device_id
            }
            _ => false,
        };
        if !local {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "transfer plan is not bound to this authenticated local device role"
                    .into(),
            });
        }
        Ok(())
    }

    async fn handle_logs_query(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let p: LogsQueryParams = parse_params(params)?;
        let facts = OperationFacts {
            capability: "logs.read".into(),
            kind: "logs".into(),
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::LogsQuery(p), client)
            .await
    }

    fn handle_logs_list_providers(&self, params: Option<Value>) -> IpcResult<Value> {
        let p: LogsQueryParams = parse_params(params.or_else(|| Some(json!({}))))?;
        let reg = self.build_log_registry(&p);
        Ok(json!({ "providers": reg.list_ids() }))
    }

    async fn handle_git_status(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let mut p: GitStatusParams = parse_params(params)?;
        p.workspace_id = self.workspace_id_for_path(p.workspace_id.as_deref(), &p.path)?;
        let facts = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "git".into(),
            path: Some(p.path.clone()),
            workspace_relative: !Path::new(&p.path).is_absolute(),
            workspace_id: p.workspace_id.clone(),
            tags: vec!["git".into(), "status".into()],
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::GitStatus(p), client)
            .await
    }

    async fn handle_git_diff(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let mut p: GitDiffParams = parse_params(params)?;
        p.workspace_id = self.workspace_id_for_path(p.workspace_id.as_deref(), &p.path)?;
        let facts = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "git".into(),
            path: Some(p.path.clone()),
            workspace_relative: !Path::new(&p.path).is_absolute(),
            workspace_id: p.workspace_id.clone(),
            // A diff returns repository file contents. Without enumerating and
            // opening every changed path before the policy gate, it cannot prove
            // that credential-like files are absent. Restricted presets therefore
            // require confirmation; full-access presets ignore this tag.
            tags: vec![
                "git".into(),
                "diff".into(),
                TAG_READS_SENSITIVE_LOCATION.into(),
            ],
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::GitDiff(p), client)
            .await
    }

    async fn handle_review_start(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        /// Network DTO deliberately excludes executable pins: the daemon resolves and
        /// pins every program itself before it creates a receipt or starts a process.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct CommandRequest {
            program: String,
            #[serde(default)]
            args: Vec<String>,
            timeout_ms: u64,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct TestRequestDto {
            program: String,
            #[serde(default)]
            args: Vec<String>,
            timeout_ms: u64,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct P {
            workspace_id: String,
            #[serde(default)]
            path: String,
            #[serde(default)]
            command: Option<CommandRequest>,
            tests: Vec<TestRequestDto>,
            // Agent transport binds the server-side operation idempotency key
            // into every mapped method.  It is authority only in the remote
            // envelope/journal, never a client-selected review receipt field.
            #[serde(default)]
            idempotency_key: Option<String>,
        }
        let p: P = parse_params(params)?;
        let _ = &p.idempotency_key;
        let device_id = self
            .active_remote_device_id
            .as_deref()
            .ok_or_else(|| IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "review.start requires verified Agent device identity".into(),
            })?
            .to_owned();
        let principal = canonicalize_principal_key(client.principal_key());
        // Exact-once journal replay (P0-B / MCP `review.start` contract):
        // consult the receipt *before* workspace/pinning/policy preflight so
        // a retried start after response loss returns the original review
        // even when the workspace was removed or a program is no longer
        // installed (the first operation already ran; its receipt carries the
        // `review_id` continuation and the exact payload hash). An
        // in-progress/uncertain marker stays fail-closed. The durable marker
        // itself is still reserved only after preflight, so a preflight
        // failure on a *new* operation never poisons the key.
        let journal_key = self
            .active_remote_operation_id
            .as_ref()
            .map(|operation_id| principal_journal_key(&principal, operation_id));
        if let Some(previous) = self.lookup_idempotent(journal_key.as_ref())? {
            if previous.get("remote_payload_hash").and_then(Value::as_str)
                != self.active_remote_payload_hash.as_deref()
            {
                return Err(IpcError::Remote {
                    code: app_error::UNAUTHORIZED,
                    message: "review operation id replay payload binding mismatch".into(),
                });
            }
            return Ok(previous);
        }
        if self.enforce_workspace {
            return Err(IpcError::Remote {
                code: app_error::POLICY_DENIED,
                message: "review command execution is denied under a restricted workspace preset until OS process confinement is available".into(),
            });
        }
        let ws = self.workspace_for(Some(&p.workspace_id))?;
        let repo_cwd = ws.resolve(Path::new(&p.path)).map_err(fs_err)?;
        let command = p
            .command
            .map(|request| {
                self.pin_review_command(
                    request.program,
                    request.args,
                    request.timeout_ms,
                    &repo_cwd,
                )
            })
            .transpose()?;
        let tests: Vec<TestRequest> = p
            .tests
            .into_iter()
            .map(|request| {
                self.pin_review_command(
                    request.program,
                    request.args,
                    request.timeout_ms,
                    &repo_cwd,
                )
                .map(|command| TestRequest {
                    program: command.program,
                    args: command.args,
                    timeout_ms: command.timeout_ms,
                    invocation_pin: command.invocation_pin,
                    pin: command.pin,
                })
            })
            .collect::<IpcResult<_>>()?;

        // Review runs are a batch of independently policy-sensitive programs.
        // Never infer authorization from the first program: the most restrictive
        // local verdict wins before repository inspection or process execution.
        let mut aggregate = Decision::Allow;
        let mut reasons = Vec::new();
        let mut review_programs: Vec<(&String, &ExecutablePin, &ExecutablePin)> = Vec::new();
        if let Some(command) = command.as_ref() {
            review_programs.push((
                &command.program,
                command.invocation_pin.as_ref().unwrap_or(&command.pin),
                &command.pin,
            ));
        }
        review_programs.extend(tests.iter().map(|test| {
            (
                &test.program,
                test.invocation_pin.as_ref().unwrap_or(&test.pin),
                &test.pin,
            )
        }));
        for (program, invocation_pin, pin) in review_programs {
            let facts = OperationFacts {
                capability: "command.run".into(),
                kind: "structured".into(),
                program: Some(program.clone()),
                path: Some(repo_cwd.to_string_lossy().into_owned()),
                workspace_relative: true,
                executable_identity: Some(executable_identity_from_pin(pin)),
                invocation_identity: Some(executable_identity_from_pin(invocation_pin)),
                tags: vec!["review".into()],
                ..Default::default()
            };
            let mut verdict = self.evaluate(&facts, &principal);
            let delegated_remote = self.delegate_remote_mcp
                && self.active_remote_operation_id.is_some()
                && self.active_remote_payload_hash.is_some()
                && self
                    .active_remote_expires_at_unix
                    .is_some_and(|expiry| expiry >= Self::now());
            if delegated_remote && verdict.decision == Decision::Ask {
                verdict.decision = Decision::Allow;
                verdict
                    .reason
                    .push_str("; remote MCP delegation configured");
            }
            aggregate = aggregate.tighten(verdict.decision);
            reasons.push(verdict.reason);
        }
        if aggregate == Decision::Deny {
            return Err(IpcError::Remote {
                code: app_error::POLICY_DENIED,
                message: format!("policy denied review batch: {}", reasons.join("; ")),
            });
        }
        if aggregate == Decision::Ask {
            return Err(IpcError::Remote {
                code: app_error::POLICY_DENIED,
                message: format!("review batch requires a policy approval path which is not available for review.start: {}", reasons.join("; ")),
            });
        }
        let operation_id = self
            .active_remote_operation_id
            .clone()
            .unwrap_or_else(|| Self::new_id("op_"));
        self.begin_idempotent(journal_key.as_ref(), &operation_id)?;
        let status = git_status(
            &ws,
            &GitStatusOpts {
                path: PathBuf::from(&p.path),
                cursor: None,
                limit: 1,
            },
        )
        .map_err(fs_err)?;
        let head_oid = git_head_oid(&ws, Path::new(&p.path)).map_err(fs_err)?;
        let initial_status = serde_json::to_vec(&status).map_err(|error| IpcError::Remote {
            code: app_error::INTERNAL,
            message: error.to_string(),
        })?;
        let now = Self::now();
        let manifest = ReviewManifest {
            review_id: Self::new_id("rev_"),
            device_id,
            workspace_id: p.workspace_id,
            repo_root: status.repo_root,
            head_oid,
            principal: client.client_name.clone(),
            phase: ReviewPhase::Planned,
            command,
            tests,
            remote_operation_id: self.active_remote_operation_id.clone(),
            remote_payload_hash: self.active_remote_payload_hash.clone(),
            status_cursor: 0,
            diff_cursor: 0,
            result_sha256: None,
            created_unix: now,
            expires_unix: now.saturating_add(3600),
        };
        let saved = self
            .review_manifests
            .begin(manifest)
            .map_err(|message| IpcError::Remote {
                code: app_error::CONFLICT,
                message,
            })?;
        self.review_manifests
            .set_phase(&saved.review_id, ReviewPhase::Running)
            .map_err(|message| IpcError::Remote {
                code: app_error::INTERNAL,
                message,
            })?;
        let mut chunks = Vec::new();
        append_review_system(
            &mut chunks,
            format!(
                "baseline git status: {}",
                String::from_utf8_lossy(&initial_status)
            ),
        );
        let mut failed = false;
        let mut cancelled = false;
        if let Some(command) = saved.command.as_ref() {
            if git_head_oid(&ws, Path::new(&saved.repo_root)).map_err(fs_err)? == saved.head_oid {
                let result = self
                    .run_review_command(command, Path::new(&saved.repo_root))
                    .await;
                cancelled |= result.1;
                failed |= !result.0;
                let summary = format_run_summary("command", &result.2);
                append_review_result(
                    &mut chunks,
                    ResultKind::CommandStdout,
                    None,
                    result.2.stdout.into_bytes(),
                );
                append_review_result(
                    &mut chunks,
                    ResultKind::CommandStderr,
                    None,
                    result.2.stderr.into_bytes(),
                );
                append_review_system(&mut chunks, summary);
            } else {
                append_review_system(
                    &mut chunks,
                    "review repository HEAD changed before command spawn".into(),
                );
                failed = true;
            }
        }
        if !cancelled
            && !failed
            && git_head_oid(&ws, Path::new(&saved.repo_root)).map_err(fs_err)? != saved.head_oid
        {
            append_review_system(
                &mut chunks,
                "review repository HEAD changed after command; tests not started".into(),
            );
            failed = true;
        }
        if !cancelled && !failed {
            for (index, test) in saved.tests.iter().enumerate() {
                let result = self
                    .run_review_test(test, Path::new(&saved.repo_root))
                    .await;
                cancelled |= result.1;
                failed |= !result.0;
                let summary = format_run_summary(&format!("test[{index}]"), &result.2);
                append_review_result(
                    &mut chunks,
                    ResultKind::TestStdout,
                    Some(index as u8),
                    result.2.stdout.into_bytes(),
                );
                append_review_result(
                    &mut chunks,
                    ResultKind::TestStderr,
                    Some(index as u8),
                    result.2.stderr.into_bytes(),
                );
                append_review_system(&mut chunks, summary);
                if cancelled {
                    break;
                }
            }
        }
        if cancelled {
            append_review_system(
                &mut chunks,
                "review cancelled; process tree termination requested".into(),
            );
        }
        if !cancelled
            && git_head_oid(&ws, Path::new(&saved.repo_root)).map_err(fs_err)? != saved.head_oid
        {
            append_review_system(
                &mut chunks,
                "review repository HEAD changed after tests; final result is stale".into(),
            );
            failed = true;
        }
        match git_status(
            &ws,
            &GitStatusOpts {
                path: PathBuf::from(&saved.repo_root),
                cursor: None,
                limit: 500,
            },
        ) {
            Ok(status) => append_review_result(
                &mut chunks,
                ResultKind::GitStatus,
                None,
                serde_json::to_vec(&status)
                    .unwrap_or_else(|_| b"git status serialization failed".to_vec()),
            ),
            Err(error) => {
                append_review_system(&mut chunks, format!("git status snapshot failed: {error}"));
            }
        }
        match git_diff(
            &ws,
            &GitDiffOpts {
                path: PathBuf::from(&saved.repo_root),
                cursor: None,
                limit: 500,
                max_bytes: 64 * 1024,
                ..Default::default()
            },
        ) {
            Ok(diff) => append_review_result(
                &mut chunks,
                ResultKind::GitDiff,
                None,
                serde_json::to_vec(&diff)
                    .unwrap_or_else(|_| b"git diff serialization failed".to_vec()),
            ),
            Err(error) => {
                append_review_system(&mut chunks, format!("git diff snapshot failed: {error}"));
            }
        }
        if chunks.len() >= 58 {
            append_review_system(
                &mut chunks,
                "review aggregate spool truncated at bounded chunk budget".into(),
            );
        }
        let phase = if cancelled {
            ReviewPhase::Cancelled
        } else if failed {
            ReviewPhase::Failed
        } else {
            ReviewPhase::Completed
        };
        self.review_results
            .write(&saved.review_id, saved.expires_unix, chunks)
            .map_err(|message| IpcError::Remote {
                code: app_error::INTERNAL,
                message,
            })?;
        let digest = self
            .review_results
            .page(&saved.review_id, 0, 1, Self::now())
            .map_err(|message| IpcError::Remote {
                code: app_error::INTERNAL,
                message,
            })?
            .sha256;
        let completed = self
            .review_manifests
            .finish(&saved.review_id, phase, digest)
            .map_err(|message| IpcError::Remote {
                code: app_error::INTERNAL,
                message,
            })?;
        let mut body = serde_json::to_value(completed).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })?;
        if let Some(object) = body.as_object_mut() {
            object.insert(
                "remote_payload_hash".into(),
                json!(self.active_remote_payload_hash),
            );
            // The compaction classifier recognizes a completed receipt only
            // when it carries the exact-once `operation_id` this version
            // writes in `begin_idempotent` (P0-B). `ReviewManifest` serializes
            // the control-plane id as `remote_operation_id`, so without this
            // field a finished review was classified uncertain: compaction
            // refused to shrink it (retaining pins/argv durably) and a retried
            // `review.start` after restart or response loss received an
            // "in-progress or uncertain" CONFLICT instead of the documented
            // receipt. The local journal id equals `active_remote_operation_id`
            // on the Agent path and is freshly minted for local runs; it is
            // additive for receipt consumers.
            object.insert("operation_id".into(), json!(operation_id));
        }
        self.store_idempotent(journal_key.as_ref(), &body)?;
        Ok(body)
    }

    fn pin_review_command(
        &self,
        program: String,
        args: Vec<String>,
        timeout_ms: u64,
        cwd: &Path,
    ) -> IpcResult<ReviewCommand> {
        if program.trim().is_empty() || timeout_ms == 0 || timeout_ms > 300_000 {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "invalid review argv command".into(),
            });
        }
        let invocation =
            resolve_executable_invocation_path(&program, Some(cwd)).ok_or_else(|| {
                IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "review program could not be resolved to a regular executable".into(),
                }
            })?;
        let resolved =
            resolve_executable_path(&program, Some(cwd)).ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "review program could not be resolved to a regular executable".into(),
            })?;
        let invocation_program = invocation.to_string_lossy().into_owned();
        let backing_program = resolved.to_string_lossy().into_owned();
        if classify_from_request_in_dir(None, &invocation_program, &args, Some(cwd))
            != CommandKind::Structured
            || classify_from_request_in_dir(None, &backing_program, &args, Some(cwd))
                != CommandKind::Structured
        {
            return Err(IpcError::Remote { code: app_error::POLICY_DENIED, message: "review commands must be pinned structured argv executables, not shells or interpreters".into() });
        }
        let pin = pin_executable(&resolved, CommandKind::Structured).map_err(|error| {
            IpcError::Remote {
                code: app_error::POLICY_DENIED,
                message: format!("unable to pin review executable: {error}"),
            }
        })?;
        let invocation_pin =
            pin_executable(&invocation, CommandKind::Structured).map_err(|error| {
                IpcError::Remote {
                    code: app_error::POLICY_DENIED,
                    message: format!("unable to pin review invocation executable: {error}"),
                }
            })?;
        Ok(ReviewCommand {
            program: invocation_program,
            args,
            timeout_ms,
            invocation_pin: Some(invocation_pin),
            pin,
        })
    }

    async fn run_review_command(
        &self,
        command: &ReviewCommand,
        cwd: &Path,
    ) -> (bool, bool, RunResult) {
        let invocation_pin = command.invocation_pin.as_ref().unwrap_or(&command.pin);
        let classified = classify_from_request_in_dir(None, &command.program, &command.args, None)
            == CommandKind::Structured
            && classify_from_request_in_dir(None, &command.pin.path, &command.args, None)
                == CommandKind::Structured;
        let prepared = if classified {
            prepare_executable(
                Path::new(&command.program),
                invocation_pin,
                &command.pin,
                Some(&self.paths.runtime_dir),
            )
            .ok()
        } else {
            None
        };
        let Some(prepared) = prepared else {
            return (
                false,
                false,
                RunResult {
                    exit_code: None,
                    stdout: String::new(),
                    stderr: "OWNMESH_E_EXECUTABLE_IDENTITY_DRIFT: executable preparation failed; review command was not spawned".into(),
                    stdout_decoding: None,
                    stderr_decoding: None,
                    timed_out: false,
                    duration_ms: 0,
                    truncated: false,
                    pid: None,
                    replayed: false,
                },
            );
        };
        let request = RunRequest {
            kind: CommandKind::Structured,
            program: command.program.clone(),
            args: command.args.clone(),
            cwd: Some(cwd.to_path_buf()),
            env: HashMap::new(),
            stdin: None,
            timeout_ms: Some(command.timeout_ms),
            max_output_bytes: 96 * 1024,
            idempotency_key: None,
        };
        match run_prepared_command_cancellable(&request, prepared, None, self.active_cancel.clone())
            .await
        {
            Ok(result) => {
                let cancelled = self
                    .active_cancel
                    .as_ref()
                    .is_some_and(|receiver| *receiver.borrow());
                (
                    result.exit_code == Some(0) && !result.timed_out && !cancelled,
                    cancelled,
                    result,
                )
            }
            Err(error) => {
                let cancelled = matches!(error, ownmesh_exec::ExecError::Cancelled);
                (
                    false,
                    cancelled,
                    RunResult {
                        exit_code: None,
                        stdout: String::new(),
                        stderr: error.to_string(),
                        stdout_decoding: None,
                        stderr_decoding: None,
                        timed_out: false,
                        duration_ms: 0,
                        truncated: false,
                        pid: None,
                        replayed: false,
                    },
                )
            }
        }
    }

    async fn run_review_test(&self, test: &TestRequest, cwd: &Path) -> (bool, bool, RunResult) {
        self.run_review_command(
            &ReviewCommand {
                program: test.program.clone(),
                args: test.args.clone(),
                timeout_ms: test.timeout_ms,
                invocation_pin: test.invocation_pin.clone(),
                pin: test.pin.clone(),
            },
            cwd,
        )
        .await
    }

    fn handle_review_show(
        &self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            review_id: String,
        }
        let p: P = parse_params(params)?;
        let review = self
            .review_manifests
            .get(&p.review_id)
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "review not found".into(),
            })?;
        if review.principal != client.client_name
            || self.active_remote_device_id.as_deref() != Some(review.device_id.as_str())
            || review.expires_unix < Self::now()
        {
            return Err(IpcError::Remote {
                code: app_error::POLICY_DENIED,
                message: "review binding mismatch".into(),
            });
        }
        let ws = self.workspace_for(Some(&review.workspace_id))?;
        if git_head_oid(&ws, Path::new(&review.repo_root)).map_err(fs_err)? != review.head_oid {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "review repository HEAD changed; start a new review".into(),
            });
        }
        let result = self
            .review_results
            .page(&p.review_id, 0, 1, Self::now())
            .map_err(|message| IpcError::Remote {
                code: app_error::INTERNAL,
                message,
            })?;
        Ok(json!({ "review": review, "result": result }))
    }

    fn handle_review_page(
        &self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct P {
            review_id: String,
            #[serde(default)]
            cursor: u64,
            #[serde(default = "review_page_limit")]
            max_bytes: usize,
            // The authenticated Agent layer adds its server-owned idempotency
            // key uniformly to mapped methods. Pagination itself is read-only;
            // retain no caller authority from this transport field.
            #[serde(default)]
            idempotency_key: Option<String>,
        }
        let p: P = parse_params(params)?;
        let _ = &p.idempotency_key;
        let review = self
            .review_manifests
            .get(&p.review_id)
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "review not found".into(),
            })?;
        if review.principal != client.client_name
            || self.active_remote_device_id.as_deref() != Some(review.device_id.as_str())
            || review.expires_unix < Self::now()
        {
            return Err(IpcError::Remote {
                code: app_error::POLICY_DENIED,
                message: "review binding expired or mismatched".into(),
            });
        }
        let ws = self.workspace_for(Some(&review.workspace_id))?;
        let head = git_head_oid(&ws, Path::new(&review.repo_root)).map_err(fs_err)?;
        if head != review.head_oid {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "review repository HEAD changed; start a new review".into(),
            });
        }
        let page = self
            .review_results
            .page(
                &p.review_id,
                p.cursor,
                p.max_bytes.min(48 * 1024),
                Self::now(),
            )
            .map_err(|message| IpcError::Remote {
                code: app_error::CONFLICT,
                message,
            })?;
        serde_json::to_value(page).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })
    }

    fn handle_approval_list(&self) -> IpcResult<Value> {
        let mut list: Vec<&ApprovalRecord> = self.approvals.values().collect();
        list.sort_by(|a, b| b.created_at_unix.cmp(&a.created_at_unix));
        Ok(json!({ "approvals": list }))
    }

    fn handle_approval_show(&self, params: Option<Value>) -> IpcResult<Value> {
        let id = require_id(params, "id")?;
        let rec = self.approvals.get(&id).ok_or_else(|| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: format!("approval not found: {id}"),
        })?;
        serde_json::to_value(rec).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })
    }

    async fn handle_approval_approve(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            #[serde(default)]
            grant_seconds: Option<i64>,
            #[serde(default)]
            temporary_grant: bool,
            // Client-supplied approver identity is intentionally ignored.
            #[serde(default)]
            approver_principal_id: Option<String>,
            #[serde(default)]
            approver_id: Option<String>,
            #[serde(default)]
            principal_id: Option<String>,
        }
        let p: P = parse_params(params)?;
        let _ = (p.approver_principal_id, p.approver_id, p.principal_id);
        let approver = canonicalize_principal_key(client.principal_key());
        let rec = self.approvals.get(&p.id).ok_or_else(|| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: format!("approval not found: {}", p.id),
        })?;
        if rec.state != "pending" {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!("approval already {}", rec.state),
            });
        }
        ensure_independent_human_approver(&approver, &rec.requester_principal)?;
        let request = rec.request.clone();
        let capability = rec.capability.clone();
        let operation_id = rec.operation_id.clone();
        let requester_principal = rec.requester_principal.clone();
        if let PendingRequest::AdminTokenRevoke(target) = &request {
            if canonicalize_principal_key(&target.principal) == requester_principal {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "cannot revoke the principal that authorized this request".into(),
                });
            }
        }
        // Server-captured policy facts only — never trust client-supplied grant scope.
        let approved_facts = rec.facts.clone();
        let raw_idem_key = match &request {
            PendingRequest::Exec(x) => x.idempotency_key.clone(),
            PendingRequest::FsList(x) => x.idempotency_key.clone(),
            PendingRequest::FsStat(x) => x.idempotency_key.clone(),
            PendingRequest::FsRead(x) => x.idempotency_key.clone(),
            PendingRequest::FsWrite(x) => x.idempotency_key.clone(),
            PendingRequest::FsDelete(x) => x.idempotency_key.clone(),
            PendingRequest::LogsQuery(x) => x.idempotency_key.clone(),
            PendingRequest::GitStatus(x) => x.idempotency_key.clone(),
            PendingRequest::GitDiff(x) => x.idempotency_key.clone(),
            PendingRequest::SystemDiagnose(x) => x.idempotency_key.clone(),
            PendingRequest::AdminPolicyPreset(x) => Some(x.idempotency_key.clone()),
            PendingRequest::AdminPolicyRuleAdd(x) => Some(x.idempotency_key.clone()),
            PendingRequest::AdminPolicyRuleRemove(x) => Some(x.idempotency_key.clone()),
            PendingRequest::AdminDaemonUnlock(x) => Some(x.idempotency_key.clone()),
            PendingRequest::AdminTokenRevoke(x) => Some(x.idempotency_key.clone()),
            PendingRequest::AdminApprovalBridge(x) => Some(x.idempotency_key.clone()),
            PendingRequest::AdminGrantsMint(x) => Some(x.idempotency_key.clone()),
        };
        // Same principal namespace as gate_and_run so approve + direct retry share one slot.
        let idem_key = raw_idem_key
            .as_ref()
            .map(|k| principal_journal_key(&requester_principal, k));

        // Build (or refuse) the temporary grant before mutating durable approval state.
        if p.temporary_grant && pending_request_is_admin(&request) {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "temporary grants are not supported for admin or approval-bridge actions"
                    .into(),
            });
        }
        self.check_pending_request_lockdown(&request)?;
        let pending_grant = if p.temporary_grant {
            let secs = p.grant_seconds.unwrap_or(DEFAULT_GRANT_SECS);
            // Bind the grant to the requester that was approved — never a global prin_local.
            let grant_principal = if requester_principal.is_empty() {
                LOCAL_PRINCIPAL.to_owned()
            } else {
                requester_principal.clone()
            };
            let expires_unix = Self::now().saturating_add(secs);
            let grant_id = Self::new_id("grant_");
            // Every grant — not just command.run — is minted from the recorded
            // server approval facts. Hand-assembling the struct here is what
            // previously produced unscoped (all-path) filesystem grants, so the
            // vetted constructor is now the only issuance path.
            let Some(facts) = approved_facts.as_ref() else {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "temporary grant requires server approval facts".into(),
                });
            };
            // Defense-in-depth: approval capability and fact capability must agree.
            if facts.capability.trim() != capability.trim() {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "temporary grant capability does not match server approval facts"
                        .into(),
                });
            }
            Some(
                temporary_grant_from_facts(grant_id, grant_principal, expires_unix, facts)
                    .map_err(|message| IpcError::Remote {
                        code: app_error::INVALID_PARAMS,
                        message,
                    })?,
            )
        } else {
            None
        };

        let approvals_before = self.approvals.clone();
        let grants_before = self.grants.clone();
        let op_journal_before = self.op_journal.clone();

        // The approval record commits `executing` first. Any crash after this
        // point is fail-closed even if later pre-execution preparation has not
        // completed: restart can never expose this approval as pending again.
        if let Some(rec) = self.approvals.get_mut(&p.id) {
            rec.state = "executing".into();
            rec.decided_at_unix = Some(Self::now());
        }
        if let Err(e) = self.persist_approvals() {
            self.approvals = approvals_before;
            self.grants = grants_before;
            self.op_journal = op_journal_before;
            return Err(e);
        }

        if let Err(e) = self.begin_idempotent(idem_key.as_ref(), &operation_id) {
            self.approvals = approvals_before;
            self.grants = grants_before;
            self.op_journal = op_journal_before;
            let rollback_errors = self.persist_approvals().err().into_iter().collect();
            return Err(with_rollback_errors(e, rollback_errors));
        }

        // Disclosed back to the caller so "allow for a while" never hides how
        // much it actually allowed.
        let granted_scope = pending_grant.as_ref().map(|grant| {
            json!({
                "id": grant.id,
                "capability": grant.capability,
                "principal_id": grant.principal_id,
                "scope": grant.path_prefix,
                "workspace_id": grant.workspace_id,
                "expires_at_unix": grant.expires_unix,
            })
        });
        if let Some(grant) = pending_grant {
            self.grants.push(StoredGrant::Temporary(grant));
            if let Err(e) = self.persist_grants() {
                self.approvals = approvals_before;
                self.grants = grants_before;
                self.op_journal = op_journal_before;
                let mut rollback_errors = Vec::new();
                // Remove the keyed marker before making the approval pending again.
                if idem_key.is_some() {
                    rollback_errors.extend(self.persist_op_journal().err());
                }
                rollback_errors.extend(self.persist_approvals().err());
                return Err(with_rollback_errors(e, rollback_errors));
            }
        }

        // From this point onward the durable `executing` state is intentionally
        // never compensated back to pending. An execution error can itself have an
        // uncertain side effect, so retry must be refused just like a final persist
        // failure.
        let executing_approvals = self.approvals.clone();
        let executing_op_journal = self.op_journal.clone();
        let is_approval_bridge = matches!(&request, PendingRequest::AdminApprovalBridge(_));
        let result = match &request {
            PendingRequest::Exec(p) => self.execute_exec(p, false).await,
            PendingRequest::AdminApprovalBridge(p) => {
                self.execute_approval_bridge(p, &approver).await
            }
            other => self.execute_request(other).await,
        }?;
        // A bridge may have durably completed its target approval. Preserve that
        // terminal target state if finalizing the outer bridge later fails.
        let post_execution_approvals = is_approval_bridge.then(|| self.approvals.clone());
        let mut body = json!({
            "approval_required": false,
            "operation_id": operation_id,
            "approval_id": p.id,
            "result": result,
            "replayed": false,
            "decision": "allow",
            "reason": "human approved",
        });
        if let Some(grant) = granted_scope {
            body["grant"] = grant;
        }

        if let Err(e) = self.store_idempotent(idem_key.as_ref(), &body) {
            if !is_approval_bridge {
                self.op_journal = executing_op_journal;
                self.approvals = executing_approvals;
            }
            return Err(e);
        }

        if let Some(rec) = self.approvals.get_mut(&p.id) {
            rec.state = "approved".into();
            rec.result = Some(body.clone());
            rec.decided_by_principal = Some(approver);
        }
        if let Err(e) = self.persist_approvals() {
            // The operation ran. Keep the durable and in-memory non-retriable
            // marker rather than pretending this approval is pending again. A
            // successfully persisted op-journal completion remains usable.
            self.approvals = post_execution_approvals.unwrap_or(executing_approvals);
            return Err(e);
        }

        self.append_audit(
            "approval.approved",
            Some(&capability),
            Some(&operation_id),
            Some("allow"),
            format!("approved {}", p.id),
        );
        Ok(body)
    }

    async fn execute_approval_bridge(
        &mut self,
        params: &AdminApprovalBridgeParams,
        approver: &str,
    ) -> IpcResult<Value> {
        let target = self
            .approvals
            .get(&params.approval_id)
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("local approval not found: {}", params.approval_id),
            })?
            .clone();
        if target.state != "pending"
            || target
                .expires_at_unix
                .is_some_and(|expiry| expiry < Self::now())
            || target.target_payload_hash.is_some()
            || pending_request_is_admin(&target.request)
        {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "target local approval is no longer pending and eligible".into(),
            });
        }
        ensure_independent_human_approver(approver, &target.requester_principal)?;
        self.check_pending_request_lockdown(&target.request)?;
        let recovery = ClientIdentity::new(approver, env!("CARGO_PKG_VERSION"));
        // Box the call because an approval bridge is itself executed from the
        // approval handler. Admission above forbids targeting another admin
        // request, so this indirection cannot form a runtime approval cycle.
        Box::pin(self.handle_approval_approve(
            Some(json!({
                "id": params.approval_id,
                "temporary_grant": params.temporary_grant,
                "grant_seconds": params.grant_seconds,
            })),
            &recovery,
        ))
        .await
    }

    fn deny_approval_bridge(
        &mut self,
        bridge_id: &str,
        params: &AdminApprovalBridgeParams,
        approver: &str,
    ) -> IpcResult<Value> {
        let bridge = self
            .approvals
            .get(bridge_id)
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("approval not found: {bridge_id}"),
            })?
            .clone();
        let target = self
            .approvals
            .get(&params.approval_id)
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("local approval not found: {}", params.approval_id),
            })?
            .clone();
        if bridge.state != "pending" || target.state != "pending" {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "approval bridge or target was already decided".into(),
            });
        }
        ensure_independent_human_approver(approver, &bridge.requester_principal)?;
        ensure_independent_human_approver(approver, &target.requester_principal)?;
        let snapshot = self.approvals.clone();
        let now = Self::now();
        for id in [bridge_id, params.approval_id.as_str()] {
            if let Some(record) = self.approvals.get_mut(id) {
                record.state = "denied".into();
                record.decided_at_unix = Some(now);
                record.decided_by_principal = Some(approver.to_owned());
            }
        }
        if let Err(error) = self.persist_approvals() {
            self.approvals = snapshot;
            return Err(error);
        }
        self.append_audit(
            "approval.bridge_denied",
            Some(&target.capability),
            Some(&target.operation_id),
            Some("deny"),
            format!("denied local request {}", target.id),
        );
        Ok(json!({
            "approval_id": bridge_id,
            "target_approval_id": target.id,
            "target_operation_id": target.operation_id,
            "state": "denied",
        }))
    }

    fn handle_approval_deny(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let id = require_id(params, "id")?;
        let approver = canonicalize_principal_key(client.principal_key());
        let approvals_snapshot = self.approvals.clone();
        let rec = self
            .approvals
            .get_mut(&id)
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("approval not found: {id}"),
            })?;
        if rec.state != "pending" {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!("approval already {}", rec.state),
            });
        }
        ensure_independent_human_approver(&approver, &rec.requester_principal)?;
        rec.state = "denied".into();
        rec.decided_at_unix = Some(Self::now());
        rec.decided_by_principal = Some(approver);
        let operation_id = rec.operation_id.clone();
        let capability = rec.capability.clone();
        if let Err(e) = self.persist_approvals() {
            self.approvals = approvals_snapshot;
            return Err(e);
        }
        self.append_audit(
            "approval.denied",
            Some(&capability),
            Some(&operation_id),
            Some("deny"),
            format!("denied {id}"),
        );
        Ok(json!({
            "approval_id": id,
            "operation_id": operation_id,
            "state": "denied",
        }))
    }

    fn handle_policy_show(&self) -> IpcResult<Value> {
        Ok(json!({
            "preset": preset_name(self.policy.preset),
            "note": self.policy.note,
            "rules": self.policy.rules,
            "lockdown": self.lockdown,
            "delegate_remote_mcp": self.delegate_remote_mcp,
            "grants": self.grants,
            "full_access_conformance": full_access_has_no_hidden_restrictive_rules(&self.policy)
                || self.policy.preset != AccessPreset::FullAccess,
            "full_access_no_hidden_deny": if self.policy.preset == AccessPreset::FullAccess {
                full_access_has_no_hidden_restrictive_rules(&self.policy)
            } else {
                true
            },
            "workspace_root_enforcement": self.enforce_workspace,
            "enforce_workspace": self.enforce_workspace,
            "workspace_root_enforcement_note":
                "Independent of access_preset. When true, filesystem and command tools require a registered workspace. Full Access still allows an explicitly permitted absolute path only with workspace_id: null.",
        }))
    }

    fn handle_grants_list(&self) -> IpcResult<Value> {
        Ok(json!({
            "grants": self.grants,
            "bounded_tool": self.grants.iter().filter(|g| g.as_bounded_tool().is_some()).count(),
            "temporary": self.grants.iter().filter(|g| g.as_temporary().is_some()).count(),
        }))
    }

    fn handle_grants_show(&self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
        }
        let p: P = parse_params(params)?;
        let grant = self
            .grants
            .iter()
            .find(|grant| grant.id() == p.id)
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("grant not found: {}", p.id),
            })?;
        Ok(json!({ "grant": grant }))
    }

    fn handle_grants_revoke(&mut self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
        }
        let p: P = parse_params(params)?;
        let snapshot = self.grants.clone();
        let before = self.grants.len();
        self.grants.retain(|grant| grant.id() != p.id);
        if self.grants.len() == before {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("grant not found: {}", p.id),
            });
        }
        if let Err(e) = self.persist_grants() {
            self.grants = snapshot;
            return Err(e);
        }
        self.append_audit(
            "grants.revoke",
            None,
            None,
            Some("deny"),
            format!("revoked grant {}", p.id),
        );
        Ok(json!({ "revoked": p.id, "ok": true }))
    }

    fn execute_admin_grants_mint(&mut self, params: &AdminGrantsMintParams) -> IpcResult<Value> {
        validate_admin_idempotency_key(&params.idempotency_key)?;
        if params.ttl_seconds < 1 || params.ttl_seconds > MAX_BOUNDED_TOOL_GRANT_TTL_SECS {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("ttl_seconds must be 1..={MAX_BOUNDED_TOOL_GRANT_TTL_SECS}"),
            });
        }
        if let Some(max_uses) = params.max_uses {
            if max_uses == 0 || max_uses > MAX_BOUNDED_TOOL_GRANT_USES {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: format!("max_uses must be 1..={MAX_BOUNDED_TOOL_GRANT_USES}"),
                });
            }
        }
        let mut tools = Vec::new();
        for raw in &params.tools {
            let canonical = canonical_bounded_tool(raw).ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("unsupported or wildcard tool {raw}"),
            })?;
            if !tools.contains(&canonical.to_string()) {
                tools.push(canonical.to_string());
            }
        }
        if tools.is_empty() {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "tools must list at least one canonical tool".into(),
            });
        }
        let principal_id = params
            .principal_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "bounded grant mint requires the verified remote principal".into(),
            })?
            .to_owned();
        let device_id = params
            .device_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "bounded grant mint requires the verified device id".into(),
            })?
            .to_owned();
        let workspace_id = params
            .workspace_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        if let Some(workspace) = workspace_id.as_deref() {
            let _ = self.workspace_for(Some(workspace))?;
        }
        let now = Self::now();
        let grant = BoundedToolGrant {
            grant_type: BoundedToolGrantType::BoundedTool,
            id: Self::new_id("grant_"),
            principal_id,
            device_id,
            tools,
            workspace_id,
            expires_unix: now.saturating_add(params.ttl_seconds),
            max_uses: params.max_uses,
            uses: 0,
            minted_at_unix: now,
        };
        grant.validate().map_err(|message| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message,
        })?;
        let snapshot = self.grants.clone();
        self.grants.push(StoredGrant::BoundedTool(grant.clone()));
        if let Err(e) = self.persist_grants() {
            self.grants = snapshot;
            return Err(e);
        }
        self.append_audit(
            "grants.mint",
            None,
            None,
            Some("allow"),
            format!("minted bounded tool grant {}", grant.id),
        );
        Ok(json!({ "grant": grant, "ok": true }))
    }

    fn handle_admin_grants_mint_request(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let mut params: AdminGrantsMintParams = parse_params(params)?;
        validate_admin_idempotency_key(&params.idempotency_key)?;
        // Stamp identity from the live verified remote dispatch, then persist it
        // on the approval record. Recovery approve does not restore
        // `active_remote_*`, so execute must not reread those fields.
        let principal_id = self
            .active_remote_principal
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "bounded grant mint requires the verified remote principal".into(),
            })?;
        let device_id = self
            .active_remote_device_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "bounded grant mint requires the verified device id".into(),
            })?;
        params.principal_id = Some(principal_id);
        params.device_id = Some(device_id);
        self.enqueue_bound_admin_request(
            "admin.grants.mint",
            "Fresh passkey approval is required to mint a bounded tool grant.",
            PendingRequest::AdminGrantsMint(params),
            client,
        )
    }

    fn handle_policy_preset(&mut self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            name: String,
            #[serde(default)]
            delegate_remote_mcp: Option<bool>,
        }
        let p: P = parse_params(params)?;
        let preset = parse_preset(&p.name).ok_or_else(|| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: format!("unknown preset: {}", p.name),
        })?;
        let policy = preset_document(preset);
        let enforce_workspace = matches!(
            preset,
            AccessPreset::WorkspaceOnly | AccessPreset::Recommended
        );
        let file = PolicyFile {
            schema_version: 1,
            preset: Some(preset_name(preset).into()),
            delegate_remote_mcp: p.delegate_remote_mcp.unwrap_or(self.delegate_remote_mcp),
            rules: Vec::new(),
        };
        save_policy(&self.paths, &file).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })?;
        self.policy = policy;
        self.custom_policy_rules.clear();
        self.delegate_remote_mcp = file.delegate_remote_mcp;
        self.enforce_workspace = enforce_workspace;
        self.append_audit(
            "policy.preset",
            None,
            None,
            None,
            format!("preset set to {}", preset_name(preset)),
        );
        self.handle_policy_show()
    }

    fn execute_admin_policy_preset(
        &mut self,
        params: &AdminPolicyPresetParams,
    ) -> IpcResult<Value> {
        self.handle_policy_preset(Some(json!({
            "name": params.name,
            "delegate_remote_mcp": params.delegate_remote_mcp,
        })))
    }

    fn execute_admin_policy_rule_add(
        &mut self,
        params: &AdminPolicyRuleAddParams,
    ) -> IpcResult<Value> {
        if self.policy.preset == AccessPreset::FullAccess {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "full_access cannot contain hidden rules; select preset custom first"
                    .into(),
            });
        }
        if self
            .custom_policy_rules
            .iter()
            .any(|rule| rule.id == params.id)
        {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!("policy rule already exists: {}", params.id),
            });
        }
        let mut custom = self.custom_policy_rules.clone();
        custom.push(params.rule());
        let file = PolicyFile {
            schema_version: 1,
            preset: Some(preset_name(self.policy.preset).into()),
            delegate_remote_mcp: self.delegate_remote_mcp,
            rules: custom.clone(),
        };
        save_policy(&self.paths, &file).map_err(|error| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: error.to_string(),
        })?;
        self.custom_policy_rules = custom;
        self.policy = policy_from_file(&file);
        self.append_audit(
            "policy.rule_add",
            None,
            None,
            Some("allow"),
            format!("added policy rule {}", params.id),
        );
        self.handle_policy_show()
    }

    fn execute_admin_policy_rule_remove(
        &mut self,
        params: &AdminPolicyRuleRemoveParams,
    ) -> IpcResult<Value> {
        let mut custom = self.custom_policy_rules.clone();
        let before = custom.len();
        custom.retain(|rule| rule.id != params.id);
        if custom.len() == before {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("custom policy rule not found: {}", params.id),
            });
        }
        let file = PolicyFile {
            schema_version: 1,
            preset: Some(preset_name(self.policy.preset).into()),
            delegate_remote_mcp: self.delegate_remote_mcp,
            rules: custom.clone(),
        };
        save_policy(&self.paths, &file).map_err(|error| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: error.to_string(),
        })?;
        self.custom_policy_rules = custom;
        self.policy = policy_from_file(&file);
        self.append_audit(
            "policy.rule_remove",
            None,
            None,
            Some("allow"),
            format!("removed policy rule {}", params.id),
        );
        self.handle_policy_show()
    }

    fn handle_admin_policy_preset_request(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let params: AdminPolicyPresetParams = parse_params(params)?;
        validate_admin_idempotency_key(&params.idempotency_key)?;
        let preset = parse_preset(&params.name).ok_or_else(|| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: format!("unknown preset: {}", params.name),
        })?;
        if params.name != preset_name(preset) {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("preset must use canonical name {}", preset_name(preset)),
            });
        }
        self.enqueue_bound_admin_request(
            "admin.policy.preset",
            "Fresh passkey approval is required to replace the device policy preset.",
            PendingRequest::AdminPolicyPreset(params),
            client,
        )
    }

    fn handle_admin_policy_rule_add_request(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let params: AdminPolicyRuleAddParams = parse_params(params)?;
        validate_admin_idempotency_key(&params.idempotency_key)?;
        let candidate = PolicyFile {
            schema_version: 1,
            preset: Some(preset_name(self.policy.preset).into()),
            delegate_remote_mcp: self.delegate_remote_mcp,
            rules: vec![params.rule()],
        };
        candidate.validate().map_err(|error| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: error.to_string(),
        })?;
        if self.policy.preset == AccessPreset::FullAccess {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "full_access cannot contain hidden rules; select preset custom first"
                    .into(),
            });
        }
        if self
            .custom_policy_rules
            .iter()
            .any(|rule| rule.id == params.id)
        {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!("policy rule already exists: {}", params.id),
            });
        }
        self.enqueue_bound_admin_request(
            "admin.policy.rule_add",
            "Fresh passkey approval is required to add this exact policy rule.",
            PendingRequest::AdminPolicyRuleAdd(params),
            client,
        )
    }

    fn handle_admin_policy_rule_remove_request(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let params: AdminPolicyRuleRemoveParams = parse_params(params)?;
        validate_admin_idempotency_key(&params.idempotency_key)?;
        if !self
            .custom_policy_rules
            .iter()
            .any(|rule| rule.id == params.id)
        {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("custom policy rule not found: {}", params.id),
            });
        }
        self.enqueue_bound_admin_request(
            "admin.policy.rule_remove",
            "Fresh passkey approval is required to remove this exact policy rule.",
            PendingRequest::AdminPolicyRuleRemove(params),
            client,
        )
    }

    fn handle_admin_unlock_request(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let params: AdminDaemonUnlockParams = parse_params(params)?;
        validate_admin_idempotency_key(&params.idempotency_key)?;
        if !self.lockdown {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "device is not in emergency lockdown".into(),
            });
        }
        self.enqueue_bound_admin_request(
            "admin.daemon.unlock",
            "Fresh passkey approval is required to lift emergency lockdown.",
            PendingRequest::AdminDaemonUnlock(params),
            client,
        )
    }

    fn handle_admin_token_revoke_request(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let params: AdminTokenRevokeParams = parse_params(params)?;
        validate_admin_idempotency_key(&params.idempotency_key)?;
        let canonical = canonicalize_principal_key(&params.principal);
        if canonical.is_empty() || canonical != params.principal || params.principal.len() > 512 {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "principal must be a canonical server-assigned principal key".into(),
            });
        }
        if canonical == canonicalize_principal_key(client.principal_key()) {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "cannot revoke the principal authorizing this request; enroll or use a different administrator"
                    .into(),
            });
        }
        self.enqueue_bound_admin_request(
            "admin.token.revoke",
            "Fresh passkey approval is required to revoke this principal.",
            PendingRequest::AdminTokenRevoke(params),
            client,
        )
    }

    fn handle_admin_approval_bridge_request(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let params: AdminApprovalBridgeParams = parse_params(params)?;
        validate_admin_idempotency_key(&params.idempotency_key)?;
        if !matches!(params.decision.as_str(), "approve" | "deny") {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "decision must be approve or deny".into(),
            });
        }
        match (
            params.decision.as_str(),
            params.temporary_grant,
            params.grant_seconds,
        ) {
            ("approve", true, Some(seconds)) if (1..=86_400).contains(&seconds) => {}
            ("approve", false, None) | ("deny", false, None) => {}
            ("approve", true, _) => {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "temporary_grant requires grant_seconds between 1 and 86400".into(),
                });
            }
            ("approve", false, Some(_)) => {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "grant_seconds requires temporary_grant=true".into(),
                });
            }
            ("deny", _, Some(_)) | ("deny", true, None) => {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "deny intent cannot include a temporary grant".into(),
                });
            }
            _ => unreachable!("decision validated above"),
        }
        let target = self
            .approvals
            .get(&params.approval_id)
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("local approval not found: {}", params.approval_id),
            })?;
        if target.state != "pending"
            || target
                .expires_at_unix
                .is_some_and(|expiry| expiry < Self::now())
            || target.target_payload_hash.is_some()
            || pending_request_is_admin(&target.request)
        {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "target must be a pending, unexpired, local non-admin approval".into(),
            });
        }
        if params.temporary_grant && temporary_grant_requires_operation_binding(&target.capability)
        {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!(
                    "temporary grants are not supported for {} approvals",
                    target.capability
                ),
            });
        }
        let target_preview = Self::approval_target_preview(target);
        let reason = format!(
            "Fresh passkey confirmation is required to {} local {} request {}.",
            params.decision, target.capability, target.id
        );
        let mut response = self.enqueue_bound_admin_request(
            "admin.approval.bridge",
            &reason,
            PendingRequest::AdminApprovalBridge(params),
            client,
        )?;
        response
            .as_object_mut()
            .expect("admin enqueue response is an object")
            .insert("target_preview".into(), target_preview);
        Ok(response)
    }

    fn handle_policy_validate(&self) -> IpcResult<Value> {
        let ok_full = if self.policy.preset == AccessPreset::FullAccess {
            full_access_has_no_hidden_restrictive_rules(&self.policy)
        } else {
            true
        };
        Ok(json!({
            "ok": ok_full,
            "preset": preset_name(self.policy.preset),
            "rule_count": self.policy.rules.len(),
            "full_access_no_hidden_deny": ok_full,
        }))
    }

    fn handle_policy_explain(&self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            #[serde(default)]
            capability: Option<String>,
            #[serde(default)]
            kind: Option<String>,
            #[serde(default)]
            path: Option<String>,
            #[serde(default)]
            program: Option<String>,
            #[serde(default)]
            elevated: bool,
            /// Free-text query fallback (e.g. "exec", "write").
            #[serde(default)]
            query: Option<String>,
            /// Workspace in which a workspace-relative path is resolved.
            #[serde(default)]
            workspace_id: Option<String>,
        }
        let p: P = parse_params(params)?;
        let mut capability = p.capability.unwrap_or_default();
        let mut kind = p.kind.unwrap_or_default();
        if capability.is_empty() {
            if let Some(q) = &p.query {
                let ql = q.to_ascii_lowercase();
                if ql.contains("write") || ql.contains("delete") {
                    capability = "filesystem.write".into();
                    kind = "file".into();
                } else if ql.contains("read") || ql.contains("list") {
                    capability = "filesystem.read".into();
                    kind = "file".into();
                } else if ql.contains("log") {
                    capability = "logs.read".into();
                    kind = "logs".into();
                } else {
                    capability = "command.run".into();
                    kind = "structured".into();
                }
            } else {
                capability = "command.run".into();
            }
        }
        let has_path = p.path.is_some();
        let write = capability == "filesystem.write";
        let tags = p
            .path
            .as_deref()
            .map(|path| sensitive_path_tags(path, write))
            .unwrap_or_default();
        let facts = OperationFacts {
            capability,
            kind,
            path: p.path,
            program: p.program,
            elevated: p.elevated,
            workspace_relative: has_path,
            workspace_id: Some(Self::canonical_workspace_id(p.workspace_id.as_deref())?),
            tags,
            ..Default::default()
        };
        // Explain uses the local operator principal; grants are principal-scoped.
        let verdict = self.evaluate(&facts, LOCAL_PRINCIPAL);
        Ok(json!({
            "facts": facts,
            "decision": decision_str(verdict.decision),
            "matched_rule_id": verdict.matched_rule_id,
            "reason": verdict.reason,
            "lockdown": self.lockdown,
        }))
    }

    fn handle_lockdown(&mut self) -> IpcResult<Value> {
        let previous = self.lockdown;
        let grants_before = self.grants.clone();
        self.lockdown = true;
        self.grants.clear();
        if let Err(e) = self.persist_lockdown() {
            self.lockdown = previous;
            self.grants = grants_before;
            return Err(e);
        }
        if let Err(e) = self.persist_grants() {
            self.grants = grants_before;
            self.lockdown = previous;
            let rollback = self.persist_lockdown().err();
            return Err(match rollback {
                Some(rollback_err) => IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("{e}; also failed to restore lockdown flag: {rollback_err}"),
                },
                None => e,
            });
        }
        self.append_audit(
            "daemon.lockdown",
            None,
            None,
            Some("deny"),
            "lockdown on; grants cleared",
        );
        Ok(json!({ "lockdown": true, "grants_cleared": true }))
    }

    fn handle_unlock(&mut self) -> IpcResult<Value> {
        let previous = self.lockdown;
        self.lockdown = false;
        if let Err(e) = self.persist_lockdown() {
            self.lockdown = previous;
            return Err(e);
        }
        self.append_audit("daemon.unlock", None, None, Some("allow"), "lockdown off");
        Ok(json!({ "lockdown": false }))
    }

    fn handle_token_revoke(&mut self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            /// Canonical server-assigned principal key (legacy RPC field `client` accepted).
            #[serde(alias = "client")]
            principal: String,
        }
        let p: P = parse_params(params)?;
        let principal = canonicalize_principal_key(&p.principal);
        if principal.is_empty() {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "principal (server-assigned principal key) is required".into(),
            });
        }
        let inserted = {
            let mut guard = self.revoked_clients.write().map_err(|_| IpcError::Remote {
                code: app_error::INTERNAL,
                message: "revoked clients lock poisoned".into(),
            })?;
            guard.insert(principal.clone())
        };
        if let Err(e) = self.persist_revoked() {
            if inserted {
                if let Ok(mut guard) = self.revoked_clients.write() {
                    guard.remove(&principal);
                }
            }
            return Err(e);
        }
        self.append_audit(
            "token.revoke",
            None,
            None,
            Some("deny"),
            format!("revoked principal {principal}"),
        );
        Ok(json!({ "revoked": principal, "ok": true }))
    }

    /// Dispatch with an optional cancel receiver for interrupting in-flight exec.
    ///
    /// When `remote_operation_id` is set (Agent/MCP path), Ask/Allow receipts echo
    /// that id so DeviceRoom correlation/operation_id binding holds. Optional
    /// `remote_expires_at_unix` / `remote_payload_hash` are captured onto any
    /// deferred ApprovalRecord so recovery decisions remain exact-action bound.
    ///
    /// Production Agent path uses [`Self::dispatch_cancellable_bound`]; this thin
    /// wrapper remains for integration tests that do not supply binding facts.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn dispatch_cancellable(
        &mut self,
        method: &str,
        params: Option<Value>,
        client: &ClientIdentity,
        cancel: Option<watch::Receiver<bool>>,
        remote_operation_id: Option<String>,
    ) -> IpcResult<Value> {
        self.dispatch_cancellable_bound(
            method,
            params,
            client,
            cancel,
            remote_operation_id,
            None,
            None,
            None,
        )
        .await
    }

    /// Like [`dispatch_cancellable`] with explicit remote exact-action binding facts.
    pub async fn dispatch_cancellable_bound(
        &mut self,
        method: &str,
        params: Option<Value>,
        client: &ClientIdentity,
        cancel: Option<watch::Receiver<bool>>,
        remote_operation_id: Option<String>,
        remote_expires_at_unix: Option<i64>,
        remote_payload_hash: Option<String>,
        remote_device_id: Option<String>,
    ) -> IpcResult<Value> {
        self.dispatch_cancellable_bound_with_generation(
            method,
            params,
            client,
            cancel,
            remote_operation_id,
            remote_expires_at_unix,
            remote_payload_hash,
            remote_device_id,
            None,
        )
        .await
    }

    /// Like [`Self::dispatch_cancellable_bound`] but carries a positive,
    /// control-plane-issued principal credential generation. This separate API
    /// preserves the stable runtime test/local-IPC call shape while making the
    /// additional authority fact explicit at the authenticated Agent boundary.
    pub async fn dispatch_cancellable_bound_with_generation(
        &mut self,
        method: &str,
        params: Option<Value>,
        client: &ClientIdentity,
        cancel: Option<watch::Receiver<bool>>,
        remote_operation_id: Option<String>,
        remote_expires_at_unix: Option<i64>,
        remote_payload_hash: Option<String>,
        remote_device_id: Option<String>,
        remote_principal_credential_generation: Option<u64>,
    ) -> IpcResult<Value> {
        self.active_cancel = cancel;
        self.active_remote_operation_id = remote_operation_id
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());
        self.active_remote_expires_at_unix = remote_expires_at_unix.filter(|&t| t > 0);
        self.active_remote_payload_hash = remote_payload_hash
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());
        self.active_remote_device_id = remote_device_id
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());
        self.active_remote_principal = Some(canonicalize_principal_key(client.principal_key()))
            .filter(|value| !value.is_empty());
        self.active_remote_principal_credential_generation =
            remote_principal_credential_generation.filter(|generation| *generation > 0);
        let outcome = self.dispatch(method, params, client).await;
        self.active_cancel = None;
        self.active_remote_operation_id = None;
        self.active_remote_expires_at_unix = None;
        self.active_remote_payload_hash = None;
        self.active_remote_device_id = None;
        self.active_remote_principal = None;
        self.active_remote_principal_credential_generation = None;
        outcome
    }

    /// Apply a control-plane recovery approval decision to a deferred device
    /// approval. Look up by device `approval_id` when provided, otherwise by
    /// `target_operation_id` (the remote MCP operation id retained at Ask).
    ///
    /// Reachable only from the authenticated Agent channel. Does not accept
    /// client-supplied allow/force flags, and does not claim a ChatGPT
    /// cryptographic attestation — the control plane already authenticated the
    /// human approver via OAuth + one-time CSRF claim.
    pub async fn apply_control_plane_approval_decision(
        &mut self,
        params: Option<Value>,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct P {
            #[serde(default)]
            approval_id: Option<String>,
            #[serde(default)]
            target_operation_id: Option<String>,
            decision: String,
            #[serde(default)]
            tool: Option<String>,
            #[serde(default)]
            target_tool: Option<String>,
            #[serde(default)]
            target_payload_hash: Option<String>,
            #[serde(default)]
            target_expires_at: Option<String>,
            /// Authenticated approver principal from verified bound_action (server-set).
            #[serde(default)]
            approver_principal: Option<String>,
        }
        let p: P = parse_params(params)?;
        let _ = (p.tool, p.target_tool);
        let decision = p.decision.trim().to_ascii_lowercase();
        if decision != "approve" && decision != "deny" {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "decision must be approve or deny".into(),
            });
        }
        let approval_id = p
            .approval_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let target_operation_id = p
            .target_operation_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let decision_target_hash = p
            .target_payload_hash
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let decision_target_expires = p
            .target_expires_at
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let approver_principal = p
            .approver_principal
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);

        // Resolve deferred approval. Prefer exact device approval id; fall back
        // to the remote operation id retained when policy returned Ask.
        let resolved_id = if let Some(id) = approval_id.as_ref() {
            if self.approvals.contains_key(id) {
                id.clone()
            } else if let Some(target) = target_operation_id.as_ref() {
                self.approvals
                    .iter()
                    .find(|(_, rec)| rec.operation_id == *target && rec.state == "pending")
                    .map(|(k, _)| k.clone())
                    .ok_or_else(|| IpcError::Remote {
                        code: app_error::INVALID_PARAMS,
                        message: format!(
                            "approval not found for id={id} target_operation_id={target}"
                        ),
                    })?
            } else {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: format!("approval not found: {id}"),
                });
            }
        } else if let Some(target) = target_operation_id.as_ref() {
            let matches: Vec<String> = self
                .approvals
                .iter()
                .filter(|(_, rec)| rec.operation_id == *target && rec.state == "pending")
                .map(|(k, _)| k.clone())
                .collect();
            match matches.as_slice() {
                [only] => only.clone(),
                [] => {
                    return Err(IpcError::Remote {
                        code: app_error::INVALID_PARAMS,
                        message: format!("no pending approval for operation {target}"),
                    });
                }
                _ => {
                    return Err(IpcError::Remote {
                        code: app_error::CONFLICT,
                        message: format!(
                            "multiple pending approvals for operation {target}; supply approval_id"
                        ),
                    });
                }
            }
        } else {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "approval_id or target_operation_id required".into(),
            });
        };

        let rec = self
            .approvals
            .get(&resolved_id)
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("approval not found: {resolved_id}"),
            })?
            .clone();
        if let PendingRequest::AdminApprovalBridge(bridge) = &rec.request {
            if bridge.decision != decision {
                return Err(IpcError::Remote {
                    code: app_error::UNAUTHORIZED,
                    message: format!(
                        "approval decision does not match bound bridge intent ({})",
                        bridge.decision
                    ),
                });
            }
        }
        if let Some(target) = target_operation_id.as_ref() {
            if &rec.operation_id != target {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: format!(
                        "target_operation_id {target} does not match approval {}",
                        rec.operation_id
                    ),
                });
            }
        }
        if rec.state != "pending" {
            // Exact-once: already decided/executing — surface durable state, never re-run.
            return Ok(json!({
                "approval_decision_applied": true,
                "replayed": true,
                "approval_id": resolved_id,
                "target_operation_id": rec.operation_id,
                "decision": decision,
                "state": rec.state,
                "result": rec.result.clone(),
            }));
        }
        // E3: fail closed when the original remote action window has elapsed.
        if let Some(exp) = rec.expires_at_unix {
            if Self::now() > exp {
                return Err(IpcError::Remote {
                    code: app_error::UNAUTHORIZED,
                    message: format!(
                        "approval {resolved_id} expired at unix {exp}; re-authorize the original action"
                    ),
                });
            }
        }
        // Decision must cite the same target payload hash recorded at Ask (when known).
        if let (Some(stored), Some(cited)) = (
            rec.target_payload_hash.as_ref(),
            decision_target_hash.as_ref(),
        ) {
            if !stored.eq_ignore_ascii_case(cited) {
                return Err(IpcError::Remote {
                    code: app_error::UNAUTHORIZED,
                    message: "target_payload_hash does not match deferred approval binding".into(),
                });
            }
        }
        // When the deferred record has a hash, the decision must present it.
        if rec.target_payload_hash.is_some() && decision_target_hash.is_none() {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "target_payload_hash required for bound recovery approval".into(),
            });
        }
        // Optional RFC3339 target_expires_at on the decision must not disagree
        // with the stored unix expiry (when both present).
        if let (Some(stored_unix), Some(cited)) =
            (rec.expires_at_unix, decision_target_expires.as_ref())
        {
            if let Ok(ts) = ownmesh_domain::Timestamp::parse(cited) {
                let cited_unix = ts.date_time().unix_timestamp();
                if cited_unix != stored_unix {
                    return Err(IpcError::Remote {
                        code: app_error::UNAUTHORIZED,
                        message: "target_expires_at does not match deferred approval binding"
                            .into(),
                    });
                }
            }
        }

        // Prefer the authenticated control-plane approver principal from the
        // verified bound_action. Fall back to a synthetic recovery identity so
        // independent-approver checks still pass for legacy local paths.
        let recovery_key = approver_principal
            .as_deref()
            .map(|p| format!("user:control-plane:{p}"))
            .unwrap_or_else(|| "user:control-plane-recovery".to_owned());
        let recovery = ClientIdentity::new(&recovery_key, env!("CARGO_PKG_VERSION"));

        if decision == "deny" {
            if let PendingRequest::AdminApprovalBridge(bridge) = &rec.request {
                let body = self.deny_approval_bridge(
                    &resolved_id,
                    bridge,
                    &canonicalize_principal_key(recovery.principal_key()),
                )?;
                return Ok(json!({
                    "approval_decision_applied": true,
                    "replayed": false,
                    "approval_id": resolved_id,
                    "target_operation_id": rec.operation_id,
                    "decision": "deny",
                    "state": "denied",
                    "result": body,
                }));
            }
            let body = self.handle_approval_deny(Some(json!({ "id": resolved_id })), &recovery)?;
            return Ok(json!({
                "approval_decision_applied": true,
                "replayed": false,
                "approval_id": resolved_id,
                "target_operation_id": body.get("operation_id").cloned().unwrap_or(Value::Null),
                "decision": "deny",
                "state": "denied",
                "result": body,
            }));
        }

        let body = self
            .handle_approval_approve(
                Some(json!({ "id": resolved_id, "temporary_grant": false })),
                &recovery,
            )
            .await?;
        let target = body
            .get("operation_id")
            .cloned()
            .unwrap_or_else(|| json!(target_operation_id.clone().unwrap_or_default()));
        let exec_result = body.get("result").cloned().unwrap_or(Value::Null);
        Ok(json!({
            "approval_decision_applied": true,
            "replayed": false,
            "approval_id": resolved_id,
            "target_operation_id": target,
            "decision": "approve",
            "state": "approved",
            "result": exec_result,
            "execution": body,
        }))
    }

    /// Dispatch one authenticated RPC method bound to `client` identity.
    pub async fn dispatch(
        &mut self,
        method: &str,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        // client.client_name holds the server-assigned principal key (never a
        // self-reported HELLO label).
        if self.is_client_revoked(&client.client_name) {
            return Err(IpcError::Remote {
                code: app_error::TOKEN_REVOKED,
                message: format!("principal {} is revoked", client.client_name),
            });
        }
        self.check_lockdown(method)?;
        self.check_journal_degraded(method)?;
        match method {
            methods::OPS_EXEC => self.handle_exec(params, client).await,
            methods::OPS_FS_LIST => self.handle_fs_list(params, client).await,
            methods::OPS_FS_STAT => self.handle_fs_stat(params, client).await,
            methods::OPS_FS_READ => self.handle_fs_read(params, client).await,
            methods::OPS_FS_WRITE => self.handle_fs_write(params, client).await,
            methods::OPS_FS_DELETE => self.handle_fs_delete(params, client).await,
            methods::OPS_LOGS_QUERY => self.handle_logs_query(params, client).await,
            methods::TRANSFER_PLAN => self.handle_transfer_plan(params, client).await,
            methods::TRANSFER_PREFLIGHT_SOURCE => {
                self.handle_transfer_preflight_source(params, client).await
            }
            methods::TRANSFER_PREFLIGHT_DESTINATION => {
                self.handle_transfer_preflight_destination(params, client)
                    .await
            }
            methods::TRANSFER_START => self.handle_transfer_start(params, client).await,
            methods::TRANSFER_SOURCE_OPEN => self.handle_transfer_source_open(params, client).await,
            methods::TRANSFER_SOURCE_CHUNK => {
                self.handle_transfer_source_chunk(params, client).await
            }
            methods::TRANSFER_DESTINATION_PREPARE => {
                self.handle_transfer_destination_prepare(params, client)
                    .await
            }
            methods::TRANSFER_DESTINATION_CHUNK => {
                self.handle_transfer_destination_chunk(params, client).await
            }
            methods::TRANSFER_FINALIZE => self.handle_transfer_finalize(params, client).await,
            methods::TRANSFER_STATUS => self.handle_transfer_status(params, client).await,
            methods::TRANSFER_LIST => self.handle_transfer_list(params, client).await,
            methods::TRANSFER_CANCEL => self.handle_transfer_cancel(params, client).await,
            methods::TRANSFER_ARTIFACT_GET => {
                self.handle_transfer_artifact_get(params, client).await
            }
            ops_methods::LOGS_LIST_PROVIDERS => self.handle_logs_list_providers(params),
            ops_methods::GIT_STATUS => self.handle_git_status(params, client).await,
            ops_methods::GIT_DIFF => self.handle_git_diff(params, client).await,
            ops_methods::REVIEW_START => self.handle_review_start(params, client).await,
            ops_methods::REVIEW_SHOW => self.handle_review_show(params, client),
            ops_methods::REVIEW_PAGE => self.handle_review_page(params, client),
            ops_methods::WORKSPACE_LIST => self.handle_workspace_list(client),
            ops_methods::WORKSPACE_SHOW => self.handle_workspace_show(params),
            ops_methods::WORKSPACE_ADD => self.handle_workspace_add(params, client),
            ops_methods::WORKSPACE_UPDATE => self.handle_workspace_update(params, client),
            ops_methods::WORKSPACE_REMOVE => self.handle_workspace_remove(params, client),
            ops_methods::SYSTEM_DIAGNOSE => self.handle_system_diagnose(params, client).await,
            methods::PROFILE_LIST | methods::PROFILE_SCAN => self.handle_profile_list(params),
            methods::PROFILE_SHOW => self.handle_profile_show(params),
            methods::APPROVAL_LIST => self.handle_approval_list(),
            methods::APPROVAL_SHOW => self.handle_approval_show(params),
            methods::APPROVAL_APPROVE => self.handle_approval_approve(params, client).await,
            methods::APPROVAL_DENY => self.handle_approval_deny(params, client),
            methods::POLICY_SHOW => self.handle_policy_show(),
            methods::POLICY_PRESET => self.handle_policy_preset(params),
            methods::POLICY_VALIDATE => self.handle_policy_validate(),
            methods::POLICY_EXPLAIN => self.handle_policy_explain(params),
            methods::GRANTS_LIST => self.handle_grants_list(),
            methods::GRANTS_SHOW => self.handle_grants_show(params),
            methods::GRANTS_REVOKE => self.handle_grants_revoke(params),
            methods::DAEMON_LOCKDOWN => self.handle_lockdown(),
            methods::DAEMON_UNLOCK => self.handle_unlock(),
            methods::TOKEN_REVOKE => self.handle_token_revoke(params),
            methods::ADMIN_POLICY_PRESET_REQUEST => {
                self.handle_admin_policy_preset_request(params, client)
            }
            methods::ADMIN_POLICY_RULE_ADD_REQUEST => {
                self.handle_admin_policy_rule_add_request(params, client)
            }
            methods::ADMIN_POLICY_RULE_REMOVE_REQUEST => {
                self.handle_admin_policy_rule_remove_request(params, client)
            }
            methods::ADMIN_DAEMON_UNLOCK_REQUEST => {
                self.handle_admin_unlock_request(params, client)
            }
            methods::ADMIN_TOKEN_REVOKE_REQUEST => {
                self.handle_admin_token_revoke_request(params, client)
            }
            methods::ADMIN_APPROVAL_BRIDGE_REQUEST => {
                self.handle_admin_approval_bridge_request(params, client)
            }
            methods::ADMIN_GRANTS_MINT_REQUEST => {
                self.handle_admin_grants_mint_request(params, client)
            }
            session_methods::OPEN => self.handle_session_open(params, client).await,
            session_methods::LIST => self.handle_session_list(params, client),
            session_methods::SHOW => self.handle_session_show(params, client),
            session_methods::ATTACH => self.handle_session_attach(params, client),
            session_methods::CLAIM => self.handle_session_claim(params, client).await,
            session_methods::RENEW => self.handle_session_renew(params, client).await,
            session_methods::DETACH => self.handle_session_detach(params, client).await,
            session_methods::RELEASE => self.handle_session_release(params, client),
            session_methods::GIVE => self.handle_session_give(params, client).await,
            session_methods::CLOSE => self.handle_session_close(params, client).await,
            session_methods::TERMINATE => self.handle_session_terminate(params, client).await,
            session_methods::REPLAY => self.handle_session_replay(params, client).await,
            session_methods::PUSH_OUTPUT => self.handle_session_push_output(params, client),
            session_methods::WRITE => self.handle_session_write(params, client).await,
            session_methods::RESIZE => self.handle_session_resize(params, client).await,
            other => Err(IpcError::Remote {
                code: app_error::METHOD_NOT_FOUND,
                message: format!("method not found: {other}"),
            }),
        }
    }

    async fn ensure_remote_supervisor(&mut self) -> IpcResult<&SupervisorClient> {
        if self.supervisor.is_none() {
            let state_dir = self.paths.state_dir.join("session-supervisor");
            let endpoint =
                Endpoint::default_for(&self.paths.runtime_dir, IpcBus::SessionSupervisor);
            // The sibling binary is pinned and revalidated; never resolve it
            // through PATH where a same-user replacement could be selected.
            let ownmeshd = std::env::current_exe().map_err(|err| IpcError::Remote {
                code: app_error::INTERNAL,
                message: format!("resolve ownmeshd executable for sidecar: {err}"),
            })?;
            let host_name = if cfg!(windows) {
                "ownmesh-session-host.exe"
            } else {
                "ownmesh-session-host"
            };
            let host = ownmeshd
                .parent()
                .ok_or_else(|| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: "ownmeshd executable has no parent directory".into(),
                })?
                .join(host_name);
            let pin =
                pin_executable(&host, CommandKind::Structured).map_err(|err| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("session-host executable custody failed: {err}"),
                })?;
            verify_executable_pin(&host, &pin).map_err(|err| IpcError::Remote {
                code: app_error::INTERNAL,
                message: format!("session-host executable changed before launch: {err}"),
            })?;
            let mut command = Command::new(&host);
            command
                .arg("supervise")
                .arg("--state-dir")
                .arg(&state_dir)
                .arg("--runtime-dir")
                .arg(&self.paths.runtime_dir)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                const DETACHED_PROCESS: u32 = 0x0000_0008;
                const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
                command
                    .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
            }
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                // The sidecar owns the PTY after daemon exit. Production
                // service managers should additionally supervise it; this
                // independent process group keeps an ordinary daemon restart
                // from coupling its lifetime to the daemon's process group.
                command.process_group(0);
            }
            // A second daemon may race this launch. The sidecar listener is the
            // singleton authority; a duplicate immediately fails bind and is
            // harmless. We never fall back to an embedded remote PTY.
            command.spawn().map_err(|error| IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!("launch persistent session sidecar: {error}"),
            })?;
            let credential_dir = state_dir.join("session-supervisor-credentials");
            let mut last = "sidecar did not provision management credential".to_owned();
            for _ in 0..40 {
                if let Ok(management) = read_management_credential(&credential_dir) {
                    match SupervisorClient::bootstrap(
                        endpoint.clone(),
                        self.paths.runtime_dir.clone(),
                        management,
                    )
                    .await
                    {
                        Ok(client) => {
                            self.supervisor = Some(client);
                            break;
                        }
                        Err(err) => last = format!("sidecar credential bootstrap: {err}"),
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            if self.supervisor.is_none() {
                return Err(IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: format!("persistent session sidecar unavailable: {last}"),
                });
            }
        }
        self.recover_sidecar_transitions().await?;
        self.reattach_persistent_sidecars().await?;
        self.supervisor.as_ref().ok_or_else(|| IpcError::Remote {
            code: app_error::INTERNAL,
            message: "persistent session sidecar state unavailable".into(),
        })
    }

    /// Reattach every persisted, non-terminal sidecar without spawning a
    /// replacement PTY. A `Starting` row proves that open never completed, so
    /// it is terminated with its exact authenticated binding and closed only
    /// after the supervisor's durable acknowledgement. A missing active host
    /// is an explicit conflict; an expired controller binding is deliberately
    /// left for exact reclaim so expiry never kills a still-valid host TTL.
    async fn reattach_persistent_sidecars(&mut self) -> IpcResult<()> {
        const MAX_REATTACH: usize = 64;
        let now = Self::now();
        let bindings: Vec<_> = self
            .sessions
            .list()
            .into_iter()
            .filter_map(|info| {
                info.sidecar_host
                    .map(|binding| (info.id, info.state, binding))
            })
            .collect();
        if bindings.len() > MAX_REATTACH {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "persistent sidecar reattach quota exceeded".into(),
            });
        }
        let mut recovered_pids = Vec::new();
        let mut interrupted_opens = Vec::new();
        {
            let proxy = self.supervisor.as_ref().ok_or_else(|| IpcError::Remote {
                code: app_error::CONFLICT,
                message: "sidecar unavailable during reattach".into(),
            })?;
            for (session_id, state, binding) in bindings {
                let exact = supervisor_binding_from(&session_id, &binding);
                if state == ownmesh_session::SessionState::Starting {
                    let transition_id =
                        format!("open-recovery:{session_id}:{}", binding.controller_epoch);
                    proxy
                        .terminate(&exact, transition_id)
                        .await
                        .map_err(|error| IpcError::Remote {
                            code: app_error::CONFLICT,
                            message: format!(
                                "interrupted persistent session {session_id} cleanup is pending: {error}"
                            ),
                        })?;
                    interrupted_opens.push(session_id);
                    continue;
                }
                if binding.binding_expires_unix <= now {
                    continue;
                }
                let status = proxy
                    .status(&exact)
                    .await
                    .map_err(|error| IpcError::Remote {
                        code: app_error::CONFLICT,
                        message: format!(
                            "persistent session {session_id} cannot reattach without respawn: {error}"
                        ),
                    })?;
                let (pid, birth) = match (status.pid, status.process_birth_id) {
                    (Some(pid), Some(birth)) if !status.exited => (pid, birth),
                    _ => {
                        return Err(IpcError::Remote {
                            code: app_error::CONFLICT,
                            message: format!(
                                "persistent session {session_id} did not attest child process identity"
                            ),
                        });
                    }
                };
                if let (Some(expected_pid), Some(expected_birth)) =
                    (binding.child_pid, binding.child_process_birth)
                {
                    if pid != expected_pid || birth != expected_birth {
                        return Err(IpcError::Remote {
                            code: app_error::CONFLICT,
                            message: format!(
                                "persistent session {session_id} child process identity changed during reattach"
                            ),
                        });
                    }
                }
                recovered_pids.push((session_id, pid, birth));
            }
        }
        if recovered_pids.is_empty() && interrupted_opens.is_empty() {
            return Ok(());
        }
        let snapshot = self.sessions.clone();
        for session_id in interrupted_opens {
            self.sessions.close(&session_id).map_err(session_err)?;
            self.sessions
                .set_sidecar_host_binding(&session_id, None)
                .map_err(session_err)?;
            self.sessions
                .set_host_pid(&session_id, None)
                .map_err(session_err)?;
        }
        for (session_id, pid, birth) in recovered_pids {
            self.sessions
                .set_host_pid(&session_id, Some(pid))
                .map_err(session_err)?;
            let mut binding = self
                .sessions
                .get(&session_id)
                .map_err(session_err)?
                .sidecar_host
                .clone()
                .ok_or_else(|| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: "reattached persistent session lost binding".into(),
                })?;
            binding.child_pid = Some(pid);
            binding.child_process_birth = Some(birth);
            self.sessions
                .set_sidecar_host_binding(&session_id, Some(binding))
                .map_err(session_err)?;
        }
        self.commit_sessions(snapshot)
    }

    /// Reconcile only expired transition-journal records (the safe, non-blocking
    /// pass). Live in-window records are left for the supervisor path so a
    /// diagnosis or startup can never fail on replay of an ambiguous transition.
    ///
    /// P0-A: a stale row whose host TTL expired must never poison unrelated
    /// future sessions; provably-moot records are cleared, anything else is
    /// retained fail-closed and surfaced through `transition_recovery_health`.
    /// The health state is refreshed from the journal after the pass so a
    /// record retained on an earlier pass that is now provably moot (cleared)
    /// stops being reported as unresolved (P1-F).
    pub(super) async fn reconcile_expired_transitions(&mut self) {
        if self.transition_recovery_running {
            return;
        }
        self.transition_recovery_running = true;
        let records = self.transition_journal.pending();
        let now = Self::now();
        for record in &records {
            if record.expires_unix <= now
                && self
                    .reconcile_expired_transition_record(record.clone())
                    .await
                    .is_err()
            {
                self.record_transition_recovery_issue(&record.transition_id);
            }
        }
        self.refresh_transition_recovery_health();
        self.transition_recovery_running = false;
    }

    /// Refresh the bounded retained-expired health state to match the current
    /// journal: every expired record still pending after the reconcile pass is
    /// unresolved, and a record that was retained on an earlier pass but has
    /// since been cleared (session closed, host TTL provably passed) must stop
    /// being reported. The bounded list keeps the first `TRANSITION_HEALTH_RETAINED_CAP`
    /// ids; the total is the current unresolved count, not a cumulative counter.
    fn refresh_transition_recovery_health(&mut self) {
        let now = Self::now();
        let retained: Vec<String> = self
            .transition_journal
            .pending()
            .into_iter()
            .filter(|record| record.expires_unix <= now)
            .map(|record| record.transition_id)
            .collect();
        self.transition_recovery_health.retained_expired_total = retained.len();
        self.transition_recovery_health.retained_expired = retained
            .into_iter()
            .take(TRANSITION_HEALTH_RETAINED_CAP)
            .collect();
    }

    async fn recover_sidecar_transitions(&mut self) -> IpcResult<()> {
        // Expired records are reconciled first, non-blockingly: a stale row
        // must never poison unrelated future sessions, and safe cleanup must
        // not be prevented by a separate record's failure. If authoritative
        // state cannot prove the record harmless it is retained fail-closed
        // and surfaced in health — recovery continues.
        self.reconcile_expired_transitions().await;
        // Live records keep the fail-closed replay: an in-window transition
        // that cannot be replayed aborts rather than converting ambiguity
        // into success.
        if self.transition_recovery_running {
            // Another recovery pass owns the journal; the live replay is
            // idempotent and will be performed by that owner.
            return Ok(());
        }
        self.transition_recovery_running = true;
        let records = self.transition_journal.pending();
        let now = Self::now();
        for record in records {
            if record.expires_unix > now {
                let result = self.recover_transition_record(record).await;
                if let Err(error) = result {
                    self.transition_recovery_running = false;
                    return Err(error);
                }
            }
        }
        self.transition_recovery_running = false;
        Ok(())
    }

    /// Record a retained-expired transition journal issue in the bounded
    /// health state (deduplicated by transition id).
    fn record_transition_recovery_issue(&mut self, transition_id: &str) {
        if self
            .transition_recovery_health
            .retained_expired
            .iter()
            .any(|id| id == transition_id)
        {
            return;
        }
        if self.transition_recovery_health.retained_expired.len() < TRANSITION_HEALTH_RETAINED_CAP {
            self.transition_recovery_health
                .retained_expired
                .push(transition_id.to_string());
        }
        self.transition_recovery_health.retained_expired_total = self
            .transition_recovery_health
            .retained_expired_total
            .saturating_add(1);
    }

    async fn recover_transition_record(
        &mut self,
        record: session_transition_journal::TransitionRecord,
    ) -> IpcResult<()> {
        if record.expires_unix <= Self::now() {
            // The host TTL passed while the record was queued: reconcile
            // non-blockingly instead of aborting every other session.
            return self.reconcile_expired_transition_record(record).await;
        }
        let terminal = matches!(
            record.kind,
            TransitionKind::Close | TransitionKind::Terminate
        );
        let current = match self.sessions.get(&record.session_id) {
            Ok(current) => current,
            // `terminate` removes its SessionManager entry. If the durable
            // sidecar tombstone and the session snapshot were both committed,
            // a crash can leave only the harmless journal cleanup outstanding.
            Err(ownmesh_session::SessionError::NotFound)
                if terminal && record.phase == TransitionPhase::Applied =>
            {
                return self
                    .transition_journal
                    .clear(&record.transition_id)
                    .map_err(|e| IpcError::Remote {
                        code: app_error::INTERNAL,
                        message: format!("clear completed terminal transition: {e}"),
                    });
            }
            Err(error) => return Err(session_err(error)),
        };
        if current.workspace_id.as_deref() != Some(record.workspace_id.as_str()) {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "sidecar transition workspace mismatch during recovery".into(),
            });
        }
        let binding = match record.phase {
            TransitionPhase::Applied => {
                if terminal {
                    None
                } else {
                    Some(record.new_binding.clone().ok_or_else(|| IpcError::Remote {
                        code: app_error::INTERNAL,
                        message: "applied sidecar transition missing binding".into(),
                    })?)
                }
            }
            TransitionPhase::Intent => {
                let old = supervisor_binding_from(&record.session_id, &record.old_binding);
                let proxy = self.supervisor.as_ref().ok_or_else(|| IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: "sidecar unavailable during transition recovery".into(),
                })?;
                let next = if terminal {
                    proxy
                        .terminate(&old, record.transition_id.clone())
                        .await
                        .map_err(|e| IpcError::Remote {
                            code: app_error::CONFLICT,
                            message: format!("replay sidecar transition: {e}"),
                        })?;
                    None
                } else {
                    Some(
                        match record.kind {
                            session_transition_journal::TransitionKind::Detach => {
                                proxy
                                    .detach(
                                        &old,
                                        record.target.controller_epoch,
                                        record.transition_id.clone(),
                                    )
                                    .await
                            }
                            session_transition_journal::TransitionKind::Claim => {
                                proxy
                                    .claim(
                                        &old,
                                        record.target.principal.clone(),
                                        record.target.controller_epoch,
                                        record.target.binding_expires_unix,
                                        record.transition_id.clone(),
                                    )
                                    .await
                            }
                            session_transition_journal::TransitionKind::Give => {
                                proxy
                                    .rotate(
                                        &old,
                                        record.target.principal.clone(),
                                        record.target.controller_epoch,
                                        record.target.binding_expires_unix,
                                        record.transition_id.clone(),
                                    )
                                    .await
                            }
                            session_transition_journal::TransitionKind::Renew => {
                                proxy
                                    .renew(
                                        &old,
                                        record.target.binding_expires_unix,
                                        record.transition_id.clone(),
                                    )
                                    .await
                            }
                            session_transition_journal::TransitionKind::Reclaim => {
                                proxy
                                    .reclaim(
                                        &old,
                                        record.target.principal.clone(),
                                        record.target.controller_epoch,
                                        record.target.binding_expires_unix,
                                        record.transition_id.clone(),
                                    )
                                    .await
                            }
                            TransitionKind::Close | TransitionKind::Terminate => {
                                unreachable!("terminal transition handled above")
                            }
                        }
                        .map_err(|e| IpcError::Remote {
                            code: app_error::CONFLICT,
                            message: format!("replay sidecar transition: {e}"),
                        })?,
                    )
                };
                if terminal {
                    self.transition_journal
                        .mark_terminal_applied(&record.transition_id)
                        .map_err(|e| IpcError::Remote {
                            code: app_error::INTERNAL,
                            message: format!("mark recovered terminal transition applied: {e}"),
                        })?;
                    None
                } else {
                    let next = next.ok_or_else(|| IpcError::Remote {
                        code: app_error::INTERNAL,
                        message: "non-terminal sidecar transition returned no binding".into(),
                    })?;
                    let binding = SidecarHostBinding {
                        device_id: record.device_id.clone(),
                        workspace_id: record.workspace_id.clone(),
                        owner_principal: record.target.principal.clone(),
                        host_nonce: next.host_nonce,
                        controller_epoch: next.controller_epoch,
                        binding_expires_unix: record.target.binding_expires_unix,
                        host_expires_unix: record.old_binding.host_expires_unix,
                        child_pid: record.old_binding.child_pid,
                        child_process_birth: record.old_binding.child_process_birth,
                    };
                    self.transition_journal
                        .mark_applied(&record.transition_id, binding.clone())
                        .map_err(|e| IpcError::Remote {
                            code: app_error::INTERNAL,
                            message: format!("mark recovered transition applied: {e}"),
                        })?;
                    Some(binding)
                }
            }
        };
        let snapshot = self.sessions.clone();
        if !terminal {
            // P0-A review (crash window): the original handler mutated a
            // preview session (controller principal, lease id, epoch, expiry,
            // attached state), rotated the sidecar, journaled the transition,
            // then committed the preview. A crash between the supervisor
            // mutation / `Applied` journal write and that commit leaves the
            // durable controller unchanged while the sidecar already belongs
            // to the successor. Recovery therefore restores the FULL
            // controller mutation recorded in the journal target — not only
            // the sidecar binding — so the former controller cannot keep
            // writing through the successor's host after the record is
            // cleared. The exact recorded lease id is restored so remote
            // write authorization (lease id + epoch) keeps working after
            // restart.
            //
            // Defense in depth: fencing guarantees at most one in-flight
            // record per session and recovery runs before any request, so the
            // durable generation can never be ahead of the record target. If
            // it ever is (crash-interleaved/foreign journal), the record is
            // NOT applied (that would regress the authoritative session) and
            // is cleared only when the durable binding is already at or past
            // the target generation; a stale pre-transition binding keeps the
            // record retained fail-closed.
            let current = self.sessions.get(&record.session_id).map_err(session_err)?;
            let durable_ahead = current.controller_epoch > record.target.controller_epoch;
            let binding_stale = current
                .sidecar_host
                .as_ref()
                .is_some_and(|binding| binding.controller_epoch < record.target.controller_epoch);
            // `current` is a plain `&SessionInfo` (no lock guard); move it to
            // end the borrow before touching the transition journal below.
            let _ = current;
            if durable_ahead {
                if binding_stale {
                    return Err(IpcError::Remote {
                        code: app_error::CONFLICT,
                        message: format!(
                            "recovered sidecar transition {} for session {} is older than the \
durable controller generation but its sidecar binding is still the pre-transition generation; \
retained fail-closed — run `ownmesh doctor` or inspect {} ",
                            record.transition_id,
                            record.session_id,
                            self.transition_journal_dir().display(),
                        ),
                    });
                }
                return self
                    .transition_journal
                    .clear(&record.transition_id)
                    .map_err(|e| IpcError::Remote {
                        code: app_error::INTERNAL,
                        message: format!("clear already-superseded recovered transition: {e}"),
                    });
            }
            self.sessions
                .reconcile_controller_from_transition(
                    &record.session_id,
                    &record.target.principal,
                    record
                        .target
                        .lease_id
                        .as_deref()
                        .ok_or_else(|| IpcError::Remote {
                            code: app_error::INTERNAL,
                            message: format!(
                                "recovered sidecar transition {} for session {} is missing its \
recorded lease id; retained fail-closed — run `ownmesh doctor` or inspect {} ",
                                record.transition_id,
                                record.session_id,
                                self.transition_journal_dir().display(),
                            ),
                        })?,
                    record.target.controller_epoch,
                    record.target.binding_expires_unix,
                    record.target.controller_attached,
                )
                .map_err(session_err)?;
        }
        if let Some(binding) = binding {
            self.sessions
                .set_sidecar_host_binding(&record.session_id, Some(binding))
                .map_err(session_err)?;
        } else {
            match record.kind {
                TransitionKind::Close => self
                    .sessions
                    .close(&record.session_id)
                    .map_err(session_err)?,
                TransitionKind::Terminate => self
                    .sessions
                    .terminate(&record.session_id)
                    .map_err(session_err)?,
                _ => unreachable!("only terminal transitions omit a binding"),
            }
            self.sessions
                .set_sidecar_host_binding(&record.session_id, None)
                .map_err(session_err)?;
        }
        self.commit_sessions(snapshot)?;
        self.transition_journal
            .clear(&record.transition_id)
            .map_err(|e| IpcError::Remote {
                code: app_error::INTERNAL,
                message: format!("clear recovered transition journal: {e}"),
            })
    }

    /// Authoritative proof that every sidecar referenced by an expired
    /// transition record is dead (P0-A review).
    ///
    /// Returns `Ok(true)` only when death is proven for **every** binding the
    /// record can touch (the old binding and, when present, the distinct
    /// successor binding), `Ok(false)` when a live process or supervisor-
    /// tracked host was found (the record must be retained), and `Err` when
    /// no proof could be produced (indeterminate → retain fail-closed;
    /// ambiguity is never converted into success).
    ///
    /// Two independent authoritative sources, combined across all bindings:
    ///
    /// 1. **OS process proof.** For each binding that carries the attested
    ///    child identity (`child_pid` + `child_process_birth`), ask the OS
    ///    whether that exact process still exists. `process_birth_id`
    ///    returns `Ok(None)` only when the OS confirmed the PID no longer
    ///    exists; a reused PID reports a different birth, which equally
    ///    proves the original child is gone. A matching birth means that
    ///    sidecar is still live → retain (never contradicted by the
    ///    supervisor). An inspection error is indeterminate and falls
    ///    through to the supervisor probe.
    /// 2. **Supervisor proof.** When any referenced binding is provisional
    ///    (no attested pid/birth) or its OS inspection was indeterminate,
    ///    the live supervisor is the authoritative registry: it removes a
    ///    host only after its termination succeeds and retries failed
    ///    terminations (`sweep_expired`), so a session the supervisor does
    ///    not track proves no sidecar can be live under it. A probe failure
    ///    (supervisor down/restarting) is indeterminate → fail closed.
    ///
    /// P0-B review: proving only the *first* available child identity is
    /// insufficient. If the old binding's PID is dead (or reused with a
    /// different birth) while a distinct successor binding is live — or the
    /// supervisor still tracks a host for this session — clearing the
    /// record would orphan that sidecar. Every referenced binding must be
    /// covered before the row is cleared.
    async fn prove_expired_sidecar_dead(
        &self,
        record: &session_transition_journal::TransitionRecord,
    ) -> Result<bool, String> {
        // Every binding this record can touch: old + (when present) new.
        let bindings = std::iter::once(&record.old_binding).chain(record.new_binding.iter());
        // True when at least one referenced binding still lacks OS proof of
        // death (provisional identity or indeterminate inspection), so the
        // supervisor probe is required before the row may be cleared.
        let mut need_supervisor = false;
        for binding in bindings {
            if let Some((pid, expected_birth)) = binding.child_pid.zip(binding.child_process_birth)
            {
                match ownmesh_ipc::process_birth_id(pid) {
                    // OS-confirmed gone, or the PID was reused by a different
                    // process: the original child is provably dead.
                    Ok(None) => {}
                    Ok(Some(birth)) if birth != expected_birth => {}
                    // The attested child is still live: that is authoritative
                    // and never contradicted by a supervisor probe (fail-
                    // closed).
                    Ok(Some(_)) => return Ok(false),
                    // Indeterminate OS inspection: fall through to the
                    // supervisor probe as a second authoritative source.
                    Err(_) => need_supervisor = true,
                }
            } else {
                // Provisional binding: no OS identity to prove death with.
                need_supervisor = true;
            }
        }
        if need_supervisor {
            if let Some(supervisor) = self.supervisor.as_ref() {
                return match supervisor.host_live(&record.session_id).await {
                    Ok(live) => Ok(!live),
                    Err(error) => Err(format!("supervisor liveness probe failed: {error}")),
                };
            }
            return Err(
                "sidecar has no attested child pid and the session supervisor is not connected"
                    .into(),
            );
        }
        Ok(true)
    }

    /// Reconcile a transition journal record whose host TTL has expired.
    ///
    /// The record is cleared only when authoritative state proves both that
    /// the intent is moot and that no live sidecar can be orphaned:
    ///
    /// - the record's `expires_unix` covers every binding it references
    ///   (journal validation enforces `expires_unix >= host_expires_unix`;
    ///   this function re-checks defensively so a crash-interleaved or
    ///   inconsistent record can never be cleared without that proof);
    /// - [`Self::prove_expired_sidecar_dead`] proves the referenced sidecar
    ///   is dead (OS process proof, or supervisor liveness probe for
    ///   provisional bindings) — expiry alone is never treated as proof of
    ///   termination, because a failed sweep/terminate could otherwise leave
    ///   an orphaned sidecar running after its journal record was cleared;
    /// - the session no longer exists (`NotFound`): no controller can be
    ///   granted and no host is affected;
    /// - the session is `Closed` and its current `sidecar_host` (which
    ///   `SessionManager::close` deliberately leaves intact) is not a live
    ///   host referenced by this record.
    ///
    /// When the session is still present and non-terminal the intent may
    /// still matter, so the record is retained fail-closed (ambiguity is
    /// never converted into success) and surfaced through the bounded
    /// `transition_recovery_health` state instead of aborting every unrelated
    /// future session.
    async fn reconcile_expired_transition_record(
        &mut self,
        record: session_transition_journal::TransitionRecord,
    ) -> IpcResult<()> {
        // Authoritative proof that every host this record can touch is dead:
        // `expires_unix` is the host-TTL bound and the supervisor sweeps
        // hosts whose TTL passed. A record whose expiry precedes a referenced
        // host's TTL is inconsistent — clearing it could strand a live
        // sidecar, so it is retained fail-closed (never converted into
        // success) and surfaced in health.
        if record.expires_unix < record.old_binding.host_expires_unix
            || record
                .new_binding
                .as_ref()
                .is_some_and(|binding| record.expires_unix < binding.host_expires_unix)
        {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!(
                    "expired sidecar transition journal record {} has an inconsistent host-expiry \
bound; retained for review — run `ownmesh doctor` or inspect {} ",
                    record.transition_id,
                    self.transition_journal_dir().display(),
                ),
            });
        }
        // P0-A review: never clear an expired record on time/session state
        // alone — the referenced sidecar must be provably dead. A live child
        // process or a supervisor-tracked host means the record stays, and an
        // indeterminate probe stays fail-closed too.
        match self.prove_expired_sidecar_dead(&record).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: format!(
                        "expired sidecar transition journal record {} still references a live \
sidecar (attested child process or supervisor-tracked host); retained for review — run \
`ownmesh doctor` or inspect {} ",
                        record.transition_id,
                        self.transition_journal_dir().display(),
                    ),
                });
            }
            Err(message) => {
                return Err(IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: format!(
                        "expired sidecar transition journal record {} cannot prove its sidecar \
terminated ({message}); retained fail-closed — run `ownmesh doctor` or inspect {} ",
                        record.transition_id,
                        self.transition_journal_dir().display(),
                    ),
                });
            }
        }
        let current = match self.sessions.get(&record.session_id) {
            Ok(current) => current,
            // Session gone entirely + host TTL provably passed + the
            // referenced sidecar is provably dead: the intent is moot.
            // Clearing can never grant a controller or touch a live host.
            Err(ownmesh_session::SessionError::NotFound) => {
                return self
                    .transition_journal
                    .clear(&record.transition_id)
                    .map_err(|e| IpcError::Remote {
                        code: app_error::INTERNAL,
                        message: format!("clear moot expired transition: {e}"),
                    });
            }
            Err(error) => return Err(session_err(error)),
        };
        if current.state == SessionState::Closed {
            // Terminal session: no controller can be granted; the referenced
            // sidecar is provably dead. `SessionManager::close` leaves
            // `sidecar_host` intact, so verify the session's current binding
            // is not a live host referenced by this record before clearing.
            if let Some(binding) = &current.sidecar_host {
                let references_this_record = binding.host_nonce == record.old_binding.host_nonce
                    || record
                        .new_binding
                        .as_ref()
                        .is_some_and(|b| binding.host_nonce == b.host_nonce);
                if references_this_record && binding.host_expires_unix > Self::now() {
                    return Err(IpcError::Remote {
                        code: app_error::CONFLICT,
                        message: format!(
                            "expired sidecar transition journal record {} references a still-live \
host; retained for review — run `ownmesh doctor` or inspect {} ",
                            record.transition_id,
                            self.transition_journal_dir().display(),
                        ),
                    });
                }
            }
            return self
                .transition_journal
                .clear(&record.transition_id)
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("clear moot expired transition: {e}"),
                });
        }
        // Session still present and non-terminal: retain fail-closed and tell
        // the operator how to diagnose it. This is a per-record health issue,
        // never a global abort.
        Err(IpcError::Remote {
            code: app_error::CONFLICT,
            message: format!(
                "expired sidecar transition journal record {} (session {} still present) retained for review; \
run `ownmesh doctor` or inspect {} ",
                record.transition_id,
                record.session_id,
                self.transition_journal_dir().display(),
            ),
        })
    }

    /// Directory hosting the durable transition journal (for diagnostics).
    fn transition_journal_dir(&self) -> PathBuf {
        self.paths.state_dir.join("session-transitions")
    }

    fn handle_profile_list(&self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            #[serde(default)]
            cursor: Option<String>,
            #[serde(default)]
            limit: Option<usize>,
        }
        let p: P = parse_params(params)?;
        let reg = ProfileRegistry::with_official();
        let mut statuses: Vec<ProfileStatus> = reg.detect_all();
        statuses.sort_by(|a, b| a.id.cmp(&b.id));
        let limit = p.limit.unwrap_or(32).clamp(1, 64);
        let start = p
            .cursor
            .as_deref()
            .and_then(|c| statuses.iter().position(|s| s.id == c).map(|i| i + 1))
            .unwrap_or(0);
        let end = (start + limit).min(statuses.len());
        let page = &statuses[start..end];
        let truncated = end < statuses.len();
        let next_cursor = if truncated {
            page.last().map(|s| s.id.clone())
        } else {
            None
        };
        Ok(json!({
            "profiles": page,
            "count": page.len(),
            "total": statuses.len(),
            "truncated": truncated,
            "next_cursor": next_cursor,
            "official_count": 9,
            "note": "local PATH detection only; credentials never leave the device",
        }))
    }

    fn handle_profile_show(&self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
        }
        let p: P = parse_params(params)?;
        let reg = ProfileRegistry::with_official();
        let profile = reg.get(&p.id).map_err(|e| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: e.to_string(),
        })?;
        let status = reg.detect(&p.id).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })?;
        Ok(json!({
            "profile": profile,
            "status": status,
            "adapter": official_adapter_spec(&p.id),
            "auth_status": "unknown_no_credential_probe",
        }))
    }

    fn require_reader(&self, session_id: &str, principal: &str, now_unix: i64) -> IpcResult<()> {
        match self
            .sessions
            .authorize_reader(session_id, principal, now_unix)
        {
            Ok(()) => Ok(()),
            Err(ownmesh_session::SessionError::NotReader) => Err(IpcError::Remote {
                code: app_error::POLICY_DENIED,
                message: format!("principal {principal} cannot read session {session_id}"),
            }),
            Err(e) => Err(session_err(e)),
        }
    }

    fn require_controller(
        &self,
        session_id: &str,
        principal: &str,
        now_unix: i64,
    ) -> IpcResult<()> {
        match self
            .sessions
            .authorize_controller(session_id, principal, now_unix)
        {
            Ok(()) => Ok(()),
            Err(ownmesh_session::SessionError::NotController) => Err(IpcError::Remote {
                code: app_error::POLICY_DENIED,
                message: format!("principal {principal} is not controller of session {session_id}"),
            }),
            Err(e) => Err(session_err(e)),
        }
    }

    /// Resolve the session's immutable workspace binding and optionally check a
    /// caller-supplied `workspace_id`. Returns the bound id for action/audit use.
    ///
    /// Omitting the field is allowed for local IPC recovery paths; the bound value
    /// is still returned so callers can include it in subsequent exact-action hashes.
    /// A mismatched supplied id fails closed.
    fn require_session_workspace(
        &self,
        session_id: &str,
        workspace_id: Option<&str>,
    ) -> IpcResult<String> {
        let info = self.sessions.get(session_id).map_err(session_err)?;
        let bound = info
            .workspace_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("ws_default");
        let bound = if bound == "default" {
            "ws_default"
        } else {
            bound
        }
        .to_owned();
        if let Some(raw) = workspace_id.map(str::trim).filter(|s| !s.is_empty()) {
            let want = if raw == "default" { "ws_default" } else { raw };
            if bound != want {
                return Err(IpcError::Remote {
                    code: app_error::POLICY_DENIED,
                    message: format!(
                        "session {session_id} is bound to workspace {bound}, not {want}"
                    ),
                });
            }
        }
        Ok(bound)
    }

    fn sidecar_binding(&self, session_id: &str) -> IpcResult<SupervisorBinding> {
        let info = self.sessions.get(session_id).map_err(session_err)?;
        let binding = info.sidecar_host.clone().ok_or_else(|| IpcError::Remote {
            code: app_error::CONFLICT,
            message: format!("session {session_id} has no persistent sidecar binding"),
        })?;
        if let Some(active_device_id) = self.active_remote_device_id.as_deref() {
            if binding.device_id != active_device_id {
                return Err(IpcError::Remote {
                    code: app_error::POLICY_DENIED,
                    message: format!(
                        "persistent session {session_id} is bound to device {}, not verified device {active_device_id}",
                        binding.device_id
                    ),
                });
            }
        }
        Ok(SupervisorBinding {
            session_id: info.id.clone(),
            device_id: binding.device_id,
            workspace_id: binding.workspace_id,
            owner_principal: binding.owner_principal,
            host_nonce: binding.host_nonce,
            controller_epoch: binding.controller_epoch,
        })
    }

    fn verified_sidecar_binding_from(
        &self,
        session_id: &str,
        binding: &SidecarHostBinding,
    ) -> IpcResult<SupervisorBinding> {
        if let Some(active_device_id) = self.active_remote_device_id.as_deref() {
            if binding.device_id != active_device_id {
                return Err(IpcError::Remote {
                    code: app_error::POLICY_DENIED,
                    message: format!(
                        "persistent session {session_id} is bound to device {}, not verified device {active_device_id}",
                        binding.device_id
                    ),
                });
            }
        }
        Ok(supervisor_binding_from(session_id, binding))
    }

    /// Move pending live-host bytes into the session replay ring (bounded chunks).
    ///
    /// Loops until the live ring is empty or the per-call spool budget is hit.
    /// When live-ring bytes remain after the budget, a visible system note is
    /// appended so callers never see a false EOF (`truncated:false,next_seq:null`).
    fn drain_live_output_into_session(&mut self, session_id: &str) -> IpcResult<usize> {
        if !self.live_hosts.contains_key(session_id) {
            return Ok(0);
        }
        // Cap how much we fold into the durable spool per call so a huge ring
        // cannot monopolize the request path. Remaining live bytes stay visible.
        let per_call_budget = ownmesh_session::MAX_REPLAY_PAGE_BYTES;
        let mut drained = 0usize;
        let mut saw_ring_truncated = false;
        let mut exited = false;
        let mut exit_code: Option<u32> = None;
        let mut remaining_after = 0usize;

        while drained < per_call_budget {
            let take = (per_call_budget - drained).min(ownmesh_session::MAX_CHUNK_BYTES);
            // Drain without holding `live_hosts` across session mutations.
            let (text, ring_truncated, child_exited, child_code, remaining) = {
                let Some(host) = self.live_hosts.get(session_id) else {
                    break;
                };
                host.drain_output(take).map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("live PTY drain failed: {e}"),
                })?
            };
            saw_ring_truncated |= ring_truncated;
            exited |= child_exited;
            if child_code.is_some() {
                exit_code = child_code;
            }
            remaining_after = remaining;
            if text.is_empty() {
                break;
            }
            let snapshot = self.sessions.clone();
            // Split oversized text into MAX_CHUNK_BYTES pieces.
            let mut offset = 0usize;
            while offset < text.len() {
                let end = (offset + ownmesh_session::MAX_CHUNK_BYTES).min(text.len());
                // Prefer char boundaries for UTF-8 safety.
                let end = if text.is_char_boundary(end) {
                    end
                } else {
                    text.char_indices()
                        .map(|(i, _)| i)
                        .take_while(|i| *i <= end)
                        .last()
                        .unwrap_or(offset)
                        .max(offset + 1)
                        .min(text.len())
                };
                if end <= offset {
                    break;
                }
                let piece = &text[offset..end];
                self.sessions
                    .push_output(session_id, piece, SessionStreamKind::Stdout)
                    .map_err(session_err)?;
                drained = drained.saturating_add(piece.len());
                offset = end;
            }
            self.commit_sessions(snapshot)?;
            if remaining == 0 {
                break;
            }
        }

        // Re-check pending after the loop (reader may have appended concurrently).
        if let Some(host) = self.live_hosts.get(session_id) {
            remaining_after = remaining_after.max(host.pending_output_bytes());
        }

        if saw_ring_truncated || remaining_after > 0 {
            let snapshot = self.sessions.clone();
            if saw_ring_truncated {
                let _ = self.sessions.push_output(
                    session_id,
                    "[live-pty ring truncated under backpressure]",
                    SessionStreamKind::System,
                );
            }
            if remaining_after > 0 {
                let _ = self.sessions.push_output(
                    session_id,
                    format!(
                        "[live-pty more output pending bytes={remaining_after}; continue replay]"
                    ),
                    SessionStreamKind::System,
                );
            }
            self.commit_sessions(snapshot)?;
        }
        if exited {
            // Keep host until terminate/close so late drains still work; mark system note once.
            let note = match exit_code {
                Some(code) => format!("[live-pty exited code={code}]"),
                None => "[live-pty exited]".to_owned(),
            };
            let snapshot = self.sessions.clone();
            let _ = self
                .sessions
                .push_output(session_id, note, SessionStreamKind::System);
            let _ = self.commit_sessions(snapshot);
        }
        Ok(drained)
    }

    fn stop_live_host(&mut self, session_id: &str) {
        if let Some(mut host) = self.live_hosts.remove(session_id) {
            let _ = host.terminate();
            let _ = self.sessions.set_host_pid(session_id, None);
        }
    }

    /// Test helper: set policy in-memory without touching disk preset file optionally.
    #[cfg(test)]
    pub fn set_policy_for_test(&mut self, doc: PolicyDocument) {
        self.enforce_workspace = matches!(
            doc.preset,
            AccessPreset::WorkspaceOnly | AccessPreset::Recommended
        );
        self.policy = doc;
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn enforces_workspace_for_test(&self) -> bool {
        self.enforce_workspace
    }

    #[cfg(test)]
    pub fn is_lockdown(&self) -> bool {
        self.lockdown
    }

    /// Test helper: grants currently held in memory.
    ///
    /// Available whenever `cfg(test)` (bin unit tests + path-included integration harnesses).
    #[cfg(test)]
    #[allow(dead_code)]
    #[must_use]
    pub fn grants_for_test(&self) -> &[StoredGrant] {
        &self.grants
    }

    /// Test helper: inject a legacy/forged grant row (does not persist).
    ///
    /// Used to prove command.run grant matching stays fail-closed even when a
    /// persisted-shaped row is already present in memory.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn inject_grant_for_test(&mut self, grant: TemporaryGrant) {
        self.grants.push(StoredGrant::Temporary(grant));
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn inject_stored_grant_for_test(&mut self, grant: StoredGrant) {
        self.grants.push(grant);
    }

    /// Test helper: whether an idempotency key is present in the op journal.
    /// Accepts either a raw caller key or a principal-namespaced journal key.
    #[cfg(test)]
    #[allow(dead_code)]
    #[must_use]
    pub fn has_op_journal_key_for_test(&self, key: &str) -> bool {
        if self.op_journal.contains_key(key) {
            return true;
        }
        let suffix = format!("\u{1f}{key}");
        self.op_journal.keys().any(|k| k.ends_with(&suffix))
    }

    /// Test helper: whether a key is retained as non-retriable/uncertain.
    #[cfg(test)]
    #[allow(dead_code)]
    #[must_use]
    pub fn op_journal_key_is_in_progress_for_test(&self, key: &str) -> bool {
        if self
            .op_journal
            .get(key)
            .is_some_and(is_op_journal_in_progress)
        {
            return true;
        }
        let suffix = format!("\u{1f}{key}");
        self.op_journal
            .iter()
            .any(|(k, v)| k.ends_with(&suffix) && is_op_journal_in_progress(v))
    }

    /// Fault the nth future op-journal persist without touching the durable file.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn fail_op_journal_persist_on_nth_call_for_test(&self, nth: usize) {
        assert!(nth > 0);
        self.op_journal_persist_fault.store(nth, Ordering::SeqCst);
    }

    /// Fault the nth future op-journal *write* (after the stale-backup
    /// removal, before the durable write) without touching the durable file.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn fail_op_journal_write_on_nth_call_for_test(&self, nth: usize) {
        assert!(nth > 0);
        self.op_journal_write_fault.store(nth, Ordering::SeqCst);
    }

    /// Fault the nth future approval persist without touching the durable file.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn fail_approvals_persist_on_nth_call_for_test(&self, nth: usize) {
        assert!(nth > 0);
        self.approvals_persist_fault.store(nth, Ordering::SeqCst);
    }

    /// Fault the nth future session persist without touching the durable file.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn fail_sessions_persist_on_nth_call_for_test(&self, nth: usize) {
        // nth=0 clears the fault injector.
        self.sessions_persist_fault.store(nth, Ordering::SeqCst);
    }

    /// Fault a destination journal save after its part write has completed.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn fail_transfer_journal_persist_on_nth_call_for_test(&self, nth: usize) {
        self.transfer_journal_persist_fault
            .store(nth, Ordering::SeqCst);
    }

    /// Test helper: number of in-memory sessions.
    #[cfg(test)]
    #[allow(dead_code)]
    #[must_use]
    pub fn session_count_for_test(&self) -> usize {
        self.sessions.list().len()
    }

    /// Test helper: drop the live PTY while keeping session metadata (daemon restart).
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn stop_live_host_for_test(&mut self, session_id: &str) {
        self.stop_live_host(session_id);
    }

    /// Test helper: force a controller lease expiry timestamp (does not auto-extend).
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn set_session_controller_expiry_for_test(
        &mut self,
        id: &str,
        expires_unix: i64,
    ) -> IpcResult<()> {
        self.sessions
            .set_controller_expires_unix(id, expires_unix)
            .map_err(session_err)
    }

    /// Test helper: inspect controller principal after auth-side effects.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn session_controller_for_test(&self, id: &str) -> Option<String> {
        self.sessions
            .get(id)
            .ok()
            .and_then(|info| info.controller.as_ref().map(|c| c.principal_id.clone()))
    }

    /// Test helper: serialize the complete in-memory session manager for equality checks.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn session_state_for_test(&self) -> Value {
        serde_json::to_value(&self.sessions).expect("session manager must serialize")
    }

    /// Sweep expired transfer journals, private parts, and source snapshots.
    ///
    /// The daemon owns this behind its runtime mutex, which serializes cleanup
    /// with every transfer admission and quota mutation performed by IPC or the
    /// Agent transport. `JournalStore` independently locks its state directory
    /// for direct cloned-store callers.
    pub(crate) fn cleanup_expired_transfers(&mut self) -> Result<usize, String> {
        let now = Self::now() as u64;
        // Release only stale destination handles before filesystem cleanup.
        // Live exact-bound streams remain cached across the periodic sweep so
        // a long transfer is not forced to rehash its prefix every interval.
        let store = self.transfer_store.clone();
        self.transfer_receivers.retain(|plan_id, cached| {
            let Some(plan) = store.load_plan(plan_id, now).ok().flatten() else {
                return false;
            };
            let Ok(journal) = store.load_for_fence(&plan, cached.epoch, cached.fence) else {
                return false;
            };
            journal.expires_at_unix() > now
                && cached.matches(cached.epoch, cached.fence, &journal)
                && cached
                    .sink
                    .validate_cached_position(journal.bytes_received())
                    .is_ok()
        });
        let removed = self
            .transfer_store
            .cleanup_expired(now)
            .map_err(|error| format!("cleanup transfer state: {error}"))?;
        if removed != 0 {
            // Drop only cache entries whose exact immutable plan disappeared
            // or no longer validates. An unrelated expired transfer must not
            // interrupt another live long-running source transfer.
            let store = self.transfer_store.clone();
            self.transfer_senders
                .retain(|plan_id, _| store.load_plan(plan_id, now).ok().flatten().is_some());
            self.transfer_last_chunks
                .retain(|plan_id, _| store.load_plan(plan_id, now).ok().flatten().is_some());
        }
        Ok(removed)
    }
}

/// Build the IPC method handler backed by shared runtime state.
pub fn runtime_handler(runtime: Arc<Mutex<DaemonRuntime>>) -> MethodHandler {
    Arc::new(move |method, params, client| {
        let runtime = Arc::clone(&runtime);
        Box::pin(async move {
            let mut guard = runtime.lock().await;
            guard.dispatch(&method, params, &client).await
        })
    })
}

/// Fail-closed gate for approval decisions at the runtime handler boundary.
///
/// Ordinary IPC already denies approve/deny (no distinct OS/UI presence proof). This gate
/// remains as defense in depth for direct-dispatch / internal callers:
/// - Approver must be an OS-shaped human principal (`user:*`) — never a client credential.
/// - Credentialed requesters cannot self-approve.
/// - Client-supplied approver fields are never consulted (caller passes auth identity only).
///
/// Note: a bare `user:<uid>` string is **not** a presence proof on the IPC plane; AuthGate
/// refuses ordinary IPC human-operator methods entirely until a bound presence mechanism exists.
fn ensure_independent_human_approver(approver: &str, requester: &str) -> IpcResult<()> {
    let approver = canonicalize_principal_key(approver);
    let requester = canonicalize_principal_key(requester);
    if approver.is_empty()
        || !is_human_os_principal(&approver)
        || is_credentialed_client_principal(&approver)
    {
        return Err(IpcError::Remote {
            code: app_error::UNAUTHORIZED,
            message: "approval requires an independently authenticated human OS principal (user:*)"
                .into(),
        });
    }
    // Agent/service creators (`client:*`) must always be decided by a different principal.
    if is_credentialed_client_principal(&requester) && requester == approver {
        return Err(IpcError::Remote {
            code: app_error::UNAUTHORIZED,
            message: "operation creator cannot self-approve; independent human principal required"
                .into(),
        });
    }
    Ok(())
}

/// Reject request-declared principal when it disagrees with authenticated identity.
fn reject_spoofed_principal(claimed: Option<&str>, authenticated: &str) -> IpcResult<()> {
    if let Some(claimed) = claimed {
        if claimed != authenticated {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: format!(
                    "self-reported principal '{claimed}' does not match authenticated client '{authenticated}'"
                ),
            });
        }
    }
    Ok(())
}

fn with_rollback_errors(primary: IpcError, rollback_errors: Vec<IpcError>) -> IpcError {
    if rollback_errors.is_empty() {
        return primary;
    }
    let details = rollback_errors
        .into_iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    match primary {
        IpcError::Remote { code, message } => IpcError::Remote {
            code,
            message: format!("{message}; rollback persistence also failed: {details}"),
        },
        other => IpcError::Remote {
            code: app_error::INTERNAL,
            message: format!("{other}; rollback persistence also failed: {details}"),
        },
    }
}

/// Bound environment overlay for structured/raw command execution.
/// Rejects oversized or malformed keys/values before process spawn.
fn sanitize_exec_env(raw: &HashMap<String, String>) -> IpcResult<HashMap<String, String>> {
    const MAX_ENV_ENTRIES: usize = 32;
    const MAX_ENV_KEY_BYTES: usize = 128;
    const MAX_ENV_VALUE_BYTES: usize = 4_096;
    const MAX_ENV_TOTAL_BYTES: usize = 16_384;
    if raw.len() > MAX_ENV_ENTRIES {
        return Err(IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: format!("env exceeds {MAX_ENV_ENTRIES} entries"),
        });
    }
    let mut out = HashMap::with_capacity(raw.len());
    let mut total = 0usize;
    for (key, value) in raw {
        if key.is_empty()
            || key.len() > MAX_ENV_KEY_BYTES
            || key.contains('\0')
            || key.contains('=')
        {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "env key is empty, too long, or contains NUL/=".into(),
            });
        }
        if value.len() > MAX_ENV_VALUE_BYTES || value.contains('\0') {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "env value is too long or contains NUL".into(),
            });
        }
        total = total.saturating_add(key.len()).saturating_add(value.len());
        if total > MAX_ENV_TOTAL_BYTES {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("env exceeds {MAX_ENV_TOTAL_BYTES} total bytes"),
            });
        }
        out.insert(key.clone(), value.clone());
    }
    Ok(out)
}

fn parse_params<T: for<'de> Deserialize<'de>>(params: Option<Value>) -> IpcResult<T> {
    let value = params.unwrap_or_else(|| json!({}));
    serde_json::from_value(value).map_err(|e| IpcError::Remote {
        code: app_error::INVALID_PARAMS,
        message: format!("invalid params: {e}"),
    })
}

fn require_id(params: Option<Value>, field: &str) -> IpcResult<String> {
    let value = params.unwrap_or_else(|| json!({}));
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: format!("{field} is required"),
        })
}

fn fs_err(err: ownmesh_fs::FsError) -> IpcError {
    match err {
        ownmesh_fs::FsError::HashMismatch { .. } => IpcError::Remote {
            code: app_error::CONFLICT,
            // The FS error includes an absolute custody path and file hashes.
            // Neither belongs in a remote response; callers only need to know
            // that their optimistic precondition became stale.
            message: "file changed since it was read".into(),
        },
        ownmesh_fs::FsError::GitWorktreeOutsideWorkspace => IpcError::Remote {
            code: app_error::POLICY_DENIED,
            message: "git worktree is outside the selected workspace".into(),
        },
        other => IpcError::Remote {
            code: app_error::INTERNAL,
            message: other.to_string(),
        },
    }
}

fn session_err(err: ownmesh_session::SessionError) -> IpcError {
    let code = match &err {
        ownmesh_session::SessionError::NotFound
        | ownmesh_session::SessionError::Invalid(_)
        | ownmesh_session::SessionError::ChunkTooLarge
        | ownmesh_session::SessionError::SequenceRequired(_)
        | ownmesh_session::SessionError::SequenceStale { .. }
        | ownmesh_session::SessionError::SequenceGap { .. }
        | ownmesh_session::SessionError::SequenceConflict { .. } => app_error::INVALID_PARAMS,
        ownmesh_session::SessionError::NotReader => app_error::POLICY_DENIED,
        ownmesh_session::SessionError::SessionLimit
        | ownmesh_session::SessionError::ReplayBudget
        | ownmesh_session::SessionError::LeaseHeld(_)
        | ownmesh_session::SessionError::NotController
        | ownmesh_session::SessionError::ObserverCannotWrite
        | ownmesh_session::SessionError::Closed => app_error::CONFLICT,
        ownmesh_session::SessionError::Persist(_) => app_error::INTERNAL,
    };
    IpcError::Remote {
        code,
        message: err.to_string(),
    }
}

/// Remote MCP principals are namespaced `client:remote:<tenant>:<principal>`.
fn is_remote_runtime_principal(principal: &str) -> bool {
    let p = canonicalize_principal_key(principal);
    p.starts_with("client:remote:") || p.starts_with("client:remote-agent:")
}

/// Map a session.give `to` target into the authenticated runtime principal space.
///
/// Accepts a full `client:remote:<tenant>:<principal>` key (must share the caller's
/// tenant) or a bare principal id which is bound to the caller's tenant.
fn normalize_handoff_target(from: &str, to: &str) -> IpcResult<String> {
    let to = to.trim();
    if to.is_empty() || to.len() > 128 {
        return Err(IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: "session.give to must be a non-empty principal id (<=128 chars)".into(),
        });
    }
    if to
        .chars()
        .any(|c| c.is_control() || c == '/' || c == '\\' || c == ' ')
    {
        return Err(IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: "session.give to contains invalid characters".into(),
        });
    }
    let from_canon = canonicalize_principal_key(from);
    if let Some(rest) = from_canon.strip_prefix("client:remote:") {
        let mut parts = rest.splitn(2, ':');
        let tenant = parts.next().unwrap_or("");
        if tenant.is_empty() {
            return Err(IpcError::Remote {
                code: app_error::INTERNAL,
                message: "authenticated remote principal missing tenant".into(),
            });
        }
        let to_canon = canonicalize_principal_key(to);
        if let Some(to_rest) = to_canon.strip_prefix("client:remote:") {
            let mut to_parts = to_rest.splitn(2, ':');
            let to_tenant = to_parts.next().unwrap_or("");
            let to_prin = to_parts.next().unwrap_or("");
            if to_tenant != tenant || to_prin.is_empty() {
                return Err(IpcError::Remote {
                    code: app_error::POLICY_DENIED,
                    message: "session.give target must share the controller tenant".into(),
                });
            }
            return Ok(format!("client:remote:{tenant}:{to_prin}"));
        }
        // Bare principal id — bind to controller tenant.
        if to_canon.contains(':') {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "session.give to must be a bare principal id or client:remote:... key"
                    .into(),
            });
        }
        return Ok(format!("client:remote:{tenant}:{to_canon}"));
    }
    // Local IPC path: keep the supplied principal as-is (canonicalized).
    Ok(canonicalize_principal_key(to))
}

/// Build the durable local journal key so receipts never cross principals.
fn principal_journal_key(principal: &str, idempotency_key: &str) -> String {
    format!(
        "{}\u{1f}{}",
        canonicalize_principal_key(principal),
        idempotency_key
    )
}

fn pending_request_is_admin(request: &PendingRequest) -> bool {
    matches!(
        request,
        PendingRequest::AdminPolicyPreset(_)
            | PendingRequest::AdminPolicyRuleAdd(_)
            | PendingRequest::AdminPolicyRuleRemove(_)
            | PendingRequest::AdminDaemonUnlock(_)
            | PendingRequest::AdminTokenRevoke(_)
            | PendingRequest::AdminApprovalBridge(_)
            | PendingRequest::AdminGrantsMint(_)
    )
}

fn pending_request_tool(request: &PendingRequest) -> Option<&'static str> {
    match request {
        PendingRequest::Exec(params) => {
            let kind = params.policy_kind.as_deref().unwrap_or("");
            if kind.eq_ignore_ascii_case("raw_shell") || kind.eq_ignore_ascii_case("raw") {
                Some("command_shell")
            } else {
                Some("command_run")
            }
        }
        PendingRequest::FsList(_) => Some("fs_list"),
        PendingRequest::FsStat(_) => Some("fs_stat"),
        PendingRequest::FsRead(_) => Some("fs_read"),
        PendingRequest::FsWrite(_) => Some("fs_write"),
        PendingRequest::FsDelete(_) => Some("fs_delete"),
        PendingRequest::LogsQuery(_) => Some("logs_query"),
        PendingRequest::GitStatus(_) => Some("git_status"),
        PendingRequest::GitDiff(_) => Some("git_diff"),
        PendingRequest::SystemDiagnose(_)
        | PendingRequest::AdminPolicyPreset(_)
        | PendingRequest::AdminPolicyRuleAdd(_)
        | PendingRequest::AdminPolicyRuleRemove(_)
        | PendingRequest::AdminDaemonUnlock(_)
        | PendingRequest::AdminTokenRevoke(_)
        | PendingRequest::AdminApprovalBridge(_)
        | PendingRequest::AdminGrantsMint(_) => None,
    }
}

fn validate_admin_idempotency_key(value: &str) -> IpcResult<()> {
    if value.trim() != value
        || value.is_empty()
        || value.len() > 256
        || value.chars().any(char::is_control)
    {
        return Err(IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message:
                "idempotency_key must be 1-256 control-free characters without edge whitespace"
                    .into(),
        });
    }
    Ok(())
}

fn broker_binding_error(message: &str) -> IpcError {
    IpcError::Remote {
        code: app_error::UNAUTHORIZED,
        message: format!(
            "privileged broker binding unavailable: {message} (fail-closed; no local exec)"
        ),
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
}

fn split_remote_principal(value: &str) -> Option<(&str, &str)> {
    let mut fields = value.split(':');
    match (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) {
        (Some("client"), Some("remote"), Some(tenant), Some(principal), None)
            if !tenant.is_empty()
                && !principal.is_empty()
                && tenant.len() <= 128
                && principal.len() <= 128 =>
        {
            Some((tenant, principal))
        }
        _ => None,
    }
}

/// Durable op-journal entry state classification (P0-B).
///
/// Completed is an *explicit, positive* marker only: either the compact
/// `durable_receipt: true` encoding this version writes, the explicit
/// `__ownmesh_operation_state == "completed"` value, or a legacy (pre-1.2.13)
/// completed result body that carries positive proof of completion (a non-
/// empty `operation_id` plus a recognizable completion field such as
/// `decision`/`approval_required`/`review_id`). A JSON object with *no* state
/// field and none of that proof — e.g. a truncated or hand-written `{}` — is
/// **uncertain**, never completed: compacting or evicting it could hide an
/// unfinished side effect. The exact `in_progress` marker, any other present
/// state value (unknown/forward-version string, or non-string such as
/// `null`/number/boolean), and any non-object top-level entry are also
/// uncertain and must never be compacted, evicted, or replayed as a completed
/// receipt.
///
/// ADR 0010 §1b requires every completed entry to carry the exact-once
/// `operation_id` marker, so the `durable_receipt: true` and explicit
/// `"completed"` markers only classify as completed together with a non-empty
/// `operation_id`. A marker without one is malformed (hand-written or
/// truncated): compacting or eventually evicting it would let a retried
/// operation run as a brand-new side effect, so it stays uncertain and is
/// never replayed, compacted, or pruned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpJournalEntryState {
    /// `__ownmesh_operation_state == "in_progress"`: the exact-once marker.
    InProgress,
    /// A state field is present but not a value this version writes, or the
    /// entry is not a JSON object, or the object carries no explicit
    /// completed marker with the exact-once `operation_id`: fail closed
    /// (forward-version / unknown / malformed / truncated).
    Uncertain,
    /// The entry is provably a completed receipt (explicit marker with a
    /// non-empty `operation_id`, or legacy completed body with positive
    /// completion proof).
    Completed,
}

/// Non-empty exact-once `operation_id` (ADR 0010 §1b).
fn has_exact_once_operation_id(object: &serde_json::Map<String, Value>) -> bool {
    object
        .get("operation_id")
        .and_then(Value::as_str)
        .is_some_and(|id| !id.is_empty())
}

fn op_journal_entry_state(value: &Value) -> OpJournalEntryState {
    // A non-object entry (null/array/string/number/boolean) has no state
    // field by construction, but it is not a completed receipt this version
    // writes either — classify it uncertain so it is never compacted,
    // evicted, or replayed as completed (fail-closed).
    let Some(object) = value.as_object() else {
        return OpJournalEntryState::Uncertain;
    };
    match object.get(OP_JOURNAL_STATE_FIELD) {
        None => {
            // No state field: completed only when the entry carries an
            // explicit positive marker *with the exact-once operation_id*
            // (ADR 0010 §1b), or is a legacy completed result body with
            // positive completion proof. A `durable_receipt: true` marker
            // without an `operation_id` is malformed — compacting or
            // evicting it could let a retry execute as a new side effect, so
            // it stays uncertain. Anything else — including a bare `{}` —
            // stays uncertain and is never pruned or replayed as completed.
            if object.get("durable_receipt").and_then(Value::as_bool) == Some(true)
                && has_exact_once_operation_id(object)
            {
                return OpJournalEntryState::Completed;
            }
            if legacy_completed_body(object) {
                return OpJournalEntryState::Completed;
            }
            OpJournalEntryState::Uncertain
        }
        Some(field) => match field.as_str() {
            Some(OP_JOURNAL_IN_PROGRESS) => OpJournalEntryState::InProgress,
            // The explicit completed value this version writes always carries
            // the exact-once `operation_id` (ADR 0010 §1b); a `"completed"`
            // marker without one is malformed and stays uncertain.
            Some("completed") if has_exact_once_operation_id(object) => {
                OpJournalEntryState::Completed
            }
            // A present state field that is not the exact in-progress marker
            // or the explicit completed value (including a non-string value
            // such as null/number/boolean) is uncertain: it is not a
            // completed receipt this version wrote.
            Some(_) | None => OpJournalEntryState::Uncertain,
        },
    }
}

/// Positive completion proof for legacy (pre-1.2.13) result bodies: every
/// completed entry this runtime ever wrote carries a non-empty `operation_id`
/// plus a recognizable completion field (`decision`, `approval_required`, or
/// a `review_id` receipt). Requiring this proof means a truncated or
/// hand-written object is never promoted to a completed receipt.
fn legacy_completed_body(object: &serde_json::Map<String, Value>) -> bool {
    let has_operation_id = object
        .get("operation_id")
        .and_then(Value::as_str)
        .is_some_and(|id| !id.is_empty());
    if !has_operation_id {
        return false;
    }
    let has_decision = object
        .get("decision")
        .and_then(Value::as_str)
        .is_some_and(|d| !d.is_empty());
    let has_approval_flag = object
        .get("approval_required")
        .is_some_and(Value::is_boolean);
    let has_review_id = object
        .get("review_id")
        .and_then(Value::as_str)
        .is_some_and(|id| !id.is_empty());
    has_decision || has_approval_flag || has_review_id
}

fn is_op_journal_in_progress(value: &Value) -> bool {
    op_journal_entry_state(value) == OpJournalEntryState::InProgress
}

/// Fail-closed protection predicate: in-progress markers and unknown states
/// are never compacted or evicted, and never replayed as completed.
fn is_op_journal_uncertain(value: &Value) -> bool {
    op_journal_entry_state(value) != OpJournalEntryState::Completed
}

/// Project a server-side [`ExecutablePin`] into policy grant/facts identity binding.
/// Never construct this from client-supplied digests.
fn executable_identity_from_pin(pin: &ExecutablePin) -> ExecutableIdentityBinding {
    ExecutableIdentityBinding {
        path: pin.path.clone(),
        content_sha256: pin.content_sha256.clone(),
        len: pin.len,
        device: pin.device,
        inode: pin.inode,
        path_device: pin.path_device,
        path_inode: pin.path_inode,
        link_target: pin.link_target.clone(),
        policy_kind: pin.policy_kind.clone(),
    }
}

fn decision_str(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        Decision::Deny => "deny",
    }
}

fn preset_name(p: AccessPreset) -> &'static str {
    match p {
        AccessPreset::WorkspaceOnly => "workspace_only",
        AccessPreset::Recommended => "recommended",
        AccessPreset::FullUserAccess => "full_user_access",
        AccessPreset::FullAccess => "full_access",
        AccessPreset::Custom => "custom",
    }
}

/// Machine classification tags for a workspace-relative filesystem path.
///
/// Restricted presets turn `reads_sensitive_location` into an `Ask`
/// (specification §7.1/§7.4). The tag is derived here, from the path the daemon
/// resolved, so a client or model cannot suppress it by omitting a field — and
/// cannot manufacture one either, because callers never supply `tags`.
fn sensitive_path_tags(path: &str, write: bool) -> Vec<String> {
    if !looks_sensitive(Path::new(path)) {
        return Vec::new();
    }
    let tag = if write {
        TAG_WRITES_SENSITIVE_LOCATION
    } else {
        TAG_READS_SENSITIVE_LOCATION
    };
    vec![tag.to_owned()]
}

fn parse_preset(name: &str) -> Option<AccessPreset> {
    match name.to_ascii_lowercase().replace('-', "_").as_str() {
        "workspace_only" | "workspaceonly" => Some(AccessPreset::WorkspaceOnly),
        "recommended" => Some(AccessPreset::Recommended),
        "full_user_access" | "fulluseraccess" => Some(AccessPreset::FullUserAccess),
        "full_access" | "fullaccess" => Some(AccessPreset::FullAccess),
        "custom" => Some(AccessPreset::Custom),
        _ => None,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// RFC 4648 standard Base64 with `=` padding (not base64url).
fn supervisor_binding_from(session_id: &str, binding: &SidecarHostBinding) -> SupervisorBinding {
    SupervisorBinding {
        session_id: session_id.into(),
        device_id: binding.device_id.clone(),
        workspace_id: binding.workspace_id.clone(),
        owner_principal: binding.owner_principal.clone(),
        host_nonce: binding.host_nonce.clone(),
        controller_epoch: binding.controller_epoch,
    }
}

/// Reconcile only rows whose original sidecar child is definitely gone.  A
/// live process, unknown process identity, or a platform probe failure keeps
/// the row intact for explicit recovery rather than risking a false terminal
/// report or a PID-reuse kill.
fn reconcile_dead_persistent_sessions(sessions: &mut SessionManager, sidecar_root: &Path) -> usize {
    let candidates: Vec<_> = sessions
        .list()
        .into_iter()
        .filter_map(|info| info.sidecar_host.map(|binding| (info.id, binding)))
        .collect();
    let mut reconciled = 0;
    for (session_id, binding) in candidates {
        let dead = match persistent_child_is_live(&binding) {
            Ok(false) => true,
            Ok(true) => false,
            Err(_) => persistent_sidecar_has_terminal_receipt(sidecar_root, &binding, &session_id),
        };
        if !dead {
            continue;
        }
        if sessions.close(&session_id).is_ok()
            && sessions.set_sidecar_host_binding(&session_id, None).is_ok()
        {
            let _ = sessions.set_host_pid(&session_id, None);
            reconciled += 1;
        }
    }
    reconciled
}

fn persistent_sidecar_has_terminal_receipt(
    sidecar_root: &Path,
    binding: &SidecarHostBinding,
    session_id: &str,
) -> bool {
    let Ok(Some(receipt)) = OwnerSpool::termination_receipt(sidecar_root, session_id) else {
        return false;
    };
    receipt.session_id == session_id
        && receipt.device_id == binding.device_id
        && receipt.workspace_id == binding.workspace_id
        && receipt.owner_principal == binding.owner_principal
        && receipt.host_nonce == binding.host_nonce
        && receipt.controller_epoch == binding.controller_epoch
}

/// A process is live only when both the stored PID and OS-issued birth witness
/// still match. A missing/changing witness proves the original child ended,
/// but does not assign ownership to a reused PID.
fn persistent_child_is_live(binding: &SidecarHostBinding) -> Result<bool, String> {
    let pid = binding
        .child_pid
        .ok_or("persistent sidecar binding lacks a durable child PID")?;
    let expected = binding
        .child_process_birth
        .ok_or("persistent sidecar binding lacks a durable child birth witness")?;
    match ownmesh_ipc::process_birth_id(pid)? {
        Some(observed) => Ok(observed == expected),
        None => Ok(false),
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod device_binding_tests {
    use super::*;

    /// Owner-only tempdir: `tempfile` respects the process umask, and the
    /// daemon custody attestation rejects group/world-writable ancestors, so
    /// tests pin mode 0700 to stay umask-independent.
    fn tempdir() -> std::io::Result<tempfile::TempDir> {
        let dir = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(dir)
    }

    #[test]
    fn authenticated_workspace_registry_contains_ids_and_policy_but_no_roots() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime
            .upsert_workspace(WorkspaceEntry {
                id: "ws_repo".into(),
                root: dir.path().join("repo"),
                label: Some("Repository".into()),
                generation: String::new(),
            })
            .unwrap();
        runtime.set_policy_for_test(preset_document(AccessPreset::Recommended));

        let (enforce_workspace, registrations) = runtime.remote_workspace_registry();
        assert!(enforce_workspace);
        assert_eq!(
            registrations
                .iter()
                .map(|workspace| workspace.id.as_str())
                .collect::<Vec<_>>(),
            vec!["ws_default", "ws_repo"]
        );
        assert!(registrations
            .iter()
            .all(|workspace| valid_workspace_generation(&workspace.generation)));

        runtime.workspaces[0].id = "default".into();
        let (_, legacy) = runtime.remote_workspace_registry();
        assert_eq!(
            legacy
                .iter()
                .map(|workspace| workspace.id.as_str())
                .collect::<Vec<_>>(),
            vec!["ws_default", "ws_repo"]
        );
    }

    #[test]
    fn workspace_add_returns_generation_and_does_not_claim_cloud_readiness() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let root = dir.path().join("proj");
        std::fs::create_dir_all(&root).unwrap();
        let added = runtime
            .handle_workspace_add(
                Some(json!({
                    "path": root.to_string_lossy(),
                    "id": "ws_proj",
                    "label": "Project",
                })),
                &ClientIdentity::new("client:local:test", "test"),
            )
            .unwrap();
        assert_eq!(added["id"], "ws_proj");
        assert_eq!(added["activation_state"], "device_local");
        let generation = added["generation"].as_str().unwrap();
        assert!(valid_workspace_generation(generation));
        let listed = runtime
            .handle_workspace_list(&ClientIdentity::new("client:local:test", "test"))
            .unwrap();
        assert_eq!(
            listed["workspace_root_enforcement"],
            listed["enforce_workspace"]
        );
        assert!(listed["workspace_root_enforcement_note"]
            .as_str()
            .unwrap()
            .contains("Independent of access_preset"));
    }

    #[test]
    fn workspace_generation_changes_only_when_the_id_maps_to_another_root() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let first = runtime
            .upsert_workspace(WorkspaceEntry {
                id: "ws_repo".into(),
                root: dir.path().join("repo-a"),
                label: Some("A".into()),
                generation: String::new(),
            })
            .unwrap();
        let label_only = runtime
            .upsert_workspace(WorkspaceEntry {
                id: "ws_repo".into(),
                root: dir.path().join("repo-a"),
                label: Some("renamed".into()),
                generation: String::new(),
            })
            .unwrap();
        assert_eq!(label_only.generation, first.generation);

        let remapped = runtime
            .upsert_workspace(WorkspaceEntry {
                id: "ws_repo".into(),
                root: dir.path().join("repo-b"),
                label: None,
                generation: String::new(),
            })
            .unwrap();
        assert_ne!(remapped.generation, first.generation);

        runtime
            .workspaces
            .retain(|workspace| workspace.id != "ws_repo");
        runtime.persist_workspaces().unwrap();
        let readded = runtime
            .upsert_workspace(WorkspaceEntry {
                id: "ws_repo".into(),
                root: dir.path().join("repo-b"),
                label: None,
                generation: String::new(),
            })
            .unwrap();
        assert_ne!(readded.generation, remapped.generation);
    }

    fn reused_process_identity_fixture() -> (u32, u64) {
        // A live PID with a different OS birth witness deterministically models
        // PID reuse: the process exists, but it cannot be the persisted child.
        let pid = std::process::id();
        let observed = ownmesh_ipc::process_birth_id(pid).unwrap().unwrap();
        let stale_birth = if observed == u64::MAX {
            observed - 1
        } else {
            observed + 1
        };
        (pid, stale_birth)
    }

    #[test]
    fn verified_remote_device_cannot_substitute_a_persistent_sidecar_binding() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let session = runtime
            .sessions
            .open(
                SessionKind::Pty,
                "device-bound",
                "client:remote:tenant:owner",
                DaemonRuntime::now(),
                None,
            )
            .unwrap();
        runtime
            .sessions
            .set_sidecar_host_binding(
                &session.id,
                Some(SidecarHostBinding {
                    device_id: "dev_a".into(),
                    workspace_id: "ws_default".into(),
                    owner_principal: "client:remote:tenant:owner".into(),
                    host_nonce: "host_nonce".into(),
                    controller_epoch: 1,
                    binding_expires_unix: DaemonRuntime::now() + 60,
                    host_expires_unix: DaemonRuntime::now() + 600,
                    child_pid: None,
                    child_process_birth: None,
                }),
            )
            .unwrap();
        runtime.active_remote_device_id = Some("dev_b".into());
        let error = runtime.sidecar_binding(&session.id).unwrap_err();
        assert!(matches!(
            error,
            IpcError::Remote {
                code: app_error::POLICY_DENIED,
                ..
            }
        ));
        runtime.active_remote_device_id = Some("dev_a".into());
        assert_eq!(
            runtime.sidecar_binding(&session.id).unwrap().device_id,
            "dev_a"
        );
    }

    #[test]
    fn missing_supervisor_reconciles_only_a_confirmed_dead_child() {
        let (dead_pid, dead_birth) = reused_process_identity_fixture();
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let session = runtime
            .sessions
            .open(
                SessionKind::Pty,
                "dead-child",
                "client:remote:tenant:owner",
                DaemonRuntime::now(),
                None,
            )
            .unwrap();
        runtime
            .sessions
            .set_host_pid(&session.id, Some(dead_pid))
            .unwrap();
        runtime
            .sessions
            .set_sidecar_host_binding(
                &session.id,
                Some(SidecarHostBinding {
                    device_id: "dev_a".into(),
                    workspace_id: "ws_default".into(),
                    owner_principal: "client:remote:tenant:owner".into(),
                    host_nonce: "host_nonce".into(),
                    controller_epoch: 1,
                    binding_expires_unix: DaemonRuntime::now() + 60,
                    host_expires_unix: DaemonRuntime::now() + 600,
                    child_pid: Some(dead_pid),
                    child_process_birth: Some(dead_birth),
                }),
            )
            .unwrap();

        assert!(runtime
            .reconcile_terminal_after_supervisor_failure(&session.id, TransitionKind::Close)
            .unwrap());
        let reconciled = runtime.sessions.get(&session.id).unwrap();
        assert_eq!(reconciled.state, ownmesh_session::SessionState::Closed);
        assert!(reconciled.sidecar_host.is_none());
    }

    #[test]
    fn startup_reconciles_a_provably_dead_persistent_session() {
        let (dead_pid, dead_birth) = reused_process_identity_fixture();
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let session_id = {
            let mut runtime = DaemonRuntime::open(&paths).unwrap();
            let session = runtime
                .sessions
                .open(
                    SessionKind::Pty,
                    "dead-after-restart",
                    "client:remote:tenant:owner",
                    DaemonRuntime::now(),
                    None,
                )
                .unwrap();
            runtime
                .sessions
                .set_sidecar_host_binding(
                    &session.id,
                    Some(SidecarHostBinding {
                        device_id: "dev_a".into(),
                        workspace_id: "ws_default".into(),
                        owner_principal: "client:remote:tenant:owner".into(),
                        host_nonce: "host_nonce".into(),
                        controller_epoch: 1,
                        binding_expires_unix: DaemonRuntime::now() + 60,
                        host_expires_unix: DaemonRuntime::now() + 600,
                        child_pid: Some(dead_pid),
                        child_process_birth: Some(dead_birth),
                    }),
                )
                .unwrap();
            runtime.persist_sessions().unwrap();
            session.id
        };

        let runtime = DaemonRuntime::open(&paths).unwrap();
        let recovered = runtime.sessions.get(&session_id).unwrap();
        assert_eq!(recovered.state, ownmesh_session::SessionState::Closed);
        assert!(recovered.sidecar_host.is_none());
        assert!(recovered.host_pid.is_none());
    }

    #[tokio::test]
    async fn close_retry_after_restart_terminates_an_interrupted_starting_sidecar() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let sidecar_root = paths.state_dir.join("session-supervisor");
        let (supervisor_server, _) =
            ownmesh_session_host::SupervisorIpcServer::new(&sidecar_root, &paths.runtime_dir)
                .unwrap();
        let endpoint = supervisor_server.endpoint().clone();
        let server = Arc::clone(supervisor_server.server());
        let server_task = tokio::spawn({
            let server = Arc::clone(&server);
            async move { server.serve().await.unwrap() }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let management =
            read_management_credential(supervisor_server.credential_state_dir()).unwrap();
        let supervisor =
            SupervisorClient::bootstrap(endpoint, paths.runtime_dir.clone(), management)
                .await
                .unwrap();

        let session = runtime
            .sessions
            .open(
                SessionKind::Pty,
                "interrupted-open",
                "client:remote:tenant:owner",
                DaemonRuntime::now(),
                None,
            )
            .unwrap();
        let lease = session.controller.clone().unwrap();
        let (program, args) = if cfg!(windows) {
            (
                "ping.exe".to_owned(),
                vec!["-n".into(), "30".into(), "127.0.0.1".into()],
            )
        } else {
            ("/bin/sh".to_owned(), vec!["-c".into(), "sleep 30".into()])
        };
        let exact = supervisor
            .spawn(SupervisorSpawnRequest {
                session_id: session.id.clone(),
                device_id: "dev_a".into(),
                workspace_id: "ws_default".into(),
                owner_principal: "client:remote:tenant:owner".into(),
                controller_epoch: lease.epoch,
                binding_expires_unix: lease.expires_unix,
                host_expires_unix: DaemonRuntime::now() + 7_200,
                command: SupervisorCommand {
                    program,
                    args,
                    cwd: None,
                    env: Vec::new(),
                },
                cols: 80,
                rows: 24,
                io_mode: HostIoMode::StructuredPipes,
                profile_id: Some("test-profile".into()),
                adapter_dialect: Some("test-jsonl".into()),
            })
            .await
            .unwrap();
        runtime
            .sessions
            .set_state(&session.id, ownmesh_session::SessionState::Starting)
            .unwrap();
        runtime
            .sessions
            .set_sidecar_host_binding(
                &session.id,
                Some(SidecarHostBinding {
                    device_id: exact.device_id.clone(),
                    workspace_id: exact.workspace_id.clone(),
                    owner_principal: exact.owner_principal.clone(),
                    host_nonce: exact.host_nonce.clone(),
                    controller_epoch: exact.controller_epoch,
                    binding_expires_unix: lease.expires_unix,
                    host_expires_unix: DaemonRuntime::now() + 7_200,
                    child_pid: None,
                    child_process_birth: None,
                }),
            )
            .unwrap();
        runtime.persist_sessions().unwrap();
        runtime.supervisor = Some(supervisor);

        let result = runtime
            .handle_session_close(
                Some(json!({
                    "id": session.id,
                    "lease_id": lease.lease_id,
                    "controller_epoch": lease.epoch,
                    "workspace_id": "ws_default",
                })),
                &ClientIdentity::new("client:remote:tenant:owner", "test"),
            )
            .await
            .unwrap();
        assert_eq!(result.get("closed"), Some(&json!(true)));
        assert_eq!(result.get("reconciled"), Some(&json!(true)));

        let recovered = runtime.sessions.get(&session.id).unwrap();
        assert_eq!(recovered.state, ownmesh_session::SessionState::Closed);
        assert!(recovered.sidecar_host.is_none());
        assert!(runtime
            .supervisor
            .as_ref()
            .unwrap()
            .status(&exact)
            .await
            .is_err());
        let receipt = OwnerSpool::termination_receipt(&sidecar_root, &session.id)
            .unwrap()
            .expect("acknowledged recovery must leave a durable receipt");
        assert_eq!(
            receipt.transition_id,
            format!("open-recovery:{}:{}", session.id, lease.epoch)
        );

        server.request_shutdown();
        server_task.await.unwrap();
    }

    #[test]
    fn missing_supervisor_never_marks_a_live_pid_terminal() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let session = runtime
            .sessions
            .open(
                SessionKind::Pty,
                "live-child",
                "client:remote:tenant:owner",
                DaemonRuntime::now(),
                None,
            )
            .unwrap();
        let child_pid = std::process::id();
        let child_process_birth = ownmesh_ipc::process_birth_id(child_pid)
            .unwrap()
            .expect("current process has an OS birth identity");
        runtime
            .sessions
            .set_host_pid(&session.id, Some(child_pid))
            .unwrap();
        runtime
            .sessions
            .set_sidecar_host_binding(
                &session.id,
                Some(SidecarHostBinding {
                    device_id: "dev_a".into(),
                    workspace_id: "ws_default".into(),
                    owner_principal: "client:remote:tenant:owner".into(),
                    host_nonce: "host_nonce".into(),
                    controller_epoch: 1,
                    binding_expires_unix: DaemonRuntime::now() + 60,
                    host_expires_unix: DaemonRuntime::now() + 600,
                    child_pid: Some(child_pid),
                    child_process_birth: Some(child_process_birth),
                }),
            )
            .unwrap();

        let error = runtime
            .reconcile_terminal_after_supervisor_failure(&session.id, TransitionKind::Close)
            .unwrap_err();
        match error {
            IpcError::Remote { code, message } => {
                assert_eq!(code, app_error::CONFLICT);
                assert!(message.contains("child is still alive"), "{message}");
            }
            other => panic!("expected typed supervisor conflict, got {other}"),
        }
        assert_eq!(
            runtime.sessions.get(&session.id).unwrap().state,
            ownmesh_session::SessionState::Running
        );
    }

    #[tokio::test]
    async fn rejected_remote_open_never_leaves_running_session_metadata() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.set_policy_for_test(preset_document(AccessPreset::FullUserAccess));
        let remote = ClientIdentity::new("client:remote:tenant:owner", "test");

        let error = runtime
            .dispatch(
                session_methods::OPEN,
                Some(json!({"title":"requires-device"})),
                &remote,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                ..
            }
        ));
        assert!(runtime.sessions.list().is_empty());
    }
}

#[cfg(test)]
mod transfer_runtime_tests {
    use super::*;
    use ownmesh_transfer::ChunkSink;

    /// Owner-only tempdir: `tempfile` respects the process umask, and the
    /// daemon custody attestation rejects group/world-writable ancestors, so
    /// tests pin mode 0700 to stay umask-independent.
    fn tempdir() -> std::io::Result<tempfile::TempDir> {
        let dir = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(dir)
    }

    fn remote_client() -> ClientIdentity {
        ClientIdentity::new("client:remote:tenant_a:principal_a", "test")
    }

    fn bind_remote_transfer(runtime: &mut DaemonRuntime) {
        runtime.active_remote_operation_id = Some("op_transfer_test".into());
        runtime.active_remote_payload_hash = Some("a".repeat(64));
        runtime.active_remote_device_id = Some("dev_transfer_test".into());
        runtime.active_remote_expires_at_unix = Some(DaemonRuntime::now() + 300);
    }

    #[tokio::test]
    async fn transfer_source_plan_does_not_require_a_local_destination_root() {
        let temp = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(temp.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        std::fs::write(
            paths.state_dir.join("workspace").join("source.bin"),
            b"source bytes",
        )
        .unwrap();
        bind_remote_transfer(&mut runtime);

        let plan = runtime
            .handle_transfer_plan(
                Some(json!({
                    "source_path": "source.bin",
                    "destination_path": "received.bin",
                    // This workspace intentionally exists only on the remote
                    // destination daemon; source planning must not resolve it.
                    "destination_workspace_id": "ws_remote_destination",
                    "workspace_id": "ws_default"
                })),
                &remote_client(),
            )
            .await
            .unwrap();
        assert_eq!(plan["size_bytes"], json!(12));
        assert_eq!(
            plan["destination_workspace_id"],
            json!("ws_remote_destination")
        );
    }

    #[tokio::test]
    async fn transfer_preflight_splits_source_hash_from_destination_no_replace_custody() {
        let source_temp = tempdir().unwrap();
        let source_paths = OwnMeshPaths::for_base(source_temp.path());
        let mut source_runtime = DaemonRuntime::open(&source_paths).unwrap();
        std::fs::write(
            source_paths.state_dir.join("workspace").join("source.bin"),
            b"preflight source bytes",
        )
        .unwrap();
        bind_remote_transfer(&mut source_runtime);
        let source = source_runtime
            .handle_transfer_preflight_source(
                Some(json!({
                    "transfer_id": "xfer_preflight_split",
                    "source_path": "source.bin",
                    "destination_path": "received.bin",
                    "source_principal_id": "principal_a",
                    "destination_principal_id": "principal_a",
                    "source_device_id": "dev_transfer_test",
                    "destination_device_id": "dev_destination",
                    "source_workspace_id": "ws_default",
                    "destination_workspace_id": "ws_destination",
                    "epoch": 1,
                    "fence": 1,
                    "session_nonce": "nonce_split",
                    "expires_at": (DaemonRuntime::now() as u64 + 120) * 1000,
                    "coordinator_request_id": "coord_split",
                    "workspace_version": 1,
                    "workspace_id": "ws_default"
                })),
                &remote_client(),
            )
            .await
            .unwrap();
        assert_eq!(source["role"], json!("source"));
        assert!(source["size_bytes"].as_u64().unwrap() > 0);

        let destination_temp = tempdir().unwrap();
        let destination_paths = OwnMeshPaths::for_base(destination_temp.path());
        let mut destination_runtime = DaemonRuntime::open(&destination_paths).unwrap();
        let destination_root = destination_temp.path().join("destination");
        std::fs::create_dir_all(&destination_root).unwrap();
        destination_runtime
            .upsert_workspace(WorkspaceEntry {
                id: "ws_destination".into(),
                root: destination_root.clone(),
                label: None,
                generation: String::new(),
            })
            .unwrap();
        bind_remote_transfer(&mut destination_runtime);
        destination_runtime.active_remote_device_id = Some("dev_destination".into());
        let destination_request = json!({
            "transfer_id": "xfer_preflight_split",
            "source_path": "source.bin",
            "destination_path": "received.bin",
            "source_principal_id": "principal_a",
            "destination_principal_id": "principal_a",
            "source_device_id": "dev_transfer_test",
            "destination_device_id": "dev_destination",
            "source_workspace_id": "ws_default",
            "destination_workspace_id": "ws_destination",
            "workspace_id": "ws_destination",
            "plan_sha256": source["plan_sha256"],
            "epoch": 1,
            "fence": 1,
            "session_nonce": "nonce_split",
            "expires_at": (DaemonRuntime::now() as u64 + 120) * 1000,
            "coordinator_request_id": "coord_split",
            "workspace_version": 1,
        });
        let destination = destination_runtime
            .handle_transfer_preflight_destination(
                Some(destination_request.clone()),
                &remote_client(),
            )
            .await
            .unwrap();
        assert_eq!(destination["available"], json!(true));
        std::fs::write(destination_root.join("received.bin"), b"untouched").unwrap();
        assert!(destination_runtime
            .handle_transfer_preflight_destination(Some(destination_request), &remote_client())
            .await
            .is_err());
        let invalid_hash = json!({
            "transfer_id": "xfer_bad_hash",
            "source_path": "source.bin",
            "destination_path": "another.bin",
            "source_principal_id": "principal_a",
            "destination_principal_id": "principal_a",
            "source_device_id": "dev_transfer_test",
            "destination_device_id": "dev_destination",
            "source_workspace_id": "ws_default",
            "destination_workspace_id": "ws_destination",
            "workspace_id": "ws_destination",
            "plan_sha256": "g".repeat(64),
            "epoch": 1,
            "fence": 1,
            "session_nonce": "nonce_split",
            "expires_at": (DaemonRuntime::now() as u64 + 120) * 1000,
            "coordinator_request_id": "coord_split",
            "workspace_version": 1,
        });
        assert!(destination_runtime
            .handle_transfer_preflight_destination(Some(invalid_hash), &remote_client())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn cross_device_start_binds_each_runtime_to_its_own_transfer_role() {
        let signed_expires_at_unix = DaemonRuntime::now() + 300;
        let source_temp = tempdir().unwrap();
        let source_paths = OwnMeshPaths::for_base(source_temp.path());
        let mut source = DaemonRuntime::open(&source_paths).unwrap();
        let content = b"cross-device source custody";
        std::fs::write(
            source_paths.state_dir.join("workspace").join("source.bin"),
            content,
        )
        .unwrap();
        bind_remote_transfer(&mut source);
        source.active_remote_expires_at_unix = Some(signed_expires_at_unix);
        source.active_remote_device_id = Some("dev_source".into());

        let destination_temp = tempdir().unwrap();
        let destination_paths = OwnMeshPaths::for_base(destination_temp.path());
        let mut destination = DaemonRuntime::open(&destination_paths).unwrap();
        let destination_root = destination_temp.path().join("destination");
        destination
            .upsert_workspace(WorkspaceEntry {
                id: "ws_destination".into(),
                root: destination_root,
                label: None,
                generation: String::new(),
            })
            .unwrap();
        bind_remote_transfer(&mut destination);
        destination.active_remote_expires_at_unix = Some(signed_expires_at_unix);
        destination.active_remote_device_id = Some("dev_destination".into());

        let expires_at = u64::try_from(signed_expires_at_unix).unwrap();
        assert_eq!(
            destination.active_remote_expires_at_unix,
            Some(expires_at as i64)
        );
        let binding = TransferBinding {
            tenant_id: "tenant_a".into(),
            source_principal_id: "principal_a".into(),
            destination_principal_id: "principal_a".into(),
            source_device_id: "dev_source".into(),
            destination_device_id: "dev_destination".into(),
            source_workspace_id: "ws_default".into(),
            destination_workspace_id: "ws_destination".into(),
            source_relative_path: "source.bin".into(),
            destination_relative_path: "received.bin".into(),
        };
        let transfer_id = "xfer_cross_device";
        let plan = TransferPlan::from_verified(
            binding,
            TransferGrant {
                grant_id: transfer_id.into(),
                operation_id: transfer_id.into(),
                payload_sha256: "a".repeat(64),
                expires_at_unix: expires_at,
            },
            content.len() as u64,
            sha256_hex(content),
        )
        .unwrap();
        let start = |workspace_id: &str| {
            json!({
                "transfer_id": transfer_id,
                "role": if workspace_id == "ws_default" { "source" } else { "destination" },
                "ticket": "opaque.ticket",
                "plan_sha256": plan.plan_sha256(),
                "content_sha256": plan.sha256(),
                "size_bytes": plan.size_bytes(),
                "source_path": "source.bin",
                "destination_path": "received.bin",
                "source_device_id": "dev_source",
                "destination_device_id": "dev_destination",
                "source_workspace_id": "ws_default",
                "destination_workspace_id": "ws_destination",
                "source_workspace_version": 1,
                "destination_workspace_version": 1,
                "workspace_id": workspace_id,
                "workspace_version": 1,
                "epoch": 1,
                "fence": 1,
                "grant_id": transfer_id,
                "grant_operation_id": transfer_id,
                "grant_payload_sha256": "a".repeat(64),
                "grant_expires_at_unix": expires_at
            })
        };
        let client = remote_client();
        let source_started = source
            .handle_transfer_start(Some(start("ws_default")), &client)
            .await
            .unwrap();
        let destination_started = destination
            .handle_transfer_start(Some(start("ws_destination")), &client)
            .await
            .unwrap();
        assert_eq!(source_started["plan_id"], destination_started["plan_id"]);
        let plan_id = source_started["plan_id"].as_str().unwrap();
        source
            .handle_transfer_source_open(
                Some(
                    json!({"plan_id":plan_id,"sequence":0,"offset":0,"workspace_id":"ws_default"}),
                ),
                &client,
            )
            .await
            .unwrap();
        destination
            .handle_transfer_destination_prepare(
                Some(
                    json!({"plan_id":plan_id,"epoch":1,"fence":1,"next_sequence":0,"next_offset":0,"workspace_id":"ws_destination"}),
                ),
                &client,
            )
            .await
            .unwrap();

        let first = source
            .handle_transfer_source_chunk(
                Some(json!({ "plan_id": plan_id, "sequence": 0 })),
                &client,
            )
            .await
            .unwrap();
        assert_eq!(first["eof"], Value::Null);
        let eof = source
            .handle_transfer_source_chunk(
                Some(json!({ "plan_id": plan_id, "sequence": 1 })),
                &client,
            )
            .await
            .unwrap();
        assert_eq!(eof["eof"], json!(true));
        std::fs::write(
            source_paths.state_dir.join("workspace").join("source.bin"),
            b"mutated after final destination ACK",
        )
        .unwrap();
        source
            .handle_transfer_source_open(
                Some(json!({ "plan_id": plan_id, "sequence": 1, "offset": content.len(), "workspace_id": "ws_default" })),
                &client,
            )
            .await
            .expect("retained source snapshot must reopen after pathname mutation");
        assert_eq!(
            source
                .handle_transfer_source_chunk(
                    Some(json!({ "plan_id": plan_id, "sequence": 1 })),
                    &client,
                )
                .await
                .unwrap()["eof"],
            json!(true)
        );
        let cleanup = source
            .handle_transfer_cancel(
                Some(json!({ "plan_id": plan_id, "epoch": 1, "fence": 1 })),
                &client,
            )
            .await
            .expect("finish_ack cleanup removes retained source custody");
        assert_eq!(cleanup["replayed"], json!(false));
        drop(source);
        let mut source = DaemonRuntime::open(&source_paths).unwrap();
        bind_remote_transfer(&mut source);
        source.active_remote_device_id = Some("dev_source".into());
        let replayed = source
            .handle_transfer_cancel(
                Some(json!({ "plan_id": plan_id, "epoch": 1, "fence": 1 })),
                &client,
            )
            .await
            .expect("lost cleanup reply replays from the completed tombstone");
        assert_eq!(replayed["replayed"], json!(true));
        assert!(source
            .handle_transfer_source_open(
                Some(json!({ "plan_id": plan_id, "sequence": 1, "offset": content.len(), "workspace_id": "ws_default" })),
                &client,
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn source_start_rejects_mutation_before_admission() {
        let signed_expires_at_unix = DaemonRuntime::now() + 300;
        let source_temp = tempdir().unwrap();
        let source_paths = OwnMeshPaths::for_base(source_temp.path());
        let mut source = DaemonRuntime::open(&source_paths).unwrap();
        let content = b"immutable source bytes";
        let source_file = source_paths.state_dir.join("workspace").join("source.bin");
        std::fs::write(&source_file, content).unwrap();
        bind_remote_transfer(&mut source);
        source.active_remote_expires_at_unix = Some(signed_expires_at_unix);
        source.active_remote_device_id = Some("dev_source".into());
        let expires_at = u64::try_from(signed_expires_at_unix).unwrap();
        let binding = TransferBinding {
            tenant_id: "tenant_a".into(),
            source_principal_id: "principal_a".into(),
            destination_principal_id: "principal_a".into(),
            source_device_id: "dev_source".into(),
            destination_device_id: "dev_destination".into(),
            source_workspace_id: "ws_default".into(),
            destination_workspace_id: "ws_destination".into(),
            source_relative_path: "source.bin".into(),
            destination_relative_path: "received.bin".into(),
        };
        let transfer_id = "xfer_mutated_source";
        let plan = TransferPlan::from_verified(
            binding,
            TransferGrant {
                grant_id: transfer_id.into(),
                operation_id: transfer_id.into(),
                payload_sha256: "a".repeat(64),
                expires_at_unix: expires_at,
            },
            content.len() as u64,
            sha256_hex(content),
        )
        .unwrap();
        std::fs::write(&source_file, b"mutated source bytes!!!!").unwrap();
        let started = source
            .handle_transfer_start(
                Some(json!({
                    "transfer_id": transfer_id,
                    "role": "source",
                    "ticket": "opaque.ticket",
                    "plan_sha256": plan.plan_sha256(),
                    "content_sha256": plan.sha256(),
                    "size_bytes": plan.size_bytes(),
                    "source_path": "source.bin",
                    "destination_path": "received.bin",
                    "source_device_id": "dev_source",
                    "destination_device_id": "dev_destination",
                    "source_workspace_id": "ws_default",
                    "destination_workspace_id": "ws_destination",
                    "source_workspace_version": 1,
                    "destination_workspace_version": 1,
                    "workspace_id": "ws_default",
                    "workspace_version": 1,
                    "epoch": 1,
                    "fence": 1,
                    "grant_id": transfer_id,
                    "grant_operation_id": transfer_id,
                    "grant_payload_sha256": "a".repeat(64),
                    "grant_expires_at_unix": expires_at
                })),
                &remote_client(),
            )
            .await;
        assert!(started.is_err());
    }

    #[tokio::test]
    async fn source_reconnect_reuses_retained_snapshot_after_original_is_removed() {
        let temp = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(temp.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let mut content = vec![0_u8; MAX_CHUNK_BYTES * 2 + 37];
        for (index, byte) in content.iter_mut().enumerate() {
            *byte = u8::try_from(index % 251).unwrap();
        }
        let source_path = paths.state_dir.join("workspace").join("resume-source.bin");
        std::fs::write(&source_path, &content).unwrap();
        bind_remote_transfer(&mut runtime);
        let client = remote_client();
        let authority_operation = runtime.active_remote_operation_id.clone().unwrap();
        let authority_payload = runtime.active_remote_payload_hash.clone().unwrap();
        let authority_expiry = runtime.active_remote_expires_at_unix.unwrap();
        let plan = runtime
            .handle_transfer_plan(
                Some(json!({
                    "source_path": "resume-source.bin",
                    "destination_path": "remote-received.bin",
                    "destination_workspace_id": "ws_remote_destination",
                    "workspace_id": "ws_default"
                })),
                &client,
            )
            .await
            .unwrap();
        let plan_id = plan["plan_id"].as_str().unwrap().to_owned();
        runtime
            .handle_transfer_source_open(
                Some(json!({ "plan_id": plan_id, "sequence": 0, "offset": 0, "workspace_id": "ws_default" })),
                &client,
            )
            .await
            .unwrap();
        let first = runtime
            .handle_transfer_source_chunk(
                Some(json!({ "plan_id": plan_id, "sequence": 0 })),
                &client,
            )
            .await
            .unwrap();
        let first_frame = base64_decode_strict(first["frame_base64"].as_str().unwrap()).unwrap();
        assert_eq!(
            TransferChunk::decode(&first_frame).unwrap().bytes,
            content[..MAX_CHUNK_BYTES]
        );

        // A process restart plus original-path deletion must still reopen the
        // immutable owner-only snapshot at the durable Room cursor.
        drop(runtime);
        std::fs::rename(&source_path, source_path.with_extension("removed")).unwrap();
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.active_remote_operation_id = Some(authority_operation.clone());
        runtime.active_remote_payload_hash = Some(authority_payload.clone());
        runtime.active_remote_device_id = Some("dev_transfer_test".into());
        runtime.active_remote_expires_at_unix = Some(authority_expiry);
        runtime
            .handle_transfer_source_open(
                Some(json!({ "plan_id": plan_id, "sequence": 1, "offset": MAX_CHUNK_BYTES, "workspace_id": "ws_default" })),
                &client,
            )
            .await
            .expect("reconnect must not reopen the deleted workspace pathname");
        let second = runtime
            .handle_transfer_source_chunk(
                Some(json!({ "plan_id": plan_id, "sequence": 1 })),
                &client,
            )
            .await
            .unwrap();
        let second_frame = base64_decode_strict(second["frame_base64"].as_str().unwrap()).unwrap();
        assert_eq!(
            TransferChunk::decode(&second_frame).unwrap().bytes,
            content[MAX_CHUNK_BYTES..MAX_CHUNK_BYTES * 2]
        );
        let third = runtime
            .handle_transfer_source_chunk(
                Some(json!({ "plan_id": plan_id, "sequence": 2 })),
                &client,
            )
            .await
            .unwrap();
        let third_frame = base64_decode_strict(third["frame_base64"].as_str().unwrap()).unwrap();
        assert_eq!(
            TransferChunk::decode(&third_frame).unwrap().bytes,
            content[MAX_CHUNK_BYTES * 2..]
        );

        // A replacement is never an authority: a retained snapshot whose size
        // or hash no longer matches the immutable plan must not resume.
        drop(runtime);
        let snapshot = paths
            .state_dir
            .join("transfers")
            .join(format!(".{plan_id}.source"));
        std::fs::remove_file(&snapshot).unwrap();
        std::fs::write(&snapshot, b"substituted snapshot").unwrap();
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.active_remote_operation_id = Some(authority_operation);
        runtime.active_remote_payload_hash = Some(authority_payload);
        runtime.active_remote_device_id = Some("dev_transfer_test".into());
        runtime.active_remote_expires_at_unix = Some(authority_expiry);
        assert!(runtime
            .handle_transfer_source_open(
                Some(json!({ "plan_id": plan_id, "sequence": 2, "offset": MAX_CHUNK_BYTES * 2, "workspace_id": "ws_default" })),
                &client,
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn cleanup_of_an_expired_transfer_keeps_an_unrelated_live_sender() {
        let temp = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(temp.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        std::fs::write(
            paths.state_dir.join("workspace").join("live-source.bin"),
            b"live transfer bytes",
        )
        .unwrap();
        bind_remote_transfer(&mut runtime);
        let client = remote_client();
        let live = runtime
            .handle_transfer_plan(
                Some(json!({
                    "source_path": "live-source.bin",
                    "destination_path": "live-destination.bin",
                    "destination_workspace_id": "ws_remote_destination",
                    "workspace_id": "ws_default"
                })),
                &client,
            )
            .await
            .unwrap();
        let live_id = live["plan_id"].as_str().unwrap().to_owned();
        runtime
            .handle_transfer_source_open(
                Some(json!({ "plan_id": live_id, "workspace_id": "ws_default" })),
                &client,
            )
            .await
            .unwrap();

        let now = DaemonRuntime::now() as u64;
        let expired = TransferPlan::from_verified(
            TransferBinding {
                tenant_id: "tenant_a".into(),
                source_principal_id: "principal_a".into(),
                destination_principal_id: "principal_a".into(),
                source_device_id: "dev_transfer_test".into(),
                destination_device_id: "dev_transfer_test".into(),
                source_workspace_id: "ws_default".into(),
                destination_workspace_id: "ws_default".into(),
                source_relative_path: "expired-source.bin".into(),
                destination_relative_path: "expired-destination.bin".into(),
            },
            TransferGrant {
                grant_id: "expired-grant".into(),
                operation_id: "expired-operation".into(),
                payload_sha256: "a".repeat(64),
                expires_at_unix: now + 60,
            },
            1,
            sha256_hex(b"x"),
        )
        .unwrap();
        runtime.transfer_store.save_plan(&expired).unwrap();
        let lease = runtime
            .transfer_store
            .acquire(&expired, now, now + 1)
            .unwrap();
        let journal = runtime
            .transfer_store
            .claim(&lease, &expired, "expired-owner", 1, 1, now, now + 1)
            .unwrap();
        let mut sink = PartFileSink::create(&runtime.transfer_store, &expired, 1, 0).unwrap();
        sink.write_chunk(0, b"x").unwrap();
        drop(sink);
        runtime.transfer_store.save(&lease, &journal).unwrap();

        let cleanup_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let removed = loop {
            let removed = runtime.cleanup_expired_transfers().unwrap();
            if removed != 0 {
                break removed;
            }
            assert!(
                std::time::Instant::now() < cleanup_deadline,
                "expired transfer was not cleaned within the bounded wait"
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        };
        assert_eq!(removed, 1);
        assert!(
            runtime
                .handle_transfer_source_chunk(
                    Some(json!({ "plan_id": live_id, "sequence": 0 })),
                    &client,
                )
                .await
                .is_ok(),
            "unrelated live sender must survive expired-transfer cleanup"
        );
    }

    #[tokio::test]
    async fn destination_receiver_rehashes_once_per_process_and_ignores_stale_eviction() {
        let temp = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(temp.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.set_policy_for_test(preset_document(AccessPreset::FullAccess));
        let destination_root = temp.path().join("destination");
        runtime
            .upsert_workspace(WorkspaceEntry {
                id: "ws_destination".into(),
                root: destination_root.clone(),
                label: None,
                generation: String::new(),
            })
            .unwrap();
        let mut bytes = vec![0_u8; MAX_CHUNK_BYTES * 5 + 17];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        std::fs::write(
            paths.state_dir.join("workspace").join("cached-source.bin"),
            &bytes,
        )
        .unwrap();
        bind_remote_transfer(&mut runtime);
        let client = remote_client();
        let plan = runtime
            .handle_transfer_plan(
                Some(json!({
                    "source_path": "cached-source.bin",
                    "destination_path": "cached-output.bin",
                    "destination_workspace_id": "ws_destination",
                    "workspace_id": "ws_default"
                })),
                &client,
            )
            .await
            .unwrap();
        let plan_id = plan["plan_id"].as_str().unwrap().to_owned();
        runtime
            .handle_transfer_destination_prepare(
                Some(json!({ "plan_id": plan_id, "epoch": 1, "fence": 1, "next_sequence": 0, "next_offset": 0, "workspace_id": "ws_destination" })),
                &client,
            )
            .await
            .unwrap();
        assert_eq!(runtime.transfer_receiver_rebuilds.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.transfer_receivers.len(), 1);
        assert_eq!(runtime.cleanup_expired_transfers().unwrap(), 0);
        assert_eq!(runtime.transfer_receivers.len(), 1);
        assert_eq!(
            runtime.transfer_receiver_rebuilds.load(Ordering::SeqCst),
            1,
            "periodic cleanup must retain an exact live receiver"
        );
        assert!(runtime
            .handle_transfer_cancel(
                Some(json!({ "plan_id": plan_id, "epoch": 2, "fence": 2 })),
                &client,
            )
            .await
            .is_err());
        assert!(runtime
            .handle_transfer_finalize(
                Some(json!({ "plan_id": plan_id, "epoch": 1, "fence": 1, "workspace_id": "ws_destination" })),
                &client,
            )
            .await
            .is_err());
        assert_eq!(runtime.transfer_receivers.len(), 1);
        assert_eq!(
            runtime.transfer_receiver_rebuilds.load(Ordering::SeqCst),
            1,
            "stale cancel and premature finalize must not evict"
        );
        runtime
            .handle_transfer_source_open(
                Some(json!({ "plan_id": plan_id, "workspace_id": "ws_default" })),
                &client,
            )
            .await
            .unwrap();
        for sequence in 0..2_u64 {
            let chunk = runtime
                .handle_transfer_source_chunk(
                    Some(json!({ "plan_id": plan_id, "sequence": sequence })),
                    &client,
                )
                .await
                .unwrap();
            runtime
                .handle_transfer_destination_chunk(
                    Some(json!({ "plan_id": plan_id, "epoch": 1, "fence": 1, "workspace_id": "ws_destination", "frame_base64": chunk["frame_base64"] })),
                    &client,
                )
                .await
                .unwrap();
        }
        assert_eq!(
            runtime.transfer_receiver_rebuilds.load(Ordering::SeqCst),
            1,
            "multiple chunks in one process must reuse one rolling hash"
        );
        drop(runtime);

        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.set_policy_for_test(preset_document(AccessPreset::FullAccess));
        bind_remote_transfer(&mut runtime);
        runtime
            .handle_transfer_destination_prepare(
                Some(json!({ "plan_id": plan_id, "epoch": 2, "fence": 2, "next_sequence": 2, "next_offset": MAX_CHUNK_BYTES * 2, "workspace_id": "ws_destination" })),
                &client,
            )
            .await
            .unwrap();
        assert_eq!(
            runtime.transfer_receiver_rebuilds.load(Ordering::SeqCst),
            1,
            "restart performs exactly one bounded prefix rebuild"
        );
        runtime
            .handle_transfer_source_open(
                Some(json!({ "plan_id": plan_id, "sequence": 2, "offset": MAX_CHUNK_BYTES * 2, "workspace_id": "ws_default" })),
                &client,
            )
            .await
            .unwrap();
        for sequence in 2..6_u64 {
            let chunk = runtime
                .handle_transfer_source_chunk(
                    Some(json!({ "plan_id": plan_id, "sequence": sequence })),
                    &client,
                )
                .await
                .unwrap();
            runtime
                .handle_transfer_destination_chunk(
                    Some(json!({ "plan_id": plan_id, "epoch": 2, "fence": 2, "workspace_id": "ws_destination", "frame_base64": chunk["frame_base64"] })),
                    &client,
                )
                .await
                .unwrap();
        }
        assert_eq!(runtime.transfer_receiver_rebuilds.load(Ordering::SeqCst), 1);
        assert!(runtime.transfer_receivers.is_empty());
        runtime
            .handle_transfer_finalize(
                Some(json!({ "plan_id": plan_id, "epoch": 2, "fence": 2, "workspace_id": "ws_destination" })),
                &client,
            )
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(destination_root.join("cached-output.bin")).unwrap(),
            bytes
        );
    }

    #[tokio::test]
    async fn destination_save_failure_evicts_cache_and_fresh_fence_can_cancel() {
        assert!(MAX_CACHED_DESTINATION_TRANSFERS <= JournalLimits::default().max_plans);
        let temp = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(temp.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime
            .upsert_workspace(WorkspaceEntry {
                id: "ws_destination".into(),
                root: temp.path().join("destination"),
                label: None,
                generation: String::new(),
            })
            .unwrap();
        std::fs::write(
            paths.state_dir.join("workspace").join("fault-source.bin"),
            vec![7_u8; MAX_CHUNK_BYTES + 1],
        )
        .unwrap();
        bind_remote_transfer(&mut runtime);
        let client = remote_client();
        let plan = runtime
            .handle_transfer_plan(
                Some(json!({
                    "source_path": "fault-source.bin",
                    "destination_path": "fault-output.bin",
                    "destination_workspace_id": "ws_destination",
                    "workspace_id": "ws_default"
                })),
                &client,
            )
            .await
            .unwrap();
        let plan_id = plan["plan_id"].as_str().unwrap().to_owned();
        runtime
            .handle_transfer_destination_prepare(
                Some(json!({ "plan_id": plan_id, "epoch": 1, "fence": 1, "next_sequence": 0, "next_offset": 0, "workspace_id": "ws_destination" })),
                &client,
            )
            .await
            .unwrap();
        runtime
            .handle_transfer_source_open(
                Some(json!({ "plan_id": plan_id, "workspace_id": "ws_default" })),
                &client,
            )
            .await
            .unwrap();
        let chunk = runtime
            .handle_transfer_source_chunk(
                Some(json!({ "plan_id": plan_id, "sequence": 0 })),
                &client,
            )
            .await
            .unwrap();
        runtime.fail_transfer_journal_persist_on_nth_call_for_test(1);
        assert!(runtime
            .handle_transfer_destination_chunk(
                Some(json!({ "plan_id": plan_id, "epoch": 1, "fence": 1, "workspace_id": "ws_destination", "frame_base64": chunk["frame_base64"] })),
                &client,
            )
            .await
            .is_err());
        assert!(runtime.transfer_receivers.is_empty());
        assert!(runtime
            .handle_transfer_destination_chunk(
                Some(json!({ "plan_id": plan_id, "epoch": 1, "fence": 1, "workspace_id": "ws_destination", "frame_base64": chunk["frame_base64"] })),
                &client,
            )
            .await
            .is_err());
        runtime
            .handle_transfer_destination_prepare(
                Some(json!({ "plan_id": plan_id, "epoch": 2, "fence": 2, "next_sequence": 0, "next_offset": 0, "workspace_id": "ws_destination" })),
                &client,
            )
            .await
            .unwrap();
        assert_eq!(runtime.transfer_receiver_rebuilds.load(Ordering::SeqCst), 2);
        runtime
            .handle_transfer_cancel(
                Some(json!({ "plan_id": plan_id, "epoch": 2, "fence": 2 })),
                &client,
            )
            .await
            .unwrap();
        assert!(runtime.transfer_receivers.is_empty());
        assert_eq!(
            runtime.transfer_receiver_rebuilds.load(Ordering::SeqCst),
            2,
            "exact cancel uses the retained receiver without another rehash"
        );
        assert!(!paths
            .state_dir
            .join("transfers")
            .join(format!(".{plan_id}.2.part"))
            .exists());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn normal_transfer_finalize_unlinks_its_published_generation_part() {
        let temp = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(temp.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime
            .upsert_workspace(WorkspaceEntry {
                id: "ws_destination".into(),
                root: temp.path().join("destination"),
                label: Some("destination".into()),
                generation: String::new(),
            })
            .unwrap();
        let content = b"normal-published-transfer";
        std::fs::write(
            paths.state_dir.join("workspace").join("normal.bin"),
            content,
        )
        .unwrap();
        bind_remote_transfer(&mut runtime);
        let client = remote_client();
        let plan = runtime
            .handle_transfer_plan(
                Some(json!({
                    "source_path": "normal.bin",
                    "destination_path": "normal-output.bin",
                    "destination_workspace_id": "ws_destination",
                    "workspace_id": "ws_default"
                })),
                &client,
            )
            .await
            .unwrap();
        let plan_id = plan["plan_id"].as_str().unwrap().to_owned();
        runtime
            .handle_transfer_destination_prepare(
                Some(json!({ "plan_id": plan_id, "epoch": 1, "fence": 1, "next_sequence": 0, "next_offset": 0, "workspace_id": "ws_destination" })),
                &client,
            )
            .await
            .unwrap();
        runtime
            .handle_transfer_source_open(
                Some(json!({ "plan_id": plan_id, "workspace_id": "ws_default" })),
                &client,
            )
            .await
            .unwrap();
        let chunk = runtime
            .handle_transfer_source_chunk(
                Some(json!({ "plan_id": plan_id, "sequence": 0 })),
                &client,
            )
            .await
            .unwrap();
        runtime
            .handle_transfer_destination_chunk(
                Some(json!({ "plan_id": plan_id, "epoch": 1, "fence": 1, "workspace_id": "ws_destination", "frame_base64": chunk["frame_base64"] })),
                &client,
            )
            .await
            .unwrap();
        let finalized = runtime
            .handle_transfer_finalize(
                Some(json!({ "plan_id": plan_id, "epoch": 1, "fence": 1, "workspace_id": "ws_destination" })),
                &client,
            )
            .await
            .unwrap();
        assert_eq!(finalized["replayed"], json!(false));
        assert!(!paths
            .state_dir
            .join("transfers")
            .join(format!(".{plan_id}.1.part"))
            .exists());
        assert_eq!(
            std::fs::read(temp.path().join("destination").join("normal-output.bin")).unwrap(),
            content
        );
        let stored_plan = runtime
            .transfer_store
            .load_plan(&plan_id, DaemonRuntime::now() as u64)
            .unwrap()
            .unwrap();
        assert!(runtime
            .transfer_store
            .load(&stored_plan)
            .unwrap()
            .unwrap()
            .published());
        let error = runtime
            .handle_transfer_artifact_get(
                Some(json!({ "plan_id": plan_id, "workspace_id": "ws_destination", "offset": content.len() + 1 })),
                &client,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                ref message,
            } if message == "transfer artifact offset exceeds its immutable total size"
        ));
    }

    #[test]
    fn transfer_platform_unsupported_is_not_an_internal_error() {
        assert!(matches!(
            DaemonRuntime::transfer_error(TransferError::PlatformUnsupported),
            IpcError::Remote {
                code: app_error::PLATFORM_UNSUPPORTED,
                ref message,
            } if message == "restricted transfer publication is unsupported on this platform"
        ));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn transfer_streams_binary_resumes_after_restart_and_pages_artifact() {
        let temp = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(temp.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let destination_root = temp.path().join("destination");
        runtime
            .upsert_workspace(WorkspaceEntry {
                id: "ws_destination".into(),
                root: destination_root,
                label: Some("destination".into()),
                generation: String::new(),
            })
            .unwrap();
        let source = paths.state_dir.join("workspace").join("source.bin");
        let mut bytes = vec![0_u8; MAX_CHUNK_BYTES * 3 + 17];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        std::fs::write(&source, &bytes).unwrap();
        bind_remote_transfer(&mut runtime);
        let client = remote_client();
        let plan = runtime
            .handle_transfer_plan(
                Some(json!({
                    "source_path": "source.bin",
                    "destination_path": "received.bin",
                    "destination_workspace_id": "ws_destination",
                    "workspace_id": "ws_default"
                })),
                &client,
            )
            .await
            .unwrap();
        let plan_id = plan["plan_id"].as_str().unwrap().to_owned();
        runtime
            .handle_transfer_destination_prepare(
                Some(json!({ "plan_id": plan_id, "epoch": 1, "fence": 1, "next_sequence": 0, "next_offset": 0, "workspace_id": "ws_destination" })),
                &client,
            )
            .await
            .unwrap();
        runtime
            .handle_transfer_source_open(
                Some(json!({ "plan_id": plan_id, "workspace_id": "ws_default" })),
                &client,
            )
            .await
            .unwrap();
        let first = runtime
            .handle_transfer_source_chunk(
                Some(json!({ "plan_id": plan_id, "sequence": 0 })),
                &client,
            )
            .await
            .unwrap();
        let frame = first["frame_base64"].as_str().unwrap().to_owned();
        runtime
            .handle_transfer_destination_chunk(
                Some(json!({ "plan_id": plan_id, "epoch": 1, "fence": 1, "workspace_id": "ws_destination", "frame_base64": frame })),
                &client,
            )
            .await
            .unwrap();
        // A retry must not append the first chunk twice.
        assert!(runtime
            .handle_transfer_destination_chunk(
                Some(json!({ "plan_id": plan_id, "epoch": 1, "fence": 1, "workspace_id": "ws_destination", "frame_base64": first["frame_base64"] })),
                &client,
            )
            .await
            .is_err());
        // Deterministic crash window: chunk 1 has reached the destination
        // journal, but its relay ACK was not durably committed. The Room will
        // therefore resume at the earlier chunk-0 cursor after restart.
        let locally_saved_without_room_ack = runtime
            .handle_transfer_source_chunk(
                Some(json!({ "plan_id": plan_id, "sequence": 1 })),
                &client,
            )
            .await
            .unwrap();
        runtime
            .handle_transfer_destination_chunk(
                Some(json!({ "plan_id": plan_id, "epoch": 1, "fence": 1, "workspace_id": "ws_destination", "frame_base64": locally_saved_without_room_ack["frame_base64"] })),
                &client,
            )
            .await
            .unwrap();
        drop(runtime);

        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        bind_remote_transfer(&mut runtime);
        runtime
            .handle_transfer_destination_prepare(
                Some(json!({ "plan_id": plan_id, "epoch": 2, "fence": 2, "next_sequence": 1, "next_offset": MAX_CHUNK_BYTES, "workspace_id": "ws_destination" })),
                &client,
            )
            .await
            .unwrap();
        runtime
            .handle_transfer_source_open(
                Some(json!({ "plan_id": plan_id, "sequence": 1, "offset": MAX_CHUNK_BYTES, "workspace_id": "ws_default" })),
                &client,
            )
            .await
            .unwrap();
        for sequence in 1..4_u64 {
            let chunk = runtime
                .handle_transfer_source_chunk(
                    Some(json!({ "plan_id": plan_id, "sequence": sequence })),
                    &client,
                )
                .await
                .unwrap();
            runtime
                .handle_transfer_destination_chunk(
                    Some(json!({ "plan_id": plan_id, "epoch": 2, "fence": 2, "workspace_id": "ws_destination", "frame_base64": chunk["frame_base64"] })),
                    &client,
                )
                .await
                .unwrap();
        }
        // Simulate a process crash exactly after the no-replace publish and
        // before the runtime can durably record/send its terminal reply.
        let stored_plan = runtime
            .transfer_store
            .load_plan(&plan_id, DaemonRuntime::now() as u64)
            .unwrap()
            .unwrap();
        runtime
            .transfer_store
            .publish_completed_no_replace(
                &stored_plan,
                &runtime.workspace_for(Some("ws_destination")).unwrap(),
            )
            .unwrap();
        drop(runtime);
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        bind_remote_transfer(&mut runtime);
        let recovered = runtime
            .handle_transfer_finalize(
                Some(json!({ "plan_id": plan_id, "epoch": 2, "fence": 2, "workspace_id": "ws_destination" })),
                &client,
            )
            .await
            .unwrap();
        assert_eq!(recovered["replayed"], json!(false));
        for epoch in [1_u64, 2] {
            assert!(
                !paths
                    .state_dir
                    .join("transfers")
                    .join(format!(".{plan_id}.{epoch}.part"))
                    .exists(),
                "published generation parts must be removed after recovery"
            );
        }
        let published_plan = runtime
            .transfer_store
            .load_plan(&plan_id, DaemonRuntime::now() as u64)
            .unwrap()
            .unwrap();
        assert!(runtime
            .transfer_store
            .load(&published_plan)
            .unwrap()
            .unwrap()
            .published());
        let mut reconstructed = Vec::new();
        let mut offset = 0_u64;
        loop {
            let page = runtime
                .handle_transfer_artifact_get(
                    Some(json!({ "plan_id": plan_id, "workspace_id": "ws_destination", "offset": offset, "max_bytes": MAX_CHUNK_BYTES })),
                    &client,
                )
                .await
                .unwrap();
            reconstructed
                .extend(base64_decode_strict(page["content_base64"].as_str().unwrap()).unwrap());
            if !page["truncated"].as_bool().unwrap() {
                break;
            }
            offset = page["next_offset"].as_u64().unwrap();
        }
        assert_eq!(reconstructed, bytes);
        // A lost terminal reply is idempotent: the durable publication receipt
        // verifies the pinned artifact instead of treating its own no-replace
        // destination as a foreign conflict. A later substitution is never
        // accepted as that receipt.
        let replay = runtime
            .handle_transfer_finalize(
                Some(json!({ "plan_id": plan_id, "epoch": 2, "fence": 2, "workspace_id": "ws_destination" })),
                &client,
            )
            .await
            .unwrap();
        assert_eq!(replay["replayed"], json!(true));
        for epoch in [1_u64, 2] {
            assert!(!paths
                .state_dir
                .join("transfers")
                .join(format!(".{plan_id}.{epoch}.part"))
                .exists());
        }
        assert_eq!(
            std::fs::read(temp.path().join("destination").join("received.bin")).unwrap(),
            bytes
        );
        std::fs::write(
            temp.path().join("destination").join("received.bin"),
            b"substituted",
        )
        .unwrap();
        assert!(runtime
            .handle_transfer_finalize(
                Some(json!({ "plan_id": plan_id, "epoch": 2, "fence": 2, "workspace_id": "ws_destination" })),
                &client,
            )
            .await
            .is_err());
    }
}

fn base64_standard(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < bytes.len() {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < bytes.len() {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

/// Decode only canonical RFC 4648 base64.  The caller checks its encoded-size
/// ceiling before this routine allocates, so malformed transport input cannot
/// become an oversized binary frame.
fn base64_decode_strict(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(4) {
        return None;
    }
    let padding = value
        .as_bytes()
        .iter()
        .rev()
        .take_while(|&&b| b == b'=')
        .count();
    if padding > 2 || value[..value.len() - padding].bytes().any(|b| b == b'=') {
        return None;
    }
    let mut out = Vec::with_capacity(value.len() / 4 * 3 - padding);
    let decode = |b: u8| match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    for (group, raw) in value.as_bytes().chunks_exact(4).enumerate() {
        let last = group + 1 == value.len() / 4;
        let a = decode(raw[0])?;
        let b = decode(raw[1])?;
        let c = if raw[2] == b'=' { 0 } else { decode(raw[2])? };
        let d = if raw[3] == b'=' { 0 } else { decode(raw[3])? };
        if !last && raw[2] == b'=' {
            return None;
        }
        if !last && raw[3] == b'=' {
            return None;
        }
        if raw[2] == b'=' && raw[3] != b'=' {
            return None;
        }
        if raw[2] == b'=' && (b & 0x0f) != 0 {
            return None;
        }
        if raw[3] == b'=' && raw[2] != b'=' && (c & 0x03) != 0 {
            return None;
        }
        out.push((a << 2) | (b >> 4));
        if raw[2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if raw[3] != b'=' {
            out.push((c << 6) | d);
        }
    }
    Some(out)
}

fn policy_from_file(file: &PolicyFile) -> PolicyDocument {
    let preset = file
        .preset
        .as_deref()
        .and_then(parse_preset)
        .unwrap_or(AccessPreset::Recommended);
    let mut policy = preset_document(preset);
    policy.rules.extend(file.rules.iter().cloned());
    policy
}

/// Hard ceilings for durable op-journal state (count + file bytes).
const MAX_OP_JOURNAL_ENTRIES: usize = 4_096;
const MAX_OP_JOURNAL_FILE_BYTES: usize = 4 * 1024 * 1024;
/// Per-entry durable value budget used by tests to build over-budget fixtures.
#[cfg(test)]
const MAX_OP_JOURNAL_VALUE_BYTES: usize = 64 * 1024;

/// Completed op-journal receipts are retained for this long before they may
/// be evicted at capacity, aligned with the control-plane idempotency window
/// (`MCP_OPS_TOMBSTONE_TTL_MS` = 30 days). In-progress/uncertain markers are
/// never evicted regardless of age.
const OP_JOURNAL_COMPLETED_TTL_SECS: i64 = 30 * 24 * 60 * 60;
/// Marker field stamped on completed op-journal entries so the lifecycle can
/// distinguish them from in-progress/uncertain markers.
const OP_JOURNAL_COMPLETED_UNIX_FIELD: &str = "__ownmesh_completed_unix";
/// Bounded health state for transition-journal recovery (P0-A): expired
/// records retained fail-closed (session still present and non-terminal).
#[derive(Debug, Clone, Default)]
struct TransitionRecoveryHealth {
    /// Unique transition ids retained fail-closed, capped for the health
    /// surface.
    retained_expired: Vec<String>,
    /// Total unique retained-expired records (may exceed the bounded list).
    retained_expired_total: usize,
}

/// Cap for the bounded health list of retained-expired transition records.
const TRANSITION_HEALTH_RETAINED_CAP: usize = 16;

/// Hard ceilings for durable grants / approvals / revoked-principal state.
/// Stat-before-read + entry budgets keep startup fail-closed under oversized
/// or corrupt local state (no unbounded `read_to_string`).
const MAX_GRANTS_FILE_BYTES: usize = 1024 * 1024;
const MAX_GRANTS_ENTRIES: usize = 4_096;
const MAX_APPROVALS_FILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_APPROVALS_ENTRIES: usize = 4_096;
const MAX_APPROVAL_VALUE_BYTES: usize = 64 * 1024;
const MAX_REVOKED_FILE_BYTES: usize = 1024 * 1024;
const MAX_REVOKED_ENTRIES: usize = 16_384;

fn load_or_init_workspaces(
    path: &Path,
    default_root: &Path,
) -> Result<Vec<WorkspaceEntry>, String> {
    const MAX_BYTES: u64 = 256 * 1024;
    const MAX_ENTRIES: usize = 64;
    let default_entry = WorkspaceEntry {
        id: "ws_default".into(),
        root: default_root.to_path_buf(),
        label: Some("Default workspace".into()),
        generation: new_workspace_generation(),
    };
    if !path.exists() {
        let file = WorkspaceRegistryFile {
            schema_version: 1,
            workspaces: vec![default_entry.clone()],
        };
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(path, bytes).map_err(|e| e.to_string())?;
        return Ok(vec![default_entry]);
    }
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if meta.len() > MAX_BYTES {
        return Err(format!(
            "workspaces.json exceeds {MAX_BYTES} byte budget ({})",
            meta.len()
        ));
    }
    let raw = std::fs::read(path).map_err(|e| e.to_string())?;
    let file: WorkspaceRegistryFile =
        serde_json::from_slice(&raw).map_err(|e| format!("workspaces.json parse: {e}"))?;
    if file.schema_version != 1 {
        return Err(format!(
            "unsupported workspaces.json schema_version {}",
            file.schema_version
        ));
    }
    if file.workspaces.len() > MAX_ENTRIES {
        return Err(format!(
            "workspaces.json has {} entries (max {MAX_ENTRIES})",
            file.workspaces.len()
        ));
    }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut upgraded = false;
    for mut entry in file.workspaces {
        entry.id = entry.id.trim().to_string();
        if entry.id.is_empty()
            || entry.id.len() > 128
            || !(entry.id.starts_with("ws_") || entry.id == "default")
            || !entry
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!("invalid workspace id in registry: {:?}", entry.id));
        }
        if !entry.root.is_absolute() {
            return Err(format!(
                "workspace {} root must be absolute: {}",
                entry.id,
                entry.root.display()
            ));
        }
        if !seen.insert(entry.id.clone()) {
            return Err(format!("duplicate workspace id: {}", entry.id));
        }
        if entry.generation.is_empty() {
            entry.generation = new_workspace_generation();
            upgraded = true;
        } else if !valid_workspace_generation(&entry.generation) {
            return Err(format!(
                "invalid workspace generation in registry: {}",
                entry.id
            ));
        }
        out.push(entry);
    }
    if !out
        .iter()
        .any(|w| w.id == "ws_default" || w.id == "default")
    {
        out.insert(0, default_entry);
        upgraded = true;
    }
    // Normalize legacy bare "default" id to the domain-shaped ws_default.
    for entry in &mut out {
        if entry.id == "default" {
            entry.id = "ws_default".into();
            upgraded = true;
        }
    }
    if upgraded {
        let upgraded_file = WorkspaceRegistryFile {
            schema_version: 1,
            workspaces: out.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&upgraded_file).map_err(|e| e.to_string())?;
        if bytes.len() > MAX_BYTES as usize {
            return Err(format!(
                "upgraded workspaces.json exceeds {MAX_BYTES} byte budget ({})",
                bytes.len()
            ));
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// Path of the stale backup (`<primary>.bak`) an older writer or a crash
/// between the backup copy and cleanup can leave behind.
fn stale_op_journal_backup_path(path: &Path) -> PathBuf {
    let mut bak = path.as_os_str().to_os_string();
    bak.push(".bak");
    PathBuf::from(bak)
}

/// Read a bounded journal file (primary or recovery backup) into parsed,
/// bounded, compacted entries. `label` names the source in error messages.
fn read_and_bound_op_journal(file: &Path, label: &str) -> Result<HashMap<String, Value>, String> {
    // P0-B: a legacy (pre-1.2.13) journal may exceed the durable budget
    // because completed entries retained large stdout/file bodies. Read it
    // (bounded) so compaction can shrink it; only reject when the compacted
    // result still exceeds the budget.
    const MAX_LEGACY_READ_BYTES: u64 = MAX_OP_JOURNAL_FILE_BYTES as u64 * 4;
    let meta = std::fs::metadata(file)
        .map_err(|e| format!("failed to stat {label} {}: {e}", file.display()))?;
    if meta.len() > MAX_LEGACY_READ_BYTES {
        return Err(format!(
            "{label} {} exceeds {MAX_LEGACY_READ_BYTES} read budget ({})",
            file.display(),
            meta.len()
        ));
    }
    let raw = std::fs::read(file)
        .map_err(|e| format!("failed to read {label} {}: {e}", file.display()))?;
    let parsed: HashMap<String, Value> = serde_json::from_slice(&raw)
        .map_err(|e| format!("corrupt {label} {}: {e}", file.display()))?;
    bound_op_journal(parsed)
}

fn load_op_journal(path: &Path) -> Result<HashMap<String, Value>, String> {
    let bak = stale_op_journal_backup_path(path);
    if !path.exists() {
        // Primary missing but a backup survives (e.g. a crash in an older
        // writer between its backup copy and the replace, or an external
        // removal of the primary): the backup is the last-known durable
        // journal and its exact-once receipts must not be silently dropped by
        // starting empty — a retried operation would re-execute (P0-B review).
        // Recover from it with the same bounded read + fail-closed compaction
        // as the primary, persist the compacted form as the new primary, and
        // remove the backup so the state is not double-counted on the next
        // load. A corrupt/over-budget backup starts the daemon in degraded
        // read-only mode with an actionable repair hint instead of converting
        // ambiguity into a healthy empty journal.
        if bak.exists() {
            let journal = read_and_bound_op_journal(&bak, "op journal backup")?;
            write_op_journal(path, &journal).map_err(|e| {
                format!(
                    "failed to persist recovered op journal {}: {e}",
                    path.display()
                )
            })?;
            // The promoted primary is durable, so a stale backup that cannot
            // be removed is no longer the only copy — but it may still hold
            // the pre-compaction large-body journal. Fail startup instead of
            // leaving that sensitive copy behind while claiming it was
            // removed (P0-B review).
            remove_stale_op_journal_backup_fallible(path).map_err(|e| {
                format!(
                    "failed to remove recovered op journal backup {} after promoting the primary: \
{e}; remove or repair the backup (it may hold a legacy large-body journal) and restart",
                    stale_op_journal_backup_path(path).display()
                )
            })?;
            return Ok(journal);
        }
        return Ok(HashMap::new());
    }
    let journal = read_and_bound_op_journal(path, "operation journal")?;
    // P0-B review: remove a stale backup *before* the compacted write so a
    // crash between the write and the cleanup cannot leave a legacy
    // large-body copy on disk while the daemon is stopped. The primary is
    // authoritative (it was just read), so the stale duplicate can be removed
    // first; `write_op_journal` uses the no-backup atomic writer, so no new
    // `.bak` is created. (The recovery path above — primary missing, backup
    // is the only durable copy — must keep the backup until the recovered
    // primary is durable, so its removal stays after the write.)
    //
    // P0-B review: the stale backup may hold the pre-compaction legacy
    // journal with large stdout/file bodies. The compacted primary is about
    // to be written, but running with the sensitive copy still on disk while
    // claiming it was removed would be dishonest, and a later persist might
    // never retry the cleanup. Fail startup with an actionable message
    // instead (the same fail-closed contract as a compaction that cannot be
    // persisted).
    remove_stale_op_journal_backup_fallible(path).map_err(|e| {
        format!(
            "failed to remove stale op journal backup {} before writing the compacted primary: \
{e}; remove or repair the backup (it may hold a legacy large-body journal) and restart",
            stale_op_journal_backup_path(path).display()
        )
    })?;
    // Persist the compacted result so legacy large bodies are not retained
    // indefinitely on disk (P0-B). Fail-closed: if the compaction cannot be
    // made durable, the load fails instead of returning a compacted in-memory
    // view while the large bodies remain on disk — diagnostics would
    // otherwise report the compacted state while the durable file is still
    // over budget.
    write_op_journal(path, &journal).map_err(|e| {
        format!(
            "failed to persist compacted operation journal {}: {e}; the journal remains over \
budget on disk — free space or repair the journal before starting",
            path.display()
        )
    })?;
    Ok(journal)
}

fn bound_op_journal(journal: HashMap<String, Value>) -> Result<HashMap<String, Value>, String> {
    if journal.len() > MAX_OP_JOURNAL_ENTRIES {
        return Err(format!(
            "operation journal exceeds {MAX_OP_JOURNAL_ENTRIES} entry budget ({})",
            journal.len()
        ));
    }
    // P0-B: compact every provably-completed entry to an exact-once receipt
    // (the same view as durable persistence) so legacy journals with large
    // stdout/file bodies shrink at load instead of retaining them
    // indefinitely. In-progress/uncertain markers are never compacted.
    let mut journal = op_journal_durable_view(&journal);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    for value in journal.values_mut() {
        // Stamp legacy completed entries (pre-1.2.13) so the bounded lifecycle
        // can age them for eviction; in-progress/unknown markers keep no stamp
        // and are never evicted.
        if op_journal_entry_state(value) == OpJournalEntryState::Completed
            && value.get(OP_JOURNAL_COMPLETED_UNIX_FIELD).is_none()
        {
            if let Some(object) = value.as_object_mut() {
                object.insert(OP_JOURNAL_COMPLETED_UNIX_FIELD.into(), json!(now));
            }
        }
    }
    // Validate the size of the bytes the durable writer actually emits:
    // `write_op_journal`/`persist_op_journal` serialize pretty JSON, so a
    // compact-serialized check could pass while the pretty file exceeds the
    // budget (P0-B review: a reproducible uncertain entry measured 4,194,285
    // compact bytes vs 4,194,305 pretty bytes against the 4 MiB cap).
    let encoded = serde_json::to_vec_pretty(&journal)
        .map_err(|e| format!("operation journal re-encode failed: {e}"))?;
    if encoded.len() > MAX_OP_JOURNAL_FILE_BYTES {
        return Err(format!(
            "operation journal exceeds {MAX_OP_JOURNAL_FILE_BYTES} byte budget after compaction"
        ));
    }
    Ok(journal)
}

/// Compacted durable view of an op journal: completed entries become exact-
/// once receipts (identity + status only); in-progress/uncertain markers stay
/// intact. Shared by [`DaemonRuntime::persist_op_journal`], the pressure
/// estimate, and in-memory compaction so all views agree about durable size
/// and state.
fn op_journal_durable_view(journal: &HashMap<String, Value>) -> HashMap<String, Value> {
    let mut out = HashMap::with_capacity(journal.len());
    for (key, value) in journal {
        // Unknown/forward-version states are kept verbatim (fail-closed): a
        // compacted receipt could hide an unfinished side effect.
        if op_journal_entry_state(value) != OpJournalEntryState::Completed {
            out.insert(key.clone(), value.clone());
            continue;
        }
        let mut status = value
            .get("status")
            .cloned()
            .unwrap_or_else(|| json!("completed"));
        // P0-B review: a `review.start` receipt stores the terminal manifest
        // phase (`completed`/`failed`/`cancelled`) as `phase`, not `status`.
        // A compacted failed/cancelled review must replay with the same
        // terminal status — the old code defaulted a missing `status` to
        // `completed`, hiding a failed review behind a completed receipt that
        // the control plane then persisted as a successful operation result.
        // The terminal `phase` is preserved on the compact receipt so replay
        // consumers see the same phase as the first response.
        let phase = value.get("phase").filter(|v| v.is_string()).cloned();
        if let Some(phase_str) = phase.as_ref().and_then(Value::as_str) {
            if matches!(phase_str, "completed" | "failed" | "cancelled")
                && (phase_str != "completed" || value.get("status").is_none())
            {
                status = json!(phase_str);
            }
        }
        let operation_id = value.get("operation_id").cloned();
        let completed_unix = value.get(OP_JOURNAL_COMPLETED_UNIX_FIELD).cloned();
        // `remote_payload_hash` is the review.start replay binding: an
        // identical retry within the retention window must return the compact
        // receipt, not an unauthorized binding mismatch (P0-B). It is a small
        // additive field, so it is preserved on the receipt.
        let remote_payload_hash = value.get("remote_payload_hash").cloned();
        // `review_id` is the identifier `review.show`/`review.page` need to
        // continue a review: an idempotent replay of `review.start` after
        // compaction or restart must still return it, so it is preserved on
        // the receipt (P0-B). `workspace_id` is the review's workspace
        // binding and is equally small and additive.
        let review_id = value.get("review_id").cloned();
        let workspace_id = value.get("workspace_id").cloned();
        // Continuation identifiers (review): compact receipts must keep the
        // small identifiers a client needs to continue an operation whose
        // response was lost after compaction/restart. `session.open` returns
        // the generated session `id` and its controller lease at the top
        // level; `session.attach`/`session.claim` return the session snapshot
        // nested under `session` (whose `id`/`controller`/`controller_epoch`
        // are what a retry needs to attach). These are all small bounded
        // fields; large bodies (stdout/file content) are still dropped.
        //
        // P0-B review: the receipt preserves the *original field names* so
        // the first and the replayed public responses are schema-stable — a
        // top-level `id` stays `id` (never renamed to `session_id`, which
        // would also mislabel non-session ids such as `workspace.add`'s
        // `ws_...`), and an explicit top-level `session_id` stays
        // `session_id`. `session.open` writes both (the handler adds
        // `session_id` as an additive alias of `id`), so a replayed open
        // returns the same shape as the first response.
        let session_id = value
            .get("id")
            .filter(|v| v.is_string())
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .map(|s| json!(s));
        let session_id_alias = value
            .get("session_id")
            .filter(|v| v.is_string())
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .map(|s| json!(s));
        let controller_epoch = value
            .get("controller_epoch")
            .cloned()
            .filter(|v| v.is_u64() || v.is_i64());
        // The controller lease is a small object (principal, lease id, epoch,
        // expiry); preserving it lets a retried `session.open`/`attach`
        // continue with the same seat instead of failing to attach.
        let controller = value.get("controller").filter(|v| v.is_object()).cloned();
        // P0-B review: `session.renew`/`give`/`claim` return their controller
        // lease at the top level as `lease`. The lease is a small bounded
        // object (principal id, opaque lease id, epoch, expiry) — preserving
        // it keeps a replayed remote mutation receipt schema-stable with the
        // first response (a client that retries renew must see the actual
        // extended expiry, never a bare `{session_id, workspace_id}`).
        let lease = value.get("lease").filter(|v| v.is_object()).cloned();
        // Nested `session` snapshot (session.attach/claim): bounded and small;
        // the whole snapshot is preserved so the retry can continue the
        // session. It never carries result bodies.
        let session = value.get("session").filter(|v| v.is_object()).cloned();
        // P0-B review: remote session mutation receipts (close/detach/
        // terminate/give/claim) carry small terminal flags (`closed`,
        // `detached`, `terminated`, `reconciled`, `live_pty`). Preserving
        // them keeps a replayed mutation schema-stable with the first
        // response — a replayed `session.close` must still say `closed`.
        let terminal_flags: Vec<(&str, Value)> =
            ["closed", "detached", "terminated", "reconciled", "live_pty"]
                .into_iter()
                .filter_map(|flag| {
                    value
                        .get(flag)
                        .filter(|v| v.is_boolean() || v.is_number())
                        .cloned()
                        .map(|v| (flag, v))
                })
                .collect();
        // A reconciled terminal failure (#142) carries a small bounded
        // `error` object (code/message/retryable). Preserving it keeps a
        // replayed key returning the original definitive error instead of a
        // generic one; the message is already capped at write time.
        let error = value.get("error").filter(|v| v.is_object()).cloned();
        let mut compact = json!({
            "durable_receipt": true,
            "truncated": true,
            "status": status,
            "note": "op-journal entry compacted before durable persistence",
        });
        if let Some(object) = compact.as_object_mut() {
            for (flag, v) in terminal_flags {
                object.insert(flag.into(), v);
            }
            if let Some(oid) = operation_id {
                object.insert("operation_id".into(), oid);
            }
            if let Some(cu) = completed_unix {
                object.insert(OP_JOURNAL_COMPLETED_UNIX_FIELD.into(), cu);
            }
            if let Some(rph) = remote_payload_hash {
                object.insert("remote_payload_hash".into(), rph);
            }
            if let Some(rid) = review_id {
                object.insert("review_id".into(), rid);
            }
            if let Some(ws) = workspace_id {
                object.insert("workspace_id".into(), ws);
            }
            if let Some(ph) = phase {
                object.insert("phase".into(), ph);
            }
            if let Some(sid) = session_id {
                object.insert("id".into(), sid);
            }
            if let Some(sid) = session_id_alias {
                object.insert("session_id".into(), sid);
            }
            if let Some(epoch) = controller_epoch {
                object.insert("controller_epoch".into(), epoch);
            }
            if let Some(ctl) = controller {
                object.insert("controller".into(), ctl);
            }
            if let Some(ls) = lease {
                object.insert("lease".into(), ls);
            }
            if let Some(session) = session {
                object.insert("session".into(), session);
            }
            if let Some(error) = error {
                object.insert("error".into(), error);
            }
        }
        out.insert(key.clone(), compact);
    }
    out
}

/// Cap a stored failure message so reconciled failed receipts stay small
/// journal entries regardless of the underlying error text.
fn bounded_journal_error_message(message: &str) -> String {
    const MAX_MESSAGE_BYTES: usize = 512;
    if message.len() <= MAX_MESSAGE_BYTES {
        return message.to_owned();
    }
    let mut cut = MAX_MESSAGE_BYTES;
    while cut > 0 && !message.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &message[..cut])
}

fn read_bounded_state_file(path: &Path, max_bytes: usize, label: &str) -> Result<Vec<u8>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("failed to stat {label} {}: {e}", path.display()))?;
    if meta.len() as usize > max_bytes {
        return Err(format!(
            "{label} {} exceeds {max_bytes} byte budget ({})",
            path.display(),
            meta.len()
        ));
    }
    let raw = std::fs::read(path)
        .map_err(|e| format!("failed to read {label} {}: {e}", path.display()))?;
    if raw.len() > max_bytes {
        return Err(format!(
            "{label} {} exceeds {max_bytes} byte budget after read",
            path.display()
        ));
    }
    Ok(raw)
}

fn load_grants(path: &Path) -> Result<Vec<StoredGrant>, String> {
    let raw = read_bounded_state_file(path, MAX_GRANTS_FILE_BYTES, "grants state")?;
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let grants: Vec<StoredGrant> = serde_json::from_slice(&raw)
        .map_err(|e| format!("corrupt grants state {}: {e}", path.display()))?;
    if grants.len() > MAX_GRANTS_ENTRIES {
        return Err(format!(
            "grants state {} exceeds {MAX_GRANTS_ENTRIES} entry budget ({})",
            path.display(),
            grants.len()
        ));
    }
    Ok(grants)
}

fn load_approvals(path: &Path) -> Result<HashMap<String, ApprovalRecord>, String> {
    let raw = read_bounded_state_file(path, MAX_APPROVALS_FILE_BYTES, "approval state")?;
    if raw.is_empty() {
        return Ok(HashMap::new());
    }
    let parsed: HashMap<String, ApprovalRecord> = serde_json::from_slice(&raw)
        .map_err(|e| format!("corrupt approval state {}: {e}", path.display()))?;
    if parsed.len() > MAX_APPROVALS_ENTRIES {
        return Err(format!(
            "approval state {} exceeds {MAX_APPROVALS_ENTRIES} entry budget ({})",
            path.display(),
            parsed.len()
        ));
    }
    for (key, value) in &parsed {
        let bytes = serde_json::to_vec(value).map_err(|e| {
            format!(
                "approval state {} entry {key} re-serialize failed: {e}",
                path.display()
            )
        })?;
        if bytes.len() > MAX_APPROVAL_VALUE_BYTES {
            return Err(format!(
                "approval state {} entry {key} exceeds {MAX_APPROVAL_VALUE_BYTES} byte budget ({})",
                path.display(),
                bytes.len()
            ));
        }
    }
    Ok(parsed)
}

fn load_revoked(path: &Path) -> Result<HashSet<String>, String> {
    let raw = read_bounded_state_file(path, MAX_REVOKED_FILE_BYTES, "revoked client state")?;
    if raw.is_empty() {
        return Ok(HashSet::new());
    }
    let list: Vec<String> = serde_json::from_slice(&raw)
        .map_err(|e| format!("corrupt revoked client state {}: {e}", path.display()))?;
    if list.len() > MAX_REVOKED_ENTRIES {
        return Err(format!(
            "revoked client state {} exceeds {MAX_REVOKED_ENTRIES} entry budget ({})",
            path.display(),
            list.len()
        ));
    }
    let mut canonical = HashSet::with_capacity(list.len());
    for stored in &list {
        if stored.len() > 1024 {
            return Err(format!(
                "corrupt revoked client state {}: principal exceeds 1024 bytes",
                path.display()
            ));
        }
        let principal = canonicalize_principal_key(stored);
        if principal.is_empty() {
            return Err(format!(
                "corrupt revoked client state {}: empty client identity",
                path.display()
            ));
        }
        canonical.insert(principal);
    }

    // Migrate legacy alias spellings immediately. A failure is startup failure so
    // checks never run against state whose durable representation is ambiguous.
    let mut canonical_list: Vec<String> = canonical.iter().cloned().collect();
    canonical_list.sort();
    if list != canonical_list {
        write_json(path, &canonical_list).map_err(|e| {
            format!(
                "failed to canonicalize revoked client state {}: {e}",
                path.display()
            )
        })?;
    }
    Ok(canonical)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let raw = serde_json::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    // Use shared atomic_write (Windows: MoveFileExW replace, no delete window).
    ownmesh_config::atomic_write(path, raw.as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
}

/// Durable op-journal write with **no** `.bak` backup.
///
/// `ownmesh_config::atomic_write` preserves the previous file as `path.bak`
/// before replacing it. For the op journal that previous file may be a legacy
/// (pre-1.2.13) journal whose completed entries still carry large stdout/file
/// bodies — exactly the content compaction exists to remove, and a crash
/// between the backup and any cleanup could leave that sensitive copy behind
/// indefinitely (P0-B privacy). The no-backup writer keeps the temp-file +
/// rename atomicity and never duplicates the previous contents.
fn write_op_journal<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let raw = serde_json::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    ownmesh_config::atomic_write_without_backup(path, raw.as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
}

/// Best-effort removal of a stale `path.bak` left by an older writer or a
/// crash between the backup copy and its cleanup. Never fails the caller: the
/// primary journal is already durably committed; doctor surfaces a lingering
/// backup so the class is not reported healthy. Also retried on every
/// successful persist so a transient lock cannot retain the backup forever.
fn remove_stale_op_journal_backup(path: &Path) {
    if let Err(e) = remove_stale_op_journal_backup_fallible(path) {
        eprintln!(
            "warning: failed to remove stale op journal backup {}: {e}",
            stale_op_journal_backup_path(path).display()
        );
    }
}

/// Fallible removal of a stale `path.bak`; `NotFound` is success. The load
/// path uses this to fail startup when a stale backup cannot be removed:
/// the backup may hold the pre-compaction legacy journal with large
/// stdout/file bodies, and running with it on disk while claiming the body
/// copy is removed would be dishonest (P0-B privacy, review). The operator
/// fixes permissions/locks and restarts.
fn remove_stale_op_journal_backup_fallible(path: &Path) -> std::io::Result<()> {
    let bak = stale_op_journal_backup_path(path);
    match std::fs::remove_file(&bak) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod broker_intent_tests {
    use super::*;

    /// Owner-only tempdir: `tempfile` respects the process umask, and the
    /// daemon custody attestation rejects group/world-writable ancestors, so
    /// tests pin mode 0700 to stay umask-independent.
    fn tempdir() -> std::io::Result<tempfile::TempDir> {
        let dir = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(dir)
    }

    fn fixture_executable() -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            PathBuf::from("/bin/true")
        }
        #[cfg(not(target_os = "linux"))]
        {
            std::env::current_exe().unwrap()
        }
    }

    fn bound_runtime() -> (tempfile::TempDir, DaemonRuntime, ExecParams) {
        let temp = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(temp.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.active_remote_operation_id = Some("op_elevated_exact_1".into());
        runtime.active_remote_payload_hash = Some("a".repeat(64));
        runtime.active_remote_device_id = Some("device_elevated_1".into());
        runtime.active_remote_principal = Some("client:remote:tenant_e8:principal_e8".into());
        runtime.active_remote_principal_credential_generation = Some(7);
        runtime.active_remote_expires_at_unix = Some(DaemonRuntime::now() + 300);
        let executable = fixture_executable();
        let pin = pin_executable(&executable, CommandKind::Structured).unwrap();
        (
            temp,
            runtime,
            ExecParams {
                kind: Some("structured".into()),
                policy_kind: Some("structured".into()),
                program: pin.path.clone(),
                args: vec!["--version".into()],
                cwd: None,
                workspace_id: Some("ws_default".into()),
                env: HashMap::new(),
                timeout_ms: Some(2_000),
                idempotency_key: Some("idempotent_elevated_1".into()),
                max_output_bytes: Some(4_096),
                elevated: true,
                detach: false,
                executable_pin: Some(pin),
                invocation_pin: None,
                shell_pin: None,
            },
        )
    }

    #[test]
    fn elevated_intent_is_exactly_bound_to_remote_authority_and_pinned_argv() {
        let (_temp, runtime, params) = bound_runtime();
        let intent = runtime
            .build_broker_execute_intent(&params, &ownmesh_broker_client::BrokerSecret::generate())
            .unwrap();
        assert_eq!(intent.operation_id, "op_elevated_exact_1");
        assert_eq!(intent.facts.remote_payload_sha256, "a".repeat(64));
        assert_eq!(intent.facts.tenant_id, "tenant_e8");
        assert_eq!(intent.facts.principal_id, "principal_e8");
        assert_eq!(intent.facts.principal_credential_generation, 7);
        assert_eq!(intent.facts.argv[0], intent.facts.executable.canonical_path);
        assert_eq!(intent.facts.argv[1], "--version");
        assert!(intent.facts.sanitized_env.is_empty());
        assert!(!intent.mac.is_empty());
    }

    #[test]
    fn elevated_intent_refuses_missing_generation_and_unsafe_handoff_facts() {
        let (_temp, mut runtime, mut params) = bound_runtime();
        runtime.active_remote_principal_credential_generation = None;
        let err = runtime
            .build_broker_execute_intent(&params, &ownmesh_broker_client::BrokerSecret::generate())
            .unwrap_err();
        assert!(err.to_string().contains("credential generation"));

        runtime.active_remote_principal_credential_generation = Some(7);
        params.cwd = Some("/untrusted-cwd".into());
        let err = runtime
            .build_broker_execute_intent(&params, &ownmesh_broker_client::BrokerSecret::generate())
            .unwrap_err();
        assert!(err.to_string().contains("cwd handoff"));

        params.cwd = None;
        params.env.insert("PATH".into(), "/attacker".into());
        let err = runtime
            .build_broker_execute_intent(&params, &ownmesh_broker_client::BrokerSecret::generate())
            .unwrap_err();
        assert!(err.to_string().contains("environment overlays"));

        params.env.clear();
        params.workspace_id = None;
        let err = runtime
            .build_broker_execute_intent(&params, &ownmesh_broker_client::BrokerSecret::generate())
            .unwrap_err();
        assert!(err.to_string().contains("workspace id"));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_cancel_watch_false_does_not_preempt_execute() {
        let (_sender, mut cancel) = tokio::sync::watch::channel(false);
        assert!(!*cancel.borrow_and_update());
        let pending =
            tokio::time::timeout(std::time::Duration::from_millis(20), cancel.changed()).await;
        assert!(
            pending.is_err(),
            "false cancel state must not preempt execute"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn review_cargo_rustup_proxy_keeps_cargo_invocation_identity() {
        let temp = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(temp.path());
        let runtime = DaemonRuntime::open(&paths).unwrap();
        let cwd = std::env::current_dir().unwrap();

        let command = runtime
            .pin_review_command("cargo.exe".into(), vec!["--version".into()], 10_000, &cwd)
            .expect("Windows Rust toolchain must expose a Cargo proxy");

        let invocation_pin = command
            .invocation_pin
            .as_ref()
            .expect("new review commands pin the invocation path too");
        assert!(
            Path::new(&command.program).is_absolute(),
            "persisted invocation paths must be absolute: {}",
            command.program
        );
        assert!(
            command
                .program
                .to_ascii_lowercase()
                .ends_with("\\cargo.exe"),
            "review must invoke Cargo rather than its Rustup backing executable: {}",
            command.program
        );
        assert_eq!(
            PathBuf::from(&command.pin.path),
            std::fs::canonicalize(&command.program).unwrap(),
            "Cargo invocation must retain its canonical backing executable pin"
        );
        assert_eq!(invocation_pin.path, command.program);
        verify_executable_pin(Path::new(&command.program), invocation_pin).unwrap();
        verify_executable_pin(Path::new(&command.pin.path), &command.pin).unwrap();

        let (succeeded, cancelled, result) = runtime.run_review_command(&command, &cwd).await;
        assert!(succeeded, "cargo proxy review failed: {result:?}");
        assert!(!cancelled);
        assert!(result.stdout.to_ascii_lowercase().contains("cargo"));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn closed_windows_cancel_watch_is_disabled_after_one_error() {
        let (sender, mut cancel) = tokio::sync::watch::channel(false);
        drop(sender);
        let mut channel_open = true;
        assert!(cancel.changed().await.is_err());
        assert!(channel_open);
        channel_open = false;
        tokio::select! {
            biased;
            () = std::future::pending::<()>() => panic!("pending execute cannot complete"),
            _ = cancel.changed(), if channel_open => panic!("closed cancel watch must be disabled"),
            () = tokio::time::sleep(std::time::Duration::from_millis(20)) => {},
        }
    }

    /// §7.1 promises Recommended confirms credential access. An ordinary file
    /// still reads without friction, and full access keeps no hidden ask.
    #[tokio::test]
    async fn recommended_asks_before_reading_a_workspace_credential_file() {
        let temp = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(temp.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let workspace = paths.state_dir.join("workspace");
        std::fs::write(workspace.join(".env"), b"API_TOKEN=super-secret\n").unwrap();
        std::fs::write(workspace.join("main.rs"), b"fn main() {}\n").unwrap();
        let client = ClientIdentity::new("sensitive-read-test", "test");
        let read =
            |path: &str| json!({ "path": path, "workspace_id": "ws_default", "max_bytes": 1024 });

        runtime.set_policy_for_test(preset_document(AccessPreset::Recommended));
        let gated = runtime
            .dispatch(methods::OPS_FS_READ, Some(read(".env")), &client)
            .await
            .expect("an ask is a successful response carrying approval_required");
        assert_eq!(
            gated["approval_required"],
            json!(true),
            "credential read must reach a human first: {gated}"
        );
        assert!(
            gated["result"].is_null(),
            "no content may be returned with the approval request: {gated}"
        );

        let ordinary = runtime
            .dispatch(methods::OPS_FS_READ, Some(read("main.rs")), &client)
            .await
            .expect("ordinary reads stay allowed under recommended");
        assert_eq!(ordinary["approval_required"], json!(false), "{ordinary}");

        runtime.set_policy_for_test(preset_document(AccessPreset::FullAccess));
        let full = runtime
            .dispatch(methods::OPS_FS_READ, Some(read(".env")), &client)
            .await
            .expect("full access has no hidden ask");
        assert_eq!(full["approval_required"], json!(false), "{full}");
    }

    #[tokio::test]
    async fn recommended_asks_before_returning_git_diff_contents() {
        let temp = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(temp.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.set_policy_for_test(preset_document(AccessPreset::Recommended));
        let client = ClientIdentity::new("sensitive-diff-test", "test");

        let gated = runtime
            .dispatch(
                ops_methods::GIT_DIFF,
                Some(json!({
                    "path": "",
                    "pathspec": ".env",
                    "workspace_id": "ws_default"
                })),
                &client,
            )
            .await
            .expect("an ask is a successful response carrying approval_required");

        assert_eq!(gated["approval_required"], json!(true), "{gated}");
        assert!(gated["result"].is_null(), "{gated}");
    }

    #[tokio::test]
    async fn policy_explain_uses_the_same_default_workspace_and_sensitive_facts() {
        let temp = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(temp.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.set_policy_for_test(preset_document(AccessPreset::Recommended));
        let client = ClientIdentity::new("policy-explain-test", "test");

        let explained = runtime
            .dispatch(
                methods::POLICY_EXPLAIN,
                Some(json!({ "query": "read", "path": ".env" })),
                &client,
            )
            .await
            .unwrap();
        assert_eq!(explained["decision"], json!("ask"), "{explained}");
        assert_eq!(
            explained["facts"]["workspace_id"],
            json!("ws_default"),
            "{explained}"
        );
        assert_eq!(
            explained["facts"]["tags"],
            json!([TAG_READS_SENSITIVE_LOCATION]),
            "{explained}"
        );
    }

    #[tokio::test]
    async fn local_elevation_stays_in_the_same_runtime_and_terminal_failure_never_reruns() {
        let temp = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(temp.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.set_policy_for_test(preset_document(AccessPreset::FullAccess));
        let program = fixture_executable().display().to_string();
        let client = ClientIdentity::new("local-elevation-test", "test");
        let params = json!({
            "program": program,
            "args": [],
            "kind": "structured",
            "workspace_id": "ws_default",
            "elevated": true,
            "idempotency_key": "local-elevated-never-fallback"
        });
        let first = runtime
            .dispatch(methods::OPS_EXEC, Some(params.clone()), &client)
            .await
            .expect_err("local elevation must not fall back to local spawning");
        assert!(first.to_string().contains("broker") || first.to_string().contains("binding"));
        // #142: the definitive failure reconciles the reserved marker into a
        // terminal failed receipt, so a retry replays that same stored error.
        // It must never rerun the operation and never masquerade as success.
        let second = runtime
            .dispatch(methods::OPS_EXEC, Some(params), &client)
            .await
            .expect_err("terminal failure must not rerun");
        assert!(
            second.to_string().contains("broker") || second.to_string().contains("binding"),
            "replay must return the stored terminal failure: {second}"
        );
    }

    /// P1-D review: `handle_exec` must reject a structured program that
    /// cannot be resolved to a launchable file, fail-closed, instead of
    /// silently falling back to a bare-name spawn whose OS PATH lookup can
    /// disagree with profile detection/review pinning (detect-ready then
    /// spawn-bare-name inconsistency). The error names the program and the
    /// remedy.
    #[tokio::test]
    async fn structured_exec_unresolvable_program_fails_closed_before_authorization() {
        let temp = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(temp.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.set_policy_for_test(preset_document(AccessPreset::FullAccess));
        let client = ClientIdentity::new("exec-resolution-test", "test");
        let missing = temp.path().join("no-such-ownmesh-tool");
        let err = runtime
            .dispatch(
                methods::OPS_EXEC,
                Some(json!({
                    "program": missing.display().to_string(),
                    "args": [],
                    "kind": "structured",
                    "workspace_id": "ws_default",
                })),
                &client,
            )
            .await
            .expect_err("unresolvable structured program must fail closed");
        assert!(
            err.to_string().contains("could not be resolved"),
            "actionable resolution failure expected: {err}"
        );
        // No op-journal receipt was created: nothing was authorized or run.
        assert!(
            runtime.op_journal.is_empty(),
            "no side-effect receipt may exist"
        );
    }

    #[test]
    fn uncertain_broker_write_is_non_retriable_conflict() {
        let error = DaemonRuntime::broker_client_error(BrokerV2ClientError::ExecutionUncertain(
            "lost response".into(),
        ));
        assert!(matches!(
            error,
            IpcError::Remote {
                code: app_error::CONFLICT,
                ..
            }
        ));
    }

    #[test]
    fn broker_failure_never_becomes_a_successful_exec_result() {
        let denied =
            DaemonRuntime::broker_response_value(ownmesh_broker_client::BrokerResponseV2 {
                request_id: "breq_failed".into(),
                ok: false,
                exit_code: Some(1),
                stdout: "must-not-be-a-result".into(),
                stderr: "failed".into(),
                error: Some("broker failed".into()),
                timed_out: false,
                cancelled: false,
                truncated: false,
                duration_ms: 1,
            })
            .unwrap_err();
        assert!(denied.to_string().contains("broker rejected"));

        let result =
            DaemonRuntime::broker_response_value(ownmesh_broker_client::BrokerResponseV2 {
                request_id: "breq_ok".into(),
                ok: true,
                exit_code: Some(0),
                stdout: "ok".into(),
                stderr: String::new(),
                error: None,
                timed_out: false,
                cancelled: false,
                truncated: true,
                duration_ms: 2,
            })
            .unwrap();
        assert_eq!(result["exit_code"], 0);
        assert_eq!(result["stdout"], "ok");
        assert_eq!(result["truncated"], true);
        assert_eq!(result["replayed"], false);
    }
}

#[cfg(test)]
mod journal_lifecycle_tests {
    use super::*;

    /// Owner-only tempdir: `tempfile` respects the process umask, and the
    /// daemon custody attestation rejects group/world-writable ancestors, so
    /// tests pin mode 0700 to stay umask-independent.
    fn tempdir() -> std::io::Result<tempfile::TempDir> {
        let dir = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(dir)
    }

    /// A PID the OS confirms does not exist on every supported platform
    /// (2e9 exceeds the Linux `pid_max` default and the macOS/Windows PID
    /// space, and never matches a short-lived CI process), so
    /// `ownmesh_ipc::process_birth_id` proves the child is gone.
    const DEAD_TEST_PID: u32 = 2_000_000_000;

    /// A transition record whose host TTL has provably passed and whose
    /// referenced sidecar carries a confirmed-dead child identity, so
    /// reconcile can clear it once session state is moot.
    fn expired_record(transition_id: &str, session_id: &str, now: i64) -> TransitionRecord {
        TransitionRecord {
            transition_id: transition_id.into(),
            kind: TransitionKind::Claim,
            phase: TransitionPhase::Intent,
            session_id: session_id.into(),
            device_id: "dev_test".into(),
            workspace_id: "ws_default".into(),
            authenticated_principal: "owner".into(),
            old_binding: SidecarHostBinding {
                device_id: "dev_test".into(),
                workspace_id: "ws_default".into(),
                owner_principal: "owner".into(),
                host_nonce: "nonce_old".into(),
                controller_epoch: 1,
                binding_expires_unix: now - 20,
                host_expires_unix: now - 10,
                child_pid: Some(DEAD_TEST_PID),
                child_process_birth: Some(1),
            },
            target: TransitionTarget {
                principal: "owner".into(),
                controller_epoch: 2,
                binding_expires_unix: now - 20,
                controller_attached: true,
                lease_id: Some("lease_expired".into()),
                terminal: false,
            },
            new_binding: None,
            created_unix: now - 3600,
            expires_unix: now - 10,
        }
    }

    /// A non-terminal `Applied` give record whose target seat and successor
    /// binding are recorded, for the crash-window recovery tests below.
    fn applied_give_record(transition_id: &str, session_id: &str, now: i64) -> TransitionRecord {
        TransitionRecord {
            transition_id: transition_id.into(),
            kind: TransitionKind::Give,
            phase: TransitionPhase::Applied,
            session_id: session_id.into(),
            device_id: "dev_test".into(),
            workspace_id: "ws_default".into(),
            authenticated_principal: "owner_a".into(),
            old_binding: SidecarHostBinding {
                device_id: "dev_test".into(),
                workspace_id: "ws_default".into(),
                owner_principal: "owner_a".into(),
                host_nonce: "nonce_old".into(),
                controller_epoch: 1,
                binding_expires_unix: now - 20,
                host_expires_unix: now + 2000,
                child_pid: None,
                child_process_birth: None,
            },
            target: TransitionTarget {
                principal: "owner_b".into(),
                controller_epoch: 2,
                binding_expires_unix: now + 1500,
                controller_attached: true,
                lease_id: Some("lease_b".into()),
                terminal: false,
            },
            new_binding: Some(SidecarHostBinding {
                device_id: "dev_test".into(),
                workspace_id: "ws_default".into(),
                owner_principal: "owner_b".into(),
                host_nonce: "nonce_new".into(),
                controller_epoch: 2,
                binding_expires_unix: now + 1500,
                host_expires_unix: now + 2000,
                child_pid: None,
                child_process_birth: None,
            }),
            created_unix: now - 300,
            expires_unix: now + 2000,
        }
    }

    /// Runtime with exactly one session; `closed` decides its terminal state.
    fn runtime_with_session(closed: bool) -> (tempfile::TempDir, DaemonRuntime, String) {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let now = DaemonRuntime::now();
        let info = runtime
            .sessions
            .open(SessionKind::Pty, "journal-test", "owner", now, None)
            .unwrap();
        if closed {
            runtime.sessions.close(&info.id).unwrap();
        }
        (dir, runtime, info.id)
    }

    /// P0-A acceptance: the affected session stays fail-closed while its
    /// transition record is unresolved — `session.attach` (controller role) and
    /// the other controller-mutating handlers are fenced, while an unrelated
    /// session remains fully usable. Clearing the record restores access.
    #[tokio::test]
    async fn ambiguous_transition_fences_controller_mutation_of_affected_session() {
        let (_dir, mut runtime, sid) = runtime_with_session(false);
        let now = DaemonRuntime::now();
        // A retained (expired, ambiguous) transition record for the session.
        let record = expired_record("tr_fence", &sid, now);
        runtime
            .transition_journal
            .begin(record)
            .expect("begin record");
        let local = ClientIdentity::new("owner", "test");

        // session.attach(role=controller) is fenced with an actionable error.
        let err = runtime
            .handle_session_attach(
                Some(json!({ "id": sid.clone(), "role": "controller" })),
                &local,
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("unresolved sidecar transition"),
            "controller attach must be fenced: {err}"
        );

        // session.attach(role=observer) from the current controller would
        // release the controller lease — also a controller mutation, fenced.
        let err = runtime
            .handle_session_attach(
                Some(json!({ "id": sid.clone(), "role": "observer" })),
                &local,
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("unresolved sidecar transition"),
            "controller-downgrading observer attach must be fenced: {err}"
        );

        // session.claim is fenced the same way.
        let err = runtime
            .handle_session_claim(Some(json!({ "id": sid.clone() })), &local)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("unresolved sidecar transition"),
            "session.claim must be fenced: {err}"
        );

        // session.close is fenced: an ambiguous close/detach/give intent must
        // not be overwritten by a different terminal transition while the
        // record is unresolved.
        let err = runtime
            .handle_session_close(Some(json!({ "id": sid.clone() })), &local)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("unresolved sidecar transition"),
            "session.close must be fenced: {err}"
        );

        // session.terminate is fenced the same way (single-session path).
        let err = runtime
            .handle_session_terminate(Some(json!({ "id": sid.clone() })), &local)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("unresolved sidecar transition"),
            "session.terminate must be fenced: {err}"
        );

        // session.terminate(all) must not bypass the journal for a session
        // with an unresolved record.
        let err = runtime
            .handle_session_terminate(Some(json!({ "all": true })), &local)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("unresolved sidecar transition"),
            "session.terminate all must be fenced: {err}"
        );

        // session.write is fenced: input must not be delivered against a
        // possibly-stale sidecar binding while the transition is unresolved.
        let err = runtime
            .handle_session_write(Some(json!({ "id": sid.clone(), "data": "x" })), &local)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("unresolved sidecar transition"),
            "session.write must be fenced: {err}"
        );

        // session.resize is fenced the same way.
        let err = runtime
            .handle_session_resize(
                Some(json!({ "id": sid.clone(), "cols": 80, "rows": 24 })),
                &local,
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("unresolved sidecar transition"),
            "session.resize must be fenced: {err}"
        );

        // An unrelated session is not fenced: after releasing its (creator)
        // controller lease, a controller attach succeeds.
        let other = runtime
            .sessions
            .open(SessionKind::Pty, "fence-unrelated", "owner", now, None)
            .expect("open unrelated session")
            .id;
        runtime
            .sessions
            .release_controller(&other, "owner", now)
            .expect("release creator lease");
        let ok = runtime
            .handle_session_attach(
                Some(json!({ "id": other.clone(), "role": "controller" })),
                &local,
            )
            .expect("unrelated controller attach must succeed");
        assert_eq!(ok["role"], "controller");

        // Clearing the ambiguous record restores controller access.
        runtime
            .transition_journal
            .clear("tr_fence")
            .expect("clear record");
        runtime
            .sessions
            .release_controller(&sid, "owner", now)
            .expect("release creator lease");
        let ok = runtime
            .handle_session_attach(
                Some(json!({ "id": sid.clone(), "role": "controller" })),
                &local,
            )
            .expect("controller attach must succeed after the record is resolved");
        assert_eq!(ok["role"], "controller");

        // After the record is resolved, write/resize are no longer fenced:
        // the error becomes the genuine no-live-host conflict, never the
        // fence (proves the fence is the only thing blocking delivery).
        let err = runtime
            .handle_session_write(Some(json!({ "id": sid.clone(), "data": "x" })), &local)
            .await
            .unwrap_err();
        assert!(
            !err.to_string().contains("unresolved sidecar transition"),
            "write must not be fenced after the record is resolved: {err}"
        );
        let err = runtime
            .handle_session_resize(
                Some(json!({ "id": sid.clone(), "cols": 80, "rows": 24 })),
                &local,
            )
            .await
            .unwrap_err();
        assert!(
            !err.to_string().contains("unresolved sidecar transition"),
            "resize must not be fenced after the record is resolved: {err}"
        );
    }

    /// P0-A crash-window regression: a crash after the supervisor mutation and
    /// the `Applied` journal write but before the `SessionManager` commit
    /// leaves the durable controller unchanged while the sidecar already
    /// belongs to the successor. Recovery must apply the FULL recorded
    /// controller mutation (principal, lease id, epoch, expiry) — not only
    /// the sidecar binding — so the former controller cannot keep writing
    /// through the successor's host after the record is cleared.
    #[tokio::test]
    async fn recovered_applied_give_restores_full_controller_seat_not_only_binding() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let now = DaemonRuntime::now();
        let info = runtime
            .sessions
            .open_with(
                SessionKind::Pty,
                "crash-window",
                "owner_a",
                now,
                None,
                None,
                None,
                None,
                None,
                Some("ws_default".into()),
            )
            .unwrap();
        let sid = info.id.clone();
        // Durable state as of the crash: controller owner_a (epoch 1) and the
        // pre-transition sidecar binding. The journal holds an Applied give
        // to owner_b whose commit never completed.
        let record = applied_give_record("tr_crash_give", &sid, now);
        runtime
            .sessions
            .set_sidecar_host_binding(&sid, Some(record.old_binding.clone()))
            .unwrap();
        runtime
            .transition_journal
            .begin(record.clone())
            .expect("begin record");

        runtime
            .recover_transition_record(record)
            .await
            .expect("recovery must reconcile the full controller mutation");

        let recovered = runtime.sessions.get(&sid).unwrap();
        assert_eq!(
            recovered
                .controller
                .as_ref()
                .map(|c| c.principal_id.as_str()),
            Some("owner_b"),
            "recovery must install the recorded successor principal"
        );
        assert_eq!(
            recovered.controller.as_ref().map(|c| c.lease_id.as_str()),
            Some("lease_b"),
            "recovery must restore the exact recorded lease id"
        );
        assert_eq!(
            recovered.controller.as_ref().map(|c| c.epoch),
            Some(2),
            "recovery must restore the recorded controller epoch"
        );
        assert_eq!(
            recovered.controller.as_ref().map(|c| c.expires_unix),
            Some(now + 1500),
            "recovery must restore the recorded lease expiry"
        );
        assert_eq!(recovered.controller_epoch, 2);
        let binding = recovered.sidecar_host.as_ref().expect("successor binding");
        assert_eq!(binding.owner_principal, "owner_b");
        assert_eq!(binding.host_nonce, "nonce_new");
        assert_eq!(binding.controller_epoch, 2);

        // The former controller is no longer authorized — its write cannot
        // reach the successor's sidecar. The successor's seat authorizes.
        assert!(
            runtime
                .sessions
                .authorize_stdin(&sid, "owner_a", now)
                .is_err(),
            "the stale former controller must not remain authorized"
        );
        runtime
            .sessions
            .authorize_stdin(&sid, "owner_b", now)
            .expect("the recorded successor must be authorized");
        runtime
            .sessions
            .authorize_controller_lease(&sid, "owner_b", "lease_b", 2, now)
            .expect("remote write authorization must keep working with the restored lease");
        assert!(
            runtime
                .sessions
                .authorize_controller_lease(&sid, "owner_b", "lease_b", 2, now)
                .is_ok(),
            "lease authorization must not be poisoned by recovery"
        );

        // The full public write path refuses the stale controller too.
        let err = runtime
            .handle_session_write(
                Some(json!({ "id": sid.clone(), "data": "x" })),
                &ClientIdentity::new("owner_a", "test"),
            )
            .await
            .unwrap_err();
        assert!(
            !err.to_string().contains("unresolved sidecar transition")
                && (err.to_string().contains("not controller")
                    || err.to_string().contains("observer cannot write")),
            "stale former controller write must fail authorization, not the fence: {err}"
        );

        // The record is cleared: the ambiguity is resolved, not retained.
        assert!(
            runtime.transition_journal.pending().is_empty(),
            "a fully reconciled Applied record must be cleared"
        );
    }

    /// P0-A defense in depth: recovery must never regress a durable
    /// controller generation that is already newer than the journal record
    /// target. A superseded record is cleared without touching the session;
    /// a superseded record whose durable binding is still the stale
    /// pre-transition generation is retained fail-closed.
    #[tokio::test]
    async fn recovered_record_never_regresses_a_newer_durable_generation() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let now = DaemonRuntime::now();
        let info = runtime
            .sessions
            .open_with(
                SessionKind::Pty,
                "crash-window-ahead",
                "owner_a",
                now,
                None,
                None,
                None,
                None,
                None,
                Some("ws_default".into()),
            )
            .unwrap();
        let sid = info.id.clone();
        // Durable generation advances past the journal record (owner_c,
        // epoch 3) while the journal still holds an older Applied give
        // (target epoch 2). The durable binding is already the newer
        // generation — the record is redundant and must be cleared without
        // mutating the session.
        runtime
            .sessions
            .give_controller(&sid, "owner_a", "owner_b", now)
            .unwrap();
        runtime
            .sessions
            .give_controller(&sid, "owner_b", "owner_c", now)
            .unwrap();
        runtime
            .sessions
            .set_sidecar_host_binding(
                &sid,
                Some(SidecarHostBinding {
                    device_id: "dev_test".into(),
                    workspace_id: "ws_default".into(),
                    owner_principal: "owner_c".into(),
                    host_nonce: "nonce_newest".into(),
                    controller_epoch: 3,
                    binding_expires_unix: now + 3600,
                    host_expires_unix: now + 3600,
                    child_pid: None,
                    child_process_birth: None,
                }),
            )
            .unwrap();
        let record = applied_give_record("tr_superseded", &sid, now);
        runtime
            .transition_journal
            .begin(record.clone())
            .expect("begin record");
        runtime
            .recover_transition_record(record)
            .await
            .expect("a superseded record must be reconciled without mutating the session");
        let recovered = runtime.sessions.get(&sid).unwrap();
        assert_eq!(
            recovered.controller_epoch, 3,
            "recovery must not regress the generation"
        );
        assert_eq!(
            recovered
                .controller
                .as_ref()
                .map(|c| c.principal_id.as_str()),
            Some("owner_c")
        );
        assert_eq!(
            recovered
                .sidecar_host
                .as_ref()
                .map(|b| b.host_nonce.as_str()),
            Some("nonce_newest")
        );
        assert!(runtime.transition_journal.pending().is_empty());

        // The same durable-ahead state with a STALE pre-transition binding
        // must be retained fail-closed, never cleared into a mismatch.
        let stale_record = applied_give_record("tr_stale_binding", &sid, now);
        runtime
            .sessions
            .set_sidecar_host_binding(&sid, Some(stale_record.old_binding.clone()))
            .unwrap();
        runtime
            .transition_journal
            .begin(stale_record.clone())
            .expect("begin stale record");
        let err = runtime
            .recover_transition_record(stale_record)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("retained fail-closed"),
            "stale-binding superseded record must be retained fail-closed: {err}"
        );
        assert_eq!(
            runtime.transition_journal.pending().len(),
            1,
            "the stale-binding record must still be pending"
        );
    }

    /// P0-A regression: the old code hard-failed `recover_sidecar_transitions`
    /// on ANY expired record, poisoning every future session. An expired
    /// record whose session is provably `Closed` must be reconciled (cleared)
    /// and recovery must succeed.
    #[tokio::test]
    async fn expired_transition_record_for_closed_session_is_reconciled_not_poisoning() {
        let (_dir, mut runtime, sid) = runtime_with_session(true);
        let now = DaemonRuntime::now();
        let record = expired_record("tr_poison_closed", &sid, now);
        runtime
            .transition_journal
            .begin(record)
            .expect("begin record");
        assert_eq!(runtime.transition_journal.pending().len(), 1);

        runtime
            .recover_sidecar_transitions()
            .await
            .expect("recovery must not abort on an expired record");

        assert!(
            runtime.transition_journal.pending().is_empty(),
            "the expired record for a closed session must be cleared"
        );
        assert_eq!(
            runtime.transition_recovery_health.retained_expired_total, 0,
            "nothing was retained fail-closed"
        );
        // A brand-new unrelated session still opens without any journal error.
        runtime
            .sessions
            .open(SessionKind::Pty, "after-recovery", "owner", now, None)
            .expect("unrelated session open must succeed");
    }

    /// P0-A: a session that no longer exists at all is equally provably moot
    /// once the host TTL has passed — the record is cleared, not fatal.
    #[tokio::test]
    async fn expired_transition_record_for_missing_session_is_cleared() {
        let (_dir, mut runtime, _sid) = runtime_with_session(true);
        let now = DaemonRuntime::now();
        let record = expired_record("tr_poison_missing", "ses_gone", now);
        runtime
            .transition_journal
            .begin(record)
            .expect("begin record");
        runtime
            .recover_sidecar_transitions()
            .await
            .expect("recovery must not abort");
        assert!(runtime.transition_journal.pending().is_empty());
        assert_eq!(runtime.transition_recovery_health.retained_expired_total, 0);
    }

    /// P0-A/P1-F: a failed durable `clear` (persist fault) must not make the
    /// daemon report the stale row as gone. The in-memory journal is rolled
    /// back, so `refresh_transition_recovery_health` still surfaces the
    /// retained-expired record instead of reporting no pending transition
    /// until restart while the durable stale row remains.
    #[cfg(unix)]
    #[tokio::test]
    async fn failed_transition_clear_keeps_health_consistent_with_durable_state() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, mut runtime, sid) = runtime_with_session(true);
        let now = DaemonRuntime::now();
        let record = expired_record("tr_clear_fault", &sid, now);
        runtime
            .transition_journal
            .begin(record)
            .expect("begin record");
        // Make the journal directory read-only so the durable removal fails.
        let journal_dir = runtime.transition_journal_dir();
        std::fs::set_permissions(&journal_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        runtime.reconcile_expired_transitions().await;
        std::fs::set_permissions(&journal_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        // The failed clear rolled back: the in-memory journal still has the
        // record and health still reports it as retained-expired — the daemon
        // must not claim the durable stale row is gone.
        assert_eq!(
            runtime.transition_journal.pending().len(),
            1,
            "in-memory journal must keep the record after a failed durable clear"
        );
        assert_eq!(
            runtime.transition_recovery_health.retained_expired_total, 1,
            "health must still surface the retained-expired record"
        );
        // The durable file still contains the record.
        let reopened = SessionTransitionJournal::open(&journal_dir).unwrap();
        assert_eq!(
            reopened.pending().len(),
            1,
            "durable row must survive the failed clear"
        );
        // A later successful reconcile (durable write possible again) clears
        // it and health follows.
        runtime.reconcile_expired_transitions().await;
        assert!(runtime.transition_journal.pending().is_empty());
        assert_eq!(runtime.transition_recovery_health.retained_expired_total, 0);
    }

    /// P0-A: an expired record whose session is still present and non-terminal
    /// is retained fail-closed (never converted into success), surfaced in
    /// health, and must NOT block unrelated future sessions.
    #[tokio::test]
    async fn expired_uncertain_record_is_retained_and_surfaced_not_global_abort() {
        let (_dir, mut runtime, sid) = runtime_with_session(false);
        let now = DaemonRuntime::now();
        let record = expired_record("tr_poison_uncertain", &sid, now);
        runtime
            .transition_journal
            .begin(record)
            .expect("begin record");

        runtime
            .recover_sidecar_transitions()
            .await
            .expect("recovery continues past a retained record");

        assert_eq!(
            runtime.transition_journal.pending().len(),
            1,
            "fail-closed retention"
        );
        assert_eq!(
            runtime.transition_recovery_health.retained_expired_total, 1,
            "health must surface the retained record"
        );
        assert_eq!(
            runtime.transition_recovery_health.retained_expired[0],
            "tr_poison_uncertain"
        );
        // An unrelated session still opens — no global poison pill.
        runtime
            .sessions
            .open(SessionKind::Pty, "after-retained", "owner", now, None)
            .expect("unrelated session open must succeed");
    }

    /// P0-A acceptance 3: one bad record must not prevent independent safe
    /// cleanup. A live record that cannot be replayed (no supervisor) aborts
    /// fail-closed, but the expired record was already reconciled first.
    #[tokio::test]
    async fn expired_cleanup_happens_before_live_replay_abort() {
        let (_dir, mut runtime, sid) = runtime_with_session(true);
        let now = DaemonRuntime::now();
        let expired = expired_record("tr_expired_first", &sid, now);
        let mut live = expired_record("tr_live_second", "ses_unrelated", now);
        live.expires_unix = now + 3600;
        live.created_unix = now - 1;
        live.target.binding_expires_unix = now + 60;
        live.old_binding.binding_expires_unix = now + 60;
        live.old_binding.host_expires_unix = now + 600;
        runtime
            .transition_journal
            .begin(expired)
            .expect("begin expired");
        runtime.transition_journal.begin(live).expect("begin live");

        // A live record that cannot be replayed aborts fail-closed (its host
        // may still be live, so ambiguity must never become success).
        runtime
            .recover_sidecar_transitions()
            .await
            .expect_err("live replay must fail closed without authoritative state");
        // …but the expired record was already safely cleared first.
        let pending = runtime.transition_journal.pending();
        assert_eq!(pending.len(), 1, "only the live record remains");
        assert_eq!(pending[0].transition_id, "tr_live_second");
        assert_eq!(runtime.transition_recovery_health.retained_expired_total, 0);
    }

    /// P0-A acceptance 1/5: the shared expired-only reconcile pass used by
    /// diagnosis and daemon startup clears provably-moot records and retains
    /// ambiguous ones fail-closed, exactly like the supervisor path — so
    /// `system.diagnose` reflects post-recovery state instead of hiding an
    /// expired poison-pill record behind `overall=healthy`.
    #[tokio::test]
    async fn reconcile_expired_transitions_is_used_by_diagnosis_and_is_safe() {
        let (_dir, mut runtime, sid) = runtime_with_session(true);
        let now = DaemonRuntime::now();
        let record = expired_record("tr_reconcile_closed", &sid, now);
        runtime
            .transition_journal
            .begin(record)
            .expect("begin record");
        // A live record is untouched by the expired-only pass (it belongs to
        // the supervisor replay path and must not fail a diagnosis).
        let mut live = expired_record("tr_reconcile_live", "ses_other", now);
        live.expires_unix = now + 3600;
        live.created_unix = now - 1;
        live.target.binding_expires_unix = now + 60;
        live.old_binding.binding_expires_unix = now + 60;
        live.old_binding.host_expires_unix = now + 600;
        runtime
            .transition_journal
            .begin(live)
            .expect("begin live record");

        runtime.reconcile_expired_transitions().await;

        let pending = runtime.transition_journal.pending();
        assert_eq!(pending.len(), 1, "only the live record remains");
        assert_eq!(pending[0].transition_id, "tr_reconcile_live");
        assert_eq!(runtime.transition_recovery_health.retained_expired_total, 0);
    }

    /// P0-A acceptance 2: the expired-only pass never converts ambiguity into
    /// success — an expired record whose session is still non-terminal stays
    /// retained and is surfaced in the bounded health state.
    #[tokio::test]
    async fn reconcile_expired_transitions_retains_ambiguous_records_fail_closed() {
        let (_dir, mut runtime, sid) = runtime_with_session(false);
        let now = DaemonRuntime::now();
        let record = expired_record("tr_reconcile_ambiguous", &sid, now);
        runtime
            .transition_journal
            .begin(record)
            .expect("begin record");

        runtime.reconcile_expired_transitions().await;

        assert_eq!(runtime.transition_journal.pending().len(), 1);
        assert_eq!(runtime.transition_recovery_health.retained_expired_total, 1);
        assert_eq!(
            runtime.transition_recovery_health.retained_expired[0],
            "tr_reconcile_ambiguous"
        );
    }

    /// P0-A review (orphan protection): an expired record whose referenced
    /// sidecar is *still live* — attested child process with a matching birth
    /// — is retained even when the session is `Closed`, and surfaced in
    /// health. Expiry plus session state alone must never clear a journal
    /// record while the sidecar it references could still be running.
    #[tokio::test]
    async fn expired_record_with_live_attested_child_is_retained_not_cleared() {
        let (_dir, mut runtime, sid) = runtime_with_session(true);
        let now = DaemonRuntime::now();
        let mut record = expired_record("tr_live_child", &sid, now);
        let pid = std::process::id();
        let birth = ownmesh_ipc::process_birth_id(pid)
            .expect("this test process is live and inspectable")
            .expect("this test process must have a birth witness");
        record.old_binding.child_pid = Some(pid);
        record.old_binding.child_process_birth = Some(birth);
        runtime
            .transition_journal
            .begin(record)
            .expect("begin record");

        runtime.reconcile_expired_transitions().await;

        assert_eq!(
            runtime.transition_journal.pending().len(),
            1,
            "a live attested sidecar must keep the record retained"
        );
        assert_eq!(
            runtime.transition_recovery_health.retained_expired_total, 1,
            "health must surface the retained record"
        );
        assert_eq!(
            runtime.transition_recovery_health.retained_expired[0],
            "tr_live_child"
        );
    }

    /// P0-A review: an expired record whose binding carries no attested child
    /// identity and whose supervisor is not connected cannot be proven moot —
    /// the sidecar might still be running under an orphaned supervisor
    /// instance. The record stays retained fail-closed (never cleared) and is
    /// surfaced in health; a later reconcile after the supervisor connects can
    /// clear it via the supervisor liveness probe.
    #[tokio::test]
    async fn expired_record_without_attestation_and_supervisor_is_retained_fail_closed() {
        let (_dir, mut runtime, sid) = runtime_with_session(true);
        let now = DaemonRuntime::now();
        let mut record = expired_record("tr_no_proof", &sid, now);
        record.old_binding.child_pid = None;
        record.old_binding.child_process_birth = None;
        runtime
            .transition_journal
            .begin(record)
            .expect("begin record");

        runtime.reconcile_expired_transitions().await;

        assert_eq!(
            runtime.transition_journal.pending().len(),
            1,
            "indeterminate proof must never clear the record"
        );
        assert_eq!(runtime.transition_recovery_health.retained_expired_total, 1);
        assert_eq!(
            runtime.transition_recovery_health.retained_expired[0],
            "tr_no_proof"
        );
    }

    /// P0-A review: when an expired record's binding carries no attested child
    /// identity, the connected supervisor's liveness probe is the authoritative
    /// proof. A session the supervisor does not track (never spawned, or
    /// removed only after successful termination) is provably moot and is
    /// cleared once session state is terminal.
    #[tokio::test]
    async fn expired_record_without_pid_is_cleared_when_supervisor_has_no_live_host() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let sidecar_root = paths.state_dir.join("session-supervisor");
        let (supervisor_server, _) =
            ownmesh_session_host::SupervisorIpcServer::new(&sidecar_root, &paths.runtime_dir)
                .unwrap();
        let endpoint = supervisor_server.endpoint().clone();
        let server = Arc::clone(supervisor_server.server());
        let server_task = tokio::spawn(async move { server.serve().await.unwrap() });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let management =
            read_management_credential(supervisor_server.credential_state_dir()).unwrap();
        let supervisor =
            SupervisorClient::bootstrap(endpoint, paths.runtime_dir.clone(), management)
                .await
                .unwrap();
        runtime.supervisor = Some(supervisor);

        let sid = {
            let info = runtime
                .sessions
                .open(
                    SessionKind::Pty,
                    "probe-clear",
                    "owner",
                    DaemonRuntime::now(),
                    None,
                )
                .unwrap();
            runtime.sessions.close(&info.id).unwrap();
            info.id
        };
        let now = DaemonRuntime::now();
        let mut record = expired_record("tr_probe_clear", &sid, now);
        record.old_binding.child_pid = None;
        record.old_binding.child_process_birth = None;
        runtime
            .transition_journal
            .begin(record)
            .expect("begin record");

        runtime.reconcile_expired_transitions().await;

        assert!(
            runtime.transition_journal.pending().is_empty(),
            "the supervisor probe proves no live sidecar; the moot record clears"
        );
        assert_eq!(runtime.transition_recovery_health.retained_expired_total, 0);
        supervisor_server.server().request_shutdown();
        server_task.await.unwrap();
    }

    /// P0-A: reconcile must never clear an expired record without
    /// authoritative proof that every host it references is dead. A
    /// crash-interleaved record whose expiry precedes its host TTL is
    /// retained fail-closed even when the session is `Closed`, and surfaced
    /// in health — never converted into a moot cleanup.
    #[tokio::test]
    async fn expired_record_with_inconsistent_host_bound_is_retained_fail_closed() {
        let (_dir, mut runtime, sid) = runtime_with_session(true);
        let now = DaemonRuntime::now();
        let mut record = expired_record("tr_bad_bound", &sid, now);
        // Inconsistent: the record expired before its host TTL, so the host
        // may still be alive. A real `begin` rejects this; the defensive
        // reconcile check must too.
        record.old_binding.host_expires_unix = now + 3600;
        runtime
            .transition_journal
            .insert_unvalidated_for_test(record.clone());

        runtime.reconcile_expired_transitions().await;

        assert_eq!(
            runtime.transition_journal.pending().len(),
            1,
            "inconsistent record must be retained fail-closed"
        );
        assert_eq!(
            runtime.transition_recovery_health.retained_expired_total, 1,
            "health must surface the retained record"
        );
        // Unrelated sessions still open — no global poison pill.
        runtime
            .sessions
            .open(SessionKind::Pty, "after-bad-bound", "owner", now, None)
            .expect("unrelated session open must succeed");
    }

    /// P0-A: a `Closed` session whose `sidecar_host` (left intact by
    /// `SessionManager::close`) still references a live host from the record
    /// must not be cleared — the record is retained fail-closed and surfaced
    /// in health.
    #[tokio::test]
    async fn closed_session_with_live_referenced_host_is_retained_fail_closed() {
        let (_dir, mut runtime, sid) = runtime_with_session(true);
        let now = DaemonRuntime::now();
        let record = expired_record("tr_live_host", &sid, now);
        // The session still carries a sidecar binding with the record's host
        // nonce, and that host is still within its TTL.
        let live = SidecarHostBinding {
            device_id: "dev_test".into(),
            workspace_id: "ws_default".into(),
            owner_principal: "owner".into(),
            host_nonce: "nonce_old".into(),
            controller_epoch: 1,
            binding_expires_unix: now - 20,
            host_expires_unix: now + 3600,
            child_pid: None,
            child_process_birth: None,
        };
        runtime
            .sessions
            .set_sidecar_host_binding(&sid, Some(live))
            .expect("set binding");
        runtime
            .transition_journal
            .insert_unvalidated_for_test(record.clone());

        runtime.reconcile_expired_transitions().await;

        assert_eq!(
            runtime.transition_journal.pending().len(),
            1,
            "record referencing a still-live host must be retained"
        );
        assert_eq!(
            runtime.transition_recovery_health.retained_expired_total, 1,
            "health must surface the retained record"
        );
    }

    /// P1-F: retained transition health is refreshed from the journal, not
    /// append-only. A record retained on an earlier pass (session still
    /// non-terminal) that is later provably moot (session closed) is cleared
    /// by the next pass and must stop being reported as unresolved.
    #[tokio::test]
    async fn retained_transition_health_is_cleared_when_record_resolves() {
        let (_dir, mut runtime, sid) = runtime_with_session(false);
        let now = DaemonRuntime::now();
        let record = expired_record("tr_resolves_later", &sid, now);
        runtime
            .transition_journal
            .begin(record)
            .expect("begin record");

        // Pass 1: session still non-terminal → retained fail-closed.
        runtime.reconcile_expired_transitions().await;
        assert_eq!(runtime.transition_journal.pending().len(), 1);
        assert_eq!(runtime.transition_recovery_health.retained_expired_total, 1);
        assert_eq!(
            runtime.transition_recovery_health.retained_expired[0],
            "tr_resolves_later"
        );

        // The session becomes terminal; pass 2 must clear the record and the
        // health state must stop reporting it.
        runtime.sessions.close(&sid).expect("close session");
        runtime.reconcile_expired_transitions().await;
        assert!(
            runtime.transition_journal.pending().is_empty(),
            "provably-moot record must be cleared"
        );
        assert_eq!(
            runtime.transition_recovery_health.retained_expired_total, 0,
            "resolved record must not stay in health"
        );
        assert!(runtime
            .transition_recovery_health
            .retained_expired
            .is_empty());
    }

    /// P0-B: a completed result larger than the durable value budget persists
    /// as a compact exact-once receipt, and the in-memory map is compacted to
    /// the same receipt after durable persistence so large result bodies are
    /// never retained indefinitely in memory either. Replay returns the
    /// receipt (never a re-execution); the caller holds the full result only
    /// for the immediate response.
    #[test]
    fn large_completed_result_persists_compacted_and_replays_receipt_in_session() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let key = Some("prin\u{1f}op_large".to_string());
        runtime
            .begin_idempotent(key.as_ref(), "op_large_1")
            .expect("begin marker");
        let big_stdout = "x".repeat(MAX_OP_JOURNAL_VALUE_BYTES + 4096);
        let body = json!({
            "approval_required": false,
            "operation_id": "op_large_1",
            "result": { "stdout": big_stdout },
            "replayed": false,
            "decision": "allow",
        });
        runtime
            .store_idempotent(key.as_ref(), &body)
            .expect("store completed");

        // In-session replay returns the compact receipt, not the huge body:
        // bounded memory, exact-once preserved (never a re-execution).
        let replayed = runtime
            .lookup_idempotent(key.as_ref())
            .expect("lookup")
            .expect("entry present");
        assert_eq!(replayed["durable_receipt"], true);
        assert_eq!(replayed["truncated"], true);
        assert!(
            replayed.get("result").is_none(),
            "in-memory replay must be the compact receipt"
        );

        // The durable file carries only the compact receipt.
        let raw = std::fs::read_to_string(paths.state_dir.join("op-journal.json")).unwrap();
        let durable: HashMap<String, Value> = serde_json::from_str(&raw).unwrap();
        let durable_entry = durable.get(key.as_deref().unwrap()).expect("durable key");
        assert_eq!(durable_entry["durable_receipt"], true);
        assert_eq!(durable_entry["truncated"], true);
        assert!(
            durable_entry.get("stdout").is_none(),
            "no body in durable state"
        );
        assert_eq!(durable_entry["operation_id"], "op_large_1");
        assert!(durable_entry
            .get(OP_JOURNAL_COMPLETED_UNIX_FIELD)
            .and_then(Value::as_i64)
            .is_some_and(|stamp| stamp > 0));
        assert!(
            raw.len() < MAX_OP_JOURNAL_VALUE_BYTES * 2,
            "durable file must stay small"
        );
    }

    /// P0-B: unknown/forward-version op-journal states are fail-closed —
    /// never compacted, never evicted, never replayed as a completed receipt.
    #[test]
    fn unknown_op_journal_state_is_fail_closed() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let key = "prin\u{1f}op_future";
        let now = DaemonRuntime::now();
        // A forward-version marker a newer release might write.
        let future = json!({
            OP_JOURNAL_STATE_FIELD: "phase_two",
            "operation_id": "op_future_1",
            "result": { "stdout": "body-must-survive" },
            OP_JOURNAL_COMPLETED_UNIX_FIELD: now - OP_JOURNAL_COMPLETED_TTL_SECS - 1,
        });
        runtime.op_journal.insert(key.into(), future.clone());

        // Replay is refused, exactly like an in-progress marker.
        let err = runtime
            .lookup_idempotent(Some(&key.to_string()))
            .unwrap_err();
        assert!(
            err.to_string().contains("uncertain"),
            "unknown state must refuse replay: {err}"
        );

        // Eviction must never touch it, even though it looks ancient.
        let evicted = runtime
            .evict_expired_completed_op_journal_entries()
            .expect("eviction");
        assert_eq!(evicted, 0, "unknown state must never be evicted");
        let kept = runtime.op_journal.get(key).expect("still present");
        assert_eq!(
            kept.get("result")
                .and_then(|v| v.get("stdout"))
                .and_then(Value::as_str),
            Some("body-must-survive"),
            "unknown state body must never be compacted away"
        );

        // The durable view keeps it verbatim too.
        let durable = op_journal_durable_view(&runtime.op_journal);
        let durable_entry = durable.get(key).expect("durable present");
        assert_eq!(
            durable_entry
                .get("result")
                .and_then(|v| v.get("stdout"))
                .and_then(Value::as_str),
            Some("body-must-survive")
        );

        // And it survives a reload from disk verbatim (bound_op_journal).
        runtime.persist_op_journal().expect("persist");
        let loaded = load_op_journal(&paths.state_dir.join("op-journal.json")).unwrap();
        let reloaded = loaded.get(key).expect("loaded");
        assert_eq!(
            reloaded
                .get("result")
                .and_then(|v| v.get("stdout"))
                .and_then(Value::as_str),
            Some("body-must-survive"),
            "reload must keep unknown-state bodies fail-closed"
        );
    }

    /// P0-B: a present-but-malformed state field (`null`, number, boolean) is
    /// *not* a completed receipt this version wrote — it must be classified
    /// uncertain (fail-closed), never compacted, never evicted, and never
    /// replayed as completed. The old classifier treated any non-string
    /// present value as `Completed`, which could hide an unfinished side
    /// effect behind a compacted receipt.
    #[test]
    fn malformed_op_journal_state_is_fail_closed() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let now = DaemonRuntime::now();
        let cases = [
            ("prin\u{1f}op_null_state".to_string(), json!(null)),
            ("prin\u{1f}op_number_state".to_string(), json!(7)),
            ("prin\u{1f}op_bool_state".to_string(), json!(true)),
        ];
        for (key, state) in &cases {
            let entry = json!({
                OP_JOURNAL_STATE_FIELD: state,
                "operation_id": format!("op_{key}"),
                "result": { "stdout": "body-must-survive" },
                OP_JOURNAL_COMPLETED_UNIX_FIELD: now - OP_JOURNAL_COMPLETED_TTL_SECS - 1,
            });
            assert_eq!(
                op_journal_entry_state(&entry),
                OpJournalEntryState::Uncertain,
                "present non-string state must be uncertain: {key}"
            );
            runtime.op_journal.insert(key.clone(), entry);
        }

        // Replay is refused for every malformed state, exactly like an
        // in-progress marker.
        for (key, _) in &cases {
            let err = runtime.lookup_idempotent(Some(key)).unwrap_err();
            assert!(
                err.to_string().contains("uncertain"),
                "malformed state must refuse replay: {key}: {err}"
            );
        }

        // Eviction must never touch them, even though they look ancient.
        let evicted = runtime
            .evict_expired_completed_op_journal_entries()
            .expect("eviction");
        assert_eq!(evicted, 0, "malformed state must never be evicted");

        // The durable view keeps them verbatim (never compacted away).
        let durable = op_journal_durable_view(&runtime.op_journal);
        for (key, _) in &cases {
            let durable_entry = durable.get(key).expect("durable present");
            assert_eq!(
                durable_entry
                    .get("result")
                    .and_then(|v| v.get("stdout"))
                    .and_then(Value::as_str),
                Some("body-must-survive"),
                "malformed state body must never be compacted away: {key}"
            );
        }

        // And they survive a reload from disk verbatim.
        runtime.persist_op_journal().expect("persist");
        let loaded = load_op_journal(&paths.state_dir.join("op-journal.json")).unwrap();
        for (key, _) in &cases {
            let reloaded = loaded.get(key).expect("loaded");
            assert_eq!(
                reloaded
                    .get("result")
                    .and_then(|v| v.get("stdout"))
                    .and_then(Value::as_str),
                Some("body-must-survive"),
                "reload must keep malformed-state bodies fail-closed: {key}"
            );
        }
    }

    /// P0-B: after a restart, replay returns the compact durable receipt —
    /// exact-once is preserved honestly (no re-execution, documented receipt).
    #[test]
    fn replay_after_restart_returns_compact_receipt() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let key = Some("prin\u{1f}op_restart".to_string());
        {
            let mut runtime = DaemonRuntime::open(&paths).unwrap();
            runtime
                .begin_idempotent(key.as_ref(), "op_restart_1")
                .unwrap();
            let body = json!({
                "approval_required": false,
                "operation_id": "op_restart_1",
                "result": { "stdout": "kept in memory only" },
                "replayed": false,
                "decision": "allow",
            });
            runtime.store_idempotent(key.as_ref(), &body).unwrap();
        }
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let replayed = runtime
            .lookup_idempotent(key.as_ref())
            .expect("lookup")
            .expect("entry present");
        assert_eq!(replayed["durable_receipt"], true);
        assert_eq!(replayed["truncated"], true);
        assert_eq!(replayed["operation_id"], "op_restart_1");
        assert!(
            replayed.get("result").is_none(),
            "restart replay must be the compact receipt"
        );
    }

    /// P0-B / control-plane retention-window synchronization: a completed
    /// receipt older than the documented idempotency window
    /// (`OP_JOURNAL_COMPLETED_TTL_SECS` = the control plane's 30-day
    /// tombstone TTL) must not be replayed — the CP hard-deletes its
    /// tombstone and dispatches the retry as a *new* operation, so returning
    /// the stale receipt would silently replace the caller's fresh
    /// operation. In-progress/uncertain markers never age out, and a young
    /// completed receipt still replays.
    #[test]
    fn completed_receipt_expires_at_the_documented_window_but_uncertain_never_does() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let now = DaemonRuntime::now();

        // Ancient completed receipt: lookup must not replay it and must drop it.
        let ancient_key = "prin\u{1f}op_ancient_lookup".to_string();
        runtime.op_journal.insert(
            ancient_key.clone(),
            json!({
                "durable_receipt": true,
                "truncated": true,
                "status": "completed",
                "operation_id": "op_ancient_lookup",
                OP_JOURNAL_COMPLETED_UNIX_FIELD: now - OP_JOURNAL_COMPLETED_TTL_SECS - 1,
            }),
        );
        assert!(
            runtime
                .lookup_idempotent(Some(&ancient_key))
                .expect("lookup")
                .is_none(),
            "a completed receipt past the retention window must not be replayed"
        );
        assert!(
            !runtime.op_journal.contains_key(&ancient_key),
            "the expired receipt must be removed from the journal"
        );
        let durable: HashMap<String, Value> = serde_json::from_str(
            &std::fs::read_to_string(paths.state_dir.join("op-journal.json")).unwrap(),
        )
        .unwrap();
        assert!(
            !durable.contains_key(&ancient_key),
            "the expired receipt must not remain durable"
        );

        // Ancient in-progress marker: NEVER expires (fail-closed — an
        // uncertain outcome must not become retriable).
        let in_progress_key = "prin\u{1f}op_stale_inflight".to_string();
        runtime.op_journal.insert(
            in_progress_key.clone(),
            json!({
                OP_JOURNAL_STATE_FIELD: OP_JOURNAL_IN_PROGRESS,
                "operation_id": "op_stale_inflight",
                OP_JOURNAL_COMPLETED_UNIX_FIELD: now - OP_JOURNAL_COMPLETED_TTL_SECS - 10,
            }),
        );
        let err = runtime
            .lookup_idempotent(Some(&in_progress_key))
            .unwrap_err();
        assert!(
            err.to_string().contains("in-progress"),
            "ancient in-progress marker must stay refused, not expired: {err}"
        );
        assert!(
            runtime.op_journal.contains_key(&in_progress_key),
            "ancient in-progress marker must not be removed"
        );

        // Unknown/forward-version state: never expired.
        let unknown_key = "prin\u{1f}op_stale_unknown".to_string();
        runtime.op_journal.insert(
            unknown_key.clone(),
            json!({
                "operation_id": "op_stale_unknown",
                "result": { "stdout": "body-must-survive" },
                OP_JOURNAL_COMPLETED_UNIX_FIELD: now - OP_JOURNAL_COMPLETED_TTL_SECS - 10,
            }),
        );
        let err = runtime.lookup_idempotent(Some(&unknown_key)).unwrap_err();
        assert!(err.to_string().contains("uncertain"), "{err}");
        assert!(runtime.op_journal.contains_key(&unknown_key));

        // Young completed receipt: still replayed (within the window).
        let young_key = "prin\u{1f}op_young".to_string();
        runtime.op_journal.insert(
            young_key.clone(),
            json!({
                "durable_receipt": true,
                "truncated": true,
                "status": "completed",
                "operation_id": "op_young",
                OP_JOURNAL_COMPLETED_UNIX_FIELD: now - 60,
            }),
        );
        let replayed = runtime
            .lookup_idempotent(Some(&young_key))
            .expect("lookup")
            .expect("young receipt present");
        assert_eq!(replayed["operation_id"], "op_young");

        // Full restart path: after a reload, the expired receipt is not
        // returned either (the loaded journal is compacted, so the ancient
        // receipt would only survive if the window check were skipped).
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let now = DaemonRuntime::now();
        runtime.op_journal.insert(
            "prin\u{1f}op_ancient_2".into(),
            json!({
                "durable_receipt": true,
                "truncated": true,
                "status": "completed",
                "operation_id": "op_ancient_2",
                OP_JOURNAL_COMPLETED_UNIX_FIELD: now - OP_JOURNAL_COMPLETED_TTL_SECS - 5,
            }),
        );
        assert!(
            runtime
                .lookup_idempotent(Some(&"prin\u{1f}op_ancient_2".to_string()))
                .expect("lookup")
                .is_none(),
            "expired receipt must never replay after restart either"
        );
    }

    /// P0-B: in-progress/uncertain markers are never compacted, never evicted,
    /// and replay of an in-progress key stays refused (exact-once preserved).
    #[test]
    fn in_progress_markers_survive_compaction_and_eviction() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let key = Some("prin\u{1f}op_inflight".to_string());
        runtime
            .begin_idempotent(key.as_ref(), "op_inflight_1")
            .expect("begin marker");
        // Plant an ancient completed receipt directly to force eviction.
        let old = json!({
            "durable_receipt": true,
            "truncated": true,
            "status": "completed",
            "operation_id": "op_ancient",
            OP_JOURNAL_COMPLETED_UNIX_FIELD: DaemonRuntime::now() - OP_JOURNAL_COMPLETED_TTL_SECS - 1,
        });
        runtime
            .op_journal
            .insert("prin\u{1f}op_ancient".into(), old);

        let evicted = runtime
            .evict_expired_completed_op_journal_entries()
            .expect("eviction");
        assert_eq!(evicted, 1, "only the old completed receipt is evicted");
        assert!(
            runtime.op_journal_key_is_in_progress_for_test("op_inflight"),
            "in-progress marker must survive eviction"
        );
        assert!(
            !runtime.has_op_journal_key_for_test("op_ancient"),
            "old completed receipt removed"
        );
        // The durable file keeps the in-progress marker verbatim (no compaction).
        let raw = std::fs::read_to_string(paths.state_dir.join("op-journal.json")).unwrap();
        let durable: HashMap<String, Value> = serde_json::from_str(&raw).unwrap();
        let marker = durable.get(key.as_deref().unwrap()).unwrap();
        assert_eq!(
            marker.get(OP_JOURNAL_STATE_FIELD).and_then(Value::as_str),
            Some(OP_JOURNAL_IN_PROGRESS)
        );
        // Replay of an in-progress key stays refused.
        let err = runtime.lookup_idempotent(key.as_ref()).unwrap_err();
        assert!(err.to_string().contains("in-progress"), "{err}");
    }

    /// #142: a terminal execution failure must reconcile its reserved marker
    /// into a compact failed receipt instead of stranding an eternal
    /// in_progress key. A crash between reserve and terminal result keeps the
    /// marker (exact-once commit point), which is what this test's starting
    /// point models.
    #[test]
    fn terminal_failure_reconciles_in_progress_marker_into_failed_receipt() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let journal_key = Some("prin\u{1f}op_failed".to_string());
        runtime
            .begin_idempotent(journal_key.as_ref(), "op_failed_1")
            .expect("begin marker");
        assert!(runtime.op_journal_key_is_in_progress_for_test("op_failed"));

        let reconciled = runtime.reconcile_failed_idempotent(
            "op_failed",
            "prin",
            "op_failed_1",
            app_error::INVALID_PARAMS,
            "no such file",
        );
        assert!(reconciled, "own in-progress marker must reconcile");
        assert!(
            !runtime.op_journal_key_is_in_progress_for_test("op_failed"),
            "marker no longer in progress after reconciliation"
        );

        // The durable file holds the compact failed receipt, not the marker.
        let raw = std::fs::read_to_string(paths.state_dir.join("op-journal.json")).unwrap();
        let durable: HashMap<String, Value> = serde_json::from_str(&raw).unwrap();
        let receipt = durable.get(journal_key.as_deref().unwrap()).unwrap();
        assert!(
            receipt.get(OP_JOURNAL_STATE_FIELD).is_none(),
            "compacted receipts classify via positive proof, not the marker field"
        );
        assert_eq!(
            receipt.get("status").and_then(Value::as_str),
            Some("failed")
        );
        assert_eq!(receipt.get("durable_receipt"), Some(&Value::Bool(true)));
        let error = receipt
            .get("error")
            .expect("bounded error object survives compaction");
        assert_eq!(
            error.get("code").and_then(Value::as_i64),
            Some(app_error::INVALID_PARAMS)
        );
        assert_eq!(
            error.get("message").and_then(Value::as_str),
            Some("no such file")
        );
        assert_eq!(error.get("retryable"), Some(&Value::Bool(false)));

        // Reconciling again (or after any other terminal outcome) is a no-op.
        let again = runtime.reconcile_failed_idempotent(
            "op_failed",
            "prin",
            "op_failed_1",
            app_error::INTERNAL,
            "second attempt",
        );
        assert!(!again, "completed receipts are never rewritten");
    }

    /// #142 safety envelope: reconciliation only touches this operation's own
    /// in_progress marker — foreign operation ids, unknown keys, and
    /// completed/uncertain entries stay untouched.
    #[test]
    fn failure_reconciliation_is_scoped_to_the_own_in_progress_marker() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();

        // Unknown key: nothing to reconcile.
        assert!(!runtime.reconcile_failed_idempotent(
            "missing",
            "prin",
            "op_x",
            app_error::INTERNAL,
            "boom"
        ));

        // Marker reserved under a different operation id: never clobbered.
        let key = Some("prin\u{1f}op_other".to_string());
        runtime
            .begin_idempotent(key.as_ref(), "op_reserved_by_a")
            .expect("begin");
        assert!(!runtime.reconcile_failed_idempotent(
            "op_other",
            "prin",
            "op_reserved_by_b",
            app_error::INTERNAL,
            "boom"
        ));
        assert!(
            runtime.op_journal_key_is_in_progress_for_test("op_other"),
            "foreign operation id must not reconcile"
        );

        // Uncertain (unknown state) entries stay verbatim fail-closed.
        runtime.op_journal.insert(
            "prin\u{1f}op_uncertain".into(),
            json!({
                OP_JOURNAL_STATE_FIELD: "phase_two",
                "operation_id": "op_uncertain_1",
            }),
        );
        assert!(!runtime.reconcile_failed_idempotent(
            "op_uncertain",
            "prin",
            "op_uncertain_1",
            app_error::INTERNAL,
            "boom"
        ));
        assert!(runtime.has_op_journal_key_for_test("prin\u{1f}op_uncertain"));
        let entry = runtime
            .op_journal
            .get("prin\u{1f}op_uncertain")
            .unwrap()
            .clone();
        assert_eq!(
            entry.get(OP_JOURNAL_STATE_FIELD).and_then(Value::as_str),
            Some("phase_two")
        );

        // Completed receipts stay untouched (a replayed success is intact).
        let completed = json!({
            "durable_receipt": true,
            "truncated": true,
            "status": "completed",
            "operation_id": "op_done",
            OP_JOURNAL_COMPLETED_UNIX_FIELD: DaemonRuntime::now(),
        });
        runtime
            .op_journal
            .insert("prin\u{1f}op_done".into(), completed);
        assert!(!runtime.reconcile_failed_idempotent(
            "op_done",
            "prin",
            "op_done",
            app_error::INTERNAL,
            "boom"
        ));
        assert!(runtime.has_op_journal_key_for_test("prin\u{1f}op_done"));
    }

    /// P0-B: near capacity, only old completed receipts are evicted; a fresh
    /// side-effect key is still accepted afterwards.
    #[test]
    fn near_capacity_evicts_old_completed_before_accepting_new_keys() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        // Fill to the entry cap with ancient completed receipts.
        let now = DaemonRuntime::now();
        for i in 0..MAX_OP_JOURNAL_ENTRIES {
            let key = format!("prin\u{1f}op_fill_{i}");
            let old = json!({
                "durable_receipt": true,
                "truncated": true,
                "status": "completed",
                "operation_id": format!("op_fill_{i}"),
                OP_JOURNAL_COMPLETED_UNIX_FIELD: now - OP_JOURNAL_COMPLETED_TTL_SECS - 1,
            });
            runtime.op_journal.insert(key, old);
        }
        assert_eq!(runtime.op_journal.len(), MAX_OP_JOURNAL_ENTRIES);

        let key = Some("prin\u{1f}op_new_1".to_string());
        runtime
            .begin_idempotent(key.as_ref(), "op_new_1")
            .expect("eviction makes room for a new side-effect key");
        assert!(runtime.has_op_journal_key_for_test("op_new_1"));
        assert!(
            runtime.op_journal.len() < MAX_OP_JOURNAL_ENTRIES,
            "old completed receipts evicted"
        );
    }

    /// P0-B: at the durable *byte* cap, `maybe_make_op_journal_room` evicts
    /// only old completed receipts (never uncertain/in-progress entries) and
    /// a new side-effect key is still accepted. The exact durable-byte
    /// estimate — the same pretty-serialized view persistence writes — is
    /// what triggers the eviction, so the real 4 MiB budget is never
    /// silently exceeded while the estimate still claims headroom.
    #[test]
    fn byte_cap_evicts_old_completed_before_accepting_new_keys() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let now = DaemonRuntime::now();
        // A large uncertain entry (kept verbatim fail-closed, never evicted)
        // plus old completed receipts: the durable view exceeds the byte cap.
        let big_body = "u".repeat(4_000_000);
        runtime.op_journal.insert(
            "prin\u{1f}op_uncertain_big".into(),
            json!({
                OP_JOURNAL_STATE_FIELD: "phase_two",
                "operation_id": "op_uncertain_big",
                "result": { "stdout": big_body },
            }),
        );
        for i in 0..2000 {
            let key = format!("prin\u{1f}op_old_{i}");
            runtime.op_journal.insert(
                key,
                json!({
                    "durable_receipt": true,
                    "truncated": true,
                    "status": "completed",
                    "operation_id": format!("op_old_{i}"),
                    OP_JOURNAL_COMPLETED_UNIX_FIELD: now - OP_JOURNAL_COMPLETED_TTL_SECS - 1,
                }),
            );
        }
        assert!(
            runtime.op_journal_durable_byte_estimate() >= MAX_OP_JOURNAL_FILE_BYTES,
            "fixture must exceed the durable byte budget"
        );
        let key = Some("prin\u{1f}op_new_byte".to_string());
        runtime
            .begin_idempotent(key.as_ref(), "op_new_byte")
            .expect("eviction makes byte room for a new side-effect key");
        assert!(runtime.has_op_journal_key_for_test("op_new_byte"));
        // The uncertain entry is preserved verbatim (never evicted).
        assert!(runtime.has_op_journal_key_for_test("prin\u{1f}op_uncertain_big"));
        // The old completed receipts were evicted.
        assert!(!runtime.has_op_journal_key_for_test("prin\u{1f}op_old_0"));
        // The durable file is under the budget again.
        let on_disk = std::fs::metadata(paths.state_dir.join("op-journal.json"))
            .unwrap()
            .len() as usize;
        assert!(
            on_disk < MAX_OP_JOURNAL_FILE_BYTES,
            "durable file must be under budget after eviction, got {on_disk}"
        );
    }

    /// P0-B review (near-capacity behavior): a journal that is still *under*
    /// the durable byte budget, but where the incoming in-progress marker
    /// would push the serialized file over it, must evict expired completed
    /// receipts instead of refusing the new side-effect key with a byte-budget
    /// failure. This pins the bounded lifecycle: long-lived normal operation
    /// prunes terminal receipts proactively rather than hitting the hard cap,
    /// and the refusal path is reserved for genuinely non-evictable pressure.
    #[test]
    fn near_byte_cap_evicts_before_the_incoming_marker_insert() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let now = DaemonRuntime::now();
        // A few expired completed receipts that ARE evictable. They are added
        // BEFORE the body is sized so the linear size computation below
        // accounts for them.
        for i in 0..4 {
            runtime.op_journal.insert(
                format!("prin\u{1f}op_near_old_{i}"),
                json!({
                    "durable_receipt": true,
                    "truncated": true,
                    "status": "completed",
                    "operation_id": format!("op_near_old_{i}"),
                    OP_JOURNAL_COMPLETED_UNIX_FIELD: now - OP_JOURNAL_COMPLETED_TTL_SECS - 1,
                }),
            );
        }
        // A large uncertain entry is kept verbatim (fail-closed, never
        // evicted). Size it so the current durable estimate lands within one
        // marker's worth of the byte cap: inserting the marker would exceed
        // the budget, but evicting the old completed receipts frees room.
        runtime.op_journal.insert(
            "prin\u{1f}op_near_uncertain".into(),
            json!({
                OP_JOURNAL_STATE_FIELD: "phase_two",
                "operation_id": "op_near_uncertain",
                "result": { "stdout": "x" },
            }),
        );
        let base = runtime.op_journal_durable_byte_estimate();
        // Empirical marginal serialized cost of one extra in-progress marker
        // entry in the pretty-printed durable view (the standalone-object size
        // overestimates because map framing and the trailing newline are
        // shared).
        let mut probe = runtime.op_journal.clone();
        probe.insert(
            "prin\u{1f}op_near_probe".into(),
            json!({
                OP_JOURNAL_STATE_FIELD: OP_JOURNAL_IN_PROGRESS,
                "operation_id": "op_probe",
            }),
        );
        let marginal = serde_json::to_vec_pretty(&op_journal_durable_view(&probe))
            .unwrap()
            .len()
            .saturating_sub(base);
        assert!(marginal > 0, "marker marginal size must be positive");
        // The durable size is linear in the body length (plain 'x' characters
        // need no JSON escaping): size = constant + body_len, where the
        // constant covers framing and the four receipt entries. Target the
        // current estimate exactly one byte under the projected cap so the
        // incoming marker pushes the durable file over it.
        let constant = base.saturating_sub(1).saturating_sub(2);
        let body_len = (MAX_OP_JOURNAL_FILE_BYTES + 1)
            .saturating_sub(marginal)
            .saturating_sub(constant)
            .saturating_sub(1);
        runtime.op_journal.insert(
            "prin\u{1f}op_near_uncertain".into(),
            json!({
                OP_JOURNAL_STATE_FIELD: "phase_two",
                "operation_id": "op_near_uncertain",
                "result": { "stdout": "x".repeat(body_len) },
            }),
        );
        let current = runtime.op_journal_durable_byte_estimate();
        assert!(
            current < MAX_OP_JOURNAL_FILE_BYTES,
            "fixture must be under the byte cap, got {current}"
        );
        let mut projected = runtime.op_journal.clone();
        projected.insert(
            "prin\u{1f}op_near_new".to_string(),
            json!({
                OP_JOURNAL_STATE_FIELD: OP_JOURNAL_IN_PROGRESS,
                "operation_id": "op_near_new",
            }),
        );
        let projected_bytes = serde_json::to_vec_pretty(&op_journal_durable_view(&projected))
            .unwrap()
            .len();
        assert!(
            projected_bytes >= MAX_OP_JOURNAL_FILE_BYTES,
            "fixture must be within one marker of the byte cap (current {current}, projected {projected_bytes})"
        );
        // The near-capacity journal must accept the new side-effect key by
        // evicting the expired receipts — previously it refused with a
        // byte-budget persist failure even though receipts were evictable.
        runtime
            .begin_idempotent(
                Some("prin\u{1f}op_near_new".to_string()).as_ref(),
                "op_near_new",
            )
            .expect("near-capacity journal with evictable receipts must accept a new key");
        assert!(runtime.has_op_journal_key_for_test("op_near_new"));
        // The uncertain entry is preserved verbatim; the expired receipts were
        // evicted; the durable file is under budget again.
        assert!(runtime.has_op_journal_key_for_test("prin\u{1f}op_near_uncertain"));
        assert!(!runtime.has_op_journal_key_for_test("prin\u{1f}op_near_old_0"));
        let on_disk = std::fs::metadata(paths.state_dir.join("op-journal.json"))
            .unwrap()
            .len() as usize;
        assert!(
            on_disk < MAX_OP_JOURNAL_FILE_BYTES,
            "durable file must be under budget after near-capacity eviction, got {on_disk}"
        );
    }

    /// P0-B: at capacity with nothing evictable (all in-progress), new
    /// side-effect keys are refused fail-closed — never evicting an uncertain
    /// outcome to make room.
    #[test]
    fn at_capacity_with_only_in_progress_refuses_new_keys() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        for i in 0..MAX_OP_JOURNAL_ENTRIES {
            let key = format!("prin\u{1f}op_busy_{i}");
            let marker = json!({
                OP_JOURNAL_STATE_FIELD: OP_JOURNAL_IN_PROGRESS,
                "operation_id": format!("op_busy_{i}"),
            });
            runtime.op_journal.insert(key, marker);
        }
        let err = runtime
            .begin_idempotent(Some("prin\u{1f}op_extra".to_string()).as_ref(), "op_extra")
            .unwrap_err();
        assert!(
            err.to_string().contains("capacity"),
            "must refuse at capacity: {err}"
        );
        assert_eq!(runtime.op_journal.len(), MAX_OP_JOURNAL_ENTRIES);
    }

    /// P0-B: an eviction persist fault rolls back the in-memory eviction so
    /// the durable file stays authoritative (no partial lifecycle).
    #[test]
    fn eviction_persist_fault_rolls_back_in_memory() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let now = DaemonRuntime::now();
        let key = "prin\u{1f}op_faulty";
        let old = json!({
            "durable_receipt": true,
            "truncated": true,
            "status": "completed",
            "operation_id": "op_faulty",
            OP_JOURNAL_COMPLETED_UNIX_FIELD: now - OP_JOURNAL_COMPLETED_TTL_SECS - 1,
        });
        runtime.op_journal.insert(key.into(), old);
        // Fault the next op-journal persist (eviction's own write).
        runtime.fail_op_journal_persist_on_nth_call_for_test(1);
        let err = runtime
            .evict_expired_completed_op_journal_entries()
            .expect_err("persist fault must fail eviction");
        assert!(err.to_string().contains("fault-injected"), "{err}");
        assert!(
            runtime.op_journal.contains_key(key),
            "in-memory eviction must roll back on persist failure"
        );
    }

    /// P0-B: a legacy (pre-1.2.13) op journal with large completed bodies is
    /// compacted at load AND the compacted result is persisted back to disk, so
    /// large stdout/file bodies are not retained indefinitely. In-progress
    /// markers stay verbatim.
    #[test]
    fn legacy_op_journal_is_compacted_and_persisted_at_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("op-journal.json");
        let big_body = "x".repeat(80 * 1024);
        let legacy = serde_json::json!({
            "prin\u{1f}op_done": {
                "status": "completed",
                "operation_id": "op_done",
                "approval_required": false,
                "replayed": false,
                "decision": "allow",
                "result": { "stdout": big_body }
            },
            "prin\u{1f}op_busy": {
                "__ownmesh_operation_state": "in_progress",
                "operation_id": "op_busy"
            }
        });
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let journal = load_op_journal(&path).expect("legacy journal loads");
        // Completed entry is a compact receipt (no result body).
        let done = journal.get("prin\u{1f}op_done").unwrap();
        assert_eq!(
            done.get("durable_receipt").and_then(Value::as_bool),
            Some(true)
        );
        assert!(done.get("result").is_none(), "large body must be compacted");
        assert!(
            done.get(OP_JOURNAL_COMPLETED_UNIX_FIELD).is_some(),
            "legacy completed entry stamped for the bounded lifecycle"
        );
        // In-progress marker stays verbatim.
        let busy = journal.get("prin\u{1f}op_busy").unwrap();
        assert_eq!(
            busy.get(OP_JOURNAL_STATE_FIELD).and_then(Value::as_str),
            Some(OP_JOURNAL_IN_PROGRESS)
        );
        // The durable file was rewritten compacted (P0-B finding: load must
        // persist the compaction, not only compact in memory).
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.len() < 4 * 1024,
            "durable file must be compacted after load, got {} bytes",
            raw.len()
        );
        let durable: HashMap<String, Value> = serde_json::from_str(&raw).unwrap();
        assert!(
            durable
                .get("prin\u{1f}op_done")
                .unwrap()
                .get("result")
                .is_none(),
            "durable file must not retain the large body"
        );
    }

    /// P0-B: a legacy journal above the durable byte budget is still loaded
    /// when compaction brings it under budget (bounded read), instead of being
    /// rejected before compaction.
    #[test]
    fn legacy_op_journal_above_budget_is_compacted_not_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("op-journal.json");
        let big_body = "y".repeat(5 * 1024 * 1024);
        let legacy = serde_json::json!({
            "prin\u{1f}op_huge": {
                "status": "completed",
                "operation_id": "op_huge",
                "approval_required": false,
                "replayed": false,
                "decision": "allow",
                "result": { "stdout": big_body }
            }
        });
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert!(
            std::fs::metadata(&path).unwrap().len() > MAX_OP_JOURNAL_FILE_BYTES as u64,
            "fixture must exceed the durable budget"
        );
        let journal = load_op_journal(&path).expect("over-budget legacy journal compacts at load");
        assert_eq!(journal.len(), 1);
        assert_eq!(
            journal
                .get("prin\u{1f}op_huge")
                .unwrap()
                .get("durable_receipt")
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    /// P0-B: the durable byte estimate must match the real persisted file
    /// exactly (same pretty-serialized durable view `persist_op_journal`
    /// writes). The old per-entry sum omitted JSON framing and pretty-print
    /// overhead, so eviction and `system.diagnose` under-reported pressure
    /// and the real file could hit the hard 4 MiB cap while the estimate
    /// still claimed headroom.
    #[test]
    fn op_journal_durable_byte_estimate_matches_persisted_file() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let now = DaemonRuntime::now();
        // A mix of completed receipts (with a >64KiB result body that must be
        // compacted away) and in-progress markers, so the estimate covers both
        // the compacted view and the verbatim uncertain entries.
        let big_body = "z".repeat(80 * 1024);
        for i in 0..8 {
            let key = format!("prin\u{1f}op_est_{i}");
            runtime.op_journal.insert(
                key,
                json!({
                    "status": "completed",
                    "operation_id": format!("op_est_{i}"),
                    "approval_required": false,
                    "replayed": false,
                    "decision": "allow",
                    "result": { "stdout": big_body },
                    OP_JOURNAL_COMPLETED_UNIX_FIELD: now - 1,
                }),
            );
        }
        runtime.op_journal.insert(
            "prin\u{1f}op_est_busy".into(),
            json!({
                OP_JOURNAL_STATE_FIELD: OP_JOURNAL_IN_PROGRESS,
                "operation_id": "op_est_busy",
            }),
        );
        let estimate = runtime.op_journal_durable_byte_estimate();
        runtime.persist_op_journal().expect("persist");
        let on_disk = std::fs::metadata(paths.state_dir.join("op-journal.json"))
            .unwrap()
            .len() as usize;
        assert_eq!(
            estimate, on_disk,
            "durable byte estimate must equal the persisted file size (estimate {estimate}, file {on_disk})"
        );
        // The estimate is the compacted view: the >64KiB bodies are not
        // retained in durable state.
        assert!(
            estimate < 8 * 1024,
            "compacted durable view must stay small, got {estimate} bytes"
        );
        // The in-progress marker is preserved verbatim in the durable view.
        let durable = op_journal_durable_view(&runtime.op_journal);
        assert_eq!(
            durable
                .get("prin\u{1f}op_est_busy")
                .and_then(|v| v.get(OP_JOURNAL_STATE_FIELD))
                .and_then(Value::as_str),
            Some(OP_JOURNAL_IN_PROGRESS)
        );
    }

    /// P0-B: the compact receipt preserves `remote_payload_hash` so an
    /// identical `review.start` retry within the retention window replays the
    /// receipt instead of failing the payload binding check.
    #[test]
    fn op_journal_durable_view_preserves_remote_payload_hash() {
        let mut journal = HashMap::new();
        journal.insert(
            "prin\u{1f}op_review".into(),
            json!({
                "status": "completed",
                "operation_id": "op_review",
                "approval_required": false,
                "replayed": false,
                "decision": "allow",
                "remote_payload_hash": "a".repeat(64),
                "result": { "stdout": "review output" }
            }),
        );
        let view = op_journal_durable_view(&journal);
        let receipt = view.get("prin\u{1f}op_review").unwrap();
        assert_eq!(
            receipt.get("remote_payload_hash").and_then(Value::as_str),
            Some("a".repeat(64).as_str()),
            "replay binding must survive compaction"
        );
        assert!(receipt.get("result").is_none());
    }

    /// P0-B: a compacted `review.start` receipt must preserve `review_id` —
    /// `review.show`/`review.page` need it to continue the review, so an
    /// idempotent replay after compaction or restart must still return it.
    #[test]
    fn op_journal_durable_view_preserves_review_id() {
        let mut journal = HashMap::new();
        journal.insert(
            "prin\u{1f}op_review".into(),
            json!({
                "status": "completed",
                "operation_id": "op_review",
                "review_id": "rev_abc123",
                "workspace_id": "ws_default",
                "remote_payload_hash": "a".repeat(64),
                "result": { "stdout": "review output" }
            }),
        );
        let view = op_journal_durable_view(&journal);
        let receipt = view.get("prin\u{1f}op_review").unwrap();
        assert_eq!(
            receipt.get("review_id").and_then(Value::as_str),
            Some("rev_abc123"),
            "review.show/page identifier must survive compaction"
        );
        assert_eq!(
            receipt.get("workspace_id").and_then(Value::as_str),
            Some("ws_default"),
            "workspace binding must survive compaction"
        );
        assert!(receipt.get("result").is_none());

        // Full lifecycle: store, persist, reload, replay — the review_id
        // stays on the receipt so the client can continue the review.
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let key = Some("prin\u{1f}op_review_lifecycle".to_string());
        {
            let mut runtime = DaemonRuntime::open(&paths).unwrap();
            runtime
                .begin_idempotent(key.as_ref(), "op_review_1")
                .unwrap();
            let body = json!({
                "approval_required": false,
                "operation_id": "op_review_1",
                "review_id": "rev_lifecycle_1",
                "workspace_id": "ws_default",
                "result": { "stdout": "kept in memory only" },
                "replayed": false,
                "decision": "allow",
            });
            runtime.store_idempotent(key.as_ref(), &body).unwrap();
        }
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let replayed = runtime
            .lookup_idempotent(key.as_ref())
            .expect("lookup")
            .expect("entry present");
        assert_eq!(replayed["durable_receipt"], true);
        assert_eq!(
            replayed.get("review_id").and_then(Value::as_str),
            Some("rev_lifecycle_1"),
            "restart replay must keep the review identifier"
        );
        assert!(replayed.get("result").is_none());
    }

    /// P0-B regression (review): the completed `review.start` journal entry is
    /// the serialized `ReviewManifest`, which stores the control-plane id as
    /// `remote_operation_id` — NOT the `operation_id` exact-once marker that
    /// `begin_idempotent` writes and the compaction classifier requires. An
    /// entry without `operation_id` was classified uncertain: compaction
    /// refused to shrink it (retaining pins/argv durably) and a retried
    /// `review.start` after restart/response-loss received an in-progress/
    /// uncertain CONFLICT instead of the documented receipt. The handler now
    /// stamps `operation_id` onto the body before `store_idempotent`; this
    /// test proves the real manifest shape classifies, compacts, and replays.
    #[test]
    fn review_manifest_receipt_classifies_compacts_and_replays() {
        // The exact body `handle_review_start` stores: `finish()` returns the
        // manifest, the handler adds `remote_payload_hash` and (after the
        // fix) `operation_id`.
        let manifest = review_fixture_manifest();
        let mut without_operation_id = serde_json::to_value(manifest.clone()).unwrap();
        if let Some(object) = without_operation_id.as_object_mut() {
            object.insert("remote_payload_hash".into(), json!("a".repeat(64)));
        }
        // Fail-closed regression: the pre-fix shape must NEVER be treated as
        // a completed receipt (that is what made a finished review replay as
        // an uncertain conflict).
        assert_eq!(
            op_journal_entry_state(&without_operation_id),
            OpJournalEntryState::Uncertain,
            "ReviewManifest body without the exact-once operation_id must stay uncertain"
        );
        assert!(
            !op_journal_durable_view(&HashMap::from([(
                "prin\u{1f}op_review_real".to_string(),
                without_operation_id.clone()
            )]))
            .get("prin\u{1f}op_review_real")
            .unwrap()
            .get("durable_receipt")
            .and_then(Value::as_bool)
            .unwrap_or(false),
            "pre-fix body must not be compacted (would hide the unfinished state)"
        );

        // Post-fix shape: `operation_id` is stamped, so the entry is a
        // provably-completed receipt and compacts to a bounded receipt that
        // preserves the continuation identifiers (`review_id`, `workspace_id`,
        // `remote_payload_hash`) while dropping pins/argv/result metadata.
        let mut completed = serde_json::to_value(manifest.clone()).unwrap();
        if let Some(object) = completed.as_object_mut() {
            object.insert("operation_id".into(), json!("op_review_real_1"));
            object.insert("remote_payload_hash".into(), json!("a".repeat(64)));
        }
        assert_eq!(
            op_journal_entry_state(&completed),
            OpJournalEntryState::Completed,
            "operation_id + review_id is a completed receipt"
        );
        let view = op_journal_durable_view(&HashMap::from([(
            "prin\u{1f}op_review_real".to_string(),
            completed.clone(),
        )]));
        let receipt = view.get("prin\u{1f}op_review_real").unwrap();
        assert_eq!(receipt["durable_receipt"], true);
        assert_eq!(
            receipt.get("review_id").and_then(Value::as_str),
            Some("rev_manifest_1"),
            "review.show/page identifier must survive compaction"
        );
        assert_eq!(
            receipt.get("workspace_id").and_then(Value::as_str),
            Some("ws_default"),
            "workspace binding must survive compaction"
        );
        assert_eq!(
            receipt.get("remote_payload_hash").and_then(Value::as_str),
            Some("a".repeat(64).as_str()),
            "replay binding must survive compaction"
        );
        assert_eq!(
            receipt.get("operation_id").and_then(Value::as_str),
            Some("op_review_real_1")
        );
        assert!(
            receipt.get("command").is_none(),
            "pinned argv must not survive compaction"
        );
        assert!(receipt.get("tests").is_none(), "test pins must not survive");

        // Full lifecycle through the journal: begin marker, store the real
        // manifest body, replay in-session and after a restart.
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let key = Some("prin\u{1f}op_review_lifecycle_real".to_string());
        {
            let mut runtime = DaemonRuntime::open(&paths).unwrap();
            runtime
                .begin_idempotent(key.as_ref(), "op_review_real_1")
                .unwrap();
            runtime.store_idempotent(key.as_ref(), &completed).unwrap();
            // In-session replay: the receipt, never a conflict, never a
            // re-execution, and never the full manifest body.
            let replayed = runtime
                .lookup_idempotent(key.as_ref())
                .expect("lookup")
                .expect("entry present");
            assert_eq!(replayed["durable_receipt"], true);
            assert_eq!(
                replayed.get("review_id").and_then(Value::as_str),
                Some("rev_manifest_1")
            );
            assert!(replayed.get("command").is_none());
        }
        // Restart: bound_op_journal compacts the completed entry at load and
        // the replay still returns the receipt with the continuation ids.
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let replayed = runtime
            .lookup_idempotent(key.as_ref())
            .expect("lookup after restart")
            .expect("entry present after restart");
        assert_eq!(replayed["durable_receipt"], true);
        assert_eq!(
            replayed.get("review_id").and_then(Value::as_str),
            Some("rev_manifest_1"),
            "restart replay must keep the review identifier"
        );
        assert_eq!(
            replayed.get("remote_payload_hash").and_then(Value::as_str),
            Some("a".repeat(64).as_str())
        );
        assert!(replayed.get("result").is_none());
    }

    /// A `ReviewManifest` in the exact serialized shape `handle_review_start`
    /// persists (pins, cursors, control-plane ids).
    fn review_fixture_manifest() -> ReviewManifest {
        let pin = ExecutablePin {
            path: std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            content_sha256: sha256_hex(b"fixture"),
            len: 7,
            device: None,
            inode: None,
            path_device: None,
            path_inode: None,
            link_target: None,
            policy_kind: "structured".into(),
        };
        ReviewManifest {
            review_id: "rev_manifest_1".into(),
            device_id: "dev_test".into(),
            workspace_id: "ws_default".into(),
            repo_root: std::env::temp_dir().to_string_lossy().into_owned(),
            head_oid: "0".repeat(40),
            principal: "client:local:test".into(),
            phase: ReviewPhase::Completed,
            command: Some(ReviewCommand {
                program: "/bin/true".into(),
                args: vec!["--version".into()],
                timeout_ms: 1000,
                invocation_pin: None,
                pin: pin.clone(),
            }),
            tests: vec![TestRequest {
                program: "/bin/true".into(),
                args: vec![],
                timeout_ms: 1000,
                invocation_pin: None,
                pin,
            }],
            remote_operation_id: Some("op_review_remote_1".into()),
            remote_payload_hash: Some("a".repeat(64)),
            status_cursor: 0,
            diff_cursor: 0,
            result_sha256: Some("b".repeat(64)),
            created_unix: 1_000_000,
            expires_unix: 1_000_000 + 3600,
        }
    }

    /// P0-B continuation identifiers: compact receipts must keep the small
    /// identifiers a client needs to continue an operation whose response was
    /// lost after compaction/restart. `session.open` returns the generated
    /// session `id` and its controller lease at the top level;
    /// `session.attach`/`session.claim` return the session snapshot nested
    /// under `session`. Dropping them would make a retried `session.open` /
    /// `session.attach` unable to continue the session.
    #[test]
    fn op_journal_durable_view_preserves_session_continuation_identifiers() {
        // session.open-shaped completed entry (SessionInfo serialized at the
        // top level, plus a large stdout body that must still be dropped).
        let mut journal = HashMap::new();
        journal.insert(
            "prin\u{1f}op_session_open".into(),
            json!({
                "status": "completed",
                "operation_id": "op_session_open_1",
                "id": "sess_abc123",
                "kind": "pty",
                "state": "running",
                "controller": {
                    "principal_id": "p1",
                    "lease_id": "lease_1",
                    "epoch": 3,
                    "expires_unix": 1_900_000_000,
                },
                "controller_epoch": 3,
                "workspace_id": "ws_default",
                "live_pty": true,
                "decision": "allow",
                "stdout": "x".repeat(200_000),
            }),
        );
        let view = op_journal_durable_view(&journal);
        let receipt = view.get("prin\u{1f}op_session_open").unwrap();
        // P0-B review: the receipt preserves the *original field name* — a
        // top-level `id` stays `id` (never renamed to `session_id`), so the
        // first and the replayed public responses are schema-stable.
        assert_eq!(
            receipt.get("id").and_then(Value::as_str),
            Some("sess_abc123"),
            "session.open generated session id must survive compaction under its original field name"
        );
        assert_eq!(
            receipt
                .get("controller")
                .and_then(|v| v.get("lease_id"))
                .and_then(Value::as_str),
            Some("lease_1"),
            "session.open controller lease must survive compaction"
        );
        assert_eq!(
            receipt.get("controller_epoch").and_then(Value::as_u64),
            Some(3),
            "controller epoch must survive compaction"
        );
        assert!(
            receipt.get("stdout").is_none(),
            "large stdout body must still be dropped"
        );

        // session.attach-shaped completed entry: the continuation identifiers
        // live inside the nested `session` snapshot.
        let mut journal = HashMap::new();
        journal.insert(
            "prin\u{1f}op_session_attach".into(),
            json!({
                "status": "completed",
                "operation_id": "op_session_attach_1",
                "session": {
                    "id": "sess_attach_9",
                    "kind": "pty",
                    "state": "running",
                    "controller": { "principal_id": "p1", "lease_id": "lease_9", "epoch": 5, "expires_unix": 1_900_000_000 },
                    "controller_epoch": 5,
                    "workspace_id": "ws_default",
                },
                "principal": "p1",
                "role": "controller",
                "read_only": false,
                "workspace_id": "ws_default",
                "live_pty": true,
                "readers": ["p1"],
                "decision": "allow",
                "result": { "content": "y".repeat(200_000) },
            }),
        );
        let view = op_journal_durable_view(&journal);
        let receipt = view.get("prin\u{1f}op_session_attach").unwrap();
        let session = receipt
            .get("session")
            .expect("nested session snapshot kept");
        assert_eq!(
            session.get("id").and_then(Value::as_str),
            Some("sess_attach_9"),
            "nested session id must survive compaction"
        );
        assert_eq!(
            session
                .get("controller")
                .and_then(|v| v.get("lease_id"))
                .and_then(Value::as_str),
            Some("lease_9"),
            "nested controller lease must survive compaction"
        );
        assert!(
            receipt.get("result").is_none(),
            "large result body must still be dropped"
        );

        // An `id` that is not a bounded string (e.g. a numeric id or a
        // 100 KiB blob) must never be copied onto the receipt.
        let mut journal = HashMap::new();
        journal.insert(
            "prin\u{1f}op_weird_id".into(),
            json!({
                "status": "completed",
                "operation_id": "op_weird_id_1",
                "id": "x".repeat(100_000),
                "decision": "allow",
                "result": { "stdout": "z" },
            }),
        );
        let view = op_journal_durable_view(&journal);
        let receipt = view.get("prin\u{1f}op_weird_id").unwrap();
        assert!(
            receipt.get("id").is_none() && receipt.get("session_id").is_none(),
            "oversized id must not be copied onto the receipt: {receipt:?}"
        );
        assert!(receipt.get("result").is_none());
    }

    /// P0-B / MCP contract regression (review High): `session.open` is a
    /// side-effect operation (it spawns a PTY host or a persistent sidecar),
    /// but the handler used to bypass the device idempotency journal
    /// entirely — a retried open with the same caller idempotency key created
    /// a *second* session. The handler now reserves the exact-once marker
    /// before the session record is created and stores a compacted receipt
    /// (session id + controller lease preserved) on success, so a retry after
    /// response loss or restart continues the original session.
    #[tokio::test]
    async fn session_open_with_idempotency_key_is_exact_once() {
        // `kind=process` keeps the test hermetic: no PTY/sidecar spawn, but
        // the exact-once journal path is identical to a live open.
        async fn open(
            runtime: &mut DaemonRuntime,
            client: &ClientIdentity,
            title: &str,
            key: &str,
        ) -> IpcResult<Value> {
            runtime
                .dispatch(
                    session_methods::OPEN,
                    Some(json!({
                        "title": title,
                        "kind": "process",
                        "idempotency_key": key,
                    })),
                    client,
                )
                .await
        }

        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.set_policy_for_test(preset_document(AccessPreset::FullUserAccess));
        let local = ClientIdentity::new("client:local:test", "test");

        // First open with a caller idempotency key creates the session.
        let first = open(&mut runtime, &local, "exact-once", "idem_open_exact")
            .await
            .expect("first session.open");
        let first_id = first
            .get("id")
            .and_then(Value::as_str)
            .expect("session id")
            .to_string();
        // P0-B review: the first response carries the additive `session_id`
        // alias so the first and the replayed public responses are
        // schema-stable (the control plane reads `session_id` at the top
        // level of the result).
        assert_eq!(
            first.get("session_id").and_then(Value::as_str),
            Some(first_id.as_str()),
            "first session.open must expose the additive session_id alias: {first}"
        );
        assert_eq!(runtime.sessions.list().len(), 1);

        // A retry with the same key must replay the receipt (with the
        // original session id), never spawn a second session.
        let retry = open(&mut runtime, &local, "exact-once", "idem_open_exact")
            .await
            .expect("replayed session.open");
        assert_eq!(retry["replayed"], true, "{retry}");
        assert_eq!(
            retry.get("session_id").and_then(Value::as_str),
            Some(first_id.as_str()),
            "replay must continue the original session"
        );
        assert_eq!(
            retry.get("id").and_then(Value::as_str),
            Some(first_id.as_str()),
            "replay must keep the original field name `id` (schema-stable with the first response): {retry}"
        );
        assert_eq!(
            runtime.sessions.list().len(),
            1,
            "a retried open must not create a duplicate session"
        );

        // A different key opens a different session.
        let other = open(&mut runtime, &local, "exact-once-other", "idem_open_other")
            .await
            .expect("second session.open");
        let other_id = other
            .get("id")
            .and_then(Value::as_str)
            .expect("session id")
            .to_string();
        assert_ne!(other_id, first_id);
        assert_eq!(runtime.sessions.list().len(), 2);

        // Replay after restart: the compacted receipt survives and still
        // returns the original session id (no duplicate PTY after crash).
        drop(runtime);
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.set_policy_for_test(preset_document(AccessPreset::FullUserAccess));
        let after_restart = open(&mut runtime, &local, "exact-once", "idem_open_exact")
            .await
            .expect("replay after restart");
        assert_eq!(after_restart["replayed"], true, "{after_restart}");
        assert_eq!(
            after_restart.get("session_id").and_then(Value::as_str),
            Some(first_id.as_str()),
            "restart replay must keep the original session id"
        );
        assert_eq!(
            after_restart.get("id").and_then(Value::as_str),
            Some(first_id.as_str()),
            "restart replay must keep the original field name `id`: {after_restart}"
        );
        assert_eq!(
            runtime.sessions.list().len(),
            2,
            "no third session after restart"
        );

        // Local opens without a key stay unjournaled (unchanged behavior):
        // each call still creates its own session.
        let unkeyed = open(&mut runtime, &local, "unkeyed", "")
            .await
            .expect("unkeyed open");
        let unkeyed_id = unkeyed
            .get("id")
            .and_then(Value::as_str)
            .expect("session id")
            .to_string();
        assert_ne!(unkeyed_id, first_id);
        assert_ne!(unkeyed_id, other_id);
        assert_eq!(runtime.sessions.list().len(), 3);
    }

    /// P0-B: a JSON object with *no* explicit completed marker — e.g. a
    /// truncated or hand-written `{}` — is uncertain, never completed. The
    /// old classifier treated any object without a state field as completed,
    /// so a malformed entry could be compacted/evicted/replayed as a receipt,
    /// masking an unfinished side effect.
    #[test]
    fn unmarked_op_journal_object_is_fail_closed() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let cases = [
            ("prin\u{1f}op_bare_empty".to_string(), json!({})),
            (
                "prin\u{1f}op_status_only".to_string(),
                json!({ "status": "completed" }),
            ),
            (
                "prin\u{1f}op_result_only".to_string(),
                json!({ "result": { "stdout": "body" } }),
            ),
        ];
        for (key, value) in &cases {
            assert_eq!(
                op_journal_entry_state(value),
                OpJournalEntryState::Uncertain,
                "unmarked object must be uncertain: {key}"
            );
            runtime.op_journal.insert(key.clone(), value.clone());
        }

        // Replay is refused for every unmarked object (exact-once preserved).
        for (key, _) in &cases {
            let err = runtime.lookup_idempotent(Some(key)).unwrap_err();
            assert!(
                err.to_string().contains("uncertain"),
                "unmarked object must refuse replay: {key}: {err}"
            );
        }

        // Eviction must never touch them, even without an age stamp.
        let evicted = runtime
            .evict_expired_completed_op_journal_entries()
            .expect("eviction");
        assert_eq!(evicted, 0, "unmarked objects must never be evicted");
        assert_eq!(runtime.op_journal.len(), cases.len());

        // The durable view keeps them verbatim (never compacted away).
        let view = op_journal_durable_view(&runtime.op_journal);
        for (key, value) in &cases {
            assert_eq!(
                view.get(key),
                Some(value),
                "unmarked object must survive the durable view verbatim: {key}"
            );
        }

        // And they survive a reload from disk verbatim.
        runtime.persist_op_journal().expect("persist");
        let loaded = load_op_journal(&paths.state_dir.join("op-journal.json")).unwrap();
        for (key, value) in &cases {
            assert_eq!(
                loaded.get(key),
                Some(value),
                "reload must keep unmarked objects fail-closed: {key}"
            );
        }

        // A legacy completed body (pre-1.2.13 gate_and_run shape) is
        // positively proven completed and migrates: it is stamped and
        // compacted, so a real upgrade shrinks instead of stalling.
        let legacy = json!({
            "approval_required": false,
            "operation_id": "op_legacy_1",
            "result": { "stdout": "old body" },
            "replayed": false,
            "decision": "allow",
        });
        assert_eq!(
            op_journal_entry_state(&legacy),
            OpJournalEntryState::Completed,
            "legacy completed body must migrate to a receipt"
        );
        // …but a legacy body without an operation_id is not provably
        // completed and stays uncertain.
        let no_operation_id = json!({ "decision": "allow" });
        assert_eq!(
            op_journal_entry_state(&no_operation_id),
            OpJournalEntryState::Uncertain,
            "completion proof without operation_id stays fail-closed"
        );
    }

    /// ADR 0010 §1b / review: completed markers must carry the exact-once
    /// `operation_id`. A `durable_receipt: true` marker or an explicit
    /// `__ownmesh_operation_state == "completed"` value *without* an
    /// `operation_id` is malformed (hand-written or truncated): compacting or
    /// eventually evicting it would let a retried operation execute as a new
    /// side effect. It must stay uncertain — never replayed, never compacted,
    /// never evicted.
    #[test]
    fn completed_markers_without_operation_id_are_fail_closed() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let cases = [
            (
                "prin\u{1f}op_receipt_no_id".to_string(),
                json!({
                    "durable_receipt": true,
                    "truncated": true,
                    "status": "completed",
                }),
            ),
            (
                "prin\u{1f}op_state_no_id".to_string(),
                json!({ OP_JOURNAL_STATE_FIELD: "completed" }),
            ),
            (
                "prin\u{1f}op_state_empty_id".to_string(),
                json!({
                    OP_JOURNAL_STATE_FIELD: "completed",
                    "operation_id": "",
                }),
            ),
        ];
        for (key, value) in &cases {
            assert_eq!(
                op_journal_entry_state(value),
                OpJournalEntryState::Uncertain,
                "completed marker without an operation_id must be uncertain: {key}"
            );
            runtime.op_journal.insert(key.clone(), value.clone());
        }

        // Replay is refused: a retried operation must never be told its side
        // effect completed when the receipt is not provably a receipt.
        for (key, _) in &cases {
            let err = runtime.lookup_idempotent(Some(key)).unwrap_err();
            assert!(
                err.to_string().contains("uncertain"),
                "malformed marker must refuse replay: {key}: {err}"
            );
        }

        // Eviction never touches them, even with an ancient age stamp.
        let now = DaemonRuntime::now();
        for (key, value) in &cases {
            let mut value = value.clone();
            if let Some(object) = value.as_object_mut() {
                object.insert(OP_JOURNAL_COMPLETED_UNIX_FIELD.into(), json!(now - 100_000));
            }
            runtime.op_journal.insert(key.clone(), value);
        }
        let evicted = runtime
            .evict_expired_completed_op_journal_entries()
            .expect("eviction");
        assert_eq!(evicted, 0, "malformed markers must never be evicted");
        assert_eq!(runtime.op_journal.len(), cases.len());

        // The durable view keeps them verbatim (never compacted away).
        let view = op_journal_durable_view(&runtime.op_journal);
        for (key, value) in &cases {
            let durable = view.get(key).expect("marker survives durable view");
            assert_eq!(
                durable.get("durable_receipt"),
                value.get("durable_receipt"),
                "marker must survive the durable view verbatim: {key}"
            );
            assert_eq!(
                durable.get(OP_JOURNAL_STATE_FIELD),
                value.get(OP_JOURNAL_STATE_FIELD),
                "marker must survive the durable view verbatim: {key}"
            );
        }

        // A genuine receipt (durable_receipt + operation_id) still replays.
        let good = json!({
            "durable_receipt": true,
            "truncated": true,
            "status": "completed",
            "operation_id": "op_genuine",
            OP_JOURNAL_COMPLETED_UNIX_FIELD: now,
        });
        assert_eq!(
            op_journal_entry_state(&good),
            OpJournalEntryState::Completed,
            "receipt with its exact-once operation_id is completed"
        );
        runtime
            .op_journal
            .insert("prin\u{1f}op_genuine".into(), good);
        let replayed = runtime
            .lookup_idempotent(Some(&"prin\u{1f}op_genuine".to_string()))
            .expect("lookup")
            .expect("genuine receipt replays");
        assert_eq!(replayed["operation_id"], "op_genuine");
    }

    /// P0-B: a top-level entry that is not a JSON object (`null`, array,
    /// string, number, boolean) has no state field by construction, but it is
    /// not a completed receipt this version writes either. The old classifier
    /// treated any value without a state field as `Completed`, so a malformed
    /// top-level entry could be compacted/evicted/replayed as a receipt —
    /// hiding an unfinished side effect. It must be classified uncertain
    /// (fail-closed) instead.
    #[test]
    fn non_object_op_journal_entries_are_fail_closed() {
        let cases = [
            json!(null),
            json!([1, 2, 3]),
            json!("just a string"),
            json!(42),
            json!(true),
        ];
        for value in &cases {
            assert_eq!(
                op_journal_entry_state(value),
                OpJournalEntryState::Uncertain,
                "non-object entry must be uncertain: {value}"
            );
            assert!(
                is_op_journal_uncertain(value),
                "non-object entry must never be treated as a completed receipt: {value}"
            );
        }

        // The durable view keeps them verbatim (never compacted away).
        let mut journal = HashMap::new();
        for (i, value) in cases.iter().enumerate() {
            journal.insert(format!("prin\u{1f}op_bad_{i}"), value.clone());
        }
        let view = op_journal_durable_view(&journal);
        for (i, value) in cases.iter().enumerate() {
            let key = format!("prin\u{1f}op_bad_{i}");
            assert_eq!(
                view.get(&key),
                Some(value),
                "non-object entry must survive the durable view verbatim: {key}"
            );
        }

        // Replay is refused for every non-object entry, exactly like an
        // in-progress marker.
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        for (i, value) in cases.iter().enumerate() {
            let key = format!("prin\u{1f}op_bad_{i}");
            runtime.op_journal.insert(key.clone(), value.clone());
            let err = runtime.lookup_idempotent(Some(&key)).unwrap_err();
            assert!(
                err.to_string().contains("uncertain"),
                "non-object entry must refuse replay: {key}: {err}"
            );
        }

        // Eviction must never touch them, even though they have no age stamp.
        let evicted = runtime
            .evict_expired_completed_op_journal_entries()
            .expect("eviction");
        assert_eq!(evicted, 0, "non-object entries must never be evicted");
        assert_eq!(runtime.op_journal.len(), cases.len());

        // And they survive a reload from disk verbatim (bound_op_journal).
        runtime.persist_op_journal().expect("persist");
        let loaded = load_op_journal(&paths.state_dir.join("op-journal.json")).unwrap();
        for (i, value) in cases.iter().enumerate() {
            let key = format!("prin\u{1f}op_bad_{i}");
            assert_eq!(
                loaded.get(&key),
                Some(value),
                "reload must keep non-object entries fail-closed: {key}"
            );
        }
    }

    /// P0-B privacy: compaction at load must not leave the pre-compaction
    /// legacy journal (with large stdout/file bodies) behind in
    /// `op-journal.json.bak`. `atomic_write` preserves the previous file as
    /// `.bak` before replacing it; the op-journal write path removes the
    /// stale backup so a legacy large-body journal cannot linger on disk
    /// indefinitely.
    #[test]
    fn legacy_op_journal_compaction_removes_stale_bak() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("op-journal.json");
        let big_body = "z".repeat(80 * 1024);
        let legacy = serde_json::json!({
            "prin\u{1f}op_done": {
                "status": "completed",
                "operation_id": "op_done",
                "approval_required": false,
                "replayed": false,
                "decision": "allow",
                "result": { "stdout": big_body }
            }
        });
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let bak = dir.path().join("op-journal.json.bak");
        // Simulate a prior atomic_write that left a stale backup holding the
        // legacy large-body journal (the exact privacy leak being fixed).
        std::fs::write(&bak, serde_json::to_vec(&legacy).unwrap()).unwrap();

        let journal = load_op_journal(&path).expect("legacy journal loads and compacts");
        assert_eq!(journal.len(), 1);
        assert!(
            !bak.exists(),
            "stale .bak holding the legacy large-body journal must be removed"
        );
        // The durable file is the compacted receipt, not the large body.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.len() < 4 * 1024,
            "durable file must be compacted after load, got {} bytes",
            raw.len()
        );

        // A later persist also leaves no stale backup behind.
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime
            .begin_idempotent(Some("prin\u{1f}op_bak".to_string()).as_ref(), "op_bak")
            .expect("begin marker");
        runtime
            .store_idempotent(
                Some("prin\u{1f}op_bak".to_string()).as_ref(),
                &json!({
                    "approval_required": false,
                    "operation_id": "op_bak",
                    "result": { "stdout": "x".repeat(80 * 1024) },
                    "replayed": false,
                    "decision": "allow",
                }),
            )
            .expect("store");
        let journal_path = paths.state_dir.join("op-journal.json");
        let bak_path = paths.state_dir.join("op-journal.json.bak");
        assert!(
            !bak_path.exists(),
            "persist must not leave a stale .bak behind"
        );
        let raw = std::fs::read_to_string(&journal_path).unwrap();
        assert!(
            !raw.contains("x".repeat(80 * 1024).as_str()),
            "durable file must not retain the large result body"
        );
    }

    /// P0-B review (privacy): a stale backup that cannot be removed must fail
    /// startup instead of running with the pre-compaction large-body journal
    /// still on disk while the load claims it was removed. A directory at the
    /// backup path makes `remove_file` fail deterministically on every
    /// platform (the same class as a locked/ACL-protected file).
    #[test]
    fn unremovable_stale_bak_fails_load_fail_closed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("op-journal.json");
        let big_body = "z".repeat(80 * 1024);
        let legacy = serde_json::json!({
            "prin\u{1f}op_done": {
                "status": "completed",
                "operation_id": "op_done",
                "approval_required": false,
                "replayed": false,
                "decision": "allow",
                "result": { "stdout": big_body }
            }
        });
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let bak = dir.path().join("op-journal.json.bak");
        std::fs::create_dir(&bak).unwrap();

        let err = load_op_journal(&path).unwrap_err();
        assert!(
            err.contains("failed to remove stale op journal backup"),
            "unremovable stale backup must fail startup with an actionable message: {err}"
        );
        // The primary is untouched (no half-compacted state), and the legacy
        // large body is still on disk — the operator must resolve the backup
        // before the daemon starts; the failure is never converted into a
        // silent "healthy" load.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("z".repeat(80 * 1024).as_str()),
            "a failed load must not modify the primary"
        );
    }

    /// P0-B review: when the primary op journal is missing but a backup
    /// survives (a crash in an older writer between its backup copy and the
    /// replace, or an external removal of the primary), the backup is the
    /// last-known durable journal: its exact-once receipts must not be
    /// silently dropped by starting empty — a retried operation would
    /// re-execute. `load_op_journal` recovers from the backup, persists the
    /// compacted form as the new primary, and removes the backup so the
    /// state is not double-counted.
    #[test]
    fn missing_primary_op_journal_recovers_from_stale_bak() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("op-journal.json");
        let bak = dir.path().join("op-journal.json.bak");
        let big_body = "z".repeat(80 * 1024);
        let legacy = serde_json::json!({
            "prin\u{1f}op_done": {
                "status": "completed",
                "operation_id": "op_done",
                "approval_required": false,
                "replayed": false,
                "decision": "allow",
                "result": { "stdout": big_body }
            },
            "prin\u{1f}op_inflight": {
                "__ownmesh_operation_state": "in_progress",
                "operation_id": "op_inflight",
                "result": { "stdout": "pending body" }
            }
        });
        assert!(!path.exists());
        std::fs::write(&bak, serde_json::to_vec(&legacy).unwrap()).unwrap();

        let journal = load_op_journal(&path).expect("recovery from backup must succeed");
        // Both the completed receipt and the in-progress marker survive.
        assert_eq!(journal.len(), 2);
        let done = journal.get("prin\u{1f}op_done").expect("completed receipt");
        assert_eq!(done["durable_receipt"], true);
        assert_eq!(done["operation_id"], "op_done");
        assert!(journal["prin\u{1f}op_inflight"]["__ownmesh_operation_state"] == "in_progress");
        // The recovered state is the new primary and the backup is gone.
        assert!(
            !bak.exists(),
            "recovered backup must be removed after promotion"
        );
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("durable_receipt"),
            "primary must hold the compacted recovery journal"
        );
        assert!(
            !raw.contains("z".repeat(80 * 1024).as_str()),
            "recovered primary must not retain the large legacy body"
        );
        // A reload reads the promoted primary (no double-count, no re-recovery).
        let reloaded = load_op_journal(&path).unwrap();
        assert_eq!(reloaded.len(), 2);
    }

    /// P0-B review: a corrupt/over-budget backup with a missing primary is
    /// never converted into an empty journal — starting empty would bypass
    /// the exact-once receipts the backup may hold. The load fails closed
    /// with an actionable message.
    #[test]
    fn missing_primary_with_corrupt_bak_fails_closed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("op-journal.json");
        let bak = dir.path().join("op-journal.json.bak");
        std::fs::write(&bak, br#"{"broken"#).unwrap();

        let err = load_op_journal(&path).unwrap_err();
        assert!(
            err.contains("op journal backup") && err.contains("corrupt"),
            "corrupt backup must fail closed with an actionable message: {err}"
        );
        assert!(
            !path.exists(),
            "a failed recovery must not fabricate an empty primary"
        );
        // A fresh install with no primary and no backup is still empty.
        let fresh = dir.path().join("fresh-op-journal.json");
        let empty = load_op_journal(&fresh).unwrap();
        assert!(empty.is_empty());
    }

    /// P0-B review: `load_op_journal` must be durably fail-closed. If the
    /// compaction cannot be persisted, the load fails instead of returning a
    /// compacted in-memory view while the legacy large bodies remain on disk
    /// — diagnostics would otherwise report the compacted state while the
    /// durable file is still over budget.
    #[cfg(unix)]
    #[test]
    fn load_op_journal_fails_closed_when_compaction_persist_fails() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("op-journal.json");
        let big_body = "x".repeat(80 * 1024);
        let legacy = serde_json::json!({
            "prin\u{1f}op_done": {
                "status": "completed",
                "operation_id": "op_done",
                "approval_required": false,
                "replayed": false,
                "decision": "allow",
                "result": { "stdout": big_body }
            }
        });
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        // Make the journal directory read-only so the compaction persist fails.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let err = load_op_journal(&path).unwrap_err();
        assert!(
            err.contains("failed to persist compacted operation journal"),
            "load must fail closed with an actionable message: {err}"
        );
        // The durable file still holds the legacy large body: the failed
        // compaction wrote nothing, and the in-memory view never diverged
        // from the durable file.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("x".repeat(80 * 1024).as_str()),
            "failed compaction must not have rewritten the durable file"
        );
    }

    /// P0-B review: the stale `.bak` is removed *before* the compacted write,
    /// so a crash between the write and the cleanup cannot leave a legacy
    /// large-body copy on disk while the daemon is stopped. The fault hook
    /// fires after the stale-backup removal and before the durable write:
    /// when the write then fails, the backup is already gone and the primary
    /// remains authoritative (the failed write wrote nothing, so no exact-once
    /// receipt was lost).
    #[test]
    fn stale_bak_is_removed_before_compaction_write() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let runtime = DaemonRuntime::open(&paths).unwrap();
        let primary = paths.state_dir.join("op-journal.json");
        let bak = paths.state_dir.join("op-journal.json.bak");
        // Simulate a prior atomic_write that left a stale backup holding a
        // legacy large-body journal (the exact privacy leak being fixed), and
        // a primary that exists (the authoritative state).
        let big_body = "z".repeat(80 * 1024);
        let legacy = serde_json::json!({
            "prin\u{1f}op_done": {
                "status": "completed",
                "operation_id": "op_done",
                "approval_required": false,
                "replayed": false,
                "decision": "allow",
                "result": { "stdout": big_body }
            }
        });
        std::fs::write(&primary, serde_json::to_vec(&legacy).unwrap()).unwrap();
        std::fs::write(&bak, serde_json::to_vec(&legacy).unwrap()).unwrap();

        // Fault the write (after the stale-backup removal, before the durable
        // write). The persist fails, but the backup must already be gone.
        runtime.fail_op_journal_write_on_nth_call_for_test(1);
        let err = runtime.persist_op_journal().unwrap_err();
        let err_message = match &err {
            ownmesh_ipc::IpcError::Remote { message, .. } => message.clone(),
            other => format!("{other:?}"),
        };
        assert!(
            err_message.contains("fault-injected op journal write"),
            "write fault must fire: {err:?}"
        );
        assert!(
            !bak.exists(),
            "stale .bak must be removed before the write so a crash between the write and the \
cleanup cannot leave the legacy large-body copy behind"
        );
        // The primary is authoritative and unchanged (the failed write wrote
        // nothing), so no exact-once receipt was lost.
        let raw = std::fs::read_to_string(&primary).unwrap();
        assert!(
            raw.contains(big_body.as_str()),
            "primary must remain authoritative and unchanged after the failed write"
        );
    }

    /// P0-B review: the byte-budget check must use the pretty-serialized
    /// size the durable writer actually emits. A journal whose compact form
    /// fits the budget but whose pretty form exceeds it must be rejected —
    /// otherwise the file written to disk would exceed the cap the check
    /// validated (a reproducible uncertain entry measured 4,194,285 compact
    /// bytes vs 4,194,305 pretty bytes against the 4 MiB cap).
    #[test]
    fn bound_op_journal_rejects_pretty_oversize_even_when_compact_fits() {
        // In-progress/uncertain markers are kept verbatim by compaction, so
        // a journal of them can be sized to land compact-under/pretty-over
        // the budget. The compact/pretty difference is pure JSON framing
        // (whitespace), independent of payload content, so measure the
        // framing constant once and solve for the body size deterministically
        // instead of searching.
        let mut journal = HashMap::new();
        for i in 0..100 {
            journal.insert(
                format!("prin\u{1f}op_uncertain_{i}"),
                json!({
                    OP_JOURNAL_STATE_FIELD: OP_JOURNAL_IN_PROGRESS,
                    "operation_id": format!("op_uncertain_{i}"),
                    "payload": "",
                }),
            );
        }
        let base_compact = serde_json::to_vec(&journal).unwrap().len();
        let base_pretty = serde_json::to_vec_pretty(&journal).unwrap().len();
        let overhead = base_pretty - base_compact;
        assert!(
            overhead > 0 && overhead < MAX_OP_JOURNAL_FILE_BYTES / 2,
            "fixture framing overhead must be sane: {overhead}"
        );
        // compact(B) = base_compact + 100*B; pretty(B) = compact(B) + overhead.
        // Target compact = budget - overhead/2 so pretty lands over the budget.
        let target_compact = MAX_OP_JOURNAL_FILE_BYTES - overhead / 2;
        let body_len = (target_compact - base_compact) / 100;
        let body = "u".repeat(body_len);
        for i in 0..100 {
            journal.insert(
                format!("prin\u{1f}op_uncertain_{i}"),
                json!({
                    OP_JOURNAL_STATE_FIELD: OP_JOURNAL_IN_PROGRESS,
                    "operation_id": format!("op_uncertain_{i}"),
                    "payload": body,
                }),
            );
        }
        let compact = serde_json::to_vec(&journal).unwrap().len();
        let pretty = serde_json::to_vec_pretty(&journal).unwrap().len();
        assert!(
            compact < MAX_OP_JOURNAL_FILE_BYTES && pretty > MAX_OP_JOURNAL_FILE_BYTES,
            "fixture must land compact-under/pretty-over the budget (compact {compact}, pretty {pretty})"
        );
        assert!(
            bound_op_journal(journal).is_err(),
            "pretty-oversize journal must be rejected even when compact fits"
        );
    }

    /// P0-B review (High): an expired transition record whose *old* binding's
    /// child is provably dead must NOT be cleared while a distinct successor
    /// binding (`new_binding`) is live. The old proof checked only the first
    /// available child identity and returned early, orphaning the live
    /// successor. Every referenced binding must be covered before the row is
    /// cleared.
    #[tokio::test]
    async fn expired_record_with_live_successor_binding_is_retained_fail_closed() {
        let (_dir, mut runtime, sid) = runtime_with_session(true);
        let now = DaemonRuntime::now();
        let mut record = expired_record("tr_live_successor", &sid, now);
        let live_pid = std::process::id();
        let live_birth = ownmesh_ipc::process_birth_id(live_pid)
            .expect("the test process attests its own birth id")
            .expect("the test process is live");
        let mut successor = record.old_binding.clone();
        successor.host_nonce = "nonce_successor".into();
        successor.controller_epoch = 2;
        successor.child_pid = Some(live_pid);
        successor.child_process_birth = Some(live_birth);
        record.new_binding = Some(successor);
        runtime
            .transition_journal
            .begin(record)
            .expect("begin record");

        runtime.reconcile_expired_transitions().await;

        assert_eq!(
            runtime.transition_journal.pending().len(),
            1,
            "a live successor binding must retain the expired record"
        );
        assert_eq!(runtime.transition_recovery_health.retained_expired_total, 1);
        assert_eq!(
            runtime.transition_recovery_health.retained_expired[0],
            "tr_live_successor"
        );
    }

    /// P0-B review (High): when the old binding's child is dead but the
    /// distinct successor binding is provisional (no attested pid) and no
    /// supervisor is connected to prove it dead, the record must be retained
    /// fail-closed. The old proof returned `Ok(true)` from the first
    /// (dead) binding alone and cleared the row without any proof for the
    /// successor.
    #[tokio::test]
    async fn expired_record_with_provisional_successor_and_no_supervisor_is_retained() {
        let (_dir, mut runtime, sid) = runtime_with_session(true);
        let now = DaemonRuntime::now();
        let mut record = expired_record("tr_provisional_successor", &sid, now);
        let mut successor = record.old_binding.clone();
        successor.host_nonce = "nonce_successor".into();
        successor.controller_epoch = 2;
        successor.child_pid = None;
        successor.child_process_birth = None;
        record.new_binding = Some(successor);
        runtime
            .transition_journal
            .begin(record)
            .expect("begin record");
        // No supervisor connected: the successor's death cannot be proved.
        assert!(runtime.supervisor.is_none());

        runtime.reconcile_expired_transitions().await;

        assert_eq!(
            runtime.transition_journal.pending().len(),
            1,
            "an unproven successor must retain the expired record (ambiguity is never success)"
        );
        assert_eq!(runtime.transition_recovery_health.retained_expired_total, 1);
    }

    /// P0-B review (High): when *both* referenced bindings carry confirmed-dead
    /// child identities, the expired record is provably moot and clears even
    /// though a successor binding is present — coverage of every referenced
    /// binding is what matters, not a blanket retention.
    #[tokio::test]
    async fn expired_record_with_dead_successor_binding_is_cleared() {
        let (_dir, mut runtime, sid) = runtime_with_session(true);
        let now = DaemonRuntime::now();
        let mut record = expired_record("tr_dead_successor", &sid, now);
        let mut successor = record.old_binding.clone();
        successor.host_nonce = "nonce_successor".into();
        successor.controller_epoch = 2;
        successor.child_pid = Some(DEAD_TEST_PID);
        successor.child_process_birth = Some(2);
        record.new_binding = Some(successor);
        runtime
            .transition_journal
            .begin(record)
            .expect("begin record");

        runtime.reconcile_expired_transitions().await;

        assert!(
            runtime.transition_journal.pending().is_empty(),
            "both referenced bindings provably dead: the moot record clears"
        );
        assert_eq!(runtime.transition_recovery_health.retained_expired_total, 0);
    }

    /// P0-B review (Medium): a compacted `review.start` receipt must replay
    /// with the same terminal status/phase as the first response. The old
    /// durable view read only `status` (absent on a review body) and defaulted
    /// it to `completed`, so a compacted failed/cancelled review was persisted
    /// by the control plane as a successful operation result. The terminal
    /// `phase` is preserved and `status` is derived from it.
    #[test]
    fn op_journal_durable_view_preserves_terminal_review_phase_and_status() {
        let mut journal = HashMap::new();
        journal.insert(
            "prin\u{1f}op_review_failed".into(),
            json!({
                "review_id": "rev_failed_1",
                "phase": "failed",
                "operation_id": "op_review_failed_1",
                "remote_payload_hash": "a".repeat(64),
                "workspace_id": "ws_default",
            }),
        );
        journal.insert(
            "prin\u{1f}op_review_cancelled".into(),
            json!({
                "review_id": "rev_cancelled_1",
                "phase": "cancelled",
                "operation_id": "op_review_cancelled_1",
                "remote_payload_hash": "a".repeat(64),
            }),
        );
        journal.insert(
            "prin\u{1f}op_review_completed".into(),
            json!({
                "review_id": "rev_completed_1",
                "phase": "completed",
                "operation_id": "op_review_completed_1",
                "remote_payload_hash": "a".repeat(64),
            }),
        );
        let view = op_journal_durable_view(&journal);
        let failed = view.get("prin\u{1f}op_review_failed").unwrap();
        assert_eq!(
            failed.get("status").and_then(Value::as_str),
            Some("failed"),
            "failed review must replay as failed, not completed: {failed}"
        );
        assert_eq!(
            failed.get("phase").and_then(Value::as_str),
            Some("failed"),
            "terminal phase must be preserved on the compact receipt: {failed}"
        );
        assert_eq!(
            failed.get("review_id").and_then(Value::as_str),
            Some("rev_failed_1"),
            "review_id continuation must survive compaction"
        );
        let cancelled = view.get("prin\u{1f}op_review_cancelled").unwrap();
        assert_eq!(
            cancelled.get("status").and_then(Value::as_str),
            Some("cancelled"),
            "cancelled review must replay as cancelled: {cancelled}"
        );
        let completed = view.get("prin\u{1f}op_review_completed").unwrap();
        assert_eq!(
            completed.get("status").and_then(Value::as_str),
            Some("completed")
        );
        // All three remain provably-completed receipts (replayable); only the
        // status/phase wording differs.
        for key in [
            "prin\u{1f}op_review_failed",
            "prin\u{1f}op_review_cancelled",
            "prin\u{1f}op_review_completed",
        ] {
            assert_eq!(
                op_journal_entry_state(view.get(key).unwrap()),
                OpJournalEntryState::Completed,
                "{key} must remain a completed receipt"
            );
        }
    }

    /// P0-B review (Medium): `session.renew`/`give`/`claim` return their
    /// controller lease at the top level as `lease`; the compact receipt must
    /// preserve it so a replayed remote mutation is schema-stable with the
    /// first response (a client retrying renew must see the actual extended
    /// expiry).
    #[test]
    fn op_journal_durable_view_preserves_top_level_lease() {
        let journal = HashMap::from([(
            "prin\u{1f}op_renew_1".to_string(),
            json!({
                "status": "completed",
                "operation_id": "op_renew_1",
                "approval_required": false,
                "decision": "allow",
                "session_id": "ses_renew_1",
                "workspace_id": "ws_default",
                "lease": {
                    "principal_id": "client:remote:t:p",
                    "lease_id": "lease_renew_1",
                    "epoch": 4,
                    "expires_unix": 1_700_000_000,
                },
                "result": { "stdout": "x".repeat(80 * 1024) },
            }),
        )]);
        let view = op_journal_durable_view(&journal);
        let receipt = view.get("prin\u{1f}op_renew_1").unwrap();
        assert_eq!(receipt["durable_receipt"], true);
        assert_eq!(
            receipt["lease"]["expires_unix"].as_i64(),
            Some(1_700_000_000),
            "the extended lease expiry must survive compaction: {receipt}"
        );
        assert_eq!(receipt["lease"]["lease_id"].as_str(), Some("lease_renew_1"));
        assert_eq!(receipt["lease"]["epoch"].as_u64(), Some(4));
        assert!(
            receipt.get("result").is_none(),
            "large result body must still be dropped"
        );
    }

    /// P0-B review (High): a remote `session.renew` retried with the same
    /// signed operation key must replay its first receipt — it must never
    /// extend the lease a second time. The transport injects the key, but the
    /// handler previously discarded it.
    #[tokio::test]
    async fn session_renew_is_exact_once_with_remote_idempotency_key() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.set_policy_for_test(preset_document(AccessPreset::FullUserAccess));
        let now = DaemonRuntime::now();
        let remote_principal = "client:remote:tenant_test:principal_test";
        let info = runtime
            .sessions
            .open(
                SessionKind::Pty,
                "renew-exact-once",
                remote_principal,
                now,
                None,
            )
            .unwrap();
        let lease = runtime
            .sessions
            .get(&info.id)
            .unwrap()
            .controller
            .clone()
            .unwrap();
        let remote = ClientIdentity::new(remote_principal, "agent");
        let params = json!({
            "id": info.id,
            "lease_id": lease.lease_id,
            "controller_epoch": lease.epoch,
            "ttl_secs": 60,
            "idempotency_key": "idem_renew_exact_1",
        });

        let first = runtime
            .handle_session_renew(Some(params.clone()), &remote)
            .await
            .expect("first renew");
        let first_expiry = first["lease"]["expires_unix"].as_i64().unwrap();
        let first_lease_id = first["lease"]["lease_id"].as_str().unwrap().to_string();
        assert!(first_expiry > now);
        assert_eq!(runtime.sessions.list().len(), 1);

        // Retry with the same key: replay the receipt; the lease is not
        // extended a second time and the sidecar nonce is not rotated twice.
        let retry = runtime
            .handle_session_renew(Some(params), &remote)
            .await
            .expect("replayed renew");
        assert_eq!(retry["replayed"], true, "{retry}");
        assert_eq!(
            retry["lease"]["expires_unix"].as_i64(),
            Some(first_expiry),
            "replay must return the first (already-extended) expiry: {retry}"
        );
        assert_eq!(
            retry["lease"]["lease_id"].as_str(),
            Some(first_lease_id.as_str())
        );
        assert_eq!(
            runtime
                .sessions
                .get(&info.id)
                .unwrap()
                .controller
                .as_ref()
                .unwrap()
                .expires_unix,
            first_expiry,
            "the lease must not be extended a second time"
        );

        // A different key renews again (extends from the current expiry).
        let other = runtime
            .handle_session_renew(
                Some(json!({
                    "id": info.id,
                    "lease_id": lease.lease_id,
                    "controller_epoch": lease.epoch,
                    "ttl_secs": 60,
                    "idempotency_key": "idem_renew_exact_2",
                })),
                &remote,
            )
            .await
            .expect("second renew");
        assert!(
            other.get("replayed").is_none(),
            "a brand-new operation has no replayed marker: {other}"
        );
        assert!(
            other["lease"]["expires_unix"].as_i64().unwrap() >= first_expiry,
            "a new operation extends the lease from the current expiry (same-second timestamps may be equal)"
        );

        // Local IPC (no key) is unchanged: each call renews.
        let local = ClientIdentity::new(remote_principal, "local");
        let local_params = json!({
            "id": info.id,
            "lease_id": lease.lease_id,
            "controller_epoch": lease.epoch,
            "ttl_secs": 60,
        });
        let local_renew = runtime
            .handle_session_renew(Some(local_params.clone()), &local)
            .await
            .expect("local renew without key");
        assert!(local_renew.get("replayed").is_none());
        let local_renew2 = runtime
            .handle_session_renew(Some(local_params), &local)
            .await
            .expect("second local renew without key");
        assert!(local_renew2.get("replayed").is_none());
    }

    /// P0-B review (High): `session.close` is a terminal side-effect mutation
    /// (it terminates the sidecar). A retried remote close with the same key
    /// must replay the first receipt instead of re-running the close (which
    /// would fail as a stale lease CAS) or issuing a second termination.
    #[tokio::test]
    async fn session_close_is_exact_once_with_remote_idempotency_key() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.set_policy_for_test(preset_document(AccessPreset::FullUserAccess));
        let now = DaemonRuntime::now();
        let remote_principal = "client:remote:tenant_test:principal_close";
        let info = runtime
            .sessions
            .open(
                SessionKind::Pty,
                "close-exact-once",
                remote_principal,
                now,
                None,
            )
            .unwrap();
        let lease = runtime
            .sessions
            .get(&info.id)
            .unwrap()
            .controller
            .clone()
            .unwrap();
        let remote = ClientIdentity::new(remote_principal, "agent");
        let params = json!({
            "id": info.id,
            "lease_id": lease.lease_id,
            "controller_epoch": lease.epoch,
            "idempotency_key": "idem_close_exact_1",
        });

        let first = runtime
            .handle_session_close(Some(params.clone()), &remote)
            .await
            .expect("first close");
        assert_eq!(first["closed"], true);
        assert_eq!(
            runtime.sessions.get(&info.id).unwrap().state,
            SessionState::Closed
        );
        // Retry with the same key: replay the receipt. Without the journal,
        // the retry would fail `authorize_controller_lease` (the seat is gone)
        // or, worse, re-run the close path.
        let retry = runtime
            .handle_session_close(Some(params), &remote)
            .await
            .expect("replayed close");
        assert_eq!(retry.get("replayed").and_then(Value::as_bool), Some(true));
        assert_eq!(retry["closed"], true);
        assert_eq!(
            retry.get("session_id").and_then(Value::as_str),
            Some(info.id.as_str())
        );
        assert_eq!(
            runtime.sessions.get(&info.id).unwrap().state,
            SessionState::Closed,
            "the retry must not reopen or double-close"
        );
    }

    /// P0-B review (Medium): `session.open` consults its idempotency receipt
    /// before workspace preflight, so a retry after response loss still
    /// returns the original receipt when the workspace was removed
    /// (preflight would otherwise fail on the retry).
    #[tokio::test]
    async fn session_open_retry_replays_before_workspace_preflight() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.set_policy_for_test(preset_document(AccessPreset::FullUserAccess));
        let local = ClientIdentity::new("client:local:test", "test");

        // First open with a caller idempotency key creates the session.
        let first = runtime
            .dispatch(
                session_methods::OPEN,
                Some(json!({
                    "title": "preflight-replay",
                    "kind": "process",
                    "idempotency_key": "idem_open_preflight_1",
                })),
                &local,
            )
            .await
            .expect("first session.open");
        let first_id = first["id"].as_str().unwrap().to_string();

        // Removing the (default) workspace registry entry does not exist here,
        // so simulate the preflight failure the fix must bypass: a workspace
        // that is no longer registered. The replay happens before the
        // workspace resolution, so it still succeeds.
        runtime.workspaces.clear();
        let retry = runtime
            .dispatch(
                session_methods::OPEN,
                Some(json!({
                    "title": "preflight-replay",
                    "kind": "process",
                    "idempotency_key": "idem_open_preflight_1",
                })),
                &local,
            )
            .await
            .expect("replayed session.open must bypass removed-workspace preflight");
        assert_eq!(retry["replayed"], true, "{retry}");
        assert_eq!(
            retry.get("id").and_then(Value::as_str),
            Some(first_id.as_str()),
            "replay must continue the original session"
        );

        // A NEW open (different key) fails preflight fail-closed and leaves no
        // journal marker (preflight errors never poison a key).
        let err = runtime
            .dispatch(
                session_methods::OPEN,
                Some(json!({
                    "title": "preflight-new",
                    "kind": "process",
                    "workspace_id": "ws_default",
                    "idempotency_key": "idem_open_preflight_2",
                })),
                &local,
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("workspace"),
            "new open with an unregistered workspace must fail: {err}"
        );
        // The failed preflight did not reserve a marker for the new key.
        assert!(
            runtime
                .lookup_idempotent(Some(&principal_journal_key(
                    &local.client_name,
                    "idem_open_preflight_2"
                )))
                .is_ok()
                && runtime
                    .lookup_idempotent(Some(&principal_journal_key(
                        &local.client_name,
                        "idem_open_preflight_2"
                    )))
                    .unwrap()
                    .is_none(),
            "preflight failure must not leave an in-progress marker"
        );
    }

    /// P0-B review (Medium): `persist_op_journal` must fail closed (rolling
    /// back the in-memory mutation) when a stale `.bak` cannot be removed
    /// before the compacted write — otherwise compaction "succeeds" while the
    /// pre-compaction large-body journal remains on disk, exactly the privacy
    /// class that only startup used to refuse.
    #[test]
    fn unremovable_stale_bak_fails_persist_fail_closed() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        let key = "prin\u{1f}op_bakfail_1".to_string();
        // The primary must exist so the pre-write removal path runs; the
        // begin marker persists it.
        runtime
            .begin_idempotent(Some(&key), "op_bakfail_1")
            .expect("begin marker");
        assert!(paths.state_dir.join("op-journal.json").exists());
        // An unremovable stale backup (a directory at the .bak path makes
        // remove_file fail deterministically on every platform).
        let bak = paths.state_dir.join("op-journal.json.bak");
        std::fs::create_dir(&bak).unwrap();

        let err = runtime
            .store_idempotent(
                Some(&key),
                &json!({
                    "approval_required": false,
                    "operation_id": "op_bakfail_1",
                    "result": { "stdout": "z".repeat(80 * 1024) },
                }),
            )
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("failed to remove stale op journal backup"),
            "unremovable stale backup must fail the persist with an actionable message: {err}"
        );
        // The in-memory entry is rolled back to the fail-closed marker (never
        // a claim of completed while the large body remains on disk).
        assert!(
            is_op_journal_in_progress(runtime.op_journal.get(&key).unwrap()),
            "a failed persist must restore the in-progress marker, not a completed receipt"
        );
        // The primary is untouched (no half-compacted state).
        let raw = std::fs::read_to_string(paths.state_dir.join("op-journal.json")).unwrap();
        assert!(
            !raw.contains("z".repeat(80 * 1024).as_str()),
            "failed persist must not write anything"
        );

        // Resolve the blocker; the same store now succeeds and compacts.
        std::fs::remove_dir(&bak).unwrap();
        runtime
            .store_idempotent(
                Some(&key),
                &json!({
                    "approval_required": false,
                    "operation_id": "op_bakfail_1",
                    "result": { "stdout": "z".repeat(80 * 1024) },
                }),
            )
            .expect("store after resolving the backup");
        let raw = std::fs::read_to_string(paths.state_dir.join("op-journal.json")).unwrap();
        assert!(
            !raw.contains("z".repeat(80 * 1024).as_str()),
            "successful persist must compact the large body away"
        );
    }
}
