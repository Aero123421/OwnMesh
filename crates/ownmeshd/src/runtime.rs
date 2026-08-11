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
#[path = "session_transition_journal.rs"]
mod session_transition_journal;
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
    classify_from_request_in_dir, pin_executable, resolve_executable_path, run_command_cancellable,
    verify_executable_pin, CommandKind, ExecutablePin, IdempotencyJournal, RunRequest, RunResult,
};
use ownmesh_fs::{
    apply_patch, apply_unified_diff, delete_path, git_diff, git_head_oid, git_status,
    list_dir_page, looks_like_unified_diff, stat_path, write_file, GitDiffOpts, GitStatusOpts,
    WorkspaceRoot,
};
use ownmesh_ipc::{
    app_error, canonicalize_principal_key, is_credentialed_client_principal, is_human_os_principal,
    methods, read_management_credential, ClientIdentity, Endpoint, IpcBus, IpcError, IpcResult,
    MethodHandler, RevokedClients,
};
use ownmesh_logs::{
    register_builtin_providers, BuiltinProviderConfig, LogCursor, LogError, LogRegistry,
};
use ownmesh_policy::{
    evaluate_with_grants, full_access_has_no_hidden_restrictive_rules, preset_document,
    temporary_grant_from_facts, temporary_grant_requires_operation_binding, AccessPreset, Decision,
    ExecutableIdentityBinding, OperationFacts, PolicyDocument, PolicyRule, TemporaryGrant,
};
use ownmesh_profiles::{
    official_adapter_spec, parse_adapter_event_page, AdapterDialect, NativeResume, ProfileRegistry,
    ProfileStatus,
};
use ownmesh_session::{PtyCommand, PtySize};
use ownmesh_session::{
    SessionKind, SessionManager, SidecarHostBinding, StreamKind as SessionStreamKind,
};
use ownmesh_session_host::{
    default_shell_command, HostIoMode, LiveHost, SupervisorBinding, SupervisorClient,
    SupervisorCommand, SupervisorEnv, SupervisorSpawnRequest,
};
use ownmesh_transfer::{
    JournalLimits, JournalState, JournalStore, PartFileSink, PlanLimits, SourceCleanupBinding,
    TransferBinding, TransferChunk, TransferError, TransferGrant, TransferPlan, TransferReceiver,
    TransferSender, MAX_CHUNK_BYTES,
};
use review_manifest::{
    ResultKind, ReviewCommand, ReviewManifest, ReviewManifestStore, ReviewPhase, ReviewResultChunk,
    ReviewResultStore, TestRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use session_transition_journal::{
    SessionTransitionJournal, TransitionKind, TransitionPhase, TransitionRecord, TransitionTarget,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(test)]
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
    AdminPolicyPreset(AdminPolicyPresetParams),
    AdminPolicyRuleAdd(AdminPolicyRuleAddParams),
    AdminPolicyRuleRemove(AdminPolicyRuleRemoveParams),
    AdminDaemonUnlock(AdminDaemonUnlockParams),
    AdminTokenRevoke(AdminTokenRevokeParams),
    AdminApprovalBridge(AdminApprovalBridgeParams),
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
    /// Server-computed executable identity pin (device/inode/digest). Client values overwritten.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_pin: Option<ExecutablePin>,
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
    grants: Vec<TemporaryGrant>,
    approvals: HashMap<String, ApprovalRecord>,
    /// Completed operation results keyed by client idempotency key.
    op_journal: HashMap<String, Value>,
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
    approvals_persist_fault: AtomicUsize,
    #[cfg(test)]
    sessions_persist_fault: AtomicUsize,
    #[cfg(test)]
    transfer_journal_persist_fault: AtomicUsize,
    #[cfg(test)]
    transfer_receiver_rebuilds: AtomicUsize,
}

const MAX_CACHED_DESTINATION_TRANSFERS: usize = 256;

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
        let op_journal = load_op_journal(&paths.state_dir.join("op-journal.json"))?;
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
        #[cfg(test)]
        self.maybe_inject_persist_fault(&self.op_journal_persist_fault, "op journal")?;
        let encoded =
            serde_json::to_vec_pretty(&self.op_journal).map_err(|e| IpcError::Remote {
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
        write_json(
            &self.paths.state_dir.join("op-journal.json"),
            &self.op_journal,
        )
        .map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: format!("failed to persist op journal: {e}"),
        })
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
    fn workspace_for(&self, workspace_id: Option<&str>) -> IpcResult<WorkspaceRoot> {
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
        };
        if let Some(slot) = self.workspaces.iter_mut().find(|w| w.id == stored.id) {
            *slot = stored.clone();
        } else {
            if self.workspaces.len() >= 64 {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "workspace registry full (max 64)".into(),
                });
            }
            self.workspaces.push(stored.clone());
        }
        self.persist_workspaces()?;
        Ok(stored)
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
        ];
        if self.lockdown && !ALLOWED.contains(&method) {
            return Err(IpcError::Remote {
                code: app_error::LOCKDOWN,
                message: "emergency lockdown active; run `ownmesh unlock` locally".into(),
            });
        }
        Ok(())
    }

    fn check_pending_request_lockdown(&self, request: &PendingRequest) -> IpcResult<()> {
        if matches!(request, PendingRequest::AdminDaemonUnlock(_)) && !self.lockdown {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "device is not in emergency lockdown".into(),
            });
        }
        if self.lockdown && !matches!(request, PendingRequest::AdminDaemonUnlock(_)) {
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
        evaluate_with_grants(&self.policy, facts, &self.grants, Self::now(), principal)
    }

    fn lookup_idempotent(&self, key: Option<&String>) -> IpcResult<Option<Value>> {
        let Some(key) = key else {
            return Ok(None);
        };
        let Some(entry) = self.op_journal.get(key) else {
            return Ok(None);
        };
        if is_op_journal_in_progress(entry) {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!(
                    "idempotency key {key} has an in-progress or uncertain outcome; retry refused"
                ),
            });
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
        if self.op_journal.len() >= MAX_OP_JOURNAL_ENTRIES {
            return Err(IpcError::Remote {
                code: app_error::INTERNAL,
                message: format!(
                    "op journal at capacity ({MAX_OP_JOURNAL_ENTRIES}); refuse new idempotency key"
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
    fn store_idempotent(&mut self, key: Option<&String>, value: &Value) -> IpcResult<()> {
        let Some(k) = key else {
            return Ok(());
        };
        let snapshot = self.op_journal.clone();
        self.op_journal.insert(k.clone(), value.clone());
        if let Err(e) = self.persist_op_journal() {
            self.op_journal = snapshot;
            return Err(e);
        }
        Ok(())
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
            let mut replayed = prev;
            if let Some(obj) = replayed.as_object_mut() {
                obj.insert("replayed".into(), json!(true));
            }
            return Ok(replayed);
        }

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
                self.begin_idempotent(journal_key.as_ref(), &operation_id)?;
                // Once the durable marker exists, every execution/finalization error
                // deliberately leaves it in place. Retrying an uncertain external
                // side effect is less safe than requiring operator reconciliation.
                let result = self.execute_request(&request).await?;
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
            PendingRequest::AdminApprovalBridge(_) => Err(IpcError::Remote {
                code: app_error::INTERNAL,
                message: "approval bridge requires the authenticated approval executor".into(),
            }),
        }
    }

    async fn execute_exec(&mut self, p: &ExecParams, use_exec_journal: bool) -> IpcResult<Value> {
        // Re-resolve executable aliases immediately before execution. In particular,
        // an approval delay must not let a previously structured symlink become a shell.
        let cwd = p.cwd.as_deref().map(Path::new);
        let current_kind =
            classify_from_request_in_dir(p.kind.as_deref(), &p.program, &p.args, cwd);
        let approved_kind = CommandKind::parse_requested(p.policy_kind.as_deref());
        if matches!(current_kind, CommandKind::RawShell)
            && !matches!(approved_kind, CommandKind::RawShell)
        {
            return Err(IpcError::Remote {
                code: app_error::POLICY_DENIED,
                message: "command classification changed to raw_shell before execution; request must be re-authorized".into(),
            });
        }
        // Fail closed when the pinned executable identity/content drifted (TOCTOU).
        if let Some(pin) = &p.executable_pin {
            let pin_path = Path::new(&pin.path);
            // Prefer the pinned path; fall back to the request program only when equal.
            let check_path = if p.program == pin.path {
                Path::new(&p.program)
            } else {
                pin_path
            };
            if let Err(err) = verify_executable_pin(check_path, pin) {
                return Err(IpcError::Remote {
                    code: app_error::POLICY_DENIED,
                    message: format!(
                        "executable identity changed before execution; request must be re-authorized ({err})"
                    ),
                });
            }
            if current_kind.as_str() != pin.policy_kind {
                return Err(IpcError::Remote {
                    code: app_error::POLICY_DENIED,
                    message:
                        "command classification drifted from pinned policy_kind before execution"
                            .into(),
                });
            }
        } else if matches!(approved_kind, CommandKind::Structured)
            && Path::new(&p.program).is_absolute()
        {
            // Structured absolute executables must always carry a pin after enqueue/allow.
            return Err(IpcError::Remote {
                code: app_error::POLICY_DENIED,
                message:
                    "structured executable missing identity pin; request must be re-authorized"
                        .into(),
            });
        }
        // `handle_exec` replaced argv executable aliases with the exact canonical
        // path that was classified. Do not reopen the original symlink/PATH alias.
        let kind = CommandKind::parse_requested(p.kind.as_deref());
        let execution_program = p
            .executable_pin
            .as_ref()
            .map(|pin| pin.path.clone())
            .unwrap_or_else(|| p.program.clone());

        // Elevated execution has no local fallback.  Only the custody-attested
        // Linux v2 broker path below may spawn with privilege.
        if p.elevated {
            return self.try_broker_elevated(p).await;
        }
        // Spawn mode follows the client request shape (argv vs shell-string).
        // Policy already used server-side classification in handle_exec.
        // Hard ceilings are enforced here even if a caller bypasses MCP schema.
        let timeout_ms = p.timeout_ms.unwrap_or(30_000).clamp(1, 300_000);
        // Keep a single durable hop under the control-plane data_json budget
        // (~256 KiB) after JSON framing. Larger captures require an explicit
        // smaller max or a future spool cursor — never one giant unbounded JSON.
        let max_output_bytes = p.max_output_bytes.unwrap_or(128 * 1024).clamp(1, 200_000);
        let env = sanitize_exec_env(&p.env)?;
        let req = RunRequest {
            kind,
            program: execution_program,
            args: p.args.clone(),
            cwd: p.cwd.as_ref().map(PathBuf::from),
            env,
            stdin: None,
            timeout_ms: Some(timeout_ms),
            max_output_bytes,
            idempotency_key: p.idempotency_key.clone(),
        };
        // Approved operations are journaled by `op_journal` as part of the approval
        // transaction. Do not also mutate `exec_journal`, which cannot participate in
        // that transaction's in-memory rollback.
        let cancel = self.active_cancel.clone();
        let result: RunResult = if use_exec_journal {
            Box::pin(run_command_cancellable(
                &req,
                Some(&mut self.exec_journal),
                cancel,
            ))
            .await
        } else {
            Box::pin(run_command_cancellable(&req, None, cancel)).await
        }
        .map_err(|e| {
            let code = match &e {
                ownmesh_exec::ExecError::Cancelled => app_error::CONFLICT,
                _ => app_error::INTERNAL,
            };
            IpcError::Remote {
                code,
                message: e.to_string(),
            }
        })?;
        serde_json::to_value(result).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })
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
        let timeout_ms = p.timeout_ms.unwrap_or(30_000).clamp(1, 300_000);
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

    fn execute_fs_list(&self, p: &FsListParams) -> IpcResult<Value> {
        let ws = self.workspace_for(p.workspace_id.as_deref())?;
        let max_entries = p.max_entries.unwrap_or(200).clamp(1, 500);
        let page = list_dir_page(&ws, &p.path, p.recursive, max_entries, p.cursor.as_deref())
            .map_err(fs_err)?;
        Ok(json!({
            "entries": page.entries,
            "next_cursor": page.next_cursor,
            "truncated": page.truncated,
            "total_matched": page.total_matched,
            "workspace_id": p.workspace_id.as_deref().unwrap_or("ws_default"),
        }))
    }

    fn execute_fs_stat(&self, p: &FsStatParams) -> IpcResult<Value> {
        let ws = self.workspace_for(p.workspace_id.as_deref())?;
        let st = stat_path(&ws, &p.path, p.hash).map_err(fs_err)?;
        serde_json::to_value(st).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })
    }

    fn execute_fs_read(&self, p: &FsReadParams) -> IpcResult<Value> {
        // Hard cap per hop so Base64(~4/3) + metadata fits:
        // - Agent envelope 750 KiB JSON
        // - Durable MCP data_json 256 KiB
        // Larger files are retrieved by paging offset/max_bytes (next_offset).
        const MAX_READ_BYTES: u64 = 160 * 1024;
        let ws = self.workspace_for(p.workspace_id.as_deref())?;
        let offset = p.offset.unwrap_or(0);
        let want = p.max_bytes.unwrap_or(64 * 1024).min(MAX_READ_BYTES);
        let (data, total, truncated) =
            ownmesh_fs::read_file_range(&ws, &p.path, offset, want).map_err(fs_err)?;
        let returned = data.len() as u64;
        let next_offset = offset.saturating_add(returned);
        // Prefer UTF-8 text; otherwise return standard Base64 (RFC 4648 with padding)
        // so clients can decode without inventing a custom alphabet. Never lossy-decode
        // arbitrary bytes as text.
        let (encoding, content) = match String::from_utf8(data.clone()) {
            Ok(text) => ("utf-8", Value::String(text)),
            Err(_) => ("base64", Value::String(base64_standard(&data))),
        };
        let mut body = json!({
            "path": p.path,
            "content": content,
            "encoding": encoding,
            "offset": offset,
            "bytes": returned,
            "returned_bytes": returned,
            "total_bytes": total,
            "truncated": truncated,
            "sha256": sha256_hex(&data),
        });
        if truncated {
            body.as_object_mut()
                .expect("object")
                .insert("next_offset".into(), json!(next_offset));
        }
        Ok(body)
    }

    fn execute_fs_write(&self, p: &FsWriteParams) -> IpcResult<Value> {
        let ws = self.workspace_for(p.workspace_id.as_deref())?;
        let format = p
            .patch_format
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("");
        // Explicit replace always wins. Unified is selected by format or by a
        // hash-checked patch whose body is a unified diff (E7).
        let use_unified = match format {
            "replace" | "whole" | "full" => false,
            "unified" | "unified_diff" | "diff" => true,
            _ if p.expected_sha256.is_some() && looks_like_unified_diff(&p.content) => true,
            _ => false,
        };

        if use_unified {
            let new_hash =
                apply_unified_diff(&ws, &p.path, &p.content, p.expected_sha256.as_deref())
                    .map_err(fs_err)?;
            return Ok(json!({
                "path": p.path,
                "bytes_written": p.content.len(),
                "sha256": new_hash,
                "patched": true,
                "patch_format": "unified",
                "workspace_id": p.workspace_id.as_deref().unwrap_or("ws_default"),
            }));
        }

        if let Some(expected) = p.expected_sha256.as_deref() {
            let new_hash =
                apply_patch(&ws, &p.path, p.content.as_bytes(), Some(expected)).map_err(fs_err)?;
            return Ok(json!({
                "path": p.path,
                "bytes_written": p.content.len(),
                "sha256": new_hash,
                "patched": true,
                "patch_format": "replace",
                "workspace_id": p.workspace_id.as_deref().unwrap_or("ws_default"),
            }));
        }
        write_file(&ws, &p.path, p.content.as_bytes()).map_err(fs_err)?;
        Ok(json!({
            "path": p.path,
            "bytes_written": p.content.len(),
            "workspace_id": p.workspace_id.as_deref().unwrap_or("ws_default"),
        }))
    }

    fn execute_fs_delete(&self, p: &FsDeleteParams) -> IpcResult<Value> {
        let ws = self.workspace_for(p.workspace_id.as_deref())?;
        delete_path(&ws, &p.path, p.recursive).map_err(fs_err)?;
        Ok(json!({
            "path": p.path,
            "deleted": true,
            "workspace_id": p.workspace_id.as_deref().unwrap_or("ws_default"),
        }))
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
            .query(cursor.as_ref(), p.limit.unwrap_or(100))
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
        serde_json::to_value(page).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })
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
        serde_json::to_value(page).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })
    }

    async fn handle_exec(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let mut p: ExecParams = parse_params(params)?;
        // Never trust client-supplied pins / policy classification.
        p.executable_pin = None;
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
        if matches!(
            CommandKind::parse_requested(p.kind.as_deref()),
            CommandKind::Structured
        ) {
            if let Some(resolved) = resolve_executable_path(&p.program, cwd) {
                p.program = resolved.to_string_lossy().into_owned();
            }
        }
        // Reclassify on the server so direct shells, resolved shell symlinks, and
        // all `env` indirection cannot bypass raw_shell rules.
        let kind = classify_from_request_in_dir(p.kind.as_deref(), &p.program, &p.args, cwd);
        p.policy_kind = Some(kind.as_str().to_owned());
        if matches!(kind, CommandKind::Structured) {
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
        // Facts carry only server-computed pin identity — never client digests.
        let facts = OperationFacts {
            capability: "command.run".into(),
            kind: kind.as_str().to_string(),
            program: Some(p.program.clone()),
            elevated: p.elevated,
            path: p.cwd.clone(),
            workspace_relative: false,
            executable_identity: p.executable_pin.as_ref().map(executable_identity_from_pin),
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::Exec(Box::new(p)), client)
            .await
    }

    fn transfer_error(error: TransferError) -> IpcError {
        let code = match error {
            TransferError::DestinationExists | TransferError::Replay | TransferError::Gap => {
                app_error::CONFLICT
            }
            TransferError::InvalidBinding(_)
            | TransferError::InvalidPlan(_)
            | TransferError::ChunkTooLarge
            | TransferError::MalformedChunk
            | TransferError::ChunkHashMismatch
            | TransferError::Overflow => app_error::INVALID_PARAMS,
            TransferError::PlatformUnsupported => app_error::PLATFORM_UNSUPPORTED,
            TransferError::SourceChanged
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

    async fn handle_transfer_plan(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            source_path: String,
            destination_path: String,
            destination_workspace_id: String,
            #[serde(default)]
            workspace_id: Option<String>,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let source_workspace_id = p.workspace_id.unwrap_or_else(|| "ws_default".into());
        let binding = TransferBinding {
            tenant_id: authority.tenant_id.clone(),
            source_principal_id: authority.principal_id.clone(),
            destination_principal_id: authority.principal_id.clone(),
            source_device_id: authority.device_id.clone(),
            destination_device_id: authority.device_id.clone(),
            source_workspace_id: source_workspace_id.clone(),
            destination_workspace_id: p.destination_workspace_id.clone(),
            source_relative_path: p.source_path,
            destination_relative_path: p.destination_path,
        };
        binding.validate().map_err(Self::transfer_error)?;
        // Source planning owns only source custody.  The destination Agent
        // performs its own workspace/no-replace preflight and later obtains the
        // destination lease.  Resolving a remote destination root here would
        // incorrectly require two devices to share a daemon filesystem.
        // TransferBinding::validate above still rejects absolute/traversal paths
        // before either value becomes immutable plan metadata.
        let source = self.workspace_for(Some(&source_workspace_id))?;
        let source_handle = source
            .open_verified_read(Path::new(&binding.source_relative_path))
            .map_err(fs_err)?;
        let grant = TransferGrant {
            grant_id: format!("grant_{}", authority.operation_id),
            operation_id: authority.operation_id.clone(),
            payload_sha256: authority.payload_sha256.clone(),
            expires_at_unix: authority.expires_at_unix,
        };
        let plan = TransferPlan::for_workspace_source(
            source_handle,
            binding,
            grant,
            PlanLimits::default(),
            Self::now() as u64,
        )
        .map_err(Self::transfer_error)?;
        self.transfer_store
            .save_plan(&plan)
            .map_err(Self::transfer_error)?;
        Ok(json!({
            "plan_id": plan.id(),
            "size_bytes": plan.size_bytes(),
            "sha256": plan.sha256(),
            "source_workspace_id": plan.binding().source_workspace_id,
            "destination_workspace_id": plan.binding().destination_workspace_id,
            "expires_at_unix": authority.expires_at_unix,
        }))
    }

    /// Internal source-side preflight used only by the authenticated Agent
    /// transport.  It hashes from a pinned source custody path and creates the
    /// immutable local source plan, but deliberately does not inspect a
    /// destination filesystem: that custody boundary belongs to the other
    /// device's `transfer.preflight_destination` operation.
    async fn handle_transfer_preflight_source(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            transfer_id: String,
            source_path: String,
            destination_path: String,
            source_principal_id: String,
            destination_principal_id: String,
            source_device_id: String,
            destination_device_id: String,
            source_workspace_id: String,
            destination_workspace_id: String,
            epoch: u32,
            fence: u64,
            session_nonce: String,
            expires_at: u64,
            coordinator_request_id: String,
            workspace_version: u64,
            #[serde(default)]
            plan_sha256: Option<String>,
            #[serde(default)]
            content_sha256: Option<String>,
            #[serde(default)]
            size_bytes: Option<u64>,
            #[serde(default)]
            grant_id: Option<String>,
            #[serde(default)]
            grant_operation_id: Option<String>,
            #[serde(default)]
            grant_payload_sha256: Option<String>,
            #[serde(default)]
            grant_expires_at_unix: Option<u64>,
            #[serde(default)]
            workspace_id: Option<String>,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let source_workspace_id = p.workspace_id.unwrap_or_else(|| "ws_default".into());
        let binding = TransferBinding {
            tenant_id: authority.tenant_id.clone(),
            source_principal_id: p.source_principal_id,
            destination_principal_id: p.destination_principal_id,
            source_device_id: p.source_device_id,
            destination_device_id: p.destination_device_id,
            source_workspace_id: source_workspace_id.clone(),
            destination_workspace_id: p.destination_workspace_id,
            source_relative_path: p.source_path,
            destination_relative_path: p.destination_path,
        };
        if p.transfer_id.is_empty()
            || p.transfer_id.len() > 256
            || p.transfer_id.bytes().any(|byte| byte.is_ascii_control())
            || p.epoch == 0
            || p.fence == 0
            || p.session_nonce.is_empty()
            || p.session_nonce.len() > 256
            || p.session_nonce.bytes().any(|byte| byte.is_ascii_control())
            || p.expires_at <= (Self::now() as u64).saturating_mul(1000)
            || p.coordinator_request_id.is_empty()
            || p.coordinator_request_id.len() > 256
            || p.coordinator_request_id
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || p.workspace_version == 0
            || p.source_workspace_id != source_workspace_id
            || binding.source_principal_id != authority.principal_id
            || binding.source_device_id != authority.device_id
        {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "source preflight is not bound to the authenticated Agent identity".into(),
            });
        }
        binding.validate().map_err(Self::transfer_error)?;
        let source = self.workspace_for(Some(&source_workspace_id))?;
        let source_handle = source
            .open_verified_read(Path::new(&binding.source_relative_path))
            .map_err(fs_err)?;
        let final_plan = match (
            p.plan_sha256,
            p.content_sha256,
            p.size_bytes,
            p.grant_id,
            p.grant_operation_id,
            p.grant_payload_sha256,
            p.grant_expires_at_unix,
        ) {
            (None, None, None, None, None, None, None) => None,
            (
                Some(plan_sha256),
                Some(content_sha256),
                Some(size_bytes),
                Some(grant_id),
                Some(operation_id),
                Some(payload_sha256),
                Some(expires_at_unix),
            ) => {
                if expires_at_unix != authority.expires_at_unix {
                    return Err(IpcError::Remote {
                        code: app_error::UNAUTHORIZED,
                        message: "final transfer grant expiry differs from authenticated operation"
                            .into(),
                    });
                }
                let grant = TransferGrant {
                    grant_id,
                    operation_id,
                    payload_sha256,
                    expires_at_unix,
                };
                let verified =
                    TransferPlan::from_verified(binding.clone(), grant, size_bytes, content_sha256)
                        .map_err(Self::transfer_error)?;
                if verified.plan_sha256() != plan_sha256 {
                    return Err(IpcError::Remote {
                        code: app_error::UNAUTHORIZED,
                        message: "final transfer plan digest is not canonical".into(),
                    });
                }
                Some(verified)
            }
            _ => {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "final transfer preflight fields must be supplied together".into(),
                })
            }
        };
        let grant = TransferGrant {
            grant_id: format!("grant_{}", authority.operation_id),
            operation_id: authority.operation_id.clone(),
            payload_sha256: authority.payload_sha256.clone(),
            expires_at_unix: authority.expires_at_unix,
        };
        let observed = TransferPlan::for_workspace_source(
            source_handle,
            binding,
            grant,
            PlanLimits::default(),
            Self::now() as u64,
        )
        .map_err(Self::transfer_error)?;
        let plan = if let Some(final_plan) = final_plan {
            if observed.size_bytes() != final_plan.size_bytes()
                || observed.sha256() != final_plan.sha256()
            {
                return Err(IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: "source changed after preflight evidence".into(),
                });
            }
            final_plan
        } else {
            observed
        };
        self.transfer_store
            .save_plan(&plan)
            .map_err(Self::transfer_error)?;
        Ok(json!({
            "transfer_id": p.transfer_id,
            "role": "source",
            "tenant_id": authority.tenant_id,
            "principal_id": authority.principal_id,
            "device_id": authority.device_id,
            "workspace_id": plan.binding().source_workspace_id,
            "plan_id": plan.id(),
            "size_bytes": plan.size_bytes(),
            "sha256": plan.sha256(),
            "plan_sha256": plan.plan_sha256(),
            "source_workspace_id": plan.binding().source_workspace_id,
            "destination_workspace_id": plan.binding().destination_workspace_id,
            "epoch": p.epoch,
            "fence": p.fence,
            "session_nonce": p.session_nonce,
            "expires_at": p.expires_at,
            "coordinator_request_id": p.coordinator_request_id,
            "workspace_version": p.workspace_version,
            "expires_at_unix": authority.expires_at_unix,
        }))
    }

    /// Internal destination-side preflight.  It is intentionally read-only:
    /// reserve/part-file creation happens later in `destination_prepare`, after
    /// both authenticated Agent replies have been correlated by the coordinator.
    async fn handle_transfer_preflight_destination(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            transfer_id: String,
            source_path: String,
            destination_path: String,
            source_principal_id: String,
            destination_principal_id: String,
            source_device_id: String,
            destination_device_id: String,
            source_workspace_id: String,
            destination_workspace_id: String,
            workspace_id: String,
            plan_sha256: String,
            epoch: u32,
            fence: u64,
            session_nonce: String,
            expires_at: u64,
            coordinator_request_id: String,
            workspace_version: u64,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let binding = TransferBinding {
            tenant_id: authority.tenant_id.clone(),
            source_principal_id: p.source_principal_id,
            destination_principal_id: p.destination_principal_id,
            source_device_id: p.source_device_id,
            destination_device_id: p.destination_device_id,
            source_workspace_id: p.source_workspace_id,
            destination_workspace_id: p.workspace_id.clone(),
            source_relative_path: p.source_path,
            destination_relative_path: p.destination_path,
        };
        if p.transfer_id.is_empty()
            || p.transfer_id.len() > 256
            || p.transfer_id.bytes().any(|byte| byte.is_ascii_control())
            || p.epoch == 0
            || p.fence == 0
            || p.session_nonce.is_empty()
            || p.session_nonce.len() > 256
            || p.session_nonce.bytes().any(|byte| byte.is_ascii_control())
            || p.expires_at <= (Self::now() as u64).saturating_mul(1000)
            || p.coordinator_request_id.is_empty()
            || p.coordinator_request_id.len() > 256
            || p.coordinator_request_id
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || p.workspace_version == 0
            || p.destination_workspace_id != p.workspace_id
            || !p
                .plan_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || p.plan_sha256.len() != 64
            || binding.destination_principal_id != authority.principal_id
            || binding.destination_device_id != authority.device_id
        {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "destination preflight is not bound to the authenticated Agent identity"
                    .into(),
            });
        }
        binding.validate().map_err(Self::transfer_error)?;
        let workspace = self.workspace_for(Some(&binding.destination_workspace_id))?;
        let destination = workspace
            .resolve(Path::new(&binding.destination_relative_path))
            .map_err(fs_err)?;
        if destination.exists() {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "destination already exists; overwrite is forbidden".into(),
            });
        }
        let parent = destination.parent().ok_or_else(|| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: "destination parent is missing".into(),
        })?;
        let parent_meta = std::fs::symlink_metadata(parent).map_err(|error| IpcError::Remote {
            code: app_error::INTERNAL,
            message: format!("inspect destination parent: {error}"),
        })?;
        if !parent_meta.is_dir() || parent_meta.file_type().is_symlink() {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "destination parent is not a pinned workspace directory".into(),
            });
        }
        Ok(json!({
            "transfer_id": p.transfer_id,
            "role": "destination",
            "tenant_id": authority.tenant_id,
            "principal_id": authority.principal_id,
            "device_id": authority.device_id,
            "workspace_id": binding.destination_workspace_id,
            "plan_sha256": p.plan_sha256,
            "destination_workspace_id": binding.destination_workspace_id,
            "destination_path": binding.destination_relative_path,
            "epoch": p.epoch,
            "fence": p.fence,
            "session_nonce": p.session_nonce,
            "expires_at": p.expires_at,
            "coordinator_request_id": p.coordinator_request_id,
            "workspace_version": p.workspace_version,
            "available": true,
            "expires_at_unix": authority.expires_at_unix,
        }))
    }

    /// Strict Agent-only admission for a ticket-bound transfer session.  The
    /// bearer remains opaque and is never persisted or returned from runtime.
    async fn handle_transfer_start(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            transfer_id: String,
            role: String,
            ticket: String,
            plan_sha256: String,
            content_sha256: String,
            size_bytes: u64,
            source_path: String,
            destination_path: String,
            source_device_id: String,
            destination_device_id: String,
            source_workspace_id: String,
            destination_workspace_id: String,
            source_workspace_version: u64,
            destination_workspace_version: u64,
            workspace_id: String,
            workspace_version: u64,
            epoch: u32,
            fence: u64,
            grant_id: String,
            grant_operation_id: String,
            grant_payload_sha256: String,
            grant_expires_at_unix: u64,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let hex =
            |value: &str| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
        let local_device = if p.role == "source" {
            &p.source_device_id
        } else {
            &p.destination_device_id
        };
        let local_workspace = if p.role == "source" {
            &p.source_workspace_id
        } else {
            &p.destination_workspace_id
        };
        if !matches!(p.role.as_str(), "source" | "destination")
            || p.transfer_id.is_empty()
            || p.transfer_id.len() > 256
            || p.source_path.is_empty()
            || p.destination_path.is_empty()
            || p.source_path.len() > 4096
            || p.destination_path.len() > 4096
            || p.source_path.contains('\\')
            || p.destination_path.contains('\\')
            || p.source_path
                .split('/')
                .any(|part| part == "." || part == ".." || part.is_empty())
            || p.destination_path
                .split('/')
                .any(|part| part == "." || part == ".." || part.is_empty())
            || p.transfer_id != p.grant_id
            || p.grant_operation_id != p.transfer_id
            || p.grant_expires_at_unix != authority.expires_at_unix
            || authority.device_id != *local_device
            || p.workspace_id != *local_workspace
            || p.epoch == 0
            || p.fence == 0
            || p.workspace_version == 0
            || p.source_workspace_version == 0
            || p.destination_workspace_version == 0
            || !hex(&p.plan_sha256)
            || !hex(&p.content_sha256)
            || !hex(&p.grant_payload_sha256)
            || p.ticket.is_empty()
            || p.ticket.len() > 16 * 1024
            || p.ticket.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "invalid ticket-bound transfer start".into(),
            });
        }
        let binding = TransferBinding {
            tenant_id: authority.tenant_id.clone(),
            source_principal_id: authority.principal_id.clone(),
            destination_principal_id: authority.principal_id.clone(),
            source_device_id: p.source_device_id,
            destination_device_id: p.destination_device_id,
            source_workspace_id: p.source_workspace_id,
            destination_workspace_id: p.destination_workspace_id,
            source_relative_path: p.source_path,
            destination_relative_path: p.destination_path,
        };
        let plan = TransferPlan::from_verified(
            binding,
            TransferGrant {
                grant_id: p.grant_id,
                operation_id: p.grant_operation_id,
                payload_sha256: p.grant_payload_sha256,
                expires_at_unix: p.grant_expires_at_unix,
            },
            p.size_bytes,
            p.content_sha256,
        )
        .map_err(Self::transfer_error)?;
        if plan.plan_sha256() != p.plan_sha256 {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "transfer start plan hash mismatch".into(),
            });
        }
        self.transfer_store
            .save_plan(&plan)
            .map_err(Self::transfer_error)?;
        // `ticket` is passed straight to connect_transfer_socket by the Agent
        // transport.  This receipt intentionally omits the bearer and paths.
        Ok(
            json!({ "transfer_id": p.transfer_id, "plan_id": plan.id(), "role": p.role, "plan_sha256": p.plan_sha256, "epoch": p.epoch, "fence": p.fence, "admitted": true }),
        )
    }

    fn transfer_plan_for(
        &self,
        plan_id: &str,
        authority: &TransferAuthority,
        role: Option<&str>,
    ) -> IpcResult<TransferPlan> {
        let plan = self
            .transfer_store
            .load_plan(plan_id, Self::now() as u64)
            .map_err(Self::transfer_error)?
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "transfer plan was not found".into(),
            })?;
        Self::verify_local_transfer_identity(&plan, authority, role)?;
        Ok(plan)
    }

    async fn handle_transfer_source_open(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            plan_id: String,
            #[serde(default)]
            sequence: u64,
            #[serde(default)]
            offset: u64,
            #[serde(default)]
            workspace_id: Option<String>,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let plan = self.transfer_plan_for(&p.plan_id, &authority, Some("source"))?;
        if p.workspace_id.as_deref().unwrap_or("ws_default") != plan.binding().source_workspace_id {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "source open workspace does not match immutable plan".into(),
            });
        }
        let workspace = self.workspace_for(Some(&plan.binding().source_workspace_id))?;
        let sender = self
            .transfer_store
            .open_source_sender_at_lazy(plan.clone(), p.sequence, p.offset, || {
                workspace
                    .open_verified_read(Path::new(&plan.binding().source_relative_path))
                    .map_err(|_| TransferError::CustodyUnavailable)
            })
            .map_err(Self::transfer_error)?;
        self.transfer_senders.insert(plan.id().to_owned(), sender);
        self.transfer_last_chunks.remove(plan.id());
        Ok(
            json!({ "plan_id": plan.id(), "next_sequence": p.sequence, "next_offset": p.offset, "chunk_max_bytes": MAX_CHUNK_BYTES }),
        )
    }

    async fn handle_transfer_source_chunk(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            plan_id: String,
            sequence: u64,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let plan = self.transfer_plan_for(&p.plan_id, &authority, Some("source"))?;
        if let Some((sequence, frame)) = self.transfer_last_chunks.get(plan.id()) {
            if *sequence == p.sequence {
                return Ok(
                    json!({ "plan_id": plan.id(), "sequence": sequence, "frame_base64": frame, "replayed": true }),
                );
            }
        }
        let next = self
            .transfer_senders
            .get_mut(plan.id())
            .ok_or_else(|| IpcError::Remote {
                code: app_error::CONFLICT,
                message: "source is not open; reopen at the durable receiver cursor".into(),
            })?
            .next_chunk()
            .map_err(Self::transfer_error)?;
        let Some(chunk) = next else {
            self.transfer_senders.remove(plan.id());
            self.transfer_last_chunks.remove(plan.id());
            // Keep the immutable source snapshot + plan until the Agent has
            // received the Room's authenticated finish_ack. A disconnect
            // after the last destination ACK must be able to reopen exactly
            // this retained handle at offset == size without trusting a path.
            return Ok(json!({ "plan_id": plan.id(), "sequence": p.sequence, "eof": true }));
        };
        if chunk.sequence != p.sequence {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "source chunk sequence is not the requested contiguous cursor".into(),
            });
        }
        let frame = base64_standard(&chunk.encode().map_err(Self::transfer_error)?);
        self.transfer_last_chunks
            .insert(plan.id().to_owned(), (chunk.sequence, frame.clone()));
        Ok(
            json!({ "plan_id": plan.id(), "sequence": chunk.sequence, "offset": chunk.offset, "bytes": chunk.bytes.len(), "sha256": chunk.sha256, "frame_base64": frame, "replayed": false }),
        )
    }

    async fn handle_transfer_destination_prepare(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            plan_id: String,
            epoch: u64,
            fence: u64,
            next_sequence: u64,
            next_offset: u64,
            workspace_id: String,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let plan = self.transfer_plan_for(&p.plan_id, &authority, Some("destination"))?;
        if p.workspace_id != plan.binding().destination_workspace_id {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "destination workspace does not match immutable plan".into(),
            });
        }
        let workspace = self.workspace_for(Some(&p.workspace_id))?;
        let destination = workspace
            .resolve(Path::new(&plan.binding().destination_relative_path))
            .map_err(fs_err)?;
        if let Some(journal) = self
            .transfer_store
            .load(&plan)
            .map_err(Self::transfer_error)?
        {
            if journal.published() {
                self.transfer_receivers.remove(plan.id());
                let mut artifact = workspace
                    .open_verified_transfer_artifact_read(Path::new(
                        &plan.binding().destination_relative_path,
                    ))
                    .map_err(fs_err)?
                    .into_file();
                self.transfer_store
                    .verify_published_destination_handle(&plan, &mut artifact)
                    .map_err(Self::transfer_error)?;
                return Ok(
                    json!({ "plan_id": plan.id(), "state": journal.state(), "next_sequence": journal.contiguous_ack().map(|v| v + 1).unwrap_or(0), "next_offset": journal.bytes_received(), "epoch": p.epoch, "fence": p.fence, "completed": true, "published": true }),
                );
            }
        }
        if destination.exists() {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "destination already exists; overwrite is forbidden".into(),
            });
        }
        self.ensure_destination_cache_capacity(plan.id())
            .map_err(Self::transfer_error)?;
        let now = Self::now() as u64;
        let lease = self
            .transfer_store
            .acquire_for_fence(&plan, now, authority.expires_at_unix, p.epoch, p.fence)
            .map_err(Self::transfer_error)?;
        let journal = self
            .transfer_store
            .claim_at_room_cursor(
                &lease,
                &plan,
                &authority.principal_id,
                p.epoch,
                p.fence,
                now,
                authority.expires_at_unix,
                p.next_sequence,
                p.next_offset,
            )
            .map_err(Self::transfer_error)?;
        // The fresh durable fence is authoritative now. Drop the prior
        // generation's retained handle before PartFileSink stages/removes its
        // generation path (required for no-share-delete Windows handles).
        self.transfer_receivers.remove(plan.id());
        if journal.state() == JournalState::Completed {
            let mut sink = PartFileSink::create(
                &self.transfer_store,
                &plan,
                p.epoch,
                journal.bytes_received(),
            )
            .map_err(Self::transfer_error)?;
            sink.verify_complete().map_err(Self::transfer_error)?;
            return Ok(
                json!({ "plan_id": plan.id(), "state": journal.state(), "next_sequence": p.next_sequence, "next_offset": p.next_offset, "epoch": journal.epoch(), "fence": journal.fence(), "completed": true }),
            );
        }
        let cached = self
            .rebuild_destination_transfer(plan.clone(), journal.clone(), p.epoch, p.fence)
            .map_err(Self::transfer_error)?;
        self.transfer_receivers.insert(plan.id().to_owned(), cached);
        Ok(
            json!({ "plan_id": plan.id(), "state": journal.state(), "next_sequence": journal.contiguous_ack().map(|v| v + 1).unwrap_or(0), "next_offset": journal.bytes_received(), "epoch": journal.epoch(), "fence": journal.fence() }),
        )
    }

    async fn handle_transfer_destination_chunk(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            plan_id: String,
            epoch: u64,
            fence: u64,
            frame_base64: String,
            workspace_id: String,
        }
        let p: Params = parse_params(params)?;
        if p.frame_base64.len() > (MAX_CHUNK_BYTES + 52).div_ceil(3) * 4 {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "transfer frame exceeds bounded base64 budget".into(),
            });
        }
        let authority = self.transfer_authority(client)?;
        let plan = self.transfer_plan_for(&p.plan_id, &authority, Some("destination"))?;
        if p.workspace_id != plan.binding().destination_workspace_id {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "destination chunk workspace does not match immutable plan".into(),
            });
        }
        let frame = base64_decode_strict(&p.frame_base64).ok_or_else(|| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: "transfer frame is not canonical base64".into(),
        })?;
        let chunk = TransferChunk::decode(&frame).map_err(Self::transfer_error)?;
        let now = Self::now() as u64;
        let lease = self
            .transfer_store
            .acquire(&plan, now, authority.expires_at_unix)
            .map_err(Self::transfer_error)?;
        let journal = self
            .transfer_store
            .load_for_fence(&plan, p.epoch, p.fence)
            .map_err(Self::transfer_error)?;
        self.ensure_destination_cache_capacity(plan.id())
            .map_err(Self::transfer_error)?;
        // Remove while mutating so every error path evicts the rolling state.
        // Only an exact durable cursor match may reuse the retained handle.
        let cached = self.transfer_receivers.remove(plan.id());
        let mut active = match cached {
            Some(cached) => {
                if !cached.matches(p.epoch, p.fence, &journal) {
                    return Err(Self::transfer_error(TransferError::CorruptJournal));
                }
                cached
                    .sink
                    .validate_cached_position(journal.bytes_received())
                    .map_err(Self::transfer_error)?;
                cached
            }
            None => self
                .rebuild_destination_transfer(plan.clone(), journal.clone(), p.epoch, p.fence)
                .map_err(Self::transfer_error)?,
        };
        active
            .receiver
            .receive(&mut active.sink, chunk)
            .map_err(Self::transfer_error)?;
        let updated = active.receiver.journal_snapshot();
        #[cfg(test)]
        self.maybe_inject_persist_fault(&self.transfer_journal_persist_fault, "transfer journal")?;
        self.transfer_store
            .save(&lease, &updated)
            .map_err(Self::transfer_error)?;
        if updated.state() == JournalState::Receiving {
            self.transfer_receivers.insert(plan.id().to_owned(), active);
        }
        Ok(
            json!({ "plan_id": plan.id(), "state": updated.state(), "contiguous_ack": updated.contiguous_ack(), "bytes_received": updated.bytes_received(), "completed": updated.state() == JournalState::Completed }),
        )
    }

    async fn handle_transfer_finalize(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            plan_id: String,
            epoch: u64,
            fence: u64,
            workspace_id: String,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let plan = self.transfer_plan_for(&p.plan_id, &authority, Some("destination"))?;
        if p.workspace_id != plan.binding().destination_workspace_id {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "finalize workspace does not match immutable plan".into(),
            });
        }
        let journal = self
            .transfer_store
            .load(&plan)
            .map_err(Self::transfer_error)?
            .ok_or_else(|| IpcError::Remote {
                code: app_error::CONFLICT,
                message: "transfer is incomplete".into(),
            })?;
        let workspace = self.workspace_for(Some(&p.workspace_id))?;
        if journal.published() {
            self.transfer_receivers.remove(plan.id());
            let mut artifact = workspace
                .open_verified_transfer_artifact_read(Path::new(
                    &plan.binding().destination_relative_path,
                ))
                .map_err(fs_err)?
                .into_file();
            self.transfer_store
                .verify_published_destination_handle(&plan, &mut artifact)
                .map_err(Self::transfer_error)?;
            drop(artifact);
            self.transfer_store
                .cleanup_published_generation_parts(&plan)
                .map_err(Self::transfer_error)?;
            return Ok(
                json!({ "plan_id": plan.id(), "published": true, "replayed": true, "sha256": plan.sha256(), "size_bytes": plan.size_bytes() }),
            );
        }
        if journal.epoch() != p.epoch
            || journal.fence() != p.fence
            || journal.state() != JournalState::Completed
        {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "transfer is incomplete".into(),
            });
        }
        // Only an exact terminal fence may release the retained append handle
        // before publish. Stale or premature finalize requests cannot evict a
        // healthy long-running receiver.
        self.transfer_receivers.remove(plan.id());
        let lease = self
            .transfer_store
            .acquire(&plan, Self::now() as u64, authority.expires_at_unix)
            .map_err(Self::transfer_error)?;
        match self
            .transfer_store
            .publish_completed_no_replace(&plan, &workspace)
        {
            Ok(()) | Err(ownmesh_transfer::TransferError::DestinationExists) => {
                let mut artifact = workspace
                    .open_verified_transfer_artifact_read(Path::new(
                        &plan.binding().destination_relative_path,
                    ))
                    .map_err(fs_err)?
                    .into_file();
                self.transfer_store
                    .verify_published_destination_handle(&plan, &mut artifact)
                    .map_err(Self::transfer_error)?;
            }
            Err(error) => return Err(Self::transfer_error(error)),
        }
        // The destination file is now verified as the exact immutable plan
        // artifact. Persist this receipt before returning so a crash after the
        // no-replace publish is replay-safe rather than a false conflict.
        let mut receipt = self
            .transfer_store
            .load_for_fence(&plan, p.epoch, p.fence)
            .map_err(Self::transfer_error)?;
        receipt
            .mark_published(&plan)
            .map_err(Self::transfer_error)?;
        self.transfer_store
            .save(&lease, &receipt)
            .map_err(Self::transfer_error)?;
        self.transfer_store
            .cleanup_published_generation_parts(&plan)
            .map_err(Self::transfer_error)?;
        Ok(
            json!({ "plan_id": plan.id(), "published": true, "replayed": false, "sha256": plan.sha256(), "size_bytes": plan.size_bytes() }),
        )
    }

    async fn handle_transfer_status(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            plan_id: String,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let plan = self.transfer_plan_for(&p.plan_id, &authority, None)?;
        let journal = self
            .transfer_store
            .load(&plan)
            .map_err(Self::transfer_error)?;
        Ok(
            json!({ "plan_id": plan.id(), "size_bytes": plan.size_bytes(), "sha256": plan.sha256(), "state": journal.as_ref().map(ownmesh_transfer::TransferJournal::state), "contiguous_ack": journal.as_ref().and_then(ownmesh_transfer::TransferJournal::contiguous_ack), "bytes_received": journal.as_ref().map(ownmesh_transfer::TransferJournal::bytes_received).unwrap_or(0) }),
        )
    }

    async fn handle_transfer_list(
        &mut self,
        _params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let authority = self.transfer_authority(client)?;
        let plans = self
            .transfer_store
            .list_plans(Self::now() as u64)
            .map_err(Self::transfer_error)?;
        let mut entries = Vec::new();
        for plan in plans {
            if Self::verify_local_transfer_identity(&plan, &authority, None).is_ok() {
                let journal = self
                    .transfer_store
                    .load(&plan)
                    .map_err(Self::transfer_error)?;
                entries.push(json!({ "plan_id": plan.id(), "source_workspace_id": plan.binding().source_workspace_id, "destination_workspace_id": plan.binding().destination_workspace_id, "size_bytes": plan.size_bytes(), "sha256": plan.sha256(), "state": journal.as_ref().map(ownmesh_transfer::TransferJournal::state), "bytes_received": journal.as_ref().map(ownmesh_transfer::TransferJournal::bytes_received).unwrap_or(0) }));
            }
        }
        Ok(json!({ "transfers": entries }))
    }

    async fn handle_transfer_cancel(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            plan_id: String,
            epoch: u64,
            fence: u64,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let cleanup_binding = SourceCleanupBinding {
            plan_id: p.plan_id.clone(),
            tenant_id: authority.tenant_id.clone(),
            principal_id: authority.principal_id.clone(),
            device_id: authority.device_id.clone(),
            epoch: p.epoch,
            fence: p.fence,
        };
        if let Some(outcome) = self
            .transfer_store
            .complete_source_cleanup(&cleanup_binding, Self::now() as u64)
            .map_err(Self::transfer_error)?
        {
            self.transfer_senders.remove(&p.plan_id);
            self.transfer_last_chunks.remove(&p.plan_id);
            self.transfer_receivers.remove(&p.plan_id);
            return Ok(
                json!({ "plan_id": p.plan_id, "cancelled": true, "source_only": true, "replayed": outcome.replayed }),
            );
        }
        let plan = self.transfer_plan_for(&p.plan_id, &authority, None)?;
        let journal = match self.transfer_store.load_for_fence(&plan, p.epoch, p.fence) {
            Ok(journal) => journal,
            // A source Agent has no receiver journal or part file to cancel.
            // It still owns an in-memory sender cache which must be dropped on
            // an authenticated transfer cancellation; do not manufacture a
            // destination journal on the source device.
            Err(ownmesh_transfer::TransferError::Terminal)
                if plan.binding().source_device_id == authority.device_id
                    && plan.binding().destination_device_id != authority.device_id =>
            {
                self.transfer_senders.remove(plan.id());
                self.transfer_last_chunks.remove(plan.id());
                self.transfer_store
                    .begin_source_cleanup(&plan, &cleanup_binding, Self::now() as u64)
                    .map_err(Self::transfer_error)?;
                let outcome = self
                    .transfer_store
                    .complete_source_cleanup(&cleanup_binding, Self::now() as u64)
                    .map_err(Self::transfer_error)?
                    .ok_or_else(|| IpcError::Remote {
                        code: app_error::INTERNAL,
                        message: "source cleanup intent disappeared".into(),
                    })?;
                return Ok(
                    json!({ "plan_id": plan.id(), "cancelled": true, "source_only": true, "replayed": outcome.replayed }),
                );
            }
            Err(error) => return Err(Self::transfer_error(error)),
        };
        if journal.state() == JournalState::Cancelled {
            return Ok(
                json!({ "plan_id": plan.id(), "cancelled": true, "state": journal.state(), "replayed": true }),
            );
        }
        if matches!(
            journal.state(),
            JournalState::Completed | JournalState::Published | JournalState::Failed
        ) {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "completed or failed transfer cannot be cancelled".into(),
            });
        }
        // Exact non-terminal fence/state has now been accepted. Stale cancel
        // requests above cannot evict the active destination stream.
        let cached_destination = self.transfer_receivers.remove(plan.id());
        let now = Self::now() as u64;
        let lease = self
            .transfer_store
            .acquire(&plan, now, authority.expires_at_unix)
            .map_err(Self::transfer_error)?;
        let mut active = match cached_destination {
            Some(cached) => {
                if !cached.matches(p.epoch, p.fence, &journal) {
                    return Err(Self::transfer_error(TransferError::CorruptJournal));
                }
                cached
                    .sink
                    .validate_cached_position(journal.bytes_received())
                    .map_err(Self::transfer_error)?;
                cached
            }
            None => self
                .rebuild_destination_transfer(plan.clone(), journal.clone(), p.epoch, p.fence)
                .map_err(Self::transfer_error)?,
        };
        active
            .receiver
            .cancel(&mut active.sink)
            .map_err(Self::transfer_error)?;
        let updated = active.receiver.journal_snapshot();
        self.transfer_store
            .save(&lease, &updated)
            .map_err(Self::transfer_error)?;
        self.transfer_senders.remove(plan.id());
        self.transfer_last_chunks.remove(plan.id());
        let _ = self.transfer_store.remove_source_snapshot(&plan);
        Ok(json!({ "plan_id": plan.id(), "cancelled": true, "state": updated.state() }))
    }

    async fn handle_transfer_artifact_get(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            plan_id: String,
            workspace_id: String,
            #[serde(default)]
            offset: u64,
            #[serde(default)]
            max_bytes: Option<u64>,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let plan = self.transfer_plan_for(&p.plan_id, &authority, Some("destination"))?;
        if p.workspace_id != plan.binding().destination_workspace_id {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "artifact workspace does not match immutable plan".into(),
            });
        }
        let journal = self
            .transfer_store
            .load(&plan)
            .map_err(Self::transfer_error)?
            .ok_or_else(|| IpcError::Remote {
                code: app_error::CONFLICT,
                message: "artifact is not prepared".into(),
            })?;
        if !matches!(
            journal.state(),
            JournalState::Completed | JournalState::Published
        ) {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "artifact is incomplete".into(),
            });
        }
        let ws = self.workspace_for(Some(&p.workspace_id))?;
        let artifact = ws
            .open_verified_transfer_artifact_read(Path::new(
                &plan.binding().destination_relative_path,
            ))
            .map_err(fs_err)?;
        // The completed artifact is deliberately a no-replace hardlink to the
        // private verified part.  `ownmesh-fs` correctly rejects that
        // cross-boundary hardlink for ordinary path-selected reads; this is the
        // narrow exception for an already authenticated immutable plan.  The
        // caller cannot choose this path, and the read remains regular-file,
        // no-symlink, offset/page bounded.
        let want = p
            .max_bytes
            .unwrap_or(64 * 1024)
            .clamp(1, MAX_CHUNK_BYTES as u64);
        let total = artifact.size_bytes();
        if p.offset > total {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "transfer artifact offset exceeds its immutable total size".into(),
            });
        }
        let mut file = artifact.into_file();
        self.transfer_store
            .verify_published_destination_handle(&plan, &mut file)
            .map_err(Self::transfer_error)?;
        file.seek(SeekFrom::Start(p.offset))
            .map_err(|error| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("seek transfer artifact: {error}"),
            })?;
        let mut data = vec![0_u8; usize::try_from(want).unwrap_or(MAX_CHUNK_BYTES)];
        let returned = file.read(&mut data).map_err(|error| IpcError::Remote {
            code: app_error::INTERNAL,
            message: format!("read transfer artifact: {error}"),
        })?;
        data.truncate(returned);
        let truncated = p
            .offset
            .saturating_add(u64::try_from(returned).unwrap_or(u64::MAX))
            < total;
        let returned = data.len() as u64;
        Ok(
            json!({ "plan_id": plan.id(), "offset": p.offset, "bytes": returned, "total_bytes": total, "next_offset": if truncated { Value::from(p.offset.saturating_add(returned)) } else { Value::Null }, "truncated": truncated, "encoding": "base64", "content_base64": base64_standard(&data), "page_sha256": sha256_hex(&data), "sha256": plan.sha256() }),
        )
    }

    async fn handle_fs_list(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let p: FsListParams = parse_params(params)?;
        let facts = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: true,
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::FsList(p), client)
            .await
    }

    async fn handle_fs_stat(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let p: FsStatParams = parse_params(params)?;
        let facts = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: true,
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::FsStat(p), client)
            .await
    }

    async fn handle_fs_read(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let p: FsReadParams = parse_params(params)?;
        let facts = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: true,
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::FsRead(p), client)
            .await
    }

    async fn handle_fs_write(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let p: FsWriteParams = parse_params(params)?;
        let facts = OperationFacts {
            capability: "filesystem.write".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: true,
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::FsWrite(p), client)
            .await
    }

    async fn handle_fs_delete(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let p: FsDeleteParams = parse_params(params)?;
        let facts = OperationFacts {
            capability: "filesystem.write".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: true,
            tags: vec!["delete".into()],
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::FsDelete(p), client)
            .await
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
        let p: GitStatusParams = parse_params(params)?;
        let facts = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "git".into(),
            path: Some(p.path.clone()),
            workspace_relative: true,
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
        let p: GitDiffParams = parse_params(params)?;
        let facts = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "git".into(),
            path: Some(p.path.clone()),
            workspace_relative: true,
            tags: vec!["git".into(), "diff".into()],
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
                    pin: command.pin,
                })
            })
            .collect::<IpcResult<_>>()?;

        // Review runs are a batch of independently policy-sensitive programs.
        // Never infer authorization from the first program: the most restrictive
        // local verdict wins before repository inspection or process execution.
        let principal = canonicalize_principal_key(client.principal_key());
        let mut aggregate = Decision::Allow;
        let mut reasons = Vec::new();
        let mut review_programs: Vec<(&String, &ExecutablePin)> = Vec::new();
        if let Some(command) = command.as_ref() {
            review_programs.push((&command.program, &command.pin));
        }
        review_programs.extend(tests.iter().map(|test| (&test.program, &test.pin)));
        for (program, pin) in review_programs {
            let facts = OperationFacts {
                capability: "command.run".into(),
                kind: "structured".into(),
                program: Some(program.clone()),
                path: Some(repo_cwd.to_string_lossy().into_owned()),
                workspace_relative: true,
                executable_identity: Some(executable_identity_from_pin(pin)),
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
        let resolved =
            resolve_executable_path(&program, Some(cwd)).ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "review program could not be resolved to a regular executable".into(),
            })?;
        let resolved_program = resolved.to_string_lossy().into_owned();
        if classify_from_request_in_dir(None, &resolved_program, &args, Some(cwd))
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
        Ok(ReviewCommand {
            program: resolved_program,
            args,
            timeout_ms,
            pin,
        })
    }

    async fn run_review_command(
        &self,
        command: &ReviewCommand,
        cwd: &Path,
    ) -> (bool, bool, RunResult) {
        let revalidated = verify_executable_pin(Path::new(&command.pin.path), &command.pin).is_ok()
            && classify_from_request_in_dir(None, &command.pin.path, &command.args, None)
                == CommandKind::Structured;
        if !revalidated {
            return (
                false,
                false,
                RunResult {
                    exit_code: None,
                    stdout: String::new(),
                    stderr: "executable pin revalidation failed; review command was not spawned"
                        .into(),
                    timed_out: false,
                    duration_ms: 0,
                    truncated: false,
                    replayed: false,
                },
            );
        }
        let request = RunRequest {
            kind: CommandKind::Structured,
            program: command.pin.path.clone(),
            args: command.args.clone(),
            cwd: Some(cwd.to_path_buf()),
            env: HashMap::new(),
            stdin: None,
            timeout_ms: Some(command.timeout_ms),
            max_output_bytes: 96 * 1024,
            idempotency_key: None,
        };
        match run_command_cancellable(&request, None, self.active_cancel.clone()).await {
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
                        timed_out: false,
                        duration_ms: 0,
                        truncated: false,
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
            PendingRequest::AdminPolicyPreset(x) => Some(x.idempotency_key.clone()),
            PendingRequest::AdminPolicyRuleAdd(x) => Some(x.idempotency_key.clone()),
            PendingRequest::AdminPolicyRuleRemove(x) => Some(x.idempotency_key.clone()),
            PendingRequest::AdminDaemonUnlock(x) => Some(x.idempotency_key.clone()),
            PendingRequest::AdminTokenRevoke(x) => Some(x.idempotency_key.clone()),
            PendingRequest::AdminApprovalBridge(x) => Some(x.idempotency_key.clone()),
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
            Some(if temporary_grant_requires_operation_binding(&capability) {
                // Fail closed before any approval-state mutation: command.run
                // temporary grants are never safe (interpreter argv reuse, etc.).
                // One-shot approve without temporary_grant still executes once.
                let Some(facts) = approved_facts.as_ref() else {
                    return Err(IpcError::Remote {
                        code: app_error::INVALID_PARAMS,
                        message: "temporary grant for command.run requires server approval facts"
                            .into(),
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
                temporary_grant_from_facts(grant_id, grant_principal, expires_unix, facts).map_err(
                    |message| IpcError::Remote {
                        code: app_error::INVALID_PARAMS,
                        message,
                    },
                )?
            } else {
                TemporaryGrant {
                    id: grant_id,
                    capability: capability.clone(),
                    principal_id: grant_principal,
                    expires_unix,
                    path_prefix: None,
                    kind: None,
                    program_equals: None,
                    elevated: None,
                    executable_identity: None,
                }
            })
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

        if let Some(grant) = pending_grant {
            self.grants.push(grant);
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
        let body = json!({
            "approval_required": false,
            "operation_id": operation_id,
            "approval_id": p.id,
            "result": result,
            "replayed": false,
            "decision": "allow",
            "reason": "human approved",
        });

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
        }))
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
        let facts = OperationFacts {
            capability,
            kind,
            path: p.path,
            program: p.program,
            elevated: p.elevated,
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
        self.lockdown = true;
        if let Err(e) = self.persist_lockdown() {
            self.lockdown = previous;
            return Err(e);
        }
        self.append_audit("daemon.lockdown", None, None, Some("deny"), "lockdown on");
        Ok(json!({ "lockdown": true }))
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
            "transfer.start" => self.handle_transfer_start(params, client).await,
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
    /// replacement PTY. A missing active host is an explicit conflict; an
    /// expired controller binding is deliberately left for exact reclaim so
    /// expiry never kills a still-valid host TTL.
    async fn reattach_persistent_sidecars(&mut self) -> IpcResult<()> {
        const MAX_REATTACH: usize = 64;
        let now = Self::now();
        let bindings: Vec<_> = self
            .sessions
            .list()
            .into_iter()
            .filter_map(|info| info.sidecar_host.map(|binding| (info.id, binding)))
            .collect();
        if bindings.len() > MAX_REATTACH {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "persistent sidecar reattach quota exceeded".into(),
            });
        }
        let mut recovered_pids = Vec::new();
        {
            let proxy = self.supervisor.as_ref().ok_or_else(|| IpcError::Remote {
                code: app_error::CONFLICT,
                message: "sidecar unavailable during reattach".into(),
            })?;
            for (session_id, binding) in bindings {
                if binding.binding_expires_unix <= now {
                    continue;
                }
                let exact = supervisor_binding_from(&session_id, &binding);
                let status = proxy
                    .status(&exact)
                    .await
                    .map_err(|error| IpcError::Remote {
                        code: app_error::CONFLICT,
                        message: format!(
                            "persistent session {session_id} cannot reattach without respawn: {error}"
                        ),
                    })?;
                recovered_pids.push((session_id, status.pid));
            }
        }
        if recovered_pids.is_empty() {
            return Ok(());
        }
        let snapshot = self.sessions.clone();
        for (session_id, pid) in recovered_pids {
            self.sessions
                .set_host_pid(&session_id, pid)
                .map_err(session_err)?;
        }
        self.commit_sessions(snapshot)
    }

    async fn recover_sidecar_transitions(&mut self) -> IpcResult<()> {
        if self.transition_recovery_running {
            return Ok(());
        }
        self.transition_recovery_running = true;
        let records = self.transition_journal.pending();
        for record in records {
            let result = self.recover_transition_record(record).await;
            if let Err(error) = result {
                self.transition_recovery_running = false;
                return Err(error);
            }
        }
        self.transition_recovery_running = false;
        Ok(())
    }

    async fn recover_transition_record(
        &mut self,
        record: session_transition_journal::TransitionRecord,
    ) -> IpcResult<()> {
        if record.expires_unix <= Self::now() {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!(
                    "expired sidecar transition journal record {}",
                    record.transition_id
                ),
            });
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

    async fn handle_session_open(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            #[serde(default)]
            title: Option<String>,
            /// Ignored: principal is bound to authenticated client identity.
            #[serde(default)]
            principal: Option<String>,
            #[serde(default)]
            kind: Option<String>,
            #[serde(default)]
            profile_id: Option<String>,
            /// A prompt for a profile's documented non-interactive structured
            /// surface. It remains an individual argv element, never a shell
            /// fragment.
            #[serde(default)]
            prompt: Option<String>,
            /// Vendor-native continuation id, separate from the OwnMesh
            /// session id. It is canonical action input and never inferred
            /// from terminal output.
            #[serde(default)]
            native_session_id: Option<String>,
            /// `auto` follows the source-backed adapter preference;
            /// `structured` refuses a PTY downgrade; `pty` is explicit.
            #[serde(default)]
            adapter_mode: Option<String>,
            #[serde(default)]
            command: Option<Vec<String>>,
            /// MCP schema uses program/args; agent_transport maps them to command.
            #[serde(default)]
            program: Option<String>,
            #[serde(default)]
            args: Option<Vec<String>>,
            #[serde(default)]
            cwd: Option<String>,
            #[serde(default)]
            workspace_id: Option<String>,
        }
        let p: P = parse_params(params)?;
        reject_spoofed_principal(p.principal.as_deref(), &client.client_name)?;
        // Restricted presets cannot confine an interactive shell/process tree to
        // registered workspace roots. session.open is classified as command
        // execution: deny PTY/shell launch until OS process confinement exists
        // (same posture as command.run). full_user_access / full_access keep
        // sessions available; workspace remains audit/cwd context only there.
        if self.enforce_workspace {
            return Err(IpcError::Remote {
                code: app_error::POLICY_DENIED,
                message: format!(
                    "session.open denied under {} until OS process confinement is available; \
interactive shells bypass workspace path enforcement via stdin. Use filesystem.* tools \
within a registered workspace, or switch access mode to full_user_access/full_access",
                    preset_name(self.policy.preset)
                ),
            });
        }
        // Bind workspace identity at open: validates id/ownership against the
        // device workspace registry. Restricted modes also pin the cwd root;
        // full_access modes keep workspace as audit/context metadata only.
        let workspace_id = {
            let _ws = self.workspace_for(p.workspace_id.as_deref())?;
            let raw = p
                .workspace_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("ws_default");
            if raw == "default" {
                "ws_default".to_owned()
            } else {
                raw.to_owned()
            }
        };
        let mut kind = match p.kind.as_deref() {
            Some("process") => SessionKind::Process,
            Some("profile_agent") | Some("profile") => SessionKind::ProfileAgent,
            _ => SessionKind::Pty,
        };
        if p.profile_id.is_some() && kind == SessionKind::Pty {
            // Explicit profile_id without kind defaults to profile agent session.
            kind = SessionKind::ProfileAgent;
        }
        let adapter_mode = match p.adapter_mode.as_deref().unwrap_or("auto") {
            "auto" => "auto",
            "structured" => "structured",
            "pty" => "pty",
            other => {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: format!("adapter_mode must be auto|structured|pty (got {other})"),
                });
            }
        };
        if p.native_session_id
            .as_deref()
            .is_some_and(|id| id.is_empty() || id.len() > 512 || id.chars().any(char::is_control))
        {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "native_session_id must be a non-control string <= 512 bytes".into(),
            });
        }
        if p.adapter_mode.is_some() && p.profile_id.is_none() {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "adapter_mode requires profile_id; generic program/args are unchanged"
                    .into(),
            });
        }
        if p.native_session_id.is_some() && p.profile_id.is_none() {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message:
                    "native_session_id requires profile_id; generic program/args are unchanged"
                        .into(),
            });
        }
        let principal = client.client_name.clone();
        let title = p.title.unwrap_or_else(|| "session".into());
        // Resolve/pin cwd under the selected workspace (custody when enforce is on;
        // absolute resolve when unrestricted). Never accept an unbound external cwd
        // without going through workspace resolution.
        let ws_root = self.workspace_for(Some(workspace_id.as_str()))?;
        let cwd = if let Some(raw) = p.cwd.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let resolved = ws_root.resolve(Path::new(raw)).map_err(fs_err)?;
            Some(resolved.to_string_lossy().into_owned())
        } else {
            Some(ws_root.root().to_string_lossy().into_owned())
        };
        // Official profile launch plan (E6): detection + preferred interface, with
        // PTY fallback. Never copies tool credentials to the cloud. Generic CLIs
        // still use program/args/command without profile registration.
        let mut profile_meta: Option<Value> = None;
        let mut structured_adapter: Option<(String, AdapterDialect)> = None;
        // Argv resumes consume the native id in their exact launch plan; a
        // negotiated JSON-RPC resume keeps it for the structured driver.
        let mut driver_native_session_id = p.native_session_id.clone();
        let command = if let Some(cmd) = p.command.clone().filter(|c| !c.is_empty()) {
            Some(cmd)
        } else if let Some(program) = p
            .program
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let mut argv = vec![program.to_owned()];
            if let Some(args) = p.args.clone() {
                argv.extend(args);
            }
            Some(argv)
        } else if let Some(profile_id) = p
            .profile_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let reg = ProfileRegistry::with_official();
            let spec = official_adapter_spec(profile_id).ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("no source-backed adapter contract for profile {profile_id}"),
            })?;
            // Process-argv resumes (Claude/Kimi/Hermes) consume the native id
            // before ACP bootstrap; passing it again would incorrectly issue a
            // second `session/load`. Negotiated resumes (Codex/ACP) start the
            // normal structured child and let the exact driver perform the
            // source-backed resume after capability negotiation.
            let native_resume = p.native_session_id.as_deref().map(|native_id| match &spec.resume {
                NativeResume::Argv { .. } => {
                    driver_native_session_id = None;
                    reg.resume_plan_with_prompt(profile_id, native_id, p.prompt.as_deref()).map(Some).map_err(|e| {
                        IpcError::Remote {
                            code: app_error::INVALID_PARAMS,
                            message: format!("profile native resume plan failed: {e}"),
                        }
                    })
                }
                NativeResume::Negotiated { .. } => Ok(None),
                NativeResume::Degraded => Err(IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: format!(
                        "profile {profile_id} has no source-backed native resume; use a new profile session or explicit PTY"
                    ),
                }),
            }).transpose()?.flatten();
            let plan = match native_resume {
                Some(plan) => plan,
                None => reg
                    // Structured adapters must be allowed to select their declared
                    // stdio/HTTP dialect. PTY is opt-in only; this keeps generic
                    // CLI behavior unchanged while avoiding an accidental terminal
                    // downgrade for an explicit structured profile request.
                    .launch_plan(
                        profile_id,
                        p.prompt.as_deref(),
                        /* force_pty */ adapter_mode == "pty",
                    )
                    .map_err(|e| IpcError::Remote {
                        code: app_error::INVALID_PARAMS,
                        message: format!("profile launch plan failed: {e}"),
                    })?,
            };
            if adapter_mode == "structured" && plan.use_pty {
                return Err(IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: format!(
                        "profile {profile_id} cannot provide structured mode; use adapter_mode=pty explicitly"
                    ),
                });
            }
            if !plan.use_pty {
                structured_adapter = Some((spec.profile_id.clone(), spec.dialect));
            }
            profile_meta = Some(json!({
                "profile_id": plan.profile_id,
                "interface": plan.interface.as_str(),
                "use_pty": plan.use_pty,
                "program": plan.program,
                "adapter_mode": adapter_mode,
                "transport": spec.transport,
                "dialect": spec.dialect,
                "native_resume": spec.resume,
                "safe_capabilities": spec.safe_capabilities,
                "native_resume_requested": p.native_session_id.is_some(),
                "structured_requested": adapter_mode == "structured" || (adapter_mode == "auto" && !plan.use_pty),
            }));
            let mut argv = vec![plan.program];
            argv.extend(plan.args);
            Some(argv)
        } else {
            None
        };
        let snapshot = self.sessions.clone();
        let info = self
            .sessions
            .open_with(
                kind,
                title,
                principal,
                Self::now(),
                p.profile_id.clone(),
                p.native_session_id.clone(),
                command.clone(),
                cwd.clone(),
                None,
                Some(workspace_id.clone()),
            )
            .map_err(session_err)?;
        // Own a live PTY for interactive sessions (E5) and profile PTY fallback (E6).
        // Process-only kinds stay metadata until structured adapters stream events.
        // Failure to spawn is fail-closed so ChatGPT never sees a fake echo-only session.
        let spawn_live = matches!(kind, SessionKind::Pty | SessionKind::ProfileAgent);
        if spawn_live {
            let pty_cmd = match command.as_ref() {
                Some(argv) if !argv.is_empty() => PtyCommand {
                    program: argv[0].clone(),
                    args: argv[1..].to_vec(),
                    cwd: cwd.clone(),
                    env: vec![("TERM".into(), "xterm-256color".into())],
                },
                _ => {
                    let mut shell = default_shell_command();
                    shell.cwd.clone_from(&cwd);
                    shell
                }
            };
            let size = PtySize {
                cols: info.cols,
                rows: info.rows,
            };
            if is_remote_runtime_principal(&client.client_name) {
                let device_id = self
                    .active_remote_device_id
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| IpcError::Remote {
                        code: app_error::UNAUTHORIZED,
                        message: "remote session.open requires verified Agent device identity"
                            .into(),
                    })?
                    .to_owned();
                let lease = info.controller.as_ref().ok_or_else(|| IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: "remote session open did not produce a controller lease".into(),
                })?;
                let request = SupervisorSpawnRequest {
                    session_id: info.id.clone(),
                    // Verified Agent transport identity — never a caller
                    // argument or process-local placeholder.
                    device_id: device_id.clone(),
                    workspace_id: workspace_id.clone(),
                    owner_principal: client.client_name.clone(),
                    controller_epoch: info.controller_epoch,
                    binding_expires_unix: lease.expires_unix,
                    host_expires_unix: Self::now().saturating_add(24 * 60 * 60),
                    command: SupervisorCommand {
                        program: pty_cmd.program,
                        args: pty_cmd.args,
                        cwd: pty_cmd.cwd,
                        env: pty_cmd
                            .env
                            .into_iter()
                            .map(|(key, value)| SupervisorEnv { key, value })
                            .collect(),
                    },
                    cols: size.cols,
                    rows: size.rows,
                    io_mode: if structured_adapter.is_some() {
                        HostIoMode::StructuredPipes
                    } else {
                        HostIoMode::Pty
                    },
                    profile_id: structured_adapter.as_ref().map(|(id, _)| id.clone()),
                    adapter_dialect: structured_adapter
                        .as_ref()
                        .map(|(_, dialect)| dialect.as_str().to_owned()),
                };
                let binding = {
                    let supervisor = self.ensure_remote_supervisor().await?;
                    supervisor
                        .spawn(request)
                        .await
                        .map_err(|err| IpcError::Remote {
                            code: app_error::CONFLICT,
                            message: format!("persistent session sidecar spawn failed: {err}"),
                        })?
                };
                if let Some((_, dialect)) = structured_adapter {
                    let native_id = match Self::bootstrap_structured_adapter(
                        self.ensure_remote_supervisor().await?,
                        &binding,
                        dialect,
                        p.prompt.as_deref(),
                        driver_native_session_id.as_deref(),
                        cwd.as_deref().ok_or_else(|| IpcError::Remote {
                            code: app_error::INVALID_PARAMS,
                            message: "structured profile requires an absolute workspace cwd".into(),
                        })?,
                    )
                    .await
                    {
                        Ok(native_id) => native_id,
                        Err(error) => {
                            if let Ok(proxy) = self.ensure_remote_supervisor().await {
                                let _ = proxy
                                    .terminate(
                                        &binding,
                                        format!("open-rollback:{}:structured", info.id),
                                    )
                                    .await;
                            }
                            self.sessions = snapshot;
                            return Err(error);
                        }
                    };
                    if let Some(native_id) = native_id {
                        if let Err(error) = self.sessions.set_native_session_id(&info.id, native_id)
                        {
                            if let Ok(proxy) = self.ensure_remote_supervisor().await {
                                let _ = proxy
                                    .terminate(
                                        &binding,
                                        format!("open-rollback:{}:native-id", info.id),
                                    )
                                    .await;
                            }
                            self.sessions = snapshot;
                            return Err(session_err(error));
                        }
                    }
                }
                let status = {
                    let supervisor = self.ensure_remote_supervisor().await?;
                    supervisor
                        .status(&binding)
                        .await
                        .map_err(|err| IpcError::Remote {
                            code: app_error::CONFLICT,
                            message: format!("persistent session sidecar status failed: {err}"),
                        })?
                };
                if let Err(err) = self.sessions.set_host_pid(&info.id, status.pid) {
                    if let Ok(proxy) = self.ensure_remote_supervisor().await {
                        let _ = proxy
                            .terminate(&binding, format!("open-rollback:{}:host-pid", info.id))
                            .await;
                    }
                    self.sessions = snapshot;
                    return Err(session_err(err));
                }
                let durable = SidecarHostBinding {
                    device_id,
                    workspace_id: workspace_id.clone(),
                    owner_principal: client.client_name.clone(),
                    host_nonce: binding.host_nonce.clone(),
                    controller_epoch: binding.controller_epoch,
                    binding_expires_unix: lease.expires_unix,
                    host_expires_unix: Self::now().saturating_add(24 * 60 * 60),
                };
                if let Err(err) = self
                    .sessions
                    .set_sidecar_host_binding(&info.id, Some(durable))
                {
                    if let Ok(proxy) = self.ensure_remote_supervisor().await {
                        let _ = proxy
                            .terminate(&binding, format!("open-rollback:{}:binding", info.id))
                            .await;
                    }
                    self.sessions = snapshot;
                    return Err(session_err(err));
                }
                if let Err(err) = self.commit_sessions(snapshot) {
                    if let Ok(proxy) = self.ensure_remote_supervisor().await {
                        let _ = proxy
                            .terminate(&binding, format!("open-rollback:{}:persist", info.id))
                            .await;
                    }
                    return Err(err);
                }
                let mut value =
                    serde_json::to_value(self.sessions.get(&info.id).map_err(session_err)?)
                        .map_err(|e| IpcError::Remote {
                            code: app_error::INTERNAL,
                            message: e.to_string(),
                        })?;
                if let Some(obj) = value.as_object_mut() {
                    obj.insert("live_pty".into(), json!(true));
                    obj.insert("persistent_sidecar".into(), json!(true));
                    if let Some(meta) = profile_meta {
                        obj.insert("profile".into(), meta);
                    }
                }
                return Ok(value);
            }
            match LiveHost::spawn(&pty_cmd, size) {
                Ok(host) => {
                    let pid = host.handle.pid;
                    let backend = format!("{:?}", host.handle.backend);
                    if let Err(e) = self.sessions.set_host_pid(&info.id, pid) {
                        drop(host);
                        self.sessions = snapshot;
                        return Err(session_err(e));
                    }
                    if let Err(e) = self.commit_sessions(snapshot) {
                        drop(host);
                        return Err(e);
                    }
                    self.live_hosts.insert(info.id.clone(), host);
                    // Drain any initial banner into the replay ring (bounded).
                    // Avoid blocking the open path on a noisy interactive shell banner;
                    // callers pull output via session.replay.
                    let _ = pid;
                    let info = self.sessions.get(&info.id).map_err(session_err)?;
                    let mut value = serde_json::to_value(info).map_err(|e| IpcError::Remote {
                        code: app_error::INTERNAL,
                        message: e.to_string(),
                    })?;
                    if let Some(obj) = value.as_object_mut() {
                        obj.insert("live_pty".into(), json!(true));
                        obj.insert("pty_backend".into(), json!(backend));
                        if let Some(meta) = profile_meta {
                            obj.insert("profile".into(), meta);
                        }
                    }
                    return Ok(value);
                }
                Err(err) => {
                    self.sessions = snapshot;
                    return Err(IpcError::Remote {
                        code: app_error::INTERNAL,
                        message: format!("failed to spawn live PTY host: {err}"),
                    });
                }
            }
        }
        self.commit_sessions(snapshot)?;
        let mut value = serde_json::to_value(info).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })?;
        if let Some(obj) = value.as_object_mut() {
            obj.insert("live_pty".into(), json!(false));
            if let Some(meta) = profile_meta {
                obj.insert("profile".into(), meta);
            }
        }
        Ok(value)
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

    fn handle_session_list(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            #[serde(default)]
            workspace_id: Option<String>,
        }
        let p: P = parse_params(params)?;
        let now = self.prepare_session_access()?;
        let principal = &client.client_name;
        // Remote MCP always supplies workspace_id. Restricted modes refuse an
        // unbound list so cross-workspace session metadata cannot leak.
        let filter_ws = match p
            .workspace_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(raw) => {
                let want = if raw == "default" { "ws_default" } else { raw };
                // Validate the workspace id exists on this device.
                let _ = self.workspace_for(Some(want))?;
                Some(want.to_owned())
            }
            // Remote MCP always binds workspace; local IPC recovery may omit.
            None if is_remote_runtime_principal(principal) => {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "session.list requires workspace_id for remote MCP callers".into(),
                });
            }
            None => None,
        };
        let sessions: Vec<_> = self
            .sessions
            .list()
            .into_iter()
            .filter(|info| {
                let readable = self
                    .sessions
                    .readers(&info.id, now)
                    .map(|r| r.contains(principal))
                    .unwrap_or(false);
                if !readable {
                    return false;
                }
                match filter_ws.as_deref() {
                    None => true,
                    Some(want) => {
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
                        };
                        bound == want
                    }
                }
            })
            .collect();
        Ok(json!({
            "sessions": sessions,
            "workspace_id": filter_ws,
            "filtered_by_workspace": filter_ws.is_some(),
        }))
    }

    fn handle_session_show(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            #[serde(default)]
            workspace_id: Option<String>,
        }
        let p: P = parse_params(params)?;
        let now = self.prepare_session_access()?;
        self.require_reader(&p.id, &client.client_name, now)?;
        // Remote MCP must bind workspace; local IPC recovery may omit but cannot
        // spoof a mismatched id when one is supplied.
        if p.workspace_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_none()
            && is_remote_runtime_principal(&client.client_name)
        {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "session.show requires workspace_id for remote MCP callers".into(),
            });
        }
        let bound_ws = self.require_session_workspace(&p.id, p.workspace_id.as_deref())?;
        let info = self.sessions.get(&p.id).map_err(session_err)?;
        let mut value = serde_json::to_value(info).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })?;
        if let Some(obj) = value.as_object_mut() {
            obj.insert("workspace_id".into(), json!(bound_ws));
        }
        Ok(value)
    }

    fn handle_session_attach(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            #[serde(default)]
            principal: Option<String>,
            /// MCP `role: observer|controller` (preferred exact-action field).
            #[serde(default)]
            role: Option<String>,
            /// Legacy boolean; ignored when `role` is present.
            #[serde(default)]
            read_only: Option<bool>,
            #[serde(default)]
            workspace_id: Option<String>,
        }
        let p: P = parse_params(params)?;
        reject_spoofed_principal(p.principal.as_deref(), &client.client_name)?;
        // Normalize role into a bound semantic field. Missing/invalid roles fail closed
        // so observer attach cannot silently escalate to controller claim.
        let read_only = match p.role.as_deref().map(str::trim) {
            Some("observer") => true,
            Some("controller") => false,
            Some(other) if !other.is_empty() => {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: format!(
                        "session.attach role must be observer|controller (got '{other}')"
                    ),
                });
            }
            Some(_) | None => match p.read_only {
                Some(v) => v,
                None => {
                    return Err(IpcError::Remote {
                        code: app_error::INVALID_PARAMS,
                        message: "session.attach requires role=observer|controller (or read_only)"
                            .into(),
                    });
                }
            },
        };
        let now = self.prepare_session_access()?;
        // Local IPC has no cloud workspace grant proof, so it must already be
        // a reader. Remote requests reached this point only after the Worker
        // bound its tenant/principal/workspace grant into the exact operation.
        if !is_remote_runtime_principal(&client.client_name) {
            self.require_reader(&p.id, &client.client_name, now)?;
        }
        let bound_ws = self.require_session_workspace(&p.id, p.workspace_id.as_deref())?;
        let principal = client.client_name.clone();
        let snapshot = self.sessions.clone();
        if read_only {
            // Reattachment keeps an existing reader in observer mode. Session id
            // alone is never an invitation, and observer attach never grants
            // controller rights.
            // Exact-action: observer attach must not leave an active controller lease
            // on the same principal (would silently keep write/resize rights).
            if self
                .sessions
                .is_controller(&p.id, &principal, now)
                .map_err(session_err)?
            {
                self.sessions
                    .release_controller(&p.id, &principal, now)
                    .map_err(session_err)?;
            }
            self.sessions
                .attach_observer(&p.id, principal.clone(), now)
                .map_err(session_err)?;
        } else {
            // Controller claim is deliberately stricter: a reader must already
            // be present (open creator, observer, or explicit give handoff).
            self.require_reader(&p.id, &principal, now)?;
            let _ = self
                .sessions
                .claim_controller(&p.id, principal.clone(), now)
                .map_err(session_err)?;
        }
        self.commit_sessions(snapshot)?;
        // Pull any pending live PTY output into the durable replay ring.
        let _ = self.drain_live_output_into_session(&p.id);
        let info = self.sessions.get(&p.id).map_err(session_err)?;
        Ok(json!({
            "session": info,
            "principal": principal,
            "role": if read_only { "observer" } else { "controller" },
            "read_only": read_only,
            "workspace_id": bound_ws,
            "live_pty": self.live_hosts.contains_key(&p.id),
            "readers": self.sessions.readers(&p.id, now).map_err(session_err)?.into_iter().collect::<Vec<_>>(),
        }))
    }

    async fn handle_session_claim(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            #[serde(default)]
            principal: Option<String>,
            #[serde(default)]
            workspace_id: Option<String>,
        }
        let p: P = parse_params(params)?;
        reject_spoofed_principal(p.principal.as_deref(), &client.client_name)?;
        let now = self.prepare_session_access()?;
        // Only an existing reader may claim a released/expired controller lease.
        self.require_reader(&p.id, &client.client_name, now)?;
        let bound_ws = self.require_session_workspace(&p.id, p.workspace_id.as_deref())?;
        let principal = client.client_name.clone();
        let snapshot = self.sessions.clone();
        let mut preview = self.sessions.clone();
        let lease = preview
            .claim_controller(&p.id, principal, now)
            .map_err(session_err)?;
        if let Some(old_binding) = self
            .sessions
            .get(&p.id)
            .map_err(session_err)?
            .sidecar_host
            .clone()
        {
            let transition_id = format!("claim:{}:{}:{}", p.id, client.client_name, lease.epoch);
            self.ensure_remote_supervisor().await?;
            let record = TransitionRecord {
                transition_id: transition_id.clone(),
                kind: TransitionKind::Claim,
                phase: TransitionPhase::Intent,
                session_id: p.id.clone(),
                device_id: old_binding.device_id.clone(),
                workspace_id: bound_ws.clone(),
                authenticated_principal: client.client_name.clone(),
                old_binding: old_binding.clone(),
                target: TransitionTarget {
                    principal: client.client_name.clone(),
                    controller_epoch: lease.epoch,
                    binding_expires_unix: lease.expires_unix,
                    controller_attached: true,
                    terminal: false,
                },
                new_binding: None,
                created_unix: now,
                expires_unix: old_binding.host_expires_unix,
            };
            self.transition_journal
                .begin(record)
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("begin sidecar claim journal: {e}"),
                })?;
            let old = self.verified_sidecar_binding_from(&p.id, &old_binding)?;
            let proxy = self.supervisor.as_ref().ok_or_else(|| IpcError::Remote {
                code: app_error::CONFLICT,
                message: "sidecar unavailable after bootstrap".into(),
            })?;
            let returned = if old_binding.binding_expires_unix <= now {
                proxy
                    .reclaim(
                        &old,
                        client.client_name.clone(),
                        lease.epoch,
                        lease.expires_unix,
                        transition_id.clone(),
                    )
                    .await
            } else {
                proxy
                    .claim(
                        &old,
                        client.client_name.clone(),
                        lease.epoch,
                        lease.expires_unix,
                        transition_id.clone(),
                    )
                    .await
            }
            .map_err(|e| IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!("sidecar claim failed: {e}"),
            })?;
            let new_binding = SidecarHostBinding {
                device_id: old_binding.device_id.clone(),
                workspace_id: old_binding.workspace_id.clone(),
                owner_principal: client.client_name.clone(),
                host_nonce: returned.host_nonce,
                controller_epoch: returned.controller_epoch,
                binding_expires_unix: lease.expires_unix,
                host_expires_unix: old_binding.host_expires_unix,
            };
            self.transition_journal
                .mark_applied(&transition_id, new_binding.clone())
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("mark sidecar claim journal: {e}"),
                })?;
            preview
                .set_sidecar_host_binding(&p.id, Some(new_binding))
                .map_err(session_err)?;
            self.sessions = preview;
            self.commit_sessions(snapshot)?;
            self.transition_journal
                .clear(&transition_id)
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("clear sidecar claim journal: {e}"),
                })?;
        } else {
            self.sessions = preview;
            self.commit_sessions(snapshot)?;
        }
        Ok(json!({ "lease": lease, "session_id": p.id, "workspace_id": bound_ws }))
    }

    fn handle_session_release(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            #[serde(default)]
            principal: Option<String>,
            #[serde(default)]
            workspace_id: Option<String>,
        }
        let p: P = parse_params(params)?;
        reject_spoofed_principal(p.principal.as_deref(), &client.client_name)?;
        if is_remote_runtime_principal(&client.client_name) {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "session.release is not available over remote MCP; use exact lease-bound session.detach".into(),
            });
        }
        let now = self.prepare_session_access()?;
        let bound_ws = self.require_session_workspace(&p.id, p.workspace_id.as_deref())?;
        let principal = client.client_name.clone();
        let snapshot = self.sessions.clone();
        self.sessions
            .release_controller(&p.id, &principal, now)
            .map_err(session_err)?;
        self.commit_sessions(snapshot)?;
        Ok(json!({ "released": true, "session_id": p.id, "workspace_id": bound_ws }))
    }

    /// Renew the exact controller seat without changing its epoch. Remote callers
    /// must echo the opaque lease id and generation, so a stale controller cannot
    /// extend a handed-off or reclaimed seat.
    async fn handle_session_renew(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            lease_id: String,
            controller_epoch: u64,
            ttl_secs: i64,
            #[serde(default)]
            principal: Option<String>,
            #[serde(default)]
            workspace_id: Option<String>,
        }
        let p: P = parse_params(params)?;
        reject_spoofed_principal(p.principal.as_deref(), &client.client_name)?;
        let now = self.prepare_session_access()?;
        let bound_ws = self.require_session_workspace(&p.id, p.workspace_id.as_deref())?;
        let snapshot = self.sessions.clone();
        let mut preview = self.sessions.clone();
        let lease = preview
            .renew_controller_lease(
                &p.id,
                &client.client_name,
                &p.lease_id,
                p.controller_epoch,
                now,
                p.ttl_secs,
            )
            .map_err(session_err)?;
        if let Some(old_binding) = self
            .sessions
            .get(&p.id)
            .map_err(session_err)?
            .sidecar_host
            .clone()
        {
            let transition_id = format!(
                "renew:{}:{}:{}:{}",
                p.id, p.lease_id, p.controller_epoch, lease.expires_unix
            );
            // Finish any earlier durable transition before publishing this
            // renewal intent; this keeps the old nonce an exact CAS witness.
            self.ensure_remote_supervisor().await?;
            let record = TransitionRecord {
                transition_id: transition_id.clone(),
                kind: TransitionKind::Renew,
                phase: TransitionPhase::Intent,
                session_id: p.id.clone(),
                device_id: old_binding.device_id.clone(),
                workspace_id: bound_ws.clone(),
                authenticated_principal: client.client_name.clone(),
                old_binding: old_binding.clone(),
                target: TransitionTarget {
                    principal: client.client_name.clone(),
                    controller_epoch: lease.epoch,
                    binding_expires_unix: lease.expires_unix,
                    controller_attached: true,
                    terminal: false,
                },
                new_binding: None,
                created_unix: now,
                expires_unix: old_binding.host_expires_unix,
            };
            self.transition_journal
                .begin(record)
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("begin sidecar renew journal: {e}"),
                })?;
            let old = self.verified_sidecar_binding_from(&p.id, &old_binding)?;
            let proxy = self.supervisor.as_ref().ok_or_else(|| IpcError::Remote {
                code: app_error::CONFLICT,
                message: "sidecar unavailable after bootstrap".into(),
            })?;
            let returned = proxy
                .renew(&old, lease.expires_unix, transition_id.clone())
                .await
                .map_err(|e| IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: format!("sidecar renew failed: {e}"),
                })?;
            if returned.controller_epoch != lease.epoch {
                return Err(IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: "sidecar renew returned a different controller epoch".into(),
                });
            }
            let new_binding = SidecarHostBinding {
                device_id: old_binding.device_id.clone(),
                workspace_id: old_binding.workspace_id.clone(),
                owner_principal: client.client_name.clone(),
                host_nonce: returned.host_nonce,
                controller_epoch: returned.controller_epoch,
                binding_expires_unix: lease.expires_unix,
                host_expires_unix: old_binding.host_expires_unix,
            };
            self.transition_journal
                .mark_applied(&transition_id, new_binding.clone())
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("mark sidecar renew journal: {e}"),
                })?;
            preview
                .set_sidecar_host_binding(&p.id, Some(new_binding))
                .map_err(session_err)?;
            self.sessions = preview;
            self.commit_sessions(snapshot)?;
            self.transition_journal
                .clear(&transition_id)
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("clear sidecar renew journal: {e}"),
                })?;
        } else {
            self.sessions = preview;
            self.commit_sessions(snapshot)?;
        }
        Ok(json!({ "lease": lease, "session_id": p.id, "workspace_id": bound_ws }))
    }

    /// Explicitly detach the current controller while retaining the PTY and its
    /// bounded replay. This is deliberately separate from legacy release: remote
    /// calls are exact-seat bound and cannot detach a successor's controller.
    async fn handle_session_detach(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            lease_id: String,
            controller_epoch: u64,
            #[serde(default)]
            principal: Option<String>,
            #[serde(default)]
            workspace_id: Option<String>,
        }
        let p: P = parse_params(params)?;
        reject_spoofed_principal(p.principal.as_deref(), &client.client_name)?;
        let now = self.prepare_session_access()?;
        let bound_ws = self.require_session_workspace(&p.id, p.workspace_id.as_deref())?;
        let snapshot = self.sessions.clone();
        let mut preview = self.sessions.clone();
        preview
            .detach_controller_lease(
                &p.id,
                &client.client_name,
                &p.lease_id,
                p.controller_epoch,
                now,
            )
            .map_err(session_err)?;
        if let Some(old_binding) = self
            .sessions
            .get(&p.id)
            .map_err(session_err)?
            .sidecar_host
            .clone()
        {
            let next_epoch = preview.get(&p.id).map_err(session_err)?.controller_epoch;
            let transition_id = format!("detach:{}:{}:{}", p.id, p.lease_id, p.controller_epoch);
            // Bootstrap/recover before publishing a new intent; otherwise the
            // bootstrap recovery loop would consume this handler's fresh row.
            self.ensure_remote_supervisor().await?;
            let record = TransitionRecord {
                transition_id: transition_id.clone(),
                kind: TransitionKind::Detach,
                phase: TransitionPhase::Intent,
                session_id: p.id.clone(),
                device_id: old_binding.device_id.clone(),
                workspace_id: bound_ws.clone(),
                authenticated_principal: client.client_name.clone(),
                old_binding: old_binding.clone(),
                target: TransitionTarget {
                    principal: old_binding.owner_principal.clone(),
                    controller_epoch: next_epoch,
                    binding_expires_unix: old_binding.binding_expires_unix,
                    controller_attached: false,
                    terminal: false,
                },
                new_binding: None,
                created_unix: now,
                expires_unix: old_binding.host_expires_unix,
            };
            self.transition_journal
                .begin(record)
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("begin sidecar detach journal: {e}"),
                })?;
            let old = self.verified_sidecar_binding_from(&p.id, &old_binding)?;
            let proxy = self.supervisor.as_ref().ok_or_else(|| IpcError::Remote {
                code: app_error::CONFLICT,
                message: "sidecar unavailable after bootstrap".into(),
            })?;
            let returned = proxy
                .detach(&old, next_epoch, transition_id.clone())
                .await
                .map_err(|e| IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: format!("sidecar detach failed: {e}"),
                })?;
            let new_binding = SidecarHostBinding {
                device_id: old_binding.device_id.clone(),
                workspace_id: old_binding.workspace_id.clone(),
                owner_principal: old_binding.owner_principal.clone(),
                host_nonce: returned.host_nonce,
                controller_epoch: returned.controller_epoch,
                binding_expires_unix: old_binding.binding_expires_unix,
                host_expires_unix: old_binding.host_expires_unix,
            };
            self.transition_journal
                .mark_applied(&transition_id, new_binding.clone())
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("mark sidecar detach journal: {e}"),
                })?;
            preview
                .set_sidecar_host_binding(&p.id, Some(new_binding))
                .map_err(session_err)?;
            self.sessions = preview;
            self.commit_sessions(snapshot)?;
            self.transition_journal
                .clear(&transition_id)
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("clear sidecar detach journal: {e}"),
                })?;
        } else {
            self.sessions = preview;
            self.commit_sessions(snapshot)?;
        }
        Ok(json!({
            "detached": true,
            "session_id": p.id,
            "workspace_id": bound_ws,
            "live_pty": self.live_hosts.contains_key(&p.id),
        }))
    }

    async fn handle_session_give(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            to: String,
            #[serde(default)]
            from: Option<String>,
            #[serde(default)]
            workspace_id: Option<String>,
            #[serde(default)]
            lease_id: Option<String>,
            #[serde(default)]
            controller_epoch: Option<u64>,
        }
        let p: P = parse_params(params)?;
        // give requires from == authenticated identity (spoofed from is rejected).
        if let Some(from) = p.from.as_deref() {
            if from != client.client_name {
                return Err(IpcError::Remote {
                    code: app_error::UNAUTHORIZED,
                    message: format!(
                        "session.give from must be authenticated client (got '{from}', auth is '{}')",
                        client.client_name
                    ),
                });
            }
        }
        let now = self.prepare_session_access()?;
        let bound_ws = self.require_session_workspace(&p.id, p.workspace_id.as_deref())?;
        let from = client.client_name.clone();
        if is_remote_runtime_principal(&from) {
            let lease_id = p
                .lease_id
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "session.give requires lease_id for remote principals".into(),
                })?;
            let epoch = p.controller_epoch.ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "session.give requires controller_epoch for remote principals".into(),
            })?;
            self.sessions
                .authorize_controller_lease(&p.id, &from, lease_id, epoch, now)
                .map_err(session_err)?;
        }
        // Normalize bare principal ids into the remote runtime form when the
        // controller is a remote MCP principal (same tenant namespace).
        let to = normalize_handoff_target(&from, &p.to)?;
        let snapshot = self.sessions.clone();
        let mut preview = self.sessions.clone();
        let lease = preview
            .give_controller(&p.id, &from, to, now)
            .map_err(session_err)?;
        if let Some(old_binding) = self
            .sessions
            .get(&p.id)
            .map_err(session_err)?
            .sidecar_host
            .clone()
        {
            // The old controller's exact remote seat was authorized above.
            // Keep the transition ID bound to that seat, so a retried handoff
            // cannot rotate a successor generation or target a different owner.
            let transition_id = format!(
                "give:{}:{}:{}",
                p.id,
                p.lease_id.as_deref().unwrap_or(&lease.lease_id),
                p.controller_epoch.unwrap_or(lease.epoch),
            );
            // Recover outstanding work before creating this intent, otherwise
            // bootstrap could consume this operation's just-created row.
            self.ensure_remote_supervisor().await?;
            let record = TransitionRecord {
                transition_id: transition_id.clone(),
                kind: TransitionKind::Give,
                phase: TransitionPhase::Intent,
                session_id: p.id.clone(),
                device_id: old_binding.device_id.clone(),
                workspace_id: bound_ws.clone(),
                authenticated_principal: from.clone(),
                old_binding: old_binding.clone(),
                target: TransitionTarget {
                    principal: lease.principal_id.clone(),
                    controller_epoch: lease.epoch,
                    binding_expires_unix: lease.expires_unix,
                    controller_attached: true,
                    terminal: false,
                },
                new_binding: None,
                created_unix: now,
                expires_unix: old_binding.host_expires_unix,
            };
            self.transition_journal
                .begin(record)
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("begin sidecar give journal: {e}"),
                })?;
            let old = self.verified_sidecar_binding_from(&p.id, &old_binding)?;
            let proxy = self.supervisor.as_ref().ok_or_else(|| IpcError::Remote {
                code: app_error::CONFLICT,
                message: "sidecar unavailable after bootstrap".into(),
            })?;
            let returned = proxy
                .rotate(
                    &old,
                    lease.principal_id.clone(),
                    lease.epoch,
                    lease.expires_unix,
                    transition_id.clone(),
                )
                .await
                .map_err(|e| IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: format!("sidecar give failed: {e}"),
                })?;
            let new_binding = SidecarHostBinding {
                device_id: old_binding.device_id.clone(),
                workspace_id: old_binding.workspace_id.clone(),
                owner_principal: lease.principal_id.clone(),
                host_nonce: returned.host_nonce,
                controller_epoch: returned.controller_epoch,
                binding_expires_unix: lease.expires_unix,
                host_expires_unix: old_binding.host_expires_unix,
            };
            self.transition_journal
                .mark_applied(&transition_id, new_binding.clone())
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("mark sidecar give journal: {e}"),
                })?;
            preview
                .set_sidecar_host_binding(&p.id, Some(new_binding))
                .map_err(session_err)?;
            self.sessions = preview;
            self.commit_sessions(snapshot)?;
            self.transition_journal
                .clear(&transition_id)
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("clear sidecar give journal: {e}"),
                })?;
        } else {
            self.sessions = preview;
            self.commit_sessions(snapshot)?;
        }
        let readers: Vec<String> = self
            .sessions
            .readers(&p.id, now)
            .map_err(session_err)?
            .into_iter()
            .collect();
        Ok(json!({ "lease": lease, "readers": readers, "workspace_id": bound_ws }))
    }

    async fn handle_session_close(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            #[serde(default)]
            lease_id: Option<String>,
            #[serde(default)]
            controller_epoch: Option<u64>,
            #[serde(default)]
            workspace_id: Option<String>,
        }
        let p: P = parse_params(params)?;
        let now = self.prepare_session_access()?;
        let bound_ws = self.require_session_workspace(&p.id, p.workspace_id.as_deref())?;
        let remote = is_remote_runtime_principal(&client.client_name);
        if remote {
            let lease_id = p
                .lease_id
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "session.close requires lease_id for remote principals".into(),
                })?;
            let epoch = p.controller_epoch.ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "session.close requires controller_epoch for remote principals".into(),
            })?;
            self.sessions
                .authorize_controller_lease(&p.id, &client.client_name, lease_id, epoch, now)
                .map_err(session_err)?;
        } else {
            self.require_controller(&p.id, &client.client_name, now)?;
        }
        let _ = self.drain_live_output_into_session(&p.id);
        let snapshot = self.sessions.clone();
        let mut preview = self.sessions.clone();
        let active = self
            .sessions
            .get(&p.id)
            .map_err(session_err)?
            .controller
            .clone()
            .ok_or_else(|| IpcError::Remote {
                code: app_error::CONFLICT,
                message: "session has no active controller".into(),
            })?;
        preview.close(&p.id).map_err(session_err)?;
        if let Some(old_binding) = self
            .sessions
            .get(&p.id)
            .map_err(session_err)?
            .sidecar_host
            .clone()
        {
            let transition_id = format!(
                "close:{}:{}:{}",
                p.id,
                p.lease_id.as_deref().unwrap_or(&active.lease_id),
                p.controller_epoch.unwrap_or(active.epoch),
            );
            self.ensure_remote_supervisor().await?;
            let record = TransitionRecord {
                transition_id: transition_id.clone(),
                kind: TransitionKind::Close,
                phase: TransitionPhase::Intent,
                session_id: p.id.clone(),
                device_id: old_binding.device_id.clone(),
                workspace_id: bound_ws.clone(),
                authenticated_principal: client.client_name.clone(),
                old_binding: old_binding.clone(),
                target: TransitionTarget {
                    principal: client.client_name.clone(),
                    controller_epoch: active.epoch,
                    binding_expires_unix: active.expires_unix,
                    controller_attached: true,
                    terminal: true,
                },
                new_binding: None,
                created_unix: now,
                expires_unix: old_binding.host_expires_unix,
            };
            self.transition_journal
                .begin(record)
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("begin sidecar close journal: {e}"),
                })?;
            let binding = self.verified_sidecar_binding_from(&p.id, &old_binding)?;
            let proxy = self.supervisor.as_ref().ok_or_else(|| IpcError::Remote {
                code: app_error::CONFLICT,
                message: "sidecar unavailable after bootstrap".into(),
            })?;
            proxy
                .terminate(&binding, transition_id.clone())
                .await
                .map_err(|e| IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: format!("sidecar close failed: {e}"),
                })?;
            self.transition_journal
                .mark_terminal_applied(&transition_id)
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("mark sidecar close journal: {e}"),
                })?;
            preview
                .set_sidecar_host_binding(&p.id, None)
                .map_err(session_err)?;
            self.sessions = preview;
            self.commit_sessions(snapshot)?;
            self.transition_journal
                .clear(&transition_id)
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("clear sidecar close journal: {e}"),
                })?;
        } else {
            self.sessions = preview;
            self.commit_sessions(snapshot)?;
            self.stop_live_host(&p.id);
        }
        Ok(json!({ "closed": true, "session_id": p.id, "workspace_id": bound_ws }))
    }

    async fn handle_session_terminate(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            #[serde(default)]
            id: Option<String>,
            /// Public MCP's canonical field; accept it as an exact alias for
            /// the local IPC `id` without allowing the two to disagree.
            #[serde(default)]
            session_id: Option<String>,
            #[serde(default)]
            all: bool,
            #[serde(default)]
            workspace_id: Option<String>,
            #[serde(default)]
            lease_id: Option<String>,
            #[serde(default)]
            controller_epoch: Option<u64>,
        }
        let p: P = parse_params(params)?;
        let now = self.prepare_session_access()?;
        if p.all {
            if is_remote_runtime_principal(&client.client_name) {
                return Err(IpcError::Remote {
                    code: app_error::POLICY_DENIED,
                    message: "remote session.terminate all is forbidden; terminate one exact lease"
                        .into(),
                });
            }
            // Only sessions this principal actively controls may be mass-terminated.
            let controlled: Vec<String> = self
                .sessions
                .list()
                .into_iter()
                .filter(|info| {
                    info.active_controller(now)
                        .map(|c| c.principal_id == client.client_name)
                        .unwrap_or(false)
                })
                .map(|info| info.id)
                .collect();
            let mut drained = Vec::new();
            for id in &controlled {
                let _ = self.drain_live_output_into_session(id);
                drained.push(id.clone());
            }
            let snapshot = self.sessions.clone();
            let mut n = 0usize;
            for id in &controlled {
                self.sessions.terminate(id).map_err(session_err)?;
                n += 1;
            }
            self.commit_sessions(snapshot)?;
            for id in drained {
                self.stop_live_host(&id);
            }
            return Ok(json!({ "terminated": n, "all": true }));
        }
        if p.id.is_some() && p.session_id.is_some() && p.id != p.session_id {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "id and session_id disagree".into(),
            });
        }
        let id = p.id.or(p.session_id).ok_or_else(|| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: "id or all required".into(),
        })?;
        let bound_ws = self.require_session_workspace(&id, p.workspace_id.as_deref())?;
        let remote = is_remote_runtime_principal(&client.client_name);
        if remote {
            let lease_id = p
                .lease_id
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "session.terminate requires lease_id for remote principals".into(),
                })?;
            let epoch = p.controller_epoch.ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "session.terminate requires controller_epoch for remote principals".into(),
            })?;
            self.sessions
                .authorize_controller_lease(&id, &client.client_name, lease_id, epoch, now)
                .map_err(session_err)?;
        } else {
            self.require_controller(&id, &client.client_name, now)?;
        }
        let _ = self.drain_live_output_into_session(&id);
        let snapshot = self.sessions.clone();
        let mut preview = self.sessions.clone();
        let active = self
            .sessions
            .get(&id)
            .map_err(session_err)?
            .controller
            .clone()
            .ok_or_else(|| IpcError::Remote {
                code: app_error::CONFLICT,
                message: "session has no active controller".into(),
            })?;
        preview.terminate(&id).map_err(session_err)?;
        if let Some(old_binding) = self
            .sessions
            .get(&id)
            .map_err(session_err)?
            .sidecar_host
            .clone()
        {
            let transition_id = format!(
                "terminate:{}:{}:{}",
                id,
                p.lease_id.as_deref().unwrap_or(&active.lease_id),
                p.controller_epoch.unwrap_or(active.epoch),
            );
            self.ensure_remote_supervisor().await?;
            let record = TransitionRecord {
                transition_id: transition_id.clone(),
                kind: TransitionKind::Terminate,
                phase: TransitionPhase::Intent,
                session_id: id.clone(),
                device_id: old_binding.device_id.clone(),
                workspace_id: bound_ws.clone(),
                authenticated_principal: client.client_name.clone(),
                old_binding: old_binding.clone(),
                target: TransitionTarget {
                    principal: client.client_name.clone(),
                    controller_epoch: active.epoch,
                    binding_expires_unix: active.expires_unix,
                    controller_attached: true,
                    terminal: true,
                },
                new_binding: None,
                created_unix: now,
                expires_unix: old_binding.host_expires_unix,
            };
            self.transition_journal
                .begin(record)
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("begin sidecar terminate journal: {e}"),
                })?;
            let binding = self.verified_sidecar_binding_from(&id, &old_binding)?;
            let proxy = self.supervisor.as_ref().ok_or_else(|| IpcError::Remote {
                code: app_error::CONFLICT,
                message: "sidecar unavailable after bootstrap".into(),
            })?;
            proxy
                .terminate(&binding, transition_id.clone())
                .await
                .map_err(|e| IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: format!("sidecar terminate failed: {e}"),
                })?;
            self.transition_journal
                .mark_terminal_applied(&transition_id)
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("mark sidecar terminate journal: {e}"),
                })?;
            // `SessionManager::terminate` removes the entry, which is the
            // durable binding clear. Do not mutate the already-removed
            // preview entry here: doing so turns an otherwise successful
            // exact sidecar tombstone into a spurious `session not found`.
            self.sessions = preview;
            self.commit_sessions(snapshot)?;
            self.transition_journal
                .clear(&transition_id)
                .map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("clear sidecar terminate journal: {e}"),
                })?;
        } else {
            self.sessions = preview;
            self.commit_sessions(snapshot)?;
            self.stop_live_host(&id);
        }
        Ok(json!({ "terminated": 1, "session_id": id, "workspace_id": bound_ws }))
    }

    async fn handle_session_replay(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            #[serde(default)]
            from_seq: Option<u64>,
            #[serde(default)]
            limit: Option<usize>,
            #[serde(default)]
            max_bytes: Option<usize>,
            /// Absolute sidecar spool cursor. Independent per observer and
            /// encoded explicitly because PTY output is raw bytes.
            #[serde(default)]
            sidecar_cursor: Option<u64>,
            /// Ignored: read ACL uses authenticated client identity.
            #[serde(default)]
            principal: Option<String>,
            #[serde(default)]
            workspace_id: Option<String>,
        }
        let p: P = parse_params(params)?;
        reject_spoofed_principal(p.principal.as_deref(), &client.client_name)?;
        let now = self.prepare_session_access()?;
        self.require_reader(&p.id, &client.client_name, now)?;
        let _bound_ws = self.require_session_workspace(&p.id, p.workspace_id.as_deref())?;
        let sidecar_page = if self
            .sessions
            .get(&p.id)
            .map_err(session_err)?
            .sidecar_host
            .is_some()
        {
            let binding = self.sidecar_binding(&p.id)?;
            let max_bytes = p
                .max_bytes
                .unwrap_or(ownmesh_session::MAX_REPLAY_PAGE_BYTES)
                .min(ownmesh_session::MAX_REPLAY_PAGE_BYTES);
            let supervisor = self.ensure_remote_supervisor().await?;
            Some(
                supervisor
                    .drain(&binding, p.sidecar_cursor.unwrap_or(0), max_bytes)
                    .await
                    .map_err(|err| IpcError::Remote {
                        code: app_error::CONFLICT,
                        message: format!("persistent session sidecar drain failed: {err}"),
                    })?,
            )
        } else {
            None
        };
        // Fold embedded live host output into the legacy durable replay ring.
        let drained = self.drain_live_output_into_session(&p.id)?;
        let page = self
            .sessions
            .replay_from_bounded(
                &p.id,
                &client.client_name,
                p.from_seq.unwrap_or(1),
                now,
                p.limit
                    .unwrap_or(ownmesh_session::DEFAULT_REPLAY_PAGE_LIMIT),
                p.max_bytes
                    .unwrap_or(ownmesh_session::MAX_REPLAY_PAGE_BYTES),
            )
            .map_err(session_err)?;
        // Live-ring remainder is a durable continuation fact — never report EOF.
        let live_pending = self
            .live_hosts
            .get(&p.id)
            .map(LiveHost::pending_output_bytes)
            .unwrap_or(0);
        let mut truncated = page.truncated;
        let mut next_seq = page.next_seq;
        if live_pending > 0 {
            truncated = true;
            if next_seq.is_none() {
                // Point past the last returned chunk so the next page continues.
                next_seq = page
                    .chunks
                    .last()
                    .map(|c| c.seq.saturating_add(1))
                    .or(Some(1));
            }
        }
        let sidecar_truncated = sidecar_page
            .as_ref()
            .map(|page| page.truncated)
            .unwrap_or(false);
        let sidecar_next_cursor = sidecar_page.as_ref().and_then(|page| page.next_offset);
        let sidecar_total_bytes = sidecar_page.as_ref().map(|page| page.total_bytes);
        let sidecar_bytes_base64 = sidecar_page
            .as_ref()
            .map(|page| base64_standard(&page.bytes));
        // Structured profiles additionally expose a bounded, normalized view
        // over the exact raw sidecar spool cursor.  The raw base64 field stays
        // available for binary-safe recovery; malformed vendor output becomes
        // an explicit adapter error rather than disappearing into a terminal.
        let profile_events = self
            .sessions
            .get(&p.id)
            .ok()
            .and_then(|info| info.profile_id.as_deref())
            .and_then(official_adapter_spec)
            .filter(|spec| spec.structured_events)
            .and_then(|_| {
                sidecar_page.as_ref().map(|spool| {
                    let byte_len = u64::try_from(spool.bytes.len()).unwrap_or(u64::MAX);
                    let tail_after_page = spool.next_offset.unwrap_or(spool.total_bytes);
                    let base = tail_after_page.saturating_sub(byte_len);
                    parse_adapter_event_page(&spool.bytes, base)
                })
            });
        let profile_event_cursor = profile_events.as_ref().map(|page| page.next_cursor);
        let profile_event_truncated =
            profile_events.as_ref().is_some_and(|page| page.has_more) || sidecar_truncated;
        Ok(json!({
            "chunks": page.chunks,
            "session_id": p.id,
            "truncated": truncated || sidecar_truncated,
            "next_seq": next_seq,
            "returned_bytes": page.returned_bytes,
            "live_drained_bytes": drained,
            "live_pending_bytes": live_pending,
            "live_pty": self.live_hosts.contains_key(&p.id) || sidecar_page.is_some(),
            "sidecar_bytes_encoding": sidecar_page.as_ref().map(|_| "base64"),
            "sidecar_bytes_base64": sidecar_bytes_base64,
            "sidecar_next_cursor": sidecar_next_cursor,
            "sidecar_total_bytes": sidecar_total_bytes,
            "profile_events": profile_events.as_ref().map(|page| &page.events),
            "profile_event_cursor": profile_event_cursor,
            "profile_event_truncated": profile_event_truncated,
        }))
    }

    fn handle_session_push_output(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            data: String,
            #[serde(default)]
            stream: Option<String>,
        }
        let p: P = parse_params(params)?;
        let now = self.prepare_session_access()?;
        self.require_controller(&p.id, &client.client_name, now)?;
        let stream = match p.stream.as_deref() {
            Some("stderr") => SessionStreamKind::Stderr,
            Some("system") => SessionStreamKind::System,
            _ => SessionStreamKind::Stdout,
        };
        let snapshot = self.sessions.clone();
        let chunk = self
            .sessions
            .push_output(&p.id, p.data, stream)
            .map_err(session_err)?;
        self.commit_sessions(snapshot)?;
        Ok(json!({ "chunk": chunk }))
    }

    async fn handle_session_write(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            data: String,
            #[serde(default)]
            principal: Option<String>,
            #[serde(default)]
            workspace_id: Option<String>,
            /// Monotonic controller input sequence (required on remote MCP path).
            #[serde(default)]
            input_seq: Option<u64>,
            #[serde(default)]
            lease_id: Option<String>,
            #[serde(default)]
            controller_epoch: Option<u64>,
        }
        let p: P = parse_params(params)?;
        reject_spoofed_principal(p.principal.as_deref(), &client.client_name)?;
        if p.data.len() > ownmesh_session::MAX_CHUNK_BYTES {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!(
                    "session.write data exceeds {} byte chunk budget",
                    ownmesh_session::MAX_CHUNK_BYTES
                ),
            });
        }
        let now = self.prepare_session_access()?;
        let principal = client.client_name.clone();
        if is_remote_runtime_principal(&principal) {
            let lease_id = p
                .lease_id
                .as_deref()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "session.write requires lease_id for remote principals".into(),
                })?;
            let epoch = p.controller_epoch.ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "session.write requires controller_epoch for remote principals".into(),
            })?;
            self.sessions
                .authorize_controller_lease(&p.id, &principal, lease_id, epoch, now)
                .map_err(session_err)?;
        } else {
            self.sessions
                .authorize_stdin(&p.id, &principal, now)
                .map_err(session_err)?;
        }
        let bound_ws = self.require_session_workspace(&p.id, p.workspace_id.as_deref())?;
        // Validate sequence before side effects; advance only with the durable commit.
        if p.input_seq.is_none() && is_remote_runtime_principal(&principal) {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "session.write requires input_seq for remote principals".into(),
            });
        }
        if !self.live_hosts.contains_key(&p.id)
            && self
                .sessions
                .get(&p.id)
                .map_err(session_err)?
                .sidecar_host
                .is_none()
        {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!(
                    "session {} has no live PTY host (restarted daemon or non-PTY kind)",
                    p.id
                ),
            });
        }

        // E5/E3: durably reserve (session, seq, payload digest) BEFORE any PTY write.
        // Stale/gap/conflict never reach the process; exact-once retries replay.
        let input_digest = sha256_hex(p.data.as_bytes());
        let snapshot = self.sessions.clone();
        let (applied_seq, replayed, should_deliver, uncertain) = if let Some(seq) = p.input_seq {
            let outcome = self
                .sessions
                .reserve_input_seq(&p.id, seq, &input_digest)
                .map_err(session_err)?;
            match outcome {
                // Durable applied receipt: never re-deliver.
                ownmesh_session::SeqReserveOutcome::Replayed { seq } => {
                    (Some(seq), true, false, false)
                }
                // First reservation: deliver once after durable pending receipt.
                ownmesh_session::SeqReserveOutcome::Deliver { seq } => {
                    (Some(seq), false, true, false)
                }
                // Prior attempt left Pending — delivery is uncertain. At-most-once:
                // never re-write the PTY; surface explicit uncertain reconciliation.
                ownmesh_session::SeqReserveOutcome::RetryPending { seq } => {
                    (Some(seq), false, false, true)
                }
            }
        } else {
            (None, false, true, false)
        };
        // Persist reservation before mutation so a crash leaves a durable receipt
        // and retries cannot rewind sequences.
        self.commit_sessions(snapshot)?;

        if uncertain {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!(
                    "session.write input_seq {} delivery uncertain (prior attempt pending);                      not re-delivered (at-most-once). Reconcile session state before retrying                      with a new sequence.",
                    applied_seq.unwrap_or_default()
                ),
            });
        }

        if !should_deliver {
            return Ok(json!({
                "accepted": true,
                "replayed": true,
                "uncertain": false,
                "bytes": p.data.len(),
                "live_pty": true,
                "live_drained_bytes": 0,
                "workspace_id": bound_ws,
                "input_seq": applied_seq,
            }));
        }

        // Deliver bytes to the live PTY when owned; never pretend success on echo alone.
        if let Some(host) = self.live_hosts.get(&p.id) {
            if let Err(e) = host.write_stdin(p.data.as_bytes()) {
                return Err(IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("live PTY stdin write failed: {e}"),
                });
            }
        } else if self
            .sessions
            .get(&p.id)
            .map_err(session_err)?
            .sidecar_host
            .is_some()
        {
            let binding = self.sidecar_binding(&p.id)?;
            let supervisor = self.ensure_remote_supervisor().await?;
            supervisor
                .write(&binding, p.data.as_bytes().to_vec())
                .await
                .map_err(|err| IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: format!("persistent session sidecar stdin write failed: {err}"),
                })?;
        } else {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!(
                    "session {} has no live PTY host (restarted daemon or non-PTY kind)",
                    p.id
                ),
            });
        }

        // Finalize receipt + bounded system observation after successful delivery.
        let snapshot = self.sessions.clone();
        if let Some(seq) = applied_seq {
            self.sessions
                .finalize_input_seq(&p.id, seq)
                .map_err(session_err)?;
        }
        let receipt = if p.data.len() <= 64 {
            format!("[stdin-accepted] {}", p.data.replace('\n', "\\n"))
        } else {
            format!("[stdin-accepted] <{} bytes>", p.data.len())
        };
        let chunk = self
            .sessions
            .push_output(&p.id, receipt, SessionStreamKind::System)
            .map_err(session_err)?;
        self.commit_sessions(snapshot)?;
        let drained = self.drain_live_output_into_session(&p.id)?;
        let _ = replayed;
        Ok(json!({
            "accepted": true,
            "replayed": false,
            "chunk": chunk,
            "bytes": p.data.len(),
            "live_pty": true,
            "live_drained_bytes": drained,
            "workspace_id": bound_ws,
            "input_seq": applied_seq,
        }))
    }

    async fn handle_session_resize(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            cols: u16,
            rows: u16,
            #[serde(default)]
            workspace_id: Option<String>,
            /// Monotonic controller resize sequence (required on remote MCP path).
            #[serde(default)]
            resize_seq: Option<u64>,
            #[serde(default)]
            lease_id: Option<String>,
            #[serde(default)]
            controller_epoch: Option<u64>,
        }
        let p: P = parse_params(params)?;
        let now = self.prepare_session_access()?;
        if is_remote_runtime_principal(&client.client_name) {
            let lease_id = p
                .lease_id
                .as_deref()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "session.resize requires lease_id for remote principals".into(),
                })?;
            let epoch = p.controller_epoch.ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "session.resize requires controller_epoch for remote principals".into(),
            })?;
            self.sessions
                .authorize_controller_lease(&p.id, &client.client_name, lease_id, epoch, now)
                .map_err(session_err)?;
        } else {
            self.require_controller(&p.id, &client.client_name, now)?;
        }
        let bound_ws = self.require_session_workspace(&p.id, p.workspace_id.as_deref())?;
        if p.resize_seq.is_none() && is_remote_runtime_principal(&client.client_name) {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "session.resize requires resize_seq for remote principals".into(),
            });
        }
        // Fail closed before reserving/finalizing when no live host exists.
        // Persisted/stale sessions after daemon recovery must not consume sequences
        // or report resized:true without a real PTY side effect (matches write).
        if !self.live_hosts.contains_key(&p.id)
            && self
                .sessions
                .get(&p.id)
                .map_err(session_err)?
                .sidecar_host
                .is_none()
        {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!(
                    "session {} has no live PTY host (restarted daemon or non-PTY kind)",
                    p.id
                ),
            });
        }

        // Reserve seq+digest before PTY resize mutation (same exact-once rules as write).
        let resize_digest = format!("{}:{}", p.cols, p.rows);
        let snapshot = self.sessions.clone();
        let (applied_seq, should_deliver, uncertain) = if let Some(seq) = p.resize_seq {
            let outcome = self
                .sessions
                .reserve_resize_seq(&p.id, seq, &resize_digest)
                .map_err(session_err)?;
            match outcome {
                ownmesh_session::SeqReserveOutcome::Replayed { seq } => (Some(seq), false, false),
                ownmesh_session::SeqReserveOutcome::Deliver { seq } => (Some(seq), true, false),
                // At-most-once: never re-resize on uncertain pending receipt.
                ownmesh_session::SeqReserveOutcome::RetryPending { seq } => {
                    (Some(seq), false, true)
                }
            }
        } else {
            (None, true, false)
        };
        self.commit_sessions(snapshot)?;

        if uncertain {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!(
                    "session.resize resize_seq {} delivery uncertain (prior attempt pending);                      not re-delivered (at-most-once). Reconcile session state before retrying                      with a new sequence.",
                    applied_seq.unwrap_or_default()
                ),
            });
        }

        if should_deliver {
            if let Some(host) = self.live_hosts.get(&p.id) {
                host.resize(p.cols, p.rows).map_err(|e| IpcError::Remote {
                    code: app_error::INTERNAL,
                    message: format!("live PTY resize failed: {e}"),
                })?;
            } else {
                let binding = self.sidecar_binding(&p.id)?;
                let supervisor = self.ensure_remote_supervisor().await?;
                supervisor
                    .resize(&binding, p.cols, p.rows)
                    .await
                    .map_err(|err| IpcError::Remote {
                        code: app_error::CONFLICT,
                        message: format!("persistent session sidecar resize failed: {err}"),
                    })?;
            }
            let principal = client.client_name.as_str();
            let snapshot = self.sessions.clone();
            if let Some(seq) = applied_seq {
                self.sessions
                    .finalize_resize_seq(&p.id, seq)
                    .map_err(session_err)?;
            }
            self.sessions
                .resize(&p.id, principal, p.cols, p.rows, now)
                .map_err(session_err)?;
            self.commit_sessions(snapshot)?;
        }
        Ok(json!({
            "resized": true,
            "replayed": !should_deliver,
            "cols": p.cols,
            "rows": p.rows,
            "workspace_id": bound_ws,
            "live_pty": true,
            "resize_seq": applied_seq,
        }))
    }

    fn handle_workspace_list(&self, _client: &ClientIdentity) -> IpcResult<Value> {
        let mut workspaces: Vec<Value> = self
            .workspaces
            .iter()
            .map(|w| {
                json!({
                    "id": w.id,
                    "root": w.root.to_string_lossy(),
                    "label": w.label,
                })
            })
            .collect();
        workspaces.sort_by(|a, b| {
            a["id"]
                .as_str()
                .unwrap_or("")
                .cmp(b["id"].as_str().unwrap_or(""))
        });
        Ok(json!({
            "workspaces": workspaces,
            "count": workspaces.len(),
            "enforce_workspace": self.enforce_workspace,
        }))
    }

    fn handle_workspace_show(&self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
        }
        let p: P = parse_params(params)?;
        let id = p.id.trim();
        let entry = self
            .workspaces
            .iter()
            .find(|w| w.id == id || (id == "default" && w.id == "ws_default"))
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("unknown workspace_id: {id}"),
            })?;
        Ok(json!({
            "id": entry.id,
            "root": entry.root.to_string_lossy(),
            "label": entry.label,
            "exists": entry.root.exists(),
        }))
    }

    fn handle_workspace_add(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            path: String,
            #[serde(default)]
            id: Option<String>,
            #[serde(default)]
            label: Option<String>,
        }
        let p: P = parse_params(params)?;
        let root = PathBuf::from(p.path.trim());
        if !root.is_absolute() {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "workspace path must be absolute".into(),
            });
        }
        let id = if let Some(raw) = p.id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            raw.to_owned()
        } else {
            // Deterministic short id from canonical path bytes (ws_ + 12 hex).
            let key = root.to_string_lossy().to_ascii_lowercase();
            let digest = sha256_hex(key.as_bytes());
            format!("ws_{}", &digest[..12])
        };
        let entry = WorkspaceEntry {
            id,
            root,
            label: p.label,
        };
        let stored = self.upsert_workspace(entry)?;
        self.append_audit(
            "workspace.add",
            Some("workspace.add"),
            Some(stored.id.as_str()),
            Some("ok"),
            format!(
                "root={} principal={}",
                stored.root.display(),
                client.client_name
            ),
        );
        Ok(json!({
            "id": stored.id,
            "root": stored.root.to_string_lossy(),
            "label": stored.label,
            "created": true,
        }))
    }

    fn handle_workspace_update(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            #[serde(default)]
            label: Option<String>,
            #[serde(default)]
            path: Option<String>,
        }
        let p: P = parse_params(params)?;
        let id = p.id.trim().to_owned();
        if (id == "ws_default" || id == "default")
            && p.path
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .is_some()
        {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "ws_default root cannot be relocated".into(),
            });
        }
        let idx = self
            .workspaces
            .iter()
            .position(|w| w.id == id || (id == "default" && w.id == "ws_default"))
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("unknown workspace_id: {id}"),
            })?;
        if let Some(path) = p.path.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let root = PathBuf::from(path);
            if !root.is_absolute() {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "workspace path must be absolute".into(),
                });
            }
            std::fs::create_dir_all(&root).map_err(|e| IpcError::Remote {
                code: app_error::INTERNAL,
                message: e.to_string(),
            })?;
            self.workspaces[idx].root = root;
        }
        if let Some(label) = p.label {
            let label = label.trim().to_owned();
            self.workspaces[idx].label = if label.is_empty() { None } else { Some(label) };
        }
        self.persist_workspaces()?;
        let stored = self.workspaces[idx].clone();
        self.append_audit(
            "workspace.update",
            Some("workspace.update"),
            Some(stored.id.as_str()),
            Some("ok"),
            format!(
                "root={} principal={}",
                stored.root.display(),
                client.client_name
            ),
        );
        Ok(json!({
            "id": stored.id,
            "root": stored.root.to_string_lossy(),
            "label": stored.label,
            "updated": true,
        }))
    }

    fn handle_workspace_remove(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
        }
        let p: P = parse_params(params)?;
        let id = p.id.trim();
        if id == "ws_default" || id == "default" {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "ws_default cannot be removed".into(),
            });
        }
        let before = self.workspaces.len();
        self.workspaces.retain(|w| w.id != id);
        if self.workspaces.len() == before {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("unknown workspace_id: {id}"),
            });
        }
        self.persist_workspaces()?;
        self.append_audit(
            "workspace.remove",
            Some("workspace.remove"),
            Some(id),
            Some("ok"),
            format!("removed principal={}", client.client_name),
        );
        Ok(json!({
            "id": id,
            "removed": true,
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
    pub fn grants_for_test(&self) -> &[TemporaryGrant] {
        &self.grants
    }

    /// Test helper: inject a legacy/forged grant row (does not persist).
    ///
    /// Used to prove command.run grant matching stays fail-closed even when a
    /// persisted-shaped row is already present in memory.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn inject_grant_for_test(&mut self, grant: TemporaryGrant) {
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
    IpcError::Remote {
        code: app_error::INTERNAL,
        message: err.to_string(),
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
    )
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

fn is_op_journal_in_progress(value: &Value) -> bool {
    value.get(OP_JOURNAL_STATE_FIELD).and_then(Value::as_str) == Some(OP_JOURNAL_IN_PROGRESS)
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

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod device_binding_tests {
    use super::*;
    use tempfile::tempdir;

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
}

#[cfg(test)]
mod transfer_runtime_tests {
    use super::*;
    use ownmesh_transfer::ChunkSink;
    use tempfile::tempdir;

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
            })
            .unwrap();
        bind_remote_transfer(&mut destination);
        destination.active_remote_device_id = Some("dev_destination".into());

        let expires_at = u64::try_from(source.active_remote_expires_at_unix.unwrap()).unwrap();
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

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        assert_eq!(runtime.cleanup_expired_transfers().unwrap(), 1);
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
const MAX_OP_JOURNAL_VALUE_BYTES: usize = 64 * 1024;

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
        out.push(entry);
    }
    if !out
        .iter()
        .any(|w| w.id == "ws_default" || w.id == "default")
    {
        out.insert(0, default_entry);
    }
    // Normalize legacy bare "default" id to the domain-shaped ws_default.
    for entry in &mut out {
        if entry.id == "default" {
            entry.id = "ws_default".into();
        }
    }
    Ok(out)
}

fn load_op_journal(path: &Path) -> Result<HashMap<String, Value>, String> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("failed to stat operation journal {}: {e}", path.display()))?;
    if meta.len() as usize > MAX_OP_JOURNAL_FILE_BYTES {
        return Err(format!(
            "operation journal {} exceeds {MAX_OP_JOURNAL_FILE_BYTES} byte budget ({})",
            path.display(),
            meta.len()
        ));
    }
    let raw = std::fs::read(path)
        .map_err(|e| format!("failed to read operation journal {}: {e}", path.display()))?;
    if raw.len() > MAX_OP_JOURNAL_FILE_BYTES {
        return Err(format!(
            "operation journal {} exceeds {MAX_OP_JOURNAL_FILE_BYTES} byte budget",
            path.display()
        ));
    }
    let parsed: HashMap<String, Value> = serde_json::from_slice(&raw)
        .map_err(|e| format!("corrupt operation journal {}: {e}", path.display()))?;
    bound_op_journal(parsed)
}

fn bound_op_journal(mut journal: HashMap<String, Value>) -> Result<HashMap<String, Value>, String> {
    if journal.len() > MAX_OP_JOURNAL_ENTRIES {
        return Err(format!(
            "operation journal exceeds {MAX_OP_JOURNAL_ENTRIES} entry budget ({})",
            journal.len()
        ));
    }
    for (key, value) in &mut journal {
        let bytes = serde_json::to_vec(value)
            .map_err(|e| format!("operation journal value serialize failed for {key}: {e}"))?;
        if bytes.len() > MAX_OP_JOURNAL_VALUE_BYTES {
            // Retain a compact non-retriable receipt so exact-once is preserved.
            let status = value
                .get("status")
                .cloned()
                .unwrap_or_else(|| json!("completed"));
            let operation_id = value.get("operation_id").cloned();
            let state = value.get(OP_JOURNAL_STATE_FIELD).cloned();
            let mut compact = json!({
                "durable_receipt": true,
                "truncated": true,
                "status": status,
                "note": "op-journal entry exceeded durable value budget"
            });
            if let Some(obj) = compact.as_object_mut() {
                if let Some(oid) = operation_id {
                    obj.insert("operation_id".into(), oid);
                }
                if let Some(st) = state {
                    obj.insert(OP_JOURNAL_STATE_FIELD.into(), st);
                }
            }
            *value = compact;
        }
    }
    let encoded = serde_json::to_vec(&journal)
        .map_err(|e| format!("operation journal re-encode failed: {e}"))?;
    if encoded.len() > MAX_OP_JOURNAL_FILE_BYTES {
        return Err(format!(
            "operation journal exceeds {MAX_OP_JOURNAL_FILE_BYTES} byte budget after compaction"
        ));
    }
    Ok(journal)
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

fn load_grants(path: &Path) -> Result<Vec<TemporaryGrant>, String> {
    let raw = read_bounded_state_file(path, MAX_GRANTS_FILE_BYTES, "grants state")?;
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let grants: Vec<TemporaryGrant> = serde_json::from_slice(&raw)
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

#[cfg(test)]
mod broker_intent_tests {
    use super::*;
    use tempfile::tempdir;

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
                executable_pin: Some(pin),
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

    #[tokio::test]
    async fn local_elevation_stays_in_the_same_runtime_and_uncertain_marker_blocks_replay() {
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
        let second = runtime
            .dispatch(methods::OPS_EXEC, Some(params), &client)
            .await
            .expect_err("uncertain elevated operation must not rerun");
        assert!(
            second.to_string().contains("in-progress") || second.to_string().contains("uncertain")
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
