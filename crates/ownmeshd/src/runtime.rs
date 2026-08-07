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

use ownmesh_broker_client::{BrokerEndpoint, BrokerSecret};
use ownmesh_config::{load_policy, save_policy, OwnMeshPaths, PolicyFile};
use ownmesh_exec::{
    classify_from_request_in_dir, pin_executable, resolve_executable_path, run_command,
    verify_executable_pin, CommandKind, ExecutablePin, IdempotencyJournal, RunRequest, RunResult,
};
use ownmesh_fs::{
    delete_path, git_diff, git_status, list_dir, read_file, stat_path, write_file, GitDiffOpts,
    GitStatusOpts, WorkspaceRoot,
};
use ownmesh_ipc::{
    app_error, canonicalize_principal_key, is_credentialed_client_principal, is_human_os_principal,
    methods, ClientIdentity, IpcError, IpcResult, MethodHandler, RevokedClients,
};
use ownmesh_logs::{
    register_builtin_providers, BuiltinProviderConfig, LogCursor, LogError, LogRegistry,
};
use ownmesh_policy::{
    evaluate_with_grants, full_access_has_no_hidden_restrictive_rules, preset_document,
    temporary_grant_from_facts, temporary_grant_requires_operation_binding, AccessPreset, Decision,
    OperationFacts, PolicyDocument, TemporaryGrant,
};
use ownmesh_session::{SessionKind, SessionManager, StreamKind as SessionStreamKind};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use uuid::Uuid;

/// Session IPC method names (owned here; ipc crate methods table is ms1-stable).
pub mod session_methods {
    pub const OPEN: &str = "session.open";
    pub const LIST: &str = "session.list";
    pub const SHOW: &str = "session.show";
    pub const ATTACH: &str = "session.attach";
    pub const CLAIM: &str = "session.claim";
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
    pub const LOGS_LIST_PROVIDERS: &str = "ops.logs.list_providers";
}

const LOCAL_PRINCIPAL: &str = "prin_local";
const DEFAULT_GRANT_SECS: i64 = 3600;
const OP_JOURNAL_STATE_FIELD: &str = "__ownmesh_operation_state";
const OP_JOURNAL_IN_PROGRESS: &str = "in_progress";

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
    Exec(ExecParams),
    FsList(FsListParams),
    FsStat(FsStatParams),
    FsRead(FsReadParams),
    FsWrite(FsWriteParams),
    FsDelete(FsDeleteParams),
    LogsQuery(LogsQueryParams),
    GitStatus(GitStatusParams),
    GitDiff(GitDiffParams),
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
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsStatParams {
    pub path: String,
    #[serde(default)]
    pub hash: bool,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsReadParams {
    pub path: String,
    #[serde(default)]
    pub max_bytes: Option<u64>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsWriteParams {
    pub path: String,
    /// UTF-8 text body (binary via base64 can land later).
    pub content: String,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsDeleteParams {
    pub path: String,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub idempotency_key: Option<String>,
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

/// Shared daemon operation state.
pub struct DaemonRuntime {
    paths: OwnMeshPaths,
    policy: PolicyDocument,
    grants: Vec<TemporaryGrant>,
    approvals: HashMap<String, ApprovalRecord>,
    /// Completed operation results keyed by client idempotency key.
    op_journal: HashMap<String, Value>,
    exec_journal: IdempotencyJournal,
    lockdown: bool,
    revoked_clients: RevokedClients,
    audit: Vec<AuditEntry>,
    workspace_root: PathBuf,
    enforce_workspace: bool,
    log_path: PathBuf,
    sessions: SessionManager,
    sessions_path: PathBuf,
    broker_endpoint: Option<BrokerEndpoint>,
    broker_secret: Option<BrokerSecret>,
    #[cfg(test)]
    op_journal_persist_fault: AtomicUsize,
    #[cfg(test)]
    approvals_persist_fault: AtomicUsize,
}

impl DaemonRuntime {
    /// Bootstrap runtime from discovered / test paths.
    pub fn open(paths: &OwnMeshPaths) -> Result<Self, String> {
        paths.ensure_layout().map_err(|e| e.to_string())?;
        let journal_path = paths.state_dir.join("idempotency-journal.json");
        let exec_journal = IdempotencyJournal::open(&journal_path).map_err(|e| e.to_string())?;
        let policy_file = load_policy(paths).unwrap_or_default();
        let policy = policy_from_file(&policy_file);
        let enforce_workspace = matches!(
            policy.preset,
            AccessPreset::WorkspaceOnly | AccessPreset::Recommended
        );
        let workspace_root = paths.state_dir.join("workspace");
        std::fs::create_dir_all(&workspace_root).map_err(|e| e.to_string())?;
        let log_path = paths.state_dir.join("logs").join("audit.log");
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        if !log_path.exists() {
            std::fs::write(&log_path, b"").map_err(|e| e.to_string())?;
        }
        let op_journal = load_op_journal(&paths.state_dir.join("op-journal.json"))?;
        let grants = load_grants(&paths.state_dir.join("grants.json"));
        let approvals = load_approvals(&paths.state_dir.join("approvals.json"))?;
        let lockdown = paths.state_dir.join("lockdown.flag").exists();
        let revoked_clients = Arc::new(RwLock::new(load_revoked(
            &paths.state_dir.join("revoked-clients.json"),
        )?));
        let sessions_path = paths.state_dir.join("sessions").join("sessions.json");
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
        let (broker_endpoint, broker_secret) = load_broker_client(paths);
        Ok(Self {
            paths: paths.clone(),
            policy,
            grants,
            approvals,
            op_journal,
            exec_journal,
            lockdown,
            revoked_clients,
            audit: Vec::new(),
            workspace_root,
            enforce_workspace,
            log_path,
            sessions,
            sessions_path,
            broker_endpoint,
            broker_secret,
            #[cfg(test)]
            op_journal_persist_fault: AtomicUsize::new(0),
            #[cfg(test)]
            approvals_persist_fault: AtomicUsize::new(0),
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

    fn workspace(&self) -> IpcResult<WorkspaceRoot> {
        WorkspaceRoot::new(&self.workspace_root, self.enforce_workspace).map_err(|e| {
            IpcError::Remote {
                code: app_error::INTERNAL,
                message: e.to_string(),
            }
        })
    }

    fn check_lockdown(&self, method: &str) -> IpcResult<()> {
        // Local recovery methods remain available during lockdown.
        const ALLOWED: &[&str] = &[
            methods::DAEMON_UNLOCK,
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
        if let Some(prev) = self.lookup_idempotent(idempotency_key.as_ref())? {
            let mut replayed = prev;
            if let Some(obj) = replayed.as_object_mut() {
                obj.insert("replayed".into(), json!(true));
            }
            return Ok(replayed);
        }
        let requester_principal = canonicalize_principal_key(client.principal_key());

        let verdict = self.evaluate(&facts, &requester_principal);
        let operation_id = Self::new_id("op_");
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
                self.begin_idempotent(idempotency_key.as_ref(), &operation_id)?;
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
                self.store_idempotent(idempotency_key.as_ref(), &body)?;
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

        // elevated=true is production-unsupported until a secure mint authority exists.
        // Fail closed regardless of broker install/artifacts; never fall back to local exec.
        if p.elevated {
            let _ = execution_program;
            return self.try_broker_elevated(p).await;
        }
        // Spawn mode follows the client request shape (argv vs shell-string).
        // Policy already used server-side classification in handle_exec.
        let req = RunRequest {
            kind,
            program: execution_program,
            args: p.args.clone(),
            cwd: p.cwd.as_ref().map(PathBuf::from),
            env: HashMap::new(),
            stdin: None,
            timeout_ms: p.timeout_ms.or(Some(30_000)),
            max_output_bytes: p.max_output_bytes.unwrap_or(1024 * 1024),
            idempotency_key: p.idempotency_key.clone(),
        };
        // Approved operations are journaled by `op_journal` as part of the approval
        // transaction. Do not also mutate `exec_journal`, which cannot participate in
        // that transaction's in-memory rollback.
        let result: RunResult = if use_exec_journal {
            run_command(&req, Some(&mut self.exec_journal)).await
        } else {
            run_command(&req, None).await
        }
        .map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })?;
        serde_json::to_value(result).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })
    }

    async fn try_broker_elevated(&self, _p: &ExecParams) -> IpcResult<Value> {
        // Ignore broker_endpoint/broker_secret presence: production elevated exec is
        // unsupported until secure mint authority is established. No process spawn.
        let _ = (&self.broker_endpoint, &self.broker_secret);
        Err(IpcError::Remote {
            code: app_error::INTERNAL,
            message: "unsupported: elevated execution requires broker; broker unavailable (not configured); secure mint authority not established (fail-closed; no local exec)".into(),
        })
    }

    fn execute_fs_list(&self, p: &FsListParams) -> IpcResult<Value> {
        let ws = self.workspace()?;
        let entries =
            list_dir(&ws, &p.path, p.recursive, p.max_entries.unwrap_or(1000)).map_err(fs_err)?;
        Ok(json!({ "entries": entries }))
    }

    fn execute_fs_stat(&self, p: &FsStatParams) -> IpcResult<Value> {
        let ws = self.workspace()?;
        let st = stat_path(&ws, &p.path, p.hash).map_err(fs_err)?;
        serde_json::to_value(st).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })
    }

    fn execute_fs_read(&self, p: &FsReadParams) -> IpcResult<Value> {
        let ws = self.workspace()?;
        let data = read_file(&ws, &p.path, p.max_bytes.unwrap_or(1024 * 1024)).map_err(fs_err)?;
        let text = String::from_utf8_lossy(&data).into_owned();
        Ok(json!({ "path": p.path, "content": text, "bytes": data.len() }))
    }

    fn execute_fs_write(&self, p: &FsWriteParams) -> IpcResult<Value> {
        let ws = self.workspace()?;
        write_file(&ws, &p.path, p.content.as_bytes()).map_err(fs_err)?;
        Ok(json!({ "path": p.path, "bytes_written": p.content.len() }))
    }

    fn execute_fs_delete(&self, p: &FsDeleteParams) -> IpcResult<Value> {
        let ws = self.workspace()?;
        delete_path(&ws, &p.path, p.recursive).map_err(fs_err)?;
        Ok(json!({ "path": p.path, "deleted": true }))
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
        let ws = self.workspace()?;
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
        let ws = self.workspace()?;
        let page = git_diff(
            &ws,
            &GitDiffOpts {
                path: PathBuf::from(&p.path),
                pathspec: p.pathspec.clone(),
                staged: p.staged,
                cursor: p.cursor,
                limit: p.limit.unwrap_or(200),
                max_bytes: p.max_bytes.unwrap_or(1024 * 1024),
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
        if p.program.trim().is_empty() {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "program is required".into(),
            });
        }
        // Resolve argv executables once, before classification, and persist that exact
        // canonical path with approvals/execution. Raw-shell command strings are not paths.
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
        let facts = OperationFacts {
            capability: "command.run".into(),
            kind: kind.as_str().to_string(),
            program: Some(p.program.clone()),
            elevated: p.elevated,
            path: p.cwd.clone(),
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::Exec(p), client)
            .await
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
        // Server-captured policy facts only — never trust client-supplied grant scope.
        let approved_facts = rec.facts.clone();
        let idem_key = match &request {
            PendingRequest::Exec(x) => x.idempotency_key.clone(),
            PendingRequest::FsList(x) => x.idempotency_key.clone(),
            PendingRequest::FsStat(x) => x.idempotency_key.clone(),
            PendingRequest::FsRead(x) => x.idempotency_key.clone(),
            PendingRequest::FsWrite(x) => x.idempotency_key.clone(),
            PendingRequest::FsDelete(x) => x.idempotency_key.clone(),
            PendingRequest::LogsQuery(x) => x.idempotency_key.clone(),
            PendingRequest::GitStatus(x) => x.idempotency_key.clone(),
            PendingRequest::GitDiff(x) => x.idempotency_key.clone(),
        };

        // Build (or refuse) the temporary grant before mutating durable approval state.
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
        let result = match &request {
            PendingRequest::Exec(p) => self.execute_exec(p, false).await,
            other => self.execute_request(other).await,
        }?;
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
            self.op_journal = executing_op_journal;
            self.approvals = executing_approvals;
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
            self.approvals = executing_approvals;
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
        };
        save_policy(&self.paths, &file).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })?;
        self.policy = policy;
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
            ops_methods::LOGS_LIST_PROVIDERS => self.handle_logs_list_providers(params),
            ops_methods::GIT_STATUS => self.handle_git_status(params, client).await,
            ops_methods::GIT_DIFF => self.handle_git_diff(params, client).await,
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
            session_methods::OPEN => self.handle_session_open(params, client),
            session_methods::LIST => self.handle_session_list(client),
            session_methods::SHOW => self.handle_session_show(params, client),
            session_methods::ATTACH => self.handle_session_attach(params, client),
            session_methods::CLAIM => self.handle_session_claim(params, client),
            session_methods::RELEASE => self.handle_session_release(params, client),
            session_methods::GIVE => self.handle_session_give(params, client),
            session_methods::CLOSE => self.handle_session_close(params, client),
            session_methods::TERMINATE => self.handle_session_terminate(params, client),
            session_methods::REPLAY => self.handle_session_replay(params, client),
            session_methods::PUSH_OUTPUT => self.handle_session_push_output(params, client),
            session_methods::WRITE => self.handle_session_write(params, client),
            session_methods::RESIZE => self.handle_session_resize(params, client),
            other => Err(IpcError::Remote {
                code: app_error::METHOD_NOT_FOUND,
                message: format!("method not found: {other}"),
            }),
        }
    }

    fn handle_session_open(
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
            #[serde(default)]
            command: Option<Vec<String>>,
            #[serde(default)]
            cwd: Option<String>,
        }
        let p: P = parse_params(params)?;
        reject_spoofed_principal(p.principal.as_deref(), &client.client_name)?;
        let kind = match p.kind.as_deref() {
            Some("process") => SessionKind::Process,
            Some("profile_agent") | Some("profile") => SessionKind::ProfileAgent,
            _ => SessionKind::Pty,
        };
        let principal = client.client_name.clone();
        let title = p.title.unwrap_or_else(|| "session".into());
        let snapshot = self.sessions.clone();
        let info = self.sessions.open_with(
            kind,
            title,
            principal,
            Self::now(),
            p.profile_id,
            None,
            p.command,
            p.cwd,
            None,
        );
        self.commit_sessions(snapshot)?;
        serde_json::to_value(info).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })
    }

    fn handle_session_list(&mut self, client: &ClientIdentity) -> IpcResult<Value> {
        let now = self.prepare_session_access()?;
        let principal = &client.client_name;
        let sessions: Vec<_> = self
            .sessions
            .list()
            .into_iter()
            .filter(|info| {
                self.sessions
                    .readers(&info.id, now)
                    .map(|r| r.contains(principal))
                    .unwrap_or(false)
            })
            .collect();
        Ok(json!({ "sessions": sessions }))
    }

    fn handle_session_show(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let now = self.prepare_session_access()?;
        let id = require_id(params, "id")?;
        self.require_reader(&id, &client.client_name, now)?;
        let info = self.sessions.get(&id).map_err(session_err)?;
        serde_json::to_value(info).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })
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
            #[serde(default)]
            read_only: bool,
        }
        let p: P = parse_params(params)?;
        reject_spoofed_principal(p.principal.as_deref(), &client.client_name)?;
        let now = self.prepare_session_access()?;
        // Session IDs are identifiers, not bearer capabilities. Attaching cannot
        // grant a new principal access; delegation must happen through session.give.
        self.require_reader(&p.id, &client.client_name, now)?;
        let principal = client.client_name.clone();
        let snapshot = self.sessions.clone();
        if p.read_only {
            self.sessions
                .attach_observer(&p.id, principal.clone(), now)
                .map_err(session_err)?;
        } else {
            let _ = self
                .sessions
                .claim_controller(&p.id, principal.clone(), now)
                .map_err(session_err)?;
        }
        self.commit_sessions(snapshot)?;
        let info = self.sessions.get(&p.id).map_err(session_err)?;
        Ok(json!({
            "session": info,
            "principal": principal,
            "read_only": p.read_only,
            "readers": self.sessions.readers(&p.id, now).map_err(session_err)?.into_iter().collect::<Vec<_>>(),
        }))
    }

    fn handle_session_claim(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            #[serde(default)]
            principal: Option<String>,
        }
        let p: P = parse_params(params)?;
        reject_spoofed_principal(p.principal.as_deref(), &client.client_name)?;
        let now = self.prepare_session_access()?;
        // Only an existing reader may claim a released/expired controller lease.
        self.require_reader(&p.id, &client.client_name, now)?;
        let principal = client.client_name.clone();
        let snapshot = self.sessions.clone();
        let lease = self
            .sessions
            .claim_controller(&p.id, principal, now)
            .map_err(session_err)?;
        self.commit_sessions(snapshot)?;
        Ok(json!({ "lease": lease, "session_id": p.id }))
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
        }
        let p: P = parse_params(params)?;
        reject_spoofed_principal(p.principal.as_deref(), &client.client_name)?;
        let now = self.prepare_session_access()?;
        let principal = client.client_name.clone();
        let snapshot = self.sessions.clone();
        self.sessions
            .release_controller(&p.id, &principal, now)
            .map_err(session_err)?;
        self.commit_sessions(snapshot)?;
        Ok(json!({ "released": true, "session_id": p.id }))
    }

    fn handle_session_give(
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
        let from = client.client_name.clone();
        let snapshot = self.sessions.clone();
        let lease = self
            .sessions
            .give_controller(&p.id, &from, p.to, now)
            .map_err(session_err)?;
        self.commit_sessions(snapshot)?;
        let readers: Vec<String> = self
            .sessions
            .readers(&p.id, now)
            .map_err(session_err)?
            .into_iter()
            .collect();
        Ok(json!({ "lease": lease, "readers": readers }))
    }

    fn handle_session_close(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let now = self.prepare_session_access()?;
        let id = require_id(params, "id")?;
        self.require_controller(&id, &client.client_name, now)?;
        let snapshot = self.sessions.clone();
        self.sessions.close(&id).map_err(session_err)?;
        self.commit_sessions(snapshot)?;
        Ok(json!({ "closed": true, "session_id": id }))
    }

    fn handle_session_terminate(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            #[serde(default)]
            id: Option<String>,
            #[serde(default)]
            all: bool,
        }
        let p: P = parse_params(params)?;
        let now = self.prepare_session_access()?;
        if p.all {
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
            let snapshot = self.sessions.clone();
            let mut n = 0usize;
            for id in controlled {
                self.sessions.terminate(&id).map_err(session_err)?;
                n += 1;
            }
            self.commit_sessions(snapshot)?;
            return Ok(json!({ "terminated": n, "all": true }));
        }
        let id = p.id.ok_or_else(|| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: "id or all required".into(),
        })?;
        self.require_controller(&id, &client.client_name, now)?;
        let snapshot = self.sessions.clone();
        self.sessions.terminate(&id).map_err(session_err)?;
        self.commit_sessions(snapshot)?;
        Ok(json!({ "terminated": 1, "session_id": id }))
    }

    fn handle_session_replay(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            #[serde(default)]
            from_seq: Option<u64>,
            /// Ignored: read ACL uses authenticated client identity.
            #[serde(default)]
            principal: Option<String>,
        }
        let p: P = parse_params(params)?;
        reject_spoofed_principal(p.principal.as_deref(), &client.client_name)?;
        let now = self.prepare_session_access()?;
        self.require_reader(&p.id, &client.client_name, now)?;
        let chunks = self
            .sessions
            .replay_from(&p.id, &client.client_name, p.from_seq.unwrap_or(1), now)
            .map_err(session_err)?;
        Ok(json!({ "chunks": chunks, "session_id": p.id }))
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

    fn handle_session_write(
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
        }
        let p: P = parse_params(params)?;
        reject_spoofed_principal(p.principal.as_deref(), &client.client_name)?;
        let now = self.prepare_session_access()?;
        let principal = client.client_name.clone();
        self.sessions
            .authorize_stdin(&p.id, &principal, now)
            .map_err(session_err)?;
        // Record input echo for observers (controller write path).
        let snapshot = self.sessions.clone();
        let chunk = self
            .sessions
            .push_output(
                &p.id,
                format!("[stdin] {}", p.data),
                SessionStreamKind::System,
            )
            .map_err(session_err)?;
        self.commit_sessions(snapshot)?;
        Ok(json!({ "accepted": true, "chunk": chunk }))
    }

    fn handle_session_resize(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            cols: u16,
            rows: u16,
        }
        let p: P = parse_params(params)?;
        let now = self.prepare_session_access()?;
        self.require_controller(&p.id, &client.client_name, now)?;
        let principal = client.client_name.as_str();
        let snapshot = self.sessions.clone();
        self.sessions
            .resize(&p.id, principal, p.cols, p.rows, now)
            .map_err(session_err)?;
        self.commit_sessions(snapshot)?;
        Ok(json!({ "resized": true, "cols": p.cols, "rows": p.rows }))
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

    /// Test helper: whether an idempotency key is present in the op journal.
    #[cfg(test)]
    #[allow(dead_code)]
    #[must_use]
    pub fn has_op_journal_key_for_test(&self, key: &str) -> bool {
        self.op_journal.contains_key(key)
    }

    /// Test helper: whether a key is retained as non-retriable/uncertain.
    #[cfg(test)]
    #[allow(dead_code)]
    #[must_use]
    pub fn op_journal_key_is_in_progress_for_test(&self, key: &str) -> bool {
        self.op_journal
            .get(key)
            .is_some_and(is_op_journal_in_progress)
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

    /// Test helper: number of in-memory sessions.
    #[cfg(test)]
    #[allow(dead_code)]
    #[must_use]
    pub fn session_count_for_test(&self) -> usize {
        self.sessions.list().len()
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

/// Fail-closed gate for approval decisions.
///
/// - Approver must be an OS-attested human principal (`user:*`).
/// - Non-human / credentialed principals can never approve.
/// - Credentialed requesters cannot self-approve (identity must differ from approver).
/// - Client-supplied approver fields are never consulted (caller passes auth identity only).
///
/// AuthGate already rejects credentialed callers for approve/deny; this is defense in depth
/// inside the production runtime handler so a bypassed gate cannot self-approve.
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
    // Local human operators may approve their own deferred ops (same user:* principal).
    // Agent/service creators (`client:*`) must always be decided by a different human.
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
    let code = match err {
        ownmesh_session::SessionError::NotFound => app_error::INVALID_PARAMS,
        ownmesh_session::SessionError::NotReader => app_error::POLICY_DENIED,
        ownmesh_session::SessionError::LeaseHeld(_)
        | ownmesh_session::SessionError::NotController
        | ownmesh_session::SessionError::ObserverCannotWrite
        | ownmesh_session::SessionError::Closed => app_error::CONFLICT,
        _ => app_error::INTERNAL,
    };
    IpcError::Remote {
        code,
        message: err.to_string(),
    }
}

/// Production elevated broker loading is disabled until a secure mint authority
/// exists. Ignore all install records and artifacts, including hand-written
/// `installed=true` / `support=supported` records, and return no broker config.
pub(crate) fn load_broker_client(
    _paths: &OwnMeshPaths,
) -> (Option<BrokerEndpoint>, Option<BrokerSecret>) {
    (None, None)
}

fn is_op_journal_in_progress(value: &Value) -> bool {
    value.get(OP_JOURNAL_STATE_FIELD).and_then(Value::as_str) == Some(OP_JOURNAL_IN_PROGRESS)
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

fn policy_from_file(file: &PolicyFile) -> PolicyDocument {
    let preset = file
        .preset
        .as_deref()
        .and_then(parse_preset)
        .unwrap_or(AccessPreset::Recommended);
    preset_document(preset)
}

fn load_op_journal(path: &Path) -> Result<HashMap<String, Value>, String> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read operation journal {}: {e}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|e| format!("corrupt operation journal {}: {e}", path.display()))
}

fn load_grants(path: &Path) -> Vec<TemporaryGrant> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn load_approvals(path: &Path) -> Result<HashMap<String, ApprovalRecord>, String> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|e| format!("corrupt approval state {}: {e}", path.display()))
}

fn load_revoked(path: &Path) -> Result<HashSet<String>, String> {
    if !path.exists() {
        return Ok(HashSet::new());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let list: Vec<String> = serde_json::from_str(&raw)
        .map_err(|e| format!("corrupt revoked client state {}: {e}", path.display()))?;
    let mut canonical = HashSet::with_capacity(list.len());
    for stored in &list {
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
