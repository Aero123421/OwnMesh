//! Policy-gated operation runtime for ownmeshd.
//!
//! Flow: classify facts → evaluate policy (+ grants / lockdown) →
//! allow execute | ask enqueue | deny. Completed results are journaled by
//! idempotency key so duplicate operations are not re-executed.

use ownmesh_broker_client::{
    default_broker_endpoint, elevate, BrokerEndpoint, BrokerSecret, ElevatedCommand,
};
use ownmesh_config::{load_policy, save_policy, OwnMeshPaths, PolicyFile};
use ownmesh_exec::{run_command, CommandKind, IdempotencyJournal, RunRequest, RunResult};
use ownmesh_fs::{
    delete_path, git_diff, git_status, list_dir, read_file, stat_path, write_file, GitDiffOpts,
    GitStatusOpts, WorkspaceRoot,
};
use ownmesh_ipc::{app_error, methods, IpcError, IpcResult, MethodHandler};
use ownmesh_logs::{
    register_builtin_providers, BuiltinProviderConfig, LogCursor, LogError, LogRegistry,
};
use ownmesh_policy::{
    evaluate_with_grants, full_access_has_no_hidden_restrictive_rules, preset_document,
    AccessPreset, Decision, OperationFacts, PolicyDocument, TemporaryGrant,
};
use ownmesh_session::{
    SessionKind, SessionManager, StreamKind as SessionStreamKind,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
    /// Serialized original request params.
    pub request: PendingRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
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
    revoked_clients: HashSet<String>,
    audit: Vec<AuditEntry>,
    workspace_root: PathBuf,
    enforce_workspace: bool,
    log_path: PathBuf,
    sessions: SessionManager,
    sessions_path: PathBuf,
    broker_endpoint: Option<BrokerEndpoint>,
    broker_secret: Option<BrokerSecret>,
}

impl DaemonRuntime {
    /// Bootstrap runtime from discovered / test paths.
    pub fn open(paths: &OwnMeshPaths) -> Result<Self, String> {
        paths.ensure_layout().map_err(|e| e.to_string())?;
        let journal_path = paths.state_dir.join("idempotency-journal.json");
        let exec_journal =
            IdempotencyJournal::open(&journal_path).map_err(|e| e.to_string())?;
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
        let op_journal = load_json_map(&paths.state_dir.join("op-journal.json"));
        let grants = load_grants(&paths.state_dir.join("grants.json"));
        let lockdown = paths.state_dir.join("lockdown.flag").exists();
        let revoked_clients = load_revoked(&paths.state_dir.join("revoked-clients.json"));
        let sessions_path = paths.state_dir.join("sessions").join("sessions.json");
        let mut sessions =
            SessionManager::load_from_path(&sessions_path).unwrap_or_else(|_| SessionManager::new());
        let _ = sessions.mark_hosts_detached_after_restart();
        let (broker_endpoint, broker_secret) = load_broker_client(paths);
        Ok(Self {
            paths: paths.clone(),
            policy,
            grants,
            approvals: HashMap::new(),
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
        })
    }

    fn persist_sessions(&self) {
        let _ = self.sessions.save_to_path(&self.sessions_path);
    }

    fn persist_op_journal(&self) {
        let _ = write_json(&self.paths.state_dir.join("op-journal.json"), &self.op_journal);
    }

    fn persist_grants(&self) {
        let _ = write_json(&self.paths.state_dir.join("grants.json"), &self.grants);
    }

    fn persist_lockdown(&self) {
        let flag = self.paths.state_dir.join("lockdown.flag");
        if self.lockdown {
            let _ = std::fs::write(flag, b"1");
        } else {
            let _ = std::fs::remove_file(flag);
        }
    }

    fn persist_revoked(&self) {
        let list: Vec<&String> = self.revoked_clients.iter().collect();
        let _ = write_json(&self.paths.state_dir.join("revoked-clients.json"), &list);
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

    fn evaluate(&self, facts: &OperationFacts) -> ownmesh_policy::PolicyVerdict {
        evaluate_with_grants(
            &self.policy,
            facts,
            &self.grants,
            Self::now(),
            LOCAL_PRINCIPAL,
        )
    }

    fn lookup_idempotent(&self, key: Option<&String>) -> Option<Value> {
        key.and_then(|k| self.op_journal.get(k).cloned())
    }

    fn store_idempotent(&mut self, key: Option<&String>, value: &Value) {
        if let Some(k) = key {
            self.op_journal.insert(k.clone(), value.clone());
            self.persist_op_journal();
        }
    }

    async fn gate_and_run(
        &mut self,
        facts: OperationFacts,
        idempotency_key: Option<String>,
        request: PendingRequest,
    ) -> IpcResult<Value> {
        if let Some(prev) = self.lookup_idempotent(idempotency_key.as_ref()) {
            let mut replayed = prev;
            if let Some(obj) = replayed.as_object_mut() {
                obj.insert("replayed".into(), json!(true));
            }
            return Ok(replayed);
        }

        let verdict = self.evaluate(&facts);
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
                    request,
                    result: None,
                };
                self.approvals.insert(approval_id.clone(), rec);
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
                let result = self.execute_request(&request).await?;
                let body = json!({
                    "approval_required": false,
                    "operation_id": operation_id,
                    "result": result,
                    "replayed": false,
                    "decision": "allow",
                    "reason": verdict.reason,
                });
                self.store_idempotent(idempotency_key.as_ref(), &body);
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
            PendingRequest::Exec(p) => self.execute_exec(p).await,
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

    async fn execute_exec(&mut self, p: &ExecParams) -> IpcResult<Value> {
        if p.elevated {
            if let Some(value) = self.try_broker_elevated(p).await? {
                return Ok(value);
            }
            // Broker unavailable: fall back to local structured exec (ms1 behavior).
        }
        let kind = match p.kind.as_deref() {
            Some("raw_shell") | Some("raw") => CommandKind::RawShell,
            _ => CommandKind::Structured,
        };
        let req = RunRequest {
            kind,
            program: p.program.clone(),
            args: p.args.clone(),
            cwd: p.cwd.as_ref().map(PathBuf::from),
            env: HashMap::new(),
            stdin: None,
            timeout_ms: p.timeout_ms.or(Some(30_000)),
            max_output_bytes: p.max_output_bytes.unwrap_or(1024 * 1024),
            idempotency_key: p.idempotency_key.clone(),
        };
        let result: RunResult = run_command(&req, Some(&mut self.exec_journal))
            .await
            .map_err(|e| IpcError::Remote {
                code: app_error::INTERNAL,
                message: e.to_string(),
            })?;
        serde_json::to_value(result).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })
    }

    async fn try_broker_elevated(&self, p: &ExecParams) -> IpcResult<Option<Value>> {
        let (Some(endpoint), Some(secret)) = (&self.broker_endpoint, &self.broker_secret) else {
            return Ok(None);
        };
        let cmd = ElevatedCommand {
            program: p.program.clone(),
            args: p.args.clone(),
            cwd: p.cwd.clone(),
            env: vec![],
        };
        match elevate(
            endpoint,
            secret,
            "ownmeshd",
            p.idempotency_key
                .clone()
                .unwrap_or_else(|| Self::new_id("elev_")),
            cmd,
            Self::now(),
            60,
        )
        .await
        {
            Ok(resp) => Ok(Some(json!({
                "exit_code": resp.exit_code,
                "stdout": resp.stdout,
                "stderr": resp.stderr,
                "timed_out": false,
                "duration_ms": 0,
                "truncated": false,
                "replayed": false,
                "elevated_via": "broker",
                "broker_ok": resp.ok,
                "broker_error": resp.error,
            }))),
            Err(_) => Ok(None),
        }
    }

    fn execute_fs_list(&self, p: &FsListParams) -> IpcResult<Value> {
        let ws = self.workspace()?;
        let entries = list_dir(
            &ws,
            &p.path,
            p.recursive,
            p.max_entries.unwrap_or(1000),
        )
        .map_err(fs_err)?;
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
                windows_channel: p
                    .channel
                    .clone()
                    .unwrap_or_else(|| "Application".into()),
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

    async fn handle_exec(&mut self, params: Option<Value>) -> IpcResult<Value> {
        let p: ExecParams = parse_params(params)?;
        if p.program.trim().is_empty() {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "program is required".into(),
            });
        }
        let kind = p.kind.clone().unwrap_or_else(|| "structured".into());
        let facts = OperationFacts {
            capability: "command.run".into(),
            kind: kind.clone(),
            program: Some(p.program.clone()),
            elevated: p.elevated,
            path: p.cwd.clone(),
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::Exec(p)).await
    }

    async fn handle_fs_list(&mut self, params: Option<Value>) -> IpcResult<Value> {
        let p: FsListParams = parse_params(params)?;
        let facts = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: true,
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::FsList(p))
            .await
    }

    async fn handle_fs_stat(&mut self, params: Option<Value>) -> IpcResult<Value> {
        let p: FsStatParams = parse_params(params)?;
        let facts = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: true,
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::FsStat(p))
            .await
    }

    async fn handle_fs_read(&mut self, params: Option<Value>) -> IpcResult<Value> {
        let p: FsReadParams = parse_params(params)?;
        let facts = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: true,
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::FsRead(p))
            .await
    }

    async fn handle_fs_write(&mut self, params: Option<Value>) -> IpcResult<Value> {
        let p: FsWriteParams = parse_params(params)?;
        let facts = OperationFacts {
            capability: "filesystem.write".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: true,
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::FsWrite(p))
            .await
    }

    async fn handle_fs_delete(&mut self, params: Option<Value>) -> IpcResult<Value> {
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
        self.gate_and_run(facts, key, PendingRequest::FsDelete(p))
            .await
    }

    async fn handle_logs_query(&mut self, params: Option<Value>) -> IpcResult<Value> {
        let p: LogsQueryParams = parse_params(params)?;
        let facts = OperationFacts {
            capability: "logs.read".into(),
            kind: "logs".into(),
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::LogsQuery(p))
            .await
    }

    fn handle_logs_list_providers(&self, params: Option<Value>) -> IpcResult<Value> {
        let p: LogsQueryParams = parse_params(params.or_else(|| Some(json!({}))))?;
        let reg = self.build_log_registry(&p);
        Ok(json!({ "providers": reg.list_ids() }))
    }

    async fn handle_git_status(&mut self, params: Option<Value>) -> IpcResult<Value> {
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
        self.gate_and_run(facts, key, PendingRequest::GitStatus(p))
            .await
    }

    async fn handle_git_diff(&mut self, params: Option<Value>) -> IpcResult<Value> {
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
        self.gate_and_run(facts, key, PendingRequest::GitDiff(p))
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

    async fn handle_approval_approve(&mut self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            #[serde(default)]
            grant_seconds: Option<i64>,
            #[serde(default)]
            temporary_grant: bool,
        }
        let p: P = parse_params(params)?;
        let rec = self
            .approvals
            .get_mut(&p.id)
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("approval not found: {}", p.id),
            })?;
        if rec.state != "pending" {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!("approval already {}", rec.state),
            });
        }
        let request = rec.request.clone();
        let capability = rec.capability.clone();
        let operation_id = rec.operation_id.clone();
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

        rec.state = "approved".into();
        rec.decided_at_unix = Some(Self::now());

        if p.temporary_grant {
            let secs = p.grant_seconds.unwrap_or(DEFAULT_GRANT_SECS);
            let grant = TemporaryGrant {
                id: Self::new_id("grant_"),
                capability: capability.clone(),
                principal_id: LOCAL_PRINCIPAL.into(),
                expires_unix: Self::now().saturating_add(secs),
                path_prefix: None,
            };
            self.grants.push(grant);
            self.persist_grants();
        }

        let result = self.execute_request(&request).await?;
        let body = json!({
            "approval_required": false,
            "operation_id": operation_id,
            "approval_id": p.id,
            "result": result,
            "replayed": false,
            "decision": "allow",
            "reason": "human approved",
        });
        if let Some(rec) = self.approvals.get_mut(&p.id) {
            rec.result = Some(body.clone());
        }
        self.store_idempotent(idem_key.as_ref(), &body);
        self.append_audit(
            "approval.approved",
            Some(&capability),
            Some(&operation_id),
            Some("allow"),
            format!("approved {}", p.id),
        );
        Ok(body)
    }

    fn handle_approval_deny(&mut self, params: Option<Value>) -> IpcResult<Value> {
        let id = require_id(params, "id")?;
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
        rec.state = "denied".into();
        rec.decided_at_unix = Some(Self::now());
        let operation_id = rec.operation_id.clone();
        let capability = rec.capability.clone();
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
        self.policy = preset_document(preset);
        self.enforce_workspace = matches!(
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
        let verdict = self.evaluate(&facts);
        Ok(json!({
            "facts": facts,
            "decision": decision_str(verdict.decision),
            "matched_rule_id": verdict.matched_rule_id,
            "reason": verdict.reason,
            "lockdown": self.lockdown,
        }))
    }

    fn handle_lockdown(&mut self) -> IpcResult<Value> {
        self.lockdown = true;
        self.persist_lockdown();
        self.append_audit("daemon.lockdown", None, None, Some("deny"), "lockdown on");
        Ok(json!({ "lockdown": true }))
    }

    fn handle_unlock(&mut self) -> IpcResult<Value> {
        self.lockdown = false;
        self.persist_lockdown();
        self.append_audit("daemon.unlock", None, None, Some("allow"), "lockdown off");
        Ok(json!({ "lockdown": false }))
    }

    fn handle_token_revoke(&mut self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            client: String,
        }
        let p: P = parse_params(params)?;
        if p.client.trim().is_empty() {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "client is required".into(),
            });
        }
        self.revoked_clients.insert(p.client.clone());
        self.persist_revoked();
        self.append_audit(
            "token.revoke",
            None,
            None,
            Some("deny"),
            format!("revoked client {}", p.client),
        );
        Ok(json!({ "revoked": p.client, "ok": true }))
    }

    /// Dispatch one authenticated RPC method.
    pub async fn dispatch(&mut self, method: &str, params: Option<Value>) -> IpcResult<Value> {
        self.check_lockdown(method)?;
        match method {
            methods::OPS_EXEC => self.handle_exec(params).await,
            methods::OPS_FS_LIST => self.handle_fs_list(params).await,
            methods::OPS_FS_STAT => self.handle_fs_stat(params).await,
            methods::OPS_FS_READ => self.handle_fs_read(params).await,
            methods::OPS_FS_WRITE => self.handle_fs_write(params).await,
            methods::OPS_FS_DELETE => self.handle_fs_delete(params).await,
            methods::OPS_LOGS_QUERY => self.handle_logs_query(params).await,
            ops_methods::LOGS_LIST_PROVIDERS => self.handle_logs_list_providers(params),
            ops_methods::GIT_STATUS => self.handle_git_status(params).await,
            ops_methods::GIT_DIFF => self.handle_git_diff(params).await,
            methods::APPROVAL_LIST => self.handle_approval_list(),
            methods::APPROVAL_SHOW => self.handle_approval_show(params),
            methods::APPROVAL_APPROVE => self.handle_approval_approve(params).await,
            methods::APPROVAL_DENY => self.handle_approval_deny(params),
            methods::POLICY_SHOW => self.handle_policy_show(),
            methods::POLICY_PRESET => self.handle_policy_preset(params),
            methods::POLICY_VALIDATE => self.handle_policy_validate(),
            methods::POLICY_EXPLAIN => self.handle_policy_explain(params),
            methods::DAEMON_LOCKDOWN => self.handle_lockdown(),
            methods::DAEMON_UNLOCK => self.handle_unlock(),
            methods::TOKEN_REVOKE => self.handle_token_revoke(params),
            session_methods::OPEN => self.handle_session_open(params),
            session_methods::LIST => self.handle_session_list(),
            session_methods::SHOW => self.handle_session_show(params),
            session_methods::ATTACH => self.handle_session_attach(params),
            session_methods::CLAIM => self.handle_session_claim(params),
            session_methods::RELEASE => self.handle_session_release(params),
            session_methods::GIVE => self.handle_session_give(params),
            session_methods::CLOSE => self.handle_session_close(params),
            session_methods::TERMINATE => self.handle_session_terminate(params),
            session_methods::REPLAY => self.handle_session_replay(params),
            session_methods::PUSH_OUTPUT => self.handle_session_push_output(params),
            session_methods::WRITE => self.handle_session_write(params),
            session_methods::RESIZE => self.handle_session_resize(params),
            other => Err(IpcError::Remote {
                code: app_error::METHOD_NOT_FOUND,
                message: format!("method not found: {other}"),
            }),
        }
    }

    fn handle_session_open(&mut self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            #[serde(default)]
            title: Option<String>,
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
        let kind = match p.kind.as_deref() {
            Some("process") => SessionKind::Process,
            Some("profile_agent") | Some("profile") => SessionKind::ProfileAgent,
            _ => SessionKind::Pty,
        };
        let principal = p.principal.unwrap_or_else(|| LOCAL_PRINCIPAL.into());
        let title = p.title.unwrap_or_else(|| "session".into());
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
        self.persist_sessions();
        serde_json::to_value(info).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })
    }

    fn handle_session_list(&self) -> IpcResult<Value> {
        Ok(json!({ "sessions": self.sessions.list() }))
    }

    fn handle_session_show(&self, params: Option<Value>) -> IpcResult<Value> {
        let id = require_id(params, "id")?;
        let info = self.sessions.get(&id).map_err(session_err)?;
        serde_json::to_value(info).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })
    }

    fn handle_session_attach(&mut self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            #[serde(default)]
            principal: Option<String>,
            #[serde(default)]
            read_only: bool,
        }
        let p: P = parse_params(params)?;
        let principal = p.principal.unwrap_or_else(|| LOCAL_PRINCIPAL.into());
        if p.read_only {
            self.sessions
                .attach_observer(&p.id, principal.clone())
                .map_err(session_err)?;
        } else {
            let _ = self
                .sessions
                .claim_controller(&p.id, principal.clone(), Self::now())
                .map_err(session_err)?;
        }
        self.persist_sessions();
        let info = self.sessions.get(&p.id).map_err(session_err)?;
        Ok(json!({
            "session": info,
            "principal": principal,
            "read_only": p.read_only,
            "readers": self.sessions.readers(&p.id).map_err(session_err)?.into_iter().collect::<Vec<_>>(),
        }))
    }

    fn handle_session_claim(&mut self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            #[serde(default)]
            principal: Option<String>,
        }
        let p: P = parse_params(params)?;
        let principal = p.principal.unwrap_or_else(|| LOCAL_PRINCIPAL.into());
        let lease = self
            .sessions
            .claim_controller(&p.id, principal, Self::now())
            .map_err(session_err)?;
        self.persist_sessions();
        Ok(json!({ "lease": lease, "session_id": p.id }))
    }

    fn handle_session_release(&mut self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            #[serde(default)]
            principal: Option<String>,
        }
        let p: P = parse_params(params)?;
        let principal = p.principal.unwrap_or_else(|| LOCAL_PRINCIPAL.into());
        self.sessions
            .release_controller(&p.id, &principal)
            .map_err(session_err)?;
        self.persist_sessions();
        Ok(json!({ "released": true, "session_id": p.id }))
    }

    fn handle_session_give(&mut self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            to: String,
            #[serde(default)]
            from: Option<String>,
        }
        let p: P = parse_params(params)?;
        let from = p.from.unwrap_or_else(|| LOCAL_PRINCIPAL.into());
        let lease = self
            .sessions
            .give_controller(&p.id, &from, p.to, Self::now())
            .map_err(session_err)?;
        self.persist_sessions();
        let readers: Vec<String> = self
            .sessions
            .readers(&p.id)
            .map_err(session_err)?
            .into_iter()
            .collect();
        Ok(json!({ "lease": lease, "readers": readers }))
    }

    fn handle_session_close(&mut self, params: Option<Value>) -> IpcResult<Value> {
        let id = require_id(params, "id")?;
        self.sessions.close(&id).map_err(session_err)?;
        self.persist_sessions();
        Ok(json!({ "closed": true, "session_id": id }))
    }

    fn handle_session_terminate(&mut self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            #[serde(default)]
            id: Option<String>,
            #[serde(default)]
            all: bool,
        }
        let p: P = parse_params(params)?;
        if p.all {
            let n = self.sessions.terminate_all();
            self.persist_sessions();
            return Ok(json!({ "terminated": n, "all": true }));
        }
        let id = p.id.ok_or_else(|| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: "id or all required".into(),
        })?;
        self.sessions.terminate(&id).map_err(session_err)?;
        self.persist_sessions();
        Ok(json!({ "terminated": 1, "session_id": id }))
    }

    fn handle_session_replay(&self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            #[serde(default)]
            from_seq: Option<u64>,
            #[serde(default)]
            principal: Option<String>,
        }
        let p: P = parse_params(params)?;
        if let Some(prin) = p.principal {
            let readers = self.sessions.readers(&p.id).map_err(session_err)?;
            if !readers.contains(&prin) {
                return Err(IpcError::Remote {
                    code: app_error::POLICY_DENIED,
                    message: format!("principal {prin} cannot read session {}", p.id),
                });
            }
        }
        let chunks = self
            .sessions
            .replay_from(&p.id, p.from_seq.unwrap_or(1))
            .map_err(session_err)?;
        Ok(json!({ "chunks": chunks, "session_id": p.id }))
    }

    fn handle_session_push_output(&mut self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            data: String,
            #[serde(default)]
            stream: Option<String>,
        }
        let p: P = parse_params(params)?;
        let stream = match p.stream.as_deref() {
            Some("stderr") => SessionStreamKind::Stderr,
            Some("system") => SessionStreamKind::System,
            _ => SessionStreamKind::Stdout,
        };
        let chunk = self
            .sessions
            .push_output(&p.id, p.data, stream)
            .map_err(session_err)?;
        self.persist_sessions();
        Ok(json!({ "chunk": chunk }))
    }

    fn handle_session_write(&mut self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            data: String,
            #[serde(default)]
            principal: Option<String>,
        }
        let p: P = parse_params(params)?;
        let principal = p.principal.unwrap_or_else(|| LOCAL_PRINCIPAL.into());
        self.sessions
            .authorize_stdin(&p.id, &principal, Self::now())
            .map_err(session_err)?;
        // Record input echo for observers (controller write path).
        let chunk = self
            .sessions
            .push_output(
                &p.id,
                format!("[stdin] {}", p.data),
                SessionStreamKind::System,
            )
            .map_err(session_err)?;
        self.persist_sessions();
        Ok(json!({ "accepted": true, "chunk": chunk }))
    }

    fn handle_session_resize(&mut self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            cols: u16,
            rows: u16,
        }
        let p: P = parse_params(params)?;
        self.sessions
            .resize(&p.id, p.cols, p.rows)
            .map_err(session_err)?;
        self.persist_sessions();
        Ok(json!({ "resized": true, "cols": p.cols, "rows": p.rows }))
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
    pub fn is_lockdown(&self) -> bool {
        self.lockdown
    }
}

/// Build the IPC method handler backed by shared runtime state.
pub fn runtime_handler(runtime: Arc<Mutex<DaemonRuntime>>) -> MethodHandler {
    Arc::new(move |method, params| {
        let runtime = Arc::clone(&runtime);
        Box::pin(async move {
            let mut guard = runtime.lock().await;
            guard.dispatch(&method, params).await
        })
    })
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

fn load_broker_client(paths: &OwnMeshPaths) -> (Option<BrokerEndpoint>, Option<BrokerSecret>) {
    let secret_path = paths.state_dir.join("broker").join("broker.secret");
    if !secret_path.exists() {
        return (None, None);
    }
    let bytes = match std::fs::read(&secret_path) {
        Ok(b) if b.len() >= 32 => b,
        _ => return (None, None),
    };
    let endpoint = default_broker_endpoint(&paths.runtime_dir);
    // Optional override via addr file written by broker --addr-file.
    let addr_file = paths.state_dir.join("broker").join("broker.addr");
    let endpoint = if addr_file.exists() {
        std::fs::read_to_string(&addr_file)
            .ok()
            .and_then(|s| {
                let s = s.trim().to_string();
                s.parse::<std::net::SocketAddr>()
                    .ok()
                    .filter(|a| a.ip().is_loopback())
                    .map(BrokerEndpoint::LoopbackTcp)
            })
            .unwrap_or(endpoint)
    } else {
        endpoint
    };
    (Some(endpoint), Some(BrokerSecret::from_bytes(bytes)))
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

fn load_json_map(path: &Path) -> HashMap<String, Value> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn load_grants(path: &Path) -> Vec<TemporaryGrant> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn load_revoked(path: &Path) -> HashSet<String> {
    let list: Vec<String> = std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default();
    list.into_iter().collect()
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let raw = serde_json::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, raw)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}
