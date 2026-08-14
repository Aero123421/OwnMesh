//! Interactive session lifecycle handlers for [`DaemonRuntime`].
//!
//! Split out of `runtime.rs`: open/attach/claim/renew/detach/release/give/
//! close/terminate/replay/write/resize form one state machine over the session
//! registry and its PTY hosts, and reviewing that machine should not require
//! paging through unrelated filesystem, transfer, and policy code.
//!
//! Behavior is unchanged; only the file boundary moved. This is a child module
//! of `runtime`, so it reaches `DaemonRuntime`'s private state directly, and
//! handlers are `pub(super)` because the dispatch table lives in the parent.

use super::{
    app_error, base64_standard, default_shell_command, fs_err, is_remote_runtime_principal, json,
    normalize_handoff_target, official_adapter_spec, parse_adapter_event_page, parse_params,
    persistent_child_is_live, preset_name, reject_spoofed_principal, session_err, sha256_hex,
    AdapterDialect, ClientIdentity, DaemonRuntime, Deserialize, HostIoMode, IpcError, IpcResult,
    LiveHost, NativeResume, OperationFacts, Path, ProfileRegistry, PtyCommand, PtySize,
    SessionKind, SessionState, SessionStreamKind, SidecarHostBinding, SupervisorCommand,
    SupervisorEnv, SupervisorSpawnRequest, SystemDiagnoseParams, TransitionKind, TransitionPhase,
    TransitionRecord, TransitionTarget, Value,
};

/// Structured sidecar pages are capped below the durable MCP result budget.
/// Both semantic replay and explicit raw diagnostics advance with the same
/// independent byte cursor, so larger transcripts remain fully pageable.
const MAX_STRUCTURED_SIDECAR_PAGE_BYTES: usize = 48 * 1024;

impl DaemonRuntime {
    pub(super) async fn handle_system_diagnose(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let mut p: SystemDiagnoseParams = parse_params(params)?;
        let workspace_id = match p.workspace_id.as_deref() {
            Some(_) => {
                let workspace_id = Self::canonical_workspace_id(p.workspace_id.as_deref())?;
                if !self.workspaces.iter().any(|workspace| {
                    workspace.id == workspace_id
                        || (workspace_id == "ws_default" && workspace.id == "default")
                }) {
                    return Err(IpcError::Remote {
                        code: app_error::INVALID_PARAMS,
                        message: "requested workspace is not registered on this device".into(),
                    });
                }
                Some(workspace_id)
            }
            None => None,
        };
        p.workspace_id.clone_from(&workspace_id);
        let facts = OperationFacts {
            capability: "system.diagnose".into(),
            kind: "metadata".into(),
            workspace_relative: workspace_id.is_some(),
            workspace_id,
            ..Default::default()
        };
        // This read-only observation is bound to the remote operation itself;
        // it never reserves the local side-effect idempotency journal.
        self.gate_and_run(
            facts,
            None,
            super::PendingRequest::SystemDiagnose(p),
            client,
        )
        .await
    }

    pub(super) async fn execute_system_diagnose(
        &self,
        params: &SystemDiagnoseParams,
    ) -> IpcResult<Value> {
        let observed_at = ownmesh_domain::Timestamp::now().to_rfc3339();
        let now = Self::now();
        let sessions = self.sessions.list();
        let nonterminal_sessions = sessions
            .iter()
            .filter(|session| session.state != SessionState::Closed)
            .count();
        let registry_stale_sessions = sessions
            .iter()
            .filter(|session| {
                session.state == SessionState::Starting
                    || (session.state != SessionState::Closed
                        && session
                            .sidecar_host
                            .as_ref()
                            .is_some_and(|binding| binding.host_expires_unix <= now))
            })
            .count();
        let live_sidecars = sessions
            .iter()
            .filter_map(|session| {
                (session.state != SessionState::Closed)
                    .then_some(session.sidecar_host.as_ref())
                    .flatten()
                    .filter(|binding| binding.host_expires_unix > now)
                    .map(|binding| {
                        (
                            session.id.as_str(),
                            binding,
                            session.state == SessionState::Starting,
                        )
                    })
            })
            .collect::<Vec<_>>();
        let supervisor_required = !live_sidecars.is_empty();
        let (supervisor_available, supervisor_host_stale) = match self.supervisor.as_ref() {
            _ if !supervisor_required => (true, 0),
            None => (false, 0),
            Some(supervisor) => {
                let probe = async {
                    let mut stale = 0;
                    for (session_id, binding, already_stale) in live_sidecars {
                        match supervisor
                            .status(&super::supervisor_binding_from(session_id, binding))
                            .await
                        {
                            Ok(status) if status.exited && !already_stale => stale += 1,
                            // A typed server reply proves the supervisor is reachable;
                            // failure to find/match this live binding makes the registry stale.
                            Err(IpcError::Remote { .. }) if !already_stale => stale += 1,
                            Ok(_) | Err(IpcError::Remote { .. }) => {}
                            Err(_) => return None,
                        }
                    }
                    Some(stale)
                };
                // Keep the typed health probe inside the Control Plane's bounded
                // one-call wait. Healthy local supervisor IPC completes promptly;
                // a slow or wedged supervisor is itself the unavailable result.
                match tokio::time::timeout(std::time::Duration::from_millis(250), probe).await {
                    Ok(Some(stale)) => (true, stale),
                    Ok(None) | Err(_) => (false, 0),
                }
            }
        };
        let stale_sessions = registry_stale_sessions + supervisor_host_stale;
        Ok(system_diagnosis_payload(
            &observed_at,
            SystemDiagnosisFacts {
                lockdown: self.lockdown,
                workspace_state: workspace_diagnosis_state(
                    params.workspace_id.is_some(),
                    self.enforce_workspace,
                ),
                supervisor_required,
                supervisor_available,
                session_count: sessions.len(),
                nonterminal_sessions,
                stale_sessions,
            },
        ))
    }

    pub(super) async fn handle_session_open(
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
        // Own a live PTY for interactive sessions (E5) and profile PTY fallback (E6).
        // Process-only kinds stay metadata until structured adapters stream events.
        // Failure to spawn is fail-closed so ChatGPT never sees a fake echo-only session.
        let spawn_live = matches!(kind, SessionKind::Pty | SessionKind::ProfileAgent);
        // A remote persistent session cannot be owned safely without the
        // device identity authenticated by Agent transport. Check this before
        // inserting session metadata: otherwise a rejected launch is visible
        // as a `running` session for the lifetime of this daemon.
        let remote_device_id = if spawn_live && is_remote_runtime_principal(&client.client_name) {
            Some(
                self.active_remote_device_id
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| IpcError::Remote {
                        code: app_error::UNAUTHORIZED,
                        message: "remote session.open requires verified Agent device identity"
                            .into(),
                    })?
                    .to_owned(),
            )
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
                let device_id = remote_device_id
                    .clone()
                    .expect("remote persistent session identity checked before metadata insert");
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
                let binding = match self.ensure_remote_supervisor().await {
                    Ok(supervisor) => match supervisor.spawn(request).await {
                        Ok(binding) => binding,
                        Err(err) => {
                            self.sessions = snapshot;
                            return Err(IpcError::Remote {
                                code: app_error::CONFLICT,
                                message: format!("persistent session sidecar spawn failed: {err}"),
                            });
                        }
                    },
                    Err(err) => {
                        self.sessions = snapshot;
                        return Err(err);
                    }
                };
                // A successful spawn is already an externally visible side
                // effect. Persist its exact binding before any further RPC so
                // a lost status/bootstrap reply cannot turn a live child into
                // an untracked `running` session. `starting` deliberately
                // tells callers that child identity is still being attested.
                let provisional = SidecarHostBinding {
                    device_id: device_id.clone(),
                    workspace_id: workspace_id.clone(),
                    owner_principal: client.client_name.clone(),
                    host_nonce: binding.host_nonce.clone(),
                    controller_epoch: binding.controller_epoch,
                    binding_expires_unix: lease.expires_unix,
                    host_expires_unix: Self::now().saturating_add(24 * 60 * 60),
                    child_pid: None,
                    child_process_birth: None,
                };
                if let Err(err) = self
                    .sessions
                    .set_sidecar_host_binding(&info.id, Some(provisional))
                {
                    let _ = self
                        .rollback_persistent_open(&info.id, &binding, "binding")
                        .await;
                    self.sessions = snapshot;
                    return Err(session_err(err));
                }
                if let Err(err) = self
                    .sessions
                    .set_state(&info.id, ownmesh_session::SessionState::Starting)
                {
                    let _ = self
                        .rollback_persistent_open(&info.id, &binding, "starting")
                        .await;
                    self.sessions = snapshot;
                    return Err(session_err(err));
                }
                if let Err(err) = self.commit_sessions(snapshot) {
                    // `commit_sessions` restored `snapshot`; cleanup is still
                    // attempted, but a storage failure cannot safely retain a
                    // durable record. Return the persistence error rather
                    // than claiming that the child was rolled back.
                    if let Some(proxy) = self.supervisor.as_ref() {
                        let _ = proxy
                            .terminate(&binding, format!("open-rollback:{}:persist", info.id))
                            .await;
                    }
                    return Err(err);
                }
                let status = match self
                    .supervisor
                    .as_ref()
                    .expect("successful persistent sidecar spawn retains supervisor client")
                    .status(&binding)
                    .await
                {
                    Ok(status) => status,
                    Err(err) => {
                        let _ = self
                            .rollback_persistent_open(&info.id, &binding, "status")
                            .await;
                        return Err(IpcError::Remote {
                            code: app_error::CONFLICT,
                            message: format!("persistent session sidecar status failed: {err}"),
                        });
                    }
                };
                let (child_pid, child_process_birth) = match (status.pid, status.process_birth_id) {
                    (Some(pid), Some(birth)) if !status.exited => (pid, birth),
                    _ => {
                        let _ = self
                            .rollback_persistent_open(&info.id, &binding, "identity")
                            .await;
                        return Err(IpcError::Remote {
                            code: app_error::CONFLICT,
                            message: "persistent session sidecar did not attest a live child process identity".into(),
                        });
                    }
                };
                let durable_snapshot = self.sessions.clone();
                if let Err(err) = self.sessions.set_host_pid(&info.id, Some(child_pid)) {
                    let _ = self
                        .rollback_persistent_open(&info.id, &binding, "host-pid")
                        .await;
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
                    child_pid: Some(child_pid),
                    child_process_birth: Some(child_process_birth),
                };
                if let Err(err) = self
                    .sessions
                    .set_sidecar_host_binding(&info.id, Some(durable))
                {
                    let _ = self
                        .rollback_persistent_open(&info.id, &binding, "durable-binding")
                        .await;
                    return Err(session_err(err));
                }
                if let Err(err) = self
                    .sessions
                    .set_state(&info.id, ownmesh_session::SessionState::Running)
                {
                    let _ = self
                        .rollback_persistent_open(&info.id, &binding, "running")
                        .await;
                    return Err(session_err(err));
                }
                // On persistence failure `commit_sessions` restores the
                // already-persisted provisional record, not the pre-spawn
                // snapshot, so the child remains recoverable.
                self.commit_sessions(durable_snapshot)?;
                if let Some((_, dialect)) = structured_adapter {
                    // The successful spawn above installed the authenticated
                    // supervisor client. Do not re-run global reattachment
                    // here: an unrelated stale session must not strand this
                    // newly created child before its metadata is committed.
                    let supervisor = self
                        .supervisor
                        .as_ref()
                        .expect("successful persistent sidecar spawn retains supervisor client");
                    let native_id = match Self::bootstrap_structured_adapter(
                        supervisor,
                        &binding,
                        dialect,
                        p.prompt.as_deref(),
                        driver_native_session_id.as_deref(),
                        // `cwd` is always resolved from the selected workspace
                        // before the session record is created.
                        cwd.as_deref()
                            .expect("session workspace always resolves an absolute cwd"),
                    )
                    .await
                    {
                        Ok(native_id) => native_id,
                        Err(error) => {
                            let _ = self
                                .rollback_persistent_open(&info.id, &binding, "structured")
                                .await;
                            return Err(error);
                        }
                    };
                    if let Some(native_id) = native_id {
                        let native_snapshot = self.sessions.clone();
                        if let Err(error) = self.sessions.set_native_session_id(&info.id, native_id)
                        {
                            let _ = self
                                .rollback_persistent_open(&info.id, &binding, "native-id")
                                .await;
                            return Err(session_err(error));
                        }
                        if let Err(error) = self.commit_sessions(native_snapshot) {
                            let _ = self
                                .rollback_persistent_open(&info.id, &binding, "native-persist")
                                .await;
                            return Err(error);
                        }
                    }
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

    pub(super) fn handle_session_list(
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
        self.reconcile_dead_persistent_sessions()?;
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

    pub(super) fn handle_session_show(
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

    pub(super) fn handle_session_attach(
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

    pub(super) async fn handle_session_claim(
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
                child_pid: old_binding.child_pid,
                child_process_birth: old_binding.child_process_birth,
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

    pub(super) fn handle_session_release(
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
    pub(super) async fn handle_session_renew(
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
                child_pid: old_binding.child_pid,
                child_process_birth: old_binding.child_process_birth,
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
    pub(super) async fn handle_session_detach(
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
                child_pid: old_binding.child_pid,
                child_process_birth: old_binding.child_process_birth,
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

    pub(super) async fn handle_session_give(
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
                child_pid: old_binding.child_pid,
                child_process_birth: old_binding.child_process_birth,
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

    /// A failed supervisor RPC is not proof that its child died.  We only
    /// reconcile a terminal request when the durable child PID is proven gone;
    /// a live or indeterminate PID remains actionable instead of being hidden
    /// behind a false terminal session state.
    pub(super) fn reconcile_terminal_after_supervisor_failure(
        &mut self,
        session_id: &str,
        terminal: TransitionKind,
    ) -> IpcResult<bool> {
        debug_assert!(matches!(
            terminal,
            TransitionKind::Close | TransitionKind::Terminate
        ));
        let binding = self
            .sessions
            .get(session_id)
            .map_err(session_err)?
            .sidecar_host
            .clone()
            .ok_or_else(|| IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!(
                    "persistent session supervisor unavailable; session {session_id} has no durable child identity to reconcile safely"
                ),
            })?;
        if persistent_child_is_live(&binding).map_err(|error| IpcError::Remote {
            code: app_error::CONFLICT,
            message: format!(
                "persistent session supervisor unavailable; unable to verify child identity: {error}"
            ),
        })? {
            Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "persistent session supervisor unavailable; authenticated child is still alive, refusing PID-only termination".into(),
            })
        } else {
            let snapshot = self.sessions.clone();
            match terminal {
                TransitionKind::Close => {
                    self.sessions.close(session_id).map_err(session_err)?;
                    self.sessions
                        .set_sidecar_host_binding(session_id, None)
                        .map_err(session_err)?;
                    self.sessions
                        .set_host_pid(session_id, None)
                        .map_err(session_err)?;
                }
                TransitionKind::Terminate => {
                    self.sessions.terminate(session_id).map_err(session_err)?;
                }
                _ => unreachable!("terminal reconciliation only accepts close/terminate"),
            }
            self.commit_sessions(snapshot)?;
            Ok(true)
        }
    }

    /// Roll back an already-persisted persistent open only after the
    /// supervisor acknowledged termination. The supervisor writes a durable
    /// termination receipt before replying, so a failed RPC leaves the
    /// `starting`/`running` record and its exact binding available for later
    /// reconciliation instead of hiding a possibly live child.
    async fn rollback_persistent_open(
        &mut self,
        session_id: &str,
        binding: &super::SupervisorBinding,
        stage: &str,
    ) -> IpcResult<()> {
        // Make an uncertain cleanup visible before attempting the side effect.
        // If the terminate RPC is lost, this durable `starting` record and its
        // binding are reconciled later instead of masquerading as a usable
        // running session.
        let snapshot = self.sessions.clone();
        self.sessions
            .set_state(session_id, ownmesh_session::SessionState::Starting)
            .map_err(session_err)?;
        self.commit_sessions(snapshot)?;
        let proxy = self.supervisor.as_ref().ok_or_else(|| IpcError::Remote {
            code: app_error::CONFLICT,
            message: format!(
                "persistent session open failed during {stage}; supervisor is unavailable and cleanup is pending"
            ),
        })?;
        proxy
            .terminate(binding, format!("open-rollback:{session_id}:{stage}"))
            .await
            .map_err(|error| IpcError::Remote {
                code: app_error::CONFLICT,
                message: format!(
                    "persistent session open failed during {stage}; supervisor termination was not acknowledged: {error}"
                ),
            })?;
        self.close_persistent_session_record(session_id)
    }

    pub(super) async fn handle_session_close(
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
            let binding = self.verified_sidecar_binding_from(&p.id, &old_binding)?;
            if self.ensure_remote_supervisor().await.is_err() {
                self.reconcile_terminal_after_supervisor_failure(&p.id, TransitionKind::Close)?;
                return Ok(json!({
                    "closed": true,
                    "reconciled": true,
                    "session_id": p.id,
                    "workspace_id": bound_ws,
                }));
            }
            // Reattachment may have just completed cleanup of an interrupted
            // open. Treat the caller's retry as the same successful close;
            // issuing a second transition id against its tombstone would be a
            // false conflict.
            match self.sessions.get(&p.id) {
                Ok(current) if current.sidecar_host.is_none() => {
                    return Ok(json!({
                        "closed": true,
                        "reconciled": true,
                        "session_id": p.id,
                        "workspace_id": bound_ws,
                    }));
                }
                Err(ownmesh_session::SessionError::NotFound) => {
                    return Ok(json!({
                        "closed": true,
                        "reconciled": true,
                        "session_id": p.id,
                        "workspace_id": bound_ws,
                    }));
                }
                Ok(_) => {}
                Err(error) => return Err(session_err(error)),
            }
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

    pub(super) async fn handle_session_terminate(
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
            let binding = self.verified_sidecar_binding_from(&id, &old_binding)?;
            if self.ensure_remote_supervisor().await.is_err() {
                self.reconcile_terminal_after_supervisor_failure(&id, TransitionKind::Terminate)?;
                return Ok(json!({
                    "terminated": 1,
                    "reconciled": true,
                    "session_id": id,
                    "workspace_id": bound_ws,
                }));
            }
            // Interrupted-open recovery may have acknowledged termination and
            // closed this row while reconnecting the supervisor. Complete the
            // requested removal locally instead of sending a different
            // transition id to the existing termination receipt.
            match self.sessions.get(&id) {
                Ok(current) if current.sidecar_host.is_none() => {
                    let recovered_snapshot = self.sessions.clone();
                    self.sessions.terminate(&id).map_err(session_err)?;
                    self.commit_sessions(recovered_snapshot)?;
                    return Ok(json!({
                        "terminated": 1,
                        "reconciled": true,
                        "session_id": id,
                        "workspace_id": bound_ws,
                    }));
                }
                Err(ownmesh_session::SessionError::NotFound) => {
                    return Ok(json!({
                        "terminated": 1,
                        "reconciled": true,
                        "session_id": id,
                        "workspace_id": bound_ws,
                    }));
                }
                Ok(_) => {}
                Err(error) => return Err(session_err(error)),
            }
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

    pub(super) async fn handle_session_replay(
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
            /// Return the raw sidecar page for explicit diagnostics only.
            #[serde(default)]
            raw_sidecar: bool,
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
                .min(ownmesh_session::MAX_REPLAY_PAGE_BYTES)
                .min(MAX_STRUCTURED_SIDECAR_PAGE_BYTES);
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
        if p.raw_sidecar {
            let sidecar_truncated = sidecar_page
                .as_ref()
                .map(|page| page.truncated)
                .unwrap_or(false);
            return Ok(json!({
                "session_id": p.id,
                "raw_sidecar": true,
                "truncated": sidecar_truncated,
                "sidecar_bytes_encoding": sidecar_page.as_ref().map(|_| "base64"),
                "sidecar_bytes_base64": sidecar_page.as_ref().map(|page| base64_standard(&page.bytes)),
                "sidecar_next_cursor": sidecar_page.as_ref().and_then(|page| page.next_offset),
                "sidecar_total_bytes": sidecar_page.as_ref().map(|page| page.total_bytes),
            }));
        }
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
        // Structured profiles additionally expose a bounded, normalized view
        // over the exact raw sidecar spool cursor. Raw bytes remain local to
        // the sidecar; callers receive only the bounded normalized view and
        // an explicit continuation cursor. Malformed vendor output becomes an
        // explicit adapter error rather than disappearing into a terminal.
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
            "sidecar_next_cursor": sidecar_next_cursor,
            "sidecar_total_bytes": sidecar_total_bytes,
            "profile_events": profile_events.as_ref().map(|page| &page.events),
            "profile_event_cursor": profile_event_cursor,
            "profile_event_truncated": profile_event_truncated,
        }))
    }

    pub(super) fn handle_session_push_output(
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

    pub(super) async fn handle_session_write(
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

    pub(super) async fn handle_session_resize(
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
}

#[derive(Debug, Clone, Copy)]
struct SystemDiagnosisFacts {
    lockdown: bool,
    workspace_state: &'static str,
    supervisor_required: bool,
    supervisor_available: bool,
    session_count: usize,
    nonterminal_sessions: usize,
    stale_sessions: usize,
}

fn workspace_diagnosis_state(bound: bool, enforce_workspace: bool) -> &'static str {
    match (bound, enforce_workspace) {
        (true, true) => "bound_enforced",
        (true, false) => "bound_full_access",
        (false, true) => "unbound_enforced",
        (false, false) => "unbound_full_access",
    }
}

fn system_diagnosis_payload(observed_at: &str, facts: SystemDiagnosisFacts) -> Value {
    let supervisor_state = if !facts.supervisor_required {
        "not_required"
    } else if facts.supervisor_available {
        "available"
    } else {
        "unavailable"
    };
    let overall = if facts.lockdown {
        "lockdown"
    } else if supervisor_state == "unavailable" {
        "supervisor_unavailable"
    } else if facts.stale_sessions > 0 {
        "stale_sessions"
    } else if facts.workspace_state == "unbound_enforced" {
        "workspace_selection_required"
    } else {
        "healthy"
    };
    let recommendation = match overall {
        "lockdown" => "unlock_locally",
        "supervisor_unavailable" => "restart_session_supervisor",
        "stale_sessions" => "reconcile_stale_sessions",
        "workspace_selection_required" => "select_workspace",
        _ => "none",
    };
    json!({
        "schema": "ownmesh.system_diagnosis/1.0",
        "overall": overall,
        "observed_at": observed_at,
        "agent": {
            "version": env!("CARGO_PKG_VERSION"),
            "protocol_version": ownmesh_protocol::PROTOCOL_DEVICE_V1,
            "provenance": "observed",
            "observed_at": observed_at,
        },
        "checks": [
            {
                "id": "policy", "status": "pass", "state": "allow",
                "provenance": "authoritative", "observed_at": observed_at,
            },
            {
                "id": "workspace",
                "status": if facts.workspace_state == "unbound_enforced" { "warn" } else { "pass" },
                "state": facts.workspace_state,
                "provenance": "authoritative", "observed_at": observed_at,
            },
            {
                "id": "daemon",
                "status": if facts.lockdown { "warn" } else { "pass" },
                "state": if facts.lockdown { "lockdown" } else { "running" },
                "provenance": "observed", "observed_at": observed_at,
            },
            {
                "id": "session_supervisor",
                "status": if supervisor_state == "unavailable" { "fail" } else { "pass" },
                "state": supervisor_state,
                "provenance": "observed", "observed_at": observed_at,
            },
            {
                "id": "sessions",
                "status": if facts.stale_sessions > 0 { "warn" } else { "pass" },
                "state": if facts.stale_sessions > 0 { "stale" } else { "healthy" },
                "provenance": "authoritative", "observed_at": observed_at,
                "count": facts.session_count,
                "nonterminal_count": facts.nonterminal_sessions,
                "stale_count": facts.stale_sessions,
            },
        ],
        "recommendation": recommendation,
    })
}

#[cfg(test)]
mod system_diagnosis_tests {
    use super::{system_diagnosis_payload, workspace_diagnosis_state, SystemDiagnosisFacts};

    #[test]
    fn workspace_diagnosis_is_a_fixed_redacted_boundary_state() {
        assert_eq!(workspace_diagnosis_state(true, true), "bound_enforced");
        assert_eq!(workspace_diagnosis_state(true, false), "bound_full_access");
        assert_eq!(workspace_diagnosis_state(false, true), "unbound_enforced");
        assert_eq!(
            workspace_diagnosis_state(false, false),
            "unbound_full_access"
        );
    }

    #[test]
    fn common_device_local_states_are_typed_and_redacted() {
        let cases = [
            (
                SystemDiagnosisFacts {
                    lockdown: false,
                    workspace_state: "bound_enforced",
                    supervisor_required: false,
                    supervisor_available: true,
                    session_count: 0,
                    nonterminal_sessions: 0,
                    stale_sessions: 0,
                },
                "healthy",
                "none",
            ),
            (
                SystemDiagnosisFacts {
                    lockdown: false,
                    workspace_state: "bound_full_access",
                    supervisor_required: true,
                    supervisor_available: false,
                    session_count: 1,
                    nonterminal_sessions: 1,
                    stale_sessions: 0,
                },
                "supervisor_unavailable",
                "restart_session_supervisor",
            ),
            (
                SystemDiagnosisFacts {
                    lockdown: false,
                    workspace_state: "unbound_full_access",
                    supervisor_required: false,
                    supervisor_available: true,
                    session_count: 1,
                    nonterminal_sessions: 1,
                    stale_sessions: 1,
                },
                "stale_sessions",
                "reconcile_stale_sessions",
            ),
            (
                SystemDiagnosisFacts {
                    lockdown: false,
                    workspace_state: "unbound_enforced",
                    supervisor_required: false,
                    supervisor_available: true,
                    session_count: 0,
                    nonterminal_sessions: 0,
                    stale_sessions: 0,
                },
                "workspace_selection_required",
                "select_workspace",
            ),
        ];
        for (facts, overall, recommendation) in cases {
            let value = system_diagnosis_payload("2026-08-13T00:00:00Z", facts);
            assert_eq!(value["overall"], overall);
            assert_eq!(value["recommendation"], recommendation);
            assert_eq!(value["checks"].as_array().map(Vec::len), Some(5));
            let serialized = value.to_string();
            for forbidden in [
                "credential",
                "command",
                "argv",
                "environment",
                "cwd",
                "path",
            ] {
                assert!(
                    !serialized.contains(forbidden),
                    "leaked forbidden field: {serialized}"
                );
            }
        }
    }
}
