//! Strict, local-only IPC contract for the persistent session supervisor.
//!
//! The server accepts only the daemon's dedicated rotating credential for host
//! mutation. OS peer custody and the owner-only durable credential registry are
//! enforced by `ownmesh-ipc`; this module additionally binds every operation to
//! the exact manifest nonce and controller epoch.

use crate::{HostIoMode, HostManifest, SupervisorBinding, SupervisorState};
use ownmesh_ipc::{
    app_error, current_os_user_id, AuthGate, BootstrapStatus, ClientIdentity, ClientOptions,
    CredentialSecretResult, Endpoint, IpcBus, IpcClient, IpcError, IpcResult, IpcServer,
    MethodHandler, ServerConfig,
};
use ownmesh_session::{PtyCommand, PtySize};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Stable server-managed client id reserved for `ownmeshd`'s supervisor proxy.
pub const SUPERVISOR_DAEMON_CLIENT_ID: &str = "ownmeshd-session-supervisor";
const SUPERVISOR_DAEMON_PRINCIPAL: &str = "client:ownmeshd-session-supervisor";
const MAX_COMMAND_ARGS: usize = 64;
const MAX_COMMAND_ENV: usize = 64;
const MAX_COMPONENT_BYTES: usize = 4096;
const MAX_DRAIN_BYTES: usize = 1024 * 1024;

/// Bounded PTY spawn facts supplied only by the credentialed daemon proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorSpawnRequest {
    pub session_id: String,
    pub device_id: String,
    pub workspace_id: String,
    pub owner_principal: String,
    pub controller_epoch: u64,
    pub binding_expires_unix: i64,
    pub host_expires_unix: i64,
    pub command: SupervisorCommand,
    pub cols: u16,
    pub rows: u16,
    #[serde(default)]
    pub io_mode: HostIoMode,
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub adapter_dialect: Option<String>,
}

/// Serializable bounded command description for local IPC only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorCommand {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub env: Vec<SupervisorEnv>,
}

/// One bounded environment overlay entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorEnv {
    pub key: String,
    pub value: String,
}

/// Dedicated credentialed client used by exactly one `ownmeshd` instance.
pub struct SupervisorClient {
    client: IpcClient,
}

impl SupervisorClient {
    /// Provision a fresh credential, revoking the previous daemon instance.
    pub async fn bootstrap(
        endpoint: Endpoint,
        runtime_dir: impl Into<PathBuf>,
        management_credential: impl Into<String>,
    ) -> IpcResult<Self> {
        let runtime_dir = runtime_dir.into();
        let management = IpcClient::new(
            endpoint.clone(),
            runtime_dir.clone(),
            ClientIdentity::new("ownmeshd-supervisor-bootstrap", env!("CARGO_PKG_VERSION")),
            ClientOptions {
                max_reconnect_attempts: 4,
                ..ClientOptions::default()
            },
        )
        .with_client_credential(management_credential);
        // Restart path is rotate-first so a still-running predecessor loses
        // its exact daemon credential before this process receives a client.
        // First install has no active record and is the only provision fallback.
        let rotate_params = Some(json!({"client_id": SUPERVISOR_DAEMON_CLIENT_ID}));
        let issued_value = match management
            .call(ownmesh_ipc::methods::CREDENTIAL_ROTATE, rotate_params)
            .await
        {
            Ok(value) => value,
            Err(IpcError::Remote { code, message })
                if (code == app_error::UNAUTHORIZED || code == app_error::CONFLICT)
                    && message.contains("no active credential") =>
            {
                management
                    .call(
                        ownmesh_ipc::methods::CREDENTIAL_PROVISION,
                        Some(json!({"client_id": SUPERVISOR_DAEMON_CLIENT_ID})),
                    )
                    .await?
            }
            Err(error) => return Err(error),
        };
        let issued: CredentialSecretResult = serde_json::from_value(issued_value)?;
        Ok(Self {
            client: IpcClient::new(
                endpoint,
                runtime_dir,
                ClientIdentity::new("ownmeshd-session-proxy", env!("CARGO_PKG_VERSION")),
                ClientOptions {
                    max_reconnect_attempts: 4,
                    ..ClientOptions::default()
                },
            )
            .with_client_credential(issued.credential),
        })
    }

    pub async fn spawn(&self, request: SupervisorSpawnRequest) -> IpcResult<SupervisorBinding> {
        Ok(serde_json::from_value(
            self.client
                .call(SupervisorRpcMethods::SPAWN, Some(json!(request)))
                .await?,
        )?)
    }
    pub async fn status(&self, binding: &SupervisorBinding) -> IpcResult<crate::SupervisorStatus> {
        Ok(serde_json::from_value(
            self.client
                .call(SupervisorRpcMethods::STATUS, Some(json!(binding)))
                .await?,
        )?)
    }
    pub async fn write(&self, binding: &SupervisorBinding, bytes: Vec<u8>) -> IpcResult<()> {
        self.client
            .call(
                SupervisorRpcMethods::WRITE,
                Some(json!({"binding":binding,"bytes":bytes})),
            )
            .await?;
        Ok(())
    }
    pub async fn resize(&self, binding: &SupervisorBinding, cols: u16, rows: u16) -> IpcResult<()> {
        self.client
            .call(
                SupervisorRpcMethods::RESIZE,
                Some(json!({"binding":binding,"cols":cols,"rows":rows})),
            )
            .await?;
        Ok(())
    }
    pub async fn drain(
        &self,
        binding: &SupervisorBinding,
        offset: u64,
        max_bytes: usize,
    ) -> IpcResult<crate::SpoolPage> {
        self.drain_stream(binding, offset, max_bytes, "stdout")
            .await
    }

    /// Drain exactly one durable stream.  `stderr` is separate from the
    /// structured protocol stream and cannot be folded into its cursor.
    pub async fn drain_stream(
        &self,
        binding: &SupervisorBinding,
        offset: u64,
        max_bytes: usize,
        stream: &str,
    ) -> IpcResult<crate::SpoolPage> {
        if !matches!(stream, "stdout" | "stderr") {
            return Err(ownmesh_ipc::IpcError::Protocol(
                "invalid supervisor drain stream".into(),
            ));
        }
        Ok(serde_json::from_value(
            self.client
                .call(
                    SupervisorRpcMethods::DRAIN,
                    Some(json!({"binding":binding,"offset":offset,"max_bytes":max_bytes,"stream":stream})),
                )
                .await?,
        )?)
    }
    pub async fn rotate(
        &self,
        binding: &SupervisorBinding,
        owner_principal: String,
        controller_epoch: u64,
        binding_expires_unix: i64,
        transition_id: String,
    ) -> IpcResult<SupervisorBinding> {
        Ok(serde_json::from_value(
            self.client
                .call(
                    SupervisorRpcMethods::ROTATE,
                    Some(json!({"binding":binding,"owner_principal":owner_principal,"controller_epoch":controller_epoch,"binding_expires_unix":binding_expires_unix,"transition_id":transition_id})),
                )
                .await?,
        )?)
    }
    pub async fn reclaim(
        &self,
        binding: &SupervisorBinding,
        owner_principal: String,
        controller_epoch: u64,
        binding_expires_unix: i64,
        transition_id: String,
    ) -> IpcResult<SupervisorBinding> {
        Ok(serde_json::from_value(
            self.client
                .call(
                    SupervisorRpcMethods::RECLAIM,
                    Some(json!({"binding":binding,"owner_principal":owner_principal,"controller_epoch":controller_epoch,"binding_expires_unix":binding_expires_unix,"transition_id":transition_id})),
                )
                .await?,
        )?)
    }
    pub async fn detach(
        &self,
        binding: &SupervisorBinding,
        controller_epoch: u64,
        transition_id: String,
    ) -> IpcResult<SupervisorBinding> {
        Ok(serde_json::from_value(self.client.call(SupervisorRpcMethods::DETACH, Some(json!({"binding":binding,"controller_epoch":controller_epoch,"transition_id":transition_id}))).await?)?)
    }
    pub async fn claim(
        &self,
        binding: &SupervisorBinding,
        owner_principal: String,
        controller_epoch: u64,
        binding_expires_unix: i64,
        transition_id: String,
    ) -> IpcResult<SupervisorBinding> {
        Ok(serde_json::from_value(self.client.call(SupervisorRpcMethods::CLAIM, Some(json!({"binding":binding,"owner_principal":owner_principal,"controller_epoch":controller_epoch,"binding_expires_unix":binding_expires_unix,"transition_id":transition_id}))).await?)?)
    }
    pub async fn renew(
        &self,
        binding: &SupervisorBinding,
        binding_expires_unix: i64,
        transition_id: String,
    ) -> IpcResult<SupervisorBinding> {
        Ok(serde_json::from_value(self.client.call(SupervisorRpcMethods::RENEW, Some(json!({"binding":binding,"binding_expires_unix":binding_expires_unix,"transition_id":transition_id}))).await?)?)
    }
    pub async fn terminate(
        &self,
        binding: &SupervisorBinding,
        transition_id: String,
    ) -> IpcResult<()> {
        self.client
            .call(
                SupervisorRpcMethods::TERMINATE,
                Some(json!({"binding":binding,"transition_id":transition_id})),
            )
            .await?;
        Ok(())
    }
}

/// Local RPC method names. They are deliberately absent from public MCP.
pub struct SupervisorRpcMethods;
impl SupervisorRpcMethods {
    pub const SPAWN: &'static str = "session_supervisor.spawn";
    pub const STATUS: &'static str = "session_supervisor.status";
    pub const WRITE: &'static str = "session_supervisor.write";
    pub const RESIZE: &'static str = "session_supervisor.resize";
    pub const DRAIN: &'static str = "session_supervisor.drain";
    pub const TERMINATE: &'static str = "session_supervisor.terminate";
    pub const REATTACH: &'static str = "session_supervisor.reattach";
    /// CAS recovery for a binding that has expired but whose PTY TTL has not.
    pub const RECLAIM: &'static str = "session_supervisor.reclaim";
    pub const ROTATE: &'static str = "session_supervisor.rotate";
    pub const DETACH: &'static str = "session_supervisor.detach";
    pub const CLAIM: &'static str = "session_supervisor.claim";
    pub const RENEW: &'static str = "session_supervisor.renew";
}

/// Owns the local IPC server and state registry location.
pub struct SupervisorIpcServer {
    server: Arc<IpcServer>,
    pub state: Arc<SupervisorState>,
    credential_state_dir: PathBuf,
}

impl SupervisorIpcServer {
    /// Build a local-only supervisor endpoint and strict daemon credential gate.
    pub fn new(
        state_dir: impl AsRef<Path>,
        runtime_dir: impl AsRef<Path>,
    ) -> IpcResult<(Self, BootstrapStatus)> {
        let credential_state_dir = state_dir.as_ref().join("session-supervisor-credentials");
        let (auth, bootstrap) =
            AuthGate::for_user(current_os_user_id()).with_daemon_registry(&credential_state_dir)?;
        let state = Arc::new(SupervisorState::new(state_dir));
        let endpoint = Endpoint::default_for(runtime_dir.as_ref(), IpcBus::SessionSupervisor);
        let handler = supervisor_handler(Arc::clone(&state));
        let server = Arc::new(IpcServer::new(
            ServerConfig::new(
                endpoint,
                auth,
                "ownmesh-session-supervisor",
                env!("CARGO_PKG_VERSION"),
            ),
            handler,
        ));
        Ok((
            Self {
                server,
                state,
                credential_state_dir,
            },
            bootstrap,
        ))
    }

    #[must_use]
    pub fn server(&self) -> &Arc<IpcServer> {
        &self.server
    }

    /// Resolved per-user local endpoint (socket or named pipe).
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.server.config().endpoint
    }

    /// Owner-only durable management credential delivery directory.
    #[must_use]
    pub fn credential_state_dir(&self) -> &Path {
        &self.credential_state_dir
    }

    /// Serve the local endpoint and periodically apply only hard host-TTL
    /// cleanup. Controller binding expiry is deliberately not a process kill.
    pub async fn serve(self) -> IpcResult<()> {
        let state = Arc::clone(&self.state);
        let sweep = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                interval.tick().await;
                let _ = state.sweep_expired().await;
            }
        });
        let result = self.server.serve().await;
        sweep.abort();
        result
    }
}

fn supervisor_handler(state: Arc<SupervisorState>) -> MethodHandler {
    Arc::new(move |method, params, identity| {
        let state = Arc::clone(&state);
        Box::pin(async move {
            if identity.principal_key() != SUPERVISOR_DAEMON_PRINCIPAL {
                return Err(IpcError::Unauthorized(
                    "session supervisor requires dedicated ownmeshd credential".into(),
                ));
            }
            dispatch(&state, &method, params).await
        })
    })
}

#[allow(clippy::too_many_lines)]
async fn dispatch(
    state: &SupervisorState,
    method: &str,
    params: Option<Value>,
) -> IpcResult<Value> {
    match method {
        SupervisorRpcMethods::SPAWN => {
            let params: SupervisorSpawnRequest = parse(params)?;
            validate_spawn(&params)?;
            let mut manifest = HostManifest::new(
                params.session_id,
                params.device_id,
                params.workspace_id,
                params.owner_principal,
                params.controller_epoch,
                params.binding_expires_unix,
                params.host_expires_unix,
            )
            .map_err(invalid)?;
            manifest.io_mode = params.io_mode;
            manifest.profile_id.clone_from(&params.profile_id);
            manifest.adapter_dialect.clone_from(&params.adapter_dialect);
            let binding = state
                .spawn_with_io(
                    manifest,
                    params.command.into_command(),
                    PtySize {
                        cols: params.cols,
                        rows: params.rows,
                    },
                    params.io_mode,
                )
                .await
                .map_err(invalid)?;
            Ok(json!(binding))
        }
        SupervisorRpcMethods::STATUS | SupervisorRpcMethods::REATTACH => {
            let binding: SupervisorBinding = parse(params)?;
            Ok(json!(state.reattach(&binding).await.map_err(invalid)?))
        }
        SupervisorRpcMethods::WRITE => {
            let params: WriteParams = parse(params)?;
            if params.bytes.len() > 64 * 1024 {
                return Err(invalid("supervisor stdin frame exceeds budget"));
            }
            state
                .write(&params.binding, &params.bytes)
                .await
                .map_err(invalid)?;
            Ok(json!({"ok": true}))
        }
        SupervisorRpcMethods::RESIZE => {
            let params: ResizeParams = parse(params)?;
            state
                .resize(&params.binding, params.cols, params.rows)
                .await
                .map_err(invalid)?;
            Ok(json!({"ok": true}))
        }
        SupervisorRpcMethods::DRAIN => {
            let params: DrainParams = parse(params)?;
            if params.max_bytes == 0 || params.max_bytes > MAX_DRAIN_BYTES {
                return Err(invalid("invalid supervisor drain budget"));
            }
            let stderr = match params.stream.as_deref() {
                None | Some("stdout") => false,
                Some("stderr") => true,
                _ => return Err(invalid("invalid supervisor drain stream")),
            };
            Ok(json!(state
                .drain(&params.binding, params.offset, params.max_bytes, stderr)
                .await
                .map_err(invalid)?))
        }
        SupervisorRpcMethods::TERMINATE => {
            let params: TerminateParams = parse(params)?;
            require_transition_id(&params.transition_id)?;
            let digest = digest_value(json!({"binding":params.binding}))?;
            state
                .terminate_idempotent(&params.binding, &params.transition_id, &digest)
                .await
                .map_err(invalid)?;
            Ok(json!({"ok": true}))
        }
        SupervisorRpcMethods::ROTATE => {
            let params: RotateParams = parse(params)?;
            require_component(&params.owner_principal, "owner_principal")?;
            require_transition_id(&params.transition_id)?;
            let digest = transition_digest(&params)?;
            let binding = state
                .rotate_binding_idempotent(
                    &params.binding,
                    params.owner_principal,
                    params.controller_epoch,
                    params.binding_expires_unix,
                    &params.transition_id,
                    &digest,
                )
                .await
                .map_err(invalid)?;
            Ok(json!(binding))
        }
        SupervisorRpcMethods::RECLAIM => {
            let params: RotateParams = parse(params)?;
            require_component(&params.owner_principal, "owner_principal")?;
            require_transition_id(&params.transition_id)?;
            let digest = transition_digest(&params)?;
            let binding = state
                .reclaim_idempotent(
                    &params.binding,
                    params.owner_principal,
                    params.controller_epoch,
                    params.binding_expires_unix,
                    &params.transition_id,
                    &digest,
                )
                .await
                .map_err(invalid)?;
            Ok(json!(binding))
        }
        SupervisorRpcMethods::DETACH => {
            let params: DetachParams = parse(params)?;
            require_transition_id(&params.transition_id)?;
            let digest = digest_value(
                json!({"binding":params.binding,"controller_epoch":params.controller_epoch}),
            )?;
            let binding = state
                .detach_idempotent(
                    &params.binding,
                    params.controller_epoch,
                    &params.transition_id,
                    &digest,
                )
                .await
                .map_err(invalid)?;
            Ok(json!(binding))
        }
        SupervisorRpcMethods::CLAIM => {
            let params: RotateParams = parse(params)?;
            require_component(&params.owner_principal, "owner_principal")?;
            require_transition_id(&params.transition_id)?;
            let digest = transition_digest(&params)?;
            let binding = state
                .claim_idempotent(
                    &params.binding,
                    params.owner_principal,
                    params.controller_epoch,
                    params.binding_expires_unix,
                    &params.transition_id,
                    &digest,
                )
                .await
                .map_err(invalid)?;
            Ok(json!(binding))
        }
        SupervisorRpcMethods::RENEW => {
            let params: RenewParams = parse(params)?;
            require_transition_id(&params.transition_id)?;
            let digest = digest_value(
                json!({"binding":params.binding,"binding_expires_unix":params.binding_expires_unix}),
            )?;
            let binding = state
                .renew_idempotent(
                    &params.binding,
                    params.binding_expires_unix,
                    &params.transition_id,
                    &digest,
                )
                .await
                .map_err(invalid)?;
            Ok(json!(binding))
        }
        _ => Err(IpcError::Remote {
            code: app_error::METHOD_NOT_FOUND,
            message: "unknown session supervisor method".into(),
        }),
    }
}

fn parse<T: serde::de::DeserializeOwned>(params: Option<Value>) -> IpcResult<T> {
    let value = params.ok_or_else(|| invalid("session supervisor params are required"))?;
    serde_json::from_value(value)
        .map_err(|error| invalid(format!("invalid session supervisor params: {error}")))
}
fn invalid(message: impl Into<String>) -> IpcError {
    IpcError::Remote {
        code: app_error::INVALID_PARAMS,
        message: message.into(),
    }
}
fn require_component(value: &str, field: &str) -> IpcResult<()> {
    if value.is_empty() || value.len() > MAX_COMPONENT_BYTES || value.chars().any(char::is_control)
    {
        return Err(invalid(format!("invalid supervisor {field}")));
    }
    Ok(())
}
fn validate_spawn(params: &SupervisorSpawnRequest) -> IpcResult<()> {
    for (field, value) in [
        ("session_id", &params.session_id),
        ("device_id", &params.device_id),
        ("workspace_id", &params.workspace_id),
        ("owner_principal", &params.owner_principal),
        ("program", &params.command.program),
    ] {
        require_component(value, field)?;
    }
    if params.command.args.len() > MAX_COMMAND_ARGS
        || params.command.env.len() > MAX_COMMAND_ENV
        || params.cols == 0
        || params.rows == 0
        || params.cols > 512
        || params.rows > 512
    {
        return Err(invalid("supervisor spawn exceeds bounds"));
    }
    for value in params.command.args.iter().chain(
        params
            .command
            .env
            .iter()
            .flat_map(|pair| [&pair.key, &pair.value]),
    ) {
        require_component(value, "command component")?;
    }
    if let Some(cwd) = &params.command.cwd {
        require_component(cwd, "cwd")?;
    }
    if matches!(params.io_mode, HostIoMode::StructuredPipes) {
        require_component(params.profile_id.as_deref().unwrap_or(""), "profile_id")?;
        require_component(
            params.adapter_dialect.as_deref().unwrap_or(""),
            "adapter_dialect",
        )?;
    }
    Ok(())
}

fn require_transition_id(value: &str) -> IpcResult<()> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(invalid("invalid supervisor transition id"));
    }
    Ok(())
}

fn transition_digest(params: &RotateParams) -> IpcResult<String> {
    // Digest is derived by the authenticated sidecar from the exact parsed
    // request; callers never get to supply an idempotency payload digest.
    digest_value(json!({
        "binding": params.binding,
        "owner_principal": params.owner_principal,
        "controller_epoch": params.controller_epoch,
        "binding_expires_unix": params.binding_expires_unix,
    }))
}
fn digest_value(value: Value) -> IpcResult<String> {
    let bytes = serde_json::to_vec(&value)
        .map_err(|err| invalid(format!("encode supervisor transition: {err}")))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

impl SupervisorCommand {
    fn into_command(self) -> PtyCommand {
        PtyCommand {
            program: self.program,
            args: self.args,
            cwd: self.cwd,
            env: self
                .env
                .into_iter()
                .map(|pair| (pair.key, pair.value))
                .collect(),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteParams {
    binding: SupervisorBinding,
    bytes: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResizeParams {
    binding: SupervisorBinding,
    cols: u16,
    rows: u16,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainParams {
    binding: SupervisorBinding,
    offset: u64,
    max_bytes: usize,
    #[serde(default)]
    stream: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateParams {
    binding: SupervisorBinding,
    owner_principal: String,
    controller_epoch: u64,
    binding_expires_unix: i64,
    transition_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetachParams {
    binding: SupervisorBinding,
    controller_epoch: u64,
    transition_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewParams {
    binding: SupervisorBinding,
    binding_expires_unix: i64,
    transition_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminateParams {
    binding: SupervisorBinding,
    transition_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ownmesh_ipc::{
        methods, read_management_credential, ClientIdentity, ClientOptions, CredentialSecretResult,
        IpcClient,
    };
    use std::time::Duration;
    use tempfile::tempdir;

    fn client(endpoint: Endpoint, runtime: &Path, credential: Option<String>) -> IpcClient {
        let client = IpcClient::new(
            endpoint,
            runtime,
            ClientIdentity::new("untrusted-label", "test"),
            ClientOptions {
                max_reconnect_attempts: 0,
                request_timeout: Duration::from_secs(2),
                ..ClientOptions::default()
            },
        );
        match credential {
            Some(credential) => client.with_client_credential(credential),
            None => client,
        }
    }

    #[tokio::test]
    async fn strict_daemon_credential_and_nonce_binding_are_enforced() {
        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let runtime = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        let (supervisor, _) = SupervisorIpcServer::new(&state_dir, &runtime).unwrap();
        let endpoint = supervisor.server().config().endpoint.clone();
        let server = Arc::clone(supervisor.server());
        let task = tokio::spawn(async move { server.serve().await.unwrap() });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let plain = client(endpoint.clone(), &runtime, None);
        assert!(plain
            .call(SupervisorRpcMethods::SPAWN, Some(spawn_params()))
            .await
            .is_err());
        let management_secret =
            read_management_credential(supervisor.credential_state_dir()).unwrap();
        let management = client(endpoint.clone(), &runtime, Some(management_secret));
        let issued: CredentialSecretResult = serde_json::from_value(
            management
                .call(
                    methods::CREDENTIAL_PROVISION,
                    Some(json!({"client_id": SUPERVISOR_DAEMON_CLIENT_ID})),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        let daemon = client(endpoint.clone(), &runtime, Some(issued.credential.clone()));
        let binding: SupervisorBinding = serde_json::from_value(
            daemon
                .call(SupervisorRpcMethods::SPAWN, Some(spawn_params()))
                .await
                .unwrap(),
        )
        .unwrap();
        let mut stale = binding.clone();
        stale.host_nonce = "host_stale".into();
        assert!(daemon
            .call(SupervisorRpcMethods::STATUS, Some(json!(stale)))
            .await
            .is_err());
        daemon
            .call(SupervisorRpcMethods::STATUS, Some(json!(binding)))
            .await
            .unwrap();
        let rotated: CredentialSecretResult = serde_json::from_value(
            management
                .call(
                    methods::CREDENTIAL_ROTATE,
                    Some(json!({"client_id": SUPERVISOR_DAEMON_CLIENT_ID})),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        let old = client(endpoint.clone(), &runtime, Some(issued.credential));
        assert!(old
            .call(SupervisorRpcMethods::STATUS, Some(json!(binding)))
            .await
            .is_err());
        let new_daemon = client(endpoint, &runtime, Some(rotated.credential));
        new_daemon
            .call(
                SupervisorRpcMethods::TERMINATE,
                Some(json!({"binding":binding,"transition_id":"terminate-ipc"})),
            )
            .await
            .unwrap();
        supervisor.server().request_shutdown();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn bootstrap_rotates_predecessor_daemon_credential() {
        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let runtime = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        let (supervisor, _) = SupervisorIpcServer::new(&state_dir, &runtime).unwrap();
        let endpoint = supervisor.endpoint().clone();
        let server = Arc::clone(supervisor.server());
        let task = tokio::spawn(async move { server.serve().await.unwrap() });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let management = read_management_credential(supervisor.credential_state_dir()).unwrap();
        let first =
            SupervisorClient::bootstrap(endpoint.clone(), runtime.clone(), management.clone())
                .await
                .unwrap();
        let request: SupervisorSpawnRequest = serde_json::from_value(spawn_params()).unwrap();
        let binding = first.spawn(request).await.unwrap();
        let second = SupervisorClient::bootstrap(endpoint, runtime, management)
            .await
            .unwrap();
        assert!(
            first.status(&binding).await.is_err(),
            "restart must revoke old daemon credential"
        );
        second.status(&binding).await.unwrap();
        second
            .terminate(&binding, "terminate-bootstrap".into())
            .await
            .unwrap();
        supervisor.server().request_shutdown();
        task.await.unwrap();
    }

    fn spawn_params() -> Value {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        json!({"session_id":"ses_ipc", "device_id":"dev", "workspace_id":"ws", "owner_principal":"owner", "controller_epoch":1, "binding_expires_unix":now + 60, "host_expires_unix":now + 600, "command":{"program":if cfg!(windows) {"cmd.exe"} else {"/bin/sh"}, "args":[], "cwd":null, "env":[]}, "cols":80, "rows":24})
    }
}
