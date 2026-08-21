//! Windows-specific privileged-broker daemon trust boundary.
//!
//! This module intentionally contains no process spawn or pipe accept loop.
//! It turns a root/Admin-custodied installation record plus kernel-attested
//! named-pipe facts into an authorization decision.  The later pipe handler
//! must call [`WindowsTrustedDaemon::authorize_peer`] immediately after its
//! first frame and again immediately before staging/spawning an action.

use ownmesh_broker_client::{
    operation_facts_digest, parse_broker_wire_intent_v2, verify_cancel_intent_v2_message_auth,
    verify_capability_v2, verify_execute_intent_v2_message_auth, BrokerRequestV2, BrokerResponseV2,
    BrokerSecret, BrokerWireIntentV2, CapabilitySigningKey, CapabilityTokenV2, CapabilityVerifyKey,
    PeerProcessBindV2, MAX_BROKER_REQUEST_BYTES,
};
use ownmesh_ipc::{windows_running_service_facts, WindowsPipePeerFacts};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

const MAX_TRUST_RECORD_BYTES: u64 = 64 * 1024;
/// Bound all accepted pipe handlers, including clients which never finish a
/// frame. One slot is deliberately held back from execution so an authenticated
/// Cancel can still reach a running Job at saturation.
const MAX_WINDOWS_BROKER_CONNECTIONS: usize = 16;
const MAX_WINDOWS_EXECUTE_CONCURRENCY: usize = MAX_WINDOWS_BROKER_CONNECTIONS - 1;
const WINDOWS_RESPONSE_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Marker for the normal current-user OwnMesh agent. Unlike the broker, this
/// process is intentionally not an SCM service; its TokenUser SID and immutable
/// Program Files image are the authority.
pub(crate) const WINDOWS_USER_AGENT_TRUST: &str = "OwnMeshUserAgent";

/// Immutable fields recorded by the elevated installer after it has copied the
/// daemon image into the Admin-controlled installation root. `image_file_id`
/// and `image_sha256` are hex encodings of the Windows FILE_ID_128 and SHA-256
/// from that exact installed image, never caller-supplied command fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WindowsDaemonTrustRecord {
    /// Canonical Windows SID text (`S-1-...`) used only to construct and
    /// inspect the fixed named-pipe DACL.
    pub daemon_pipe_sid: String,
    /// Canonical TokenUser SID bytes rendered by `ownmesh-ipc` as
    /// `sid:<lowercase-hex>`. This is used only for peer comparison after
    /// pipe impersonation. Keeping it separate prevents an SDDL string from
    /// being compared to an unrelated textual representation.
    pub daemon_token_sid: String,
    pub daemon_service_name: String,
    pub daemon_session_id: u32,
    pub daemon_integrity_rid: u32,
    pub image_path: PathBuf,
    pub image_volume_serial: u64,
    pub image_file_id: String,
    pub image_sha256: String,
    /// Monotonically replaced by the native elevated installer when service
    /// configuration or the installed image changes. It is not trusted unless
    /// the containing custody file has passed platform ACL checks.
    pub service_config_generation: u64,
}

/// Parsed, validated record. Its private fields prevent a wire request from
/// manufacturing a trusted daemon identity.
#[derive(Debug, Clone)]
pub struct WindowsTrustedDaemon {
    record: WindowsDaemonTrustRecord,
    canonical_image: PathBuf,
    image_file_id: [u8; 16],
    image_sha256: [u8; 32],
}

/// Injected authorization boundary. Production uses [`WindowsTrustedDaemon`];
/// tests can use a narrow fake without turning synthetic JSON facts into an
/// authority source.
pub trait WindowsPeerAuthorizer: Send + Sync {
    fn authorize(&self, peer: &WindowsPipePeerFacts) -> Result<(), String>;
    fn reauthorize_before_spawn(&self, peer: &WindowsPipePeerFacts) -> Result<(), String>;
}

impl WindowsPeerAuthorizer for WindowsTrustedDaemon {
    fn authorize(&self, peer: &WindowsPipePeerFacts) -> Result<(), String> {
        self.authorize_peer(peer)
    }
    fn reauthorize_before_spawn(&self, peer: &WindowsPipePeerFacts) -> Result<(), String> {
        self.reauthorize_peer_before_spawn(peer)
    }
}

/// Durable nonce fence supplied by the Windows custody layer. A reservation is
/// made before the runner is invoked; a crash leaves it consumed.
pub trait WindowsReplayLedger: Send {
    fn reserve(&mut self, request: &BrokerRequestV2, now_unix: i64) -> Result<(), String>;
    fn mark_spawned(&mut self, nonce: &str, digest: &str) -> Result<(), String>;
    fn complete(&mut self, nonce: &str, digest: &str) -> Result<(), String>;
}

impl WindowsReplayLedger for crate::ReplayLedger {
    fn reserve(&mut self, request: &BrokerRequestV2, now_unix: i64) -> Result<(), String> {
        self.reserve_verified_request(request, now_unix)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
    fn mark_spawned(&mut self, nonce: &str, digest: &str) -> Result<(), String> {
        crate::ReplayLedger::mark_spawned(self, nonce, digest, None)
            .map_err(|error| error.to_string())
    }
    fn complete(&mut self, nonce: &str, digest: &str) -> Result<(), String> {
        self.mark_completed(nonce, digest)
            .map_err(|error| error.to_string())
    }
}

/// The Job Object/staging slice implements this trait. Keeping it injected
/// means this handler has no accidental `Command`/shell fallback.
pub trait WindowsBrokerRunner: Send + Sync {
    fn run(&self, request: &BrokerRequestV2) -> BrokerResponseV2;

    /// Signal a matching in-flight request. Implementations must bind both
    /// identifiers; a cancellation for another operation must never tear down
    /// the wrong elevated tree.
    fn cancel(&self, _request_id: &str, _nonce: &str) -> bool {
        false
    }

    /// Fence every in-flight request before the hosting SCM service exits.
    /// Production runners must make a later `run` observe this fence too, so
    /// a request which was accepted just as shutdown began cannot create an
    /// orphaned privileged process tree.
    fn cancel_all(&self) -> usize {
        0
    }
}

/// Dedicated Windows v2 data-plane handler. It is intentionally not reachable
/// from `run_broker` yet: elevated lifecycle must first prove the DACL custody
/// of its trust record, replay ledger, key material, and staged executable.
pub struct WindowsProductionBrokerServer<A, L, R> {
    listener: ownmesh_ipc::LocalListener,
    authorizer: Arc<A>,
    ledger: Arc<Mutex<L>>,
    runner: Arc<R>,
    secret: BrokerSecret,
    signing_key: CapabilitySigningKey,
    verify_key: CapabilityVerifyKey,
    broker_instance_id: String,
    broker_key_id: String,
    connection_concurrency: Arc<Semaphore>,
    execution_concurrency: Arc<Semaphore>,
    shutdown: watch::Sender<bool>,
}

impl<A, L, R> WindowsProductionBrokerServer<A, L, R>
where
    A: WindowsPeerAuthorizer + 'static,
    L: WindowsReplayLedger + 'static,
    R: WindowsBrokerRunner + 'static,
{
    /// Bind only the fixed pipe with its protected daemon/SYSTEM/Admin DACL.
    pub async fn bind(
        daemon_pipe_sid: &str,
        authorizer: A,
        ledger: L,
        runner: R,
        secret: BrokerSecret,
        signing_key: CapabilitySigningKey,
    ) -> Result<Self, String> {
        let listener = ownmesh_ipc::LocalListener::bind_secure_broker_pipe(daemon_pipe_sid)
            .await
            .map_err(|error| error.to_string())?;
        let verify_key = signing_key.verify_key();
        let broker_key_id = hex::encode(sha2::Sha256::digest(verify_key.to_bytes()));
        let broker_instance_id = hex::encode(sha2::Sha256::digest(
            [
                b"ownmesh.windows.broker.instance.v1\0".as_slice(),
                broker_key_id.as_bytes(),
            ]
            .concat(),
        ));
        let (shutdown, _) = watch::channel(false);
        Ok(Self {
            listener,
            authorizer: Arc::new(authorizer),
            ledger: Arc::new(Mutex::new(ledger)),
            runner: Arc::new(runner),
            secret,
            signing_key,
            verify_key,
            broker_instance_id,
            broker_key_id,
            connection_concurrency: Arc::new(Semaphore::new(MAX_WINDOWS_BROKER_CONNECTIONS)),
            execution_concurrency: Arc::new(Semaphore::new(MAX_WINDOWS_EXECUTE_CONCURRENCY)),
            shutdown,
        })
    }

    /// Accept exactly one client, apply the bounded handler, and write one
    /// bounded response. Callers may schedule this under their service loop.
    pub async fn serve_once(&self) -> Result<(), String> {
        let connection = self.accept_connection().await?;
        self.serve_connection(connection).await
    }

    /// Accept one connection without coupling its lifetime to the next
    /// accept.  The SCM loop must call [`Self::serve_connection`] in a
    /// separately owned task so an explicit Cancel pipe can be accepted while
    /// an Execute Job is still running.
    pub async fn accept_connection(&self) -> Result<ownmesh_ipc::ServerConnection, String> {
        self.listener
            .accept()
            .await
            .map_err(|error| error.to_string())
    }

    /// Handle a previously accepted connection under the bounded execution
    /// semaphore.  Keeping the connection owned by this future is essential:
    /// callers must never drop it merely to poll the SCM stop flag, because a
    /// dropped handler would detach the blocking Windows Job task.
    pub async fn serve_connection(
        &self,
        connection: ownmesh_ipc::ServerConnection,
    ) -> Result<(), String> {
        let permit = self.try_acquire_connection_permit()?;
        self.serve_connection_with_permit(connection, permit).await
    }

    /// Acquire a bounded admission slot before a connection becomes a handler
    /// task.  The service loop drops an over-capacity pipe immediately rather
    /// than creating an unbounded collection of tasks waiting to reply `busy`.
    pub(crate) fn try_acquire_connection_permit(&self) -> Result<OwnedSemaphorePermit, String> {
        self.connection_concurrency
            .clone()
            .try_acquire_owned()
            .map_err(|_| "Windows broker busy (bounded concurrency)".to_string())
    }

    /// Handle one already-admitted connection.  The caller keeps `permit`
    /// alive through the bounded response write: a peer which never reads a
    /// response cannot leave an unbounded set of pipe handles/tasks behind.
    pub(crate) async fn serve_connection_with_permit(
        &self,
        mut connection: ownmesh_ipc::ServerConnection,
        _permit: OwnedSemaphorePermit,
    ) -> Result<(), String> {
        let response = self.handle_connection(&mut connection).await;
        write_windows_response(&mut connection, &response).await
    }

    /// Begin a terminal SCM shutdown. This is intentionally one-way for a
    /// server instance: all active and racing runner calls are fenced before
    /// the service reports stopped.
    pub fn begin_shutdown(&self) -> usize {
        let _ = self.shutdown.send(true);
        self.runner.cancel_all()
    }

    async fn handle_connection(
        &self,
        connection: &mut ownmesh_ipc::ServerConnection,
    ) -> BrokerResponseV2 {
        let result = async {
            let bytes = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                read_windows_v2_frame(connection),
            )
            .await
            .map_err(|_| "Windows broker request frame timed out".to_string())??;
            let peer = connection
                .windows_pipe_peer_facts()
                .map_err(|error| error.to_string())?;
            self.authorizer.authorize(&peer)?;
            let intent = parse_broker_wire_intent_v2(&bytes).map_err(|error| error.to_string())?;
            match intent {
                BrokerWireIntentV2::Cancel(cancel) => {
                    verify_cancel_intent_v2_message_auth(&self.secret, &cancel, crate::now_unix())
                        .map_err(|error| error.to_string())?;
                    let request = BrokerRequestV2 {
                        protocol_version: cancel.protocol_version,
                        request_id: cancel.request_id.clone(),
                        operation_id: cancel.operation_id.clone(),
                        nonce: cancel.nonce.clone(),
                        issued_at_unix: cancel.issued_at_unix,
                        expires_at_unix: cancel.expires_at_unix,
                        facts: ownmesh_broker_client::OperationFactsV2 {
                            operation: "cancel".into(),
                            remote_payload_sha256: cancel.target_facts_digest.clone(),
                            principal_id: "windows-daemon".into(),
                            tenant_id: "windows".into(),
                            principal_credential_generation: 0,
                            timeout_ms: 1,
                            max_output_bytes: 1,
                            device_id: "windows".into(),
                            workspace_id: "windows".into(),
                            argv: vec!["cancel".into()],
                            canonical_cwd: None,
                            sanitized_env: BTreeMap::default(),
                            executable: ownmesh_broker_client::ExecutablePinV2 {
                                canonical_path: "cancel".into(),
                                image_sha256: "0".repeat(64),
                                image_len: 0,
                            },
                        },
                        capability: None,
                        mac: cancel.mac.clone(),
                    };
                    let digest = operation_facts_digest(&request.facts);
                    self.ledger
                        .lock()
                        .map_err(|_| "Windows replay ledger lock poisoned".to_string())?
                        .reserve(&request, crate::now_unix())?;
                    self.ledger
                        .lock()
                        .map_err(|_| "Windows replay ledger lock poisoned".to_string())?
                        .mark_spawned(&request.nonce, &digest)?;
                    let cancelled = self
                        .runner
                        .cancel(&cancel.target_request_id, &cancel.target_nonce);
                    self.ledger
                        .lock()
                        .map_err(|_| "Windows replay ledger lock poisoned".to_string())?
                        .complete(&request.nonce, &digest)?;
                    Ok(BrokerResponseV2 {
                        request_id: cancel.request_id,
                        ok: true,
                        exit_code: None,
                        stdout: String::new(),
                        stderr: String::new(),
                        error: None,
                        timed_out: false,
                        cancelled,
                        truncated: false,
                        duration_ms: 0,
                    })
                }
                BrokerWireIntentV2::Execute(execute) => {
                    verify_execute_intent_v2_message_auth(
                        &self.secret,
                        &execute,
                        crate::now_unix(),
                    )
                    .map_err(|error| error.to_string())?;
                    reject_windows_external_action(&execute.facts)?;
                    self.authorizer.reauthorize_before_spawn(&peer)?;
                    let external = execute.into_unprepared_request();
                    let peer_bind = windows_peer_bind(&peer)?;
                    let now = crate::now_unix();
                    let capability = CapabilityTokenV2::issue(
                        &self.signing_key,
                        &self.broker_instance_id,
                        &self.broker_key_id,
                        &external.facts.principal_id,
                        &external.operation_id,
                        &external.facts,
                        &external.nonce,
                        peer_bind.clone(),
                        now,
                        external.expires_at_unix.saturating_sub(now),
                    );
                    let mut internal = external;
                    internal.capability = Some(capability);
                    verify_capability_v2(
                        &self.verify_key,
                        &internal,
                        &self.broker_instance_id,
                        &self.broker_key_id,
                        &peer_bind,
                        now,
                    )
                    .map_err(|error| error.to_string())?;
                    // Preserve one of the 16 accepted-handler slots for a
                    // fenced Cancel connection. Without this separate limit,
                    // 16 long Jobs could make their own cancellation request
                    // fail admission before it reaches `runner.cancel`.
                    let _execution_permit = self
                        .execution_concurrency
                        .clone()
                        .try_acquire_owned()
                        .map_err(|_| "Windows broker execute capacity is full".to_string())?;
                    let digest = operation_facts_digest(&internal.facts);
                    self.ledger
                        .lock()
                        .map_err(|_| "Windows replay ledger lock poisoned".to_string())?
                        .reserve(&internal, now)?;
                    self.ledger
                        .lock()
                        .map_err(|_| "Windows replay ledger lock poisoned".to_string())?
                        .mark_spawned(&internal.nonce, &digest)?;
                    // A pipe connection is part of the authority boundary: the
                    // daemon must keep the exact, SCM-attested connection alive
                    // for the whole side effect.  Do not let a lost client leave
                    // a privileged Job running in the background.  The runner is
                    // invoked on the blocking pool because it owns synchronous
                    // Job Object handles while this task continues to observe EOF.
                    let mut response = self
                        .run_with_disconnect_cancellation(connection, internal.clone())
                        .await?;
                    if let Err(error) = self
                        .ledger
                        .lock()
                        .map_err(|_| "Windows replay ledger lock poisoned".to_string())?
                        .complete(&internal.nonce, &digest)
                    {
                        response.ok = false;
                        response.error = Some(format!(
                            "durable Windows replay ledger finalize failed: {error}"
                        ));
                    }
                    Ok(response)
                }
            }
        }
        .await;
        result.unwrap_or_else(|error: String| BrokerResponseV2 {
            request_id: "unknown".into(),
            ok: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            error: Some(error),
            timed_out: false,
            cancelled: false,
            truncated: false,
            duration_ms: 0,
        })
    }

    async fn run_with_disconnect_cancellation(
        &self,
        connection: &mut ownmesh_ipc::ServerConnection,
        request: BrokerRequestV2,
    ) -> Result<BrokerResponseV2, String> {
        let runner = Arc::clone(&self.runner);
        let request_for_runner = request.clone();
        let mut shutdown = self.shutdown.subscribe();
        if *shutdown.borrow() {
            // The caller reached a durably reserved request, but no Job was
            // started. Return an exact terminal receipt so the enclosing
            // handler can complete that reservation rather than leaving a
            // misleadingly uncertain replay entry behind during SCM stop.
            return Ok(BrokerResponseV2 {
                request_id: request.request_id,
                ok: false,
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                error: Some("Windows broker is stopping before Job execution".into()),
                timed_out: false,
                cancelled: true,
                truncated: false,
                duration_ms: 0,
            });
        }
        let mut execution = tokio::task::spawn_blocking(move || runner.run(&request_for_runner));
        let mut probe = [0_u8; 1];
        tokio::select! {
            result = &mut execution => result.map_err(|error| format!("Windows Job execution task failed: {error}")),
            changed = shutdown.changed() => {
                // `begin_shutdown` first fences the production runner's
                // current and future registrations. Await its terminal Job
                // receipt before allowing the service task to disappear.
                let _ = changed;
                let _ = self.runner.cancel(&request.request_id, &request.nonce);
                execution
                    .await
                    .map_err(|error| format!("Windows Job shutdown task failed: {error}"))
            }
            read = connection.read(&mut probe) => {
                // Treat EOF, a pipe reset/error, and an unexpected second byte
                // identically.  In particular, never propagate a read error
                // before fencing the active Job: ERROR_BROKEN_PIPE is an
                // attacker-controlled disconnect signal, not a safe early
                // return.
                let _disconnect = read.err();
                // A v2 connection is single-frame.  EOF is the normal loss of
                // custody signal; a second byte is an equally invalid protocol
                // transition and is fenced in exactly the same way.
                let cancelled = self.runner.cancel(&request.request_id, &request.nonce);
                let response = execution
                    .await
                    .map_err(|error| format!("Windows Job cancellation task failed: {error}"))?;
                // Return the runner receipt so the durable replay ledger is
                // finalized even though the caller can no longer receive it.
                // A subsequent same-nonce frame remains fenced by that ledger.
                // `cancel == false` is an allowed select race: the Job may
                // have completed just before this branch won.  Awaiting its
                // terminal response above still lets the caller finalize the
                // same durable replay reservation exactly once.
                let _ = cancelled;
                Ok(response)
            }
        }
    }
}

async fn read_windows_v2_frame(
    connection: &mut ownmesh_ipc::ServerConnection,
) -> Result<Vec<u8>, String> {
    let mut line = Vec::with_capacity(1024);
    let mut byte = [0_u8; 1];
    loop {
        let read = connection
            .read(&mut byte)
            .await
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("Windows broker peer disconnected before request".into());
        }
        if byte[0] == b'\n' {
            return Ok(line);
        }
        if line.len() >= MAX_BROKER_REQUEST_BYTES {
            return Err("Windows broker request exceeds byte limit".into());
        }
        line.push(byte[0]);
    }
}

async fn write_windows_response(
    connection: &mut ownmesh_ipc::ServerConnection,
    response: &BrokerResponseV2,
) -> Result<(), String> {
    let mut line = serde_json::to_vec(response).map_err(|error| error.to_string())?;
    line.push(b'\n');
    tokio::time::timeout(WINDOWS_RESPONSE_WRITE_TIMEOUT, async {
        connection.write_all(&line).await?;
        connection.flush().await
    })
    .await
    .map_err(|_| "Windows broker response write timed out".to_string())?
    .map_err(|error| error.to_string())
}

fn reject_windows_external_action(
    facts: &ownmesh_broker_client::OperationFactsV2,
) -> Result<(), String> {
    if facts.canonical_cwd.is_some() || !facts.sanitized_env.is_empty() || facts.argv.is_empty() {
        return Err(
            "Windows broker rejects caller cwd, environment, or empty argv (fail-closed)".into(),
        );
    }
    let first = facts.argv[0].to_ascii_lowercase();
    if [
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "sh",
        "bash",
    ]
    .contains(&first.as_str())
    {
        return Err("Windows broker rejects shell execution (fail-closed)".into());
    }
    Ok(())
}

fn windows_peer_bind(peer: &WindowsPipePeerFacts) -> Result<PeerProcessBindV2, String> {
    Ok(PeerProcessBindV2 {
        pid: i32::try_from(peer.pid()).map_err(|_| "Windows peer PID overflow")?,
        uid: 0,
        executable_path: peer.image_path().into(),
        process_birth_id: peer.creation_filetime(),
        image_identity: format!(
            "sid={};vol={};file={};sha256={}",
            peer.user_sid(),
            peer.image_volume_serial(),
            hex::encode(peer.image_file_id()),
            hex::encode(peer.image_sha256())
        ),
    })
}

impl WindowsTrustedDaemon {
    /// Validate an installer-provided record before accepting any pipe peer.
    /// The service/image custody file itself must be opened by the future
    /// elevated lifecycle code; this constructor only accepts its bounded bytes
    /// after the caller has completed that custody proof.
    pub fn from_record(record: WindowsDaemonTrustRecord) -> Result<Self, String> {
        let pipe_sid = parse_canonical_windows_sid(&record.daemon_pipe_sid)?;
        let token_sid = parse_canonical_token_sid(&record.daemon_token_sid)?;
        if pipe_sid != token_sid {
            return Err("Windows daemon pipe SID and TokenUser SID differ (fail-closed)".into());
        }
        if record.daemon_service_name != WINDOWS_USER_AGENT_TRUST {
            validate_service_name(&record.daemon_service_name)?;
        }
        if record.daemon_integrity_rid == 0 {
            return Err("Windows daemon integrity RID must be explicit (fail-closed)".into());
        }
        if record.service_config_generation == 0 {
            return Err(
                "Windows daemon service config generation must be nonzero (fail-closed)".into(),
            );
        }
        let canonical_image = std::fs::canonicalize(&record.image_path).map_err(|error| {
            format!(
                "canonicalize trusted Windows daemon image {}: {error}",
                record.image_path.display()
            )
        })?;
        let metadata =
            std::fs::symlink_metadata(&canonical_image).map_err(|error| error.to_string())?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(
                "trusted Windows daemon image must be a regular non-reparse file (fail-closed)"
                    .into(),
            );
        }
        let image_file_id = decode_fixed_hex::<16>(&record.image_file_id, "image_file_id")?;
        let image_sha256 = decode_fixed_hex::<32>(&record.image_sha256, "image_sha256")?;
        Ok(Self {
            record,
            canonical_image,
            image_file_id,
            image_sha256,
        })
    }

    #[must_use]
    pub fn record(&self) -> &WindowsDaemonTrustRecord {
        &self.record
    }

    /// Authorize a connected pipe peer using only OS-derived facts.  The SCM
    /// must say the configured daemon service is running at the exact peer PID;
    /// the configured command image, held process image, file identity, and
    /// digest must each equal the elevated installation record.
    pub fn authorize_peer(&self, peer: &WindowsPipePeerFacts) -> Result<(), String> {
        if peer.user_sid() != self.record.daemon_token_sid {
            return Err("named-pipe peer SID differs from trusted daemon SID (fail-closed)".into());
        }
        let integrity_matches = if self.record.daemon_service_name == WINDOWS_USER_AGENT_TRUST {
            peer.integrity_rid() >= self.record.daemon_integrity_rid
                && peer.integrity_rid() <= 0x3000
        } else {
            peer.integrity_rid() == self.record.daemon_integrity_rid
        };
        if (self.record.daemon_service_name != WINDOWS_USER_AGENT_TRUST
            && peer.session_id() != self.record.daemon_session_id)
            || !integrity_matches
        {
            return Err(
                "named-pipe peer session or integrity differs from trust record (fail-closed)"
                    .into(),
            );
        }
        self.authorize_process(
            peer.pid(),
            peer.image_path(),
            peer.image_volume_serial(),
            peer.image_file_id(),
            peer.image_sha256(),
            peer.creation_filetime(),
            peer,
        )
    }

    /// Re-run all mutable checks immediately before staging/spawn. Keeping this
    /// distinct from accept-time authorization makes PID reuse and live image
    /// replacement an explicit denial rather than a stale snapshot.
    pub fn reauthorize_peer_before_spawn(&self, peer: &WindowsPipePeerFacts) -> Result<(), String> {
        self.authorize_peer(peer)
    }

    fn authorize_process(
        &self,
        pid: u32,
        image_path: &str,
        volume_serial: u64,
        file_id: [u8; 16],
        image_sha256: [u8; 32],
        creation_filetime: u64,
        peer: &WindowsPipePeerFacts,
    ) -> Result<(), String> {
        if pid == 0 || creation_filetime == 0 {
            return Err("named-pipe peer PID/birth is missing (fail-closed)".into());
        }
        if self.record.daemon_service_name != WINDOWS_USER_AGENT_TRUST {
            let service = windows_running_service_facts(&self.record.daemon_service_name, pid)
                .map_err(|error| format!("trusted daemon SCM identity failed: {error}"))?;
            let service_image = extract_service_image(service.binary_command_line())?;
            let service_image = std::fs::canonicalize(service_image)
                .map_err(|error| format!("canonicalize SCM daemon image: {error}"))?;
            if !same_windows_path(&service_image, &self.canonical_image) {
                return Err("trusted daemon SCM image differs from the install record".into());
            }
        }
        if !image_path.eq_ignore_ascii_case(self.canonical_image.to_string_lossy().as_ref())
            || volume_serial != self.record.image_volume_serial
            || file_id != self.image_file_id
            || image_sha256 != self.image_sha256
        {
            return Err(
                "trusted daemon service/process image identity mismatch (fail-closed)".into(),
            );
        }
        peer.revalidate_process_birth()
            .map_err(|error| error.to_string())?;
        peer.revalidate_image().map_err(|error| error.to_string())?;
        Ok(())
    }
}

/// Bounded JSON loader for a record whose *parent handle and DACL* have already
/// been verified by the elevated lifecycle. Keeping I/O bounded prevents a
/// malicious replacement file from becoming an allocation attack before the
/// caller rejects custody. Production serving does not call this until native
/// Windows lifecycle has supplied that custody proof.
pub fn load_windows_daemon_trust_record(path: &Path) -> Result<WindowsTrustedDaemon, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_TRUST_RECORD_BYTES
    {
        return Err(
            "Windows daemon trust record must be a bounded regular non-reparse file (fail-closed)"
                .into(),
        );
    }
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_TRUST_RECORD_BYTES {
        return Err("Windows daemon trust record exceeds byte limit (fail-closed)".into());
    }
    let record = serde_json::from_slice::<WindowsDaemonTrustRecord>(&bytes)
        .map_err(|error| format!("parse Windows daemon trust record: {error}"))?;
    WindowsTrustedDaemon::from_record(record)
}

/// Decode the sole SDDL form accepted in a custody record.  Rendering must be
/// canonical, so equivalent spellings such as leading zeroes cannot become a
/// record-substitution channel.
fn parse_canonical_windows_sid(value: &str) -> Result<Vec<u8>, String> {
    if value.len() < 7 || value.len() > 184 || !value.starts_with("S-1-") {
        return Err("trusted daemon pipe SID is invalid (fail-closed)".into());
    }
    let mut parts = value.split('-');
    let (Some("S"), Some("1"), Some(authority)) = (parts.next(), parts.next(), parts.next()) else {
        return Err("trusted daemon pipe SID is malformed (fail-closed)".into());
    };
    let authority = parse_canonical_decimal(authority, "SID authority")?;
    if authority > 0x0000_ffff_ffff_ffff {
        return Err("trusted daemon SID authority exceeds 48 bits (fail-closed)".into());
    }
    let subauthorities = parts
        .map(|part| parse_canonical_decimal(part, "SID subauthority"))
        .collect::<Result<Vec<_>, _>>()?;
    if subauthorities.len() > 15 {
        return Err("trusted daemon SID has too many subauthorities (fail-closed)".into());
    }
    let mut bytes = Vec::with_capacity(8 + subauthorities.len() * 4);
    bytes.push(1);
    bytes.push(u8::try_from(subauthorities.len()).map_err(|_| "SID subauthority count overflow")?);
    let authority = authority.to_be_bytes();
    bytes.extend_from_slice(&authority[2..]);
    for subauthority in subauthorities {
        let subauthority = u32::try_from(subauthority)
            .map_err(|_| "trusted daemon SID subauthority exceeds 32 bits (fail-closed)")?;
        bytes.extend_from_slice(&subauthority.to_le_bytes());
    }
    let canonical = render_windows_sid(&bytes)?;
    if canonical != value {
        return Err("trusted daemon pipe SID is not canonical (fail-closed)".into());
    }
    Ok(bytes)
}

fn parse_canonical_token_sid(value: &str) -> Result<Vec<u8>, String> {
    let hex = value
        .strip_prefix("sid:")
        .ok_or("trusted daemon TokenUser SID lacks sid: prefix (fail-closed)")?;
    if hex.len() < 16
        || hex.len() > 136
        || hex.len() % 2 != 0
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(
            "trusted daemon TokenUser SID is not canonical lowercase hex (fail-closed)".into(),
        );
    }
    let bytes = hex::decode(hex).map_err(|_| "trusted daemon TokenUser SID is invalid hex")?;
    let canonical = render_windows_sid(&bytes)?;
    if token_sid_from_bytes(&bytes) != value || parse_canonical_windows_sid(&canonical)? != bytes {
        return Err("trusted daemon TokenUser SID is malformed (fail-closed)".into());
    }
    Ok(bytes)
}

fn parse_canonical_decimal(value: &str, label: &str) -> Result<u64, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!(
            "trusted daemon {label} is not canonical decimal (fail-closed)"
        ));
    }
    value
        .parse::<u64>()
        .map_err(|_| format!("trusted daemon {label} overflows (fail-closed)"))
}

fn render_windows_sid(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() < 8 || bytes[0] != 1 {
        return Err("trusted daemon SID binary revision is invalid (fail-closed)".into());
    }
    let count = usize::from(bytes[1]);
    let expected = 8_usize
        .checked_add(
            count
                .checked_mul(4)
                .ok_or("trusted daemon SID length overflow")?,
        )
        .ok_or("trusted daemon SID length overflow")?;
    if count > 15 || bytes.len() != expected {
        return Err("trusted daemon SID binary length is invalid (fail-closed)".into());
    }
    let mut authority_bytes = [0_u8; 8];
    authority_bytes[2..].copy_from_slice(&bytes[2..8]);
    let authority = u64::from_be_bytes(authority_bytes);
    let mut rendered = format!("S-1-{authority}");
    for chunk in bytes[8..].chunks_exact(4) {
        let subauthority = u32::from_le_bytes(chunk.try_into().map_err(|_| "SID chunk length")?);
        rendered.push('-');
        rendered.push_str(&subauthority.to_string());
    }
    Ok(rendered)
}

fn token_sid_from_bytes(bytes: &[u8]) -> String {
    format!("sid:{}", hex::encode(bytes))
}

fn validate_service_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 256
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("trusted daemon service name is invalid (fail-closed)".into());
    }
    Ok(())
}

fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "trusted daemon {label} has invalid length/encoding (fail-closed)"
        ));
    }
    let decoded = hex::decode(value).map_err(|error| error.to_string())?;
    decoded
        .try_into()
        .map_err(|_| format!("trusted daemon {label} has invalid length (fail-closed)"))
}

fn extract_service_image(command_line: &str) -> Result<&Path, String> {
    let command_line = command_line.trim();
    let image = if let Some(rest) = command_line.strip_prefix('"') {
        rest.split_once('"')
            .map(|(image, _)| image)
            .ok_or("trusted daemon service image quote is unterminated")?
    } else {
        command_line
            .split_whitespace()
            .next()
            .ok_or("trusted daemon service image is empty")?
    };
    if image.is_empty() {
        return Err("trusted daemon service image is empty".into());
    }
    Ok(Path::new(image))
}

fn same_windows_path(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(right.to_string_lossy().as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ownmesh_broker_client::{
        build_cancel_intent_v2, compute_execute_intent_mac_v2, ExecutablePinV2, ExecuteIntentV2,
        OperationFactsV2, BROKER_PROTOCOL_V2,
    };
    use ownmesh_ipc::Endpoint;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tempfile::tempdir;
    use tokio::sync::Notify;

    #[derive(Default)]
    struct AcceptAnyPeer;

    impl WindowsPeerAuthorizer for AcceptAnyPeer {
        fn authorize(&self, _peer: &WindowsPipePeerFacts) -> Result<(), String> {
            Ok(())
        }

        fn reauthorize_before_spawn(&self, _peer: &WindowsPipePeerFacts) -> Result<(), String> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct TestLedger;

    impl WindowsReplayLedger for TestLedger {
        fn reserve(&mut self, _request: &BrokerRequestV2, _now_unix: i64) -> Result<(), String> {
            Ok(())
        }

        fn mark_spawned(&mut self, _nonce: &str, _digest: &str) -> Result<(), String> {
            Ok(())
        }

        fn complete(&mut self, _nonce: &str, _digest: &str) -> Result<(), String> {
            Ok(())
        }
    }

    type TestActiveExecutions = BTreeMap<String, (String, Arc<AtomicBool>)>;

    #[derive(Clone, Default)]
    struct BlockingRunner {
        active: Arc<Mutex<TestActiveExecutions>>,
        started: Arc<Notify>,
    }

    impl WindowsBrokerRunner for BlockingRunner {
        fn run(&self, request: &BrokerRequestV2) -> BrokerResponseV2 {
            let cancelled = Arc::new(AtomicBool::new(false));
            self.active.lock().unwrap().insert(
                request.nonce.clone(),
                (request.request_id.clone(), Arc::clone(&cancelled)),
            );
            self.started.notify_one();
            while !cancelled.load(Ordering::Acquire) {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            self.active.lock().unwrap().remove(&request.nonce);
            BrokerResponseV2 {
                request_id: request.request_id.clone(),
                ok: false,
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                error: Some("test execution cancelled".into()),
                timed_out: false,
                cancelled: true,
                truncated: false,
                duration_ms: 1,
            }
        }

        fn cancel(&self, request_id: &str, nonce: &str) -> bool {
            let active = self.active.lock().unwrap();
            let Some((registered_id, cancelled)) = active.get(nonce) else {
                return false;
            };
            if registered_id != request_id {
                return false;
            }
            cancelled.store(true, Ordering::Release);
            true
        }

        fn cancel_all(&self) -> usize {
            let active = self.active.lock().unwrap();
            for (_, cancelled) in active.values() {
                cancelled.store(true, Ordering::Release);
            }
            active.len()
        }
    }

    fn test_execute(secret: &BrokerSecret) -> ExecuteIntentV2 {
        test_execute_named(secret, "concurrent-execute")
    }

    fn test_execute_named(secret: &BrokerSecret, name: &str) -> ExecuteIntentV2 {
        let now = crate::now_unix();
        let executable = std::fs::canonicalize(
            PathBuf::from(std::env::var_os("SystemRoot").unwrap())
                .join("System32")
                .join("PING.EXE"),
        )
        .unwrap();
        let mut execute = ExecuteIntentV2 {
            protocol_version: BROKER_PROTOCOL_V2,
            request_id: name.into(),
            operation_id: name.into(),
            nonce: format!("{name}-nonce"),
            issued_at_unix: now,
            expires_at_unix: now + 30,
            facts: OperationFactsV2 {
                operation: name.into(),
                remote_payload_sha256: "a".repeat(64),
                principal_id: "test-principal".into(),
                tenant_id: "test-tenant".into(),
                principal_credential_generation: 1,
                timeout_ms: 30_000,
                max_output_bytes: 4 * 1024,
                device_id: "test-device".into(),
                workspace_id: "test-workspace".into(),
                argv: vec![executable.display().to_string(), "-n".into(), "20".into()],
                canonical_cwd: None,
                sanitized_env: BTreeMap::new(),
                executable: ExecutablePinV2 {
                    canonical_path: executable.display().to_string(),
                    image_sha256: "b".repeat(64),
                    image_len: 1,
                },
            },
            mac: String::new(),
        };
        execute.mac = compute_execute_intent_mac_v2(secret, &execute);
        execute
    }

    async fn write_intent(
        connection: &mut ownmesh_ipc::ClientConnection,
        intent: BrokerWireIntentV2,
    ) {
        let mut frame = serde_json::to_vec(&intent).unwrap();
        frame.push(b'\n');
        connection.write_all(&frame).await.unwrap();
        connection.flush().await.unwrap();
    }

    async fn read_response(connection: &mut ownmesh_ipc::ClientConnection) -> BrokerResponseV2 {
        let mut line = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            assert_eq!(connection.read(&mut byte).await.unwrap(), 1);
            if byte[0] == b'\n' {
                return serde_json::from_slice(&line).unwrap();
            }
            line.push(byte[0]);
        }
    }

    async fn test_server(
        endpoint: &Endpoint,
        secret: BrokerSecret,
        runner: BlockingRunner,
    ) -> Arc<WindowsProductionBrokerServer<AcceptAnyPeer, TestLedger, BlockingRunner>> {
        let listener = ownmesh_ipc::LocalListener::bind(endpoint.clone())
            .await
            .unwrap();
        let signing_key = CapabilitySigningKey::generate();
        let verify_key = signing_key.verify_key();
        let (shutdown, _) = watch::channel(false);
        Arc::new(WindowsProductionBrokerServer {
            listener,
            authorizer: Arc::new(AcceptAnyPeer),
            ledger: Arc::new(Mutex::new(TestLedger)),
            runner: Arc::new(runner),
            secret,
            signing_key,
            verify_key,
            broker_instance_id: "test-instance".into(),
            broker_key_id: "test-key".into(),
            connection_concurrency: Arc::new(Semaphore::new(MAX_WINDOWS_BROKER_CONNECTIONS)),
            execution_concurrency: Arc::new(Semaphore::new(MAX_WINDOWS_EXECUTE_CONCURRENCY)),
            shutdown,
        })
    }

    #[tokio::test]
    async fn explicit_cancel_is_accepted_while_an_execute_connection_is_running() {
        let endpoint = Endpoint::NamedPipe(format!(
            r"\\.\pipe\ownmesh-broker-concurrency-{}",
            uuid::Uuid::new_v4()
        ));
        let secret = BrokerSecret::generate();
        let runner = BlockingRunner::default();
        let server = test_server(&endpoint, secret.clone(), runner.clone()).await;
        let execute = test_execute(&secret);
        let execute_server = Arc::clone(&server);
        let execute_task = tokio::spawn(async move {
            let connection = execute_server.accept_connection().await.unwrap();
            execute_server.serve_connection(connection).await.unwrap();
        });
        let mut execute_client = ownmesh_ipc::connect(&endpoint).await.unwrap();
        write_intent(
            &mut execute_client,
            BrokerWireIntentV2::Execute(execute.clone()),
        )
        .await;
        tokio::time::timeout(std::time::Duration::from_secs(2), runner.started.notified())
            .await
            .expect("execute must be running before explicit cancellation");

        let cancel_server = Arc::clone(&server);
        let cancel_task = tokio::spawn(async move {
            let connection = cancel_server.accept_connection().await.unwrap();
            cancel_server.serve_connection(connection).await.unwrap();
        });
        let cancel = build_cancel_intent_v2(&secret, &execute, crate::now_unix());
        let mut cancel_client = ownmesh_ipc::connect(&endpoint).await.unwrap();
        write_intent(&mut cancel_client, BrokerWireIntentV2::Cancel(cancel)).await;
        let cancel_response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_response(&mut cancel_client),
        )
        .await
        .expect("Cancel must be accepted before the Execute response");
        assert!(cancel_response.cancelled, "{cancel_response:?}");
        let execute_response = read_response(&mut execute_client).await;
        assert!(execute_response.cancelled, "{execute_response:?}");
        cancel_task.await.unwrap();
        execute_task.await.unwrap();
    }

    #[tokio::test]
    async fn reserved_cancel_slot_survives_fifteen_running_execute_jobs() {
        let endpoint = Endpoint::NamedPipe(format!(
            r"\\.\pipe\ownmesh-broker-cancel-reserve-{}",
            uuid::Uuid::new_v4()
        ));
        let secret = BrokerSecret::generate();
        let runner = BlockingRunner::default();
        let server = test_server(&endpoint, secret.clone(), runner.clone()).await;
        let mut execute_clients = Vec::new();
        let mut execute_tasks = Vec::new();
        let mut first = None;
        for index in 0..MAX_WINDOWS_EXECUTE_CONCURRENCY {
            let execute = test_execute_named(&secret, &format!("saturated-execute-{index}"));
            if first.is_none() {
                first = Some(execute.clone());
            }
            let execute_server = Arc::clone(&server);
            execute_tasks.push(tokio::spawn(async move {
                let connection = execute_server.accept_connection().await.unwrap();
                execute_server.serve_connection(connection).await
            }));
            let mut client = ownmesh_ipc::connect(&endpoint).await.unwrap();
            write_intent(&mut client, BrokerWireIntentV2::Execute(execute)).await;
            execute_clients.push(client);
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if runner.active.lock().unwrap().len() == MAX_WINDOWS_EXECUTE_CONCURRENCY {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "all execute Jobs must be active before testing reserved Cancel slot (active={})",
                runner.active.lock().unwrap().len()
            )
        });

        let target = first.expect("first execute exists");
        let cancel_server = Arc::clone(&server);
        let cancel_task = tokio::spawn(async move {
            let connection = cancel_server.accept_connection().await.unwrap();
            cancel_server.serve_connection(connection).await
        });
        let cancel = build_cancel_intent_v2(&secret, &target, crate::now_unix());
        let mut cancel_client = ownmesh_ipc::connect(&endpoint).await.unwrap();
        write_intent(&mut cancel_client, BrokerWireIntentV2::Cancel(cancel)).await;
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_response(&mut cancel_client),
        )
        .await
        .expect("Cancel must be admitted while all execute slots are occupied");
        assert!(response.cancelled, "{response:?}");
        let first_response = read_response(&mut execute_clients.remove(0)).await;
        assert!(first_response.cancelled, "{first_response:?}");
        cancel_task.await.unwrap().unwrap();

        server.begin_shutdown();
        for task in execute_tasks {
            task.await.unwrap().unwrap();
        }
        assert!(runner.active.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn common_service_cleanup_fences_a_live_job_before_dropping_handlers() {
        let endpoint = Endpoint::NamedPipe(format!(
            r"\\.\pipe\ownmesh-broker-shutdown-drain-{}",
            uuid::Uuid::new_v4()
        ));
        let secret = BrokerSecret::generate();
        let runner = BlockingRunner::default();
        let server = test_server(&endpoint, secret.clone(), runner.clone()).await;
        let execute = test_execute(&secret);
        let handler_server = Arc::clone(&server);
        let mut connections = tokio::task::JoinSet::new();
        connections.spawn(async move {
            let connection = handler_server.accept_connection().await.unwrap();
            handler_server.serve_connection(connection).await
        });
        let mut client = ownmesh_ipc::connect(&endpoint).await.unwrap();
        write_intent(&mut client, BrokerWireIntentV2::Execute(execute)).await;
        tokio::time::timeout(std::time::Duration::from_secs(2), runner.started.notified())
            .await
            .expect("execute must be active before the common cleanup path runs");

        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            crate::windows_lifecycle::shutdown_and_drain_windows_broker(&server, &mut connections),
        )
        .await
        .expect("common cleanup must wait for the fenced Job")
        .expect("common cleanup must finish after cancelling the live Job");
        assert!(connections.is_empty());
        assert!(runner.active.lock().unwrap().is_empty());
        let response = read_response(&mut client).await;
        assert!(response.cancelled, "{response:?}");
    }

    #[tokio::test]
    async fn execute_disconnect_fences_the_running_job_before_handler_returns() {
        let endpoint = Endpoint::NamedPipe(format!(
            r"\\.\pipe\ownmesh-broker-disconnect-{}",
            uuid::Uuid::new_v4()
        ));
        let secret = BrokerSecret::generate();
        let runner = BlockingRunner::default();
        let server = test_server(&endpoint, secret.clone(), runner.clone()).await;
        let execute = test_execute(&secret);
        let handler_server = Arc::clone(&server);
        let handler = tokio::spawn(async move {
            let connection = handler_server.accept_connection().await.unwrap();
            handler_server.serve_connection(connection).await
        });
        let mut client = ownmesh_ipc::connect(&endpoint).await.unwrap();
        write_intent(&mut client, BrokerWireIntentV2::Execute(execute)).await;
        tokio::time::timeout(std::time::Duration::from_secs(2), runner.started.notified())
            .await
            .expect("execute must be running before disconnect");
        drop(client);
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handler)
            .await
            .expect("disconnect handler must await the runner's terminal receipt")
            .unwrap();
        assert!(
            result.is_err(),
            "dropped client cannot receive the response"
        );
        assert!(runner.active.lock().unwrap().is_empty());
    }

    #[test]
    fn trust_record_rejects_synthetic_identity_fields_before_any_pipe_accept() {
        let dir = tempdir().unwrap();
        let image = dir.path().join("ownmeshd.exe");
        std::fs::write(&image, b"not-an-executable-but-regular").unwrap();
        let record = test_record(image);
        assert!(WindowsTrustedDaemon::from_record(record).is_ok());
        let bad_sid = WindowsDaemonTrustRecord {
            daemon_pipe_sid: "S-1-5-18)(A;;GA;;;WD".into(),
            ..test_record(dir.path().join("ownmeshd.exe"))
        };
        assert!(WindowsTrustedDaemon::from_record(bad_sid).is_err());
    }

    #[test]
    fn trust_record_rejects_sid_representation_substitution() {
        let dir = tempdir().unwrap();
        let image = dir.path().join("ownmeshd.exe");
        std::fs::write(&image, b"regular").unwrap();
        let mut mismatched = test_record(image.clone());
        mismatched.daemon_token_sid = token_sid("S-1-5-18");
        assert!(WindowsTrustedDaemon::from_record(mismatched).is_err());

        let mut noncanonical_pipe = test_record(image.clone());
        noncanonical_pipe.daemon_pipe_sid = "S-1-05-21-1".into();
        assert!(WindowsTrustedDaemon::from_record(noncanonical_pipe).is_err());

        let mut noncanonical_token = test_record(image);
        noncanonical_token.daemon_token_sid = noncanonical_token.daemon_token_sid.to_uppercase();
        assert!(WindowsTrustedDaemon::from_record(noncanonical_token).is_err());
    }

    #[test]
    fn old_ambiguous_or_unknown_record_schema_is_rejected() {
        let dir = tempdir().unwrap();
        let image = dir.path().join("ownmeshd.exe");
        std::fs::write(&image, b"regular").unwrap();
        let record = test_record(image);
        let path = dir.path().join("trust.json");
        let mut value = serde_json::to_value(&record).unwrap();
        value.as_object_mut().unwrap().remove("daemon_token_sid");
        value
            .as_object_mut()
            .unwrap()
            .insert("daemon_sid".into(), serde_json::json!("S-1-5-21-1"));
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(load_windows_daemon_trust_record(&path).is_err());
    }

    fn test_record(image_path: PathBuf) -> WindowsDaemonTrustRecord {
        WindowsDaemonTrustRecord {
            daemon_pipe_sid: "S-1-5-21-1".into(),
            daemon_token_sid: token_sid("S-1-5-21-1"),
            daemon_service_name: "OwnMeshDaemon".into(),
            daemon_session_id: 1,
            daemon_integrity_rid: 0x2000,
            image_path,
            image_volume_serial: 1,
            image_file_id: "00".repeat(16),
            image_sha256: "00".repeat(32),
            service_config_generation: 1,
        }
    }

    fn token_sid(pipe_sid: &str) -> String {
        token_sid_from_bytes(&parse_canonical_windows_sid(pipe_sid).unwrap())
    }
}
