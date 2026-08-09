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
use tokio::sync::Semaphore;

const MAX_TRUST_RECORD_BYTES: u64 = 64 * 1024;
const MAX_WINDOWS_BROKER_CONCURRENCY: usize = 16;

/// Immutable fields recorded by the elevated installer after it has copied the
/// daemon image into the Admin-controlled installation root. `image_file_id`
/// and `image_sha256` are hex encodings of the Windows FILE_ID_128 and SHA-256
/// from that exact installed image, never caller-supplied command fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WindowsDaemonTrustRecord {
    pub daemon_sid: String,
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
    fn complete(&mut self, nonce: &str, digest: &str) -> Result<(), String>;
}

impl WindowsReplayLedger for crate::ReplayLedger {
    fn reserve(&mut self, request: &BrokerRequestV2, now_unix: i64) -> Result<(), String> {
        self.reserve_verified_request(request, now_unix)
            .map(|_| ())
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
    concurrency: Arc<Semaphore>,
}

impl<A, L, R> WindowsProductionBrokerServer<A, L, R>
where
    A: WindowsPeerAuthorizer + 'static,
    L: WindowsReplayLedger + 'static,
    R: WindowsBrokerRunner + 'static,
{
    /// Bind only the fixed pipe with its protected daemon/SYSTEM/Admin DACL.
    pub async fn bind(
        daemon_sid: &str,
        authorizer: A,
        ledger: L,
        runner: R,
        secret: BrokerSecret,
        signing_key: CapabilitySigningKey,
    ) -> Result<Self, String> {
        let listener = ownmesh_ipc::LocalListener::bind_secure_broker_pipe(daemon_sid)
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
            concurrency: Arc::new(Semaphore::new(MAX_WINDOWS_BROKER_CONCURRENCY)),
        })
    }

    /// Accept exactly one client, apply the bounded handler, and write one
    /// bounded response. Callers may schedule this under their service loop.
    pub async fn serve_once(&self) -> Result<(), String> {
        let mut connection = self
            .listener
            .accept()
            .await
            .map_err(|error| error.to_string())?;
        let permit = self
            .concurrency
            .clone()
            .try_acquire_owned()
            .map_err(|_| "Windows broker busy (bounded concurrency)".to_string())?;
        let response = self.handle_connection(&mut connection).await;
        drop(permit);
        write_windows_response(&mut connection, &response).await
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
                        .complete(&request.nonce, &digest)?;
                    Ok(BrokerResponseV2 {
                        request_id: cancel.request_id,
                        ok: true,
                        exit_code: None,
                        stdout: String::new(),
                        stderr: String::new(),
                        error: None,
                        timed_out: false,
                        cancelled: true,
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
                    let digest = operation_facts_digest(&internal.facts);
                    self.ledger
                        .lock()
                        .map_err(|_| "Windows replay ledger lock poisoned".to_string())?
                        .reserve(&internal, now)?;
                    let mut response = self.runner.run(&internal);
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
    connection
        .write_all(&line)
        .await
        .map_err(|error| error.to_string())?;
    connection.flush().await.map_err(|error| error.to_string())
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
        validate_sid(&record.daemon_sid)?;
        validate_service_name(&record.daemon_service_name)?;
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
        if peer.user_sid() != self.record.daemon_sid {
            return Err("named-pipe peer SID differs from trusted daemon SID (fail-closed)".into());
        }
        if peer.session_id() != self.record.daemon_session_id
            || peer.integrity_rid() != self.record.daemon_integrity_rid
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
        let service = windows_running_service_facts(&self.record.daemon_service_name, pid)
            .map_err(|error| format!("trusted daemon SCM identity failed: {error}"))?;
        let service_image = extract_service_image(service.binary_command_line())?;
        let service_image = std::fs::canonicalize(service_image)
            .map_err(|error| format!("canonicalize SCM daemon image: {error}"))?;
        if !same_windows_path(&service_image, &self.canonical_image)
            || !image_path.eq_ignore_ascii_case(self.canonical_image.to_string_lossy().as_ref())
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

fn validate_sid(sid: &str) -> Result<(), String> {
    if !sid.starts_with("S-")
        || sid.len() > 184
        || !sid
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'S')
    {
        return Err("trusted daemon SID is invalid (fail-closed)".into());
    }
    Ok(())
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
    use tempfile::tempdir;

    #[test]
    fn trust_record_rejects_synthetic_identity_fields_before_any_pipe_accept() {
        let dir = tempdir().unwrap();
        let image = dir.path().join("ownmeshd.exe");
        std::fs::write(&image, b"not-an-executable-but-regular").unwrap();
        let record = WindowsDaemonTrustRecord {
            daemon_sid: "S-1-5-21-1".into(),
            daemon_service_name: "OwnMeshDaemon".into(),
            daemon_session_id: 1,
            daemon_integrity_rid: 0x2000,
            image_path: image,
            image_volume_serial: 1,
            image_file_id: "00".repeat(16),
            image_sha256: "00".repeat(32),
            service_config_generation: 1,
        };
        assert!(WindowsTrustedDaemon::from_record(record).is_ok());
        let bad_sid = WindowsDaemonTrustRecord {
            daemon_sid: "S-1-5-18)(A;;GA;;;WD".into(),
            ..WindowsDaemonTrustRecord {
                daemon_sid: "S-1-5-21-1".into(),
                daemon_service_name: "OwnMeshDaemon".into(),
                daemon_session_id: 1,
                daemon_integrity_rid: 0x2000,
                image_path: dir.path().join("ownmeshd.exe"),
                image_volume_serial: 1,
                image_file_id: "00".repeat(16),
                image_sha256: "00".repeat(32),
                service_config_generation: 1,
            }
        };
        assert!(WindowsTrustedDaemon::from_record(bad_sid).is_err());
    }
}
