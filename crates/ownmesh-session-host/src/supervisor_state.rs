//! In-process state behind the persistent local session-supervisor IPC service.

use crate::{HostIoMode, HostManifest, LiveHost, OwnerSpool, SpoolPage, StructuredProcessHost};
use crate::pty_host::RawDrainOutput;
use ownmesh_session::{PtyCommand, PtySize};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tokio::sync::Mutex;

const MAX_STDIN_BYTES: usize = 64 * 1024;
const MAX_HOSTS: usize = 64;

/// Exact host attachment facts supplied by the authenticated daemon client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorBinding {
    pub session_id: String,
    pub device_id: String,
    pub workspace_id: String,
    pub owner_principal: String,
    pub host_nonce: String,
    pub controller_epoch: u64,
}

impl SupervisorBinding {
    fn matches(&self, manifest: &HostManifest) -> bool {
        self.session_id == manifest.session_id
            && self.device_id == manifest.device_id
            && self.workspace_id == manifest.workspace_id
            && self.owner_principal == manifest.owner_principal
            && self.host_nonce == manifest.host_nonce
            && self.controller_epoch == manifest.controller_epoch
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorStatus {
    pub pid: Option<u32>,
    pub pending_output_bytes: usize,
    pub exited: bool,
}

struct Hosted {
    manifest: HostManifest,
    spool: OwnerSpool,
    stderr_spool: Option<OwnerSpool>,
    host: HostedHost,
}

enum HostedHost { Pty(LiveHost), Structured(StructuredProcessHost) }

impl HostedHost {
    fn write(&self, bytes: &[u8]) -> Result<(), String> { match self { Self::Pty(h) => h.write_stdin(bytes), Self::Structured(h) => h.write_frame(bytes) } }
    fn resize(&self, cols: u16, rows: u16) -> Result<(), String> { match self { Self::Pty(h) => h.resize(cols, rows), Self::Structured(_) => Err("structured pipe hosts cannot resize".into()) } }
    fn drain(&self, stderr: bool, max: usize) -> Result<RawDrainOutput, String> { match self { Self::Pty(h) if stderr => Ok((Vec::new(), false, h.is_exited(), None, 0)), Self::Pty(h) => h.drain_output_bytes(max), Self::Structured(h) if stderr => h.drain_stderr(max), Self::Structured(h) => h.drain_stdout(max) } }
    fn terminate(&mut self) -> Result<(), String> { match self { Self::Pty(h) => h.terminate(), Self::Structured(h) => h.terminate() } }
    fn status(&self) -> SupervisorStatus { match self { Self::Pty(h) => status(h), Self::Structured(h) => SupervisorStatus { pid: h.handle.pid, pending_output_bytes: h.pending_output_bytes(), exited: false } } }
}

/// Bounded supervisor host map. A disconnected daemon client leaves this
/// singleton state alive; an actual sidecar process exit drops `LiveHost` and
/// terminates its process tree as a deliberate crash-cleanup policy.
pub struct SupervisorState {
    hosts: Mutex<HashMap<String, Hosted>>,
    root: std::path::PathBuf,
}

impl SupervisorState {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            hosts: Mutex::new(HashMap::new()),
            root: root.as_ref().to_path_buf(),
        }
    }

    pub async fn spawn(
        &self,
        manifest: HostManifest,
        command: PtyCommand,
        size: PtySize,
    ) -> Result<SupervisorBinding, String> { self.spawn_with_io(manifest, command, size, HostIoMode::Pty).await }

    pub async fn spawn_with_io(
        &self,
        manifest: HostManifest,
        command: PtyCommand,
        size: PtySize,
        io_mode: HostIoMode,
    ) -> Result<SupervisorBinding, String> {
        // Refuse bad TTLs before allocating a PTY/process tree.
        manifest.validate_runtime_lifetimes(unix_now())?;
        let mut hosts = self.hosts.lock().await;
        if hosts.len() >= MAX_HOSTS {
            return Err("supervisor host quota reached".into());
        }
        if hosts.contains_key(&manifest.session_id) {
            return Err("supervisor host already live".into());
        }
        let host = match io_mode { HostIoMode::Pty => HostedHost::Pty(LiveHost::spawn(&command, size)?), HostIoMode::StructuredPipes => HostedHost::Structured(StructuredProcessHost::spawn(&command, size)?) };
        // Do not reserve durable identity until a PTY exists. If custody/spool
        // creation fails, dropping this newly spawned host cleans its tree.
        let spool = OwnerSpool::create(&self.root, manifest.clone())?;
        let stderr_spool = matches!(io_mode, HostIoMode::StructuredPipes).then(|| OwnerSpool::create_stderr(&self.root, &manifest.session_id)).transpose()?;
        let binding = binding_of(&manifest);
        hosts.insert(
            manifest.session_id.clone(),
            Hosted {
                manifest,
                spool,
                stderr_spool,
                host,
            },
        );
        Ok(binding)
    }

    pub async fn reattach(&self, binding: &SupervisorBinding) -> Result<SupervisorStatus, String> {
        let mut hosts = self.hosts.lock().await;
        let hosted = hosts
            .get_mut(&binding.session_id)
            .ok_or("supervisor host unavailable")?;
        exact_identity(binding, &hosted.manifest)?;
        Ok(hosted.host.status())
    }

    pub async fn write(&self, binding: &SupervisorBinding, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() > MAX_STDIN_BYTES {
            return Err("supervisor stdin frame exceeds budget".into());
        }
        let mut hosts = self.hosts.lock().await;
        let hosted = hosts
            .get_mut(&binding.session_id)
            .ok_or("supervisor host unavailable")?;
        exact(binding, &hosted.manifest)?;
        hosted.host.write(bytes)
    }

    pub async fn resize(
        &self,
        binding: &SupervisorBinding,
        cols: u16,
        rows: u16,
    ) -> Result<(), String> {
        if cols == 0 || rows == 0 || cols > 512 || rows > 512 {
            return Err("invalid supervisor PTY size".into());
        }
        let hosts = self.hosts.lock().await;
        let hosted = hosts
            .get(&binding.session_id)
            .ok_or("supervisor host unavailable")?;
        exact(binding, &hosted.manifest)?;
        hosted.host.resize(cols, rows)
    }

    pub async fn drain(
        &self,
        binding: &SupervisorBinding,
        offset: u64,
        max_bytes: usize,
        stderr: bool,
    ) -> Result<SpoolPage, String> {
        let mut hosts = self.hosts.lock().await;
        let hosted = hosts
            .get_mut(&binding.session_id)
            .ok_or("supervisor host unavailable")?;
        exact(binding, &hosted.manifest)?;
        let (bytes, truncated, _, _, _) = hosted.host.drain(stderr, max_bytes)?;
        let spool = if stderr { hosted.stderr_spool.as_mut().ok_or("stderr stream unavailable")? } else { &mut hosted.spool };
        if !bytes.is_empty() {
            spool.append(&bytes)?;
        }
        let mut page = spool.read_page(offset, max_bytes)?;
        page.truncated |= truncated;
        Ok(page)
    }

    /// Transfer a live PTY only after exact possession of its previous binding.
    /// The controller epoch and freshly generated host nonce change together,
    /// invalidating every old daemon/client capability before the successor can
    /// write, resize, replay, or terminate the host.
    pub async fn rotate_binding(
        &self,
        previous: &SupervisorBinding,
        next_owner_principal: impl Into<String>,
        next_epoch: u64,
        next_binding_expires_unix: i64,
    ) -> Result<SupervisorBinding, String> {
        let mut hosts = self.hosts.lock().await;
        let hosted = hosts
            .get_mut(&previous.session_id)
            .ok_or("supervisor host unavailable")?;
        exact(previous, &hosted.manifest)?;
        rotate_epoch(previous.controller_epoch, next_epoch)?;
        let next = HostManifest::new(
            hosted.manifest.session_id.clone(),
            hosted.manifest.device_id.clone(),
            hosted.manifest.workspace_id.clone(),
            next_owner_principal,
            next_epoch,
            next_binding_expires_unix,
            hosted.manifest.host_expires_unix,
        )?;
        next.validate_runtime_lifetimes(unix_now())?;
        hosted.spool.rotate_manifest(next.clone())?;
        hosted.manifest = next.clone();
        Ok(binding_of(&next))
    }

    /// Idempotent controller handoff/claim transition. Replaying the same
    /// transition id and payload returns the already-issued successor binding;
    /// reusing its id with different facts fails closed.
    pub async fn rotate_binding_idempotent(
        &self,
        previous: &SupervisorBinding,
        next_owner_principal: impl Into<String>,
        next_epoch: u64,
        next_binding_expires_unix: i64,
        transition_id: &str,
        payload_digest: &str,
    ) -> Result<SupervisorBinding, String> {
        let mut hosts = self.hosts.lock().await;
        let hosted = hosts
            .get_mut(&previous.session_id)
            .ok_or("supervisor host unavailable")?;
        if hosted
            .manifest
            .matches_transition(transition_id, payload_digest)?
        {
            return Ok(binding_of(&hosted.manifest));
        }
        exact(previous, &hosted.manifest)?;
        rotate_epoch(previous.controller_epoch, next_epoch)?;
        let mut next = HostManifest::new(
            hosted.manifest.session_id.clone(),
            hosted.manifest.device_id.clone(),
            hosted.manifest.workspace_id.clone(),
            next_owner_principal,
            next_epoch,
            next_binding_expires_unix,
            hosted.manifest.host_expires_unix,
        )?;
        next.validate_runtime_lifetimes(unix_now())?;
        next.record_transition(transition_id, payload_digest)?;
        hosted.spool.rotate_manifest(next.clone())?;
        hosted.manifest = next.clone();
        Ok(binding_of(&next))
    }

    /// CAS-reclaim an expired daemon binding while retaining the live PTY.
    /// The exact stale nonce/epoch is accepted only as evidence for recovery;
    /// all mutation methods reject it until this operation issues a successor.
    pub async fn reclaim_expired_binding(
        &self,
        previous: &SupervisorBinding,
        next_owner_principal: impl Into<String>,
        next_epoch: u64,
        next_binding_expires_unix: i64,
    ) -> Result<SupervisorBinding, String> {
        let mut hosts = self.hosts.lock().await;
        let hosted = hosts
            .get_mut(&previous.session_id)
            .ok_or("supervisor host unavailable")?;
        if !previous.matches(&hosted.manifest) {
            return Err("supervisor binding mismatch".into());
        }
        if hosted.manifest.binding_expires_unix > unix_now() {
            return Err("supervisor binding has not expired".into());
        }
        rotate_epoch(previous.controller_epoch, next_epoch)?;
        let next = HostManifest::new(
            hosted.manifest.session_id.clone(),
            hosted.manifest.device_id.clone(),
            hosted.manifest.workspace_id.clone(),
            next_owner_principal,
            next_epoch,
            next_binding_expires_unix,
            hosted.manifest.host_expires_unix,
        )?;
        next.validate_runtime_lifetimes(unix_now())?;
        hosted.spool.rotate_manifest(next.clone())?;
        hosted.manifest = next.clone();
        Ok(binding_of(&next))
    }

    /// Detach an exact active controller while preserving the host/spool. The
    /// successor nonce and epoch make all prior write/resize/terminate facts
    /// stale before any later claim can attach a new controller.
    pub async fn detach_binding(
        &self,
        previous: &SupervisorBinding,
        next_epoch: u64,
    ) -> Result<SupervisorBinding, String> {
        let mut hosts = self.hosts.lock().await;
        let hosted = hosts
            .get_mut(&previous.session_id)
            .ok_or("supervisor host unavailable")?;
        exact(previous, &hosted.manifest)?;
        rotate_epoch(previous.controller_epoch, next_epoch)?;
        let mut next = HostManifest::new(
            hosted.manifest.session_id.clone(),
            hosted.manifest.device_id.clone(),
            hosted.manifest.workspace_id.clone(),
            hosted.manifest.owner_principal.clone(),
            next_epoch,
            hosted.manifest.binding_expires_unix,
            hosted.manifest.host_expires_unix,
        )?;
        next.controller_attached = false;
        hosted.spool.rotate_manifest(next.clone())?;
        hosted.manifest = next.clone();
        Ok(binding_of(&next))
    }

    /// Receipt-aware detach. A retry after a daemon crash returns the detached
    /// successor nonce instead of applying another epoch transition.
    pub async fn detach_idempotent(
        &self,
        previous: &SupervisorBinding,
        next_epoch: u64,
        transition_id: &str,
        payload_digest: &str,
    ) -> Result<SupervisorBinding, String> {
        let mut hosts = self.hosts.lock().await;
        let hosted = hosts
            .get_mut(&previous.session_id)
            .ok_or("supervisor host unavailable")?;
        if hosted
            .manifest
            .matches_transition(transition_id, payload_digest)?
        {
            return Ok(binding_of(&hosted.manifest));
        }
        exact(previous, &hosted.manifest)?;
        rotate_epoch(previous.controller_epoch, next_epoch)?;
        let mut next = HostManifest::new(
            hosted.manifest.session_id.clone(),
            hosted.manifest.device_id.clone(),
            hosted.manifest.workspace_id.clone(),
            hosted.manifest.owner_principal.clone(),
            next_epoch,
            hosted.manifest.binding_expires_unix,
            hosted.manifest.host_expires_unix,
        )?;
        next.controller_attached = false;
        next.record_transition(transition_id, payload_digest)?;
        hosted.spool.rotate_manifest(next.clone())?;
        hosted.manifest = next.clone();
        Ok(binding_of(&next))
    }

    /// Claim only a durable detached manifest. The caller must provide the
    /// exact detached nonce/epoch; active controllers cannot be taken over.
    pub async fn claim_detached_binding(
        &self,
        previous: &SupervisorBinding,
        next_owner_principal: impl Into<String>,
        next_epoch: u64,
        next_binding_expires_unix: i64,
    ) -> Result<SupervisorBinding, String> {
        let mut hosts = self.hosts.lock().await;
        let hosted = hosts
            .get_mut(&previous.session_id)
            .ok_or("supervisor host unavailable")?;
        exact_identity(previous, &hosted.manifest)?;
        if hosted.manifest.controller_attached {
            return Err("supervisor controller is still attached".into());
        }
        rotate_epoch(previous.controller_epoch, next_epoch)?;
        let next = HostManifest::new(
            hosted.manifest.session_id.clone(),
            hosted.manifest.device_id.clone(),
            hosted.manifest.workspace_id.clone(),
            next_owner_principal,
            next_epoch,
            next_binding_expires_unix,
            hosted.manifest.host_expires_unix,
        )?;
        next.validate_runtime_lifetimes(unix_now())?;
        hosted.spool.rotate_manifest(next.clone())?;
        hosted.manifest = next.clone();
        Ok(binding_of(&next))
    }

    /// Receipt-aware claim of a controller-free durable host.
    pub async fn claim_idempotent(
        &self,
        previous: &SupervisorBinding,
        next_owner_principal: impl Into<String>,
        next_epoch: u64,
        next_binding_expires_unix: i64,
        transition_id: &str,
        payload_digest: &str,
    ) -> Result<SupervisorBinding, String> {
        let mut hosts = self.hosts.lock().await;
        let hosted = hosts
            .get_mut(&previous.session_id)
            .ok_or("supervisor host unavailable")?;
        if hosted
            .manifest
            .matches_transition(transition_id, payload_digest)?
        {
            return Ok(binding_of(&hosted.manifest));
        }
        exact_identity(previous, &hosted.manifest)?;
        if hosted.manifest.controller_attached {
            return Err("supervisor controller is still attached".into());
        }
        rotate_epoch(previous.controller_epoch, next_epoch)?;
        let mut next = HostManifest::new(
            hosted.manifest.session_id.clone(),
            hosted.manifest.device_id.clone(),
            hosted.manifest.workspace_id.clone(),
            next_owner_principal,
            next_epoch,
            next_binding_expires_unix,
            hosted.manifest.host_expires_unix,
        )?;
        next.validate_runtime_lifetimes(unix_now())?;
        next.record_transition(transition_id, payload_digest)?;
        hosted.spool.rotate_manifest(next.clone())?;
        hosted.manifest = next.clone();
        Ok(binding_of(&next))
    }

    /// Receipt-aware reclaim of an expired active capability.
    pub async fn reclaim_idempotent(
        &self,
        previous: &SupervisorBinding,
        next_owner_principal: impl Into<String>,
        next_epoch: u64,
        next_binding_expires_unix: i64,
        transition_id: &str,
        payload_digest: &str,
    ) -> Result<SupervisorBinding, String> {
        let mut hosts = self.hosts.lock().await;
        let hosted = hosts
            .get_mut(&previous.session_id)
            .ok_or("supervisor host unavailable")?;
        if hosted
            .manifest
            .matches_transition(transition_id, payload_digest)?
        {
            return Ok(binding_of(&hosted.manifest));
        }
        if !previous.matches(&hosted.manifest) {
            return Err("supervisor binding mismatch".into());
        }
        if hosted.manifest.binding_expires_unix > unix_now() {
            return Err("supervisor binding has not expired".into());
        }
        rotate_epoch(previous.controller_epoch, next_epoch)?;
        let mut next = HostManifest::new(
            hosted.manifest.session_id.clone(),
            hosted.manifest.device_id.clone(),
            hosted.manifest.workspace_id.clone(),
            next_owner_principal,
            next_epoch,
            next_binding_expires_unix,
            hosted.manifest.host_expires_unix,
        )?;
        next.validate_runtime_lifetimes(unix_now())?;
        next.record_transition(transition_id, payload_digest)?;
        hosted.spool.rotate_manifest(next.clone())?;
        hosted.manifest = next.clone();
        Ok(binding_of(&next))
    }

    /// Receipt-aware exact renewal: owner and epoch stay fixed, capability
    /// expiry and nonce rotate atomically, and stale write facts are invalid.
    pub async fn renew_idempotent(
        &self,
        previous: &SupervisorBinding,
        next_binding_expires_unix: i64,
        transition_id: &str,
        payload_digest: &str,
    ) -> Result<SupervisorBinding, String> {
        let mut hosts = self.hosts.lock().await;
        let hosted = hosts
            .get_mut(&previous.session_id)
            .ok_or("supervisor host unavailable")?;
        if hosted
            .manifest
            .matches_transition(transition_id, payload_digest)?
        {
            return Ok(binding_of(&hosted.manifest));
        }
        exact(previous, &hosted.manifest)?;
        let mut next = HostManifest::new(
            hosted.manifest.session_id.clone(),
            hosted.manifest.device_id.clone(),
            hosted.manifest.workspace_id.clone(),
            hosted.manifest.owner_principal.clone(),
            hosted.manifest.controller_epoch,
            next_binding_expires_unix,
            hosted.manifest.host_expires_unix,
        )?;
        next.validate_runtime_lifetimes(unix_now())?;
        next.record_transition(transition_id, payload_digest)?;
        hosted.spool.renew_manifest(next.clone())?;
        hosted.manifest = next.clone();
        Ok(binding_of(&next))
    }

    /// Terminate expired hosts in a bounded sweep. A running sidecar invokes
    /// this periodically; every operation independently enforces expiry too.
    pub async fn sweep_expired(&self) -> usize {
        let now = unix_now();
        let mut expired = Vec::new();
        {
            let mut hosts = self.hosts.lock().await;
            let ids: Vec<_> = hosts
                .iter()
                .filter(|(_, hosted)| hosted.manifest.host_expires_unix <= now)
                .map(|(id, _)| id.clone())
                .take(MAX_HOSTS)
                .collect();
            for id in ids {
                if let Some(hosted) = hosts.remove(&id) {
                    expired.push(hosted);
                }
            }
        }
        let count = expired.len();
        for mut hosted in expired {
            let _ = hosted.host.terminate();
        }
        count
    }

    /// Terminate a host exactly once.  The receipt survives removal from the
    /// in-memory map, so a lost daemon reply/restart can be retried only with
    /// the same exact binding and server-derived payload digest.
    pub async fn terminate_idempotent(
        &self,
        binding: &SupervisorBinding,
        transition_id: &str,
        payload_digest: &str,
    ) -> Result<(), String> {
        let mut hosts = self.hosts.lock().await;
        if let Some(hosted) = hosts.get_mut(&binding.session_id) {
            exact(binding, &hosted.manifest)?;
            hosted.host.terminate()?;
            // Do not remove the host until the terminal receipt is durable:
            // a persistence failure remains retryable without claiming a
            // process was cleaned up when it was not.
            hosted
                .spool
                .record_termination(transition_id, payload_digest)?;
            hosts.remove(&binding.session_id);
            return Ok(());
        }
        drop(hosts);
        let receipt = OwnerSpool::termination_receipt(&self.root, &binding.session_id)?
            .ok_or("supervisor host unavailable")?;
        let matches_binding = receipt.session_id == binding.session_id
            && receipt.device_id == binding.device_id
            && receipt.workspace_id == binding.workspace_id
            && receipt.owner_principal == binding.owner_principal
            && receipt.host_nonce == binding.host_nonce
            && receipt.controller_epoch == binding.controller_epoch;
        if !matches_binding {
            return Err("supervisor termination binding mismatch".into());
        }
        if receipt.transition_id == transition_id && receipt.payload_digest == payload_digest {
            Ok(())
        } else if receipt.transition_id == transition_id {
            Err("supervisor termination id payload conflict".into())
        } else {
            Err("supervisor host already terminated".into())
        }
    }

    /// Compatibility helper for older in-process tests. Local IPC always uses
    /// [`Self::terminate_idempotent`] with a caller-specific transition id.
    pub async fn terminate(&self, binding: &SupervisorBinding) -> Result<(), String> {
        self.terminate_idempotent(binding, "legacy-in-process-terminate", "legacy")
            .await
    }
}

fn binding_of(manifest: &HostManifest) -> SupervisorBinding {
    SupervisorBinding {
        session_id: manifest.session_id.clone(),
        device_id: manifest.device_id.clone(),
        workspace_id: manifest.workspace_id.clone(),
        owner_principal: manifest.owner_principal.clone(),
        host_nonce: manifest.host_nonce.clone(),
        controller_epoch: manifest.controller_epoch,
    }
}
fn exact(binding: &SupervisorBinding, manifest: &HostManifest) -> Result<(), String> {
    exact_identity(binding, manifest)?;
    if !manifest.controller_attached {
        return Err("supervisor controller is detached".into());
    }
    Ok(())
}

fn exact_identity(binding: &SupervisorBinding, manifest: &HostManifest) -> Result<(), String> {
    let now = unix_now();
    if manifest.binding_expires_unix <= now {
        return Err("supervisor binding expired".into());
    }
    binding
        .matches(manifest)
        .then_some(())
        .ok_or_else(|| "supervisor binding mismatch".into())
}

fn rotate_epoch(current: u64, next: u64) -> Result<(), String> {
    let expected = current
        .checked_add(1)
        .ok_or("supervisor controller epoch overflow")?;
    if next != expected {
        return Err("supervisor controller epoch must advance exactly once".into());
    }
    Ok(())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(i64::MAX)
}
fn status(host: &LiveHost) -> SupervisorStatus {
    SupervisorStatus {
        pid: host.handle.pid,
        pending_output_bytes: host.pending_output_bytes(),
        exited: host.is_exited(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[tokio::test]
    async fn nonce_mismatch_cannot_reattach_or_terminate() {
        let root = tempdir().unwrap();
        let state = SupervisorState::new(root.path());
        let manifest = HostManifest::new(
            "ses_sidecar",
            "dev",
            "ws",
            "client:remote:t:p",
            1,
            unix_now() + 60,
            unix_now() + 600,
        )
        .unwrap();
        let active_binding = state
            .spawn(
                manifest,
                PtyCommand {
                    program: if cfg!(windows) {
                        "cmd.exe".into()
                    } else {
                        "/bin/sh".into()
                    },
                    args: vec![],
                    cwd: None,
                    env: vec![],
                },
                PtySize::default(),
            )
            .await
            .unwrap();
        let mut forged_binding = active_binding.clone();
        forged_binding.host_nonce = "host_stale".into();
        assert!(state.reattach(&forged_binding).await.is_err());
        assert!(state.terminate(&forged_binding).await.is_err());
        state.terminate(&active_binding).await.unwrap();
    }

    #[tokio::test]
    async fn binding_expiry_preserves_host_for_cas_reclaim() {
        let root = tempdir().unwrap();
        let state = SupervisorState::new(root.path());
        let original = state
            .spawn(
                HostManifest::new(
                    "ses_rotate",
                    "dev",
                    "ws",
                    "owner_a",
                    1,
                    unix_now() + 2,
                    unix_now() + 600,
                )
                .unwrap(),
                shell_command(),
                PtySize::default(),
            )
            .await
            .unwrap();
        let successor = state
            .rotate_binding(&original, "owner_b", 2, unix_now() + 2)
            .await
            .unwrap();
        assert_ne!(successor.host_nonce, original.host_nonce);
        assert!(state.reattach(&original).await.is_err());
        state.reattach(&successor).await.unwrap();
        assert!(state
            .rotate_binding(&successor, "owner_b", 4, unix_now() + 60)
            .await
            .is_err());
        let pid_before_expiry = state.reattach(&successor).await.unwrap().pid;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        assert!(state.write(&successor, b"nope").await.is_err());
        assert_eq!(state.sweep_expired().await, 0);
        let reclaimed = state
            .reclaim_expired_binding(&successor, "owner_c", 3, unix_now() + 60)
            .await
            .unwrap();
        assert_eq!(
            state.reattach(&reclaimed).await.unwrap().pid,
            pid_before_expiry
        );
        state.terminate(&reclaimed).await.unwrap();
    }

    #[tokio::test]
    async fn past_and_oversized_lifetime_are_refused_before_spawn() {
        let root = tempdir().unwrap();
        let state = SupervisorState::new(root.path());
        let now = unix_now();
        let past =
            HostManifest::new("ses_past", "dev", "ws", "owner", 1, now - 1, now + 60).unwrap();
        assert!(state
            .spawn(past, shell_command(), PtySize::default())
            .await
            .is_err());
        let huge =
            HostManifest::new("ses_huge", "dev", "ws", "owner", 1, now + 60, now + 86_401).unwrap();
        assert!(state
            .spawn(huge, shell_command(), PtySize::default())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn transition_id_replay_is_idempotent_and_conflicts_on_payload_reuse() {
        let root = tempdir().unwrap();
        let state = SupervisorState::new(root.path());
        let binding = state
            .spawn(
                HostManifest::new(
                    "ses_transition",
                    "dev",
                    "ws",
                    "owner_a",
                    1,
                    unix_now() + 60,
                    unix_now() + 600,
                )
                .unwrap(),
                shell_command(),
                PtySize::default(),
            )
            .await
            .unwrap();
        let first = state
            .rotate_binding_idempotent(&binding, "owner_b", 2, unix_now() + 60, "tr_1", "digest_a")
            .await
            .unwrap();
        let replay = state
            .rotate_binding_idempotent(&binding, "owner_b", 2, unix_now() + 60, "tr_1", "digest_a")
            .await
            .unwrap();
        assert_eq!(first, replay);
        assert!(state
            .rotate_binding_idempotent(&binding, "owner_b", 2, unix_now() + 60, "tr_1", "digest_b")
            .await
            .is_err());
        state.terminate(&first).await.unwrap();
    }

    #[tokio::test]
    async fn detach_claim_and_renew_are_exact_and_idempotent() {
        let root = tempdir().unwrap();
        let state = SupervisorState::new(root.path());
        let active = state
            .spawn(
                HostManifest::new(
                    "ses_lifecycle",
                    "dev",
                    "ws",
                    "owner_a",
                    1,
                    unix_now() + 60,
                    unix_now() + 600,
                )
                .unwrap(),
                shell_command(),
                PtySize::default(),
            )
            .await
            .unwrap();
        let detached = state
            .detach_idempotent(&active, 2, "tr_detach", "d_detach")
            .await
            .unwrap();
        assert!(state.write(&detached, b"no").await.is_err());
        assert_eq!(
            detached,
            state
                .detach_idempotent(&active, 2, "tr_detach", "d_detach")
                .await
                .unwrap()
        );
        let claimed = state
            .claim_idempotent(
                &detached,
                "owner_b",
                3,
                unix_now() + 60,
                "tr_claim",
                "d_claim",
            )
            .await
            .unwrap();
        let renewed = state
            .renew_idempotent(&claimed, unix_now() + 60, "tr_renew", "d_renew")
            .await
            .unwrap();
        assert_ne!(renewed.host_nonce, claimed.host_nonce);
        assert!(state.write(&claimed, b"stale").await.is_err());
        assert_eq!(
            renewed,
            state
                .renew_idempotent(&claimed, unix_now() + 60, "tr_renew", "d_renew")
                .await
                .unwrap()
        );
        state.terminate(&renewed).await.unwrap();
    }

    #[tokio::test]
    async fn terminate_receipt_survives_reply_loss_and_rejects_stale_or_conflicting_replay() {
        let root = tempdir().unwrap();
        let state = SupervisorState::new(root.path());
        let binding = state
            .spawn(
                HostManifest::new(
                    "ses_terminal",
                    "dev",
                    "ws",
                    "owner_a",
                    1,
                    unix_now() + 60,
                    unix_now() + 600,
                )
                .unwrap(),
                shell_command(),
                PtySize::default(),
            )
            .await
            .unwrap();
        state
            .terminate_idempotent(&binding, "tr_terminate", "digest_terminal")
            .await
            .unwrap();
        // This is the reply-loss/restart path: the in-memory host is gone but
        // the owner-only tombstone returns the same success exactly once.
        state
            .terminate_idempotent(&binding, "tr_terminate", "digest_terminal")
            .await
            .unwrap();
        assert!(state
            .terminate_idempotent(&binding, "tr_terminate", "other_digest")
            .await
            .is_err());
        let mut stale_binding = binding.clone();
        stale_binding.host_nonce = "host_stale".into();
        assert!(state
            .terminate_idempotent(&stale_binding, "tr_terminate", "digest_terminal")
            .await
            .is_err());
    }

    fn shell_command() -> PtyCommand {
        PtyCommand {
            program: if cfg!(windows) {
                "cmd.exe".into()
            } else {
                "/bin/sh".into()
            },
            args: vec![],
            cwd: None,
            env: vec![],
        }
    }
}
