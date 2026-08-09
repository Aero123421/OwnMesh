//! In-process state behind the persistent local session-supervisor IPC service.

use crate::{HostManifest, LiveHost, OwnerSpool, SpoolPage};
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
    host: LiveHost,
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
        let host = LiveHost::spawn(&command, size)?;
        // Do not reserve durable identity until a PTY exists. If custody/spool
        // creation fails, dropping this newly spawned host cleans its tree.
        let spool = OwnerSpool::create(&self.root, manifest.clone())?;
        let binding = binding_of(&manifest);
        hosts.insert(
            manifest.session_id.clone(),
            Hosted {
                manifest,
                spool,
                host,
            },
        );
        Ok(binding)
    }

    pub async fn reattach(&self, binding: &SupervisorBinding) -> Result<SupervisorStatus, String> {
        let hosts = self.hosts.lock().await;
        let hosted = hosts
            .get(&binding.session_id)
            .ok_or("supervisor host unavailable")?;
        exact(binding, &hosted.manifest)?;
        Ok(status(&hosted.host))
    }

    pub async fn write(&self, binding: &SupervisorBinding, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() > MAX_STDIN_BYTES {
            return Err("supervisor stdin frame exceeds budget".into());
        }
        let hosts = self.hosts.lock().await;
        let hosted = hosts
            .get(&binding.session_id)
            .ok_or("supervisor host unavailable")?;
        exact(binding, &hosted.manifest)?;
        hosted.host.write_stdin(bytes)
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
    ) -> Result<SpoolPage, String> {
        let hosts = self.hosts.lock().await;
        let hosted = hosts
            .get(&binding.session_id)
            .ok_or("supervisor host unavailable")?;
        exact(binding, &hosted.manifest)?;
        let (bytes, truncated, _, _, _) = hosted.host.drain_output_bytes(max_bytes)?;
        if !bytes.is_empty() {
            hosted.spool.append(&bytes)?;
        }
        let mut page = hosted.spool.read_page(offset, max_bytes)?;
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

    pub async fn terminate(&self, binding: &SupervisorBinding) -> Result<(), String> {
        let mut hosts = self.hosts.lock().await;
        let hosted = hosts
            .get(&binding.session_id)
            .ok_or("supervisor host unavailable")?;
        exact(binding, &hosted.manifest)?;
        let mut hosted = hosts
            .remove(&binding.session_id)
            .ok_or("supervisor host unavailable")?;
        hosted.host.terminate()
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
    let now = unix_now();
    if manifest.binding_expires_unix <= now {
        return Err("supervisor binding expired".into());
    }
    if binding.matches(manifest) {
        Ok(())
    } else {
        Err("supervisor binding mismatch".into())
    }
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
