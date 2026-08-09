//! In-process state behind the persistent local session-supervisor IPC service.

use crate::{HostManifest, LiveHost, OwnerSpool, SpoolPage};
use ownmesh_session::{PtyCommand, PtySize};
use std::collections::HashMap;
use std::path::Path;
use tokio::sync::Mutex;

const MAX_STDIN_BYTES: usize = 64 * 1024;
const MAX_HOSTS: usize = 64;

/// Exact host attachment facts supplied by the authenticated daemon client.
#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Bounded supervisor host map. Dropping this value does not terminate hosts;
/// only explicit `terminate` owns tree cleanup. The sidecar process itself owns
/// its lifecycle independently from a disconnected daemon client.
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
        let mut hosts = self.hosts.lock().await;
        if hosts.len() >= MAX_HOSTS {
            return Err("supervisor host quota reached".into());
        }
        if hosts.contains_key(&manifest.session_id) {
            return Err("supervisor host already live".into());
        }
        let spool = OwnerSpool::create(&self.root, manifest.clone())?;
        let host = LiveHost::spawn(&command, size)?;
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
        let (text, truncated, _, _, _) = hosted.host.drain_output(max_bytes)?;
        if !text.is_empty() {
            hosted.spool.append(text.as_bytes())?;
        }
        let mut page = hosted.spool.read_page(offset, max_bytes)?;
        page.truncated |= truncated;
        Ok(page)
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
    if binding.matches(manifest) {
        Ok(())
    } else {
        Err("supervisor binding mismatch".into())
    }
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
            2_000_000_000,
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
}
