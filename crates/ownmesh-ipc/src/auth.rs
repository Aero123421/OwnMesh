//! Peer authentication and ACL helpers for local IPC.

use crate::error::{IpcError, IpcResult};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Filename used under the runtime directory for the daemon auth token.
pub const AUTH_TOKEN_FILE_NAME: &str = "daemon.token";

/// Material presented by a connecting peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCredential {
    /// Shared secret issued by the daemon.
    pub token: String,
    /// Connecting client label.
    pub client_name: String,
    /// Optional OS user id when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_user_id: Option<String>,
    /// Optional process id of the peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

/// Expected ACL material held by the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthGate {
    expected_token: String,
    /// When true, empty/missing tokens are rejected (default).
    require_token: bool,
}

impl AuthGate {
    /// Construct a gate with the expected shared token.
    #[must_use]
    pub fn new(expected_token: impl Into<String>) -> Self {
        Self {
            expected_token: expected_token.into(),
            require_token: true,
        }
    }

    /// Validate a peer credential.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::Unauthorized`] when the token does not match.
    pub fn verify(&self, peer: &PeerCredential) -> IpcResult<()> {
        if !self.require_token {
            return Ok(());
        }
        if peer.token.is_empty() {
            return Err(IpcError::Unauthorized(
                "missing ipc authentication token".into(),
            ));
        }
        if peer.token != self.expected_token {
            return Err(IpcError::Unauthorized(
                "ipc authentication token mismatch".into(),
            ));
        }
        if peer.client_name.trim().is_empty() {
            return Err(IpcError::Unauthorized("missing client_name".into()));
        }
        Ok(())
    }

    /// Borrow the expected token (for tests / diagnostics; do not log).
    #[must_use]
    pub fn token(&self) -> &str {
        &self.expected_token
    }
}

/// Generate a high-entropy auth token (hex).
#[must_use]
pub fn generate_token() -> String {
    let mut raw = [0_u8; 32];
    // Prefer OS randomness via UUID clock + process entropy mix without extra deps.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    for (idx, slot) in raw.iter_mut().enumerate() {
        let mix = now
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(u128::from(pid) << 32)
            .wrapping_add(idx as u128 * 0xA24B_AED4_96E9_23FD);
        *slot = (mix ^ (mix >> 8) ^ (mix >> 16)) as u8;
    }
    // Overlay with uuid bytes for stronger uniqueness.
    let u = uuid::Uuid::new_v4();
    for (dst, src) in raw.iter_mut().zip(u.as_bytes().iter().cycle()) {
        *dst ^= *src;
    }
    hex_encode(&raw)
}

/// Persist the daemon token into `runtime_dir/daemon.token` with restrictive permissions.
///
/// # Errors
///
/// Returns IO errors when the directory/file cannot be written.
pub fn write_token_file(runtime_dir: &Path, token: &str) -> IpcResult<PathBuf> {
    fs::create_dir_all(runtime_dir)?;
    let path = runtime_dir.join(AUTH_TOKEN_FILE_NAME);
    let tmp = runtime_dir.join(format!("{AUTH_TOKEN_FILE_NAME}.tmp"));
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(token.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    restrict_file_mode(&path)?;
    Ok(path)
}

/// Read a previously written token file.
///
/// # Errors
///
/// Returns IO / framing errors when the file is missing or empty.
pub fn read_token_file(runtime_dir: &Path) -> IpcResult<String> {
    let path = runtime_dir.join(AUTH_TOKEN_FILE_NAME);
    let raw = fs::read_to_string(&path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            IpcError::Disconnected(format!(
                "daemon token not found at {} (is ownmeshd running?)",
                path.display()
            ))
        } else {
            IpcError::Io(err)
        }
    })?;
    let token = raw.trim().to_owned();
    if token.is_empty() {
        return Err(IpcError::Protocol("daemon token file is empty".into()));
    }
    Ok(token)
}

/// Best-effort restrictive mode for token / socket files.
fn restrict_file_mode(path: &Path) -> IpcResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    #[cfg(windows)]
    {
        // Named-pipe ACL is enforced on the pipe itself; the token file inherits the
        // user profile ACL. No extra chmod equivalent is required here.
        let _ = path;
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Redact secrets from a free-form log/message string for defensive logging.
#[must_use]
pub fn redact_secrets(input: &str, secrets: &[&str]) -> String {
    let mut out = input.to_owned();
    for secret in secrets {
        if secret.is_empty() {
            continue;
        }
        if out.contains(secret) {
            out = out.replace(secret, "[REDACTED]");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn token_roundtrip_file() {
        let dir = tempdir().unwrap();
        let token = generate_token();
        write_token_file(dir.path(), &token).unwrap();
        let loaded = read_token_file(dir.path()).unwrap();
        assert_eq!(loaded, token);
    }

    #[test]
    fn auth_gate_rejects_bad_token() {
        let gate = AuthGate::new("correct-token");
        let bad = PeerCredential {
            token: "wrong".into(),
            client_name: "ownmesh".into(),
            os_user_id: None,
            pid: None,
        };
        let err = gate.verify(&bad).unwrap_err();
        assert_eq!(err.code(), "ipc_unauthorized");
    }

    #[test]
    fn redact_hides_token() {
        let msg = "token=super-secret value";
        assert_eq!(
            redact_secrets(msg, &["super-secret"]),
            "token=[REDACTED] value"
        );
    }
}
