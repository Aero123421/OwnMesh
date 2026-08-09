//! Windows-specific privileged-broker daemon trust boundary.
//!
//! This module intentionally contains no process spawn or pipe accept loop.
//! It turns a root/Admin-custodied installation record plus kernel-attested
//! named-pipe facts into an authorization decision.  The later pipe handler
//! must call [`WindowsTrustedDaemon::authorize_peer`] immediately after its
//! first frame and again immediately before staging/spawning an action.

use ownmesh_ipc::{windows_running_service_facts, WindowsPipePeerFacts};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAX_TRUST_RECORD_BYTES: u64 = 64 * 1024;

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
