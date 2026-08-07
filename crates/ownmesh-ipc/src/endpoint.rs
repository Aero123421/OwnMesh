//! Platform endpoint paths for the local IPC bus.

use crate::{IpcError, IpcResult};
use std::path::{Path, PathBuf};

/// Logical IPC bus kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcBus {
    /// User-level `ownmeshd` bus used by CLI/TUI/session-host.
    Daemon,
    /// Privileged broker bus (separate endpoint; not opened by default here).
    Privileged,
}

impl IpcBus {
    /// Stable file / pipe suffix.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Privileged => "privileged",
        }
    }
}

/// Fully resolved local IPC endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// Windows named pipe path (`\\.\pipe\...`).
    NamedPipe(String),
    /// Unix domain socket filesystem path.
    UnixSocket(PathBuf),
}

impl Endpoint {
    /// Render a human-readable endpoint string for status / logs.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::NamedPipe(name) => name.clone(),
            Self::UnixSocket(path) => path.display().to_string(),
        }
    }

    /// Resolve the daemon endpoint from `service_socket.path`, or use the default.
    ///
    /// Relative Unix paths are resolved beneath `runtime_dir`. Windows supports
    /// named-pipe overrides only (`pipe:name` or `\\.\pipe\name`); filesystem
    /// socket paths are rejected rather than silently ignored.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for an empty override or an unsupported Windows path.
    pub fn configured_daemon(runtime_dir: &Path, configured_path: Option<&str>) -> IpcResult<Self> {
        let Some(raw) = configured_path else {
            return Ok(Self::default_for(runtime_dir, IpcBus::Daemon));
        };
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(IpcError::Protocol(
                "service_socket.path must not be empty when configured".into(),
            ));
        }
        #[cfg(unix)]
        {
            let path = PathBuf::from(raw);
            return Ok(Self::UnixSocket(if path.is_absolute() {
                path
            } else {
                runtime_dir.join(path)
            }));
        }
        #[cfg(windows)]
        {
            if let Some(name) = raw.strip_prefix("pipe:") {
                if name.trim().is_empty() {
                    return Err(IpcError::Protocol(
                        "service_socket.path pipe name must not be empty".into(),
                    ));
                }
                return Ok(Self::NamedPipe(if name.starts_with(r"\\.\pipe\") {
                    name.to_owned()
                } else {
                    format!(r"\\.\pipe\{name}")
                }));
            }
            if raw.starts_with(r"\\.\pipe\") {
                return Ok(Self::NamedPipe(raw.to_owned()));
            }
            Err(IpcError::Protocol(format!(
                "service_socket.path '{raw}' is unsupported on Windows; use pipe:<name> or \\\\.\\pipe\\<name>"
            )))
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = runtime_dir;
            Err(IpcError::Protocol(
                "configured service_socket.path is unsupported on this platform".into(),
            ))
        }
    }

    /// Build the default endpoint for `bus` under `runtime_dir`.
    ///
    /// On Windows this returns a named pipe path scoped by the runtime directory
    /// fingerprint so concurrent test instances do not collide. On Unix it uses
    /// `{runtime_dir}/ownmesh-{bus}.sock`.
    #[must_use]
    pub fn default_for(runtime_dir: &Path, bus: IpcBus) -> Self {
        #[cfg(windows)]
        {
            // Include a stable fingerprint of the runtime path so parallel tests isolate.
            let raw = runtime_dir.to_string_lossy();
            let mut key: String = raw
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .take(40)
                .collect();
            if key.is_empty() {
                // Fallback: simple polynomial fingerprint of the full path bytes.
                let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
                for b in raw.as_bytes() {
                    acc = acc
                        .wrapping_mul(0x0100_0000_01b3)
                        .wrapping_add(u64::from(*b));
                }
                key = format!("{acc:016x}");
            }
            let name = format!(r"\\.\pipe\ownmesh-{}-{}", bus.suffix(), key);
            Self::NamedPipe(name)
        }
        #[cfg(not(windows))]
        {
            Self::UnixSocket(runtime_dir.join(format!("ownmesh-{}.sock", bus.suffix())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn default_endpoint_is_platform_specific() {
        let ep = Endpoint::default_for(Path::new("/tmp/ownmesh-test"), IpcBus::Daemon);
        let text = ep.display();
        assert!(text.contains("daemon") || text.contains("ownmesh"));
        let _ = PathBuf::from(text);
    }

    #[test]
    fn configured_daemon_uses_shared_platform_resolution() {
        let runtime = Path::new("runtime-root");
        #[cfg(unix)]
        assert_eq!(
            Endpoint::configured_daemon(runtime, Some("custom.sock")).unwrap(),
            Endpoint::UnixSocket(runtime.join("custom.sock"))
        );
        #[cfg(windows)]
        assert_eq!(
            Endpoint::configured_daemon(runtime, Some("pipe:custom")).unwrap(),
            Endpoint::NamedPipe(r"\\.\pipe\custom".into())
        );
        assert!(Endpoint::configured_daemon(runtime, Some("   ")).is_err());
    }
}
