//! Platform endpoint paths for the local IPC bus.

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
                    acc = acc.wrapping_mul(0x0100_0000_01b3).wrapping_add(u64::from(*b));
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
}
