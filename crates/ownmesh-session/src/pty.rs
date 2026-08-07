//! PTY / `ConPTY` abstraction types.
//!
//! Concrete backends live in `ownmesh-session-host` (`portable-pty` wraps
//! Windows `ConPTY` / POSIX `openpty`). This module defines the cross-crate contract.
//!
//! References:
//! - `ConPTY`: <https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session>
//! - `CreatePseudoConsole`: <https://learn.microsoft.com/en-us/windows/console/createpseudoconsole>

use serde::{Deserialize, Serialize};

/// Hint for ring-buffer sizing (~64 MiB default per spec §12.6).
pub const DEFAULT_REPLAY_BYTES_HINT: usize = 64 * 1024 * 1024;

/// Terminal geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtySize {
    pub cols: u16,
    pub rows: u16,
}

impl Default for PtySize {
    fn default() -> Self {
        Self { cols: 80, rows: 24 }
    }
}

/// Raw vs cooked view preference for clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PtyViewMode {
    #[default]
    Raw,
    Cooked,
}

/// Which OS PTY backend is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PtyBackend {
    /// Windows Pseudoconsole (`ConPTY`).
    ConPty,
    /// POSIX openpty /pts.
    PosixPty,
    /// Process pipes without a real TTY (fallback).
    PipeFallback,
}

impl PtyBackend {
    /// Backend preferred on this compile target.
    #[must_use]
    pub fn preferred() -> Self {
        if cfg!(windows) {
            Self::ConPty
        } else {
            Self::PosixPty
        }
    }
}

/// Command to spawn inside a PTY.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PtyCommand {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
}

/// Handle metadata returned by a session host after spawn.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionHostHandle {
    pub session_id: String,
    pub backend: PtyBackend,
    pub pid: Option<u32>,
    pub cols: u16,
    pub rows: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferred_backend_is_platform() {
        let b = PtyBackend::preferred();
        if cfg!(windows) {
            assert_eq!(b, PtyBackend::ConPty);
        } else {
            assert_eq!(b, PtyBackend::PosixPty);
        }
    }
}
