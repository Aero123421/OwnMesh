//! systemd journal (journald) provider.
//!
//! On Linux this shells out to `journalctl` (same data plane as sd-journal).
//! Off Linux a stub is registered so cfg-gated wiring tests stay green.
//!
//! Official references:
//! - sd-journal API: https://www.freedesktop.org/software/systemd/man/latest/sd-journal.html
//! - journalctl(1): https://www.man7.org/linux/man-pages/man1/journalctl.1.html

#[cfg(target_os = "linux")]
use crate::page_from_lines;
use crate::{check_cursor, LogCursor, LogError, LogPage, LogProvider, LogResult};
#[cfg(target_os = "linux")]
use std::process::Command;

/// Default provider id used by ownmeshd.
#[allow(dead_code)]
pub const DEFAULT_ID: &str = "journald";

/// journald / systemd journal provider.
#[derive(Debug, Clone)]
pub struct JournaldLogProvider {
    id: String,
    /// Optional systemd unit filter (`--unit=`).
    unit: Option<String>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fetch_cap: usize,
}

impl JournaldLogProvider {
    #[must_use]
    pub fn new(id: impl Into<String>, unit: Option<String>) -> Self {
        Self {
            id: id.into(),
            unit,
            fetch_cap: 200,
        }
    }

    #[must_use]
    pub fn system() -> Self {
        Self::new(DEFAULT_ID, None)
    }

    #[must_use]
    pub fn unit(&self) -> Option<&str> {
        self.unit.as_deref()
    }

    /// Whether this build can talk to a real journald.
    #[must_use]
    pub fn is_native() -> bool {
        cfg!(target_os = "linux")
    }
}

impl LogProvider for JournaldLogProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn query(&self, cursor: Option<&LogCursor>, limit: usize) -> LogResult<LogPage> {
        let start = check_cursor(&self.id, cursor)?;
        #[cfg(target_os = "linux")]
        {
            let need = start as usize + limit.max(1);
            let fetch_n = need.max(1).min(self.fetch_cap);
            let lines = fetch_journalctl(self.unit.as_deref(), fetch_n)?;
            Ok(page_from_lines(&self.id, &lines, start, limit))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (start, limit);
            Err(LogError::Unavailable(
                "journald provider requires Linux (systemd journal)".into(),
            ))
        }
    }
}

#[cfg(target_os = "linux")]
fn fetch_journalctl(unit: Option<&str>, count: usize) -> LogResult<Vec<String>> {
    let mut cmd = Command::new("journalctl");
    cmd.args([
        "--no-pager",
        "-o",
        "short-iso",
        "-n",
        &count.max(1).to_string(),
    ]);
    if let Some(u) = unit {
        let safe: String = u
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':'))
            .collect();
        if !safe.is_empty() {
            cmd.arg("--unit").arg(safe);
        }
    }
    let output = cmd
        .output()
        .map_err(|e| LogError::Backend(format!("spawn journalctl: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(LogError::Backend(format!(
            "journalctl failed ({}): {}",
            output.status,
            stderr.trim()
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_owned)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_id_stable() {
        let p = JournaldLogProvider::system();
        assert_eq!(p.id(), DEFAULT_ID);
        assert_eq!(JournaldLogProvider::is_native(), cfg!(target_os = "linux"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn journald_unavailable_off_linux() {
        let p = JournaldLogProvider::system();
        let err = p.query(None, 1).unwrap_err();
        assert!(matches!(err, LogError::Unavailable(_)), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn journald_live_or_backend_error() {
        let p = JournaldLogProvider::system();
        match p.query(None, 3) {
            Ok(page) => {
                assert!(page.lines.len() <= 3);
            }
            Err(LogError::Backend(_)) => {
                // Container CI without journal socket is fine.
            }
            Err(e) => panic!("unexpected: {e}"),
        }
    }
}
