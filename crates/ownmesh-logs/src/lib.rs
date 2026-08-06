//! `OwnMesh` log providers and cursor-based queries.
//!
//! Providers share one contract: opaque `LogCursor` + page limit → `LogPage`.
//! Platform backends (Windows Event Log, journald) are cfg-gated; Docker and
//! process providers compile everywhere and degrade cleanly when tools are absent.

mod docker;
mod file;
mod journald;
mod process;
mod registry;
mod windows_event;

pub use docker::DockerLogProvider;
pub use file::FileLogProvider;
pub use journald::JournaldLogProvider;
pub use process::ProcessLogProvider;
pub use registry::{register_builtin_providers, BuiltinProviderConfig, LogRegistry};
pub use windows_event::WindowsEventLogProvider;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable crate name used by diagnostics and tests.
#[must_use]
pub const fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

/// Crate version string from Cargo package metadata.
#[must_use]
pub const fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Log errors.
#[derive(Debug, Error)]
pub enum LogError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid cursor: {0}")]
    InvalidCursor(String),
    #[error("provider not found: {0}")]
    ProviderNotFound(String),
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    #[error("backend: {0}")]
    Backend(String),
}

pub type LogResult<T> = Result<T, LogError>;

/// Opaque cursor (byte/line/event offset for the named provider).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogCursor {
    pub provider: String,
    pub offset: u64,
}

/// One log line.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogLine {
    pub line_no: u64,
    pub text: String,
    pub cursor_after: LogCursor,
}

/// Query result page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogPage {
    pub lines: Vec<LogLine>,
    pub next_cursor: Option<LogCursor>,
    pub exhausted: bool,
}

/// Provider trait.
pub trait LogProvider: Send + Sync {
    fn id(&self) -> &str;

    /// Queries up to `limit` log lines after `cursor`.
    ///
    /// # Errors
    ///
    /// Returns an error when the cursor is invalid or the provider cannot query
    /// its backing log source.
    fn query(&self, cursor: Option<&LogCursor>, limit: usize) -> LogResult<LogPage>;
}

/// Provider ids that the current target can wire into a registry.
#[must_use]
pub fn platform_provider_ids() -> Vec<&'static str> {
    let mut ids = vec!["file", "docker", "process"];
    #[cfg(windows)]
    ids.push("windows_event");
    #[cfg(target_os = "linux")]
    ids.push("journald");
    #[cfg(not(target_os = "linux"))]
    {
        // Still advertise the cfg-gated id for documentation/wiring tests on
        // non-Linux hosts — registration inserts a stub that reports Unavailable.
        ids.push("journald");
    }
    ids
}

/// Shared cursor validation helper.
pub(crate) fn check_cursor(id: &str, cursor: Option<&LogCursor>) -> LogResult<u64> {
    match cursor {
        None => Ok(0),
        Some(c) if c.provider == id => Ok(c.offset),
        Some(c) => Err(LogError::InvalidCursor(format!(
            "provider mismatch: {} != {id}",
            c.provider
        ))),
    }
}

/// Build a page from a slice of text lines starting at absolute `start` offset.
pub(crate) fn page_from_lines(id: &str, all_lines: &[String], start: u64, limit: usize) -> LogPage {
    let Ok(start_idx) = usize::try_from(start) else {
        return LogPage {
            lines: vec![],
            next_cursor: None,
            exhausted: true,
        };
    };
    if start_idx >= all_lines.len() || limit == 0 {
        return LogPage {
            lines: vec![],
            next_cursor: None,
            exhausted: true,
        };
    }
    let end = start_idx.saturating_add(limit).min(all_lines.len());
    let mut lines = Vec::with_capacity(end - start_idx);
    for (i, text) in all_lines[start_idx..end].iter().enumerate() {
        let offset = start + i as u64 + 1;
        lines.push(LogLine {
            line_no: offset,
            text: text.clone(),
            cursor_after: LogCursor {
                provider: id.to_string(),
                offset,
            },
        });
    }
    let exhausted = end >= all_lines.len();
    let next_cursor = lines.last().map(|l| l.cursor_after.clone());
    LogPage {
        lines,
        next_cursor,
        exhausted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn file_provider_cursor_pages() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("app.log");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "line1").unwrap();
            writeln!(f, "line2").unwrap();
            writeln!(f, "line3").unwrap();
        }
        let p = FileLogProvider::new("app", &path);
        let page1 = p.query(None, 2).unwrap();
        assert_eq!(page1.lines.len(), 2);
        assert!(!page1.exhausted);
        let page2 = p.query(page1.next_cursor.as_ref(), 2).unwrap();
        assert_eq!(page2.lines.len(), 1);
        assert!(page2.exhausted);
        assert_eq!(page2.lines[0].text, "line3");
    }

    #[test]
    fn registry_wires_platform_providers() {
        let dir = tempdir().unwrap();
        let audit = dir.path().join("audit.log");
        std::fs::write(&audit, b"a\nb\n").unwrap();
        let proc_log = dir.path().join("proc.log");
        std::fs::write(&proc_log, b"p1\np2\n").unwrap();

        let mut reg = LogRegistry::new();
        register_builtin_providers(
            &mut reg,
            &BuiltinProviderConfig {
                file_id: "audit".into(),
                file_path: audit.clone(),
                windows_channel: "Application".into(),
                journald_unit: None,
                docker_container: Some("ownmesh-test".into()),
                process_id: "process".into(),
                process_log_path: Some(proc_log.clone()),
            },
        );

        let ids = reg.list_ids();
        assert!(ids.iter().any(|i| i == "audit"), "{ids:?}");
        assert!(ids.iter().any(|i| i == "docker"), "{ids:?}");
        assert!(ids.iter().any(|i| i == "process"), "{ids:?}");
        assert!(ids.iter().any(|i| i == "journald"), "{ids:?}");
        #[cfg(windows)]
        assert!(ids.iter().any(|i| i == "windows_event"), "{ids:?}");

        // File + process must answer the shared cursor contract.
        let file_page = reg.get("audit").unwrap().query(None, 10).unwrap();
        assert_eq!(file_page.lines.len(), 2);
        assert!(file_page.exhausted);

        let proc_page = reg.get("process").unwrap().query(None, 1).unwrap();
        assert_eq!(proc_page.lines.len(), 1);
        assert!(!proc_page.exhausted);
        let proc_page2 = reg
            .get("process")
            .unwrap()
            .query(proc_page.next_cursor.as_ref(), 10)
            .unwrap();
        assert_eq!(proc_page2.lines.len(), 1);
        assert!(proc_page2.exhausted);

        // journald is wired; on non-Linux it reports unavailable rather than missing.
        let j = reg.get("journald").unwrap();
        match j.query(None, 5) {
            Ok(page) => {
                // Linux with journalctl may return zero or more lines.
                assert!(page.lines.len() <= 5);
            }
            Err(LogError::Unavailable(_)) if cfg!(target_os = "linux") => {
                panic!("linux journald should not be hard-unavailable without attempting query");
            }
            Err(LogError::Unavailable(_) | LogError::Backend(_)) => {
                // Unsupported hosts, a missing journalctl, or denied permission are acceptable.
            }
            Err(e) => panic!("unexpected journald error: {e}"),
        }

        // Docker may be absent; still registered.
        let d = reg.get("docker").unwrap();
        let _ = d.query(None, 5);
    }

    #[test]
    fn platform_provider_ids_lists_expected() {
        let ids = platform_provider_ids();
        assert!(ids.contains(&"file"));
        assert!(ids.contains(&"docker"));
        assert!(ids.contains(&"process"));
        assert!(ids.contains(&"journald"));
        #[cfg(windows)]
        assert!(ids.contains(&"windows_event"));
    }

    #[test]
    fn page_from_lines_cursor_contract() {
        let lines = vec!["a".into(), "b".into(), "c".into()];
        let p1 = page_from_lines("x", &lines, 0, 2);
        assert_eq!(p1.lines.len(), 2);
        assert!(!p1.exhausted);
        assert_eq!(p1.next_cursor.as_ref().unwrap().offset, 2);
        let p2 = page_from_lines("x", &lines, 2, 2);
        assert_eq!(p2.lines.len(), 1);
        assert!(p2.exhausted);
        assert_eq!(p2.lines[0].text, "c");
    }
}
