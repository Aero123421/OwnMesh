//! Process log provider.
//!
//! Reads a process-captured stdout/stderr log file (written by session host /
//! exec spool). Shares the same line-offset cursor contract as other providers.
//! Optional `pid` is metadata only — never used to kill or signal.

use crate::file::FileLogProvider;
use crate::{LogCursor, LogPage, LogProvider, LogResult};
use std::path::{Path, PathBuf};

/// Default provider id.
#[allow(dead_code)]
pub const DEFAULT_ID: &str = "process";

/// Process output log provider (file-backed with process metadata).
#[derive(Debug, Clone)]
pub struct ProcessLogProvider {
    inner: FileLogProvider,
    pid: Option<u32>,
    label: Option<String>,
}

impl ProcessLogProvider {
    #[must_use]
    pub fn new(id: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            inner: FileLogProvider::new(id, path),
            pid: None,
            label: None,
        }
    }

    #[must_use]
    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }
}

impl LogProvider for ProcessLogProvider {
    fn id(&self) -> &str {
        self.inner.id()
    }

    fn query(&self, cursor: Option<&LogCursor>, limit: usize) -> LogResult<LogPage> {
        // Reuse file byte-offset cursor; prefix each line with process metadata.
        let mut page = self.inner.query(cursor, limit)?;
        if self.pid.is_some() || self.label.is_some() {
            let prefix = match (self.pid, self.label.as_deref()) {
                (Some(pid), Some(label)) => format!("[pid={pid} {label}] "),
                (Some(pid), None) => format!("[pid={pid}] "),
                (None, Some(label)) => format!("[{label}] "),
                (None, None) => String::new(),
            };
            for line in &mut page.lines {
                line.text = format!("{prefix}{}", line.text);
            }
        }
        Ok(page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn process_provider_pages_with_metadata() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("proc.log");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "out-1").unwrap();
            writeln!(f, "out-2").unwrap();
        }
        let p = ProcessLogProvider::new("process", &path)
            .with_pid(4242)
            .with_label("worker");
        let page = p.query(None, 10).unwrap();
        assert_eq!(page.lines.len(), 2);
        assert!(page.lines[0].text.contains("pid=4242"));
        assert!(page.lines[0].text.contains("worker"));
        assert!(page.lines[0].text.contains("out-1"));
        assert!(page.exhausted);
    }
}
