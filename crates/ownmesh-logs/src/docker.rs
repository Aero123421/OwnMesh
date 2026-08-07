//! Docker / Podman container log provider.
//!
//! Shells out to `docker logs` (or `podman logs` fallback). Compiles on all
//! targets; queries fail with `Unavailable` when no runtime is present.
//! Cursor is a line offset into the fetched tail.

use crate::{check_cursor, page_from_lines, LogCursor, LogError, LogPage, LogProvider, LogResult};
use std::process::Command;

/// Default provider id.
#[allow(dead_code)]
pub const DEFAULT_ID: &str = "docker";

/// Docker/Podman logs provider.
#[derive(Debug, Clone)]
pub struct DockerLogProvider {
    id: String,
    /// Container name or id. When `None`, query returns Unavailable.
    container: Option<String>,
    /// Override binary for tests (`docker`, `podman`, or a mock script).
    binary: Option<String>,
    fetch_cap: usize,
}

impl DockerLogProvider {
    #[must_use]
    pub fn new(id: impl Into<String>, container: Option<String>) -> Self {
        Self {
            id: id.into(),
            container,
            binary: None,
            fetch_cap: 200,
        }
    }

    #[must_use]
    pub fn with_binary(mut self, binary: impl Into<String>) -> Self {
        self.binary = Some(binary.into());
        self
    }

    #[must_use]
    pub fn container(&self) -> Option<&str> {
        self.container.as_deref()
    }
}

impl LogProvider for DockerLogProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn query(&self, cursor: Option<&LogCursor>, limit: usize) -> LogResult<LogPage> {
        let start = check_cursor(&self.id, cursor)?;
        let Some(container) = self.container.as_deref() else {
            return Err(LogError::Unavailable(
                "docker provider has no container configured".into(),
            ));
        };
        let safe: String = container
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'))
            .collect();
        if safe.is_empty() {
            return Err(LogError::Backend("invalid container name".into()));
        }
        let need = usize::try_from(start)
            .unwrap_or(usize::MAX)
            .saturating_add(limit.max(1));
        let fetch_n = need.max(1).min(self.fetch_cap);
        let lines = fetch_container_logs(self.binary.as_deref(), &safe, fetch_n)?;
        Ok(page_from_lines(&self.id, &lines, start, limit))
    }
}

fn fetch_container_logs(
    binary: Option<&str>,
    container: &str,
    count: usize,
) -> LogResult<Vec<String>> {
    let candidates: Vec<&str> = match binary {
        Some(b) => vec![b],
        None => vec!["docker", "podman"],
    };
    let mut last_err = LogError::Unavailable("no container runtime found".into());
    for bin in candidates {
        match run_logs(bin, container, count) {
            Ok(lines) => return Ok(lines),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn run_logs(bin: &str, container: &str, count: usize) -> LogResult<Vec<String>> {
    let output = Command::new(bin)
        .args(["logs", "--tail", &count.max(1).to_string(), container])
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                LogError::Unavailable(format!("{bin} not found"))
            } else {
                LogError::Backend(format!("spawn {bin}: {e}"))
            }
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(LogError::Backend(format!(
            "{bin} logs failed ({}): {}",
            output.status,
            stderr.trim()
        )));
    }
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    if text.is_empty() {
        text = String::from_utf8_lossy(&output.stderr).into_owned();
    }
    Ok(text
        .lines()
        .map(str::to_owned)
        .filter(|l| !l.is_empty())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    #[cfg(not(windows))]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn missing_container_is_unavailable() {
        let p = DockerLogProvider::new("docker", None);
        let err = p.query(None, 5).unwrap_err();
        assert!(matches!(err, LogError::Unavailable(_)), "{err}");
    }

    #[test]
    fn mock_binary_cursor_pages() {
        let dir = tempdir().unwrap();
        #[cfg(windows)]
        let bin = {
            let path = dir.path().join("mock-docker.cmd");
            // %* ignored; always print three lines.
            let mut f = fs::File::create(&path).unwrap();
            writeln!(f, "@echo line-a").unwrap();
            writeln!(f, "@echo line-b").unwrap();
            writeln!(f, "@echo line-c").unwrap();
            path.to_string_lossy().into_owned()
        };
        #[cfg(not(windows))]
        let bin = {
            let path = dir.path().join("mock-docker");
            let mut f = fs::File::create(&path).unwrap();
            writeln!(f, "#!/bin/sh").unwrap();
            writeln!(f, "echo line-a").unwrap();
            writeln!(f, "echo line-b").unwrap();
            writeln!(f, "echo line-c").unwrap();
            drop(f);
            let mut perms = fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&path, perms).unwrap();
            path.to_string_lossy().into_owned()
        };

        let p = DockerLogProvider::new("docker", Some("ctr".into())).with_binary(bin);
        let page1 = p.query(None, 2).unwrap();
        assert_eq!(page1.lines.len(), 2);
        assert_eq!(page1.lines[0].text, "line-a");
        assert!(!page1.exhausted);
        let page2 = p.query(page1.next_cursor.as_ref(), 5).unwrap();
        assert_eq!(page2.lines.len(), 1);
        assert_eq!(page2.lines[0].text, "line-c");
        assert!(page2.exhausted);
    }
}
