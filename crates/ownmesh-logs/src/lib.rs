//! OwnMesh log providers and cursor-based queries.

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
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
}

pub type LogResult<T> = Result<T, LogError>;

/// Opaque cursor (byte offset for file provider).
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
    fn query(&self, cursor: Option<&LogCursor>, limit: usize) -> LogResult<LogPage>;
}

/// Simple rotating-friendly file tail provider.
#[derive(Debug, Clone)]
pub struct FileLogProvider {
    id: String,
    path: PathBuf,
}

impl FileLogProvider {
    #[must_use]
    pub fn new(id: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            id: id.into(),
            path: path.into(),
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl LogProvider for FileLogProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn query(&self, cursor: Option<&LogCursor>, limit: usize) -> LogResult<LogPage> {
        if let Some(c) = cursor {
            if c.provider != self.id {
                return Err(LogError::InvalidCursor(format!(
                    "provider mismatch: {} != {}",
                    c.provider, self.id
                )));
            }
        }
        if !self.path.exists() {
            return Ok(LogPage {
                lines: vec![],
                next_cursor: None,
                exhausted: true,
            });
        }
        let mut file = File::open(&self.path)?;
        let start = cursor.map(|c| c.offset).unwrap_or(0);
        file.seek(SeekFrom::Start(start))?;
        let reader = BufReader::new(file);
        let mut lines = Vec::new();
        let mut offset = start;
        let mut line_no = 0u64;
        for line_res in reader.lines() {
            let text = line_res?;
            // +1 for newline approximation
            offset += text.len() as u64 + 1;
            line_no += 1;
            lines.push(LogLine {
                line_no,
                text,
                cursor_after: LogCursor {
                    provider: self.id.clone(),
                    offset,
                },
            });
            if lines.len() >= limit {
                break;
            }
        }
        let exhausted = lines.len() < limit;
        let next_cursor = lines.last().map(|l| l.cursor_after.clone());
        Ok(LogPage {
            lines,
            next_cursor,
            exhausted,
        })
    }
}

/// Registry of providers.
#[derive(Default)]
pub struct LogRegistry {
    providers: Vec<Box<dyn LogProvider>>,
}

impl LogRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    pub fn register(&mut self, provider: Box<dyn LogProvider>) {
        self.providers.push(provider);
    }

    pub fn get(&self, id: &str) -> LogResult<&dyn LogProvider> {
        self.providers
            .iter()
            .find(|p| p.id() == id)
            .map(|p| p.as_ref())
            .ok_or_else(|| LogError::ProviderNotFound(id.to_string()))
    }

    pub fn list_ids(&self) -> Vec<String> {
        self.providers.iter().map(|p| p.id().to_string()).collect()
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
            let mut f = File::create(&path).unwrap();
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
}
