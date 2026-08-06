//! File-backed log provider (byte-offset cursor).

use crate::{LogCursor, LogError, LogLine, LogPage, LogProvider, LogResult};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

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
        let start = cursor.map_or(0, |c| c.offset);
        file.seek(SeekFrom::Start(start))?;
        let reader = BufReader::new(file);
        let mut lines = Vec::new();
        let mut offset = start;
        for (line_index, line_res) in reader.lines().enumerate() {
            let text = line_res?;
            // +1 for newline approximation
            offset += text.len() as u64 + 1;
            lines.push(LogLine {
                line_no: u64::try_from(line_index)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
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
