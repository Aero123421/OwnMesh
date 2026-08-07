//! Windows Event Log provider.
//!
//! Uses `wevtutil qe` (Windows Event Log command-line) so the crate stays
//! `forbid(unsafe_code)`. Official surface:
//! - Windows Event Log API overview:
//!   <https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log>
//! - wevtutil query-events:
//!   <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil>

use crate::{check_cursor, page_from_lines, LogCursor, LogError, LogPage, LogProvider, LogResult};
#[cfg(windows)]
use std::process::Command;

/// Default provider id used by ownmeshd.
#[allow(dead_code)]
pub const DEFAULT_ID: &str = "windows_event";

/// Windows Event Log provider backed by `wevtutil`.
#[derive(Debug, Clone)]
pub struct WindowsEventLogProvider {
    id: String,
    /// Event channel / log name (e.g. `Application`, `System`).
    channel: String,
    /// Max events fetched from the OS before local cursor paging.
    fetch_cap: usize,
}

impl WindowsEventLogProvider {
    #[must_use]
    pub fn new(id: impl Into<String>, channel: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            channel: channel.into(),
            fetch_cap: 200,
        }
    }

    #[must_use]
    pub fn application() -> Self {
        Self::new(DEFAULT_ID, "Application")
    }

    #[must_use]
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// Reads events via `wevtutil`. Public for live integration tests.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform does not provide Windows Event Log
    /// access or when `wevtutil` cannot query the configured channel.
    pub fn fetch_events(&self, count: usize) -> LogResult<Vec<String>> {
        #[cfg(windows)]
        {
            fetch_wevtutil(&self.channel, count)
        }
        #[cfg(not(windows))]
        {
            let _ = count;
            Err(LogError::Unavailable(
                "Windows Event Log provider is only available on Windows".into(),
            ))
        }
    }
}

impl LogProvider for WindowsEventLogProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn query(&self, cursor: Option<&LogCursor>, limit: usize) -> LogResult<LogPage> {
        let start = check_cursor(&self.id, cursor)?;
        let need = usize::try_from(start)
            .unwrap_or(usize::MAX)
            .saturating_add(limit.max(1));
        let fetch_n = need.max(1).min(self.fetch_cap);
        let events = self.fetch_events(fetch_n)?;
        Ok(page_from_lines(&self.id, &events, start, limit))
    }
}

#[cfg(windows)]
fn fetch_wevtutil(channel: &str, count: usize) -> LogResult<Vec<String>> {
    // Invoke through cmd.exe so quoting matches the documented CLI
    // (`wevtutil qe <Path> /c:<Count> /rd:true /f:text`).
    let cmdline = format!(
        "wevtutil qe {} /c:{} /rd:true /f:text",
        sanitize_channel(channel),
        count.max(1)
    );
    let output = Command::new("cmd.exe")
        .args(["/C", &cmdline])
        .output()
        .map_err(|e| LogError::Backend(format!("spawn wevtutil: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(LogError::Backend(format!(
            "wevtutil failed ({}): {}",
            output.status,
            stderr.trim()
        )));
    }
    // Windows console output may be OEM/ANSI; lossy UTF-8 is acceptable for logs.
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(split_wevtutil_events(&text))
}

#[cfg(any(test, windows))]
fn sanitize_channel(channel: &str) -> String {
    // Allow common channel names and path-like custom channels; drop shell metacharacters.
    channel
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/' | '.' | ' '))
        .collect()
}

/// Split wevtutil text format (`Event[n]` blocks) into one string per event.
#[cfg(any(test, windows))]
fn split_wevtutil_events(text: &str) -> Vec<String> {
    let mut events = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        if line.starts_with("Event[") && !current.trim().is_empty() {
            events.push(current.trim_end().to_string());
            current.clear();
        }
        if !current.is_empty() {
            current.push('\n');
        }
        current.push_str(line);
    }
    if !current.trim().is_empty() {
        events.push(current.trim_end().to_string());
    }
    // wevtutil /rd:true returns newest first; reverse for chronological cursor paging.
    events.reverse();
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_events_and_reverse() {
        let sample = "\
Event[0]
  Log Name: Application
  Event ID: 1
Event[1]
  Log Name: Application
  Event ID: 2
";
        let events = split_wevtutil_events(sample);
        assert_eq!(events.len(), 2);
        // After reverse, older Event[1] block comes first? Wait: Event[0] is newest
        // with /rd:true, so reverse → Event[1] then Event[0].
        assert!(events[0].contains("Event[1]"));
        assert!(events[1].contains("Event[0]"));
    }

    #[test]
    fn sanitize_strips_metacharacters() {
        assert_eq!(sanitize_channel("Application;rm"), "Applicationrm");
        assert_eq!(
            sanitize_channel("Microsoft-Windows-Foo/Operational"),
            "Microsoft-Windows-Foo/Operational"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_event_log_live_query() {
        let p = WindowsEventLogProvider::application();
        let page = p
            .query(None, 3)
            .expect("Application log must be readable via wevtutil on this host");
        assert!(
            !page.lines.is_empty(),
            "expected at least one Application event"
        );
        assert!(page.lines.len() <= 3);
        for line in &page.lines {
            assert!(
                line.text.contains("Event[") || line.text.contains("Log Name"),
                "unexpected event text: {}",
                &line.text[..line.text.len().min(80)]
            );
            assert_eq!(line.cursor_after.provider, DEFAULT_ID);
        }
        // Cursor continuation must not panic and must advance.
        if let Some(cur) = &page.next_cursor {
            let page2 = p.query(Some(cur), 2).unwrap();
            assert!(page2.lines.len() <= 2);
            if !page2.lines.is_empty() && !page.lines.is_empty() {
                assert_ne!(page2.lines[0].text, page.lines[0].text);
            }
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn windows_event_unavailable_off_windows() {
        let p = WindowsEventLogProvider::application();
        let err = p.query(None, 1).unwrap_err();
        assert!(matches!(err, LogError::Unavailable(_)));
    }
}
