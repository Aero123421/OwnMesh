//! Terminal setup / restore. Panic and normal exit must always restore the terminal.

use crossterm::event::{DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use std::io::{self, stdout, Stdout};
use std::sync::atomic::{AtomicBool, Ordering};

static RAW_ENABLED: AtomicBool = AtomicBool::new(false);
static ALTERNATE_ENABLED: AtomicBool = AtomicBool::new(false);
static BRACKETED_PASTE_ENABLED: AtomicBool = AtomicBool::new(false);
// Mouse capture stays off until full mouse navigation ships (issue #134):
// capturing input without usable hit-testing steals native terminal
// selection and scrolling from the user.
static MOUSE_CAPTURE_ENABLED: AtomicBool = AtomicBool::new(false);

/// Guard that restores the terminal when dropped.
pub struct TerminalGuard {
    restored: bool,
}

impl TerminalGuard {
    /// Enter raw mode + alternate screen and install a panic hook that restores.
    ///
    /// # Errors
    ///
    /// Returns crossterm IO errors.
    pub fn enter() -> io::Result<Self> {
        install_panic_hook();
        enable_raw_mode()?;
        RAW_ENABLED.store(true, Ordering::SeqCst);
        // Mark every potentially-partial terminal state before sending the
        // sequence so an error at any point can still be rolled back.
        ALTERNATE_ENABLED.store(true, Ordering::SeqCst);
        BRACKETED_PASTE_ENABLED.store(true, Ordering::SeqCst);
        if let Err(error) = execute!(stdout(), EnterAlternateScreen, EnableBracketedPaste) {
            let _ = restore_terminal();
            return Err(error);
        }
        Ok(Self { restored: false })
    }

    /// Explicit restore (also invoked from `Drop`).
    ///
    /// # Errors
    ///
    /// Returns crossterm IO errors.
    pub fn restore(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        restore_terminal()?;
        self.restored = true;
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// Best-effort terminal restoration used by panic hook and drop.
///
/// Every pending cleanup step is attempted even after one fails, and the
/// first error is returned so callers can observe incomplete restoration
/// instead of a false success (issue #137).
pub fn restore_terminal() -> io::Result<()> {
    let mut first_error: Option<io::Error> = None;
    // A flag is only cleared once its sequence was sent successfully, so a
    // failed cleanup is retried by the next restore attempt (guard drop).
    if BRACKETED_PASTE_ENABLED.load(Ordering::SeqCst) {
        if let Err(error) = execute!(stdout(), DisableBracketedPaste) {
            first_error.get_or_insert(error);
        } else {
            BRACKETED_PASTE_ENABLED.store(false, Ordering::SeqCst);
        }
    }
    if MOUSE_CAPTURE_ENABLED.load(Ordering::SeqCst) {
        if let Err(error) = execute!(stdout(), DisableMouseCapture) {
            first_error.get_or_insert(error);
        } else {
            MOUSE_CAPTURE_ENABLED.store(false, Ordering::SeqCst);
        }
    }
    if ALTERNATE_ENABLED.load(Ordering::SeqCst) {
        if let Err(error) = execute!(stdout(), LeaveAlternateScreen) {
            first_error.get_or_insert(error);
        } else {
            ALTERNATE_ENABLED.store(false, Ordering::SeqCst);
        }
    }
    if RAW_ENABLED.load(Ordering::SeqCst) {
        if let Err(error) = disable_raw_mode() {
            first_error.get_or_insert(error);
        } else {
            RAW_ENABLED.store(false, Ordering::SeqCst);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Create a ratatui terminal backend on stdout.
///
/// # Errors
///
/// Returns IO errors from the backend.
pub fn create_ratatui() -> io::Result<ratatui::Terminal<ratatui::backend::CrosstermBackend<Stdout>>>
{
    let backend = ratatui::backend::CrosstermBackend::new(stdout());
    ratatui::Terminal::new(backend)
}

fn install_panic_hook() {
    static HOOK_SET: AtomicBool = AtomicBool::new(false);
    if HOOK_SET.swap(true, Ordering::SeqCst) {
        return;
    }
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = restore_terminal();
        original(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mouse_capture_is_not_enabled_by_default() {
        assert!(
            !MOUSE_CAPTURE_ENABLED.load(Ordering::SeqCst),
            "mouse capture must stay opt-in until hit-testing ships (#134)"
        );
    }

    #[test]
    fn restore_is_idempotent_without_enter() {
        restore_terminal().unwrap();
        restore_terminal().unwrap();
    }
}
