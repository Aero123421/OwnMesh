//! The single failure envelope shared by every CLI surface.
//!
//! Before this module, `--json` failures came back in three different shapes
//! depending on which command failed: some carried `ok`/`exit_code`, some
//! carried neither, and some printed plain text to stderr with no JSON at all.
//! Automation could not detect failures reliably.
//!
//! Two mechanisms keep the contract now:
//!
//! 1. [`fail`] renders the canonical envelope and records that it did.
//! 2. [`emit_fallback_envelope`] runs once in `main` and covers any error path
//!    that returned an [`ExitCode`] without going through [`fail`], so the
//!    guarantee holds even for paths this module does not know about.

use crate::cli::Cli;
use ownmesh_domain::ExitCode;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};

/// Envelope version emitted on stdout. Bump only on a breaking shape change.
pub const ERROR_SCHEMA_VERSION: u32 = 1;

/// Set once any terminal JSON envelope reaches stdout.
static ENVELOPE_EMITTED: AtomicBool = AtomicBool::new(false);

/// Stable machine-readable code for an exit status.
///
/// Commands may pass a more specific code (for example
/// `OWNMESH_E_INVALID_ARGUMENT`); this is the fallback derived from the shared
/// exit taxonomy so every failure has *some* stable code.
#[must_use]
pub const fn code_for(exit: ExitCode) -> &'static str {
    match exit {
        ExitCode::Success => "OWNMESH_OK",
        ExitCode::UsageConfig => "OWNMESH_E_USAGE_CONFIG",
        ExitCode::Authentication => "OWNMESH_E_AUTHENTICATION",
        ExitCode::Authorization => "OWNMESH_E_AUTHORIZATION",
        ExitCode::DeviceOffline => "OWNMESH_E_DEVICE_OFFLINE",
        ExitCode::TimeoutCancelled => "OWNMESH_E_TIMEOUT_CANCELLED",
        ExitCode::Conflict => "OWNMESH_E_CONFLICT",
        ExitCode::DependencyUnavailable => "OWNMESH_E_DEPENDENCY_UNAVAILABLE",
        ExitCode::Internal => "OWNMESH_E_INTERNAL",
    }
}

/// Emit one failure in the canonical shape and return its exit code.
///
/// Under `--json` this writes a single object to **stdout**; otherwise it
/// writes the message (and optional hint) to **stderr**. Callers use the return
/// value directly: `return Err(fail(cli, ..))`.
pub fn fail(
    cli: &Cli,
    code: &str,
    message: impl std::fmt::Display,
    hint: Option<&str>,
    exit: ExitCode,
) -> ExitCode {
    let message = message.to_string();
    if cli.json {
        if ENVELOPE_EMITTED.swap(true, Ordering::SeqCst) {
            return exit;
        }
        let mut error = json!({ "code": code, "message": message });
        if let Some(hint) = hint {
            error["hint"] = json!(hint);
        }
        println!(
            "{}",
            json!({
                "schema_version": ERROR_SCHEMA_VERSION,
                "ok": false,
                "error": error,
                "exit_code": exit.code(),
            })
        );
    } else {
        eprintln!("{message}");
        if let Some(hint) = hint {
            eprintln!("hint: {hint}");
        }
    }
    exit
}

/// [`fail`] with the code derived from the exit status.
pub fn fail_with(
    cli: &Cli,
    message: impl std::fmt::Display,
    hint: Option<&str>,
    exit: ExitCode,
) -> ExitCode {
    fail(cli, code_for(exit), message, hint, exit)
}

/// Last-resort envelope for error paths that never called [`fail`].
///
/// `main` calls this exactly once with the failing exit code. It is a safety
/// net, not the preferred path: a command that emits its own envelope produces
/// a better message and a more specific code.
pub fn emit_fallback_envelope(cli: &Cli, exit: ExitCode) {
    if !cli.json || ENVELOPE_EMITTED.swap(true, Ordering::SeqCst) {
        return;
    }
    println!(
        "{}",
        json!({
            "schema_version": ERROR_SCHEMA_VERSION,
            "ok": false,
            "error": {
                "code": code_for(exit),
                "message": exit.meaning(),
                "hint": "see stderr for the detailed diagnostic",
            },
            "exit_code": exit.code(),
        })
    );
}

/// Record that a command emitted its own conforming envelope.
///
/// Used by the few surfaces that build a richer payload inline (for example a
/// tool result carried alongside `ok: false`).
pub fn note_envelope_emitted() {
    ENVELOPE_EMITTED.store(true, Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    ENVELOPE_EMITTED.store(false, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(json: bool) -> Cli {
        Cli {
            json,
            lang: None,
            command: None,
        }
    }

    #[test]
    fn every_exit_code_has_a_distinct_stable_code() {
        let mut seen = std::collections::HashSet::new();
        for exit in ExitCode::all_error_codes() {
            let code = code_for(exit);
            assert!(code.starts_with("OWNMESH_E_"), "{code}");
            assert!(seen.insert(code), "duplicate code {code}");
        }
    }

    #[test]
    fn fail_returns_the_requested_exit_code() {
        reset_for_test();
        let exit = fail_with(
            &cli(false),
            "boom",
            Some("try again"),
            ExitCode::DeviceOffline,
        );
        assert_eq!(exit, ExitCode::DeviceOffline);
    }

    #[test]
    fn fallback_is_suppressed_without_json() {
        reset_for_test();
        // Must not panic and must not mark an envelope as emitted.
        emit_fallback_envelope(&cli(false), ExitCode::Internal);
        assert!(!ENVELOPE_EMITTED.load(Ordering::SeqCst));
    }
}
