//! OwnMesh session host library — long-lived PTY/ConPTY ownership helpers.
//!
//! The `ownmesh-session-host` binary remains the standalone supervisor CLI.
//! `ownmeshd` embeds [`LiveHost`] so cloud sessions own a real process tree
//! rather than metadata-only echo stubs.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::match_same_arms,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value
)]

mod pty_host;
mod supervisor_spool;

pub use pty_host::{
    default_shell_command, read_until, spawn_pty, LiveHost, PtySession, LIVE_OUTPUT_RING_BYTES,
    PIPE_FALLBACK_MAX_BYTES, READ_UNTIL_MAX_BYTES,
};
pub use supervisor_spool::{HostManifest, OwnerSpool, SpoolPage, SUPERVISOR_SPOOL_MAX_BYTES};
