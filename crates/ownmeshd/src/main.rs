//! OwnMesh device agent (`ownmeshd`) entrypoint.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

mod daemon;

use clap::{Parser, Subcommand};
use ownmesh_domain::ExitCode;
use std::process::ExitCode as StdExitCode;

/// OwnMesh user-level device agent.
#[derive(Debug, Parser)]
#[command(
    name = "ownmeshd",
    version,
    about = "OwnMesh device agent — user-level daemon"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the daemon in the foreground (default).
    Run,
    /// Print version and exit.
    Version,
    /// Show whether a local daemon appears reachable.
    Status,
}

fn main() -> StdExitCode {
    init_tracing();
    let cli = Cli::parse();
    let code = match cli.command.unwrap_or(Commands::Run) {
        Commands::Run => match daemon::run_foreground() {
            Ok(()) => ExitCode::Success,
            Err(code) => code,
        },
        Commands::Version => {
            println!(
                "{name} {version}",
                name = env!("CARGO_PKG_NAME"),
                version = env!("CARGO_PKG_VERSION")
            );
            ExitCode::Success
        }
        Commands::Status => match daemon::probe_status() {
            Ok(()) => ExitCode::Success,
            Err(code) => code,
        },
    };
    StdExitCode::from(code.code() as u8)
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_help_has_run() {
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("run") || help.contains("Run"));
    }
}
