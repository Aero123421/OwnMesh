//! `OwnMesh` networkless privileged broker binary.
//!
//! Production elevated broker entry points are fixed as **unsupported** until a
//! secure mint authority is established. CLI never binds a serve endpoint or
//! executes elevated processes.

#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::map_unwrap_or,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

use clap::{Parser, Subcommand};
use ownmesh_broker::{broker_status, production_elevated_broker_unsupported};
use ownmesh_broker_client::DEFAULT_BROKER_ENDPOINT;
use std::path::PathBuf;

/// CLI.
#[derive(Debug, Parser)]
#[command(
    name = "ownmesh-broker",
    version,
    about = "OwnMesh privileged broker (networkless; production elevated unsupported)",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Print help overview.
    Help,
    /// Show version.
    Version,
    /// Production serve — always unsupported (no bind / no exec).
    Run {
        /// Endpoint override (ignored; production serve is unsupported).
        #[arg(long)]
        endpoint: Option<String>,
        /// Legacy bind address (ignored).
        #[arg(long)]
        bind: Option<String>,
        /// Path to request-MAC secret file (ignored).
        #[arg(long)]
        secret_file: Option<PathBuf>,
        /// Path to capability Ed25519 signing key (ignored).
        #[arg(long)]
        signing_key_file: Option<PathBuf>,
        /// Addr file (ignored).
        #[arg(long)]
        addr_file: Option<PathBuf>,
        /// Runtime dir (ignored).
        #[arg(long)]
        runtime_dir: Option<PathBuf>,
        /// Trusted executable (ignored).
        #[arg(long)]
        trusted_executable: Option<PathBuf>,
        /// Socket owner UID (ignored).
        #[arg(long)]
        socket_owner_uid: Option<u32>,
        /// Socket group GID (ignored).
        #[arg(long)]
        socket_group_gid: Option<u32>,
        /// Socket mode (ignored).
        #[arg(long, value_parser = parse_octal_mode)]
        socket_mode: Option<u32>,
        /// Allowed UIDs (ignored).
        #[arg(long = "allowed-uid")]
        allowed_uids: Vec<u32>,
    },
    /// Status (always local; always unsupported / installed=false).
    Status {
        /// State base directory (defaults to ./ownmesh-broker-state for bare binary).
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Install — always unsupported / installed=false.
    Install {
        /// Legacy state directory (ignored).
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Legacy endpoint (ignored).
        #[arg(long)]
        endpoint: Option<String>,
        /// Legacy trusted executable (ignored).
        #[arg(long)]
        trusted_executable: Option<PathBuf>,
        /// Legacy socket owner UID (ignored).
        #[arg(long)]
        socket_owner_uid: Option<u32>,
        /// Legacy socket group GID (ignored).
        #[arg(long)]
        socket_group_gid: Option<u32>,
        /// Legacy socket mode (ignored).
        #[arg(long, value_parser = parse_octal_mode)]
        socket_mode: Option<u32>,
        /// Legacy allowed UIDs (ignored).
        #[arg(long = "allowed-uid")]
        allowed_uids: Vec<u32>,
    },
    /// Uninstall — unsupported and side-effect-free.
    Uninstall {
        /// Legacy state directory (ignored).
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// One-shot elevated exec — production-unsupported (no process spawn).
    Exec {
        #[arg(long)]
        secret_file: Option<PathBuf>,
        #[arg(long)]
        signing_key_file: Option<PathBuf>,
        #[arg(long)]
        program: Option<String>,
        #[arg(long)]
        peer_pid: Option<i32>,
        #[arg(long)]
        trusted_executable: Option<PathBuf>,
        #[arg(long = "allowed-uid")]
        allowed_uids: Vec<u32>,
        #[arg(long, default_value = "ownmeshd")]
        caller: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn parse_octal_mode(value: &str) -> Result<u32, String> {
    let trimmed = value.trim().trim_start_matches("0o");
    u32::from_str_radix(trimmed, 8).map_err(|e| format!("invalid octal Unix mode {value:?}: {e}"))
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    match cli.cmd {
        Commands::Help => {
            println!(
                "ownmesh-broker — networkless privileged broker\n\
                 endpoint basename: {DEFAULT_BROKER_ENDPOINT}\n\
                 commands: help, version, run, status, install, uninstall, exec\n\
                 PRODUCTION: elevated install/status/serve/exec are unsupported until secure mint authority"
            );
            Ok(())
        }
        Commands::Version => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Commands::Status { state_dir } => {
            let base = state_dir.unwrap_or_else(|| PathBuf::from("."));
            let st = broker_status(&base)?;
            println!(
                "status=unsupported support={} network={} endpoint={} kind={} secret={} signing={} verify={}",
                st.support,
                st.network,
                st.endpoint.as_deref().unwrap_or("-"),
                st.endpoint_kind,
                st.secret_present,
                st.signing_key_present,
                st.verify_key_present
            );
            for n in &st.notes {
                println!("note: {n}");
            }
            Err(format!(
                "unsupported: privileged broker not available ({})",
                st.notes
                    .first()
                    .cloned()
                    .unwrap_or_else(|| st.support.clone())
            ))
        }
        Commands::Install {
            state_dir: _,
            endpoint: _,
            trusted_executable: _,
            socket_owner_uid: _,
            socket_group_gid: _,
            socket_mode: _,
            allowed_uids: _,
        } => Err("unsupported: elevated broker production install is disabled until a secure mint authority is established; no native service was activated or verified; no filesystem changes were made (fail-closed)".into()),
        Commands::Uninstall { state_dir: _ } => Err(
            "unsupported: elevated broker production uninstall is disabled; native service absence cannot be verified; no filesystem changes were made (fail-closed)".into(),
        ),
        Commands::Run {
            endpoint: _,
            bind: _,
            secret_file: _,
            signing_key_file: _,
            addr_file: _,
            runtime_dir: _,
            trusted_executable: _,
            socket_owner_uid: _,
            socket_group_gid: _,
            socket_mode: _,
            allowed_uids: _,
        } => Err(production_elevated_broker_unsupported()),
        Commands::Exec {
            secret_file: _,
            signing_key_file: _,
            program: _,
            peer_pid: _,
            trusted_executable: _,
            allowed_uids: _,
            caller: _,
            args: _,
        } => Err(format!(
            "unsupported: elevated broker exec CLI is disabled until a secure mint authority is established (fail-closed; no process spawn)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unsupported_commands_accept_no_legacy_arguments() {
        for command in ["run", "install", "exec", "uninstall"] {
            let cli = Cli::try_parse_from(["ownmesh-broker", command]).unwrap();
            let err = run(cli)
                .await
                .expect_err("production path must be unsupported");
            assert!(err.contains("unsupported"), "{command}: {err}");
        }
    }
}
