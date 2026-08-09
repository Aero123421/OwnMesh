//! `OwnMesh` networkless privileged broker binary.
//!
//! Linux native lifecycle is backed by a root-owned systemd service.  Other
//! operating systems remain fail-closed unsupported.

#![allow(
    clippy::doc_markdown,
    clippy::map_unwrap_or,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unused_async,
    clippy::useless_format
)]

use clap::{Parser, Subcommand};
use ownmesh_broker::{
    broker_status, install_broker_with_config, load_linux_run_config, run_broker, uninstall_broker,
    BrokerInstallConfig, UnixSocketSecurity,
};
use ownmesh_broker_client::BrokerEndpoint;
use ownmesh_broker_client::DEFAULT_BROKER_ENDPOINT;
use std::path::{Path, PathBuf};

/// CLI.
#[derive(Debug, Parser)]
#[command(
    name = "ownmesh-broker",
    version,
    about = "OwnMesh privileged broker (Linux native service; networkless)",
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
    /// Production serve from the root-owned native service configuration.
    Run {
        /// Exact root-owned configuration installed by `install`.
        #[arg(long)]
        config: PathBuf,
    },
    /// Status of the Linux native service.
    Status {
        /// State base directory (defaults to ./ownmesh-broker-state for bare binary).
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Install the Linux native service (requires root).
    Install {
        /// Legacy state directory (ignored; Linux state is fixed under /var/lib).
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Endpoint must be the fixed Linux UDS if supplied.
        #[arg(long)]
        endpoint: Option<String>,
        /// Source ownmeshd image to install beside the broker.
        #[arg(long)]
        trusted_executable: Option<PathBuf>,
        /// Unprivileged ownmeshd UID. Required for direct root invocation;
        /// defaults only from a validated sudo caller identity.
        #[arg(long)]
        daemon_uid: Option<u32>,
        /// Unprivileged ownmeshd primary GID. Required with --daemon-uid.
        #[arg(long)]
        daemon_gid: Option<u32>,
        /// Must equal --daemon-uid when supplied.
        #[arg(long)]
        socket_owner_uid: Option<u32>,
        /// Must equal --daemon-gid when supplied.
        #[arg(long)]
        socket_group_gid: Option<u32>,
        /// Must be 0600 on the Linux native service.
        #[arg(long, value_parser = parse_octal_mode)]
        socket_mode: Option<u32>,
        /// Must contain exactly --daemon-uid on the Linux native service.
        #[arg(long = "allowed-uid")]
        allowed_uids: Vec<u32>,
    },
    /// Uninstall the Linux native service (requires root).
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
                 Linux: install/status/run/uninstall use a root-owned systemd service; Windows/macOS unsupported"
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
                "status={} support={} network={} endpoint={} kind={} secret={} signing={} verify={}",
                if st.installed { "installed" } else { "absent" },
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
            if st.installed { Ok(()) } else { Err(st.notes.first().cloned().unwrap_or_else(|| "broker is not installed".into())) }
        }
        Commands::Install { state_dir, endpoint, trusted_executable, daemon_uid, daemon_gid, socket_owner_uid, socket_group_gid, socket_mode, allowed_uids } => {
            let endpoint = endpoint.map(|raw| raw.strip_prefix("unix:").map(PathBuf::from).map(BrokerEndpoint::UnixSocket).ok_or_else(|| "install endpoint must use unix:/run/ownmesh/broker.sock".to_string())).transpose()?;
            let broker = std::env::current_exe().map_err(|e| format!("resolve broker executable: {e}"))?;
            let trusted = trusted_executable.unwrap_or_else(|| broker.with_file_name("ownmeshd"));
            let (daemon_uid, daemon_group_gid) = resolve_daemon_identity(daemon_uid, daemon_gid)?;
            let rec = install_broker_with_config(state_dir.as_deref().unwrap_or_else(|| Path::new(".")), BrokerInstallConfig {
                endpoint, trusted_executable: trusted, daemon_uid, daemon_gid: daemon_group_gid,
                socket_security: UnixSocketSecurity { owner_uid: socket_owner_uid.unwrap_or(daemon_uid), group_gid: socket_group_gid.unwrap_or(daemon_group_gid), mode: socket_mode.unwrap_or(0o600) },
                allowed_uids: if allowed_uids.is_empty() { vec![daemon_uid] } else { allowed_uids },
            })?;
            println!("installed=true support={} endpoint={}", rec.support, rec.endpoint); Ok(())
        }
        Commands::Uninstall { state_dir } => { uninstall_broker(state_dir.as_deref().unwrap_or_else(|| Path::new(".")))?; println!("installed=false"); Ok(()) }
        Commands::Run { config } => run_broker(load_linux_run_config(&config)?).await,
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

fn resolve_daemon_identity(uid: Option<u32>, gid: Option<u32>) -> Result<(u32, u32), String> {
    let (uid, gid) = match (uid, gid) {
        (Some(uid), Some(gid)) => (uid, gid),
        (None, None) => {
            let uid = std::env::var("SUDO_UID")
                .ok()
                .and_then(|v| v.parse::<u32>().ok());
            let gid = std::env::var("SUDO_GID")
                .ok()
                .and_then(|v| v.parse::<u32>().ok());
            match (uid, gid) {
                (Some(uid), Some(gid)) => (uid, gid),
                _ => return Err("direct root install requires --daemon-uid <nonzero> --daemon-gid <nonzero>; sudo defaults require both SUDO_UID and SUDO_GID".into()),
            }
        }
        _ => return Err("--daemon-uid and --daemon-gid must be supplied together".into()),
    };
    if uid == 0 || gid == 0 {
        return Err("Linux native broker refuses root ownmeshd identity; choose an explicit non-root daemon UID/GID".into());
    }
    Ok((uid, gid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_requires_strict_config_argument() {
        assert!(Cli::try_parse_from(["ownmesh-broker", "run"]).is_err());
    }
}
