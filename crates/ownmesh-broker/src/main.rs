//! `OwnMesh` networkless privileged broker binary.

#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::map_unwrap_or,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

use clap::{Parser, Subcommand};
use ownmesh_broker::{
    broker_status, default_signing_key_path, enforce_bind_is_networkless,
    ensure_broker_key_separation, execute_verified_for_process, install_broker_with_config,
    load_or_create_capability_keys, load_or_create_secret, now_unix, run_broker, uninstall_broker,
    BrokerInstallConfig, BrokerServeConfig, UnixSocketSecurity,
};
use ownmesh_broker_client::{
    broker_endpoint_display, build_request, default_broker_endpoint, resolve_broker_endpoint,
    BrokerEndpoint, ElevatedCommand, ReplayCache, DEFAULT_BROKER_ENDPOINT,
};
use std::net::SocketAddr;
use std::path::PathBuf;

/// CLI.
#[derive(Debug, Parser)]
#[command(
    name = "ownmesh-broker",
    version,
    about = "OwnMesh privileged broker (networkless)",
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
    /// Run broker (OS pipe/socket or loopback fallback).
    Run {
        /// Endpoint override: `tcp:127.0.0.1:0`, `pipe:NAME`, `unix:/path.sock`.
        #[arg(long)]
        endpoint: Option<String>,
        /// Legacy bind address (loopback only). Prefer `--endpoint`.
        #[arg(long)]
        bind: Option<String>,
        /// Path to request-MAC secret file (32+ bytes). Generated if missing.
        #[arg(long)]
        secret_file: PathBuf,
        /// Path to capability Ed25519 signing key (broker-only). Defaults beside secret.
        #[arg(long)]
        signing_key_file: Option<PathBuf>,
        /// Write chosen bind address / endpoint to this file.
        #[arg(long)]
        addr_file: Option<PathBuf>,
        /// Runtime dir used when resolving default endpoint.
        #[arg(long)]
        runtime_dir: Option<PathBuf>,
        /// Exact root-controlled ownmeshd executable allowed to request minting.
        #[arg(long)]
        trusted_executable: PathBuf,
        /// Explicit Unix socket owner UID.
        #[arg(long)]
        socket_owner_uid: u32,
        /// Explicit Unix socket group GID.
        #[arg(long)]
        socket_group_gid: u32,
        /// Unix socket mode in octal; production requires exactly 600.
        #[arg(long, value_parser = parse_octal_mode)]
        socket_mode: u32,
        /// Explicit allowed ownmeshd UID; repeat for multiple UIDs.
        #[arg(long = "allowed-uid", required = true)]
        allowed_uids: Vec<u32>,
    },
    /// Status (always local; no network probes).
    Status {
        /// State base directory (defaults to ./ownmesh-broker-state for bare binary).
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Stage service templates; exits unsupported until activation is verified.
    Install {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        trusted_executable: PathBuf,
        #[arg(long)]
        socket_owner_uid: u32,
        #[arg(long)]
        socket_group_gid: u32,
        #[arg(long, value_parser = parse_octal_mode)]
        socket_mode: u32,
        #[arg(long = "allowed-uid", required = true)]
        allowed_uids: Vec<u32>,
    },
    /// Uninstall local marker + templates.
    Uninstall {
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// One-shot local elevated run via in-process verify (test helper).
    Exec {
        #[arg(long)]
        secret_file: PathBuf,
        #[arg(long)]
        signing_key_file: Option<PathBuf>,
        #[arg(long)]
        program: String,
        /// PID whose UID and executable are independently resolved by the OS.
        #[arg(long)]
        peer_pid: Option<i32>,
        /// Exact root-controlled executable the OS-resolved PID must match.
        #[arg(long)]
        trusted_executable: PathBuf,
        /// Explicit allowed UID for the resolved process; repeat as needed.
        #[arg(long = "allowed-uid", required = true)]
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
                 capability mint key is broker-only (separate from request MAC secret)"
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
            let status_label = if st.installed {
                "installed"
            } else if st.support == "unsupported" {
                "unsupported"
            } else {
                "idle"
            };
            println!(
                "status={} support={} network={} endpoint={} kind={} secret={} signing={} verify={}",
                status_label,
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
            // Non-zero when platform cannot enforce peer creds (explicit unsupported).
            if st.support == "unsupported" && !st.installed {
                return Err(format!(
                    "unsupported: privileged broker not available ({})",
                    st.notes
                        .first()
                        .cloned()
                        .unwrap_or_else(|| st.support.clone())
                ));
            }
            Ok(())
        }
        Commands::Install {
            state_dir,
            endpoint,
            trusted_executable,
            socket_owner_uid,
            socket_group_gid,
            socket_mode,
            allowed_uids,
        } => {
            let ep = match endpoint {
                Some(s) => Some(
                    resolve_broker_endpoint(&state_dir.join("runtime"), Some(&s))
                        .map_err(|e| e.to_string())?,
                ),
                None => None,
            };
            let rec = install_broker_with_config(
                &state_dir,
                BrokerInstallConfig {
                    endpoint: ep,
                    trusted_executable,
                    socket_security: UnixSocketSecurity {
                        owner_uid: socket_owner_uid,
                        group_gid: socket_group_gid,
                        mode: socket_mode,
                    },
                    allowed_uids,
                },
            )?;
            if !rec.installed || rec.support == "unsupported" {
                return Err(format!(
                    "unsupported/failed: refusing installed success (support={}, notes={:?})",
                    rec.support, rec.notes
                ));
            }
            println!(
                "installed endpoint={} kind={} signing_key={}",
                rec.endpoint, rec.endpoint_kind, rec.signing_key_file
            );
            Ok(())
        }
        Commands::Uninstall { state_dir } => {
            uninstall_broker(&state_dir)?;
            println!("uninstalled");
            Ok(())
        }
        Commands::Run {
            endpoint,
            bind,
            secret_file,
            signing_key_file,
            addr_file,
            runtime_dir,
            trusted_executable,
            socket_owner_uid,
            socket_group_gid,
            socket_mode,
            allowed_uids,
        } => {
            let runtime = runtime_dir.unwrap_or_else(|| {
                secret_file
                    .parent()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."))
            });
            let ep = if let Some(bind) = bind {
                let addr: SocketAddr = bind
                    .parse()
                    .map_err(|e| format!("invalid bind address: {e}"))?;
                enforce_bind_is_networkless(addr)?;
                BrokerEndpoint::LoopbackTcp(addr)
            } else {
                resolve_broker_endpoint(&runtime, endpoint.as_deref()).map_err(|e| e.to_string())?
            };
            ep.enforce_networkless().map_err(|e| e.to_string())?;
            let signing_key_file =
                signing_key_file.unwrap_or_else(|| default_signing_key_path(&secret_file));
            ensure_broker_key_separation(&secret_file, &signing_key_file)?;
            eprintln!(
                "ownmesh-broker starting endpoint={} signing_key={}",
                broker_endpoint_display(&ep),
                signing_key_file.display()
            );
            run_broker(BrokerServeConfig {
                endpoint: ep,
                secret_file,
                signing_key_file,
                trusted_executable,
                allowed_uids,
                socket_security: UnixSocketSecurity {
                    owner_uid: socket_owner_uid,
                    group_gid: socket_group_gid,
                    mode: socket_mode,
                },
                addr_file,
            })
            .await
        }
        Commands::Exec {
            secret_file,
            signing_key_file,
            program,
            peer_pid,
            trusted_executable,
            allowed_uids,
            caller,
            args,
        } => {
            let pid = peer_pid.unwrap_or_else(|| i32::try_from(std::process::id()).unwrap_or(0));
            let policy =
                ownmesh_broker::peer::load_trusted_peer_policy(&trusted_executable, allowed_uids)?;
            let _initial_authorization = policy.authorize_process(pid)?;
            // Only touch broker secrets after the OS-derived synthetic peer has
            // passed the same exact executable/PID/UID policy as production.
            let signing_path =
                signing_key_file.unwrap_or_else(|| default_signing_key_path(&secret_file));
            ensure_broker_key_separation(&secret_file, &signing_path)?;
            let secret = load_or_create_secret(&secret_file)?;
            let (signing_key, verify_key) = load_or_create_capability_keys(&signing_path)?;
            ensure_broker_key_separation(&secret_file, &signing_path)?;
            let now = now_unix();
            let req = build_request(
                &secret,
                caller,
                format!("op_{now}"),
                ElevatedCommand {
                    program,
                    args,
                    cwd: None,
                    env: vec![],
                },
                now,
                60,
            );
            let mut replay = ReplayCache::new();
            let resp = execute_verified_for_process(
                &secret,
                &signing_key,
                &verify_key,
                &mut replay,
                &req,
                &policy,
                pid,
                now,
            )?;
            println!("{}", serde_json::to_string_pretty(&resp).unwrap());
            if !resp.ok {
                std::process::exit(resp.exit_code.unwrap_or(1));
            }
            Ok(())
        }
    }
}

// silence unused import when default_broker_endpoint only used on some cfgs
#[allow(dead_code)]
fn _keep(p: &std::path::Path) -> BrokerEndpoint {
    default_broker_endpoint(p)
}
