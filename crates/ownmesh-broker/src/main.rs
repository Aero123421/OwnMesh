//! `OwnMesh` networkless privileged broker binary.

use clap::{Parser, Subcommand};
use ownmesh_broker::{
    broker_status, enforce_bind_is_networkless, execute_verified, install_broker,
    load_or_create_secret, now_unix, run_broker, uninstall_broker, BrokerServeConfig,
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
        /// Path to secret file (32+ bytes). Generated if missing.
        #[arg(long)]
        secret_file: PathBuf,
        /// Write chosen bind address / endpoint to this file.
        #[arg(long)]
        addr_file: Option<PathBuf>,
        /// Allowed caller principal ids (comma-separated).
        #[arg(long, default_value = "ownmeshd")]
        allow_callers: String,
        /// Require capability token on every request.
        #[arg(long, default_value_t = false)]
        require_capability: bool,
        /// Runtime dir used when resolving default endpoint.
        #[arg(long)]
        runtime_dir: Option<PathBuf>,
    },
    /// Status (always local; no network probes).
    Status {
        /// State base directory (defaults to ./ownmesh-broker-state for bare binary).
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Install service templates + local marker.
    Install {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        endpoint: Option<String>,
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
        program: String,
        #[arg(long, default_value = "ownmeshd")]
        caller: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
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
                 commands: help, version, run, status, install, uninstall, exec"
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
                "status={} network={} endpoint={} kind={} secret={}",
                if st.installed { "installed" } else { "idle" },
                st.network,
                st.endpoint.as_deref().unwrap_or("-"),
                st.endpoint_kind,
                st.secret_present
            );
            Ok(())
        }
        Commands::Install {
            state_dir,
            endpoint,
        } => {
            let ep = match endpoint {
                Some(s) => Some(
                    resolve_broker_endpoint(&state_dir.join("runtime"), Some(&s))
                        .map_err(|e| e.to_string())?,
                ),
                None => None,
            };
            let rec = install_broker(&state_dir, ep)?;
            println!(
                "installed endpoint={} kind={}",
                rec.endpoint, rec.endpoint_kind
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
            addr_file,
            allow_callers,
            require_capability,
            runtime_dir,
        } => {
            run_server(
                endpoint,
                bind,
                secret_file,
                addr_file,
                allow_callers,
                require_capability,
                runtime_dir,
            )
            .await
        }
        Commands::Exec {
            secret_file,
            program,
            caller,
            args,
        } => run_exec(&secret_file, program, caller, args),
    }
}

async fn run_server(
    endpoint: Option<String>,
    bind: Option<String>,
    secret_file: PathBuf,
    addr_file: Option<PathBuf>,
    allow_callers: String,
    require_capability: bool,
    runtime_dir: Option<PathBuf>,
) -> Result<(), String> {
    let runtime = runtime_dir.unwrap_or_else(|| {
        secret_file
            .parent()
            .map_or_else(|| PathBuf::from("."), PathBuf::from)
    });
    let endpoint = if let Some(bind) = bind {
        let addr: SocketAddr = bind
            .parse()
            .map_err(|e| format!("invalid bind address: {e}"))?;
        enforce_bind_is_networkless(addr)?;
        BrokerEndpoint::LoopbackTcp(addr)
    } else {
        resolve_broker_endpoint(&runtime, endpoint.as_deref()).map_err(|e| e.to_string())?
    };
    endpoint.enforce_networkless().map_err(|e| e.to_string())?;
    let allowed = allow_callers
        .split(',')
        .map(str::trim)
        .filter(|caller| !caller.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    eprintln!(
        "ownmesh-broker starting endpoint={}",
        broker_endpoint_display(&endpoint)
    );
    run_broker(BrokerServeConfig {
        endpoint,
        secret_file,
        allow_callers: allowed,
        require_capability,
        addr_file,
    })
    .await
}

fn run_exec(
    secret_file: &std::path::Path,
    program: String,
    caller: String,
    args: Vec<String>,
) -> Result<(), String> {
    let secret = load_or_create_secret(secret_file)?;
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
    let resp = execute_verified(&secret, &mut replay, &["ownmeshd".into()], &req, now)?;
    println!("{}", serde_json::to_string_pretty(&resp).unwrap());
    if !resp.ok {
        std::process::exit(resp.exit_code.unwrap_or(1));
    }
    Ok(())
}

// silence unused import when default_broker_endpoint only used on some cfgs
#[allow(dead_code)]
fn _keep(p: &std::path::Path) -> BrokerEndpoint {
    default_broker_endpoint(p)
}
