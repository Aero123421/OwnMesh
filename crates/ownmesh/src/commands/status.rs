//! `ownmesh status` — fetch daemon status over local IPC.

use crate::cli::Cli;
use ownmesh_config::{load_config, OwnMeshPaths};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::{ClientIdentity, ClientOptions, Endpoint, IpcClient};
use serde_json::json;
use std::process::Command;
use std::time::Duration;

/// Run the status command.
pub fn run_status(cli: &Cli) -> Result<(), ExitCode> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            eprintln!("failed to start async runtime: {err}");
            ExitCode::Internal
        })?;

    rt.block_on(async { status_async(cli).await })
}

async fn status_async(cli: &Cli) -> Result<(), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|err| {
        eprintln!("config path error: {err}");
        ExitCode::UsageConfig
    })?;
    let _ = paths.ensure_layout();
    let cfg = load_config(&paths).map_err(|err| {
        eprintln!("config load error: {err}");
        ExitCode::UsageConfig
    })?;
    let endpoint =
        Endpoint::configured_daemon(&paths.runtime_dir, cfg.service_socket.path.as_deref())
            .map_err(|err| {
                eprintln!("service endpoint configuration error: {err}");
                ExitCode::UsageConfig
            })?;
    let client = IpcClient::new(
        endpoint,
        paths.runtime_dir.clone(),
        ClientIdentity::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        ClientOptions {
            request_timeout: Duration::from_secs(3),
            max_reconnect_attempts: 3,
            reconnect_base_delay: Duration::from_millis(50),
        },
    )
    .with_client_credential_from_env()
    .map_err(|err| {
        eprintln!("client credential configuration error: {err}");
        ExitCode::UsageConfig
    })?;

    match client.status().await {
        Ok(status) => {
            if cli.json {
                println!(
                    "{}",
                    json!({
                        "schema_version": 1,
                        "daemon": status,
                    })
                );
            } else {
                println!("ownmeshd {}", status.version);
                println!("  state:    {}", status.state);
                println!("  pid:      {}", status.pid);
                println!("  endpoint: {}", status.endpoint);
                println!("  uptime:   {}s", status.uptime_secs);
            }
            Ok(())
        }
        Err(err) => {
            if cli.json {
                println!(
                    "{}",
                    json!({
                        "schema_version": 1,
                        "error": {
                            "code": err.code(),
                            "message": err.to_string(),
                        }
                    })
                );
            } else {
                eprintln!("failed to reach ownmeshd: {err}");
                eprintln!("hint: start the daemon with `ownmeshd run`");
            }
            Err(ExitCode::DeviceOffline)
        }
    }
}

/// Best-effort helper used by integration-style unit tests: spawn `ownmeshd` if present.
#[allow(dead_code)]
pub fn spawn_ownmeshd_for_tests(runtime_dir: &std::path::Path) -> Option<std::process::Child> {
    let exe = std::env::current_exe().ok()?;
    let ownmeshd = exe.parent()?.join(if cfg!(windows) {
        "ownmeshd.exe"
    } else {
        "ownmeshd"
    });
    if !ownmeshd.exists() {
        return None;
    }
    Command::new(ownmeshd)
        .arg("run")
        .env("OWNMESH_RUNTIME_DIR", runtime_dir)
        .env("OWNMESH_CONFIG_DIR", runtime_dir.join("config"))
        .env("OWNMESH_STATE_DIR", runtime_dir.join("state"))
        .spawn()
        .ok()
}
