//! `ownmesh privileged` — install / status / uninstall for the networkless broker.

use crate::cli::{Cli, PrivilegedCmd};
use crate::commands::ipc_util::print_value;
use ownmesh_domain::ExitCode;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Command;
use uuid::Uuid;

pub fn dispatch_privileged(cli: &Cli, cmd: &PrivilegedCmd) -> Result<(), ExitCode> {
    match cmd {
        PrivilegedCmd::Install => run_install(cli),
        PrivilegedCmd::Status => run_status(cli),
        PrivilegedCmd::Uninstall => run_uninstall(cli),
    }
}

fn state_base() -> Result<PathBuf, ExitCode> {
    let paths = ownmesh_config::OwnMeshPaths::discover().map_err(|err| {
        eprintln!("paths: {err}");
        ExitCode::UsageConfig
    })?;
    let _ = paths.ensure_layout();
    Ok(paths.state_dir.clone())
}

fn run_install(cli: &Cli) -> Result<(), ExitCode> {
    let base = state_base()?;
    match invoke_broker(&["install", "--state-dir", &base.display().to_string()]) {
        Ok(0) => {
            let st = read_status_json(&base);
            print_value(cli.json, &st, |v| {
                println!(
                    "privileged broker installed endpoint={} kind={}",
                    v["endpoint"].as_str().unwrap_or("-"),
                    v["endpoint_kind"].as_str().unwrap_or("-")
                );
            });
            Ok(())
        }
        _ => fallback_install(cli, &base),
    }
}

fn fallback_install(cli: &Cli, base: &std::path::Path) -> Result<(), ExitCode> {
    let dir = base.join("broker");
    std::fs::create_dir_all(&dir).map_err(|e| {
        eprintln!("{e}");
        ExitCode::Internal
    })?;
    let secret = dir.join("broker.secret");
    if !secret.exists() {
        let mut h = Sha256::new();
        h.update(Uuid::new_v4().as_bytes());
        h.update(now_unix().to_le_bytes());
        h.update(b"ownmesh-cli-broker-secret");
        std::fs::write(&secret, h.finalize()).map_err(|e| {
            eprintln!("{e}");
            ExitCode::Internal
        })?;
    }
    let marker = json!({
        "installed": true,
        "installed_at_unix": now_unix(),
        "endpoint": "local",
        "endpoint_kind": if cfg!(windows) { "named_pipe" } else { "unix_socket" },
        "unit_path": null,
        "secret_file": secret.display().to_string(),
        "notes": [
            "broker is networkless (no non-loopback listen)",
            "install via ownmesh-broker for OS service templates"
        ],
    });
    std::fs::write(
        dir.join("broker-install.json"),
        serde_json::to_string_pretty(&marker).unwrap(),
    )
    .map_err(|e| {
        eprintln!("{e}");
        ExitCode::Internal
    })?;
    print_value(cli.json, &marker, |_| {
        println!("privileged broker installed (local marker)");
    });
    Ok(())
}

fn run_status(cli: &Cli) -> Result<(), ExitCode> {
    let base = state_base()?;
    if !cli.json {
        if let Ok(0) = invoke_broker(&["status", "--state-dir", &base.display().to_string()]) {
            return Ok(());
        }
    }
    let st = read_status_json(&base);
    print_value(cli.json, &st, |v| {
        println!(
            "privileged status={} network={} endpoint={}",
            if v["installed"].as_bool().unwrap_or(false) {
                "installed"
            } else {
                "idle"
            },
            v["network"].as_str().unwrap_or("disabled"),
            v["endpoint"].as_str().unwrap_or("-")
        );
    });
    Ok(())
}

fn run_uninstall(cli: &Cli) -> Result<(), ExitCode> {
    let base = state_base()?;
    let _ = invoke_broker(&["uninstall", "--state-dir", &base.display().to_string()]);
    let dir = base.join("broker");
    let marker = json!({
        "installed": false,
        "installed_at_unix": now_unix(),
        "endpoint": "",
        "endpoint_kind": "",
        "unit_path": null,
        "secret_file": dir.join("broker.secret").display().to_string(),
        "notes": ["uninstalled"],
    });
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(
        dir.join("broker-install.json"),
        serde_json::to_string_pretty(&marker).unwrap(),
    );
    print_value(cli.json, &marker, |_| {
        println!("privileged broker uninstalled");
    });
    Ok(())
}

fn invoke_broker(args: &[&str]) -> Result<i32, ()> {
    let candidates = ["ownmesh-broker", "ownmesh-broker.exe"];
    for name in candidates {
        if let Ok(out) = Command::new(name).args(args).status() {
            return Ok(out.code().unwrap_or(1));
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in ["ownmesh-broker", "ownmesh-broker.exe"] {
                let path = dir.join(name);
                if path.exists() {
                    if let Ok(out) = Command::new(&path).args(args).status() {
                        return Ok(out.code().unwrap_or(1));
                    }
                }
            }
        }
    }
    Err(())
}

fn read_status_json(base: &std::path::Path) -> serde_json::Value {
    let path = base.join("broker").join("broker-install.json");
    if let Ok(raw) = std::fs::read_to_string(path) {
        if let Ok(v) = serde_json::from_str(&raw) {
            return v;
        }
    }
    json!({
        "installed": false,
        "network": "disabled",
        "endpoint": null,
        "endpoint_kind": "",
        "secret_present": base.join("broker").join("broker.secret").exists(),
        "notes": ["not installed"],
    })
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
