//! `ownmesh privileged` — install / status / uninstall for the networkless broker.

use crate::cli::{Cli, PrivilegedCmd};
use crate::commands::ipc_util::print_value;
use ownmesh_domain::ExitCode;
use serde_json::json;
use std::path::PathBuf;
use std::process::Command;

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
            if !st["installed"].as_bool().unwrap_or(false) {
                eprintln!("broker install did not establish a verified native service");
                return Err(ExitCode::ProfileUnavailable);
            }
            print_value(cli.json, &st, |v| {
                println!(
                    "privileged broker installed endpoint={} kind={}",
                    v["endpoint"].as_str().unwrap_or("-"),
                    v["endpoint_kind"].as_str().unwrap_or("-")
                );
            });
            Ok(())
        }
        Ok(code) => {
            eprintln!(
                "broker service installation failed (exit {code}); no installed state recorded"
            );
            Err(ExitCode::ProfileUnavailable)
        }
        Err(()) => {
            eprintln!("ownmesh-broker is unavailable; broker service was not installed");
            Err(ExitCode::ProfileUnavailable)
        }
    }
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

fn run_uninstall(_cli: &Cli) -> Result<(), ExitCode> {
    let base = state_base()?;
    match invoke_broker(&["uninstall", "--state-dir", &base.display().to_string()]) {
        Ok(0) => {
            eprintln!(
                "broker command returned success, but native service absence is not independently verified"
            );
            Err(ExitCode::ProfileUnavailable)
        }
        Ok(code) => {
            eprintln!(
                "broker service uninstall could not verify native service removal (exit {code})"
            );
            Err(ExitCode::ProfileUnavailable)
        }
        Err(()) => {
            eprintln!("ownmesh-broker is unavailable; native service removal was not attempted");
            Err(ExitCode::ProfileUnavailable)
        }
    }
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
        if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&raw) {
            // Historical markers and generated templates are not native service probes.
            value["installed"] = json!(false);
            value["network"] = json!("disabled");
            value["notes"] =
                json!(["native broker service state is unverified; reporting not installed"]);
            return value;
        }
    }
    json!({
        "installed": false,
        "network": "disabled",
        "endpoint": null,
        "endpoint_kind": "",
        "secret_present": base.join("broker").join("broker.secret").exists(),
        "notes": ["not installed; native service management is unsupported"],
    })
}
