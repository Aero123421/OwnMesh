//! `ownmesh privileged` — install / status / uninstall for the networkless broker.
//!
//! Never disguises an unsupported platform (Windows Named Pipe without safe peer
//! PID/token/ACL enforcement) as `installed: true`.

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
            if st["installed"].as_bool().unwrap_or(false) {
                print_value(cli.json, &st, |v| {
                    println!(
                        "privileged broker installed endpoint={} kind={}",
                        v["endpoint"].as_str().unwrap_or("-"),
                        v["endpoint_kind"].as_str().unwrap_or("-")
                    );
                });
                Ok(())
            } else {
                // Broker exited 0 but did not claim install — treat as failed.
                report_unsupported(cli, &st)
            }
        }
        Ok(_code) => {
            // Non-zero: broker reported unsupported/failed. Surface marker if present.
            let st = read_status_json(&base);
            report_unsupported(cli, &st)
        }
        Err(()) => {
            // Broker binary missing — never fake installed=true.
            fallback_install_failed(cli, &base)
        }
    }
}

/// Fallback when `ownmesh-broker` is unavailable.
///
/// **Must not** write `installed: true`. On Windows this is always unsupported;
/// on Unix without the broker binary we still refuse a success disguise.
fn fallback_install_failed(cli: &Cli, base: &std::path::Path) -> Result<(), ExitCode> {
    let dir = base.join("broker");
    let _ = std::fs::create_dir_all(&dir);
    let reason = if cfg!(windows) {
        "unsupported: Named Pipe client PID/token/ACL cannot be safely enforced; \
         ownmesh-broker install refused (installed=false)"
    } else {
        "failed: ownmesh-broker binary not found; refusing installed success disguise"
    };
    let marker = json!({
        "installed": false,
        "installed_at_unix": now_unix(),
        "endpoint": serde_json::Value::Null,
        "endpoint_kind": if cfg!(windows) { "named_pipe" } else { "unix_socket" },
        "unit_path": null,
        "secret_file": dir.join("broker.secret").display().to_string(),
        "notes": [reason, "unsupported"],
        "support": if cfg!(windows) { "unsupported" } else { "failed" },
        "network": "disabled",
        "secret_present": dir.join("broker.secret").exists(),
    });
    let _ = std::fs::write(
        dir.join("broker-install.json"),
        serde_json::to_string_pretty(&marker).unwrap_or_else(|_| "{}".into()),
    );
    report_unsupported(cli, &marker)
}

fn report_unsupported(cli: &Cli, st: &serde_json::Value) -> Result<(), ExitCode> {
    // Defense: never print success if installed slipped through.
    let mut out = st.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert("installed".into(), json!(false));
        if !obj.contains_key("support") {
            obj.insert(
                "support".into(),
                json!(if cfg!(windows) {
                    "unsupported"
                } else {
                    "failed"
                }),
            );
        }
    }
    print_value(cli.json, &out, |v| {
        println!(
            "privileged broker {} (installed=false) endpoint={}",
            v["support"].as_str().unwrap_or("failed"),
            v["endpoint"].as_str().unwrap_or("-")
        );
        if let Some(notes) = v["notes"].as_array() {
            for n in notes {
                if let Some(s) = n.as_str() {
                    println!("note: {s}");
                }
            }
        }
    });
    Err(ExitCode::ProfileUnavailable)
}

fn run_status(cli: &Cli) -> Result<(), ExitCode> {
    let base = state_base()?;
    // Prefer broker binary status (it applies the peer-enforcement gate).
    match invoke_broker(&["status", "--state-dir", &base.display().to_string()]) {
        Ok(0) => {
            if cli.json {
                let st = read_status_json(&base);
                print_value(cli.json, &st, |_| {});
            }
            // broker status already printed human output when not json-only path
            Ok(())
        }
        Ok(_code) => {
            let st = sanitize_status(read_status_json(&base));
            print_value(cli.json, &st, |v| {
                println!(
                    "privileged status={} support={} network={} endpoint={}",
                    if v["installed"].as_bool().unwrap_or(false) {
                        "installed"
                    } else if v["support"].as_str() == Some("unsupported") {
                        "unsupported"
                    } else {
                        "idle"
                    },
                    v["support"].as_str().unwrap_or("-"),
                    v["network"].as_str().unwrap_or("disabled"),
                    v["endpoint"].as_str().unwrap_or("-")
                );
            });
            if v_unsupported(&st) {
                Err(ExitCode::ProfileUnavailable)
            } else {
                Ok(())
            }
        }
        Err(()) => {
            let st = sanitize_status(read_status_json(&base));
            print_value(cli.json, &st, |v| {
                println!(
                    "privileged status={} support={} network={} endpoint={}",
                    if v["installed"].as_bool().unwrap_or(false) {
                        "installed"
                    } else if v["support"].as_str() == Some("unsupported") {
                        "unsupported"
                    } else {
                        "idle"
                    },
                    v["support"].as_str().unwrap_or("-"),
                    v["network"].as_str().unwrap_or("disabled"),
                    v["endpoint"].as_str().unwrap_or("-")
                );
            });
            if v_unsupported(&st) {
                Err(ExitCode::ProfileUnavailable)
            } else {
                Ok(())
            }
        }
    }
}

fn v_unsupported(st: &serde_json::Value) -> bool {
    st["support"].as_str() == Some("unsupported")
        || st["notes"].as_array().is_some_and(|notes| {
            notes.iter().any(|n| {
                n.as_str().is_some_and(|s| {
                    let l = s.to_ascii_lowercase();
                    l.contains("unsupported") || l.contains("fail-closed")
                })
            })
        })
}

/// Clear any legacy installed=true disguise on platforms without peer enforcement.
fn sanitize_status(mut st: serde_json::Value) -> serde_json::Value {
    let kind = st["endpoint_kind"].as_str().unwrap_or("");
    let unenforceable = cfg!(windows)
        || kind == "named_pipe"
        || kind == "loopback_tcp"
        || (kind == "unix_socket" && !cfg!(unix));
    if unenforceable {
        if let Some(obj) = st.as_object_mut() {
            obj.insert("installed".into(), json!(false));
            obj.insert("support".into(), json!("unsupported"));
            let mut notes = obj
                .get("notes")
                .and_then(|n| n.as_array())
                .cloned()
                .unwrap_or_default();
            if !notes.iter().any(|n| {
                n.as_str()
                    .is_some_and(|s| s.to_ascii_lowercase().contains("unsupported"))
            }) {
                notes.push(json!(
                    "unsupported: peer credential enforcement unavailable for this endpoint/platform"
                ));
            }
            obj.insert("notes".into(), json!(notes));
        }
    }
    st
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
        "support": if cfg!(windows) { "unsupported" } else { "supported" },
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
            return sanitize_status(v);
        }
    }
    json!({
        "installed": false,
        "network": "disabled",
        "endpoint": null,
        "endpoint_kind": "",
        "secret_present": base.join("broker").join("broker.secret").exists(),
        "notes": ["not installed"],
        "support": if cfg!(windows) { "unsupported" } else { "supported" },
    })
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
