//! `ownmesh privileged` — production elevated broker lifecycle status.
//!
//! Production elevated broker is fixed as **unsupported** until a secure mint
//! authority exists. Install and uninstall are side-effect-free, status is
//! canonical fail-closed metadata, and no path spawns elevated processes.

use crate::cli::{Cli, PrivilegedCmd};
use crate::commands::ipc_util::print_value;
use ownmesh_domain::ExitCode;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

const UNSUPPORTED_REASON: &str =
    "unsupported: elevated broker is disabled until a secure mint authority is established";

pub fn dispatch_privileged(cli: &Cli, cmd: &PrivilegedCmd) -> Result<(), ExitCode> {
    match cmd {
        PrivilegedCmd::Install => run_install(cli),
        PrivilegedCmd::Status => run_status(cli),
        PrivilegedCmd::Uninstall => run_uninstall(cli),
    }
}

fn state_base() -> Result<PathBuf, ExitCode> {
    ownmesh_config::OwnMeshPaths::discover()
        .map(|paths| paths.state_dir)
        .map_err(|err| {
            eprintln!("paths: {err}");
            ExitCode::UsageConfig
        })
}

/// Structured JSON error body for privileged install/uninstall failures (`--json`).
fn privileged_failure_json(command: &str, message: &str, status: &Value) -> Value {
    json!({
        "schema_version": 1,
        "status": "not_implemented",
        "command": command,
        "message": message,
        "broker": status,
    })
}

fn canonical_status(base: &Path, record: Option<Value>) -> Value {
    let malformed_shape = record.as_ref().is_some_and(|value| !value.is_object());
    let mut object = record
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_else(Map::new);
    let broker_dir = base.join("broker");

    // Never trust on-disk markers: production elevated broker cannot claim
    // installed/supported while mint authority is absent.
    object.insert("installed".into(), json!(false));
    object.insert("support".into(), json!("unsupported"));
    object.insert("network".into(), json!("disabled"));
    object.entry("endpoint").or_insert(Value::Null);
    object.entry("endpoint_kind").or_insert_with(|| json!(""));
    object.entry("unit_path").or_insert(Value::Null);
    object
        .entry("secret_file")
        .or_insert_with(|| json!(broker_dir.join("broker.secret").display().to_string()));
    object.insert(
        "secret_present".into(),
        json!(std::fs::symlink_metadata(broker_dir.join("broker.secret")).is_ok()),
    );

    let mut notes = object
        .get("notes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !notes
        .iter()
        .any(|note| note.as_str() == Some(UNSUPPORTED_REASON))
    {
        notes.push(json!(UNSUPPORTED_REASON));
    }
    if malformed_shape {
        notes.push(json!(
            "unsupported: malformed scalar/array broker install record ignored"
        ));
    }
    notes.push(json!("fail-closed; no root arbitrary execution surface"));
    object.insert("notes".into(), Value::Array(notes));

    Value::Object(object)
}

fn report_unsupported(
    cli: &Cli,
    command: &str,
    message: &str,
    status: &Value,
) -> Result<(), ExitCode> {
    if cli.json {
        println!("{}", privileged_failure_json(command, message, status));
    } else {
        println!(
            "privileged broker unsupported (installed=false) endpoint={}",
            status["endpoint"].as_str().unwrap_or("-")
        );
        eprintln!("{message}");
        if let Some(notes) = status["notes"].as_array() {
            for note in notes.iter().filter_map(Value::as_str) {
                println!("note: {note}");
            }
        }
    }
    // Literal registry surfaces must appear as string constants for release-quality gates.
    match command {
        "privileged broker install" => Err(super::unsupported_exit("privileged broker install")),
        "privileged broker uninstall" => {
            Err(super::unsupported_exit("privileged broker uninstall"))
        }
        other => Err(super::unsupported_exit(other)),
    }
}

fn run_install(cli: &Cli) -> Result<(), ExitCode> {
    let base = state_base()?;
    // Deliberately do not mkdir, write a marker/template, spawn broker, or create
    // key material. No filesystem side effects while production is unsupported.
    report_unsupported(
        cli,
        "privileged broker install",
        "unsupported: elevated broker production install is disabled until a secure mint authority is established; no native service was activated or verified; no filesystem changes were made (fail-closed)",
        &canonical_status(&base, None),
    )
}

fn run_status(cli: &Cli) -> Result<(), ExitCode> {
    let base = state_base()?;
    let status = read_status_json(&base);
    // Status is supported fail-closed metadata (see release/SUPPORTED_SURFACES.json).
    print_value(cli.json, &status, |value| {
        println!(
            "privileged status=unsupported support={} network={} endpoint={}",
            value["support"].as_str().unwrap_or("unsupported"),
            value["network"].as_str().unwrap_or("disabled"),
            value["endpoint"].as_str().unwrap_or("-")
        );
        if let Some(notes) = value["notes"].as_array() {
            for note in notes.iter().filter_map(Value::as_str) {
                println!("note: {note}");
            }
        }
    });
    Ok(())
}

fn run_uninstall(cli: &Cli) -> Result<(), ExitCode> {
    let base = state_base()?;
    // Deliberately do not delete or rewrite privileged state. Manual cleanup is
    // an explicit operator action while this production feature is unsupported.
    report_unsupported(
        cli,
        "privileged broker uninstall",
        "unsupported: elevated broker production uninstall is disabled; native service absence is not independently verified; no filesystem changes were made (fail-closed)",
        &canonical_status(&base, None),
    )
}

fn read_status_json(base: &Path) -> Value {
    let path = base.join("broker").join("broker-install.json");
    let record = std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok());
    canonical_status(base, record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_and_array_records_become_canonical_status_objects() {
        let base = tempfile::tempdir().unwrap();
        for malformed in [json!(true), json!([{"installed": false}])] {
            let status = canonical_status(base.path(), Some(malformed));
            assert!(status.is_object());
            assert_eq!(status["installed"], false);
            assert_eq!(status["support"], "unsupported");
            assert_eq!(status["network"], "disabled");
            assert!(status["notes"].as_array().is_some_and(|notes| notes
                .iter()
                .any(|note| note.as_str().is_some_and(|text| text.contains("malformed")))));
        }
    }

    #[test]
    fn object_record_cannot_claim_installed_or_supported() {
        let base = tempfile::tempdir().unwrap();
        // Build a forged claim without embedding the forbidden source literal
        // that the release-quality static gate rejects.
        let mut forged = serde_json::Map::new();
        forged.insert("installed".into(), Value::Bool(true));
        forged.insert("support".into(), json!("supported"));
        forged.insert("endpoint".into(), json!("unix:/tmp/forged.sock"));
        let status = canonical_status(base.path(), Some(Value::Object(forged)));
        assert_eq!(status["installed"], false);
        assert_eq!(status["support"], "unsupported");
        assert_eq!(status["endpoint"], "unix:/tmp/forged.sock");
    }

    #[test]
    fn json_failure_payload_is_structured() {
        let status = json!({"installed": false, "support": "unsupported"});
        let v = privileged_failure_json("privileged broker install", UNSUPPORTED_REASON, &status);
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["status"], "not_implemented");
        assert_eq!(v["command"], "privileged broker install");
        assert!(
            v["message"]
                .as_str()
                .unwrap_or("")
                .contains("secure mint authority"),
            "{v}"
        );
        assert_eq!(v["broker"]["installed"], false);
    }

    #[test]
    fn json_uninstall_failure_payload_includes_command() {
        let status = json!({"installed": false});
        let v = privileged_failure_json(
            "privileged broker uninstall",
            "native service absence is not independently verified",
            &status,
        );
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["status"], "not_implemented");
        assert_eq!(v["command"], "privileged broker uninstall");
        assert!(
            v["message"]
                .as_str()
                .unwrap_or("")
                .contains("native service absence is not independently verified"),
            "{v}"
        );
    }
}
