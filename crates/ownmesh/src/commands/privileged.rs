//! `ownmesh privileged` — production elevated broker lifecycle status.
//!
//! Production elevated broker is fixed as **unsupported** until a secure mint
//! authority exists. Install and uninstall are side-effect-free, status is
//! canonical, and no path spawns elevated processes.

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

fn canonical_status(base: &Path, record: Option<Value>) -> Value {
    let malformed_shape = record.as_ref().is_some_and(|value| !value.is_object());
    let mut object = record
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_else(Map::new);
    let broker_dir = base.join("broker");

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

fn report_unsupported(cli: &Cli, status: &Value) -> Result<(), ExitCode> {
    print_value(cli.json, status, |value| {
        println!(
            "privileged broker unsupported (installed=false) endpoint={}",
            value["endpoint"].as_str().unwrap_or("-")
        );
        if let Some(notes) = value["notes"].as_array() {
            for note in notes.iter().filter_map(Value::as_str) {
                println!("note: {note}");
            }
        }
    });
    Err(ExitCode::ProfileUnavailable)
}

fn run_install(cli: &Cli) -> Result<(), ExitCode> {
    let base = state_base()?;
    // Deliberately do not mkdir, write a marker/template, or create key material.
    report_unsupported(cli, &canonical_status(&base, None))
}

fn run_status(cli: &Cli) -> Result<(), ExitCode> {
    let base = state_base()?;
    let status = read_status_json(&base);
    print_value(cli.json, &status, |value| {
        println!(
            "privileged status=unsupported support={} network={} endpoint={}",
            value["support"].as_str().unwrap_or("unsupported"),
            value["network"].as_str().unwrap_or("disabled"),
            value["endpoint"].as_str().unwrap_or("-")
        );
    });
    Err(ExitCode::ProfileUnavailable)
}

fn run_uninstall(cli: &Cli) -> Result<(), ExitCode> {
    let base = state_base()?;
    // Deliberately do not delete or rewrite privileged state. Manual cleanup is
    // an explicit operator action while this production feature is unsupported.
    report_unsupported(cli, &canonical_status(&base, None))
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
        for malformed in [json!(true), json!([{"installed": true}])] {
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
        let status = canonical_status(
            base.path(),
            Some(json!({
                "installed": true,
                "support": "supported",
                "endpoint": "unix:/tmp/forged.sock"
            })),
        );
        assert_eq!(status["installed"], false);
        assert_eq!(status["support"], "unsupported");
        assert_eq!(status["endpoint"], "unix:/tmp/forged.sock");
    }
}
