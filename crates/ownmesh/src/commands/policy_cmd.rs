//! `ownmesh policy` — inspect and select local policy via ownmeshd / files.

use crate::cli::{Cli, PolicyCmd, PolicyRuleCmd};
use crate::commands::admin_flow::run_admin_operation;
use crate::commands::ipc_util::{
    call_daemon_recoverable, emit_ipc_err, ipc_exit_code, print_value,
};
use ownmesh_config::{load_policy, OwnMeshPaths, PolicyFile};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::methods;
use ownmesh_policy::{
    evaluate, full_access_has_no_hidden_restrictive_rules, preset_document, AccessPreset,
    OperationFacts,
};
use serde_json::json;

pub fn dispatch_policy(cli: &Cli, cmd: &PolicyCmd) -> Result<(), ExitCode> {
    match cmd {
        PolicyCmd::Show => match call_daemon_recoverable(cli, methods::POLICY_SHOW, None) {
            Ok(value) => {
                print_value(cli.json, &value, |v| {
                    println!("preset: {}", v["preset"].as_str().unwrap_or("?"));
                    if let Some(note) = v["note"].as_str() {
                        println!("note: {note}");
                    }
                    println!("lockdown: {}", v["lockdown"]);
                    let rules = v["rules"].as_array().map_or(0, Vec::len);
                    println!("rules: {rules}");
                    if v["preset"] == "full_access" {
                        println!(
                            "full_access_no_hidden_deny: {}",
                            v["full_access_no_hidden_deny"]
                        );
                    }
                });
                Ok(())
            }
            Err(err) if ipc_exit_code(&err) == ExitCode::DeviceOffline => show_offline(cli),
            Err(err) => Err(emit_ipc_err(cli, &err)),
        },
        PolicyCmd::Preset {
            name,
            delegate_remote_mcp,
            idempotency_key,
        } => {
            let mut payload = json!({
                "name": name,
                "delegate_remote_mcp": delegate_remote_mcp,
                "idempotency_key": idempotency_key,
            });
            remove_null_fields(&mut payload);
            run_admin_operation(
                cli,
                "ownmesh_policy_preset",
                payload,
                "policy preset changed",
                false,
            )
        }
        PolicyCmd::Rule(command) => dispatch_policy_rule(cli, command),
        PolicyCmd::Validate => match call_daemon_recoverable(cli, methods::POLICY_VALIDATE, None) {
            Ok(value) => {
                print_value(cli.json, &value, |v| {
                    if v["ok"].as_bool() == Some(true) {
                        println!(
                            "policy ok (preset={}, rules={})",
                            v["preset"].as_str().unwrap_or("?"),
                            v["rule_count"]
                        );
                    } else {
                        println!("policy invalid: {v}");
                    }
                });
                if cli.json && value["ok"].as_bool() != Some(true) {
                    crate::commands::fail::note_envelope_emitted();
                }
                if value["ok"].as_bool() == Some(true) {
                    Ok(())
                } else {
                    Err(ExitCode::UsageConfig)
                }
            }
            Err(err) if ipc_exit_code(&err) == ExitCode::DeviceOffline => validate_offline(cli),
            Err(err) => Err(emit_ipc_err(cli, &err)),
        },
        PolicyCmd::Explain {
            query,
            path,
            workspace_id,
        } => {
            let mut params = json!({ "query": query });
            if let Some(path) = path {
                params["path"] = json!(path);
            }
            if let Some(workspace_id) = workspace_id {
                params["workspace_id"] = json!(workspace_id);
            }
            match call_daemon_recoverable(cli, methods::POLICY_EXPLAIN, Some(params)) {
                Ok(value) => {
                    print_value(cli.json, &value, |v| {
                        println!(
                            "decision={} reason={}",
                            v["decision"].as_str().unwrap_or("?"),
                            v["reason"].as_str().unwrap_or("")
                        );
                    });
                    Ok(())
                }
                Err(err) if ipc_exit_code(&err) == ExitCode::DeviceOffline => {
                    explain_offline(cli, query, path.as_deref())
                }
                Err(err) => Err(emit_ipc_err(cli, &err)),
            }
        }
    }
}

fn show_offline(cli: &Cli) -> Result<(), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|_| ExitCode::UsageConfig)?;
    let file = load_policy(&paths).map_err(|e| {
        eprintln!("policy load error: {e}");
        ExitCode::UsageConfig
    })?;
    let preset = file.preset.as_deref().unwrap_or("recommended");
    let doc = document_from_file(&file);
    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "source": "local_file",
                "preset": preset,
                "rules": doc.rules,
                "full_access_no_hidden_deny": full_access_has_no_hidden_restrictive_rules(&doc)
                    || doc.preset != AccessPreset::FullAccess,
            })
        );
    } else {
        println!("preset: {preset} (daemon offline — local file)");
        println!("rules: {}", doc.rules.len());
    }
    Ok(())
}

fn validate_offline(cli: &Cli) -> Result<(), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|_| ExitCode::UsageConfig)?;
    let file = load_policy(&paths).map_err(|e| {
        eprintln!("policy load error: {e}");
        ExitCode::UsageConfig
    })?;
    file.validate().map_err(|e| {
        eprintln!("policy invalid: {e}");
        ExitCode::UsageConfig
    })?;
    let preset = file.preset.as_deref().unwrap_or("recommended");
    let doc = document_from_file(&file);
    let ok = if doc.preset == AccessPreset::FullAccess {
        full_access_has_no_hidden_restrictive_rules(&doc)
    } else {
        true
    };
    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "ok": ok,
                "preset": preset,
                "source": "local_file",
            })
        );
        if !ok {
            crate::commands::fail::note_envelope_emitted();
        }
    } else if ok {
        println!("policy ok (local file, preset={preset})");
    } else {
        println!("full access hidden deny detected");
    }
    if ok {
        Ok(())
    } else {
        Err(ExitCode::UsageConfig)
    }
}

/// Offline fallback evaluates the policy file only; daemon-held grants and
/// daemon-derived path classifications are intentionally not guessed here.
fn explain_offline(cli: &Cli, query: &str, path: Option<&str>) -> Result<(), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|_| ExitCode::UsageConfig)?;
    let file = load_policy(&paths).unwrap_or_default();
    let doc = document_from_file(&file);
    let ql = query.to_ascii_lowercase();
    let facts = if ql.contains("write") {
        OperationFacts {
            capability: "filesystem.write".into(),
            kind: "file".into(),
            path: path.map(ToOwned::to_owned),
            ..Default::default()
        }
    } else if ql.contains("read") || ql.contains("list") {
        OperationFacts {
            capability: "filesystem.read".into(),
            kind: "file".into(),
            path: path.map(ToOwned::to_owned),
            ..Default::default()
        }
    } else {
        OperationFacts {
            capability: "command.run".into(),
            kind: "structured".into(),
            path: path.map(ToOwned::to_owned),
            ..Default::default()
        }
    };
    let v = evaluate(&doc, &facts);
    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "decision": format!("{:?}", v.decision).to_ascii_lowercase(),
                "reason": v.reason,
                "matched_rule_id": v.matched_rule_id,
                "source": "local_file",
            })
        );
    } else {
        println!("decision={:?} reason={}", v.decision, v.reason);
    }
    Ok(())
}

fn dispatch_policy_rule(cli: &Cli, command: &PolicyRuleCmd) -> Result<(), ExitCode> {
    match command {
        PolicyRuleCmd::Add {
            id,
            decision,
            capability,
            priority,
            when_elevated,
            when_kind,
            path_prefix,
            program_equals,
            description,
            idempotency_key,
        } => {
            let mut payload = json!({
                "id": id,
                "rule_decision": decision,
                "capability": capability,
                "priority": priority,
                "when_elevated": when_elevated,
                "when_kind": when_kind,
                "path_prefix": path_prefix,
                "program_equals": program_equals,
                "description": description,
                "idempotency_key": idempotency_key,
            });
            remove_null_fields(&mut payload);
            run_admin_operation(
                cli,
                "ownmesh_policy_rule_add",
                payload,
                "policy rule added",
                false,
            )
        }
        PolicyRuleCmd::Remove {
            id,
            idempotency_key,
        } => run_admin_operation(
            cli,
            "ownmesh_policy_rule_remove",
            json!({ "id": id, "idempotency_key": idempotency_key }),
            "policy rule removed",
            false,
        ),
    }
}

fn remove_null_fields(value: &mut serde_json::Value) {
    if let Some(object) = value.as_object_mut() {
        object.retain(|_, value| !value.is_null());
    }
}

fn document_from_file(file: &PolicyFile) -> ownmesh_policy::PolicyDocument {
    let mut document = preset_document(parse_preset_name(
        file.preset.as_deref().unwrap_or("recommended"),
    ));
    document.rules.extend(file.rules.iter().cloned());
    document
}

fn parse_preset_name(name: &str) -> AccessPreset {
    match name.to_ascii_lowercase().replace('-', "_").as_str() {
        "workspace_only" => AccessPreset::WorkspaceOnly,
        "full_user_access" => AccessPreset::FullUserAccess,
        "full_access" => AccessPreset::FullAccess,
        "custom" => AccessPreset::Custom,
        _ => AccessPreset::Recommended,
    }
}
