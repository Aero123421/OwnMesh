//! `ownmesh policy` — inspect and select local policy via ownmeshd / files.

use crate::cli::{Cli, PolicyCmd};
use crate::commands::ipc_util::{call_daemon, print_value};
use ownmesh_config::{load_policy, OwnMeshPaths};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::methods;
use ownmesh_policy::{
    evaluate, full_access_has_no_hidden_restrictive_rules, preset_document, AccessPreset,
    OperationFacts,
};
use serde_json::json;

pub fn dispatch_policy(cli: &Cli, cmd: &PolicyCmd) -> Result<(), ExitCode> {
    match cmd {
        PolicyCmd::Show => match call_daemon(methods::POLICY_SHOW, None) {
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
            Err(ExitCode::DeviceOffline) => show_offline(cli),
            Err(e) => Err(e),
        },
        PolicyCmd::Preset { name } => {
            let value = call_daemon(methods::POLICY_PRESET, Some(json!({ "name": name })))?;
            print_value(cli.json, &value, |v| {
                println!("preset set to {}", v["preset"].as_str().unwrap_or(name));
            });
            Ok(())
        }
        PolicyCmd::Rule { spec } => {
            if cli.json {
                println!(
                    "{}",
                    json!({
                        "schema_version": 1,
                        "status": "not_implemented",
                        "command": "policy rule",
                        "message": "policy rule mutation via DSL is unsupported",
                    })
                );
            } else {
                eprintln!("policy rule mutation via DSL is not implemented yet ({spec})");
            }
            Err(ExitCode::ProfileUnavailable)
        }
        PolicyCmd::Validate => match call_daemon(methods::POLICY_VALIDATE, None) {
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
                if value["ok"].as_bool() == Some(true) {
                    Ok(())
                } else {
                    Err(ExitCode::UsageConfig)
                }
            }
            Err(ExitCode::DeviceOffline) => validate_offline(cli),
            Err(e) => Err(e),
        },
        PolicyCmd::Explain { query } => {
            match call_daemon(methods::POLICY_EXPLAIN, Some(json!({ "query": query }))) {
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
                Err(ExitCode::DeviceOffline) => explain_offline(cli, query),
                Err(e) => Err(e),
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
    let doc = preset_document(parse_preset_name(preset));
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
    let doc = preset_document(parse_preset_name(preset));
    let ok = if doc.preset == AccessPreset::FullAccess {
        full_access_has_no_hidden_restrictive_rules(&doc)
    } else {
        true
    };
    if cli.json {
        println!(
            "{}",
            json!({"ok": ok, "preset": preset, "source": "local_file"})
        );
    } else if ok {
        println!("policy ok (local file, preset={preset})");
    } else {
        println!("full access hidden deny detected");
        return Err(ExitCode::UsageConfig);
    }
    Ok(())
}

fn explain_offline(cli: &Cli, query: &str) -> Result<(), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|_| ExitCode::UsageConfig)?;
    let file = load_policy(&paths).unwrap_or_default();
    let doc = preset_document(parse_preset_name(
        file.preset.as_deref().unwrap_or("recommended"),
    ));
    let ql = query.to_ascii_lowercase();
    let facts = if ql.contains("write") {
        OperationFacts {
            capability: "filesystem.write".into(),
            kind: "file".into(),
            ..Default::default()
        }
    } else {
        OperationFacts {
            capability: "command.run".into(),
            kind: "structured".into(),
            ..Default::default()
        }
    };
    let v = evaluate(&doc, &facts);
    if cli.json {
        println!(
            "{}",
            json!({
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

fn parse_preset_name(name: &str) -> AccessPreset {
    match name.to_ascii_lowercase().replace('-', "_").as_str() {
        "workspace_only" => AccessPreset::WorkspaceOnly,
        "full_user_access" => AccessPreset::FullUserAccess,
        "full_access" => AccessPreset::FullAccess,
        "custom" => AccessPreset::Custom,
        _ => AccessPreset::Recommended,
    }
}
