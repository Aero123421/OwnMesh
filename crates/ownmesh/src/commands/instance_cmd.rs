//! Control-plane instance management backed by `config.toml`.

use crate::cli::{Cli, InstanceCmd};
use ownmesh_config::{
    load_config, redact_control_plane_url, save_config, validate_control_plane_base_url,
    InstanceConfig, OwnMeshConfig, OwnMeshPaths,
};
use ownmesh_domain::ExitCode;
use serde_json::json;
use std::collections::HashSet;

const MAX_INSTANCES: usize = 64;
const MAX_BASE_URL_BYTES: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstanceCommandError {
    Usage(&'static str),
    Conflict(&'static str),
    Internal(&'static str),
}

impl InstanceCommandError {
    const fn message(self) -> &'static str {
        match self {
            Self::Usage(message) | Self::Conflict(message) | Self::Internal(message) => message,
        }
    }

    const fn exit_code(self) -> ExitCode {
        match self {
            Self::Usage(_) => ExitCode::UsageConfig,
            Self::Conflict(_) => ExitCode::Conflict,
            Self::Internal(_) => ExitCode::Internal,
        }
    }
}

/// Dispatch instance CRUD against the existing `OwnMeshConfig.instances` schema.
pub fn dispatch_instance(cli: &Cli, cmd: &InstanceCmd) -> Result<(), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|_| {
        emit_error(
            cli,
            InstanceCommandError::Internal("configuration paths are unavailable"),
        )
    })?;
    dispatch_instance_with_paths(cli, cmd, &paths)
}

fn dispatch_instance_with_paths(
    cli: &Cli,
    cmd: &InstanceCmd,
    paths: &OwnMeshPaths,
) -> Result<(), ExitCode> {
    let result = match cmd {
        InstanceCmd::Add { id, base_url } => {
            add_instance(paths, id, base_url).map(|(instance, active)| {
                if cli.json {
                    println!(
                        "{}",
                        json!({
                            "schema_version": 1,
                            "status": "added",
                            "instance": instance_json(&instance, active),
                        })
                    );
                } else {
                    println!("added {}  {}", instance.id, safe_url(&instance.base_url));
                }
            })
        }
        InstanceCmd::List => list_instances(paths).map(|(instances, active)| {
            if cli.json {
                let items = instances
                    .iter()
                    .map(|instance| {
                        instance_json(instance, active.as_deref() == Some(&instance.id))
                    })
                    .collect::<Vec<_>>();
                println!(
                    "{}",
                    json!({
                        "schema_version": 1,
                        "active_instance": active,
                        "instances": items,
                    })
                );
            } else if instances.is_empty() {
                println!("(no instances)");
            } else {
                for instance in instances {
                    let marker = if active.as_deref() == Some(&instance.id) {
                        "*"
                    } else {
                        " "
                    };
                    println!("{marker} {}  {}", instance.id, safe_url(&instance.base_url));
                }
            }
        }),
        InstanceCmd::Use { id } => use_instance(paths, id).map(|()| {
            if cli.json {
                println!(
                    "{}",
                    json!({
                        "schema_version": 1,
                        "status": "active",
                        "instance_id": id,
                    })
                );
            } else {
                println!("active instance: {id}");
            }
        }),
        InstanceCmd::Remove { id } => remove_instance(paths, id).map(|active| {
            if cli.json {
                println!(
                    "{}",
                    json!({
                        "schema_version": 1,
                        "status": "removed",
                        "instance_id": id,
                        "active_instance": active,
                    })
                );
            } else {
                println!("removed {id}");
                match active {
                    Some(active) => println!("active instance: {active}"),
                    None => println!("active instance: (unset)"),
                }
            }
        }),
    };

    result.map_err(|error| emit_error(cli, error))
}

fn emit_error(cli: &Cli, error: InstanceCommandError) -> ExitCode {
    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "ok": false,
                "error": "instance_error",
                "message": error.message(),
            })
        );
    } else {
        eprintln!("ownmesh instance: {}", error.message());
    }
    error.exit_code()
}

fn load(paths: &OwnMeshPaths) -> Result<OwnMeshConfig, InstanceCommandError> {
    let cfg = load_config(paths).map_err(|_| {
        InstanceCommandError::Usage(
            "configuration could not be loaded; run `ownmesh config validate`",
        )
    })?;
    validate_registry(&cfg)?;
    Ok(cfg)
}

fn save(paths: &OwnMeshPaths, cfg: &OwnMeshConfig) -> Result<(), InstanceCommandError> {
    save_config(paths, cfg)
        .map_err(|_| InstanceCommandError::Internal("configuration could not be saved"))
}

fn add_instance(
    paths: &OwnMeshPaths,
    id: &str,
    base_url: &str,
) -> Result<(InstanceConfig, bool), InstanceCommandError> {
    validate_instance_id(id)?;
    if base_url.len() > MAX_BASE_URL_BYTES {
        return Err(InstanceCommandError::Usage(
            "control-plane URL exceeds the size limit",
        ));
    }
    let normalized = validate_control_plane_base_url(base_url)
        .map_err(|_| InstanceCommandError::Usage("control-plane URL is invalid"))?;

    let mut cfg = load(paths)?;
    if cfg.instances.iter().any(|instance| instance.id == id) {
        return Err(InstanceCommandError::Conflict(
            "an instance with that id already exists",
        ));
    }
    if cfg.instances.len() >= MAX_INSTANCES {
        return Err(InstanceCommandError::Usage("instance limit reached"));
    }

    let instance = InstanceConfig {
        id: id.to_owned(),
        base_url: normalized,
        display_name: None,
    };
    cfg.instances.push(instance.clone());
    if cfg.active_instance.is_none() {
        cfg.active_instance = Some(instance.id.clone());
    }
    cfg.validate()
        .map_err(|_| InstanceCommandError::Usage("instance configuration is invalid"))?;
    let active = cfg.active_instance.as_deref() == Some(&instance.id);
    save(paths, &cfg)?;
    Ok((instance, active))
}

fn list_instances(
    paths: &OwnMeshPaths,
) -> Result<(Vec<InstanceConfig>, Option<String>), InstanceCommandError> {
    let cfg = load(paths)?;
    let mut instances = cfg.instances;
    instances.sort_by(|left, right| left.id.cmp(&right.id));
    Ok((instances, cfg.active_instance))
}

fn use_instance(paths: &OwnMeshPaths, id: &str) -> Result<(), InstanceCommandError> {
    validate_instance_id(id)?;
    let mut cfg = load(paths)?;
    if !cfg.instances.iter().any(|instance| instance.id == id) {
        return Err(InstanceCommandError::Usage("instance does not exist"));
    }
    cfg.active_instance = Some(id.to_owned());
    save(paths, &cfg)
}

fn remove_instance(paths: &OwnMeshPaths, id: &str) -> Result<Option<String>, InstanceCommandError> {
    validate_instance_id(id)?;
    let mut cfg = load(paths)?;
    let before = cfg.instances.len();
    cfg.instances.retain(|instance| instance.id != id);
    if cfg.instances.len() == before {
        return Err(InstanceCommandError::Usage("instance does not exist"));
    }
    if cfg.active_instance.as_deref() == Some(id) {
        cfg.active_instance = cfg.instances.first().map(|instance| instance.id.clone());
    }
    save(paths, &cfg)?;
    Ok(cfg.active_instance)
}

fn validate_instance_id(id: &str) -> Result<(), InstanceCommandError> {
    let valid = !id.is_empty()
        && id.len() <= 64
        && id != "."
        && id != ".."
        && id.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(InstanceCommandError::Usage(
            "instance id must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}",
        ))
    }
}

fn validate_registry(cfg: &OwnMeshConfig) -> Result<(), InstanceCommandError> {
    if cfg.instances.len() > MAX_INSTANCES {
        return Err(InstanceCommandError::Usage(
            "configured instance registry is invalid",
        ));
    }
    let mut ids = HashSet::with_capacity(cfg.instances.len());
    for instance in &cfg.instances {
        if validate_instance_id(&instance.id).is_err() || !ids.insert(instance.id.as_str()) {
            return Err(InstanceCommandError::Usage(
                "configured instance registry is invalid",
            ));
        }
    }
    if let Some(active) = cfg.active_instance.as_deref() {
        if !ids.contains(active) {
            return Err(InstanceCommandError::Usage(
                "configured instance registry is invalid",
            ));
        }
    }
    Ok(())
}

fn safe_url(raw: &str) -> String {
    let redacted = redact_control_plane_url(raw);
    if redacted.is_empty() {
        "[REDACTED]".into()
    } else {
        redacted
    }
}

fn instance_json(instance: &InstanceConfig, active: bool) -> serde_json::Value {
    json!({
        "id": instance.id,
        "base_url": safe_url(&instance.base_url),
        "active": active,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn instance_crud_uses_existing_config_and_has_deterministic_active_selection() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());

        let (home, active) = add_instance(&paths, "home", "https://cp.example.test/").unwrap();
        assert_eq!(home.base_url, "https://cp.example.test");
        assert!(active);
        let (_, active) = add_instance(&paths, "server-2", "http://127.0.0.1:8787").unwrap();
        assert!(!active);
        assert_eq!(
            load_config(&paths).unwrap().active_instance.as_deref(),
            Some("home")
        );

        use_instance(&paths, "server-2").unwrap();
        assert_eq!(
            load_config(&paths).unwrap().active_instance.as_deref(),
            Some("server-2")
        );
        let active = remove_instance(&paths, "server-2").unwrap();
        assert_eq!(active.as_deref(), Some("home"));
        assert_eq!(load_config(&paths).unwrap().instances.len(), 1);
    }

    #[test]
    fn instance_rejects_unsafe_ids_urls_and_duplicates_without_mutation() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());

        for bad_id in ["", ".", "../home", "has space", "line\nbreak", "-leading"] {
            let error = add_instance(&paths, bad_id, "https://cp.example.test").unwrap_err();
            assert_eq!(
                error.message(),
                "instance id must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}"
            );
        }
        for bad_url in [
            "http://example.test",
            "https://user:secret@example.test",
            "https://example.test/?access_token=secret",
        ] {
            let error = add_instance(&paths, "home", bad_url).unwrap_err();
            assert_eq!(error.message(), "control-plane URL is invalid");
            assert!(!error.message().contains("secret"));
        }

        add_instance(&paths, "home", "https://cp.example.test").unwrap();
        let before = std::fs::read(paths.config_file()).unwrap();
        let error = add_instance(&paths, "home", "https://other.example.test").unwrap_err();
        assert_eq!(error.exit_code(), ExitCode::Conflict);
        assert_eq!(std::fs::read(paths.config_file()).unwrap(), before);
    }
}
