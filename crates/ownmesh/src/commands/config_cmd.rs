//! Safe `ownmesh config` inspection and mutation.

use crate::auth::SessionPaths;
use crate::cli::{Cli, ConfigCmd};
use ownmesh_config::{
    appears_secret_free, load_config, load_policy, save_config, validate_control_plane_base_url,
    OwnMeshConfig, OwnMeshPaths,
};
use ownmesh_domain::ExitCode;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_EDIT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigCommandError {
    Usage(&'static str),
    Internal(&'static str),
}

impl ConfigCommandError {
    const fn message(self) -> &'static str {
        match self {
            Self::Usage(message) | Self::Internal(message) => message,
        }
    }

    const fn exit_code(self) -> ExitCode {
        match self {
            Self::Usage(_) => ExitCode::UsageConfig,
            Self::Internal(_) => ExitCode::Internal,
        }
    }
}

/// Dispatch the public configuration commands.
pub fn dispatch_config(cli: &Cli, cmd: &ConfigCmd) -> Result<(), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|_| {
        emit_error(
            cli,
            ConfigCommandError::Internal("configuration paths are unavailable"),
        )
    })?;
    dispatch_config_with_paths(cli, cmd, &paths)
}

fn dispatch_config_with_paths(
    cli: &Cli,
    cmd: &ConfigCmd,
    paths: &OwnMeshPaths,
) -> Result<(), ExitCode> {
    let result = match cmd {
        ConfigCmd::Get { key } => get_config(paths, key).map(|value| {
            if cli.json {
                println!(
                    "{}",
                    json!({
                        "schema_version": 1,
                        "key": key,
                        "value": value,
                    })
                );
            } else {
                print_config_value(&value);
            }
        }),
        ConfigCmd::Set { key, value } => set_config(paths, key, value).map(|()| {
            if cli.json {
                println!(
                    "{}",
                    json!({
                        "schema_version": 1,
                        "status": "updated",
                        "key": key,
                    })
                );
            } else {
                println!("updated {key}");
            }
        }),
        ConfigCmd::Edit => edit_config(paths).map(|()| {
            if cli.json {
                println!(
                    "{}",
                    json!({
                        "schema_version": 1,
                        "status": "updated",
                        "config": paths.config_file(),
                    })
                );
            } else {
                println!("configuration updated");
            }
        }),
        ConfigCmd::Validate => validate_config(paths).map(|()| {
            if cli.json {
                println!(
                    "{}",
                    json!({
                        "schema_version": 1,
                        "ok": true,
                        "config": paths.config_file(),
                    })
                );
            } else {
                println!("configuration and policy are valid");
            }
        }),
    };

    result.map_err(|error| emit_error(cli, error))
}

fn emit_error(cli: &Cli, error: ConfigCommandError) -> ExitCode {
    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "ok": false,
                "error": "config_error",
                "message": error.message(),
            })
        );
    } else {
        eprintln!("ownmesh config: {}", error.message());
    }
    error.exit_code()
}

fn load(paths: &OwnMeshPaths) -> Result<OwnMeshConfig, ConfigCommandError> {
    load_config(paths).map_err(|_| {
        ConfigCommandError::Usage(
            "configuration could not be loaded; run `ownmesh config validate`",
        )
    })
}

fn get_config(paths: &OwnMeshPaths, key: &str) -> Result<Value, ConfigCommandError> {
    let cfg = load(paths)?;
    let value = match key {
        "schema_version" => json!(cfg.schema_version),
        "active_instance" => option_string(cfg.active_instance.as_deref()),
        "lang" => safe_string_value(&cfg.lang),
        "update.mode" => json!(cfg.update.mode),
        "update.channel" => json!(cfg.update.channel),
        "telemetry.project" => json!(cfg.telemetry.project),
        "telemetry.crash_upload" => json!(cfg.telemetry.crash_upload),
        "telemetry.usage_analytics" => json!(cfg.telemetry.usage_analytics),
        "service_socket.path" => option_string(cfg.service_socket.path.as_deref()),
        "service_socket.owner" => option_string(cfg.service_socket.owner.as_deref()),
        "service_socket.group" => option_string(cfg.service_socket.group.as_deref()),
        "service_socket.mode" => option_string(cfg.service_socket.mode.as_deref()),
        "service_socket.allowed_uids" => json!(cfg.service_socket.allowed_uids),
        _ => {
            return Err(ConfigCommandError::Usage(
                "unknown or non-readable configuration key",
            ));
        }
    };
    Ok(value)
}

fn option_string(value: Option<&str>) -> Value {
    value.map_or(Value::Null, safe_string_value)
}

fn safe_string_value(value: &str) -> Value {
    if value.len() > 4096 || value.chars().any(char::is_control) || contains_secret_marker(value) {
        json!("[REDACTED]")
    } else {
        json!(value)
    }
}

fn print_config_value(value: &Value) {
    match value {
        Value::Null => println!("(unset)"),
        Value::String(value) => println!("{value}"),
        other => println!("{other}"),
    }
}

fn set_config(paths: &OwnMeshPaths, key: &str, value: &str) -> Result<(), ConfigCommandError> {
    if contains_secret_marker(key) || contains_secret_marker(value) {
        return Err(ConfigCommandError::Usage(
            "configuration values must not contain secret material",
        ));
    }

    let mut cfg = load(paths)?;
    match key {
        "active_instance" => {
            if value == "none" {
                cfg.active_instance = None;
            } else if valid_instance_id(value) && cfg.instances.iter().any(|item| item.id == value)
            {
                cfg.active_instance = Some(value.to_owned());
            } else {
                return Err(ConfigCommandError::Usage(
                    "active_instance must name an existing valid instance",
                ));
            }
        }
        "lang" => {
            if !valid_language_tag(value) {
                return Err(ConfigCommandError::Usage("invalid language tag"));
            }
            cfg.lang = value.to_owned();
        }
        "update.mode" => {
            cfg.update.mode =
                parse_enum(value, &["off", "check", "notify", "download", "auto"])?.to_owned();
        }
        "update.channel" => {
            cfg.update.channel = parse_enum(value, &["stable", "beta", "nightly"])?.to_owned();
        }
        "telemetry.project" => cfg.telemetry.project = parse_bool(value)?,
        "telemetry.crash_upload" => cfg.telemetry.crash_upload = parse_bool(value)?,
        "telemetry.usage_analytics" => cfg.telemetry.usage_analytics = parse_bool(value)?,
        "service_socket.path" => {
            cfg.service_socket.path = parse_optional_text(value, 4096)?;
        }
        "service_socket.owner" => cfg.service_socket.owner = parse_optional_u32(value)?,
        "service_socket.group" => cfg.service_socket.group = parse_optional_u32(value)?,
        "service_socket.mode" => {
            cfg.service_socket.mode = if value == "none" {
                None
            } else {
                Some(value.to_owned())
            };
        }
        "service_socket.allowed_uids" => {
            cfg.service_socket.allowed_uids = parse_u32_list(value)?;
        }
        "schema_version" => {
            return Err(ConfigCommandError::Usage("schema_version is read-only"));
        }
        _ => {
            return Err(ConfigCommandError::Usage(
                "unknown or non-writable configuration key",
            ));
        }
    }

    cfg.validate()
        .map_err(|_| ConfigCommandError::Usage("configuration value is invalid"))?;
    if key == "active_instance" {
        validate_session_issuer_binding(paths, &cfg)?;
    }
    save_config(paths, &cfg)
        .map_err(|_| ConfigCommandError::Internal("configuration could not be saved"))
}

fn parse_bool(value: &str) -> Result<bool, ConfigCommandError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(ConfigCommandError::Usage("expected `true` or `false`")),
    }
}

fn parse_enum<'a>(value: &'a str, allowed: &[&str]) -> Result<&'a str, ConfigCommandError> {
    if allowed.contains(&value) {
        Ok(value)
    } else {
        Err(ConfigCommandError::Usage(
            "configuration value is not in the allowed set",
        ))
    }
}

fn parse_optional_text(value: &str, max_len: usize) -> Result<Option<String>, ConfigCommandError> {
    if value == "none" {
        return Ok(None);
    }
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        return Err(ConfigCommandError::Usage("configuration text is invalid"));
    }
    Ok(Some(value.to_owned()))
}

fn parse_optional_u32(value: &str) -> Result<Option<String>, ConfigCommandError> {
    if value == "none" {
        return Ok(None);
    }
    value
        .parse::<u32>()
        .map(|parsed| Some(parsed.to_string()))
        .map_err(|_| ConfigCommandError::Usage("expected a decimal user or group id"))
}

fn parse_u32_list(value: &str) -> Result<Vec<u32>, ConfigCommandError> {
    if value.is_empty() || value == "none" {
        return Ok(Vec::new());
    }
    let values = value
        .split(',')
        .map(str::trim)
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ConfigCommandError::Usage("expected comma-separated decimal user ids"))?;
    if values.len() > 64 {
        return Err(ConfigCommandError::Usage("too many allowed user ids"));
    }
    Ok(values)
}

fn valid_language_tag(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 35
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_instance_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value != "."
        && value != ".."
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn contains_secret_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "access_token",
        "refresh_token",
        "client_secret",
        "private_key",
        "password",
        "bearer ",
        "-----begin",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn validate_config(paths: &OwnMeshPaths) -> Result<(), ConfigCommandError> {
    let cfg = load(paths)?;
    cfg.validate()
        .map_err(|_| ConfigCommandError::Usage("configuration is invalid"))?;
    load_policy(paths)
        .and_then(|policy| policy.validate())
        .map_err(|_| ConfigCommandError::Usage("policy is invalid"))?;
    Ok(())
}

fn edit_config(paths: &OwnMeshPaths) -> Result<(), ConfigCommandError> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(ConfigCommandError::Usage(
            "config edit requires an interactive terminal",
        ));
    }
    let editor = std::env::var_os("VISUAL")
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var_os("EDITOR").filter(|value| !value.is_empty()))
        .ok_or(ConfigCommandError::Usage(
            "set VISUAL or EDITOR to an explicit editor command",
        ))?;
    let editor_argv = parse_editor_argv(&editor)?;
    edit_config_with(paths, true, &editor_argv, launch_editor)
}

fn edit_config_with(
    paths: &OwnMeshPaths,
    interactive: bool,
    editor_argv: &[OsString],
    launch: impl FnOnce(&[OsString], &Path) -> io::Result<bool>,
) -> Result<(), ConfigCommandError> {
    if !interactive {
        return Err(ConfigCommandError::Usage(
            "config edit requires an interactive terminal",
        ));
    }
    if editor_argv.is_empty() {
        return Err(ConfigCommandError::Usage("editor command is empty"));
    }

    let cfg = load(paths)?;
    let rendered = toml::to_string_pretty(&cfg)
        .map_err(|_| ConfigCommandError::Internal("configuration could not be prepared"))?;
    let temp = EditFile::create(paths, rendered.as_bytes())?;
    let succeeded = launch(editor_argv, temp.path())
        .map_err(|_| ConfigCommandError::Usage("editor failed to start"))?;
    if !succeeded {
        return Err(ConfigCommandError::Usage(
            "editor exited without saving configuration",
        ));
    }

    let raw = read_bounded_regular_file(temp.path())?;
    if !appears_secret_free(&raw) {
        return Err(ConfigCommandError::Usage(
            "edited configuration contains forbidden secret material",
        ));
    }
    let value = raw
        .parse::<toml::Value>()
        .map_err(|_| ConfigCommandError::Usage("edited configuration is invalid"))?;
    validate_known_keys(&value)?;
    let edited: OwnMeshConfig = value
        .try_into()
        .map_err(|_| ConfigCommandError::Usage("edited configuration is invalid"))?;
    validate_edited_config(&edited)?;
    if active_issuer(&cfg) != active_issuer(&edited) {
        validate_session_issuer_binding(paths, &edited)?;
    }
    save_config(paths, &edited)
        .map_err(|_| ConfigCommandError::Internal("configuration could not be saved"))
}

fn parse_editor_argv(value: &OsStr) -> Result<Vec<OsString>, ConfigCommandError> {
    let raw = value.to_str().ok_or(ConfigCommandError::Usage(
        "editor command is not valid text",
    ))?;
    if raw
        .chars()
        .any(|character| matches!(character, '\0' | '\r' | '\n'))
    {
        return Err(ConfigCommandError::Usage("editor command is invalid"));
    }

    let mut argv = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for character in raw.chars() {
        match (quote, character) {
            (None, '\'' | '"') => quote = Some(character),
            (Some(open), close) if open == close => quote = None,
            (None, character) if character.is_whitespace() => {
                if !current.is_empty() {
                    argv.push(OsString::from(std::mem::take(&mut current)));
                }
            }
            _ => current.push(character),
        }
    }
    if quote.is_some() {
        return Err(ConfigCommandError::Usage(
            "editor command contains an unmatched quote",
        ));
    }
    if !current.is_empty() {
        argv.push(OsString::from(current));
    }
    if argv.is_empty() {
        return Err(ConfigCommandError::Usage("editor command is empty"));
    }
    Ok(argv)
}

fn launch_editor(argv: &[OsString], path: &Path) -> io::Result<bool> {
    let status = Command::new(&argv[0]).args(&argv[1..]).arg(path).status()?;
    Ok(status.success())
}

fn read_bounded_regular_file(path: &Path) -> Result<String, ConfigCommandError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| ConfigCommandError::Usage("edited configuration is unavailable"))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() > MAX_EDIT_BYTES
    {
        return Err(ConfigCommandError::Usage(
            "edited configuration is not a bounded regular file",
        ));
    }
    let file = File::open(path)
        .map_err(|_| ConfigCommandError::Usage("edited configuration is unavailable"))?;
    let mut raw = String::new();
    file.take(MAX_EDIT_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|_| ConfigCommandError::Usage("edited configuration is not valid UTF-8"))?;
    if raw.len() as u64 > MAX_EDIT_BYTES {
        return Err(ConfigCommandError::Usage(
            "edited configuration exceeds the size limit",
        ));
    }
    Ok(raw)
}

fn validate_known_keys(value: &toml::Value) -> Result<(), ConfigCommandError> {
    let table = value
        .as_table()
        .ok_or(ConfigCommandError::Usage("edited configuration is invalid"))?;
    if !only_keys(
        table,
        &[
            "schema_version",
            "active_instance",
            "lang",
            "update",
            "telemetry",
            "instances",
            "service_socket",
        ],
    ) {
        return Err(ConfigCommandError::Usage(
            "edited configuration contains unknown fields",
        ));
    }
    validate_subtable(table.get("update"), &["mode", "channel"])?;
    validate_subtable(
        table.get("telemetry"),
        &["project", "crash_upload", "usage_analytics"],
    )?;
    validate_subtable(
        table.get("service_socket"),
        &["path", "owner", "group", "mode", "allowed_uids"],
    )?;
    if let Some(instances) = table.get("instances") {
        let instances = instances
            .as_array()
            .ok_or(ConfigCommandError::Usage("edited configuration is invalid"))?;
        for instance in instances {
            let instance = instance
                .as_table()
                .ok_or(ConfigCommandError::Usage("edited configuration is invalid"))?;
            if !only_keys(instance, &["id", "base_url", "display_name"]) {
                return Err(ConfigCommandError::Usage(
                    "edited configuration contains unknown fields",
                ));
            }
        }
    }
    Ok(())
}

fn validate_edited_config(cfg: &OwnMeshConfig) -> Result<(), ConfigCommandError> {
    cfg.validate()
        .map_err(|_| ConfigCommandError::Usage("edited configuration is invalid"))?;
    if !valid_language_tag(&cfg.lang) || cfg.instances.len() > 64 {
        return Err(ConfigCommandError::Usage("edited configuration is invalid"));
    }

    let mut ids = HashSet::with_capacity(cfg.instances.len());
    for instance in &cfg.instances {
        if !valid_instance_id(&instance.id)
            || instance.base_url.len() > 2048
            || validate_control_plane_base_url(&instance.base_url).is_err()
            || !ids.insert(instance.id.as_str())
        {
            return Err(ConfigCommandError::Usage("edited configuration is invalid"));
        }
    }
    if let Some(active) = cfg.active_instance.as_deref() {
        if !valid_instance_id(active) || !ids.contains(active) {
            return Err(ConfigCommandError::Usage("edited configuration is invalid"));
        }
    }
    Ok(())
}

fn validate_session_issuer_binding(
    paths: &OwnMeshPaths,
    cfg: &OwnMeshConfig,
) -> Result<(), ConfigCommandError> {
    let Some(target) = active_issuer(cfg) else {
        return Ok(());
    };
    let session = SessionPaths::from_paths(paths.clone())
        .load_session()
        .map_err(|_| ConfigCommandError::Usage("authentication metadata is invalid"))?;
    if !session.has_refresh_token || session.issuer.is_empty() {
        return Ok(());
    }
    let bound = validate_control_plane_base_url(&session.issuer)
        .map_err(|_| ConfigCommandError::Usage("authentication metadata is invalid"))?;
    if bound == target {
        Ok(())
    } else {
        Err(ConfigCommandError::Usage(
            "log out before switching to a different control-plane instance",
        ))
    }
}

fn active_issuer(cfg: &OwnMeshConfig) -> Option<String> {
    let active = cfg.active_instance.as_deref()?;
    let instance = cfg
        .instances
        .iter()
        .find(|instance| instance.id == active)?;
    validate_control_plane_base_url(&instance.base_url).ok()
}

fn validate_subtable(
    value: Option<&toml::Value>,
    allowed: &[&str],
) -> Result<(), ConfigCommandError> {
    let Some(value) = value else {
        return Ok(());
    };
    let table = value
        .as_table()
        .ok_or(ConfigCommandError::Usage("edited configuration is invalid"))?;
    if only_keys(table, allowed) {
        Ok(())
    } else {
        Err(ConfigCommandError::Usage(
            "edited configuration contains unknown fields",
        ))
    }
}

fn only_keys(table: &toml::Table, allowed: &[&str]) -> bool {
    table.keys().all(|key| allowed.contains(&key.as_str()))
}

struct EditFile {
    path: PathBuf,
}

impl EditFile {
    fn create(paths: &OwnMeshPaths, contents: &[u8]) -> Result<Self, ConfigCommandError> {
        paths
            .ensure_layout()
            .map_err(|_| ConfigCommandError::Internal("configuration directory is unavailable"))?;
        for _ in 0..8 {
            let path = paths.config_dir.join(format!(
                ".config.edit.{}.{:016x}.toml",
                std::process::id(),
                rand::random::<u64>()
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    file.write_all(contents).map_err(|_| {
                        ConfigCommandError::Internal("temporary configuration could not be written")
                    })?;
                    file.sync_all().map_err(|_| {
                        ConfigCommandError::Internal("temporary configuration could not be synced")
                    })?;
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(_) => {
                    return Err(ConfigCommandError::Internal(
                        "temporary configuration could not be created",
                    ));
                }
            }
        }
        Err(ConfigCommandError::Internal(
            "temporary configuration could not be created",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for EditFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthSession;
    use std::cell::Cell;
    use tempfile::tempdir;

    #[test]
    fn set_is_typed_atomic_and_never_accepts_secret_material() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let _ = load_config(&paths).unwrap();

        set_config(&paths, "lang", "ja-JP").unwrap();
        set_config(&paths, "telemetry.project", "true").unwrap();
        let cfg = load_config(&paths).unwrap();
        assert_eq!(cfg.lang, "ja-JP");
        assert!(cfg.telemetry.project);

        let before = std::fs::read(paths.config_file()).unwrap();
        let error = set_config(&paths, "lang", "refresh_token=do-not-print").unwrap_err();
        assert_eq!(
            error.message(),
            "configuration values must not contain secret material"
        );
        assert_eq!(std::fs::read(paths.config_file()).unwrap(), before);

        let mut cfg = load_config(&paths).unwrap();
        cfg.instances = vec![
            ownmesh_config::InstanceConfig {
                id: "home".into(),
                base_url: "https://home.example.test".into(),
                display_name: None,
            },
            ownmesh_config::InstanceConfig {
                id: "other".into(),
                base_url: "https://other.example.test".into(),
                display_name: None,
            },
        ];
        cfg.active_instance = Some("home".into());
        save_config(&paths, &cfg).unwrap();
        SessionPaths::from_paths(paths.clone())
            .save_session(&AuthSession {
                issuer: "https://home.example.test".into(),
                client_id: "client".into(),
                has_refresh_token: true,
                ..AuthSession::default()
            })
            .unwrap();
        let before = std::fs::read(paths.config_file()).unwrap();
        let error = set_config(&paths, "active_instance", "other").unwrap_err();
        assert_eq!(
            error.message(),
            "log out before switching to a different control-plane instance"
        );
        assert_eq!(std::fs::read(paths.config_file()).unwrap(), before);
    }

    #[test]
    fn editor_is_argv_only_interactive_bounded_and_validated() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let _ = load_config(&paths).unwrap();
        let argv =
            parse_editor_argv(OsStr::new("\"C:\\Program Files\\Editor.exe\" --wait")).unwrap();
        assert_eq!(argv[0], OsString::from(r"C:\Program Files\Editor.exe"));
        assert_eq!(argv[1], OsString::from("--wait"));

        let called = Cell::new(false);
        let error = edit_config_with(&paths, false, &argv, |_, _| {
            called.set(true);
            Ok(true)
        })
        .unwrap_err();
        assert_eq!(
            error.message(),
            "config edit requires an interactive terminal"
        );
        assert!(!called.get());

        edit_config_with(&paths, true, &argv, |_, path| {
            let mut cfg = load_config(&paths).unwrap();
            cfg.lang = "zh-Hans".into();
            std::fs::write(path, toml::to_string_pretty(&cfg).unwrap()).unwrap();
            Ok(true)
        })
        .unwrap();
        assert_eq!(load_config(&paths).unwrap().lang, "zh-Hans");

        let before = std::fs::read(paths.config_file()).unwrap();
        let error = edit_config_with(&paths, true, &argv, |_, path| {
            std::fs::write(path, "refresh_token = \"do-not-print\"\n").unwrap();
            Ok(true)
        })
        .unwrap_err();
        assert_eq!(
            error.message(),
            "edited configuration contains forbidden secret material"
        );
        assert_eq!(std::fs::read(paths.config_file()).unwrap(), before);
    }
}
