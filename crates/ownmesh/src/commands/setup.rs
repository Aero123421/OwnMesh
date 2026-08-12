//! `ownmesh setup` — first-run config wizard (TTY + non-interactive / JSON).

use crate::cli::{Cli, DeviceCmd, LoginArgs, ServiceActionArgs, ServiceCmd, SetupArgs};
use ownmesh_config::{
    load_config, recover_config_policy_transaction, redact_control_plane_url,
    save_config_and_policy_transactional, validate_control_plane_base_url, InstanceConfig,
    OwnMeshConfig, OwnMeshPaths, PolicyFile, TelemetryConfig, UpdateConfig,
};
use ownmesh_domain::ExitCode;
use ownmesh_policy::AccessPreset;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};

/// JSON document accepted by `--from-json` / automation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetupRequest {
    #[serde(default)]
    pub control_plane_url: Option<String>,
    #[serde(default)]
    pub instance_id: Option<String>,
    #[serde(default)]
    pub policy_preset: Option<String>,
    #[serde(default)]
    pub lang: Option<String>,
    #[serde(default)]
    pub force: bool,
}

/// Result returned to the user (never contains secrets).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SetupResult {
    pub schema_version: u32,
    pub ok: bool,
    pub config_dir: String,
    pub config_file: String,
    pub policy_file: String,
    pub control_plane_url: String,
    pub instance_id: String,
    pub policy_preset: String,
    pub lang: String,
    pub privacy: SetupPrivacy,
    pub next_steps: Vec<String>,
    pub overwritten: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SetupPrivacy {
    pub telemetry: bool,
    pub relay: bool,
    pub update_mode: String,
}

/// Resolve whether interaction is allowed.
#[must_use]
pub fn is_interactive(args: &SetupArgs) -> bool {
    if args.non_interactive || args.from_json.is_some() {
        return false;
    }
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

/// Parse a policy preset name into [`AccessPreset`].
pub fn parse_policy_preset(name: &str) -> Result<AccessPreset, String> {
    let normalized = name.trim().to_ascii_lowercase().replace('-', "_");
    match normalized.as_str() {
        "workspace_only" | "workspaceonly" => Ok(AccessPreset::WorkspaceOnly),
        "recommended" | "default" => Ok(AccessPreset::Recommended),
        "full_user_access" | "full_user" | "fulluser" | "fulluseraccess" => {
            Ok(AccessPreset::FullUserAccess)
        }
        "full_access" | "fullaccess" | "full" => Ok(AccessPreset::FullAccess),
        other => Err(format!(
            "unknown policy preset `{other}` (expected workspace_only|recommended|full_user_access|full_access)"
        )),
    }
}

fn preset_slug(preset: AccessPreset) -> &'static str {
    match preset {
        AccessPreset::WorkspaceOnly => "workspace_only",
        AccessPreset::Recommended => "recommended",
        AccessPreset::FullUserAccess => "full_user_access",
        AccessPreset::FullAccess => "full_access",
        AccessPreset::Custom => "custom",
    }
}

/// Merge CLI flags + optional JSON document into one request.
pub fn build_request(args: &SetupArgs) -> Result<SetupRequest, String> {
    let mut req = SetupRequest::default();
    if let Some(path) = &args.from_json {
        let raw = read_json_source(path)?;
        // Refuse secret-looking keys in automation payloads.
        let lower = raw.to_ascii_lowercase();
        for needle in [
            "refresh_token",
            "access_token",
            "client_secret",
            "password",
            "private_key",
            "-----begin",
        ] {
            if lower.contains(needle) {
                return Err(format!(
                    "setup JSON must not contain secret field marker `{needle}`"
                ));
            }
        }
        req = serde_json::from_str(&raw).map_err(|e| format!("invalid setup JSON: {e}"))?;
    }
    if let Some(url) = &args.control_plane_url {
        req.control_plane_url = Some(url.clone());
    }
    if let Some(id) = &args.instance_id {
        req.instance_id = Some(id.clone());
    }
    if let Some(preset) = &args.policy_preset {
        req.policy_preset = Some(preset.clone());
    }
    if let Some(lang) = &args.language {
        req.lang = Some(lang.clone());
    }
    if args.force {
        req.force = true;
    }
    Ok(req)
}

fn read_json_source(path: &str) -> Result<String, String> {
    if path == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("read setup JSON from stdin: {e}"))?;
        return Ok(buf);
    }
    fs::read_to_string(path).map_err(|e| format!("read setup JSON {path}: {e}"))
}

/// Prompt helpers (TTY only).
/// Longest single prompt answer accepted, in bytes. Bounded so a pathological
/// stdin cannot grow the buffer without limit.
const MAX_PROMPT_BYTES: usize = 4096;

/// Explain the access presets before asking the user to pick one.
///
/// The decisive fact is which presets allow command execution: `workspace_only`
/// and `recommended` deny `command.run` and `session.open` until OS process
/// confinement exists, so choosing them means remote tools can read and write
/// files but cannot run anything.
fn write_preset_guidance(stdout: &mut impl Write) -> Result<(), String> {
    const LINES: &[&str] = &[
        "",
        "Access preset — what this machine will allow.",
        "  workspace_only     files inside registered workspaces; asks before writes.",
        "                     Commands and interactive sessions are DENIED.",
        "  recommended        reads allowed, writes ask, elevated asks.",
        "                     Commands and interactive sessions are DENIED.",
        "  full_user_access   everything your OS user can do; elevated still asks.",
        "                     Commands and interactive sessions are allowed.",
        "  full_access        allow everything, including elevated. No hidden denies.",
        "",
        "  Nothing leaves this machine because of this choice; it only decides what",
        "  an authenticated caller may ask this machine to do. Change it any time",
        "  with `ownmesh policy preset <name>`.",
        "",
    ];
    for line in LINES {
        writeln!(stdout, "{line}").map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn prompt_line(
    stdout: &mut impl Write,
    stdin: &mut impl Read,
    label: &str,
    default: &str,
) -> Result<String, String> {
    if default.is_empty() {
        write!(stdout, "{label}: ").map_err(|e| e.to_string())?;
    } else {
        write!(stdout, "{label} [{default}]: ").map_err(|e| e.to_string())?;
    }
    stdout.flush().map_err(|e| e.to_string())?;

    // Collect raw bytes, then decode once as UTF-8. Decoding byte-by-byte with
    // `byte as char` treats each byte as a Latin-1 code point and mangles every
    // multi-byte character (`家のPC` became `å®¶ã®PC`).
    let mut raw: Vec<u8> = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        let n = stdin.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 || buf[0] == b'\n' {
            break;
        }
        if raw.len() >= MAX_PROMPT_BYTES {
            return Err(format!("input exceeds {MAX_PROMPT_BYTES} bytes"));
        }
        if buf[0] != b'\r' {
            raw.push(buf[0]);
        }
    }
    let line = String::from_utf8(raw)
        .map_err(|_| "input is not valid UTF-8; retry with UTF-8 text".to_string())?;

    let trimmed = line.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

/// Re-prompt attempts before giving up, so a typo does not abort setup.
const MAX_PROMPT_RETRIES: usize = 3;

fn prompt_yes_no(
    stdout: &mut impl Write,
    stdin: &mut impl Read,
    label: &str,
    default_yes: bool,
) -> Result<bool, String> {
    let def = if default_yes { "Y/n" } else { "y/N" };
    for _ in 0..MAX_PROMPT_RETRIES {
        let answer = prompt_line(stdout, stdin, &format!("{label} ({def})"), "")?;
        if answer.is_empty() {
            return Ok(default_yes);
        }
        match answer.to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            other => {
                writeln!(stdout, "  please answer y or n (got `{other}`)")
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    Err("expected yes/no".into())
}

/// Fill missing fields via TTY wizard. Non-interactive callers must supply values.
pub fn complete_request_interactive(
    mut req: SetupRequest,
    stdout: &mut impl Write,
    stdin: &mut impl Read,
) -> Result<SetupRequest, String> {
    writeln!(
        stdout,
        "OwnMesh setup\n  Privacy defaults: telemetry OFF, cloud relay OFF, update network OFF."
    )
    .map_err(|e| e.to_string())?;

    if req
        .control_plane_url
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        let url = prompt_line(stdout, stdin, "Control-plane URL (https://…)", "")?;
        if url.trim().is_empty() {
            return Err("control-plane URL is required".into());
        }
        req.control_plane_url = Some(url);
    }

    if req.instance_id.as_deref().unwrap_or("").trim().is_empty() {
        let mut accepted = None;
        for _ in 0..MAX_PROMPT_RETRIES {
            let id = prompt_line(stdout, stdin, "Instance id", "default")?;
            let id = if id.is_empty() { "default".into() } else { id };
            if ownmesh_config::valid_instance_id(&id) {
                accepted = Some(id);
                break;
            }
            writeln!(
                stdout,
                "  instance id must match {} (ASCII letters, digits, . _ -)",
                ownmesh_config::INSTANCE_ID_SYNTAX
            )
            .map_err(|e| e.to_string())?;
        }
        req.instance_id = Some(accepted.ok_or_else(|| {
            format!(
                "instance id must match {}",
                ownmesh_config::INSTANCE_ID_SYNTAX
            )
        })?);
    }

    if req.policy_preset.as_deref().unwrap_or("").trim().is_empty() {
        // Spec 17.7: every choice states what it is, what it enables, what
        // leaves the machine, and whether it can be changed later. The
        // command-execution consequence matters most here: the two restricted
        // presets deny exec and interactive sessions outright, so a user who
        // accepts the default and then connects ChatGPT would otherwise see
        // every command denied with no explanation.
        write_preset_guidance(stdout)?;
        let preset = prompt_line(
            stdout,
            stdin,
            "Policy preset (workspace_only|recommended|full_user_access|full_access)",
            "recommended",
        )?;
        req.policy_preset = Some(if preset.is_empty() {
            "recommended".into()
        } else {
            preset
        });
    }

    if req.lang.as_deref().unwrap_or("").trim().is_empty() {
        let lang = prompt_line(stdout, stdin, "Language tag", "en-US")?;
        req.lang = Some(if lang.is_empty() {
            "en-US".into()
        } else {
            lang
        });
    }

    Ok(req)
}

/// Validate required fields for non-interactive mode (fail-closed).
pub fn require_non_interactive(req: &SetupRequest) -> Result<(), String> {
    if req
        .control_plane_url
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        return Err(
            "non-interactive setup requires --control-plane-url or JSON control_plane_url".into(),
        );
    }
    Ok(())
}

/// Apply setup against an explicit path root (tests + production).
pub fn apply_setup(
    paths: &OwnMeshPaths,
    req: &SetupRequest,
    allow_prompt_overwrite: bool,
    stdout: &mut impl Write,
    stdin: &mut impl Read,
) -> Result<SetupResult, ApplySetupError> {
    let url_raw = req
        .control_plane_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApplySetupError::usage("control-plane URL is required"))?;
    let url = validate_control_plane_base_url(url_raw).map_err(|e| {
        ApplySetupError::usage(format!(
            "invalid control-plane URL ({}): {e}",
            redact_control_plane_url(url_raw)
        ))
    })?;

    let instance_id = req
        .instance_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("default")
        .to_string();
    if !ownmesh_config::valid_instance_id(&instance_id) {
        return Err(ApplySetupError::usage(format!(
            "instance id `{instance_id}` must match {} (ASCII letters, digits, . _ -)",
            ownmesh_config::INSTANCE_ID_SYNTAX
        )));
    }

    let preset_name = req
        .policy_preset
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("recommended");
    let preset = parse_policy_preset(preset_name).map_err(ApplySetupError::usage)?;

    let lang = req
        .lang
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("en-US")
        .to_string();

    let config_path = paths.config_file();
    let existed = config_path.exists();
    let mut overwritten = false;
    if existed {
        if req.force {
            overwritten = true;
        } else if allow_prompt_overwrite {
            let yes = prompt_yes_no(
                stdout,
                stdin,
                &format!(
                    "Config already exists at {}. Overwrite",
                    config_path.display()
                ),
                false,
            )
            .map_err(ApplySetupError::usage)?;
            if !yes {
                return Err(ApplySetupError::usage(
                    "setup cancelled: existing config not overwritten",
                ));
            }
            overwritten = true;
        } else {
            return Err(ApplySetupError::usage(format!(
                "config already exists at {}. Review it with `ownmesh config validate`, \
                 or re-run with --force to replace it (the previous file is kept as {}.bak)",
                config_path.display(),
                config_path.display()
            )));
        }
    }

    // Build privacy-first config. Secrets never enter this struct.
    let cfg = OwnMeshConfig {
        schema_version: ownmesh_config::CONFIG_SCHEMA_VERSION,
        active_instance: Some(instance_id.clone()),
        lang: lang.clone(),
        update: UpdateConfig {
            mode: "off".into(),
            channel: "stable".into(),
        },
        telemetry: TelemetryConfig {
            project: false,
            crash_upload: false,
            usage_analytics: false,
        },
        instances: vec![InstanceConfig {
            id: instance_id.clone(),
            base_url: url.clone(),
            display_name: None,
        }],
        service_socket: ownmesh_config::ServiceSocketConfig::default(),
    };
    cfg.validate()
        .map_err(|e| ApplySetupError::usage(format!("config validation failed: {e}")))?;

    let policy = PolicyFile {
        schema_version: 1,
        preset: Some(preset_slug(preset).to_string()),
        delegate_remote_mcp: false,
        rules: Vec::new(),
    };
    policy
        .validate()
        .map_err(|e| ApplySetupError::usage(format!("policy validation failed: {e}")))?;

    // Atomic layout + writes. On failure after partial dir create, no corrupt config.toml remains.
    apply_setup_atomic(paths, &cfg, &policy)?;

    let result = SetupResult {
        schema_version: 1,
        ok: true,
        config_dir: paths.config_dir.display().to_string(),
        config_file: paths.config_file().display().to_string(),
        policy_file: paths.policy_file().display().to_string(),
        control_plane_url: url,
        instance_id,
        policy_preset: preset_slug(preset).to_string(),
        lang,
        privacy: SetupPrivacy {
            telemetry: false,
            relay: false,
            update_mode: "off".into(),
        },
        next_steps: vec![
            "ownmesh login".into(),
            "ownmesh device enroll".into(),
            "ownmesh service install".into(),
            "ownmesh doctor".into(),
        ],
        overwritten,
    };
    Ok(result)
}

/// Create config root and write config/policy as one journaled transaction.
///
/// Uses [`save_config_and_policy_transactional`]: exclusive lock + durable journal +
/// complete rollback on policy failure so a new config is never left paired with an old
/// strong policy. Rollback failure preserves the journal (fail closed).
pub fn apply_setup_atomic(
    paths: &OwnMeshPaths,
    cfg: &OwnMeshConfig,
    policy: &PolicyFile,
) -> Result<(), ApplySetupError> {
    paths
        .ensure_layout()
        .map_err(|e| ApplySetupError::io(format!("create config root: {e}")))?;

    // Extra defense: refuse world-writable config dir on Unix when detectable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(md) = fs::metadata(&paths.config_dir) {
            if md.mode() & 0o002 != 0 {
                return Err(ApplySetupError::usage(format!(
                    "refusing world-writable config dir {}",
                    paths.config_dir.display()
                )));
            }
        }
    }

    // Complete any interrupted prior transaction before writing a new pair.
    recover_config_policy_transaction(paths)
        .map_err(|e| ApplySetupError::io(format!("recover setup transaction: {e}")))?;

    save_config_and_policy_transactional(paths, cfg, policy)
        .map_err(|e| ApplySetupError::io(format!("write config+policy transaction: {e}")))?;

    // Verify round-trip without logging contents that could ever include secrets.
    let loaded =
        load_config(paths).map_err(|e| ApplySetupError::io(format!("reload config: {e}")))?;
    if loaded.active_instance != cfg.active_instance {
        return Err(ApplySetupError::io(
            "config reload mismatch after setup write".to_string(),
        ));
    }
    Ok(())
}

/// Simulate a failed atomic write for tests: target must remain absent or unchanged.
#[cfg(test)]
pub fn try_atomic_write_checked(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    ownmesh_config::atomic_write(path, data).map_err(|e| e.to_string())
}

#[derive(Debug)]
pub enum ApplySetupError {
    Usage(String),
    Io(String),
}

impl ApplySetupError {
    fn usage(msg: impl Into<String>) -> Self {
        Self::Usage(msg.into())
    }
    fn io(msg: impl Into<String>) -> Self {
        Self::Io(msg.into())
    }

    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Usage(_) => ExitCode::UsageConfig,
            Self::Io(_) => ExitCode::Internal,
        }
    }
}

impl std::fmt::Display for ApplySetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(m) | Self::Io(m) => write!(f, "{m}"),
        }
    }
}

fn emit_result(cli: &Cli, result: &SetupResult) {
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(result)
                .unwrap_or_else(|_| json!({"ok":false}).to_string())
        );
    } else {
        println!("OwnMesh setup complete");
        println!("  config:  {}", result.config_file);
        println!(
            "  policy:  {} (preset={})",
            result.policy_file, result.policy_preset
        );
        println!("  control: {}", result.control_plane_url);
        println!(
            "  privacy: telemetry=off relay=off update={}",
            result.privacy.update_mode
        );
        if result.overwritten {
            println!("  note:    existing config was overwritten");
        }
        println!("Next steps:");
        for step in &result.next_steps {
            println!("  - {step}");
        }
    }
}

/// CLI entrypoint.
pub fn run_setup(cli: &Cli, args: &SetupArgs) -> Result<(), ExitCode> {
    let mut req = build_request(args).map_err(|e| {
        eprintln!("setup: {e}");
        ExitCode::UsageConfig
    })?;

    let interactive = is_interactive(args);
    if interactive {
        let mut stdout = io::stdout();
        let mut stdin = io::stdin();
        req = complete_request_interactive(req, &mut stdout, &mut stdin).map_err(|e| {
            eprintln!("setup: {e}");
            ExitCode::UsageConfig
        })?;
    } else {
        require_non_interactive(&req).map_err(|e| {
            eprintln!("setup: {e}");
            ExitCode::UsageConfig
        })?;
        if req.policy_preset.as_deref().unwrap_or("").trim().is_empty() {
            req.policy_preset = Some("recommended".into());
        }
        if req.instance_id.as_deref().unwrap_or("").trim().is_empty() {
            req.instance_id = Some("default".into());
        }
        if req.lang.as_deref().unwrap_or("").trim().is_empty() {
            req.lang = Some(cli.lang.clone().unwrap_or_else(|| "en-US".into()));
        }
    }

    let paths = OwnMeshPaths::discover().map_err(|e| {
        eprintln!("setup: path error: {e}");
        ExitCode::UsageConfig
    })?;

    let mut stdout = io::stdout();
    let mut stdin = io::stdin();
    let result = apply_setup(
        &paths,
        &req,
        interactive && !req.force,
        &mut stdout,
        &mut stdin,
    )
    .map_err(|e| {
        eprintln!("setup: {e}");
        e.exit_code()
    })?;

    emit_result(cli, &result);

    if args.quickstart || args.login || args.device_login {
        super::login::run_login(
            cli,
            &LoginArgs {
                device: args.device_login,
            },
        )?;
    }
    if args.quickstart || args.enroll {
        super::device_cmd::dispatch_device(cli, &DeviceCmd::Enroll)?;
    }
    if args.quickstart {
        super::service::dispatch_service(cli, &ServiceCmd::Install(ServiceActionArgs::default()))?;
    }
    Ok(())
}

/// Test helper: setup under an isolated base directory.
#[cfg(test)]
pub fn run_setup_for_base(
    base: &std::path::Path,
    req: &SetupRequest,
) -> Result<SetupResult, ApplySetupError> {
    let paths = OwnMeshPaths::for_base(base);
    let mut stdout = Vec::new();
    let mut stdin = io::Cursor::new(Vec::new());
    apply_setup(&paths, req, false, &mut stdout, &mut stdin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::tempdir;

    #[test]
    fn non_interactive_requires_url() {
        let err = require_non_interactive(&SetupRequest::default()).unwrap_err();
        assert!(err.contains("control-plane"));
    }

    #[test]
    fn rejects_secret_json_markers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("evil.json");
        fs::write(
            &path,
            r#"{"control_plane_url":"https://x","refresh_token":"nope"}"#,
        )
        .unwrap();
        let args = SetupArgs {
            control_plane_url: None,
            instance_id: None,
            policy_preset: None,
            language: None,
            from_json: Some(path.display().to_string()),
            force: false,
            non_interactive: true,
            login: false,
            device_login: false,
            enroll: false,
            quickstart: false,
        };
        let err = build_request(&args).unwrap_err();
        assert!(err.contains("secret"));
    }

    #[test]
    fn applies_privacy_defaults_atomically() {
        let dir = tempdir().unwrap();
        let result = run_setup_for_base(
            dir.path(),
            &SetupRequest {
                control_plane_url: Some("https://cp.example.test".into()),
                instance_id: Some("home".into()),
                policy_preset: Some("recommended".into()),
                lang: Some("ja-JP".into()),
                force: false,
            },
        )
        .unwrap();
        assert!(result.ok);
        assert_eq!(result.privacy.update_mode, "off");
        assert!(!result.privacy.telemetry);
        assert!(!result.privacy.relay);
        assert_eq!(result.policy_preset, "recommended");

        let paths = OwnMeshPaths::for_base(dir.path());
        let cfg = load_config(&paths).unwrap();
        assert!(!cfg.telemetry.project);
        assert_eq!(cfg.update.mode, "off");
        assert_eq!(cfg.active_instance.as_deref(), Some("home"));
        assert_eq!(cfg.instances[0].base_url, "https://cp.example.test");

        let text = fs::read_to_string(paths.config_file()).unwrap();
        assert!(!text.to_ascii_lowercase().contains("token"));
        assert!(!text.contains("password"));
    }

    #[test]
    fn refuses_overwrite_without_force() {
        let dir = tempdir().unwrap();
        let req = SetupRequest {
            control_plane_url: Some("https://cp.example.test".into()),
            instance_id: None,
            policy_preset: Some("recommended".into()),
            lang: None,
            force: false,
        };
        run_setup_for_base(dir.path(), &req).unwrap();
        let err = run_setup_for_base(dir.path(), &req).unwrap_err();
        assert!(matches!(err, ApplySetupError::Usage(_)));
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn force_overwrites() {
        let dir = tempdir().unwrap();
        let mut req = SetupRequest {
            control_plane_url: Some("https://cp.example.test".into()),
            instance_id: Some("a".into()),
            policy_preset: Some("recommended".into()),
            lang: None,
            force: false,
        };
        run_setup_for_base(dir.path(), &req).unwrap();
        req.force = true;
        req.instance_id = Some("b".into());
        let result = run_setup_for_base(dir.path(), &req).unwrap();
        assert!(result.overwritten);
        assert_eq!(result.instance_id, "b");
    }

    #[test]
    fn interactive_fills_missing_fields() {
        let input = b"https://cp.example.test\nhome\nrecommended\nja-JP\n";
        let mut stdin = Cursor::new(input.as_slice());
        let mut stdout = Vec::new();
        let req =
            complete_request_interactive(SetupRequest::default(), &mut stdout, &mut stdin).unwrap();
        assert_eq!(
            req.control_plane_url.as_deref(),
            Some("https://cp.example.test")
        );
        assert_eq!(req.instance_id.as_deref(), Some("home"));
        assert_eq!(req.policy_preset.as_deref(), Some("recommended"));
        assert_eq!(req.lang.as_deref(), Some("ja-JP"));
    }

    /// Multi-byte answers must survive the prompt reader intact.
    ///
    /// Reading byte-by-byte with `byte as char` decoded UTF-8 as Latin-1, so
    /// `家のPC` was silently stored as `å®¶ã®PC`.
    #[test]
    fn prompt_line_preserves_multibyte_utf8() {
        let mut stdin = Cursor::new("家のPC\n".as_bytes());
        let mut stdout = Vec::new();
        let value = prompt_line(&mut stdout, &mut stdin, "Label", "default").unwrap();
        assert_eq!(value, "家のPC");

        let mut stdin = Cursor::new("Привет мир\r\n".as_bytes());
        let mut stdout = Vec::new();
        assert_eq!(
            prompt_line(&mut stdout, &mut stdin, "Label", "").unwrap(),
            "Привет мир"
        );
    }

    #[test]
    fn prompt_line_rejects_invalid_utf8_instead_of_mangling_it() {
        let mut stdin = Cursor::new([0xffu8, 0xfe, b'\n'].as_slice());
        let mut stdout = Vec::new();
        let err = prompt_line(&mut stdout, &mut stdin, "Label", "").unwrap_err();
        assert!(err.contains("UTF-8"), "{err}");
    }

    /// An id the wizard accepts must be one `instance use` also accepts.
    #[test]
    fn interactive_reprompts_until_the_instance_id_is_valid() {
        let input = "https://cp.example.test\n家のPC\nbad id!\nhome\nrecommended\nja-JP\n";
        let mut stdin = Cursor::new(input.as_bytes());
        let mut stdout = Vec::new();
        let req =
            complete_request_interactive(SetupRequest::default(), &mut stdout, &mut stdin).unwrap();
        assert_eq!(req.instance_id.as_deref(), Some("home"));
        let shown = String::from_utf8(stdout).unwrap();
        assert!(shown.contains("instance id must match"), "{shown}");
    }

    #[test]
    fn apply_setup_rejects_an_instance_id_other_commands_would_refuse() {
        let dir = tempdir().unwrap();
        let err = run_setup_for_base(
            dir.path(),
            &SetupRequest {
                control_plane_url: Some("https://cp.example.test".into()),
                instance_id: Some("家のPC".into()),
                ..SetupRequest::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("instance id"), "{err}");
        assert!(
            !OwnMeshPaths::for_base(dir.path()).config_file().exists(),
            "a rejected setup must not leave a config behind"
        );
    }

    #[test]
    fn prompt_yes_no_reprompts_on_unparseable_input() {
        let mut stdin = Cursor::new("maybe\nyeah\ny\n".as_bytes());
        let mut stdout = Vec::new();
        assert!(prompt_yes_no(&mut stdout, &mut stdin, "Overwrite", false).unwrap());
        let shown = String::from_utf8(stdout).unwrap();
        assert!(shown.contains("please answer y or n"), "{shown}");
    }

    #[test]
    fn atomic_write_failure_keeps_previous() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        try_atomic_write_checked(&path, b"version-one").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "version-one");

        // Directory-as-target fails and must not destroy a neighbor stable file.
        let bad = dir.path().join("dir-target");
        fs::create_dir(&bad).unwrap();
        fs::write(bad.join("child"), b"x").unwrap();
        assert!(try_atomic_write_checked(&bad, b"nope").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "version-one");
    }

    #[test]
    fn rejects_non_loopback_http() {
        let dir = tempdir().unwrap();
        let err = run_setup_for_base(
            dir.path(),
            &SetupRequest {
                control_plane_url: Some("http://example.test".into()),
                force: true,
                ..SetupRequest::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("control-plane") || err.to_string().contains("http"));
    }

    #[test]
    fn parse_presets() {
        assert_eq!(
            parse_policy_preset("recommended").unwrap(),
            AccessPreset::Recommended
        );
        assert_eq!(
            parse_policy_preset("full-access").unwrap(),
            AccessPreset::FullAccess
        );
        assert!(parse_policy_preset("nope").is_err());
    }

    #[test]
    fn setup_result_has_no_secrets() {
        let dir = tempdir().unwrap();
        let result = run_setup_for_base(
            dir.path(),
            &SetupRequest {
                control_plane_url: Some("https://cp.example.test".into()),
                force: true,
                policy_preset: Some("workspace_only".into()),
                ..SetupRequest::default()
            },
        )
        .unwrap();
        let dumped = serde_json::to_string(&result).unwrap();
        assert!(!dumped.to_ascii_lowercase().contains("token"));
        assert!(!dumped.contains("password"));
    }
}
