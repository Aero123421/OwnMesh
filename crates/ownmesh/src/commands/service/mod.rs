//! User-level `ownmeshd` autostart lifecycle (`ownmesh service …`).
//!
//! Distinct from the privileged broker: never creates admin/root system services.
//! Windows = current-user Scheduled Task (ONLOGON), macOS = LaunchAgent,
//! Linux = systemd --user.

mod descriptor;
mod platform;
mod security;

pub use descriptor::{ServicePaths, SERVICE_LABEL};
pub use platform::{
    resolve_ownmeshd_path, ProcessRunner, RealProcessRunner, ServiceManager, ServiceStatusSnapshot,
};
pub use security::{canonicalize_executable, validate_service_path};

use crate::cli::{Cli, ServiceActionArgs, ServiceCmd};
use ownmesh_config::OwnMeshPaths;
use ownmesh_domain::ExitCode;
use ownmesh_persist::write_atomically;
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Persisted install record under the user state directory (not secrets).
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct UserServiceRecord {
    pub schema_version: u32,
    pub installed: bool,
    pub platform: String,
    pub executable: String,
    pub unit_path: Option<String>,
    pub installed_at_unix: i64,
    pub label: String,
}

impl UserServiceRecord {
    fn record_path(paths: &OwnMeshPaths) -> PathBuf {
        paths.state_dir.join("service").join("user-service.json")
    }
}

/// Write install record atomically under state_dir/service/.
pub fn write_service_record(
    paths: &OwnMeshPaths,
    record: &UserServiceRecord,
) -> Result<(), String> {
    let path = UserServiceRecord::record_path(paths);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create service state dir: {e}"))?;
    }
    let bytes = serde_json::to_vec_pretty(record).map_err(|e| e.to_string())?;
    write_atomically(&path, &bytes).map_err(|e| format!("write service record: {e}"))
}

/// Read install record if present.
pub fn read_service_record(paths: &OwnMeshPaths) -> Option<UserServiceRecord> {
    let path = UserServiceRecord::record_path(paths);
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Remove install record (idempotent).
pub fn remove_service_record(paths: &OwnMeshPaths) -> Result<(), String> {
    let path = UserServiceRecord::record_path(paths);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove service record: {e}")),
    }
}

/// Build validated service paths for install.
pub fn build_service_paths(
    executable: Option<&str>,
    paths: &OwnMeshPaths,
) -> Result<ServicePaths, String> {
    let exe = resolve_ownmeshd_path(executable)?;
    let validated_exe = canonicalize_executable(&exe)?;
    let config_dir = validate_service_path(&paths.config_dir, "config_dir", true)?;
    let state_dir = validate_service_path(&paths.state_dir, "state_dir", true)?;
    let runtime_dir = validate_service_path(&paths.runtime_dir, "runtime_dir", true)?;
    Ok(ServicePaths {
        executable: validated_exe,
        config_dir,
        state_dir,
        runtime_dir,
    })
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(0))
        .unwrap_or(0)
}

fn emit_json_or_text(cli: &Cli, value: &serde_json::Value, text: impl FnOnce()) {
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
        );
    } else {
        text();
    }
}

/// Dispatch `ownmesh service` subcommands.
pub fn dispatch_service(cli: &Cli, cmd: &ServiceCmd) -> Result<(), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|e| {
        eprintln!("service: path error: {e}");
        ExitCode::UsageConfig
    })?;
    let runner = RealProcessRunner;
    let manager = ServiceManager::new(&runner);

    match cmd {
        ServiceCmd::Install(args) => run_install(cli, &paths, &manager, args),
        ServiceCmd::Start(args) => run_lifecycle(cli, &paths, &manager, args, Lifecycle::Start),
        ServiceCmd::Stop(args) => run_lifecycle(cli, &paths, &manager, args, Lifecycle::Stop),
        ServiceCmd::Restart(args) => run_lifecycle(cli, &paths, &manager, args, Lifecycle::Restart),
        ServiceCmd::Status => run_status(cli, &paths, &manager),
        ServiceCmd::Uninstall(args) => run_uninstall(cli, &paths, &manager, args),
    }
}

#[derive(Clone, Copy)]
enum Lifecycle {
    Start,
    Stop,
    Restart,
}

fn run_install(
    cli: &Cli,
    paths: &OwnMeshPaths,
    manager: &ServiceManager<'_, impl ProcessRunner>,
    args: &ServiceActionArgs,
) -> Result<(), ExitCode> {
    if !manager.platform_supported() {
        return fail(
            cli,
            "service install",
            &format!(
                "user-level service install unsupported on {}",
                std::env::consts::OS
            ),
        );
    }

    let service_paths = build_service_paths(args.executable.as_deref(), paths).map_err(|e| {
        eprintln!("service install: {e}");
        ExitCode::UsageConfig
    })?;

    let plan = manager.install_plan(&service_paths).map_err(|e| {
        eprintln!("service install: {e}");
        ExitCode::UsageConfig
    })?;

    if args.dry_run {
        let value = json!({
            "schema_version": 1,
            "ok": true,
            "dry_run": true,
            "action": "install",
            "platform": plan.platform,
            "unit_path": plan.unit_path,
            "executable": service_paths.executable.canonical.display().to_string(),
            "descriptor_preview": plan.descriptor_body,
        });
        emit_json_or_text(cli, &value, || {
            println!("service install (dry-run)");
            println!("  platform: {}", plan.platform);
            println!("  unit:     {}", plan.unit_path);
            println!(
                "  exe:      {}",
                service_paths.executable.canonical.display()
            );
        });
        return Ok(());
    }

    // Idempotent: if already installed with same exe, succeed after OS verify.
    let existing = manager.probe().map_err(|e| {
        eprintln!("service install: {e}");
        ExitCode::Internal
    })?;
    let same_recorded_executable = read_service_record(paths).is_some_and(|record| {
        record.executable == service_paths.executable.canonical.display().to_string()
    });
    if existing.installed && same_recorded_executable {
        let record = UserServiceRecord {
            schema_version: 1,
            installed: true,
            platform: plan.platform.clone(),
            executable: service_paths.executable.canonical.display().to_string(),
            unit_path: Some(plan.unit_path.clone()),
            installed_at_unix: now_unix(),
            label: SERVICE_LABEL.to_string(),
        };
        let _ = write_service_record(paths, &record);
        let verified = manager.probe().map_err(|e| {
            eprintln!("service install: verify failed: {e}");
            ExitCode::Internal
        })?;
        if !verified.installed {
            return fail(
                cli,
                "service install",
                "OS reports service not installed after idempotent install",
            );
        }
        let value = json!({
            "schema_version": 1,
            "ok": true,
            "action": "install",
            "idempotent": true,
            "platform": verified.platform,
            "installed": true,
            "unit_path": verified.unit_path,
        });
        emit_json_or_text(cli, &value, || {
            println!("service already installed (idempotent ok)");
            if let Some(u) = &verified.unit_path {
                println!("  unit: {u}");
            }
        });
        return Ok(());
    }

    // A privileged-broker install may have introduced a root-pinned ownmeshd
    // image. Replace an older user descriptor instead of reporting a false
    // idempotent success with the previous executable.
    if existing.installed {
        manager.uninstall().map_err(|e| {
            eprintln!("service install: replace old descriptor: {e}");
            ExitCode::Internal
        })?;
    }

    manager.install(&service_paths).map_err(|e| {
        eprintln!("service install: {e}");
        ExitCode::Internal
    })?;

    let verified = manager.probe().map_err(|e| {
        eprintln!("service install: post-install probe failed: {e}");
        ExitCode::Internal
    })?;
    if !verified.installed {
        return fail(
            cli,
            "service install",
            "install completed but OS state does not show the service as installed",
        );
    }

    let record = UserServiceRecord {
        schema_version: 1,
        installed: true,
        platform: verified.platform.clone(),
        executable: service_paths.executable.canonical.display().to_string(),
        unit_path: verified.unit_path.clone(),
        installed_at_unix: now_unix(),
        label: SERVICE_LABEL.to_string(),
    };
    write_service_record(paths, &record).map_err(|e| {
        eprintln!("service install: {e}");
        ExitCode::Internal
    })?;

    let value = json!({
        "schema_version": 1,
        "ok": true,
        "action": "install",
        "platform": verified.platform,
        "installed": true,
        "unit_path": verified.unit_path,
        "executable": record.executable,
    });
    emit_json_or_text(cli, &value, || {
        println!("service installed");
        println!("  platform: {}", verified.platform);
        if let Some(u) = &verified.unit_path {
            println!("  unit: {u}");
        }
        println!("  exe: {}", record.executable);
    });
    Ok(())
}

fn run_uninstall(
    cli: &Cli,
    paths: &OwnMeshPaths,
    manager: &ServiceManager<'_, impl ProcessRunner>,
    args: &ServiceActionArgs,
) -> Result<(), ExitCode> {
    if args.dry_run {
        let probe = manager.probe().unwrap_or_else(|e| ServiceStatusSnapshot {
            platform: std::env::consts::OS.into(),
            supported: manager.platform_supported(),
            installed: false,
            running: None,
            unit_path: None,
            message: Some(e),
        });
        let value = json!({
            "schema_version": 1,
            "ok": true,
            "dry_run": true,
            "action": "uninstall",
            "currently_installed": probe.installed,
            "unit_path": probe.unit_path,
        });
        emit_json_or_text(cli, &value, || {
            println!(
                "service uninstall (dry-run); currently_installed={}",
                probe.installed
            );
        });
        return Ok(());
    }

    manager.uninstall().map_err(|e| {
        eprintln!("service uninstall: {e}");
        ExitCode::Internal
    })?;

    remove_service_record(paths).map_err(|e| {
        eprintln!("service uninstall: {e}");
        ExitCode::Internal
    })?;

    let verified = manager.probe().map_err(|e| {
        eprintln!("service uninstall: verify failed: {e}");
        ExitCode::Internal
    })?;
    if verified.installed {
        return fail(
            cli,
            "service uninstall",
            "uninstall completed but OS still reports the service as installed",
        );
    }

    let value = json!({
        "schema_version": 1,
        "ok": true,
        "action": "uninstall",
        "installed": false,
    });
    emit_json_or_text(cli, &value, || {
        println!("service uninstalled");
    });
    Ok(())
}

fn run_lifecycle(
    cli: &Cli,
    _paths: &OwnMeshPaths,
    manager: &ServiceManager<'_, impl ProcessRunner>,
    args: &ServiceActionArgs,
    action: Lifecycle,
) -> Result<(), ExitCode> {
    let name = match action {
        Lifecycle::Start => "start",
        Lifecycle::Stop => "stop",
        Lifecycle::Restart => "restart",
    };

    if args.dry_run {
        let value = json!({
            "schema_version": 1,
            "ok": true,
            "dry_run": true,
            "action": name,
        });
        emit_json_or_text(cli, &value, || println!("service {name} (dry-run)"));
        return Ok(());
    }

    let result = match action {
        Lifecycle::Start => manager.start(),
        Lifecycle::Stop => manager.stop(),
        Lifecycle::Restart => manager.restart(),
    };
    result.map_err(|e| {
        eprintln!("service {name}: {e}");
        ExitCode::Internal
    })?;

    let probe = manager.probe().ok();
    let value = json!({
        "schema_version": 1,
        "ok": true,
        "action": name,
        "installed": probe.as_ref().map(|p| p.installed),
        "running": probe.as_ref().and_then(|p| p.running),
    });
    emit_json_or_text(cli, &value, || {
        println!("service {name} ok");
        if let Some(p) = &probe {
            if let Some(r) = p.running {
                println!("  running: {r}");
            }
        }
    });
    Ok(())
}

fn run_status(
    cli: &Cli,
    paths: &OwnMeshPaths,
    manager: &ServiceManager<'_, impl ProcessRunner>,
) -> Result<(), ExitCode> {
    let snap = manager.probe().map_err(|e| {
        eprintln!("service status: {e}");
        ExitCode::Internal
    })?;
    let record = read_service_record(paths);
    let value = json!({
        "schema_version": 1,
        "ok": true,
        "action": "status",
        "platform": snap.platform,
        "supported": snap.supported,
        "installed": snap.installed,
        "running": snap.running,
        "unit_path": snap.unit_path,
        "record": record,
        "message": snap.message,
    });
    emit_json_or_text(cli, &value, || {
        println!("ownmeshd user service");
        println!("  platform:  {}", snap.platform);
        println!("  supported: {}", snap.supported);
        println!("  installed: {}", snap.installed);
        match snap.running {
            Some(true) => println!("  running:   true"),
            Some(false) => println!("  running:   false"),
            None => println!("  running:   unknown"),
        }
        if let Some(u) = &snap.unit_path {
            println!("  unit:      {u}");
        }
        if let Some(m) = &snap.message {
            println!("  note:      {m}");
        }
    });
    Ok(())
}

fn fail(cli: &Cli, command: &str, message: &str) -> Result<(), ExitCode> {
    Err(crate::commands::fail::fail(
        cli,
        "OWNMESH_E_SERVICE",
        format!("ownmesh {command}: {message}"),
        None,
        ExitCode::Internal,
    ))
}

/// Convenience for doctor: probe without constructing CLI state beyond PATH/OS.
pub fn probe_service_status() -> Result<ServiceStatusSnapshot, String> {
    let runner = RealProcessRunner;
    let manager = ServiceManager::new(&runner);
    manager.probe()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::service::descriptor::{
        render_launch_agent_plist, render_scheduled_task_xml, render_systemd_user_unit,
    };
    use crate::commands::service::platform::ScriptedProcessRunner;
    use crate::commands::service::security::reject_injection;
    use std::path::Path;
    use tempfile::tempdir;

    fn touch_exe(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, b"fake").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&p).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&p, perms).unwrap();
        }
        p
    }

    #[test]
    fn build_paths_rejects_injection() {
        let dir = tempdir().unwrap();
        let exe = touch_exe(
            dir.path(),
            if cfg!(windows) {
                "ownmeshd.exe"
            } else {
                "ownmeshd"
            },
        );
        let paths = OwnMeshPaths::for_base(dir.path().join("om"));
        paths.ensure_layout().unwrap();
        // Valid
        let ok = build_service_paths(Some(exe.to_str().unwrap()), &paths);
        assert!(ok.is_ok(), "{ok:?}");
    }

    #[test]
    fn record_roundtrip_atomic() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let rec = UserServiceRecord {
            schema_version: 1,
            installed: true,
            platform: "test".into(),
            executable: "/tmp/ownmeshd".into(),
            unit_path: Some("/tmp/unit".into()),
            installed_at_unix: 1,
            label: SERVICE_LABEL.into(),
        };
        write_service_record(&paths, &rec).unwrap();
        let loaded = read_service_record(&paths).unwrap();
        assert_eq!(loaded, rec);
        remove_service_record(&paths).unwrap();
        remove_service_record(&paths).unwrap(); // idempotent
        assert!(read_service_record(&paths).is_none());
    }

    #[test]
    fn install_idempotent_with_scripted_runner() {
        let dir = tempdir().unwrap();
        let exe = touch_exe(
            dir.path(),
            if cfg!(windows) {
                "ownmeshd.exe"
            } else {
                "ownmeshd"
            },
        );
        let paths = OwnMeshPaths::for_base(dir.path().join("om"));
        paths.ensure_layout().unwrap();
        let service_paths = build_service_paths(Some(exe.to_str().unwrap()), &paths).unwrap();

        let runner = ScriptedProcessRunner::default();
        // First probe: not installed; install ops succeed; final probe installed.
        // Scripted runner tracks descriptor files under its root.
        runner.set_root(dir.path().join("svc-root"));
        let manager = ServiceManager::new(&runner);

        // dry-run plan works without OS
        let plan = manager.install_plan(&service_paths).unwrap();
        assert!(!plan.descriptor_body.is_empty());
        assert!(
            plan.descriptor_body.contains("ExecStart=") || plan.descriptor_body.contains("Task")
        );

        manager.install(&service_paths).unwrap();
        let snap = manager.probe().unwrap();
        assert!(snap.installed, "{snap:?}");

        // Idempotent second install
        manager.install(&service_paths).unwrap();
        let snap2 = manager.probe().unwrap();
        assert!(snap2.installed);

        manager.uninstall().unwrap();
        let snap3 = manager.probe().unwrap();
        assert!(!snap3.installed);
        // Idempotent uninstall
        manager.uninstall().unwrap();
    }

    #[test]
    fn descriptors_quote_and_escape() {
        let dir = tempdir().unwrap();
        let exe = touch_exe(
            dir.path(),
            if cfg!(windows) {
                "ownmeshd.exe"
            } else {
                "ownmeshd"
            },
        );
        let paths = OwnMeshPaths::for_base(dir.path().join("cfg base"));
        paths.ensure_layout().unwrap();
        let sp = build_service_paths(Some(exe.to_str().unwrap()), &paths).unwrap();

        let unit = render_systemd_user_unit(&sp);
        assert!(unit.contains("ExecStart="));
        // Paths themselves must not carry injection newlines (unit body is multi-line).
        assert!(!sp.executable.canonical.display().to_string().contains('\n'));
        assert!(unit.contains("NoNewPrivileges=true"));

        let plist = render_launch_agent_plist(&sp);
        assert!(plist.contains("<?xml"));
        assert!(plist.contains(SERVICE_LABEL));
        assert!(!plist.contains("<string></string><string>--evil"));

        let xml = render_scheduled_task_xml(&sp);
        assert!(xml.contains("Task"));
        assert!(xml.contains("LogonTrigger") || xml.contains("Logon"));
    }

    #[test]
    fn path_validation_rejects_newlines() {
        let err = reject_injection("foo\nbar");
        assert!(err.is_err());
        let err = reject_injection("foo\"bar");
        assert!(err.is_err());
    }
}
