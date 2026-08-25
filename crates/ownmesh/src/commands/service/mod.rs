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
use ownmesh_config::{load_config, OwnMeshPaths};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::{ClientIdentity, ClientOptions, Endpoint, IpcClient};
use ownmesh_persist::write_atomically;
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Shipped bounds; tests substitute a short deadline via `lifecycle_timeout`.
#[cfg_attr(test, allow(dead_code))]
const SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg_attr(test, allow(dead_code))]
const SERVICE_START_TIMEOUT: Duration = Duration::from_secs(15);
const SERVICE_STATE_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Bounded wait for the daemon endpoint to reach the requested state.
///
/// Tests shorten the *unreachable* direction so a deliberate timeout does not
/// cost real seconds; the reachable direction returns as soon as the endpoint
/// agrees, so production and test paths exercise the same logic.
#[cfg(not(test))]
const fn lifecycle_timeout(action: Lifecycle) -> Duration {
    match action {
        Lifecycle::Stop => SERVICE_STOP_TIMEOUT,
        Lifecycle::Start | Lifecycle::Restart => SERVICE_START_TIMEOUT,
    }
}

#[cfg(test)]
const fn lifecycle_timeout(_action: Lifecycle) -> Duration {
    Duration::from_millis(750)
}

/// Bump whenever a descriptor renderer changes in a behaviorally relevant way.
/// A record written by an older version is drift: existing installations are
/// migrated instead of being reported as idempotently current (#153).
pub const DESCRIPTOR_SCHEMA_VERSION: u32 = 2;

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
    /// Descriptor renderer generation this install was produced by.
    /// Absent in records written before #153; treated as drift.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor_version: Option<u32>,
    /// SHA-256 of the generated descriptor body, so a changed renderer or a
    /// changed bound path is detectable without re-reading the OS descriptor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor_digest: Option<String>,
}

/// Digest of a rendered descriptor body, line-ending normalized.
#[must_use]
pub fn descriptor_digest(body: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(body.replace("\r\n", "\n").as_bytes());
    hasher
        .finalize()
        .iter()
        .fold(String::new(), |mut acc, byte| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{byte:02x}");
            acc
        })
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

    let unit_path = PathBuf::from(&plan.unit_path);
    let mut removed_dropins = Vec::new();
    if platform::is_systemd_unit_path(&plan.unit_path) {
        let report =
            platform::reconcile_ownmesh_generated_dropins(&unit_path).map_err(|error| {
                eprintln!("service install: {error}");
                ExitCode::Internal
            })?;
        removed_dropins = report.removed;
        if !removed_dropins.is_empty() {
            manager.reload_user_units().map_err(|error| {
                eprintln!("service install: {error}");
                ExitCode::Internal
            })?;
        }
    }

    // Matching exe/unit path is not enough: a leftover drop-in or stale
    // descriptor can still hide host uids behind 65534, and a plist or task
    // that kept its name can carry an older release's action entirely.
    let recorded = read_service_record(paths);
    let existing = manager.probe().map_err(|error| {
        eprintln!("service install: {error}");
        ExitCode::Internal
    })?;
    let expected_digest = descriptor_digest(&plan.descriptor_body);
    let same_recorded_executable = recorded.as_ref().is_some_and(|record| {
        record.executable == service_paths.executable.canonical.display().to_string()
    });
    // A record without a descriptor identity was written before #153 and says
    // nothing about what is actually registered, so it counts as drift.
    let recorded_descriptor_current = recorded.as_ref().is_some_and(|record| {
        record.descriptor_version == Some(DESCRIPTOR_SCHEMA_VERSION)
            && record.descriptor_digest.as_deref() == Some(expected_digest.as_str())
    });
    let path_is_current = existing.unit_path.as_deref() == Some(plan.unit_path.as_str());
    let registered = manager.descriptor_state(&plan);
    let descriptor_is_current =
        path_is_current && recorded_descriptor_current && registered.is_current();
    let forcing = existing
        .hardening
        .as_ref()
        .is_some_and(|hardening| hardening.user_namespace_forcing);
    if existing.installed && same_recorded_executable && descriptor_is_current && !forcing {
        let record = UserServiceRecord {
            schema_version: 1,
            installed: true,
            platform: plan.platform.clone(),
            executable: service_paths.executable.canonical.display().to_string(),
            unit_path: Some(plan.unit_path.clone()),
            installed_at_unix: now_unix(),
            label: SERVICE_LABEL.to_string(),
            descriptor_version: Some(DESCRIPTOR_SCHEMA_VERSION),
            descriptor_digest: Some(expected_digest.clone()),
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
        // Idempotent success must mean the registration is current, not that a
        // descriptor with the expected name exists (#153).
        if let Some(reason) = manager.descriptor_state(&plan).reason() {
            return fail(
                cli,
                "service install",
                &format!("idempotent install could not confirm a current descriptor: {reason}"),
            );
        }
        let reconciled = !removed_dropins.is_empty();
        let value = json!({
            "schema_version": 1,
            "ok": true,
            "action": "install",
            "idempotent": !reconciled,
            "reconciled": reconciled,
            "removed_dropins": removed_dropins,
            "platform": verified.platform,
            "installed": true,
            "unit_path": verified.unit_path,
        });
        emit_json_or_text(cli, &value, || {
            if reconciled {
                println!("service install reconciled OwnMesh-generated drop-ins");
                for name in &removed_dropins {
                    println!("  removed: {name}");
                }
            } else {
                println!("service already installed (idempotent ok)");
            }
            if let Some(u) = &verified.unit_path {
                println!("  unit: {u}");
            }
        });
        return Ok(());
    }

    // A privileged-broker install may have introduced a root-pinned ownmeshd
    // image. Replace an older user descriptor instead of reporting a false
    // idempotent success with the previous executable.
    if existing.installed && !same_recorded_executable {
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
    if verified
        .hardening
        .as_ref()
        .is_some_and(|hardening| hardening.user_namespace_forcing)
    {
        let remaining = manager.remaining_userns_forcing_dropins(&unit_path);
        return fail(
            cli,
            "service install",
            &format!(
                "effective unit still forces a user namespace after install (remaining: {}). Delete those operator drop-ins, then re-run `ownmesh service install`; otherwise ownmeshd fails with `ancestor is owned by untrusted uid 65534`",
                if remaining.is_empty() {
                    "unknown override".to_string()
                } else {
                    remaining.join(", ")
                }
            ),
        );
    }

    // The record is the CLI's claim about what is registered, so it is written
    // only after the reconciled descriptor has been read back and verified.
    if let Some(reason) = manager.descriptor_state(&plan).reason() {
        return fail(
            cli,
            "service install",
            &format!("install completed but the registered descriptor is not current: {reason}"),
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
        descriptor_version: Some(DESCRIPTOR_SCHEMA_VERSION),
        descriptor_digest: Some(expected_digest.clone()),
    };
    write_service_record(paths, &record).map_err(|e| {
        eprintln!("service install: {e}");
        ExitCode::Internal
    })?;

    let reconciled = !removed_dropins.is_empty();
    let value = json!({
        "schema_version": 1,
        "ok": true,
        "action": "install",
        "idempotent": false,
        "reconciled": reconciled,
        "removed_dropins": removed_dropins,
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
        for name in &removed_dropins {
            println!("  removed: {name}");
        }
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
            hardening: None,
            linger: None,
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

    // A failed stop/disable/bootout leaves the descriptor and the install
    // record in place so doctor and a later retry can still reconcile the
    // orphaned unit (#147/#149).
    if let Err(error) = manager.uninstall() {
        return fail(cli, "service uninstall", &error);
    }

    // Liveness is verified before the record is deleted: the record is the only
    // remaining description of what was installed.
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
    if verified.running == Some(true) {
        return fail(
            cli,
            "service uninstall",
            "descriptor removed but the service manager still reports ownmeshd running; \
             the install record was kept so `ownmesh service uninstall` can be retried",
        );
    }

    remove_service_record(paths).map_err(|e| {
        eprintln!("service uninstall: {e}");
        ExitCode::Internal
    })?;

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
    paths: &OwnMeshPaths,
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

    // An OS service manager only acknowledges the *request*. Task Scheduler
    // `/Run` can queue an action that fails immediately, `/End` can return
    // before the instance is released, and a macOS LaunchAgent with
    // KeepAlive=true is relaunched right after a SIGTERM. Daemon IPC is the
    // only authority on whether the requested transition happened, so every
    // lifecycle verb — not just restart — crosses that boundary (#147/#154).
    let verified_running = match action {
        Lifecycle::Start => (|| -> Result<Option<bool>, String> {
            manager.start()?;
            wait_for_daemon_state(paths, true, lifecycle_timeout(Lifecycle::Start))
                .map_err(|error| annotate_lifecycle_failure(manager, "start", &error))?;
            Ok(Some(true))
        })(),
        Lifecycle::Stop => (|| -> Result<Option<bool>, String> {
            manager.stop()?;
            wait_for_daemon_state(paths, false, lifecycle_timeout(Lifecycle::Stop))
                .map_err(|error| annotate_lifecycle_failure(manager, "stop", &error))?;
            Ok(Some(false))
        })(),
        Lifecycle::Restart => (|| -> Result<Option<bool>, String> {
            manager.stop()?;
            wait_for_daemon_state(paths, false, lifecycle_timeout(Lifecycle::Stop))
                .map_err(|error| annotate_lifecycle_failure(manager, "stop", &error))?;
            manager.start()?;
            wait_for_daemon_state(paths, true, lifecycle_timeout(Lifecycle::Start))
                .map_err(|error| annotate_lifecycle_failure(manager, "start", &error))?;
            Ok(Some(true))
        })(),
    };
    // A lifecycle verb that could not be verified is a service failure, not a
    // generic internal error: `ok:true` with `running:null` would be a lie.
    let verified_running = match verified_running {
        Ok(value) => value,
        Err(error) => return fail(cli, &format!("service {name}"), &error),
    };

    let probe = manager.probe().ok();
    let running = verified_running.or_else(|| probe.as_ref().and_then(|p| p.running));
    let value = json!({
        "schema_version": 1,
        "ok": true,
        "action": name,
        "installed": probe.as_ref().map(|p| p.installed),
        "running": running,
    });
    emit_json_or_text(cli, &value, || {
        println!("service {name} ok");
        if let Some(running) = running {
            println!("  running: {running}");
        }
    });
    Ok(())
}

/// Attach bounded, locale-independent service-manager evidence to a failed
/// transition so the operator sees why the daemon never crossed the boundary.
///
/// IPC remains the readiness authority: this only explains a timeout. Nothing
/// here parses localized service-manager prose — only the manager's own
/// structured installed/running facts.
fn annotate_lifecycle_failure(
    manager: &ServiceManager<'_, impl ProcessRunner>,
    verb: &str,
    error: &str,
) -> String {
    match manager.probe() {
        Ok(snapshot) => {
            let running = match snapshot.running {
                Some(true) => "true",
                Some(false) => "false",
                None => "unknown",
            };
            format!(
                "{error} (service manager reports installed={}, running={running}{}); \
                 the {verb} request was accepted but the daemon endpoint never agreed",
                snapshot.installed,
                snapshot
                    .unit_path
                    .as_deref()
                    .map(|unit| format!(", unit={unit}"))
                    .unwrap_or_default(),
            )
        }
        Err(probe_error) => {
            format!("{error} (service manager probe also failed: {probe_error})")
        }
    }
}

/// Wait until the daemon's public status endpoint agrees with the requested
/// lifecycle state. OS service managers may acknowledge start/stop before the
/// process is actually ready/gone; reporting success earlier makes restart
/// races indistinguishable from a healthy transition.
fn wait_for_daemon_state(
    paths: &OwnMeshPaths,
    expected_online: bool,
    timeout: Duration,
) -> Result<(), String> {
    let cfg =
        load_config(paths).map_err(|error| format!("load config for readiness check: {error}"))?;
    let endpoint =
        Endpoint::configured_daemon(&paths.runtime_dir, cfg.service_socket.path.as_deref())
            .map_err(|error| format!("resolve daemon endpoint for readiness check: {error}"))?;
    let client = IpcClient::new(
        endpoint,
        paths.runtime_dir.clone(),
        ClientIdentity::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        ClientOptions {
            request_timeout: Duration::from_millis(300),
            max_reconnect_attempts: 0,
            reconnect_base_delay: Duration::from_millis(25),
        },
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("create daemon readiness runtime: {error}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        let online = runtime.block_on(client.status()).is_ok();
        if online == expected_online {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let expected = if expected_online { "ready" } else { "stopped" };
            return Err(format!(
                "daemon did not become {expected} within {} seconds",
                timeout.as_secs()
            ));
        }
        thread::sleep(SERVICE_STATE_POLL_INTERVAL);
    }
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
            descriptor_version: Some(DESCRIPTOR_SCHEMA_VERSION),
            descriptor_digest: Some(descriptor_digest("[Service]\n")),
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

    fn generated_workspace_dropin() -> &'static str {
        "# Generated by OwnMesh. Do not edit by hand.\n\
[Service]\n\
ReadWritePaths=\"/tmp/.tmpxhev0Y/config\" \"/tmp/.tmpxhev0Y/state\"\n"
    }

    fn write_unit_dropin(root: &Path, name: &str, body: &str) {
        let dir = root.join("ownmesh-ownmeshd.service.d");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn install_reconciles_generated_readwritepaths_dropin() {
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
        let root = dir.path().join("svc-root");
        runner.set_root(root.clone());
        let manager = ServiceManager::new(&runner);
        manager.install(&service_paths).unwrap();

        write_unit_dropin(
            &root,
            "10-ownmesh-workspaces.conf",
            generated_workspace_dropin(),
        );
        write_unit_dropin(
            &root,
            "20-operator.conf",
            "[Service]\nRestrictNamespaces=no\n",
        );
        assert!(
            manager
                .probe()
                .unwrap()
                .hardening
                .unwrap()
                .user_namespace_forcing
        );

        write_service_record(
            &paths,
            &UserServiceRecord {
                schema_version: 1,
                installed: true,
                platform: "test".into(),
                executable: service_paths.executable.canonical.display().to_string(),
                unit_path: Some(root.join("ownmesh-ownmeshd.service").display().to_string()),
                installed_at_unix: 1,
                label: SERVICE_LABEL.into(),
                descriptor_version: Some(DESCRIPTOR_SCHEMA_VERSION),
                descriptor_digest: Some(descriptor_digest(
                    &manager
                        .install_plan(&service_paths)
                        .unwrap()
                        .descriptor_body,
                )),
            },
        )
        .unwrap();

        let cli = Cli {
            json: false,
            lang: None,
            command: None,
        };
        let args = ServiceActionArgs {
            dry_run: false,
            executable: Some(exe.to_str().unwrap().to_string()),
        };
        run_install(&cli, &paths, &manager, &args).unwrap();

        assert!(!root
            .join("ownmesh-ownmeshd.service.d/10-ownmesh-workspaces.conf")
            .exists());
        assert!(root
            .join("ownmesh-ownmeshd.service.d/20-operator.conf")
            .exists());
        let after = manager.probe().unwrap();
        assert!(
            !after.hardening.as_ref().unwrap().user_namespace_forcing,
            "{after:?}"
        );
    }

    #[test]
    fn install_fails_closed_when_operator_dropin_still_forces_userns() {
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
        let root = dir.path().join("svc-root");
        runner.set_root(root.clone());
        let manager = ServiceManager::new(&runner);
        manager.install(&service_paths).unwrap();
        write_unit_dropin(
            &root,
            "30-private-users.conf",
            "[Service]\nPrivateUsers=yes\n",
        );
        write_service_record(
            &paths,
            &UserServiceRecord {
                schema_version: 1,
                installed: true,
                platform: "test".into(),
                executable: service_paths.executable.canonical.display().to_string(),
                unit_path: Some(root.join("ownmesh-ownmeshd.service").display().to_string()),
                installed_at_unix: 1,
                label: SERVICE_LABEL.into(),
                descriptor_version: Some(DESCRIPTOR_SCHEMA_VERSION),
                descriptor_digest: Some(descriptor_digest(
                    &manager
                        .install_plan(&service_paths)
                        .unwrap()
                        .descriptor_body,
                )),
            },
        )
        .unwrap();

        let cli = Cli {
            json: false,
            lang: None,
            command: None,
        };
        let args = ServiceActionArgs {
            dry_run: false,
            executable: Some(exe.to_str().unwrap().to_string()),
        };
        let err = run_install(&cli, &paths, &manager, &args).unwrap_err();
        assert_eq!(err, ExitCode::Internal);
        assert!(root
            .join("ownmesh-ownmeshd.service.d/30-private-users.conf")
            .exists());
        assert_eq!(
            platform::remaining_userns_forcing_dropins(&root.join("ownmesh-ownmeshd.service")),
            vec!["30-private-users.conf".to_string()]
        );
    }

    #[test]
    fn install_rewrites_stale_userns_base_unit() {
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
        let root = dir.path().join("svc-root");
        runner.set_root(root.clone());
        let manager = ServiceManager::new(&runner);
        manager.install(&service_paths).unwrap();
        let unit = root.join("ownmesh-ownmeshd.service");
        fs::write(
            &unit,
            "[Unit]\nDescription=legacy\n[Service]\nType=simple\nExecStart=/bin/true\nRestart=on-failure\nRestartSec=3\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths=/tmp/a\nPrivateTmp=true\n",
        )
        .unwrap();
        assert!(
            manager
                .probe()
                .unwrap()
                .hardening
                .unwrap()
                .user_namespace_forcing
        );
        write_service_record(
            &paths,
            &UserServiceRecord {
                schema_version: 1,
                installed: true,
                platform: "test".into(),
                executable: service_paths.executable.canonical.display().to_string(),
                unit_path: Some(unit.display().to_string()),
                installed_at_unix: 1,
                label: SERVICE_LABEL.into(),
                descriptor_version: Some(DESCRIPTOR_SCHEMA_VERSION),
                descriptor_digest: Some(descriptor_digest(
                    &manager
                        .install_plan(&service_paths)
                        .unwrap()
                        .descriptor_body,
                )),
            },
        )
        .unwrap();

        let cli = Cli {
            json: false,
            lang: None,
            command: None,
        };
        let args = ServiceActionArgs {
            dry_run: false,
            executable: Some(exe.to_str().unwrap().to_string()),
        };
        run_install(&cli, &paths, &manager, &args).unwrap();
        let body = fs::read_to_string(&unit).unwrap();
        assert!(
            !body
                .lines()
                .any(|line| line.trim_start().starts_with("ProtectSystem=")),
            "{body}"
        );
        assert!(body.contains("StartLimitBurst=5"), "{body}");
        assert!(
            !manager
                .probe()
                .unwrap()
                .hardening
                .unwrap()
                .user_namespace_forcing
        );
    }

    #[test]
    fn uninstall_removes_generated_dropin_and_keeps_operator_file() {
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
        let root = dir.path().join("svc-root");
        runner.set_root(root.clone());
        let manager = ServiceManager::new(&runner);
        manager.install(&service_paths).unwrap();
        write_unit_dropin(
            &root,
            "10-ownmesh-workspaces.conf",
            generated_workspace_dropin(),
        );
        write_unit_dropin(
            &root,
            "20-operator.conf",
            "[Service]\nRestrictNamespaces=no\n",
        );
        manager.uninstall().unwrap();
        assert!(!root
            .join("ownmesh-ownmeshd.service.d/10-ownmesh-workspaces.conf")
            .exists());
        assert!(root
            .join("ownmesh-ownmeshd.service.d/20-operator.conf")
            .exists());
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

/// Regression coverage for #147/#149/#153/#154: install must repair descriptor
/// drift, lifecycle verbs must cross the daemon IPC boundary, and uninstall
/// must not report success while the service manager still reports the daemon
/// running.
#[cfg(test)]
mod lifecycle_honesty_tests {
    use super::platform::{
        windows_task_identity, CommandOutput, DescriptorState, ProcessRunner, ScriptedProcessRunner,
    };
    use super::*;
    use crate::commands::service::descriptor::render_scheduled_task_xml;
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

    fn exe_name() -> &'static str {
        if cfg!(windows) {
            "ownmeshd.exe"
        } else {
            "ownmeshd"
        }
    }

    fn cli() -> Cli {
        Cli {
            json: false,
            lang: None,
            command: None,
        }
    }

    /// Installed fixture: temp dir, validated paths, and an installed service.
    struct Fixture {
        _dir: tempfile::TempDir,
        paths: OwnMeshPaths,
        exe: PathBuf,
        root: PathBuf,
        service_paths: ServicePaths,
    }

    fn install_fixture(runner: &ScriptedProcessRunner) -> Fixture {
        let dir = tempdir().unwrap();
        let exe = touch_exe(dir.path(), exe_name());
        let paths = OwnMeshPaths::for_base(dir.path().join("om"));
        paths.ensure_layout().unwrap();
        let service_paths = build_service_paths(Some(exe.to_str().unwrap()), &paths).unwrap();
        let root = dir.path().join("svc-root");
        runner.set_root(root.clone());
        let manager = ServiceManager::new(runner);
        let args = ServiceActionArgs {
            dry_run: false,
            executable: Some(exe.to_str().unwrap().to_string()),
        };
        run_install(&cli(), &paths, &manager, &args).unwrap();
        Fixture {
            _dir: dir,
            paths,
            exe,
            root,
            service_paths,
        }
    }

    fn install_args(fixture: &Fixture) -> ServiceActionArgs {
        ServiceActionArgs {
            dry_run: false,
            executable: Some(fixture.exe.to_str().unwrap().to_string()),
        }
    }

    #[test]
    fn install_records_a_versioned_descriptor_identity() {
        let runner = ScriptedProcessRunner::default();
        let fixture = install_fixture(&runner);
        let manager = ServiceManager::new(&runner);
        let plan = manager.install_plan(&fixture.service_paths).unwrap();

        let record = read_service_record(&fixture.paths).expect("record written");
        assert_eq!(record.descriptor_version, Some(DESCRIPTOR_SCHEMA_VERSION));
        assert_eq!(
            record.descriptor_digest.as_deref(),
            Some(descriptor_digest(&plan.descriptor_body).as_str())
        );
        assert!(manager.descriptor_state(&plan).is_current());
    }

    /// Review #2: a deliberate `service stop` must survive a later
    /// `service install`. Install may only re-register a *drifted* descriptor;
    /// treating a stopped (unloaded) service as drift would re-register it and
    /// silently bring a RunAtLoad/KeepAlive job back up.
    #[test]
    fn install_after_stop_does_not_restart_the_service() {
        let runner = ScriptedProcessRunner::default();
        let fixture = install_fixture(&runner);
        let manager = ServiceManager::new(&runner);

        manager.start().unwrap();
        assert_eq!(manager.probe().unwrap().running, Some(true));
        manager.stop().unwrap();
        assert_eq!(manager.probe().unwrap().running, Some(false));

        run_install(&cli(), &fixture.paths, &manager, &install_args(&fixture)).unwrap();

        assert_eq!(
            manager.probe().unwrap().running,
            Some(false),
            "install must not restart a service the operator deliberately stopped"
        );
        assert!(
            manager.probe().unwrap().installed,
            "the descriptor must remain installed"
        );
    }

    #[test]
    fn manually_altered_descriptor_is_repaired_not_reported_idempotent() {
        let runner = ScriptedProcessRunner::default();
        let fixture = install_fixture(&runner);
        let manager = ServiceManager::new(&runner);
        let plan = manager.install_plan(&fixture.service_paths).unwrap();
        let unit = fixture.root.join("ownmesh-ownmeshd.service");

        // Simulate a hand-edited descriptor that kept its path/name.
        let tampered = fs::read_to_string(&unit)
            .unwrap()
            .replace("NoNewPrivileges=true", "NoNewPrivileges=false");
        fs::write(&unit, &tampered).unwrap();
        assert!(
            matches!(manager.descriptor_state(&plan), DescriptorState::Drift(_)),
            "an edited descriptor must be drift"
        );

        run_install(&cli(), &fixture.paths, &manager, &install_args(&fixture)).unwrap();

        assert_eq!(
            fs::read_to_string(&unit).unwrap(),
            plan.descriptor_body,
            "install must rewrite the drifted descriptor"
        );
        assert!(manager.descriptor_state(&plan).is_current());
    }

    #[test]
    fn record_from_a_prior_descriptor_version_is_migrated() {
        let runner = ScriptedProcessRunner::default();
        let fixture = install_fixture(&runner);
        let manager = ServiceManager::new(&runner);
        let plan = manager.install_plan(&fixture.service_paths).unwrap();

        // A record written before #153 carries no descriptor identity at all.
        let mut record = read_service_record(&fixture.paths).unwrap();
        record.descriptor_version = None;
        record.descriptor_digest = None;
        write_service_record(&fixture.paths, &record).unwrap();

        run_install(&cli(), &fixture.paths, &manager, &install_args(&fixture)).unwrap();

        let migrated = read_service_record(&fixture.paths).unwrap();
        assert_eq!(migrated.descriptor_version, Some(DESCRIPTOR_SCHEMA_VERSION));
        assert_eq!(
            migrated.descriptor_digest.as_deref(),
            Some(descriptor_digest(&plan.descriptor_body).as_str())
        );
    }

    #[test]
    fn unreadable_descriptor_is_drift_rather_than_idempotent_success() {
        let runner = ScriptedProcessRunner::default();
        let fixture = install_fixture(&runner);
        let manager = ServiceManager::new(&runner);
        let plan = manager.install_plan(&fixture.service_paths).unwrap();

        fs::remove_file(fixture.root.join("ownmesh-ownmeshd.service")).unwrap();
        match manager.descriptor_state(&plan) {
            DescriptorState::Drift(reason) => assert!(!reason.is_empty()),
            DescriptorState::Current => panic!("a missing descriptor must never be current"),
        }
    }

    #[test]
    fn stop_reports_the_verified_offline_state_not_unknown() {
        // No daemon is listening, so the offline boundary is already crossed:
        // stop must report `running: false` rather than the probe's guess.
        let runner = ScriptedProcessRunner::default();
        let fixture = install_fixture(&runner);
        let manager = ServiceManager::new(&runner);
        let args = ServiceActionArgs {
            dry_run: false,
            executable: None,
        };
        run_lifecycle(&cli(), &fixture.paths, &manager, &args, Lifecycle::Stop)
            .expect("stop must succeed once the endpoint is observably offline");
    }

    #[test]
    fn start_fails_when_the_daemon_never_reaches_the_endpoint() {
        // The scripted manager accepts `/Run`-equivalent requests and reports
        // success, exactly like Task Scheduler queueing an action that dies.
        // Nothing ever binds the IPC endpoint, so start must fail closed.
        let runner = ScriptedProcessRunner::default();
        let fixture = install_fixture(&runner);
        let manager = ServiceManager::new(&runner);
        let args = ServiceActionArgs {
            dry_run: false,
            executable: None,
        };
        let result = run_lifecycle(&cli(), &fixture.paths, &manager, &args, Lifecycle::Start);
        assert!(
            result.is_err(),
            "an accepted start request that never reaches daemon IPC must not report ok"
        );
    }

    /// Service manager that keeps reporting the daemon active after uninstall,
    /// the shape #149 describes: the descriptor is gone but the loaded unit is
    /// still running.
    #[derive(Default)]
    struct StubbornRunner {
        inner: ScriptedProcessRunner,
    }

    impl ProcessRunner for StubbornRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput, String> {
            let out = self.inner.run(program, args)?;
            let is_status = args.first().copied() == Some("status")
                || args.iter().any(|a| *a == "is-active" || *a == "status");
            if is_status {
                return Ok(CommandOutput {
                    status: 0,
                    stdout: "ActiveState=active\ninstalled: true\nStatus: Running\n".into(),
                    stderr: String::new(),
                });
            }
            Ok(out)
        }

        fn fs_root(&self) -> Option<PathBuf> {
            self.inner.fs_root()
        }
    }

    #[test]
    fn uninstall_fails_and_keeps_the_record_while_the_daemon_still_runs() {
        let dir = tempdir().unwrap();
        let exe = touch_exe(dir.path(), exe_name());
        let paths = OwnMeshPaths::for_base(dir.path().join("om"));
        paths.ensure_layout().unwrap();
        let runner = StubbornRunner::default();
        runner.inner.set_root(dir.path().join("svc-root"));
        let manager = ServiceManager::new(&runner);
        let service_paths = build_service_paths(Some(exe.to_str().unwrap()), &paths).unwrap();
        manager.install(&service_paths).unwrap();
        write_service_record(
            &paths,
            &UserServiceRecord {
                schema_version: 1,
                installed: true,
                platform: "test".into(),
                executable: service_paths.executable.canonical.display().to_string(),
                unit_path: Some(
                    dir.path()
                        .join("svc-root/ownmesh-ownmeshd.service")
                        .display()
                        .to_string(),
                ),
                installed_at_unix: 1,
                label: SERVICE_LABEL.into(),
                descriptor_version: Some(DESCRIPTOR_SCHEMA_VERSION),
                descriptor_digest: Some(descriptor_digest(
                    &manager
                        .install_plan(&service_paths)
                        .unwrap()
                        .descriptor_body,
                )),
            },
        )
        .unwrap();

        let args = ServiceActionArgs {
            dry_run: false,
            executable: None,
        };
        let result = run_uninstall(&cli(), &paths, &manager, &args);
        assert!(
            result.is_err(),
            "uninstall must not report success while the manager reports ownmeshd running"
        );
        assert!(
            read_service_record(&paths).is_some(),
            "the install record must survive a partial uninstall so it can be retried"
        );
    }

    #[test]
    fn windows_task_identity_survives_scheduler_reformatting() {
        let dir = tempdir().unwrap();
        let exe = touch_exe(dir.path(), "ownmeshd.exe");
        let paths = OwnMeshPaths::for_base(dir.path().join("om"));
        paths.ensure_layout().unwrap();
        let service_paths = build_service_paths(Some(exe.to_str().unwrap()), &paths).unwrap();
        let rendered = render_scheduled_task_xml(&service_paths);
        let expected = windows_task_identity(&rendered);

        // Task Scheduler re-emits the document with different whitespace,
        // attribute order, and namespace declarations. The semantic identity
        // must be unchanged, or install would reinstall on every invocation.
        let reformatted = rendered
            .replace("\n  ", "\n\t")
            .replace("<Task version=\"1.4\"", "<Task  version=\"1.4\" ")
            .replace("<Settings>", "<Settings >");
        assert_eq!(windows_task_identity(&reformatted), expected);

        // The identity must carry the bound install-time paths (#148/#153).
        for flag in ["--config-dir", "--state-dir", "--runtime-dir"] {
            assert!(expected.arguments.contains(flag), "{expected:?}");
        }
        assert_eq!(expected.logon_trigger_count, 1);
        assert_eq!(expected.trigger_count, 1);
        assert_eq!(expected.exec_action_count, 1);
        assert_eq!(expected.run_level, "LeastPrivilege");
        assert_eq!(expected.restart_count, "3");
        assert_eq!(expected.restart_interval, "PT1M");

        // A task whose action lost the path binding is drift, not a match.
        let stale = rendered.replace(
            &format!("<Arguments>{}</Arguments>", expected.arguments),
            "<Arguments>run</Arguments>",
        );
        assert_ne!(windows_task_identity(&stale), expected);
    }

    /// A registered task that keeps the expected first action but adds a
    /// second one runs something OwnMesh never registered, so cardinality is
    /// part of the identity rather than only the first `<Exec>`'s fields.
    #[test]
    fn an_added_task_action_is_drift() {
        let dir = tempdir().unwrap();
        let exe = touch_exe(dir.path(), "ownmeshd.exe");
        let paths = OwnMeshPaths::for_base(dir.path().join("om"));
        paths.ensure_layout().unwrap();
        let service_paths = build_service_paths(Some(exe.to_str().unwrap()), &paths).unwrap();
        let rendered = render_scheduled_task_xml(&service_paths);
        let expected = windows_task_identity(&rendered);

        let with_second_action = rendered.replace(
            "</Exec>\n  </Actions>",
            "</Exec>\n    <Exec>\n      <Command>C:\\Windows\\System32\\calc.exe</Command>\n    </Exec>\n  </Actions>",
        );
        let smuggled = windows_task_identity(&with_second_action);
        assert_eq!(
            smuggled.command, expected.command,
            "fixture must keep the expected first action"
        );
        assert_eq!(smuggled.exec_action_count, 2);
        assert_ne!(
            smuggled, expected,
            "a task with an extra action must not compare equal"
        );
    }

    /// The restart policy is behavior, so a changed one is drift even though
    /// the action and trigger are untouched.
    #[test]
    fn an_altered_restart_policy_is_drift() {
        let dir = tempdir().unwrap();
        let exe = touch_exe(dir.path(), "ownmeshd.exe");
        let paths = OwnMeshPaths::for_base(dir.path().join("om"));
        paths.ensure_layout().unwrap();
        let service_paths = build_service_paths(Some(exe.to_str().unwrap()), &paths).unwrap();
        let rendered = render_scheduled_task_xml(&service_paths);
        let expected = windows_task_identity(&rendered);

        for (from, to) in [
            ("<Count>3</Count>", "<Count>99</Count>"),
            ("<Interval>PT1M</Interval>", "<Interval>PT5M</Interval>"),
            (
                "<StartWhenAvailable>true</StartWhenAvailable>",
                "<StartWhenAvailable>false</StartWhenAvailable>",
            ),
            (
                "<AllowStartOnDemand>true</AllowStartOnDemand>",
                "<AllowStartOnDemand>false</AllowStartOnDemand>",
            ),
            (
                "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
                "<DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>",
            ),
            ("<Priority>7</Priority>", "<Priority>4</Priority>"),
            ("<Hidden>false</Hidden>", "<Hidden>true</Hidden>"),
        ] {
            let altered = rendered.replace(from, to);
            assert_ne!(altered, rendered, "fixture for {from} did not apply");
            assert_ne!(
                windows_task_identity(&altered),
                expected,
                "changing {from} must be drift"
            );
        }
    }

    /// An added trigger changes when the daemon starts, so it is drift too.
    #[test]
    fn an_added_trigger_is_drift() {
        let dir = tempdir().unwrap();
        let exe = touch_exe(dir.path(), "ownmeshd.exe");
        let paths = OwnMeshPaths::for_base(dir.path().join("om"));
        paths.ensure_layout().unwrap();
        let service_paths = build_service_paths(Some(exe.to_str().unwrap()), &paths).unwrap();
        let rendered = render_scheduled_task_xml(&service_paths);
        let expected = windows_task_identity(&rendered);

        let with_boot_trigger = rendered.replace(
            "</LogonTrigger>",
            "</LogonTrigger>\n    <BootTrigger>\n      <Enabled>true</Enabled>\n    </BootTrigger>",
        );
        assert_ne!(windows_task_identity(&with_boot_trigger), expected);
    }
}
