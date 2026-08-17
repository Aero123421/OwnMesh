//! Platform install/start/stop using user-level OS mechanisms only.

// Platform cfg blocks end functions with `return` so each OS branch is an expression
// without forcing a shared trailing Err that is dead on supported targets.
#![allow(clippy::needless_return)]

#[cfg(target_os = "macos")]
use super::descriptor::{render_launch_agent_plist, SERVICE_LABEL};
#[cfg(windows)]
use super::descriptor::{
    render_scheduled_task_xml, windows_task_run_command, LEGACY_SERVICE_TASK_NAME,
    SERVICE_TASK_NAME,
};
use super::descriptor::{render_systemd_user_unit, ServicePaths, SERVICE_UNIT_NAME};
use super::security::reject_injection;
use ownmesh_persist::write_atomically;
use serde::Serialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(test)]
use std::sync::Mutex;

/// Captured command output.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    #[must_use]
    pub fn success(&self) -> bool {
        self.status == 0
    }
}

/// Abstraction over process spawning (production + tests).
pub trait ProcessRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput, String>;

    /// Optional filesystem root override used by scripted test runners.
    fn fs_root(&self) -> Option<PathBuf> {
        None
    }
}

/// Real OS process runner.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealProcessRunner;

impl ProcessRunner for RealProcessRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput, String> {
        reject_injection(program)?;
        for a in args {
            // Allow paths/flags; still block control chars.
            if a.chars().any(|c| c == '\n' || c == '\r' || c == '\0') {
                return Err("argument contains control characters".into());
            }
        }
        let mut command = Command::new(program);
        command.args(args);
        #[cfg(target_os = "linux")]
        configure_linux_user_bus(&mut command, program, args);
        let output = command
            .output()
            .map_err(|e| format!("spawn {program}: {e}"))?;
        Ok(CommandOutput {
            status: output.status.code().unwrap_or(1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// `systemctl --user` normally inherits these variables from a graphical or
/// login session. A non-interactive SSH command often does not, even while the
/// user's systemd manager and bus are healthy. Derive only the standard runtime
/// paths for the current uid, and only when the corresponding directory/socket
/// already exists. This never enables lingering or creates a user bus.
#[cfg(target_os = "linux")]
fn configure_linux_user_bus(command: &mut Command, program: &str, args: &[&str]) {
    if program != "systemctl" || !args.contains(&"--user") {
        return;
    }
    let inherited_runtime = env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let inherited_bus = env::var_os("DBUS_SESSION_BUS_ADDRESS");
    let runtime_dir = inherited_runtime.clone().unwrap_or_else(|| {
        PathBuf::from("/run/user").join(rustix::process::getuid().as_raw().to_string())
    });
    configure_linux_user_bus_from(command, inherited_runtime, inherited_bus, &runtime_dir);
}

#[cfg(target_os = "linux")]
fn configure_linux_user_bus_from(
    command: &mut Command,
    inherited_runtime: Option<PathBuf>,
    inherited_bus: Option<std::ffi::OsString>,
    runtime_dir: &Path,
) {
    use std::os::linux::fs::MetadataExt as _;
    use std::os::unix::fs::FileTypeExt as _;

    let Ok(runtime_meta) = fs::symlink_metadata(runtime_dir) else {
        return;
    };
    if !runtime_meta.file_type().is_dir()
        || runtime_meta.st_uid() != rustix::process::getuid().as_raw()
        || runtime_meta.st_mode() & 0o077 != 0
    {
        return;
    }
    let bus = runtime_dir.join("bus");
    let trusted_bus = fs::symlink_metadata(&bus).is_ok_and(|metadata| {
        metadata.file_type().is_socket() && metadata.st_uid() == rustix::process::getuid().as_raw()
    });
    if inherited_runtime.is_none() {
        command.env("XDG_RUNTIME_DIR", runtime_dir);
    }
    if inherited_bus.is_none() && trusted_bus {
        command.env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}", bus.display()),
        );
    }
}

/// Scripted runner for tests: installs descriptors under a temp root and tracks state.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct ScriptedProcessRunner {
    root: Mutex<Option<PathBuf>>,
    installed: Mutex<bool>,
    running: Mutex<bool>,
    /// Optional `systemctl --user show` effective-properties dump; `None`
    /// makes `systemctl show` fail (unit not loaded), exercising the static
    /// fallback.
    show_output: Mutex<Option<String>>,
}

#[cfg(test)]
impl ScriptedProcessRunner {
    pub fn set_root(&self, root: PathBuf) {
        let _ = fs::create_dir_all(&root);
        *self.root.lock().expect("lock") = Some(root);
    }

    pub fn set_show_output(&self, output: String) {
        *self.show_output.lock().expect("lock") = Some(output);
    }
}

#[cfg(test)]
impl ProcessRunner for ScriptedProcessRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput, String> {
        let mut installed = self.installed.lock().expect("lock");
        let mut running = self.running.lock().expect("lock");
        let action = args.first().copied().unwrap_or("");
        let has = |token: &str| {
            args.contains(&token)
                || program == token
                || args.iter().any(|a| a.eq_ignore_ascii_case(token))
        };

        // Probe / status (exact tokens — avoid matching "start" inside "status").
        if action == "status"
            || action == "/Query"
            || action == "query"
            || has("is-enabled")
            || has("is-active")
            || has("print")
        {
            let code = i32::from(!*installed);
            let stdout = if *installed {
                if *running {
                    "ActiveState=active\ninstalled: true\nStatus: Running\nstate = running\npid = 1\n"
                        .to_string()
                } else {
                    "ActiveState=inactive\ninstalled: true\nStatus: Ready\n".to_string()
                }
            } else {
                String::new()
            };
            return Ok(CommandOutput {
                status: code,
                stdout,
                stderr: String::new(),
            });
        }

        // `systemctl --user show` effective-properties dump (P1-E effective
        // hardening observation). `None` (default) reports a not-loaded unit
        // so callers fall back to the section-validated static analysis.
        if has("show") {
            let show = self.show_output.lock().expect("lock");
            return Ok(CommandOutput {
                status: i32::from(!show.is_some()),
                stdout: show.clone().unwrap_or_default(),
                stderr: if show.is_some() {
                    String::new()
                } else {
                    "Unit not loaded".into()
                },
            });
        }

        if action == "enable"
            || action == "/Create"
            || action == "bootstrap"
            || action == "load"
            || action == "import"
            || has("/Create")
        {
            *installed = true;
            return Ok(CommandOutput {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            });
        }

        if action == "disable"
            || action == "/Delete"
            || action == "bootout"
            || action == "unload"
            || has("/Delete")
            || has("remove")
        {
            *installed = false;
            *running = false;
            return Ok(CommandOutput {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            });
        }

        if action == "start" || action == "/Run" || action == "kickstart" || has("/Run") {
            if !*installed {
                return Ok(CommandOutput {
                    status: 1,
                    stdout: String::new(),
                    stderr: "not installed".into(),
                });
            }
            *running = true;
            return Ok(CommandOutput {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            });
        }

        if action == "stop" || action == "/End" || action == "kill" || has("/End") {
            *running = false;
            return Ok(CommandOutput {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            });
        }

        // daemon-reload and other no-ops
        Ok(CommandOutput {
            status: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    }

    fn fs_root(&self) -> Option<PathBuf> {
        self.root.lock().expect("lock").clone()
    }
}

/// Snapshot of OS service state.
#[derive(Debug, Clone)]
pub struct ServiceStatusSnapshot {
    pub platform: String,
    pub supported: bool,
    pub installed: bool,
    pub running: Option<bool>,
    pub unit_path: Option<String>,
    pub message: Option<String>,
    /// Effective service hardening disclosure (Linux systemd --user units):
    /// `None` on platforms without a unit-file model.
    pub hardening: Option<ServiceHardening>,
}

/// Effective hardening of an installed systemd --user unit, read read-only
/// from the unit file plus any drop-ins (P1-E). Local overrides that disable
/// the meaningful privilege guards or re-introduce unexpected filesystem/
/// visibility directives are disclosed here so doctor can warn instead of
/// claiming an unmodified baseline.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools)] // serializable DTO: one bool per directive
pub struct ServiceHardening {
    /// `NoNewPrivileges=true` present in the effective (merged) unit.
    pub no_new_privileges: bool,
    /// Per-user-safe directives from the shipped baseline unit (P1-E).
    pub umask_set: bool,
    pub restrict_suidsgid: bool,
    pub restrict_realtime: bool,
    pub lock_personality: bool,
    /// `SystemCallArchitectures=native` present in the effective unit
    /// (seccomp: blocks non-native architecture syscalls; available in user
    /// services without a user namespace).
    pub system_call_architectures: bool,
    /// `RestrictNamespaces=yes` present in the effective unit (seccomp:
    /// blocks namespace-creation syscalls; available in user services
    /// without a user namespace).
    pub restrict_namespaces: bool,
    /// Any `CapabilityBoundingSet=` value in the effective unit. An
    /// unprivileged --user manager cannot apply it: user-service startup
    /// fails with exit status 218/CAPABILITIES on systemd v259 even under
    /// `PrivateUsers=yes` (verified empirically; systemd.exec(5) documents
    /// that an unset option leaves the bounding set unmodified).
    pub capability_bounding_set: bool,
    /// An unexpected filesystem/visibility directive beyond the shipped
    /// baseline is present. The v1.2.13 baseline deliberately does **not**
    /// force a user namespace: `PrivateUsers=yes` and the filesystem
    /// namespacing directives (`ProtectSystem=`, `ProtectHome=`,
    /// `ReadWritePaths=`, `ReadOnlyPaths=`, `InaccessiblePaths=`,
    /// `PrivateTmp=`, `ProtectKernelTunables=`, `ProtectControlGroups=`,
    /// `ProtectHostname=`, `PrivateDevices=`, `PrivateNetwork=`,
    /// `DynamicUser=`, `ProcSubset=`, `BindPaths=`, `TemporaryFileSystem=`, …)
    /// implicitly enable `PrivateUsers=` in a per-user service (systemd NEWS
    /// v254; systemd.exec(5)), which maps every host uid outside the
    /// namespace — host root and every other host user alike — to the
    /// overflow uid 65534. OwnMesh custody validation cannot distinguish a
    /// host-root-owned system directory from an attacker-owned one inside
    /// that namespace, so accepting the overflow uid would let a
    /// foreign-owned 0755/01777 ancestor pass and its owner could replace
    /// the daemon's state directory (A5 cross-user boundary; v1.2.13
    /// review, ADR 0011). Any such directive is therefore disclosed as
    /// start-breaking (the daemon fails to start with `ancestor is owned by
    /// untrusted uid 65534`), never silently accepted as hardening.
    pub user_namespace_forcing: bool,
    /// Directives that make the user's home / workspace hierarchy read-only
    /// (`ProtectHome=` with a value other than `no`, or `ReadOnlyPaths=`),
    /// which conflicts with the registered-workspace model.
    pub read_only_hierarchy: bool,
    /// `PrivateUsers=yes` present. In a per-user service this forces a user
    /// namespace that hides real uids (see [`ServiceHardening::user_namespace_forcing`]);
    /// it is disclosed as start-breaking, never counted as baseline (v1.2.13
    /// review, ADR 0011).
    pub private_users: bool,
    /// `ProtectSystem=full|strict` present (forces the user namespace in a
    /// per-user service; disclosed as start-breaking, never baseline).
    pub protect_system_full: bool,
    /// `PrivateTmp=yes` present (forces the user namespace in a per-user
    /// service; disclosed as start-breaking, never baseline).
    pub private_tmp: bool,
    /// `ProtectProc=invisible` present (hidepid= on the unit's /proc
    /// instance; shipped baseline, ADR 0011).
    pub protect_proc: bool,
    /// `ProtectKernelTunables=yes` present (forces the user namespace in a
    /// per-user service; disclosed as start-breaking, never baseline).
    pub protect_kernel_tunables: bool,
    /// `ProtectControlGroups=yes|private|strict` present (forces the user
    /// namespace in a per-user service; disclosed as start-breaking, never
    /// baseline).
    pub protect_control_groups: bool,
    /// `ProtectHostname=yes` present (forces the user namespace in a
    /// per-user service; disclosed as start-breaking, never baseline).
    pub protect_hostname: bool,
    /// `ReadWritePaths=` is present with a non-empty list. In a per-user
    /// service this implies `ProtectSystem=` and forces the user namespace;
    /// it is disclosed as start-breaking, never counted as baseline (v1.2.13
    /// review, ADR 0011).
    pub read_write_paths_set: bool,
    /// `ProtectClock=` / `ProtectKernelLogs=` / `ProtectKernelModules=`
    /// present: on systemd v259 these fail user-service startup with exit
    /// status 218/CAPABILITIES even under `PrivateUsers=yes` (verified
    /// empirically), so they are disclosed as start-breaking rather than
    /// silently accepted.
    pub start_breaking_directives: bool,
    /// The unit file is masked (empty, or a symlink to /dev/null): systemd
    /// cannot activate it (systemd.unit(5)) and the daemon is not running
    /// under the shipped unit.
    pub masked: bool,
    /// Human-readable disclosure of what was found.
    pub summary: String,
}

/// Planned install artifacts (for dry-run).
#[derive(Debug, Clone)]
pub struct InstallPlan {
    pub platform: String,
    pub unit_path: String,
    pub descriptor_body: String,
}

/// User-level service manager.
pub struct ServiceManager<'a, R: ProcessRunner> {
    runner: &'a R,
}

impl<'a, R: ProcessRunner> ServiceManager<'a, R> {
    #[must_use]
    pub fn new(runner: &'a R) -> Self {
        Self { runner }
    }

    #[must_use]
    pub fn platform_supported(&self) -> bool {
        cfg!(any(windows, target_os = "macos", target_os = "linux"))
            || self.runner.fs_root().is_some()
    }

    pub fn install_plan(&self, paths: &ServicePaths) -> Result<InstallPlan, String> {
        if let Some(root) = self.runner.fs_root() {
            let unit = root.join(SERVICE_UNIT_NAME);
            return Ok(InstallPlan {
                platform: "test".into(),
                unit_path: unit.display().to_string(),
                descriptor_body: render_systemd_user_unit(paths),
            });
        }
        #[cfg(windows)]
        {
            return Ok(InstallPlan {
                platform: "windows".into(),
                unit_path: format!("task:{SERVICE_TASK_NAME}"),
                descriptor_body: render_scheduled_task_xml(paths),
            });
        }
        #[cfg(target_os = "macos")]
        {
            let unit = launch_agent_path()?;
            return Ok(InstallPlan {
                platform: "macos".into(),
                unit_path: unit.display().to_string(),
                descriptor_body: render_launch_agent_plist(paths),
            });
        }
        #[cfg(target_os = "linux")]
        {
            let unit = systemd_user_unit_path()?;
            return Ok(InstallPlan {
                platform: "linux".into(),
                unit_path: unit.display().to_string(),
                descriptor_body: render_systemd_user_unit(paths),
            });
        }
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            let _ = paths;
            Err("user-level service install unsupported on this OS".into())
        }
    }

    pub fn install(&self, paths: &ServicePaths) -> Result<(), String> {
        // Test root path: write descriptor only.
        if let Some(root) = self.runner.fs_root() {
            write_descriptor_to_root(&root, paths)?;
            // Mark installed via a create-like call.
            let _ = self.runner.run("testctl", &["enable", SERVICE_UNIT_NAME])?;
            return Ok(());
        }

        #[cfg(windows)]
        {
            return install_windows(self.runner, paths);
        }
        #[cfg(target_os = "macos")]
        {
            return install_macos(self.runner, paths);
        }
        #[cfg(target_os = "linux")]
        {
            return install_linux(self.runner, paths);
        }
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            let _ = paths;
            Err("user-level service install unsupported on this OS".into())
        }
    }

    pub fn uninstall(&self) -> Result<(), String> {
        if let Some(root) = self.runner.fs_root() {
            let unit = root.join(SERVICE_UNIT_NAME);
            let _ = fs::remove_file(unit);
            let _ = self
                .runner
                .run("testctl", &["disable", SERVICE_UNIT_NAME])?;
            return Ok(());
        }
        #[cfg(windows)]
        {
            return uninstall_windows(self.runner);
        }
        #[cfg(target_os = "macos")]
        {
            return uninstall_macos(self.runner);
        }
        #[cfg(target_os = "linux")]
        {
            return uninstall_linux(self.runner);
        }
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            Err("user-level service uninstall unsupported on this OS".into())
        }
    }

    pub fn start(&self) -> Result<(), String> {
        if self.runner.fs_root().is_some() {
            let out = self.runner.run("testctl", &["start", SERVICE_UNIT_NAME])?;
            return if out.success() {
                Ok(())
            } else {
                Err(out.stderr)
            };
        }
        #[cfg(windows)]
        {
            let task = windows_installed_task_name(self.runner)?.unwrap_or(SERVICE_TASK_NAME);
            let out = self.runner.run("schtasks", &["/Run", "/TN", task])?;
            return if out.success() {
                Ok(())
            } else {
                Err(format!(
                    "schtasks /Run failed (status {}); verify the current-user task exists",
                    out.status
                ))
            };
        }
        #[cfg(target_os = "macos")]
        {
            let uid = user_id_string()?;
            let target = format!("gui/{uid}/{SERVICE_LABEL}");
            let out = self
                .runner
                .run("launchctl", &["kickstart", "-k", &target])?;
            return if out.success() {
                Ok(())
            } else {
                Err(format!(
                    "launchctl kickstart failed: {}{}",
                    out.stdout, out.stderr
                ))
            };
        }
        #[cfg(target_os = "linux")]
        {
            let out = self
                .runner
                .run("systemctl", &["--user", "start", SERVICE_UNIT_NAME])?;
            return if out.success() {
                Ok(())
            } else {
                Err(format!(
                    "systemctl start failed: {}{}",
                    out.stdout, out.stderr
                ))
            };
        }
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            Err("unsupported".into())
        }
    }

    pub fn stop(&self) -> Result<(), String> {
        if self.runner.fs_root().is_some() {
            let out = self.runner.run("testctl", &["stop", SERVICE_UNIT_NAME])?;
            return if out.success() {
                Ok(())
            } else {
                Err(out.stderr)
            };
        }
        #[cfg(windows)]
        {
            let task = windows_installed_task_name(self.runner)?.unwrap_or(SERVICE_TASK_NAME);
            let out = self.runner.run("schtasks", &["/End", "/TN", task])?;
            // /End may fail if not running — treat as soft success when task exists.
            if out.success()
                || out.stdout.to_ascii_lowercase().contains("not running")
                || out.stderr.to_ascii_lowercase().contains("not running")
            {
                return Ok(());
            }
            return Err(format!("schtasks /End failed (status {})", out.status));
        }
        #[cfg(target_os = "macos")]
        {
            let uid = user_id_string()?;
            let target = format!("gui/{uid}/{SERVICE_LABEL}");
            let out = self
                .runner
                .run("launchctl", &["kill", "SIGTERM", &target])?;
            if out.success()
                || out.stderr.contains("No such process")
                || out.stdout.contains("No such process")
            {
                return Ok(());
            }
            return Err(format!(
                "launchctl kill failed: {}{}",
                out.stdout, out.stderr
            ));
        }
        #[cfg(target_os = "linux")]
        {
            let out = self
                .runner
                .run("systemctl", &["--user", "stop", SERVICE_UNIT_NAME])?;
            return if out.success() {
                Ok(())
            } else {
                Err(format!(
                    "systemctl stop failed: {}{}",
                    out.stdout, out.stderr
                ))
            };
        }
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            Err("unsupported".into())
        }
    }

    pub fn probe(&self) -> Result<ServiceStatusSnapshot, String> {
        if let Some(root) = self.runner.fs_root() {
            let unit = root.join(SERVICE_UNIT_NAME);
            let out = self.runner.run("testctl", &["status", SERVICE_UNIT_NAME])?;
            let installed = unit.is_file() || out.success();
            let running = if out.stdout.contains("ActiveState=active") {
                Some(true)
            } else if installed {
                Some(false)
            } else {
                None
            };
            return Ok(ServiceStatusSnapshot {
                platform: "test".into(),
                supported: true,
                installed,
                running,
                unit_path: Some(unit.display().to_string()),
                message: None,
                hardening: observe_unit_hardening(&unit),
            });
        }
        #[cfg(windows)]
        {
            return probe_windows(self.runner);
        }
        #[cfg(target_os = "macos")]
        {
            return probe_macos(self.runner);
        }
        #[cfg(target_os = "linux")]
        {
            return probe_linux(self.runner);
        }
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            Ok(ServiceStatusSnapshot {
                platform: std::env::consts::OS.into(),
                supported: false,
                installed: false,
                running: None,
                unit_path: None,
                message: Some("user-level service unsupported on this OS".into()),
                hardening: None,
            })
        }
    }
}

/// Write a unit descriptor under an isolated root (tests).
pub fn write_descriptor_to_root(root: &Path, paths: &ServicePaths) -> Result<PathBuf, String> {
    fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let unit = root.join(SERVICE_UNIT_NAME);
    let body = render_systemd_user_unit(paths);
    write_atomically(&unit, body.as_bytes()).map_err(|e| e.to_string())?;
    Ok(unit)
}

/// Locate `ownmeshd` next to the CLI or on PATH.
pub fn resolve_ownmeshd_path(explicit: Option<&str>) -> Result<PathBuf, String> {
    if let Some(raw) = explicit {
        let p = PathBuf::from(raw);
        if p.is_file() {
            return Ok(p);
        }
        return Err(format!("executable not found: {raw}"));
    }
    // A macOS privileged-broker install pins this root-owned image by exact
    // inode and audit token. Prefer it automatically so a normal LaunchAgent
    // can use elevation without exposing platform paths to the user.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let installed = if cfg!(target_os = "macos") {
            PathBuf::from("/Library/Application Support/OwnMesh/bin/ownmeshd")
        } else {
            PathBuf::from("/usr/lib/ownmesh/ownmeshd")
        };
        if installed.is_file() {
            return Ok(installed);
        }
    }
    #[cfg(windows)]
    if let Some(program_files) = env::var_os("ProgramFiles") {
        let installed = PathBuf::from(program_files)
            .join("OwnMesh")
            .join("ownmeshd.exe");
        if installed.is_file() {
            return Ok(installed);
        }
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in ["ownmeshd", "ownmeshd.exe"] {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }
    for name in ["ownmeshd", "ownmeshd.exe"] {
        if let Some(p) = which(name) {
            return Ok(p);
        }
    }
    Err("ownmeshd executable not found beside ownmesh or on PATH (pass --executable)".into())
}

fn which(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(windows)]
fn install_windows<R: ProcessRunner + ?Sized>(
    runner: &R,
    paths: &ServicePaths,
) -> Result<(), String> {
    // Prefer /XML import when we can stage a temp file under %TEMP%.
    let temp = env::temp_dir().join(format!("ownmesh-task-{}.xml", std::process::id()));
    let xml = render_scheduled_task_xml(paths);
    // Task XML is UTF-16 LE with BOM for schtasks /Create /XML.
    let mut bytes = vec![0xFF, 0xFE];
    for u in xml.encode_utf16() {
        bytes.push((u & 0xFF) as u8);
        bytes.push((u >> 8) as u8);
    }
    write_atomically(&temp, &bytes).map_err(|e| format!("write task xml: {e}"))?;

    let temp_str = temp.display().to_string();
    let out = runner.run(
        "schtasks",
        &["/Create", "/TN", SERVICE_TASK_NAME, "/XML", &temp_str, "/F"],
    );
    let _ = fs::remove_file(&temp);
    match out {
        Ok(o) if o.success() => Ok(()),
        Ok(o) => {
            // Fallback: /TR form with quoted command.
            let tr = windows_task_run_command(paths);
            let out2 = runner.run(
                "schtasks",
                &[
                    "/Create",
                    "/TN",
                    SERVICE_TASK_NAME,
                    "/SC",
                    "ONLOGON",
                    "/RL",
                    "LIMITED",
                    "/TR",
                    &tr,
                    "/F",
                ],
            )?;
            if out2.success() {
                Ok(())
            } else {
                Err(format!(
                    "schtasks create failed (XML status {}); fallback failed (status {}); verify Task Scheduler is available for this user",
                    o.status, out2.status
                ))
            }
        }
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
fn uninstall_windows<R: ProcessRunner + ?Sized>(runner: &R) -> Result<(), String> {
    let installed = query_windows_tasks(runner)?;
    for (present, task) in [
        (installed.current, SERVICE_TASK_NAME),
        (installed.legacy, LEGACY_SERVICE_TASK_NAME),
    ] {
        if !present {
            continue;
        }
        let out = runner.run("schtasks", &["/Delete", "/TN", task, "/F"])?;
        if !out.success() && query_windows_tasks(runner)?.contains(task) {
            return Err(format!(
                "schtasks could not delete task {task} (status {})",
                out.status
            ));
        }
    }
    let remaining = query_windows_tasks(runner)?;
    if remaining.current || remaining.legacy {
        return Err("OwnMesh scheduled task still exists after uninstall".into());
    }
    Ok(())
}

#[cfg(windows)]
fn probe_windows<R: ProcessRunner + ?Sized>(runner: &R) -> Result<ServiceStatusSnapshot, String> {
    let installed = query_windows_tasks(runner)?;
    if installed.current {
        let mut snapshot = probe_windows_named(runner, SERVICE_TASK_NAME)?;
        if installed.legacy {
            snapshot.unit_path = Some(format!(
                "task:{SERVICE_TASK_NAME}; legacy:{LEGACY_SERVICE_TASK_NAME}"
            ));
            snapshot.message =
                Some("legacy OwnMesh task also installed; reinstall to migrate".into());
        }
        return Ok(snapshot);
    }
    if installed.legacy {
        return probe_windows_named(runner, LEGACY_SERVICE_TASK_NAME);
    }
    Ok(ServiceStatusSnapshot {
        platform: "windows".into(),
        supported: true,
        installed: false,
        running: None,
        unit_path: Some(format!("task:{SERVICE_TASK_NAME}")),
        message: Some("scheduled task not found".into()),
        hardening: None,
    })
}

#[cfg(windows)]
fn windows_installed_task_name<R: ProcessRunner + ?Sized>(
    runner: &R,
) -> Result<Option<&'static str>, String> {
    let installed = query_windows_tasks(runner)?;
    if installed.current {
        return Ok(Some(SERVICE_TASK_NAME));
    }
    if installed.legacy {
        return Ok(Some(LEGACY_SERVICE_TASK_NAME));
    }
    Ok(None)
}

#[cfg(windows)]
fn probe_windows_named<R: ProcessRunner + ?Sized>(
    runner: &R,
    task: &str,
) -> Result<ServiceStatusSnapshot, String> {
    let out = runner.run("schtasks", &["/Query", "/TN", task, "/V", "/FO", "LIST"])?;
    if !out.success() {
        return Err(format!(
            "schtasks query failed for {task} (status {})",
            out.status
        ));
    }
    Ok(ServiceStatusSnapshot {
        platform: "windows".into(),
        supported: true,
        installed: true,
        // `schtasks` localizes its state text. Agent IPC is the authoritative
        // liveness signal, so do not report a false stopped/running value here.
        running: None,
        unit_path: Some(format!("task:{task}")),
        message: None,
        hardening: None,
    })
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct WindowsTaskSet {
    current: bool,
    legacy: bool,
}

#[cfg(windows)]
impl WindowsTaskSet {
    fn contains(self, task: &str) -> bool {
        if task.eq_ignore_ascii_case(SERVICE_TASK_NAME) {
            self.current
        } else if task.eq_ignore_ascii_case(LEGACY_SERVICE_TASK_NAME) {
            self.legacy
        } else {
            false
        }
    }
}

#[cfg(windows)]
fn query_windows_tasks<R: ProcessRunner + ?Sized>(runner: &R) -> Result<WindowsTaskSet, String> {
    let out = runner.run("schtasks", &["/Query", "/FO", "CSV", "/NH"])?;
    if !out.success() {
        return Err(format!(
            "schtasks could not enumerate scheduled tasks (status {})",
            out.status
        ));
    }
    Ok(parse_windows_task_set(&out.stdout))
}

#[cfg(windows)]
fn parse_windows_task_set(stdout: &str) -> WindowsTaskSet {
    let mut tasks = WindowsTaskSet::default();
    for line in stdout.lines() {
        let Some(name) = first_csv_field(line) else {
            continue;
        };
        let normalized = name.trim().trim_start_matches('\\');
        tasks.current |= normalized.eq_ignore_ascii_case(SERVICE_TASK_NAME);
        tasks.legacy |= normalized.eq_ignore_ascii_case(LEGACY_SERVICE_TASK_NAME);
    }
    tasks
}

#[cfg(windows)]
fn first_csv_field(line: &str) -> Option<String> {
    let line = line.trim().trim_start_matches('\u{feff}');
    if line.is_empty() {
        return None;
    }
    let Some(mut rest) = line.strip_prefix('"') else {
        return line.split(',').next().map(str::trim).map(ToOwned::to_owned);
    };
    let mut field = String::new();
    loop {
        let quote = rest.find('"')?;
        field.push_str(&rest[..quote]);
        rest = &rest[quote + 1..];
        if let Some(after_escape) = rest.strip_prefix('"') {
            field.push('"');
            rest = after_escape;
        } else {
            return Some(field);
        }
    }
}

#[cfg(target_os = "macos")]
fn launch_agent_path() -> Result<PathBuf, String> {
    let home = env::var_os("HOME").ok_or_else(|| "HOME is not set".to_string())?;
    Ok(PathBuf::from(home)
        .join("Library/LaunchAgents")
        .join(format!("{SERVICE_LABEL}.plist")))
}

#[cfg(target_os = "macos")]
fn user_id_string() -> Result<String, String> {
    let out = RealProcessRunner.run("id", &["-u"])?;
    if !out.success() {
        return Err(format!("id -u failed: {}", out.stderr));
    }
    let uid = out.stdout.trim();
    if uid.is_empty() || !uid.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("invalid uid: {uid}"));
    }
    Ok(uid.to_string())
}

#[cfg(target_os = "macos")]
fn install_macos(runner: &impl ProcessRunner, paths: &ServicePaths) -> Result<(), String> {
    let plist_path = launch_agent_path()?;
    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create LaunchAgents: {e}"))?;
    }
    let body = render_launch_agent_plist(paths);
    write_atomically(&plist_path, body.as_bytes()).map_err(|e| format!("write plist: {e}"))?;

    let uid = user_id_string()?;
    let domain = format!("gui/{uid}");
    // bootout first for idempotent re-install (ignore errors).
    let plist_str = plist_path.display().to_string();
    let _ = runner.run("launchctl", &["bootout", &domain, &plist_str]);
    let out = runner.run("launchctl", &["bootstrap", &domain, &plist_str])?;
    if out.success()
        || out.stderr.contains("already bootstrapped")
        || out.stdout.contains("already bootstrapped")
    {
        let _ = runner.run(
            "launchctl",
            &["enable", &format!("{domain}/{SERVICE_LABEL}")],
        );
        return Ok(());
    }
    Err(format!(
        "launchctl bootstrap failed: {}{}",
        out.stdout, out.stderr
    ))
}

#[cfg(target_os = "macos")]
fn uninstall_macos(runner: &impl ProcessRunner) -> Result<(), String> {
    let plist_path = launch_agent_path()?;
    let uid = user_id_string()?;
    let domain = format!("gui/{uid}");
    let plist_str = plist_path.display().to_string();
    let _ = runner.run("launchctl", &["bootout", &domain, &plist_str]);
    match fs::remove_file(&plist_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("remove plist: {e}")),
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn probe_macos(runner: &impl ProcessRunner) -> Result<ServiceStatusSnapshot, String> {
    let plist_path = launch_agent_path()?;
    let installed = plist_path.is_file();
    let uid = user_id_string().unwrap_or_else(|_| "?".into());
    let label_target = format!("gui/{uid}/{SERVICE_LABEL}");
    let out = runner.run("launchctl", &["print", &label_target]);
    let running = match out {
        Ok(o) if o.success() => {
            let lower = o.stdout.to_ascii_lowercase();
            Some(lower.contains("state = running") || lower.contains("pid = "))
        }
        _ => {
            if installed {
                Some(false)
            } else {
                None
            }
        }
    };
    Ok(ServiceStatusSnapshot {
        platform: "macos".into(),
        supported: true,
        installed,
        running,
        unit_path: Some(plist_path.display().to_string()),
        message: None,
        hardening: None,
    })
}

#[cfg(target_os = "linux")]
fn systemd_user_unit_path() -> Result<PathBuf, String> {
    if let Some(xdg) = env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(xdg)
            .join("systemd/user")
            .join(SERVICE_UNIT_NAME));
    }
    let home = env::var_os("HOME").ok_or_else(|| "HOME is not set".to_string())?;
    Ok(PathBuf::from(home)
        .join(".config/systemd/user")
        .join(SERVICE_UNIT_NAME))
}

#[cfg(target_os = "linux")]
fn install_linux(runner: &impl ProcessRunner, paths: &ServicePaths) -> Result<(), String> {
    let unit_path = systemd_user_unit_path()?;
    if let Some(parent) = unit_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create systemd user dir: {e}"))?;
    }
    let body = render_systemd_user_unit(paths);
    write_atomically(&unit_path, body.as_bytes()).map_err(|e| format!("write unit: {e}"))?;

    let out = runner.run("systemctl", &["--user", "daemon-reload"])?;
    if !out.success() {
        return Err(format!(
            "systemctl daemon-reload failed: {}{}",
            out.stdout, out.stderr
        ));
    }
    let out = runner.run("systemctl", &["--user", "enable", SERVICE_UNIT_NAME])?;
    if !out.success() {
        return Err(format!(
            "systemctl enable failed: {}{}",
            out.stdout, out.stderr
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_linux(runner: &impl ProcessRunner) -> Result<(), String> {
    let _ = runner.run("systemctl", &["--user", "stop", SERVICE_UNIT_NAME]);
    let _ = runner.run("systemctl", &["--user", "disable", SERVICE_UNIT_NAME]);
    let unit_path = systemd_user_unit_path()?;
    match fs::remove_file(&unit_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("remove unit: {e}")),
    }
    let _ = runner.run("systemctl", &["--user", "daemon-reload"]);
    Ok(())
}

#[cfg(target_os = "linux")]
fn probe_linux(runner: &impl ProcessRunner) -> Result<ServiceStatusSnapshot, String> {
    let unit_path = systemd_user_unit_path()?;
    let file_present = unit_path.is_file();
    let enabled = runner
        .run("systemctl", &["--user", "is-enabled", SERVICE_UNIT_NAME])
        .map(|o| o.success() && o.stdout.trim() == "enabled")
        .unwrap_or(false);
    let installed = file_present || enabled;
    let active = runner
        .run("systemctl", &["--user", "is-active", SERVICE_UNIT_NAME])
        .ok();
    let running = match active {
        Some(o) if o.success() && o.stdout.trim() == "active" => Some(true),
        Some(_) if installed => Some(false),
        _ => {
            if installed {
                Some(false)
            } else {
                None
            }
        }
    };
    Ok(ServiceStatusSnapshot {
        platform: "linux".into(),
        supported: true,
        installed,
        running,
        unit_path: Some(unit_path.display().to_string()),
        message: None,
        // Manager-effective hardening: `systemctl --user show` reflects the
        // loaded unit (base + drop-ins + defaults), falling back to the
        // section-validated static file analysis when systemd is unavailable.
        hardening: observe_unit_hardening_effective(runner, &unit_path),
    })
}

/// Directive name/value pairs present in the `[Service]` section of a
/// systemd unit text (comments and blank lines ignored; only real
/// `Name=value` directive lines count). Directives placed in the wrong
/// section are ignored by systemd (with a warning), so a `ProtectSystem=`
/// in `[Unit]` must never be counted as effective hardening — this is what
/// makes the static observation section-validated.
fn unit_directives(raw: &str) -> Vec<(String, String)> {
    let mut section = String::new();
    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(header) = trimmed.strip_prefix('[') {
            if let Some(name) = header.strip_suffix(']') {
                section = name.trim().to_string();
            }
            continue;
        }
        if section != "Service" {
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some((name, value)) = trimmed.split_once('=') {
            out.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    out
}

/// systemd boolean acceptance (true/yes/on/1); empty is treated as unset.
fn systemd_bool_true(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "yes" | "on" | "1"
    )
}

/// The shipped baseline requires `UMask=0077` (descriptor.rs). systemd
/// accepts any octal spelling (`0077`, `077`), so compare the parsed mode;
/// a present-but-weak UMask (e.g. `0002`) is not the baseline. `systemctl
/// show` reports the mode normalized to `%04o`, so the same comparison is
/// valid for both the static unit-file observation and the manager-effective
/// observation (P1-E review).
fn umask_is_baseline(value: &str) -> bool {
    u32::from_str_radix(value.trim(), 8).is_ok_and(|mode| mode == 0o77)
}

/// systemd --user unit search directories in precedence order, mirroring
/// systemd.unit(5) "User Unit Search Path" (highest precedence first):
/// `$XDG_CONFIG_HOME/systemd/user.control`, `$XDG_RUNTIME_DIR/systemd/user.control`,
/// `$XDG_RUNTIME_DIR/systemd/transient`, `$XDG_RUNTIME_DIR/systemd/generator.early`,
/// `~/.config/systemd/user`, `$XDG_CONFIG_DIRS/systemd/user`, `/etc/systemd/user`,
/// `$XDG_RUNTIME_DIR/systemd/user`, `/run/systemd/user`, `$XDG_RUNTIME_DIR/systemd/generator`,
/// `$XDG_DATA_HOME/systemd/user`, `$XDG_DATA_DIRS/systemd/user`,
/// `/usr/local/lib/systemd/user`, `/usr/lib/systemd/user`,
/// `$XDG_RUNTIME_DIR/systemd/generator.late`.
///
/// Unit files found in directories listed earlier override files with the
/// same name in directories lower in the list; drop-ins are merged from every
/// directory with higher-precedence directories winning for same-named files
/// and different-named files applied in lexicographic order.
///
/// `SYSTEMD_UNIT_PATH` (systemd.unit(5)) is honored: when set it *replaces*
/// the default search path, and a trailing `:` appends the default path after
/// it. Empty components are skipped (systemd rejects `::`/leading `:`; a
/// read-only observer skips them rather than failing the whole observation).
/// The result is deduplicated by exact path, mirroring systemd's `strv_uniq`
/// on the final search path.
#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
fn systemd_user_search_dirs() -> Vec<PathBuf> {
    systemd_unit_path_dirs(env::var_os("SYSTEMD_UNIT_PATH").as_deref())
}

/// Pure core of the `SYSTEMD_UNIT_PATH` handling (systemd.unit(5)): when the
/// variable is set it *replaces* the default search path, and a trailing `:`
/// appends the default path after it. Empty components are skipped (systemd
/// rejects `::`/leading `:`; a read-only observer skips them rather than
/// failing the whole observation). The result is deduplicated by exact path,
/// mirroring systemd's `strv_uniq` on the final search path. Parameters keep
/// the behavior unit-testable without mutating the process environment.
#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
fn systemd_unit_path_dirs(raw: Option<&std::ffi::OsStr>) -> Vec<PathBuf> {
    let default = systemd_user_default_search_dirs();
    let Some(raw) = raw.filter(|v| !v.is_empty()) else {
        return default;
    };
    let raw = raw.to_string_lossy();
    let append_default = raw.ends_with(':');
    let mut dirs: Vec<PathBuf> = env::split_paths(std::ffi::OsStr::new(raw.as_ref()))
        .filter(|dir| !dir.as_os_str().is_empty())
        .collect();
    if append_default {
        dirs.extend(default);
    }
    dedup_paths(dirs)
}

/// Deduplicate a path list by exact string, preserving order (systemd applies
/// `strv_uniq` to the final search path).
fn dedup_paths(dirs: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    dirs.into_iter()
        .filter(|dir| seen.insert(dir.as_os_str().to_os_string()))
        .collect()
}

/// Default systemd --user unit search path (systemd.unit(5) "User Unit Search
/// Path"), highest precedence first, without `SYSTEMD_UNIT_PATH` handling.
#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
fn systemd_user_default_search_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let xdg_config = env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty());
    let xdg_runtime = env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty());
    let xdg_data = env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty());
    let home = env::var_os("HOME").filter(|v| !v.is_empty());
    let config_home = xdg_config
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|h| PathBuf::from(h).join(".config")));
    let runtime_home = xdg_runtime.map(PathBuf::from);
    let data_home = xdg_data
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|h| PathBuf::from(h).join(".local/share")));
    // Persistent/transient dbus-API configuration (highest precedence).
    if let Some(base) = &config_home {
        dirs.push(base.join("systemd/user.control"));
    }
    if let Some(base) = &runtime_home {
        dirs.push(base.join("systemd/user.control"));
        dirs.push(base.join("systemd/transient"));
        dirs.push(base.join("systemd/generator.early"));
    }
    if let Some(base) = &config_home {
        dirs.push(base.join("systemd/user"));
    }
    // $XDG_CONFIG_DIRS/systemd/user. systemd resolves the unset default to
    // `/etc` (→ `/etc/systemd/user`, already listed above), NOT `/etc/xdg` —
    // verified against `systemd-analyze --user unit-paths` on v259 and the
    // `SD_PATH_SEARCH_CONFIGURATION` default in sd-path.c (P1-E review).
    if let Some(value) = env::var_os("XDG_CONFIG_DIRS").filter(|v| !v.is_empty()) {
        for dir in env::split_paths(&value) {
            dirs.push(dir.join("systemd/user"));
        }
    }
    dirs.push(PathBuf::from("/etc/systemd/user"));
    if let Some(base) = &runtime_home {
        dirs.push(base.join("systemd/user"));
    }
    dirs.push(PathBuf::from("/run/systemd/user"));
    if let Some(base) = &runtime_home {
        dirs.push(base.join("systemd/generator"));
    }
    if let Some(base) = &data_home {
        dirs.push(base.join("systemd/user"));
    }
    // $XDG_DATA_DIRS/systemd/user (default /usr/local/share + /usr/share).
    match env::var_os("XDG_DATA_DIRS").filter(|v| !v.is_empty()) {
        Some(value) => {
            for dir in env::split_paths(&value) {
                dirs.push(dir.join("systemd/user"));
            }
        }
        None => {
            dirs.push(PathBuf::from("/usr/local/share/systemd/user"));
            dirs.push(PathBuf::from("/usr/share/systemd/user"));
        }
    }
    dirs.push(PathBuf::from("/usr/local/lib/systemd/user"));
    dirs.push(PathBuf::from("/usr/lib/systemd/user"));
    if let Some(base) = &runtime_home {
        dirs.push(base.join("systemd/generator.late"));
    }
    dirs
}

/// Read-only disclosure of the *effective* hardening of an installed systemd
/// --user unit: the base unit file (first file found in the user-manager
/// search path, systemd.unit(5)) merged with every `{unit}.d/*.conf` drop-in
/// across the whole search path (higher-precedence directories win for
/// same-named files; different-named files apply in lexicographic order —
/// mirroring systemd's merge semantics). Returns `None` when no unit file is
/// found anywhere on the search path.
#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
pub fn observe_unit_hardening(unit_path: &Path) -> Option<ServiceHardening> {
    observe_unit_hardening_in_dirs(unit_path, &systemd_user_search_dirs())
}

/// Pure core of [`observe_unit_hardening`] with an explicit search path so the
/// full user-manager merge semantics are unit-testable without touching real
/// systemd directories.
#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
fn observe_unit_hardening_in_dirs(
    unit_path: &Path,
    search_dirs: &[PathBuf],
) -> Option<ServiceHardening> {
    let unit_name = unit_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| SERVICE_UNIT_NAME.to_string());
    // The probe-reported install path is only authoritative when systemd
    // actually searches it. With `SYSTEMD_UNIT_PATH` set (replace semantics,
    // systemd.unit(5)) the default dirs — including the install dir — may not
    // be searched at all, so falling back to the installed file would
    // misreport a unit systemd never loads (P1-E review). The fallback is
    // therefore gated on the install dir being part of the effective search
    // path; the hermetic test fixture passes the fixture's own directory.
    let installed_on_search_path = unit_path
        .parent()
        .map(|parent| search_dirs.iter().any(|dir| dir == parent))
        .unwrap_or(false);
    // Base unit: the first file found in the search path (highest precedence
    // wins). A mask (empty file or symlink to /dev/null) *terminates* the
    // search — systemd.unit(5) says a masked unit is not loaded and cannot
    // be activated, so a lower-precedence real unit must not be reported as
    // the effective one. Fall back to the probe-reported path only when that
    // path is on the effective search path (see above).
    let base = search_dirs
        .iter()
        .map(|dir| dir.join(&unit_name))
        .find(|path| path.is_file() || unit_is_masked(path))
        .or_else(|| {
            installed_on_search_path
                .then(|| {
                    (unit_path.is_file() || unit_is_masked(unit_path))
                        .then(|| unit_path.to_path_buf())
                })
                .flatten()
        })?;
    if unit_is_masked(&base) {
        return Some(ServiceHardening {
            masked: true,
            summary:
                "the systemd unit is masked (empty file or symlink to /dev/null, systemd.unit(5)); \
`ownmesh service install` cannot run the daemon under it until the mask is removed"
                    .into(),
            ..ServiceHardening::default()
        });
    }
    let mut merged: Vec<(String, String)> = unit_directives(&fs::read_to_string(&base).ok()?);
    // Drop-ins: collect every `.conf` from the name-specific `{unit}.d`
    // directory, the dash-truncated prefix directories (systemd.unit(5): a
    // unit `foo-bar-baz.service` also reads `foo-bar-.service.d` and
    // `foo-.service.d`), and the type-level `service.d` directory, across
    // the whole search path. Precedence for same-named files: name-specific
    // > prefix > type-level, and within a level higher-precedence search
    // directories win. Different-named files apply in lexicographic order
    // regardless of directory (systemd.unit(5)).
    let mut dropins: Vec<(usize, usize, PathBuf)> = Vec::new(); // (level, search index, path)
    for (index, dir) in search_dirs.iter().enumerate() {
        for (level, drop_dir) in dropin_level_dirs(&unit_name, dir) {
            if let Ok(entries) = fs::read_dir(&drop_dir) {
                for entry in entries.filter_map(std::result::Result::ok) {
                    let path = entry.path();
                    if path.extension().is_some_and(|ext| ext == "conf") {
                        dropins.push((level, index, path));
                    }
                }
            }
        }
    }
    // The probe-reported path's adjacent drop-in directory is where
    // `ownmesh service install` writes and where local overrides live; it is
    // part of the effective unit only when the install dir is on the search
    // path (see `installed_on_search_path`). With `SYSTEMD_UNIT_PATH` replace
    // semantics the install dir may not be searched at all, so its adjacent
    // drop-ins must not be merged into a unit systemd loads from elsewhere
    // (P1-E review). Reading it again when it is also on the search path is
    // harmless because same-named files are deduplicated below.
    if installed_on_search_path {
        let fallback_drop = unit_path.with_file_name(format!("{unit_name}.d"));
        if let Ok(entries) = fs::read_dir(&fallback_drop) {
            for entry in entries.filter_map(std::result::Result::ok) {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "conf") {
                    dropins.push((0, search_dirs.len(), path));
                }
            }
        }
    }
    // systemd.unit(5) / systemd issue #13198: for same-named drop-in files
    // only the file at the highest precedence applies; lower-precedence
    // same-named files are ignored *entirely* (never merged). A masked
    // same-named file (symlink to /dev/null, or empty — reads as no
    // directives) still occupies its name slot: systemd.unit(5) states a
    // type-level file applies only when there are no drop-ins *or masks*
    // with that name at higher precedence. Different-named files apply in
    // lexicographic order regardless of directory. `dropins` is collected in
    // (level, search-index) precedence order, so the first occurrence of a
    // name has the highest precedence and wins; an unreadable (dangling
    // symlink) candidate is skipped and the next-precedence same-named file
    // applies (systemd skips a drop-in it cannot load).
    let mut by_name: std::collections::BTreeMap<String, Vec<(usize, usize, PathBuf)>> =
        std::collections::BTreeMap::new();
    for (level, index, conf) in dropins {
        let name = conf
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        by_name.entry(name).or_default().push((level, index, conf));
    }
    for candidates in by_name.values_mut() {
        // Candidates are already in (level, search-index) precedence order;
        // stable-sort to be explicit.
        candidates.sort_by_key(|(level, index, _)| (*level, *index));
        for (_, _, conf) in candidates {
            if let Ok(raw) = fs::read_to_string(conf) {
                merged.extend(unit_directives(&raw));
                break;
            }
        }
    }
    let value = |name: &str| {
        merged
            .iter()
            .rev()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    };
    let no_new_privileges = value("NoNewPrivileges").is_some_and(systemd_bool_true);
    // The shipped baseline requires `UMask=0077` (descriptor.rs). systemd
    // accepts any octal spelling (`0077`, `077`), so compare the parsed mode
    // — a present-but-weak UMask (e.g. `0002`) must not count as the
    // baseline being effective (P1-E review).
    let umask_set = value("UMask").is_some_and(umask_is_baseline);
    let restrict_suidsgid = value("RestrictSUIDSGID").is_some_and(systemd_bool_true);
    let restrict_realtime = value("RestrictRealtime").is_some_and(systemd_bool_true);
    let lock_personality = value("LockPersonality").is_some_and(systemd_bool_true);
    // Seccomp guards verified available in --user services (with and without
    // `PrivateUsers=yes`; see ADR 0011). `SystemCallArchitectures=native`
    // blocks non-native architecture syscalls; `RestrictNamespaces=yes`
    // blocks namespace-creation syscalls for the whole service including
    // sessions.
    let system_call_architectures =
        value("SystemCallArchitectures").is_some_and(|v| v.eq_ignore_ascii_case("native"));
    let restrict_namespaces = value("RestrictNamespaces").is_some_and(systemd_bool_true);
    // v1.2.13 baseline (ADR 0011): the shipped unit does NOT force a user
    // namespace. `PrivateUsers=yes` and the filesystem namespacing
    // directives (`ProtectSystem=`, `ProtectHome=`, `ReadWritePaths=`,
    // `PrivateTmp=`, `ProtectKernelTunables=`, `ProtectControlGroups=`,
    // `ProtectHostname=`, …) implicitly enable `PrivateUsers=` in a per-user
    // service (systemd NEWS v254; systemd.exec(5)), which maps every host
    // uid outside the namespace — host root and every other host user alike
    // — to the overflow uid 65534. OwnMesh custody validation cannot
    // distinguish a host-root-owned system directory from an attacker-owned
    // one inside that namespace, so accepting the overflow uid would let a
    // foreign-owned 0755/01777 ancestor pass and its owner could replace the
    // daemon's state directory (A5 cross-user boundary; v1.2.13 review).
    // These directives are therefore disclosed as start-breaking (the daemon
    // fails to start with `ancestor is owned by untrusted uid 65534`), never
    // counted as baseline. The individual booleans are retained for the
    // backward-compatible JSON contract.
    let private_users = value("PrivateUsers").is_some_and(systemd_bool_true);
    let protect_system_full = value("ProtectSystem")
        .is_some_and(|v| v.eq_ignore_ascii_case("full") || v.eq_ignore_ascii_case("strict"));
    let private_tmp = value("PrivateTmp").is_some_and(systemd_bool_true);
    let protect_proc = value("ProtectProc").is_some_and(|v| v.eq_ignore_ascii_case("invisible"));
    let protect_kernel_tunables = value("ProtectKernelTunables").is_some_and(systemd_bool_true);
    let protect_control_groups = value("ProtectControlGroups").is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "yes" | "true" | "on" | "1" | "private" | "strict"
        )
    });
    let protect_hostname = value("ProtectHostname").is_some_and(systemd_bool_true);
    let read_write_paths_set = value("ReadWritePaths").is_some_and(|v| !v.is_empty());
    // `CapabilityBoundingSet=` with an empty value is still a directive (and
    // a start-breaking one in a --user service), so it must be detected even
    // though `value()` filters empty values.
    let directive_present = |name: &str| {
        merged
            .iter()
            .rev()
            .any(|(n, _)| n.eq_ignore_ascii_case(name))
    };
    // Start-breaking --user directives (verified empirically on systemd v259:
    // user-service startup fails with exit status 218/CAPABILITIES even under
    // `PrivateUsers=yes`, because applying them needs capabilities the --user
    // manager does not have in the host namespace). systemd.exec(5) documents
    // that an unset `CapabilityBoundingSet=` leaves the bounding set
    // unmodified; the login session's set is inherited unchanged.
    let start_breaking_directives = directive_present("CapabilityBoundingSet")
        || directive_present("ProtectClock")
        || directive_present("ProtectKernelLogs")
        || directive_present("ProtectKernelModules");
    let capability_bounding_set = directive_present("CapabilityBoundingSet");
    // Any directive that forces a user namespace in a per-user service is
    // disclosed as start-breaking (v1.2.13 review, ADR 0011): inside the
    // namespace every host uid outside the mapping — host root and every
    // other host user alike — appears as the overflow uid 65534, so custody
    // validation cannot verify real ownership and the daemon fails to start.
    // `ProtectClock=`/`ProtectKernelLogs=`/`ProtectKernelModules=` are
    // start-breaking for a different reason and handled separately;
    // `CapabilityBoundingSet=` does not change filesystem visibility.
    let user_namespace_forcing = private_users
        || protect_system_full
        || private_tmp
        || protect_kernel_tunables
        || protect_control_groups
        || protect_hostname
        || read_write_paths_set
        || value("ProtectSystem").is_some_and(|v| !v.eq_ignore_ascii_case("no"))
        || value("ProtectHome").is_some_and(|v| !v.eq_ignore_ascii_case("no"))
        || [
            "ReadOnlyPaths",
            "InaccessiblePaths",
            "DynamicUser",
            "ProcSubset",
            "PrivateDevices",
            "PrivateNetwork",
            "BindPaths",
            "BindReadOnlyPaths",
            "MountImages",
            "TemporaryFileSystem",
            "PrivateIPC",
        ]
        .iter()
        .any(|name| directive_present(name));
    // `ProtectHome=` read-only or a `ReadOnlyPaths=` list makes the
    // user/workspace hierarchy read-only, which conflicts with registered
    // workspaces (and also forces the user namespace, disclosed above).
    let read_only_hierarchy = value("ProtectHome").is_some_and(|v| !v.eq_ignore_ascii_case("no"))
        || directive_present("ReadOnlyPaths");
    // The v1.2.13 baseline: the process-level guards plus ProtectProc=invisible,
    // with no user-namespace-forcing directive and no read-only hierarchy.
    let baseline_intact = no_new_privileges
        && umask_set
        && restrict_suidsgid
        && restrict_realtime
        && lock_personality
        && system_call_architectures
        && restrict_namespaces
        && protect_proc
        && !user_namespace_forcing
        && !read_only_hierarchy;
    let summary = hardening_summary(
        baseline_intact,
        user_namespace_forcing,
        read_only_hierarchy,
        start_breaking_directives,
    );
    Some(ServiceHardening {
        no_new_privileges,
        umask_set,
        restrict_suidsgid,
        restrict_realtime,
        lock_personality,
        system_call_architectures,
        restrict_namespaces,
        capability_bounding_set,
        user_namespace_forcing,
        read_only_hierarchy,
        private_users,
        protect_system_full,
        private_tmp,
        protect_proc,
        protect_kernel_tunables,
        protect_control_groups,
        protect_hostname,
        read_write_paths_set,
        start_breaking_directives,
        masked: false,
        summary,
    })
}

/// Human-readable hardening disclosure shared by the static and the
/// manager-effective observation paths.
#[allow(clippy::fn_params_excessive_bools)] // DTO summarizer: one bool per disclosure class
fn hardening_summary(
    baseline_intact: bool,
    user_namespace_forcing: bool,
    read_only_hierarchy: bool,
    start_breaking_directives: bool,
) -> String {
    if start_breaking_directives {
        "the effective unit sets a directive an unprivileged --user service cannot apply — \
CapabilityBoundingSet=/ProtectClock=/ProtectKernelLogs=/ProtectKernelModules= fail startup with \
exit status 218/CAPABILITIES on systemd v259 even under PrivateUsers=yes (verified empirically; \
systemd.exec(5) documents that an unset CapabilityBoundingSet= leaves the bounding set \
unmodified); re-run `ownmesh service install` to restore the supported unit"
            .to_string()
    } else if user_namespace_forcing {
        "the effective unit forces a user namespace (PrivateUsers=yes or the filesystem \
namespacing directives ProtectSystem/ProtectHome/ReadWritePaths/PrivateTmp/\
ProtectKernelTunables/ProtectControlGroups/ProtectHostname/...); inside it every host uid \
outside the namespace — host root and every other host user alike — appears as the overflow \
uid 65534, so OwnMesh custody validation cannot verify real ownership and the daemon fails to \
start with `ancestor is owned by untrusted uid 65534`; re-run `ownmesh service install` to \
restore the supported unit"
            .to_string()
    } else if !baseline_intact {
        "a local override weakened the shipped hardening (NoNewPrivileges/UMask/RestrictSUIDSGID/\
RestrictRealtime/LockPersonality/SystemCallArchitectures/RestrictNamespaces/\
ProtectProc=invisible); re-run `ownmesh service install` to restore the supported unit"
            .to_string()
    } else if read_only_hierarchy {
        "unit or a drop-in makes parts of the user/workspace hierarchy read-only (ProtectHome/\
ReadOnlyPaths), which can conflict with registered workspaces"
            .to_string()
    } else {
        "baseline: NoNewPrivileges/UMask/RestrictSUIDSGID/RestrictRealtime/LockPersonality/\
SystemCallArchitectures/RestrictNamespaces enforced; ProtectProc=invisible (no user namespace — \
custody validation stays byte-for-byte strict, see systemd.exec(5) and ADR 0011); the \
capability bounding set is left unmodified (systemd.exec(5)) because an unprivileged --user \
service cannot change it"
            .to_string()
    }
}

/// Parse `systemctl --user show -p X -p Y …` output into a name→value map.
/// Lines are `Name=value`; empty values (e.g. an unset `ReadWritePaths=`)
/// are kept as empty strings so callers can distinguish "unset" from
/// "defaulted" manager properties.
/// systemd.unit(5): a unit file that is empty (size 0) or symlinked to
/// /dev/null is *masked* — its configuration is not loaded and it cannot be
/// activated. A dangling symlink is treated as absent (not masked) so the
/// search continues to lower-precedence directories, mirroring systemd.
fn unit_is_masked(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if meta.file_type().is_symlink() {
        // Follow the link: a target that is a char device (/dev/null) or a
        // zero-length file masks the unit.
        match fs::metadata(path) {
            Ok(target) => target.len() == 0 || !target.is_file(),
            Err(_) => false, // dangling symlink: not found, not masked
        }
    } else {
        meta.len() == 0
    }
}

/// Drop-in directory names systemd searches for a unit, highest precedence
/// first (systemd.unit(5)): the name-specific `{unit}.d`, the dash-truncated
/// prefix directories (`foo-bar-baz.service` also reads `foo-bar-.service.d`
/// and `foo-.service.d`), and the type-level `service.d` for all service
/// units. Type-level files have lower precedence than name-specific and
/// prefix files.
fn dropin_level_dirs(unit_name: &str, base: &Path) -> Vec<(usize, PathBuf)> {
    let mut dirs = Vec::new();
    dirs.push((0, base.join(format!("{unit_name}.d"))));
    for prefix in dash_prefixes(unit_name) {
        dirs.push((1, base.join(format!("{prefix}.d"))));
    }
    dirs.push((2, base.join("service.d")));
    dirs
}

/// The dash-truncated prefix names systemd.unit(5) documents for drop-ins:
/// the unit type suffix is stripped, the base name is repeatedly truncated
/// after the last dash that has characters after it, and the suffix is
/// re-appended. `foo-bar-baz.service` yields `foo-bar-.service` and
/// `foo-.service`; `ownmesh-ownmeshd.service` yields `ownmesh-.service`.
fn dash_prefixes(unit_name: &str) -> Vec<String> {
    let (base, suffix) = match unit_name.rsplit_once('.') {
        Some((base, suffix)) => (base, format!(".{suffix}")),
        None => (unit_name, String::new()),
    };
    let mut out = Vec::new();
    let mut current = base.to_string();
    loop {
        let Some(pos) = current.rfind('-') else {
            break;
        };
        // A trailing dash has nothing after it to truncate at.
        if pos == current.len() - 1 {
            break;
        }
        current.truncate(pos + 1);
        out.push(format!("{current}{suffix}"));
    }
    out
}

fn parse_show_properties(stdout: &str) -> std::collections::BTreeMap<String, String> {
    let mut props = std::collections::BTreeMap::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once('=') {
            props.insert(name.trim().to_string(), value.trim().to_string());
        }
    }
    props
}

/// Read-only observation of the *manager-effective* hardening of an installed
/// systemd --user unit: `systemctl --user show` reflects the loaded unit
/// (base file + drop-ins + manager defaults, post `daemon-reload`), which is
/// what the running daemon actually executes with. Static file analysis
/// ([`observe_unit_hardening`]) still runs first so a unit that exists but is
/// not loaded (no systemd available, or never reloaded) falls back cleanly;
/// when `systemctl show` succeeds its effective values drive the booleans and
/// the summary, and static analysis is used for directive-presence facts the
/// manager does not expose reliably (e.g. `CapabilityBoundingSet=` on a unit
/// that fails to start).
// The public wrapper is called only by the Linux systemd status path. Keep it
// available to cross-platform tests without making macOS/Windows test builds
// fail their workspace-wide `-D warnings` gate.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn observe_unit_hardening_effective<R: ProcessRunner + ?Sized>(
    runner: &R,
    unit_path: &Path,
) -> Option<ServiceHardening> {
    observe_unit_hardening_effective_in_dirs(runner, unit_path, &systemd_user_search_dirs())
}

/// Pure core of [`observe_unit_hardening_effective`] with an explicit search
/// path so the full merge semantics are unit-testable without touching real
/// systemd directories.
#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
fn observe_unit_hardening_effective_in_dirs<R: ProcessRunner + ?Sized>(
    runner: &R,
    unit_path: &Path,
    search_dirs: &[PathBuf],
) -> Option<ServiceHardening> {
    let static_obs = observe_unit_hardening_in_dirs(unit_path, search_dirs)?;
    let unit_name = unit_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| SERVICE_UNIT_NAME.to_string());
    let out = runner.run(
        "systemctl",
        &[
            "--user",
            "show",
            &unit_name,
            "-p",
            "NoNewPrivileges",
            "-p",
            "UMask",
            "-p",
            "RestrictSUIDSGID",
            "-p",
            "RestrictRealtime",
            "-p",
            "LockPersonality",
            "-p",
            "SystemCallArchitectures",
            "-p",
            "RestrictNamespaces",
            "-p",
            "ProtectSystem",
            "-p",
            "ProtectHome",
            "-p",
            "PrivateTmp",
            "-p",
            "PrivateUsers",
            "-p",
            "ProtectProc",
            "-p",
            "ProtectKernelTunables",
            "-p",
            "ProtectControlGroups",
            "-p",
            "ProtectHostname",
            "-p",
            "ProcSubset",
            "-p",
            "ReadWritePaths",
            "-p",
            "ReadOnlyPaths",
            "-p",
            "InaccessiblePaths",
        ],
    );
    let Ok(out) = out else {
        return Some(static_obs);
    };
    if !out.success() {
        return Some(static_obs);
    }
    let props = parse_show_properties(&out.stdout);
    let val = |name: &str| props.get(name).map(String::as_str);
    // `systemctl show` reflects manager defaults: a user service without the
    // directive reports NoNewPrivileges=yes, UMask=<login default>, and the
    // namespacing defaults below, so "active" means non-default here — which
    // is exactly the effective hardening the running daemon has.
    let active = |name: &str, defaults: &[&str]| {
        val(name)
            .map(|value| {
                !value.is_empty() && !defaults.iter().any(|d| value.eq_ignore_ascii_case(d))
            })
            .unwrap_or(false)
    };
    let no_new_privileges = val("NoNewPrivileges").is_some_and(systemd_bool_true);
    // The shipped baseline requires `UMask=0077`; the manager default for a
    // --user service is 0002, so only the exact shipped value counts as the
    // baseline being effective. `systemctl show` normalizes the mode to
    // `%04o`, so the octal comparison accepts `0077`/`077` spellings alike.
    let umask_set = val("UMask").is_some_and(umask_is_baseline);
    let restrict_suidsgid = val("RestrictSUIDSGID").is_some_and(systemd_bool_true);
    let restrict_realtime = val("RestrictRealtime").is_some_and(systemd_bool_true);
    let lock_personality = val("LockPersonality").is_some_and(systemd_bool_true);
    // Seccomp guards: `systemctl show` reports the effective value (empty for
    // the default `SystemCallArchitectures=`; `no` for the default
    // `RestrictNamespaces=`), so only the shipped values count as effective.
    let system_call_architectures =
        val("SystemCallArchitectures").is_some_and(|value| value.eq_ignore_ascii_case("native"));
    let restrict_namespaces = val("RestrictNamespaces").is_some_and(systemd_bool_true);
    // v1.2.13 baseline (ADR 0011): the shipped unit does NOT force a user
    // namespace. The manager defaults for the userns-forcing directives are
    // `PrivateUsers=no`, `ProtectSystem=no`, `PrivateTmp=no`,
    // `ProtectProc=default`, so only non-default values count as effective
    // and are disclosed as start-breaking (see
    // [`ServiceHardening::user_namespace_forcing`]).
    let private_users = val("PrivateUsers").is_some_and(systemd_bool_true);
    let protect_system_full = val("ProtectSystem").is_some_and(|value| {
        value.eq_ignore_ascii_case("full") || value.eq_ignore_ascii_case("strict")
    });
    let private_tmp = val("PrivateTmp").is_some_and(systemd_bool_true);
    let protect_proc =
        val("ProtectProc").is_some_and(|value| value.eq_ignore_ascii_case("invisible"));
    let protect_kernel_tunables = val("ProtectKernelTunables").is_some_and(systemd_bool_true);
    let protect_control_groups = val("ProtectControlGroups").is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "yes" | "true" | "on" | "1" | "private" | "strict"
        )
    });
    let protect_hostname = val("ProtectHostname").is_some_and(systemd_bool_true);
    let read_write_paths_set = val("ReadWritePaths").is_some_and(|value| !value.is_empty());
    let unexpected_visibility = active("ProtectHome", &["no"])
        || active("ProcSubset", &["all"])
        || val("ReadOnlyPaths").is_some_and(|v| !v.is_empty())
        || val("InaccessiblePaths").is_some_and(|v| !v.is_empty());
    // Any directive that forces a user namespace in a per-user service is
    // disclosed as start-breaking (v1.2.13 review, ADR 0011): inside the
    // namespace every host uid outside the mapping — host root and every
    // other host user alike — appears as the overflow uid 65534, so custody
    // validation cannot verify real ownership and the daemon fails to start.
    let user_namespace_forcing = private_users
        || protect_system_full
        || private_tmp
        || protect_kernel_tunables
        || protect_control_groups
        || protect_hostname
        || read_write_paths_set
        || unexpected_visibility
        || static_obs.user_namespace_forcing;
    let read_only_hierarchy =
        active("ProtectHome", &["no"]) || val("ReadOnlyPaths").is_some_and(|v| !v.is_empty());
    // The v1.2.13 baseline: the process-level guards plus ProtectProc=invisible,
    // with no user-namespace-forcing directive and no read-only hierarchy.
    let baseline_intact = no_new_privileges
        && umask_set
        && restrict_suidsgid
        && restrict_realtime
        && lock_personality
        && system_call_architectures
        && restrict_namespaces
        && protect_proc
        && !user_namespace_forcing
        && !read_only_hierarchy;
    // `CapabilityBoundingSet=` / `ProtectClock=` / `ProtectKernelLogs=` /
    // `ProtectKernelModules=` make the unit fail to start in a --user service
    // (verified 218/CAPABILITIES on v259 even under PrivateUsers=yes); the
    // manager reports the values it would apply only for a unit that can
    // apply them, so the static directive-presence facts are the reliable
    // signal.
    let capability_bounding_set = static_obs.capability_bounding_set;
    let start_breaking_directives = capability_bounding_set || static_obs.start_breaking_directives;
    let summary = hardening_summary(
        baseline_intact,
        user_namespace_forcing,
        read_only_hierarchy,
        start_breaking_directives,
    );
    Some(ServiceHardening {
        no_new_privileges,
        umask_set,
        restrict_suidsgid,
        restrict_realtime,
        lock_personality,
        system_call_architectures,
        restrict_namespaces,
        capability_bounding_set,
        user_namespace_forcing,
        read_only_hierarchy,
        private_users,
        protect_system_full,
        private_tmp,
        protect_proc,
        protect_kernel_tunables,
        protect_control_groups,
        protect_hostname,
        read_write_paths_set,
        start_breaking_directives,
        masked: static_obs.masked,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::service::security::{canonicalize_executable, validate_service_path};
    use ownmesh_config::OwnMeshPaths;
    use tempfile::tempdir;

    /// Hermetic fixture observer: the fixture's own directory is the search
    /// path, so the fallback rule (the probe-reported install path must be on
    /// the effective search path, P1-E review) is satisfied and tests never
    /// depend on the CI host's real systemd user state (a machine with an
    /// installed unit would otherwise shadow the fixture).
    fn observe_fixture(unit: &Path) -> Option<ServiceHardening> {
        let search = unit
            .parent()
            .map(|parent| vec![parent.to_path_buf()])
            .unwrap_or_default();
        observe_unit_hardening_in_dirs(unit, &search)
    }

    /// The v1.2.13 shipped --user baseline (ADR 0011): the process-level
    /// seccomp guards plus `ProtectProc=invisible`, with **no** directive
    /// that forces a user namespace (PrivateUsers=yes and the filesystem
    /// namespacing directives are deliberately absent — inside the namespace
    /// every host uid outside the mapping appears as the overflow uid 65534,
    /// so custody validation cannot verify real ownership).
    const BASELINE_UNIT: &str = "[Service]\nNoNewPrivileges=true\nUMask=0077\n\
RestrictSUIDSGID=true\nRestrictRealtime=true\nLockPersonality=true\n\
SystemCallArchitectures=native\nRestrictNamespaces=yes\n\
ProtectProc=invisible\nExecStart=/bin/true\n";

    /// P1-E regression fixtures: the hardening observer must disclose the
    /// *effective* unit (base + drop-ins) read-only, so doctor can warn about
    /// local overrides instead of claiming an unmodified baseline. Each case
    /// uses a fresh directory so drop-ins cannot leak between cases.
    #[test]
    fn unit_hardening_observer_discloses_effective_directives() {
        // P1-E: the shipped baseline deliberately omits CapabilityBoundingSet=
        // (systemd.exec(5): an unset option leaves the bounding set
        // unmodified, and an unprivileged --user service cannot apply it).
        let baseline = BASELINE_UNIT;

        // 1. Baseline unit (as rendered by the fixed descriptor).
        let dir = tempdir().unwrap();
        let unit = dir.path().join("ownmesh-ownmeshd.service");
        fs::write(&unit, baseline).unwrap();
        let h = observe_fixture(&unit).expect("unit present");
        assert!(h.no_new_privileges);
        assert!(h.umask_set);
        assert!(h.restrict_suidsgid);
        assert!(h.restrict_realtime);
        assert!(h.lock_personality);
        assert!(h.system_call_architectures, "{h:?}");
        assert!(h.restrict_namespaces, "{h:?}");
        assert!(h.protect_proc, "{h:?}");
        // The v1.2.13 baseline does NOT force a user namespace: any of these
        // directives would hide real uids and make custody validation
        // unsound (v1.2.13 review, ADR 0011).
        assert!(!h.private_users, "{h:?}");
        assert!(!h.protect_system_full, "{h:?}");
        assert!(!h.private_tmp, "{h:?}");
        assert!(!h.protect_kernel_tunables, "{h:?}");
        assert!(!h.protect_control_groups, "{h:?}");
        assert!(!h.protect_hostname, "{h:?}");
        assert!(!h.read_write_paths_set, "{h:?}");
        assert!(
            !h.capability_bounding_set,
            "CapabilityBoundingSet= is not part of the shipped baseline: {h:?}"
        );
        assert!(!h.start_breaking_directives, "{h:?}");
        assert!(!h.user_namespace_forcing, "{h:?}");
        assert!(!h.read_only_hierarchy);
        assert!(!h.masked, "{h:?}");
        assert!(h.summary.contains("baseline"), "{}", h.summary);

        // 1a. A drop-in disabling one of the shipped process-level guards or
        //     ProtectProc=invisible must be disclosed as weakened — never
        //     reported as an intact baseline.
        for (name, conf) in [
            ("NoNewPrivileges", "[Service]\nNoNewPrivileges=no\n"),
            ("UMask", "[Service]\nUMask=\n"),
            ("RestrictSUIDSGID", "[Service]\nRestrictSUIDSGID=no\n"),
            ("RestrictRealtime", "[Service]\nRestrictRealtime=no\n"),
            ("LockPersonality", "[Service]\nLockPersonality=no\n"),
            (
                "SystemCallArchitectures",
                "[Service]\nSystemCallArchitectures=\n",
            ),
            ("RestrictNamespaces", "[Service]\nRestrictNamespaces=no\n"),
            ("ProtectProc", "[Service]\nProtectProc=default\n"),
        ] {
            let dir = tempdir().unwrap();
            let unit = dir.path().join("ownmesh-ownmeshd.service");
            let drop = dir.path().join("ownmesh-ownmeshd.service.d");
            fs::create_dir_all(&drop).unwrap();
            fs::write(&unit, baseline).unwrap();
            fs::write(drop.join("local.conf"), conf).unwrap();
            let h = observe_fixture(&unit).unwrap();
            assert!(
                h.summary.contains("weakened"),
                "{name} drop-in must be disclosed: {h:?}"
            );
            assert!(
                h.summary.contains("ownmesh service install"),
                "actionable remediation: {h:?}"
            );
        }

        // 1a2. A drop-in re-adding a user-namespace-forcing directive
        //     (PrivateUsers=yes or any filesystem namespacing directive) must
        //     be disclosed as start-breaking — the daemon fails to start with
        //     `ancestor is owned by untrusted uid 65534` because custody
        //     cannot verify real uids inside the namespace (v1.2.13 review,
        //     ADR 0011) — never reported as an intact baseline.
        for (name, conf) in [
            ("PrivateUsers", "[Service]\nPrivateUsers=yes\n"),
            ("ProtectSystem", "[Service]\nProtectSystem=full\n"),
            ("PrivateTmp", "[Service]\nPrivateTmp=yes\n"),
            (
                "ProtectKernelTunables",
                "[Service]\nProtectKernelTunables=yes\n",
            ),
            (
                "ProtectControlGroups",
                "[Service]\nProtectControlGroups=yes\n",
            ),
            ("ProtectHostname", "[Service]\nProtectHostname=yes\n"),
            (
                "ReadWritePaths",
                "[Service]\nReadWritePaths=\"/tmp/state\"\n",
            ),
        ] {
            let dir = tempdir().unwrap();
            let unit = dir.path().join("ownmesh-ownmeshd.service");
            let drop = dir.path().join("ownmesh-ownmeshd.service.d");
            fs::create_dir_all(&drop).unwrap();
            fs::write(&unit, baseline).unwrap();
            fs::write(drop.join("local.conf"), conf).unwrap();
            let h = observe_fixture(&unit).unwrap();
            assert!(
                h.user_namespace_forcing,
                "{name} drop-in must be disclosed as user-namespace-forcing: {h:?}"
            );
            assert!(
                h.summary.contains("user namespace"),
                "{name} drop-in summary must explain the custody consequence: {}",
                h.summary
            );
            assert!(
                h.summary.contains("ownmesh service install"),
                "actionable remediation: {h:?}"
            );
        }

        // 1b. A unit that re-adds CapabilityBoundingSet= (any value) must be
        //     disclosed as a start-breaking --user directive (an unprivileged
        //     user manager cannot apply it — startup fails with status
        //     218/CAPABILITIES even under PrivateUsers=yes on v259), not
        //     silently accepted and not mislabeled as user-namespace-forcing.
        let dir = tempdir().unwrap();
        let unit = dir.path().join("ownmesh-ownmeshd.service");
        let with_caps = "[Service]\nNoNewPrivileges=true\nUMask=0077\nRestrictSUIDSGID=true\n\
RestrictRealtime=true\nLockPersonality=true\nSystemCallArchitectures=native\nRestrictNamespaces=yes\n\
ProtectProc=invisible\nCapabilityBoundingSet=\nExecStart=/bin/true\n";
        fs::write(&unit, with_caps).unwrap();
        let h = observe_fixture(&unit).unwrap();
        assert!(h.capability_bounding_set, "{h:?}");
        assert!(h.start_breaking_directives, "{h:?}");
        assert!(
            !h.user_namespace_forcing,
            "CapabilityBoundingSet= does not force a user namespace (it fails startup instead): {h:?}"
        );
        assert!(
            h.summary.contains("ownmesh service install"),
            "{}",
            h.summary
        );

        // 1c. A unit adding ProtectClock=/ProtectKernelLogs=/ProtectKernelModules=
        //     (start-breaking on v259 even under PrivateUsers=yes) must be
        //     disclosed, not silently accepted as hardening.
        let dir = tempdir().unwrap();
        let unit = dir.path().join("ownmesh-ownmeshd.service");
        let with_clock = "[Service]\nNoNewPrivileges=true\nUMask=0077\nRestrictSUIDSGID=true\n\
RestrictRealtime=true\nLockPersonality=true\nSystemCallArchitectures=native\nRestrictNamespaces=yes\n\
ProtectProc=invisible\nProtectClock=yes\nExecStart=/bin/true\n";
        fs::write(&unit, with_clock).unwrap();
        let h = observe_fixture(&unit).unwrap();
        assert!(h.start_breaking_directives, "{h:?}");
        assert!(
            h.summary.contains("ownmesh service install"),
            "{}",
            h.summary
        );

        // 2. Legacy shipped unit (pre-fix namespacing directives) must be
        //    disclosed (ProtectHome=read-only conflicts with workspaces) even
        //    though the reconciled baseline directives are absent.
        let dir = tempdir().unwrap();
        let unit = dir.path().join("ownmesh-ownmeshd.service");
        let legacy = "[Service]\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=read-only\nPrivateTmp=true\n";
        fs::write(&unit, legacy).unwrap();
        let h = observe_fixture(&unit).unwrap();
        assert!(h.user_namespace_forcing);
        assert!(h.read_only_hierarchy);
        assert!(
            h.summary.contains("ownmesh service install"),
            "{}",
            h.summary
        );

        // 3. A local drop-in disabling a baseline guard must be disclosed.
        let dir = tempdir().unwrap();
        let unit = dir.path().join("ownmesh-ownmeshd.service");
        let drop = dir.path().join("ownmesh-ownmeshd.service.d");
        fs::create_dir_all(&drop).unwrap();
        fs::write(
            drop.join("local.conf"),
            "[Service]\nNoNewPrivileges=false\n",
        )
        .unwrap();
        fs::write(&unit, baseline).unwrap();
        let h = observe_fixture(&unit).unwrap();
        assert!(!h.no_new_privileges, "drop-in override must win: {h:?}");
        assert!(h.summary.contains("weakened"), "{}", h.summary);

        // 3a. A drop-in disabling only SystemCallArchitectures or
        //     RestrictNamespaces must also be disclosed (the seccomp guards
        //     are part of the shipped baseline, not optional extras).
        let dir = tempdir().unwrap();
        let unit = dir.path().join("ownmesh-ownmeshd.service");
        let drop = dir.path().join("ownmesh-ownmeshd.service.d");
        fs::create_dir_all(&drop).unwrap();
        fs::write(&unit, baseline).unwrap();
        fs::write(
            drop.join("local.conf"),
            "[Service]\nSystemCallArchitectures=\nRestrictNamespaces=no\n",
        )
        .unwrap();
        let h = observe_fixture(&unit).unwrap();
        assert!(
            !h.system_call_architectures,
            "drop-in clearing SystemCallArchitectures must be disclosed: {h:?}"
        );
        assert!(
            !h.restrict_namespaces,
            "drop-in disabling RestrictNamespaces must be disclosed: {h:?}"
        );
        assert!(h.summary.contains("weakened"), "{}", h.summary);

        // 3b. A drop-in disabling only RestrictSUIDSGID must also be disclosed
        //     (not just the single privilege guard).
        let dir = tempdir().unwrap();
        let unit = dir.path().join("ownmesh-ownmeshd.service");
        let drop = dir.path().join("ownmesh-ownmeshd.service.d");
        fs::create_dir_all(&drop).unwrap();
        fs::write(&unit, baseline).unwrap();
        fs::write(
            drop.join("local.conf"),
            "[Service]\nRestrictSUIDSGID=false\n",
        )
        .unwrap();
        let h = observe_fixture(&unit).unwrap();
        assert!(h.no_new_privileges);
        assert!(!h.restrict_suidsgid, "drop-in override must win: {h:?}");
        assert!(h.summary.contains("weakened"), "{}", h.summary);

        // 3c. A drop-in adding CapabilityBoundingSet= (any value) must be
        //     disclosed as a start-breaking --user directive (status
        //     218/CAPABILITIES; it does NOT force PrivateUsers=), not silently
        //     accepted.
        let dir = tempdir().unwrap();
        let unit = dir.path().join("ownmesh-ownmeshd.service");
        let drop = dir.path().join("ownmesh-ownmeshd.service.d");
        fs::create_dir_all(&drop).unwrap();
        fs::write(&unit, baseline).unwrap();
        fs::write(
            drop.join("local.conf"),
            "[Service]\nCapabilityBoundingSet=CAP_SYS_ADMIN\n",
        )
        .unwrap();
        let h = observe_fixture(&unit).unwrap();
        assert!(
            h.capability_bounding_set,
            "CapabilityBoundingSet= drop-in must be disclosed: {h:?}"
        );
        assert!(
            !h.user_namespace_forcing,
            "CapabilityBoundingSet= does not force a user namespace: {h:?}"
        );
        assert!(
            h.summary.contains("ownmesh service install"),
            "{}",
            h.summary
        );

        // 4. Drop-in re-adding namespacing must be disclosed even when the
        //    base unit is the fixed baseline.
        let dir = tempdir().unwrap();
        let unit = dir.path().join("ownmesh-ownmeshd.service");
        let drop = dir.path().join("ownmesh-ownmeshd.service.d");
        fs::create_dir_all(&drop).unwrap();
        fs::write(&unit, baseline).unwrap();
        fs::write(
            drop.join("local.conf"),
            "[Service]\nProtectHome=read-only\n",
        )
        .unwrap();
        let h = observe_fixture(&unit).unwrap();
        assert!(h.no_new_privileges);
        assert!(h.user_namespace_forcing, "drop-in added directive: {h:?}");

        // 5. Missing unit → None (read-only, no fabrication).
        assert!(observe_fixture(&tempdir().unwrap().path().join("absent.service")).is_none());

        // Comments must never count as directives.
        let dir = tempdir().unwrap();
        let unit = dir.path().join("ownmesh-ownmeshd.service");
        let commented = "# ProtectSystem=strict\n[Service]\nNoNewPrivileges=true\n";
        fs::write(&unit, commented).unwrap();
        let h = observe_fixture(&unit).unwrap();
        assert!(
            !h.user_namespace_forcing,
            "comments are not directives: {h:?}"
        );

        // 6. Directives placed in the WRONG section are ignored by systemd
        //    (with a warning) and must never count as hardening — the static
        //    observer is section-validated. A `ProtectSystem=strict` in
        //    `[Unit]` and a `NoNewPrivileges=true` in `[Install]` are both
        //    non-effective.
        let dir = tempdir().unwrap();
        let unit = dir.path().join("ownmesh-ownmeshd.service");
        let wrong_sections = "[Unit]\nProtectSystem=strict\n[Service]\nExecStart=/bin/true\n[Install]\nNoNewPrivileges=true\n";
        fs::write(&unit, wrong_sections).unwrap();
        let h = observe_fixture(&unit).unwrap();
        assert!(
            !h.user_namespace_forcing,
            "ProtectSystem= in [Unit] is ignored by systemd and must not count: {h:?}"
        );
        assert!(
            !h.no_new_privileges,
            "NoNewPrivileges= in [Install] is ignored by systemd and must not count: {h:?}"
        );
        assert!(h.summary.contains("weakened"), "{}", h.summary);
    }

    /// P1-E: the observer reads *manager-effective* properties via
    /// `systemctl --user show` when available (reflecting the loaded unit +
    /// drop-ins + manager defaults), so a drop-in weakening a guard is
    /// disclosed even if the static file analysis would miss it, and a unit
    /// without an explicit `UMask=` is disclosed as degraded (the manager
    /// default is not the shipped 0077). When `systemctl show` fails (unit
    /// not loaded / no systemd), the section-validated static analysis is
    /// the fallback. The hermetic `_in_dirs` core keeps the test independent
    /// of the CI host's real systemd user state.
    #[test]
    fn unit_hardening_observer_reads_manager_effective_properties() {
        let runner = ScriptedProcessRunner::default();
        let dir = tempdir().unwrap();
        let unit = dir.path().join("ownmesh-ownmeshd.service");
        fs::write(&unit, BASELINE_UNIT).unwrap();
        let observe = |runner: &ScriptedProcessRunner| {
            // The fixture's own directory is the search path (same rule as
            // `observe_fixture`): the probe-reported install path must be on
            // the effective search path for the fallback to apply (P1-E
            // review).
            let search = vec![dir.path().to_path_buf()];
            observe_unit_hardening_effective_in_dirs(runner, &unit, &search).expect("observed")
        };

        // Effective dump matching the shipped baseline (manager values for
        // the namespacing options are the defaults — the v1.2.13 baseline
        // deliberately does not force a user namespace): healthy.
        runner.set_show_output(
            "NoNewPrivileges=yes\nUMask=0077\nRestrictSUIDSGID=yes\nRestrictRealtime=yes\n\
LockPersonality=yes\nSystemCallArchitectures=native\nRestrictNamespaces=yes\n\
ProtectSystem=no\nProtectHome=no\nPrivateTmp=no\nPrivateUsers=no\n\
ProtectProc=invisible\nProtectKernelTunables=no\nProtectControlGroups=no\nProtectHostname=no\n\
ProcSubset=all\nReadWritePaths=\n\
ReadOnlyPaths=\nInaccessiblePaths=\n"
                .into(),
        );
        let h = observe(&runner);
        assert!(h.no_new_privileges, "{h:?}");
        assert!(h.umask_set, "{h:?}");
        assert!(h.restrict_suidsgid, "{h:?}");
        assert!(h.restrict_realtime, "{h:?}");
        assert!(h.lock_personality, "{h:?}");
        assert!(h.system_call_architectures, "{h:?}");
        assert!(h.restrict_namespaces, "{h:?}");
        assert!(h.protect_proc, "{h:?}");
        assert!(!h.private_users, "{h:?}");
        assert!(!h.protect_system_full, "{h:?}");
        assert!(!h.private_tmp, "{h:?}");
        assert!(!h.protect_kernel_tunables, "{h:?}");
        assert!(!h.protect_control_groups, "{h:?}");
        assert!(!h.protect_hostname, "{h:?}");
        assert!(!h.read_write_paths_set, "{h:?}");
        assert!(!h.user_namespace_forcing, "{h:?}");
        assert!(h.summary.contains("baseline"), "{}", h.summary);

        // Effective dump showing a drop-in cleared ProtectProc=invisible
        // while the static file still lists the baseline directive: the
        // manager-effective value is `default`, so the baseline must be
        // disclosed as weakened.
        runner.set_show_output(
            "NoNewPrivileges=yes\nUMask=0077\nRestrictSUIDSGID=yes\nRestrictRealtime=yes\n\
LockPersonality=yes\nSystemCallArchitectures=native\nRestrictNamespaces=yes\n\
ProtectSystem=no\nProtectHome=no\nPrivateTmp=no\nPrivateUsers=no\n\
ProtectProc=default\nProtectKernelTunables=no\nProtectControlGroups=no\nProtectHostname=no\n\
ProcSubset=all\nReadWritePaths=\nReadOnlyPaths=\nInaccessiblePaths=\n"
                .into(),
        );
        let h = observe(&runner);
        assert!(!h.protect_proc, "effective ProtectProc=default: {h:?}");
        assert!(h.no_new_privileges, "{h:?}");
        assert!(h.summary.contains("weakened"), "{}", h.summary);

        // Effective dump showing a drop-in cleared the shipped UMask (manager
        // default 0002): disclosed as weakened, not silently accepted.
        runner.set_show_output(
            "NoNewPrivileges=yes\nUMask=0002\nRestrictSUIDSGID=yes\nRestrictRealtime=yes\n\
LockPersonality=yes\nSystemCallArchitectures=native\nRestrictNamespaces=yes\n\
ProtectSystem=no\nProtectHome=no\nPrivateTmp=no\nPrivateUsers=no\n\
ProtectProc=invisible\nProtectKernelTunables=no\nProtectControlGroups=no\nProtectHostname=no\n\
ProcSubset=all\nReadWritePaths=\nReadOnlyPaths=\nInaccessiblePaths=\n"
                .into(),
        );
        let h = observe(&runner);
        assert!(
            !h.umask_set,
            "effective UMask is the manager default: {h:?}"
        );
        assert!(h.protect_proc, "{h:?}");
        assert!(h.summary.contains("weakened"), "{}", h.summary);

        // Effective dump showing a drop-in weakened NoNewPrivileges and the
        // manager default UMask (no explicit UMask in the effective unit):
        // the effective observation must disclose the degradation even though
        // the static file still lists the baseline directives.
        runner.set_show_output(
            "NoNewPrivileges=no\nUMask=0002\nRestrictSUIDSGID=yes\nRestrictRealtime=yes\n\
LockPersonality=yes\nSystemCallArchitectures=native\nRestrictNamespaces=yes\n\
ProtectSystem=no\nProtectHome=no\nPrivateTmp=no\nPrivateUsers=no\n\
ProtectProc=default\nProcSubset=all\nReadWritePaths=\nReadOnlyPaths=\nInaccessiblePaths=\n"
                .into(),
        );
        let h = observe(&runner);
        assert!(!h.no_new_privileges, "effective NoNewPrivileges=no: {h:?}");
        assert!(
            !h.umask_set,
            "effective UMask is the manager default: {h:?}"
        );
        assert!(h.summary.contains("weakened"), "{}", h.summary);

        // Effective dump showing the seccomp guards cleared by a drop-in
        // (manager defaults: empty SystemCallArchitectures, RestrictNamespaces
        // no): disclosed as weakened even though the static file still lists
        // the baseline directives.
        runner.set_show_output(
            "NoNewPrivileges=yes\nUMask=0077\nRestrictSUIDSGID=yes\nRestrictRealtime=yes\n\
LockPersonality=yes\nSystemCallArchitectures=\nRestrictNamespaces=no\n\
ProtectSystem=no\nProtectHome=no\nPrivateTmp=no\nPrivateUsers=no\n\
ProtectProc=default\nProcSubset=all\nReadWritePaths=\nReadOnlyPaths=\nInaccessiblePaths=\n"
                .into(),
        );
        let h = observe(&runner);
        assert!(
            !h.system_call_architectures,
            "effective SystemCallArchitectures cleared: {h:?}"
        );
        assert!(
            !h.restrict_namespaces,
            "effective RestrictNamespaces=no: {h:?}"
        );
        assert!(h.summary.contains("weakened"), "{}", h.summary);

        // Effective dump showing a user-namespace-forcing directive the
        // static files do not carry (applied via manager state): disclosed.
        runner.set_show_output(
            "NoNewPrivileges=yes\nUMask=0077\nRestrictSUIDSGID=yes\nRestrictRealtime=yes\n\
LockPersonality=yes\nSystemCallArchitectures=native\nRestrictNamespaces=yes\n\
ProtectSystem=no\nProtectHome=read-only\nPrivateTmp=no\nPrivateUsers=no\n\
ProtectProc=default\nProcSubset=all\nReadWritePaths=\nReadOnlyPaths=\nInaccessiblePaths=\n"
                .into(),
        );
        let h = observe(&runner);
        assert!(
            h.user_namespace_forcing,
            "effective ProtectHome=read-only must be disclosed: {h:?}"
        );
        assert!(h.read_only_hierarchy, "{h:?}");
        assert!(
            h.summary.contains("ownmesh service install"),
            "{}",
            h.summary
        );

        // `systemctl show` failing (unit not loaded / no systemd): clean
        // fallback to the section-validated static analysis.
        let runner_fallback = ScriptedProcessRunner::default();
        let h = observe(&runner_fallback);
        assert!(h.no_new_privileges, "static fallback: {h:?}");
        assert!(h.umask_set, "static fallback: {h:?}");
        assert!(h.system_call_architectures, "static fallback: {h:?}");
        assert!(h.restrict_namespaces, "static fallback: {h:?}");
        assert!(h.summary.contains("baseline"), "{}", h.summary);
    }

    /// P1-E: the observer must merge the *full* user-manager search path, not
    /// just the installed unit plus its adjacent drop-in directory. A drop-in
    /// in a higher-precedence search directory (e.g. `/etc/systemd/user`)
    /// must win over a same-named drop-in in a lower-precedence directory
    /// (e.g. `/usr/lib/systemd/user`), and the base unit is the first file
    /// found in precedence order.
    #[test]
    fn unit_hardening_observer_merges_full_user_search_path() {
        let high = tempdir().unwrap(); // e.g. ~/.config/systemd/user
        let low = tempdir().unwrap(); // e.g. /usr/lib/systemd/user
        let unit_name = "ownmesh-ownmeshd.service";

        // Base unit only in the low-precedence dir; the high-precedence dir
        // carries only a drop-in. The low-precedence base disables a guard the
        // high-precedence base re-enables, so precedence is observable.
        fs::write(
            low.path().join(unit_name),
            "[Service]\nNoNewPrivileges=true\nUMask=0077\nRestrictSUIDSGID=false\n\
RestrictRealtime=true\nLockPersonality=true\nSystemCallArchitectures=native\nRestrictNamespaces=yes\n\
ProtectProc=invisible\nExecStart=/bin/true\n",
        )
        .unwrap();
        let high_drop = high.path().join(format!("{unit_name}.d"));
        fs::create_dir_all(&high_drop).unwrap();
        fs::write(
            high_drop.join("10-local.conf"),
            "[Service]\nNoNewPrivileges=false\n",
        )
        .unwrap();
        let low_drop = low.path().join(format!("{unit_name}.d"));
        fs::create_dir_all(&low_drop).unwrap();
        fs::write(
            low_drop.join("10-local.conf"),
            "[Service]\nNoNewPrivileges=true\n",
        )
        .unwrap();

        let search = vec![high.path().to_path_buf(), low.path().to_path_buf()];
        let h = observe_unit_hardening_in_dirs(&low.path().join(unit_name), &search)
            .expect("unit present");
        assert!(
            !h.no_new_privileges,
            "higher-precedence drop-in must win over the lower-precedence same-named file: {h:?}"
        );
        assert!(h.summary.contains("weakened"), "{}", h.summary);

        // A base unit in the high-precedence dir wins over the low-precedence
        // one (systemd.unit(5): earlier directories override later ones). The
        // high-precedence base differs from the low-precedence one on a
        // directive the drop-ins do not touch.
        let high_unit = high.path().join(unit_name);
        fs::write(
            &high_unit,
            "[Service]\nNoNewPrivileges=true\nUMask=0077\nRestrictSUIDSGID=true\n\
RestrictRealtime=true\nLockPersonality=true\nSystemCallArchitectures=native\nRestrictNamespaces=yes\n\
PrivateUsers=yes\nProtectSystem=full\nReadWritePaths=\"/tmp/cfg\" \"/tmp/state\" \"/tmp/runtime\"\nPrivateTmp=yes\nProtectKernelTunables=yes\n\
ProtectControlGroups=yes\nProtectHostname=yes\nProtectProc=invisible\nExecStart=/bin/true\n",
        )
        .unwrap();
        let h = observe_unit_hardening_in_dirs(&low.path().join(unit_name), &search)
            .expect("unit present");
        assert!(
            h.restrict_suidsgid,
            "base unit from the higher-precedence dir must win: {h:?}"
        );
    }

    /// P1-E / systemd issue #13198: a same-named drop-in in a higher-
    /// precedence directory *replaces* the lower-precedence same-named file
    /// entirely — the lower file's directives must not leak into the merged
    /// unit. Otherwise a masking override (e.g. a lower-precedence
    /// `ProtectHome=read-only` shadowed by a higher-precedence same-named file
    /// that does not mention it) could make the effective unit appear hardened
    /// when systemd would ignore the lower file completely.
    #[test]
    fn same_named_dropin_replaces_lower_precedence_file_entirely() {
        let high = tempdir().unwrap(); // e.g. ~/.config/systemd/user
        let low = tempdir().unwrap(); // e.g. /usr/lib/systemd/user
        let unit_name = "ownmesh-ownmeshd.service";
        fs::write(low.path().join(unit_name), BASELINE_UNIT).unwrap();

        // Lower-precedence same-named drop-in sets a workspace-conflicting
        // directive; the higher-precedence same-named file does not mention
        // it. systemd ignores the lower file entirely, so the effective unit
        // has NO ProtectHome — the observer must not report it as present.
        let low_drop = low.path().join(format!("{unit_name}.d"));
        fs::create_dir_all(&low_drop).unwrap();
        fs::write(
            low_drop.join("00-mask.conf"),
            "[Service]\nProtectHome=read-only\n",
        )
        .unwrap();
        let high_drop = high.path().join(format!("{unit_name}.d"));
        fs::create_dir_all(&high_drop).unwrap();
        fs::write(
            high_drop.join("00-mask.conf"),
            "[Service]\nNoNewPrivileges=false\n",
        )
        .unwrap();

        let search = vec![high.path().to_path_buf(), low.path().to_path_buf()];
        let h = observe_unit_hardening_in_dirs(&low.path().join(unit_name), &search)
            .expect("unit present");
        assert!(
            !h.user_namespace_forcing,
            "lower-precedence same-named drop-in must be ignored entirely, not merged: {h:?}"
        );
        assert!(
            !h.read_only_hierarchy,
            "ProtectHome= from the ignored lower-precedence file must not leak: {h:?}"
        );
        assert!(
            !h.no_new_privileges,
            "higher-precedence same-named file still applies: {h:?}"
        );

        // Different-named drop-ins from both directories still merge
        // (lexicographic order), so a distinct higher-precedence file that
        // re-adds the directive is disclosed.
        fs::write(
            high_drop.join("10-other.conf"),
            "[Service]\nProtectHome=read-only\n",
        )
        .unwrap();
        let h = observe_unit_hardening_in_dirs(&low.path().join(unit_name), &search)
            .expect("unit present");
        assert!(
            h.user_namespace_forcing && h.read_only_hierarchy,
            "distinct higher-precedence drop-in must be disclosed: {h:?}"
        );
    }

    /// systemd.unit(5): drop-ins also apply from the type-level `service.d`
    /// directory (all service units) and from the dash-truncated prefix
    /// directory of the unit name, with name-specific `{unit}.d` files
    /// taking precedence. A masked (symlink to /dev/null) same-named file in
    /// a higher-precedence level blocks the lower-level file entirely.
    #[test]
    fn type_level_and_prefix_dropins_are_observed_with_precedence() {
        let dir = tempdir().unwrap();
        let unit_name = "ownmesh-ownmeshd.service";
        fs::write(dir.path().join(unit_name), BASELINE_UNIT).unwrap();
        let search = vec![dir.path().to_path_buf()];
        let observe = |dir: &tempfile::TempDir| {
            observe_unit_hardening_in_dirs(&dir.path().join(unit_name), &search).unwrap()
        };

        // Type-level `service.d/10-x.conf` applies to the unit.
        let service_d = dir.path().join("service.d");
        fs::create_dir_all(&service_d).unwrap();
        fs::write(
            service_d.join("10-x.conf"),
            "[Service]\nNoNewPrivileges=false\n",
        )
        .unwrap();
        let h = observe(&dir);
        assert!(
            !h.no_new_privileges,
            "type-level service.d drop-in must apply: {h:?}"
        );

        // Name-specific `{unit}.d` beats type-level for the same name.
        let unit_d = dir.path().join(format!("{unit_name}.d"));
        fs::create_dir_all(&unit_d).unwrap();
        fs::write(
            unit_d.join("10-x.conf"),
            "[Service]\nNoNewPrivileges=true\n",
        )
        .unwrap();
        let h = observe(&dir);
        assert!(
            h.no_new_privileges,
            "name-specific {unit_name}.d must override type-level service.d: {h:?}"
        );
        fs::remove_dir_all(&unit_d).unwrap();

        // Dash-truncated prefix directory (`ownmesh-.service.d`) applies too.
        let prefix_d = dir.path().join("ownmesh-.service.d");
        fs::create_dir_all(&prefix_d).unwrap();
        fs::write(
            prefix_d.join("20-y.conf"),
            "[Service]\nRestrictSUIDSGID=false\n",
        )
        .unwrap();
        let h = observe(&dir);
        assert!(
            !h.restrict_suidsgid,
            "dash-prefix drop-in must apply: {h:?}"
        );

        // A /dev/null-masked same-named drop-in in the type-level dir is
        // blocked by the masked name slot in the prefix dir (the mask
        // occupies the name, systemd.unit(5)), so the type-level file must
        // not apply once its name is masked.
        fs::remove_file(prefix_d.join("20-y.conf")).unwrap();
        fs::write(prefix_d.join("20-y.conf"), "").unwrap(); // empty file = mask slot
        fs::write(
            service_d.join("20-y.conf"),
            "[Service]\nRestrictSUIDSGID=false\n",
        )
        .unwrap();
        let h = observe(&dir);
        assert!(
            h.restrict_suidsgid,
            "masked same-named drop-in at higher precedence blocks the type-level file: {h:?}"
        );
    }

    /// systemd.unit(5): a masked base unit (empty file or symlink to
    /// /dev/null) terminates the search — a lower-precedence real unit must
    /// not be reported as the effective unit, and the mask itself must be
    /// disclosed, not reported as an unmodified baseline.
    #[test]
    fn masked_base_unit_is_disclosed_not_skipped() {
        let high = tempdir().unwrap();
        let low = tempdir().unwrap();
        let unit_name = "ownmesh-ownmeshd.service";
        fs::write(high.path().join(unit_name), "").unwrap(); // empty = masked
        fs::write(low.path().join(unit_name), BASELINE_UNIT).unwrap();
        let search = vec![high.path().to_path_buf(), low.path().to_path_buf()];
        let h = observe_unit_hardening_in_dirs(&low.path().join(unit_name), &search)
            .expect("masked unit present");
        assert!(
            h.masked,
            "masked high-precedence unit must be disclosed: {h:?}"
        );
        assert!(h.summary.contains("masked"), "mask summary: {}", h.summary);
        assert!(
            !h.no_new_privileges,
            "lower-precedence real unit must not be reported: {h:?}"
        );

        // Symlink to /dev/null is equally a mask. This form is Unix-only;
        // Windows has neither /dev/null nor systemd symlink-mask semantics.
        #[cfg(unix)]
        {
            let dir = tempdir().unwrap();
            let unit = dir.path().join(unit_name);
            std::os::unix::fs::symlink("/dev/null", &unit).unwrap();
            let h = observe_fixture(&unit).expect("masked unit present");
            assert!(
                h.masked,
                "symlinked /dev/null unit must be disclosed: {h:?}"
            );
        }
    }

    /// P1-E: `SYSTEMD_UNIT_PATH` is honored. When set without a trailing
    /// colon it *replaces* the default search path (systemd.unit(5)); with a
    /// trailing colon the default path is appended. The observer must see
    /// units/drop-ins in the env-var directories and must not report
    /// hardening from default directories systemd would not load.
    #[cfg(unix)]
    #[test]
    fn systemd_unit_path_env_is_honored() {
        // The pure path builder reads process env; run it with a controlled
        // environment via a helper that takes the raw value.
        let custom = tempdir().unwrap();
        let unit_name = "ownmesh-ownmeshd.service";
        fs::write(custom.path().join(unit_name), BASELINE_UNIT).unwrap();
        let custom_drop = custom.path().join(format!("{unit_name}.d"));
        fs::create_dir_all(&custom_drop).unwrap();
        fs::write(
            custom_drop.join("local.conf"),
            "[Service]\nNoNewPrivileges=false\n",
        )
        .unwrap();

        // Replace semantics: only the SYSTEMD_UNIT_PATH dirs are searched.
        let dirs = systemd_unit_path_dirs(Some(custom.path().as_os_str()));
        assert_eq!(dirs, vec![custom.path().to_path_buf()]);
        let h = observe_unit_hardening_in_dirs(&custom.path().join(unit_name), &dirs)
            .expect("unit present");
        assert!(
            !h.no_new_privileges,
            "drop-in in the SYSTEMD_UNIT_PATH dir must apply: {h:?}"
        );

        // Append semantics: trailing ':' keeps the default path after it.
        let mut raw = custom.path().as_os_str().to_os_string();
        raw.push(":");
        let dirs = systemd_unit_path_dirs(Some(&raw));
        assert_eq!(dirs.first(), Some(&custom.path().to_path_buf()));
        assert!(
            dirs.len() > 1,
            "trailing ':' must append the default search path"
        );

        // Unset → default path (no env override).
        let dirs = systemd_unit_path_dirs(None);
        assert!(!dirs.is_empty());
        assert!(
            dirs.iter().any(|d| d.ends_with("systemd/user")),
            "default path must include the user unit dirs: {dirs:?}"
        );

        // Empty components are skipped (systemd rejects `::`/leading `:`; the
        // observer skips them rather than failing the whole observation).
        // No trailing colon, so replace semantics still apply.
        let mut raw = std::ffi::OsString::from(":");
        raw.push(custom.path().as_os_str());
        let dirs = systemd_unit_path_dirs(Some(&raw));
        assert_eq!(dirs, vec![custom.path().to_path_buf()]);
    }

    /// P1-E review: with `SYSTEMD_UNIT_PATH` set (replace semantics) the
    /// default dirs — including the install dir — may not be searched at all
    /// (systemd.unit(5)). When the override path contains no OwnMesh unit, the
    /// observer must NOT fall back to the installed unit file or its adjacent
    /// drop-ins: systemd would never load them, so reporting their hardening
    /// as "effective" would misreport a unit that is not loaded. The existing
    /// test only covered an override path that *does* contain the unit; this
    /// regression covers the empty-override case.
    #[test]
    fn systemd_unit_path_replace_without_unit_does_not_fall_back_to_install_dir() {
        let custom = tempdir().unwrap();
        let install = tempdir().unwrap();
        let unit_name = "ownmesh-ownmeshd.service";
        // The installed unit (where `ownmesh service install` writes) plus a
        // local override drop-in that weakens a guard.
        fs::write(install.path().join(unit_name), BASELINE_UNIT).unwrap();
        let install_drop = install.path().join(format!("{unit_name}.d"));
        fs::create_dir_all(&install_drop).unwrap();
        fs::write(
            install_drop.join("local.conf"),
            "[Service]\nNoNewPrivileges=false\n",
        )
        .unwrap();

        // Replace semantics: only the SYSTEMD_UNIT_PATH dirs are searched, and
        // the override dir does NOT contain the unit.
        let dirs = systemd_unit_path_dirs(Some(custom.path().as_os_str()));
        assert_eq!(dirs, vec![custom.path().to_path_buf()]);
        let h = observe_unit_hardening_in_dirs(&install.path().join(unit_name), &dirs);
        assert!(
            h.is_none(),
            "installed unit outside the effective search path must not be reported: {h:?}"
        );

        // The fallback still applies when the install dir IS on the effective
        // search path (the default path, or an appended `SYSTEMD_UNIT_PATH`
        // that includes it): the installed unit and its adjacent drop-ins are
        // then the unit systemd actually loads.
        let dirs = vec![install.path().to_path_buf()];
        let h = observe_unit_hardening_in_dirs(&install.path().join(unit_name), &dirs)
            .expect("installed unit on the search path");
        assert!(
            !h.no_new_privileges,
            "adjacent drop-in must apply when the install dir is searched: {h:?}"
        );
    }

    /// P1-E review: the modeled default search path must match what the
    /// current systemd actually loads. systemd resolves the unset
    /// `$XDG_CONFIG_DIRS` default to `/etc` (→ `/etc/systemd/user`, already
    /// listed), NOT `/etc/xdg` — verified against `systemd-analyze --user
    /// unit-paths` on v259 and the `SD_PATH_SEARCH_CONFIGURATION` default in
    /// sd-path.c. A phantom `/etc/xdg/systemd/user` entry could make the
    /// observer report hardening from a unit systemd would never load.
    #[test]
    fn default_search_path_matches_systemd_analyze_unit_paths() {
        let dirs = systemd_user_default_search_dirs();
        match env::var_os("XDG_CONFIG_DIRS").filter(|v| !v.is_empty()) {
            Some(value) => {
                for dir in env::split_paths(&value) {
                    assert!(
                        dirs.iter().any(|d| d == &dir.join("systemd/user")),
                        "explicit $XDG_CONFIG_DIRS entry must be searched: {dir:?}"
                    );
                }
            }
            None => {
                assert!(
                    !dirs.iter().any(|d| d.ends_with("xdg/systemd/user")),
                    "unset $XDG_CONFIG_DIRS must not add /etc/xdg/systemd/user: {dirs:?}"
                );
            }
        }
        // The default `/etc/systemd/user` entry is always present (it is the
        // resolved default of the unset $XDG_CONFIG_DIRS case).
        assert!(
            dirs.iter()
                .any(|d| d == &PathBuf::from("/etc/systemd/user")),
            "default path must include /etc/systemd/user: {dirs:?}"
        );
    }

    /// P1-E review: the static fallback observer must require the shipped
    /// `UMask=0077` — a present-but-weak UMask (e.g. `0002`) must not count
    /// as the baseline being effective. systemd accepts any octal spelling,
    /// so `077` is the same mode as `0077`.
    #[test]
    fn static_fallback_requires_baseline_umask() {
        // Weak UMask (0002) is not the baseline.
        let dir = tempdir().unwrap();
        let unit = dir.path().join("ownmesh-ownmeshd.service");
        fs::write(
            &unit,
            "[Service]\nNoNewPrivileges=true\nUMask=0002\nRestrictSUIDSGID=true\n\
RestrictRealtime=true\nLockPersonality=true\nSystemCallArchitectures=native\n\
RestrictNamespaces=yes\nProtectProc=invisible\nExecStart=/bin/true\n",
        )
        .unwrap();
        let h = observe_fixture(&unit).expect("unit present");
        assert!(
            !h.umask_set,
            "UMask=0002 must not count as the shipped baseline: {h:?}"
        );
        assert!(h.summary.contains("weakened"), "{}", h.summary);

        // Octal spelling `077` is the same mode as `0077` and counts.
        let dir = tempdir().unwrap();
        let unit = dir.path().join("ownmesh-ownmeshd.service");
        fs::write(
            &unit,
            "[Service]\nNoNewPrivileges=true\nUMask=077\nRestrictSUIDSGID=true\n\
RestrictRealtime=true\nLockPersonality=true\nSystemCallArchitectures=native\n\
RestrictNamespaces=yes\nProtectProc=invisible\nExecStart=/bin/true\n",
        )
        .unwrap();
        let h = observe_fixture(&unit).expect("unit present");
        assert!(h.umask_set, "UMask=077 is the same mode as 0077: {h:?}");
    }

    #[test]
    fn scripted_install_uninstall_cycle() {
        let dir = tempdir().unwrap();
        let name = if cfg!(windows) {
            "ownmeshd.exe"
        } else {
            "ownmeshd"
        };
        let exe = dir.path().join(name);
        fs::write(&exe, b"x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = fs::metadata(&exe).unwrap().permissions();
            p.set_mode(0o755);
            fs::set_permissions(&exe, p).unwrap();
        }
        let om = OwnMeshPaths::for_base(dir.path().join("om"));
        om.ensure_layout().unwrap();
        let sp = ServicePaths {
            executable: canonicalize_executable(&exe).unwrap(),
            config_dir: validate_service_path(&om.config_dir, "c", true).unwrap(),
            state_dir: validate_service_path(&om.state_dir, "s", true).unwrap(),
            runtime_dir: validate_service_path(&om.runtime_dir, "r", true).unwrap(),
        };
        let runner = ScriptedProcessRunner::default();
        runner.set_root(dir.path().join("svc"));
        let mgr = ServiceManager::new(&runner);
        assert!(mgr.platform_supported());
        mgr.install(&sp).unwrap();
        assert!(mgr.probe().unwrap().installed);
        mgr.start().unwrap();
        assert_eq!(mgr.probe().unwrap().running, Some(true));
        mgr.stop().unwrap();
        assert_eq!(mgr.probe().unwrap().running, Some(false));
        mgr.uninstall().unwrap();
        assert!(!mgr.probe().unwrap().installed);
        mgr.uninstall().unwrap();
    }

    #[test]
    fn resolve_missing_exe_errors() {
        let err = resolve_ownmeshd_path(Some("/no/such/ownmeshd-xyz")).unwrap_err();
        assert!(err.contains("not found"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn headless_systemd_user_bus_is_derived_only_from_an_existing_standard_runtime() {
        let dir = tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let _bus = std::os::unix::net::UnixListener::bind(dir.path().join("bus")).unwrap();
        let mut command = Command::new("systemctl");
        configure_linux_user_bus_from(&mut command, None, None, dir.path());
        let env = command
            .get_envs()
            .filter_map(|(key, value)| value.map(|value| (key, value)))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            env.get(std::ffi::OsStr::new("XDG_RUNTIME_DIR")),
            Some(&dir.path().as_os_str())
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("DBUS_SESSION_BUS_ADDRESS"))
                .map(|value| value.to_string_lossy().into_owned()),
            Some(format!("unix:path={}", dir.path().join("bus").display()))
        );

        let missing = dir.path().join("missing");
        let mut command = Command::new("systemctl");
        configure_linux_user_bus_from(&mut command, None, None, &missing);
        assert_eq!(command.get_envs().count(), 0);
    }

    #[cfg(windows)]
    #[derive(Debug)]
    struct WindowsTaskRunner {
        tasks: Mutex<WindowsTaskSet>,
        deny_enumeration: bool,
    }

    #[cfg(windows)]
    impl ProcessRunner for WindowsTaskRunner {
        fn run(&self, _program: &str, args: &[&str]) -> Result<CommandOutput, String> {
            let mut tasks = self.tasks.lock().expect("lock");
            if args.first() == Some(&"/Query") && !args.contains(&"/TN") {
                if self.deny_enumeration {
                    return Ok(CommandOutput {
                        status: 5,
                        stdout: String::new(),
                        stderr: "access denied".into(),
                    });
                }
                let mut stdout = String::new();
                if tasks.current {
                    stdout.push_str("\"\\OwnMesh-ownmeshd\",\"N/A\",\"Ready\"\n");
                }
                if tasks.legacy {
                    stdout.push_str("\"\\OwnMesh\\ownmeshd\",\"N/A\",\"Ready\"\n");
                }
                return Ok(CommandOutput {
                    status: 0,
                    stdout,
                    stderr: String::new(),
                });
            }
            if args.first() == Some(&"/Query") {
                return Ok(CommandOutput {
                    status: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                });
            }
            if args.first() == Some(&"/Delete") {
                let task = args
                    .windows(2)
                    .find(|pair| pair[0] == "/TN")
                    .map(|pair| pair[1])
                    .unwrap_or_default();
                if task.eq_ignore_ascii_case(SERVICE_TASK_NAME) {
                    tasks.current = false;
                } else if task.eq_ignore_ascii_case(LEGACY_SERVICE_TASK_NAME) {
                    tasks.legacy = false;
                }
                return Ok(CommandOutput {
                    status: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                });
            }
            unreachable!("unexpected command: {args:?}")
        }
    }

    #[cfg(windows)]
    #[test]
    fn scheduled_task_enumeration_is_locale_independent_and_fail_closed() {
        let parsed = parse_windows_task_set(
            "\"\\OwnMesh-ownmeshd\",\"N/A\",\"Ready\"\n\"\\OwnMesh\\ownmeshd\",\"N/A\",\"Ready\"\n",
        );
        assert_eq!(
            parsed,
            WindowsTaskSet {
                current: true,
                legacy: true
            }
        );

        let denied = WindowsTaskRunner {
            tasks: Mutex::new(WindowsTaskSet::default()),
            deny_enumeration: true,
        };
        assert!(query_windows_tasks(&denied).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn uninstall_removes_current_and_legacy_scheduled_tasks() {
        let runner = WindowsTaskRunner {
            tasks: Mutex::new(WindowsTaskSet {
                current: true,
                legacy: true,
            }),
            deny_enumeration: false,
        };
        uninstall_windows(&runner).unwrap();
        assert_eq!(
            *runner.tasks.lock().expect("lock"),
            WindowsTaskSet::default()
        );
    }
}
