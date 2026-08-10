//! Platform install/start/stop using user-level OS mechanisms only.

// Platform cfg blocks end functions with `return` so each OS branch is an expression
// without forcing a shared trailing Err that is dead on supported targets.
#![allow(clippy::needless_return)]

#[cfg(target_os = "macos")]
use super::descriptor::{render_launch_agent_plist, SERVICE_LABEL};
#[cfg(windows)]
use super::descriptor::{render_scheduled_task_xml, windows_task_run_command, SERVICE_TASK_NAME};
use super::descriptor::{render_systemd_user_unit, ServicePaths, SERVICE_UNIT_NAME};
use super::security::reject_injection;
use ownmesh_persist::write_atomically;
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
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|e| format!("spawn {program}: {e}"))?;
        Ok(CommandOutput {
            status: output.status.code().unwrap_or(1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// Scripted runner for tests: installs descriptors under a temp root and tracks state.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct ScriptedProcessRunner {
    root: Mutex<Option<PathBuf>>,
    installed: Mutex<bool>,
    running: Mutex<bool>,
}

#[cfg(test)]
impl ScriptedProcessRunner {
    pub fn set_root(&self, root: PathBuf) {
        let _ = fs::create_dir_all(&root);
        *self.root.lock().expect("lock") = Some(root);
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
            let out = self
                .runner
                .run("schtasks", &["/Run", "/TN", SERVICE_TASK_NAME])?;
            return if out.success() {
                Ok(())
            } else {
                Err(format!(
                    "schtasks /Run failed: {}{}",
                    out.stdout, out.stderr
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
            let out = self
                .runner
                .run("schtasks", &["/End", "/TN", SERVICE_TASK_NAME])?;
            // /End may fail if not running — treat as soft success when task exists.
            if out.success()
                || out.stdout.to_ascii_lowercase().contains("not running")
                || out.stderr.to_ascii_lowercase().contains("not running")
            {
                return Ok(());
            }
            return Err(format!(
                "schtasks /End failed: {}{}",
                out.stdout, out.stderr
            ));
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

    pub fn restart(&self) -> Result<(), String> {
        let _ = self.stop();
        self.start()
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
                    "schtasks create failed: {}{} | fallback: {}{}",
                    o.stdout, o.stderr, out2.stdout, out2.stderr
                ))
            }
        }
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
fn uninstall_windows<R: ProcessRunner + ?Sized>(runner: &R) -> Result<(), String> {
    let out = runner.run("schtasks", &["/Delete", "/TN", SERVICE_TASK_NAME, "/F"])?;
    if out.success()
        || out.stdout.to_ascii_lowercase().contains("cannot find")
        || out.stderr.to_ascii_lowercase().contains("cannot find")
        || out.stdout.to_ascii_lowercase().contains("not found")
        || out.stderr.to_ascii_lowercase().contains("not found")
        || out.status == 1
            && (out.stdout.to_ascii_lowercase().contains("error")
                || out.stderr.to_ascii_lowercase().contains("error"))
    {
        // Idempotent: missing task is success. Re-probe is done by caller.
        // If delete failed for other reasons, still check probe.
        let probe = probe_windows(runner)?;
        if probe.installed {
            return Err(format!(
                "schtasks delete failed: {}{}",
                out.stdout, out.stderr
            ));
        }
        return Ok(());
    }
    Ok(())
}

#[cfg(windows)]
fn probe_windows<R: ProcessRunner + ?Sized>(runner: &R) -> Result<ServiceStatusSnapshot, String> {
    let out = runner.run(
        "schtasks",
        &["/Query", "/TN", SERVICE_TASK_NAME, "/V", "/FO", "LIST"],
    )?;
    let installed = out.success();
    let lower = format!("{}{}", out.stdout, out.stderr).to_ascii_lowercase();
    let running = if !installed {
        None
    } else if lower.contains("status:") && lower.contains("running") {
        Some(true)
    } else {
        Some(false)
    };
    Ok(ServiceStatusSnapshot {
        platform: "windows".into(),
        supported: true,
        installed,
        running,
        unit_path: Some(format!("task:{SERVICE_TASK_NAME}")),
        message: if installed {
            None
        } else {
            Some("scheduled task not found".into())
        },
    })
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::service::security::{canonicalize_executable, validate_service_path};
    use ownmesh_config::OwnMeshPaths;
    use tempfile::tempdir;

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
}
