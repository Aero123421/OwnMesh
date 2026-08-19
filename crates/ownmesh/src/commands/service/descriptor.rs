//! OS service descriptor rendering (user-level only).

use super::security::{quote_windows_arg, systemd_escape_arg, xml_escape, ValidatedPath};

/// systemd user unit name.
pub const SERVICE_UNIT_NAME: &str = "ownmesh-ownmeshd.service";
/// macOS LaunchAgent label.
pub const SERVICE_LABEL: &str = "dev.ownmesh.ownmeshd";
/// Windows current-user Scheduled Task name. A root-level name is deliberate:
/// standard users cannot create Task Scheduler folders on a stock Windows install.
pub const SERVICE_TASK_NAME: &str = "OwnMesh-ownmeshd";
/// v1.2.3 and earlier used a task-folder path that often required elevation.
#[cfg(windows)]
pub const LEGACY_SERVICE_TASK_NAME: &str = r"OwnMesh\ownmeshd";

/// Validated paths embedded into descriptors.
#[derive(Debug, Clone)]
pub struct ServicePaths {
    pub executable: ValidatedPath,
    pub config_dir: ValidatedPath,
    pub state_dir: ValidatedPath,
    pub runtime_dir: ValidatedPath,
}

impl ServicePaths {
    fn exe_str(&self) -> String {
        self.executable.canonical.display().to_string()
    }
    fn config_str(&self) -> String {
        self.config_dir.canonical.display().to_string()
    }
    fn state_str(&self) -> String {
        self.state_dir.canonical.display().to_string()
    }
    fn runtime_str(&self) -> String {
        self.runtime_dir.canonical.display().to_string()
    }
}

/// Render a systemd --user unit.
///
/// Docs: https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html
/// User units: https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#User%20Unit%20Search%20Path
/// Sandboxing semantics: systemd.exec(5) documents that the filesystem
/// namespacing directives (`ProtectSystem=`, `ProtectHome=`, `ReadWritePaths=`,
/// `ReadOnlyPaths=`, `InaccessiblePaths=`, `PrivateTmp=`, `PrivateDevices=`,
/// `ProtectKernelTunables=`, `ProtectControlGroups=`, `ProtectClock=`,
/// `ProtectHostname=`, `BindPaths=`, `TemporaryFileSystem=`, …) are *only*
/// available for system services, or for services in per-user instances of the
/// service manager **in which case `PrivateUsers=` is implicitly enabled**
/// (systemd NEWS v254: “They now imply PrivateUsers=yes, … processes/files
/// will appear as owned by 'nobody' in the user unit”; the exact option set is
/// `exec_context_need_unprivileged_private_users()` / `exec_needs_cap_sys_admin()`
/// in systemd's src/core/execute.c, which differs across releases).
///
/// That user namespace maps **every** host uid outside the namespace — host
/// root and every other host user alike — to the overflow uid 65534 and omits
/// the root mapping in per-user instances, so OwnMesh custody validation
/// cannot distinguish a host-root-owned system directory from an
/// attacker-owned one inside it. Accepting the overflow uid would let a
/// foreign-owned 0755/01777 ancestor pass and its owner could replace the
/// daemon's state directory (A5 cross-user boundary; v1.2.13 review). The
/// shipped unit therefore does **not** force a user namespace, and custody
/// validation stays byte-for-byte strict (every state/config ancestor must be
/// owned by the daemon's uid or host root; see ADR 0011). A local drop-in
/// that re-adds `PrivateUsers=yes` or the namespacing directives fails closed
/// at startup with `ancestor is owned by untrusted uid 65534` and is
/// disclosed by `ownmesh doctor`.
///
/// Directive selection is empirical and version-qualified (verified with
/// `systemd-run --user -p …` on systemd v259): `ProtectProc=invisible`
/// (hidepid= on the unit's /proc instance) boots in a --user service without
/// forcing a user namespace (uid_map stays `0 0 4294967295`); systemd.exec(5)
/// documents it as system-only, so on versions where it is not applied it
/// degrades to a no-op, never a boot failure. `ProtectClock=`,
/// `ProtectKernelLogs=`, `ProtectKernelModules=` and any
/// `CapabilityBoundingSet=` value fail user-service startup with exit status
/// 218/CAPABILITIES on systemd v259 *even under* `PrivateUsers=yes` (verified
/// empirically; systemd's exit-status table documents 218 as “Failed to drop
/// capabilities”), so they are omitted — on other systemd versions/kernels
/// they may apply, but a unit that breaks boot on current Ubuntu cannot be
/// the shipped default. `ProtectHome=` is omitted because a read-only home
/// conflicts with the registered-workspace model.
/// `MemoryDenyWriteExecute=yes` is omitted because it breaks JIT runtimes
/// (Node/V8) that spawned sessions rely on. `RestrictNamespaces=yes` blocks
/// namespace-creation syscalls for the whole service including sessions; a
/// session that needs them (rootless podman, docker, unshare, bwrap) can be
/// enabled with a local drop-in that sets `RestrictNamespaces=no` —
/// `ownmesh doctor` discloses the effective unit.
#[must_use]
#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
pub fn render_systemd_user_unit(paths: &ServicePaths) -> String {
    let exe = systemd_escape_arg(&paths.exe_str());
    let config = systemd_escape_arg(&paths.config_str());
    let state = systemd_escape_arg(&paths.state_str());
    let runtime = systemd_escape_arg(&paths.runtime_str());
    format!(
        r#"[Unit]
Description=OwnMesh user-level device agent (ownmeshd)
Documentation=https://github.com/Aero123421/OwnMesh
After=default.target
# A fail-closed custody check must not restart every 3s forever.
StartLimitIntervalSec=30
StartLimitBurst=5

[Service]
Type=simple
ExecStart="{exe}" run
Restart=on-failure
RestartSec=3
Environment=OWNMESH_CONFIG_DIR="{config}"
Environment=OWNMESH_STATE_DIR="{state}"
Environment=OWNMESH_RUNTIME_DIR="{runtime}"
# User-level only — never elevate.
NoNewPrivileges=true
# v1.2.13 reconciled --user sandbox (ADR 0011). This is a SCOPED
# reconciliation, not a complete OS-level sandbox: the unit provides
# process-level and proc-visibility confinement only, and deliberately
# provides NO filesystem confinement (no ProtectSystem=/ProtectHome=/
# ReadWritePaths=/PrivateTmp=; no systemd workspace allow-list — filesystem
# governance is the daemon's own custody validation plus the
# registered-workspace model). systemd.exec(5) documents
# that the filesystem namespacing directives (ProtectSystem=/ProtectHome=/
# ReadWritePaths=/PrivateTmp=/ProtectKernelTunables=/ProtectControlGroups=/
# ProtectHostname=/…) are only available for system services, or for
# per-user services in which case PrivateUsers= is implicitly enabled
# (systemd NEWS v254; the exact option set is
# exec_context_need_unprivileged_private_users() /
# exec_needs_cap_sys_admin() in systemd's src/core/execute.c, and it differs
# across releases). That user namespace maps every host uid outside the
# namespace — host root and every other host user alike — to the overflow
# uid 65534, so OwnMesh custody validation cannot distinguish a
# host-root-owned system directory from an attacker-owned one inside it.
# Accepting the overflow uid would let a foreign-owned 0755/01777 ancestor
# pass and its owner could replace the daemon's state directory (A5
# cross-user boundary), so the shipped unit does NOT force a user namespace
# and custody stays byte-for-byte strict. A local drop-in that re-adds
# PrivateUsers=yes or the namespacing directives fails closed at startup
# with `ancestor is owned by untrusted uid 65534` and is disclosed by
# `ownmesh doctor`.
#
# Shipped hardening (all available in an unprivileged --user service
# without a user namespace):
#   * ProtectProc=invisible — hidepid= on the unit's /proc instance
#     (verified to boot on systemd v259; systemd.exec(5) documents it as
#     system-only, so on versions where it is not applied it degrades to a
#     no-op, never a boot failure).
#   * Process-level guards: UMask=0077, RestrictSUIDSGID=true,
#     RestrictRealtime=true, LockPersonality=true,
#     SystemCallArchitectures=native, RestrictNamespaces=yes.
#
# Version/privilege-qualified omissions (verified empirically on systemd
# v259, unprivileged --user): `ProtectClock=`, `ProtectKernelLogs=`,
# `ProtectKernelModules=` and any `CapabilityBoundingSet=` value (including
# the empty set) fail startup with exit status 218/CAPABILITIES even under
# PrivateUsers=yes, because applying them needs capabilities the --user
# manager does not have (systemd.exec(5) documents that an unset
# CapabilityBoundingSet= leaves the bounding set unmodified; the login
# session's set is inherited unchanged). `ProtectHome=` is omitted because
# a read-only home conflicts with the registered-workspace model;
# `MemoryDenyWriteExecute=yes` is omitted because it breaks JIT runtimes
# (Node/V8) that spawned sessions rely on. `RestrictNamespaces=yes` blocks
# namespace-creation syscalls for the whole service including sessions; a
# session that needs them (rootless podman, docker, unshare, bwrap) can be
# enabled with a local drop-in that sets `RestrictNamespaces=no` —
# `ownmesh doctor` discloses the effective unit.
ProtectProc=invisible
UMask=0077
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
SystemCallArchitectures=native
RestrictNamespaces=yes

[Install]
WantedBy=default.target
"#
    )
}

/// Render a macOS LaunchAgent plist.
///
/// Docs: https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html
#[must_use]
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
pub fn render_launch_agent_plist(paths: &ServicePaths) -> String {
    let exe = xml_escape(&paths.exe_str());
    let config = xml_escape(&paths.config_str());
    let state = xml_escape(&paths.state_str());
    let runtime = xml_escape(&paths.runtime_str());
    let label = xml_escape(SERVICE_LABEL);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>EnvironmentVariables</key>
  <dict>
    <key>OWNMESH_CONFIG_DIR</key>
    <string>{config}</string>
    <key>OWNMESH_STATE_DIR</key>
    <string>{state}</string>
    <key>OWNMESH_RUNTIME_DIR</key>
    <string>{runtime}</string>
  </dict>
</dict>
</plist>
"#
    )
}

/// Render a Windows Task Scheduler XML (current user, limited, logon trigger).
///
/// Docs: https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema
/// schtasks: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks
#[must_use]
#[cfg_attr(not(any(test, windows)), allow(dead_code))]
pub fn render_scheduled_task_xml(paths: &ServicePaths) -> String {
    let exe = xml_escape(&paths.exe_str());
    // Command line: quoted exe + run
    let args = xml_escape("run");
    let config = xml_escape(&paths.config_str());
    let state = xml_escape(&paths.state_str());
    let runtime = xml_escape(&paths.runtime_str());
    // Environment via cmd wrapper is avoided; Task Scheduler supports little env
    // injection safely. We pass env through a tiny wrapper command line using
    // `cmd /c set ...&&` is injection-prone — instead document that ownmeshd
    // discovers default user paths. Still embed WorkingDirectory.
    let workdir = {
        let p = paths
            .executable
            .canonical
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        xml_escape(&p)
    };
    let _ = (config, state, runtime); // reserved for future Task env support
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>OwnMesh user-level device agent (ownmeshd). Current-user only; not LocalSystem.</Description>
    <URI>\{task}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe}</Command>
      <Arguments>{args}</Arguments>
      <WorkingDirectory>{workdir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"#,
        task = SERVICE_TASK_NAME,
        exe = exe,
        args = args,
        workdir = workdir,
    )
}

/// Build the Windows `schtasks /TR` action string with safe quoting.
#[must_use]
#[cfg_attr(not(any(test, windows)), allow(dead_code))]
pub fn windows_task_run_command(paths: &ServicePaths) -> String {
    format!("{} run", quote_windows_arg(&paths.exe_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::service::security::canonicalize_executable;
    use ownmesh_config::OwnMeshPaths;
    use std::fs;
    use tempfile::tempdir;

    fn sample_paths() -> (tempfile::TempDir, ServicePaths) {
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
        let base = dir.path().join("om");
        let om = OwnMeshPaths::for_base(&base);
        om.ensure_layout().unwrap();
        let sp = ServicePaths {
            executable: canonicalize_executable(&exe).unwrap(),
            config_dir: crate::commands::service::security::validate_service_path(
                &om.config_dir,
                "config_dir",
                true,
            )
            .unwrap(),
            state_dir: crate::commands::service::security::validate_service_path(
                &om.state_dir,
                "state_dir",
                true,
            )
            .unwrap(),
            runtime_dir: crate::commands::service::security::validate_service_path(
                &om.runtime_dir,
                "runtime_dir",
                true,
            )
            .unwrap(),
        };
        (dir, sp)
    }

    #[test]
    fn systemd_unit_embeds_escaped_paths() {
        let (_dir, sp) = sample_paths();
        let unit = render_systemd_user_unit(&sp);
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("WantedBy=default.target"));
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(!unit.to_ascii_lowercase().contains("usersystem"));
        assert!(!unit.contains("User=root"));
    }

    /// v1.2.13 regression (ADR 0011 update): the shipped user unit must NOT
    /// force a user namespace. The filesystem namespacing directives
    /// (PrivateUsers=yes, ProtectSystem=full, PrivateTmp=yes,
    /// ProtectKernelTunables=yes, ProtectControlGroups=yes,
    /// ProtectHostname=yes, ReadWritePaths=, …) implicitly enable
    /// `PrivateUsers=` in a per-user service (systemd NEWS v254;
    /// systemd.exec(5)), which maps every host uid outside the namespace —
    /// host root and every other host user alike — to the overflow uid
    /// 65534. OwnMesh custody validation cannot distinguish a
    /// host-root-owned system directory from an attacker-owned one inside
    /// that namespace, so accepting the overflow uid would let a
    /// foreign-owned 0755/01777 ancestor pass and its owner could replace
    /// the daemon's state directory (A5 cross-user boundary). The unit must
    /// keep the process-level guards and ProtectProc=invisible, and must not
    /// ship any directive that forces the user namespace.
    #[test]
    fn systemd_unit_keeps_no_userns_sandbox_with_process_guards() {
        let (_dir, sp) = sample_paths();
        let unit = render_systemd_user_unit(&sp);
        // The process-level guards and ProtectProc=invisible must be present.
        for directive in [
            "ProtectProc=invisible",
            "NoNewPrivileges=true",
            "UMask=0077",
            "RestrictSUIDSGID=true",
            "RestrictRealtime=true",
            "LockPersonality=true",
            "SystemCallArchitectures=native",
            "RestrictNamespaces=yes",
            "StartLimitIntervalSec=30",
            "StartLimitBurst=5",
        ] {
            assert!(
                unit.lines().any(|line| line.trim_start() == directive),
                "unit must keep {directive}:
{unit}"
            );
        }
        // The unit must not force a user namespace: any of these directives
        // implicitly enables PrivateUsers= in a per-user service, hiding real
        // uids and making custody validation unsound (v1.2.13 review).
        for directive in [
            "PrivateUsers=",
            "ProtectSystem=",
            "ProtectHome=",
            "ReadWritePaths=",
            "ReadOnlyPaths=",
            "InaccessiblePaths=",
            "PrivateTmp=",
            "ProtectKernelTunables=",
            "ProtectControlGroups=",
            "ProtectHostname=",
            "PrivateDevices=",
            "BindPaths=",
            "TemporaryFileSystem=",
        ] {
            let present_as_directive = unit
                .lines()
                .any(|line| line.trim_start().starts_with(directive));
            assert!(
                !present_as_directive,
                "unit must not ship userns-forcing directive {directive}:
{unit}"
            );
        }
        // Version/privilege-qualified omissions: these fail a --user service
        // with 218/CAPABILITIES on systemd v259 even under PrivateUsers=yes
        // (verified empirically; systemd.exec(5) exit-status table).
        for directive in [
            "ProtectClock=",
            "ProtectKernelLogs=",
            "ProtectKernelModules=",
            "CapabilityBoundingSet=",
        ] {
            let present_as_directive = unit
                .lines()
                .any(|line| line.trim_start().starts_with(directive));
            assert!(
                !present_as_directive,
                "unit must not ship start-breaking directive {directive} on v259:
{unit}"
            );
        }
        // MemoryDenyWriteExecute= breaks JIT runtimes spawned sessions rely on.
        assert!(
            !unit
                .lines()
                .any(|line| line.trim_start().starts_with("MemoryDenyWriteExecute=")),
            "unit must not ship MemoryDenyWriteExecute=:
{unit}"
        );
        // The comment must cite systemd.exec(5) and the v259 qualification so
        // a future edit cannot silently re-introduce broken directives.
        assert!(
            unit.contains("systemd.exec(5)") && unit.contains("v259"),
            "unit comments must cite systemd.exec(5) and the empirical version:
{unit}"
        );
    }

    /// P1-E review (registered-workspace reconciliation): the shipped unit
    /// must never restrict the user/workspace hierarchy. Workspaces are
    /// dynamically registered anywhere under the user's home, so the unit
    /// must not ship `ProtectHome=`/`ReadOnlyPaths=`/`InaccessiblePaths=`/
    /// `ProtectSystem=` (all of which would also force the user namespace and
    /// break custody, see ADR 0011), and the unit comment must document that
    /// filesystem governance is the daemon's custody validation plus the
    /// registered-workspace model.
    #[test]
    fn systemd_unit_keeps_registered_workspace_model_writable() {
        let (_dir, sp) = sample_paths();
        let unit = render_systemd_user_unit(&sp);
        for directive in [
            "ProtectHome=",
            "ProtectSystem=",
            "ReadOnlyPaths=",
            "InaccessiblePaths=",
            "ReadWritePaths=",
        ] {
            let present = unit
                .lines()
                .any(|line| line.trim_start().starts_with(directive));
            assert!(
                !present,
                "unit must not confine the registered-workspace hierarchy with {directive}:\n{unit}"
            );
        }
        // The comment must state the workspace-model reconciliation so a
        // future edit cannot silently re-introduce home-restricting directives.
        assert!(
            unit.contains("registered-workspace model"),
            "unit comments must document the registered-workspace reconciliation:\n{unit}"
        );
    }

    #[test]
    fn launch_agent_is_user_agent_not_daemon() {
        let (_dir, sp) = sample_paths();
        let plist = render_launch_agent_plist(&sp);
        assert!(plist.contains(SERVICE_LABEL));
        assert!(plist.contains("RunAtLoad"));
        assert!(!plist.contains("LaunchDaemon"));
    }

    #[test]
    fn scheduled_task_is_least_privilege_logon() {
        let (_dir, sp) = sample_paths();
        let xml = render_scheduled_task_xml(&sp);
        assert!(
            !SERVICE_TASK_NAME.contains('\\'),
            "standard users cannot reliably create Task Scheduler folders"
        );
        assert!(xml.contains(r"<URI>\OwnMesh-ownmeshd</URI>"));
        assert!(xml.contains("LeastPrivilege"));
        assert!(xml.contains("LogonTrigger"));
        assert!(xml.contains("InteractiveToken"));
        // Must not *run as* LocalSystem (description may mention it negatively).
        assert!(!xml.contains("<UserId>LocalSystem</UserId>"));
        assert!(!xml.contains("HighestAvailable"));
        let tr = windows_task_run_command(&sp);
        assert!(tr.ends_with(" run"));
    }
}
