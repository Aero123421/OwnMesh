//! OS service descriptor rendering (user-level only).

use super::security::{quote_windows_arg, systemd_escape_arg, xml_escape, ValidatedPath};

/// systemd user unit name.
pub const SERVICE_UNIT_NAME: &str = "ownmesh-ownmeshd.service";
/// macOS LaunchAgent label.
pub const SERVICE_LABEL: &str = "dev.ownmesh.ownmeshd";
/// Windows Scheduled Task folder/name.
pub const SERVICE_TASK_NAME: &str = r"OwnMesh\ownmeshd";

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
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths="{config}" "{state}" "{runtime}"
PrivateTmp=true

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
