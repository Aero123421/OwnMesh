# OwnMesh onboarding

This document describes the supported first-run and user-level service flow.

Machine-checked surface list: [`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Supported commands

| Command | Role |
|---|---|
| `ownmesh setup` | Create config root, control-plane URL, policy preset, privacy defaults |
| `ownmesh doctor` | Read-only diagnostics (`--json`, stable exit codes) |
| `ownmesh service install\|start\|stop\|restart\|status\|uninstall` | Current-user `ownmeshd` autostart |
| `ownmesh privileged install\|status\|uninstall` | Optional networkless root/admin broker |

The normal user service never becomes privileged. When explicitly installed,
the separate broker uses systemd (Linux), launchd (macOS), or SCM (Windows).

## Privacy defaults (setup)

`ownmesh setup` always writes:

- telemetry: **OFF** (`project`, `crash_upload`, `usage_analytics`)
- cloud file relay: **OFF** (no relay enablement surface)
- update network: **OFF** (`update.mode = "off"`)

Secrets never appear in `config.toml`, setup JSON input, logs, or doctor output.

## `ownmesh setup`

### Recommended: finish the machine in one command

Desktop (opens the owner sign-in in the browser):

```bash
ownmesh setup --control-plane-url https://<worker>.workers.dev --quickstart
```

SSH, Ubuntu Server, or another headless machine (prints a verification URL and
short code that can be approved from a phone):

```bash
ownmesh setup --control-plane-url https://<worker>.workers.dev \
  --quickstart --device-login --non-interactive --force
```

`--quickstart` is only shorthand for the existing secure sequence: write local
config and policy, OAuth login, enroll this device, then install the current-user
`ownmeshd` autostart. It does not install the optional privileged broker.

### Interactive (TTY)

```bash
ownmesh setup
```

Prompts for control-plane URL, instance id, policy preset, and language. Confirms before overwriting an existing config.

### Non-interactive / automation

```bash
ownmesh setup \
  --control-plane-url https://cp.example.workers.dev \
  --policy-preset recommended \
  --instance-id home \
  --force \
  --non-interactive

# JSON object (path or "-")
ownmesh setup --from-json setup.json --non-interactive
```

JSON shape:

```json
{
  "control_plane_url": "https://cp.example.workers.dev",
  "instance_id": "home",
  "policy_preset": "recommended",
  "lang": "en-US",
  "force": true
}
```

Fail-closed rules:

- Non-TTY (or `--non-interactive`) without `control_plane_url` → error exit
- Existing config without `--force` / confirmation → error exit
- Secret markers in JSON (`refresh_token`, `access_token`, …) → refused
- Non-loopback `http://` control-plane URLs → refused
- Control-plane URLs with userinfo, query, fragment, or control characters → refused (errors redact the URL)

Config and policy writes use a **journaled two-file transaction** under an exclusive lock file in the config directory (temp + replace, with `.bak` on replace, durable recovery journal). Concurrent setup/recovery is serialized. A policy write failure rolls back so a new config is never left paired with an old strong policy. If rollback itself fails, the journal is **preserved** and the operation fails closed.

Every production path that loads config or policy (including `ownmeshd` startup and CLI reads that could act on policy) runs recovery under that lock **before** consuming the live pair. A leftover `config_written` journal is never ignored.

### Next steps printed by setup

1. `ownmesh login`
2. `ownmesh device enroll`
3. `ownmesh service install`
4. `ownmesh doctor`

## `ownmesh doctor`

Fully **read-only**: does not create config roots, keystores, unlock files, or services. Does **not** call OS credential store `load` / keychain APIs; credential checks use non-secret metadata (e.g. encrypted blob filenames) only.

```bash
ownmesh doctor
ownmesh doctor --json
ownmesh doctor --check-network
```

Checks (structured `id` / `pass|warn|fail`):

- binary version / path / `ownmeshd` location
- config present / parse / validate / permissions
- credential **presence** only (values never shown)
- daemon local IPC reachability
- control-plane URL configuration
- control-plane `/health` **only** when `--check-network` is set **or** a control-plane URL is already configured
- policy preset validity
- privacy defaults (telemetry / relay / update network)
- user-level service install state

### Exit codes

| Outcome | Exit |
|---|---|
| healthy or warn only | `0` (Success) |
| any `fail` check | `2` (Usage/config) |

## `ownmesh service` (user-level only)

Installs **current-user** autostart for `ownmeshd`. Never creates admin/root/LocalSystem services.

| Platform | Mechanism | Unit / task |
|---|---|---|
| Windows | Task Scheduler, current user, `ONLOGON`, `LeastPrivilege` | `OwnMesh\ownmeshd` |
| macOS | LaunchAgent | `~/Library/LaunchAgents/dev.ownmesh.ownmeshd.plist` |
| Linux | systemd --user | `~/.config/systemd/user/ownmesh-ownmeshd.service` |

```bash
ownmesh service install
ownmesh service install --dry-run --json
ownmesh service install --executable /path/to/ownmeshd
ownmesh service start
ownmesh service stop
ownmesh service restart
ownmesh service status --json
ownmesh service uninstall
```

Security controls:

- canonicalize executable and config/state/runtime paths
- reject symlinks, world-writable paths, injection characters
- quote / escape descriptors (Windows CommandLineToArgvW rules, systemd escaping, XML escaping)
- atomic descriptor write
- idempotent install/uninstall
- success only after OS probe confirms state

### Official references

- Windows tasks: [Task Scheduler schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema), [schtasks](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks)
- macOS: [Creating Launchd Jobs](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- systemd user units: [systemd.unit](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)

## Rollback

| Action | Rollback |
|---|---|
| `setup` overwrite | Restore `config.toml.bak` / previous policy if present; or re-run setup with prior values |
| `service install` | `ownmesh service uninstall` |
| Wrong control-plane URL | `ownmesh setup --force --control-plane-url …` then `login` / `device enroll` again |
| Doctor findings only | No mutation — fix underlying config/service/login |

The privileged broker is separate and opt-in. Install it only when elevated
commands are required: `sudo ownmesh privileged install` on Linux/macOS or an
Administrator PowerShell on Windows. Normal OwnMesh operation remains in the
user account.

## Installer archive handling

Portable installers (`installers/ownmesh-installer.sh`, `installers/ownmesh-installer.ps1`) verify minisign → checksums, then enforce the updater archive contract **before** any member payload is written: entry-count and uncompressed-size caps, exact required binaries + declared docs only, no duplicates/symlinks/devices/traversal/unexpected members. Extraction is member-by-member into a private staging directory, then atomic install with backup/rollback.

- Shell installer requires a `tar` that supports verbose listing (`tar -tvzf`) and single-member stdout extract (`tar -xOf` / `tar -xOzf`). If listing/parsing is unavailable, install **fails closed** (no full-archive fallback).
- PowerShell installer uses `System.IO.Compression.ZipFile` only (never `Expand-Archive`).

## Out of scope (still unsupported)

- no-argument TUI handoff (`ownmesh` with no subcommand)
- `mcp serve`, profile/process/multi-instance management, and `approval watch`
- direct remote `exec --device` and `session open <device>` (use the public MCP tools)
- Windows MSI/NSIS installers / macOS packages / notarization / Authenticode
