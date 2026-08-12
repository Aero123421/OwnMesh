# OwnMesh onboarding

This document covers the supported v1.2.2 first-run, ChatGPT connection, and
user-level service flow. The machine-checked command contract is
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Install

Linux or macOS:

```bash
curl -fsSL https://github.com/Aero123421/OwnMesh/releases/latest/download/ownmesh-installer.sh | sh
```

Windows PowerShell:

```powershell
$p="$env:TEMP\ownmesh-installer.ps1"; Invoke-WebRequest https://github.com/Aero123421/OwnMesh/releases/latest/download/ownmesh-installer.ps1 -OutFile $p; powershell -NoProfile -ExecutionPolicy Bypass -File $p
```

Both installers verify the mandatory minisign signature and SHA-256 checksum
before installing. They extract into private staging with entry/size ceilings,
an exact allowlist, and rejection of traversal, links, devices, and duplicate
members. For a high-assurance bootstrap, download and inspect the installer and
verify it against `SHA256SUMS`/`SHA256SUMS.minisig` before execution.

## Recommended first run

`<worker>` below is the URL printed by the guided deploy in
[Deploy the user-owned control plane](#deploy-the-user-owned-control-plane).
Run that section first — every command here needs its URL, and the guided
deploy prints the exact `ownmesh setup` line to paste.

Desktop (opens the owner sign-in in the browser):

```bash
ownmesh setup --control-plane-url https://<worker>.workers.dev --quickstart
```

SSH, Ubuntu Server, or another headless machine (prints a verification URL and
short code that can be approved on a phone or another computer):

```bash
ownmesh setup --control-plane-url https://<worker>.workers.dev \
  --quickstart --device-login --non-interactive --force
```

`--quickstart` performs the secure sequence already available as individual
commands: write local config and policy, complete OAuth login, enroll this
device, and install current-user `ownmeshd` autostart. It never installs the
optional privileged broker.

Verify the resulting machine without changing it:

```bash
ownmesh doctor --json
```

## What setup stores

`ownmesh setup` writes non-secret configuration and policy only. OAuth and
device credentials are stored in the operating-system credential store.

Privacy defaults are:

- telemetry: **OFF** (`project`, `crash_upload`, `usage_analytics`)
- cloud file relay: **OFF**
- update network: **OFF** (`update.mode = "off"`)

Secrets are rejected from setup JSON and never appear in `config.toml`, logs, or
doctor output.

### Interactive and automation modes

```bash
# Interactive TTY
ownmesh setup

# Non-interactive
ownmesh setup \
  --control-plane-url https://cp.example.workers.dev \
  --policy-preset recommended \
  --instance-id home \
  --force \
  --non-interactive

# JSON object from a file or stdin ("-")
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

Setup fails closed when a non-interactive run lacks a control-plane URL, an
existing config would be replaced without confirmation/`--force`, secret fields
appear in JSON, or the URL is unsafe. Non-loopback HTTP, URL userinfo, query,
fragment, and control characters are rejected; error messages redact the URL.

Config and policy are committed as a journaled, locked two-file transaction.
Every production reader performs recovery before consuming the live pair. If a
write or rollback cannot be completed safely, the journal is preserved and the
operation fails instead of exposing a mismatched config/policy pair.

## Deploy the user-owned control plane

From a repository clone:

```bash
cd packages/control-plane
corepack enable
pnpm install --frozen-lockfile
pnpm run deploy:guided
```

The guided deployment creates or reuses D1, applies migrations, deploys the
Worker and Durable Object, provisions required secrets, and prints the owner
login and MCP URLs. Re-running it does not silently rotate existing secrets.
See [`deploy-cloudflare.md`](./deploy-cloudflare.md) for account prerequisites.

## Connect ChatGPT

1. Add the printed `https://<worker>/mcp` URL as a custom MCP connector in
   ChatGPT and select OAuth.
2. ChatGPT dynamically registers its public client and starts authorization
   code + PKCE.
3. OwnMesh shows the owner consent page. Sign in with the registered passkey.
4. OwnMesh returns only to the exact ChatGPT callback registered for that
   transaction and issues a short-lived access token plus a rotating refresh
   token.
5. ChatGPT uses the MCP URL until access is revoked. It refreshes access without
   asking for the passkey on every normal tool call.

The passkey protects owner identity; it is not copied to ChatGPT. A sensitive
approval or admin mutation requests a fresh passkey assertion bound to that
exact operation. A long-lived browser session alone is insufficient. See
[`chatgpt-connection.md`](./chatgpt-connection.md) for connector fields and
recovery details.

## Day-to-day command areas

| Area | Examples |
|---|---|
| Machine health | `ownmesh status`, `ownmesh doctor --json` |
| Device metadata | `device list/show/rename/labels/rotate-key/revoke` |
| Remote work | `exec --device … --idempotency-key …`, `session open <device> --idempotency-key …` |
| AI CLI profiles | `profile scan/list/show/login/test/start/resume` |
| Approvals | `approval list/show/watch/approve/deny` |
| Policy/admin | `policy show/validate/explain/preset/rule`, `lockdown`, `unlock`, `tokens revoke` |
| Transfer | `transfer plan/send/list/status/cancel` |
| Local MCP bridge | `mcp serve --stdio` |

Remote mutation keys are caller-selected and mandatory so a retry cannot create
a second operation. A remote target that is unavailable fails as remote; it is
never executed on the machine running the CLI.

Device labels are replaced by the supplied bounded label set. Rename and label
updates are owner-scoped and reject revoked devices. Transfer paths are
workspace-relative; no overwrite/force mode exists.

`ownmesh mcp serve --stdio` speaks bounded JSONL on stdin/stdout and forwards to
the configured authenticated MCP issuer. Protocol replies are the only stdout
content, so editor/agent integrations can parse the stream safely.

## Fresh-passkey admin flow

Approval decisions, policy changes, unlock, and token revocation are security
mutations. They use typed requests rather than a generic local RPC escape hatch:

1. OwnMesh validates and records the exact requested action.
2. The browser approval page requires a fresh passkey assertion for that action.
3. The control plane delivers a decision bound to the operation ID, payload
   hash, owner/tenant, and expiry.
4. The device validates the decision and executes the recorded mutation once.

A forged same-user local socket request, stale browser cookie, replayed decision,
different payload, or expired operation fails closed. Denial has no mutation
side effect.

## `ownmesh doctor`

Doctor is fully read-only: it does not create config roots, keystores, unlock
files, or services and does not load credential values from keychain APIs.

```bash
ownmesh doctor
ownmesh doctor --json
ownmesh doctor --check-network   # probes the control plane; failure exits non-zero
ownmesh doctor --offline         # never touches the network
```

It checks binary/config/service state, non-secret credential presence, daemon
IPC reachability, policy/privacy defaults, and the configured control plane.

The network is contacted **only** with `--check-network`. Earlier releases also
probed whenever a control-plane URL happened to be configured, which made the
flag a no-op in practice and meant an offline laptop got a non-zero exit from a
read-only diagnostic. A control plane that cannot be reached is now reported as
a warning rather than a failure, because it is not a fault in the machine being
inspected. Healthy/warn-only returns `0`; any fail check returns `2`.

## User-level service

`ownmesh service` manages only current-user `ownmeshd` autostart:

| Platform | Mechanism | Unit / task |
|---|---|---|
| Windows | Task Scheduler, current user, `ONLOGON`, `LeastPrivilege` | `OwnMesh\ownmeshd` |
| macOS | LaunchAgent | `~/Library/LaunchAgents/dev.ownmesh.ownmeshd.plist` |
| Linux | systemd --user | `~/.config/systemd/user/ownmesh-ownmeshd.service` |

```bash
ownmesh service install
ownmesh service install --dry-run --json
ownmesh service start
ownmesh service stop
ownmesh service restart
ownmesh service status --json
ownmesh service uninstall
```

Paths are canonicalized; unsafe links, writable locations, and descriptor
injection are rejected. Descriptor writes are atomic and success is reported
only after an OS probe confirms the state.

## Optional privileged broker

Install the separate, networkless broker only when privileged commands are
needed:

```bash
sudo ownmesh privileged install
ownmesh privileged status
```

Linux uses root systemd, macOS uses a root LaunchDaemon and
audit-token-authenticated Unix socket, and Windows uses a LocalSystem SCM service
with a SID-bound protected Named Pipe. `ownmeshd`, enrollment, configuration, and
device keys remain in the normal user account.

The lifecycle implementation exists on all three OS families. Linux has a
native root receipt; macOS/Windows native release receipts and the complete
public MCP-to-broker E8 receipt remain separate open evidence.

## Rollback

| Action | Rollback |
|---|---|
| Setup overwrite | Restore `config.toml.bak`/previous policy, or rerun setup with prior values and `--force` |
| User service | `ownmesh service uninstall` |
| Privileged broker | Run `ownmesh privileged uninstall` with administrator/root authority |
| Wrong control-plane URL | Rerun setup with `--force`, then login/enroll again |
| Failed update apply | Client restores the staged backup automatically |
| Doctor findings | No rollback required; doctor performs no mutation |

## Distribution scope

v1.2.2 supports signed portable archives and the verified shell/PowerShell
one-line installers. Windows MSI/NSIS, native/universal macOS packages,
Authenticode, and Apple notarization are outside this release's distribution
contract.
