# OwnMesh v1.2.11

OwnMesh v1.2.11 is a stable update-lifecycle release. It keeps the v1.2 product
surface, OAuth/passkey model, MCP protocol, and Control Plane storage schema
unchanged. The machine-checked contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Added

- `ownmesh update` is now the complete cross-platform upgrade command. It
  downloads and verifies the signed release, drains active sessions, stops the
  user service, replaces all five binaries, restores the service only when it
  was previously running, and verifies both CLI and daemon versions.
- `ownmesh update status` reports the bounded, redacted state of an active or
  completed update transaction. Windows continues the update in a private
  detached worker so `ownmesh.exe` does not lock itself.

## Reliability and security

- A durable apply journal binds the staging directory, backup directory, and
  SHA-256 digest of every previous binary. Interrupted swaps recover before a
  new transaction begins; corrupted backups are refused rather than restored.
- Update ownership is bound to both PID and OS process-birth identity, preventing
  a reused PID from adopting an abandoned transaction.
- If a worker stops after launching the new daemon but before committing the
  transaction, recovery first quiesces that daemon, restores the old tree, and
  verifies the previously running service.
- Windows replacement retries only bounded sharing/image-lock errors. The
  verified PowerShell installer stops only known Scheduled Tasks and processes
  whose executable path exactly matches the install directory.
- Linux headless service commands derive `XDG_RUNTIME_DIR` and the DBus address
  only from an existing, owner-only `/run/user/<uid>` runtime and owned Unix
  socket. They never enable lingering or create a bus.
- Explicit update remains opt-in. Telemetry, relay, background update checks,
  and automatic network activity remain disabled by default.

## Compatibility and migration

- No D1 migration is required.
- Existing OAuth clients, passkeys, refresh tokens, enrolled devices,
  workspaces, policies, sessions, transfers, and ChatGPT connectors remain
  compatible.
- Homebrew-managed installations continue to use `brew upgrade ownmesh`.

## Upgrade

Existing releases may run the verified one-line installer once to obtain this
release. From v1.2.11 onward, normal portable upgrades are simply:

```text
ownmesh update
```

Use `ownmesh update status` to inspect a detached Windows update. After upgrade,
run `ownmesh doctor --check-network` when a network readiness check is desired.
