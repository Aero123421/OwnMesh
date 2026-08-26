# OwnMesh v1.2.21

OwnMesh v1.2.21 closes all seven open issues from the 2026-08-24 audit: three
availability/honesty bugs in the Agent transport and journal (#140, #141,
#142), three Linux disclosure gaps (#143, #144, #145), and the last roadmap
protocol gap — incremental workspace registry refresh (#146). No policy
default is loosened; every disclosure names its constraint and the documented
operator escape hatch. The machine-checked contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Fixed

- **A blackholed IPv6 address can no longer park a reconnect forever (#140).**
  The Agent and transfer WebSocket connects dialed only the resolver's first
  answer with no connect timeout, so on a dual-stack LAN whose IPv6 route did
  not reach Cloudflare, `ownmeshd` sat in `SYN-SENT` indefinitely while IPv4
  to the same issuer worked — ChatGPT stayed `device_offline` until an operator
  restart. Connects are now bounded (`CONNECT_TIMEOUT`, 15 s) and race every
  resolved address RFC 8305-style: candidates alternate address families after
  a 300 ms head start, the first established connection wins, a hung connect is
  classified as `connect_timeout` in the existing structured logs, and it is
  retried on the normal backoff path (ready still resets the backoff;
  shutdown still aborts instantly).
- **Finished failures no longer strand their idempotency key forever (#142).**
  A remote operation whose execution returned a definitive error after the
  journal reserve left the caller's key as a durable `in_progress` marker:
  retries were refused with CONFLICT, doctor warned about an uncertain
  in-flight mutation, while the transport had already recorded a terminal
  failed result. Terminal outcomes now reconcile the marker into a compact
  failed receipt — from `gate_and_run`, and at the transport for review,
  approval, and remote session-mutation receipts. Reconciliation only rewrites
  that operation's own marker (`operation_id` must match); completed receipts
  and unknown states stay untouched, and a crash between reserve and terminal
  outcome keeps the exact-once marker exactly as [ADR
  0010](adr/0010-bounded-op-journal-retention.md) requires. Retries now replay
  the stored failure instead of rerunning or refusing eternally.

## Added

- **Doctor sees what ChatGPT sees: live Agent-route presence (#141).**
  `ownmesh doctor --check-network` could pass while ChatGPT reported the
  device offline because doctor never observed the Agent WebSocket. The daemon
  now keeps a route-presence channel fed by the transport (Online once the
  authenticated ready handshake completes, Offline on every attempt start,
  Disabled when remote routing is off), exposed via the new credentialed
  `daemon.route_status` IPC method (allowed during lockdown and
  journal-degraded reads). Doctor gains a `daemon.agent_route` row that fails
  the report when the daemon is up but its route is not connected; older
  daemons without the method omit the row instead of guessing.
  `system.diagnose` gains the additive `agent_route` check id and an
  `agent_route_offline` overall value; the Control Plane folds both into its
  normalized diagnosis while old Agents stay valid.
- **Incremental workspace registry refresh (#146, ADR 0014).** A device-local
  `workspace_add`/`update`/`remove` previously reached the Control Plane only
  on the next reconnect, leaving brand-new workspaces unusable over MCP
  despite correct local state. Ready agents now publish a full registry
  snapshot in one `workspace.registry` message whenever the device registry
  changes, acknowledged by `workspace.registry.ack` after the Control Plane
  persists it through the existing `syncDeviceWorkspaces` path. Activation
  stays fail-closed on observed generations; handshakes remain authoritative
  fallbacks; old Agents and old Control Planes ignore the message safely. The
  payload contract ships as
  [`spec-bundle/schemas/workspace-registry.schema.json`](../spec-bundle/schemas/workspace-registry.schema.json)
  validated in both languages.

## Disclosed

- **PATH resolution scope (#145).** Bare-name resolution searches the service
  PATH plus a fixed set of user-local directories (`~/.local/bin`,
  Cargo, Nix, npm-global, NVM node versions); anything outside failed with a
  generic not-found while working fine in an interactive shell. Resolve
  failures in `command.run`, `session.open`, and the session host now append
  the bounded list of directories actually searched (home collapsed to `~`)
  and state plainly that shell startup files are never sourced. Doctor's
  profile-discovery listing uses the same home-collapsed labels.
- **RestrictNamespaces availability impact (#144).** Containers, rootless
  podman, `unshare`, and similar tools create Linux namespaces, which the
  shipped systemd `--user` unit blocks (`RestrictNamespaces=yes`, ADR 0011).
  Their spawn failures surfaced as opaque OS errors while doctor showed a
  green hardening pass. EPERM-class spawn errors (structured commands, raw
  shells, PTY sessions) now name the directive and the local drop-in escape
  hatch, and the `service.hardening` pass row itself discloses the namespace
  restriction. The default stays fail-closed; nothing enables namespaces
  automatically.
- **Linux session lifetime vs lingering (#143).** The user service lives only
  as long as the OS login session, so a GUI logout silently ended the ChatGPT
  route. Doctor warns when `Linger=no` (metadata-only observation via
  `loginctl`; never a keychain read, never auto-enabled), passes when enabled,
  and the TUI connector modal plus
  [`docs/chatgpt-connection.md`](chatgpt-connection.md)/[`docs/onboarding.md`](onboarding.md)
  document the caveat and the optional operator step
  (`loginctl enable-linger $USER`), including the locked-keyring note for
  unattended boots.

## Protocol

- Additive device→control-plane message `workspace.registry` /
  `workspace.registry.ack` ([ADR
  0014](adr/0014-agent-initiated-workspace-registry-refresh.md)). No existing
  message changed shape; no D1 migration is required.

## Verification

- New regression tests cover: family-interleaved dialing, fallback past a
  blackholed candidate, bounded connect timeout and its log category;
  terminal-failure reconciliation (unit + end-to-end retry-replays-failure);
  offline-route failing doctor, legacy-daemon omission; linger warn/pass rows;
  namespace-disclosure pass row; searched-directory error text; workspace
  registry refresh end-to-end (DO+D1 persistence without reconnect),
  rejection taxonomy, schema validation in Rust and TypeScript, and live-loop
  publication on change.
- Quality gates: `cargo fmt --check`, `cargo clippy -D warnings` (pedantic),
  `cargo build/test --workspace --locked`, `pnpm -r test/typecheck/lint`,
  and `python scripts/check_release_quality.py`.

## Known open items (unchanged)

- macOS/Windows native broker lifecycle receipts and the full public
  MCP → agent → broker receipt remain open evidence (W-E8-RECEIPTS).
- Automated external ChatGPT exercise remains manual-compatibility only
  (W-E10-AUTO).
- Authenticode, Apple notarization, MSI/NSIS, and native macOS packages are
  not part of this release train.
