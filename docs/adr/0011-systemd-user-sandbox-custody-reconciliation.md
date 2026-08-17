# ADR 0011: Reconcile systemd --user service sandboxing with OwnMesh custody validation

- Status: Accepted (updated for v1.2.13 review)
- Date: 2026-08-16 (updated 2026-08-17 for the v1.2.13 review and review pass 2)
- Deciders: OwnMesh runtime maintainers

## v1.2.13 review pass 2 update (daemon-side reconciliation, verified against primary docs)

The review demand "process guards and daemon custody checks do not reconcile OS-level confinement
with registered workspaces" is addressed as follows, without weakening any boundary:

- **Primary-doc verification.** The claim that every filesystem namespacing directive forces
  `PrivateUsers=yes` in a per-user service was re-verified against the current official
  documentation, not only the systemd NEWS note: the current systemd.exec(5) man page states
  these options are "only available for system services, or for services running in per-user
  instances of the service manager in which case PrivateUsers= is implicitly enabled", and the
  systemd v254 release announcement states "They now imply PrivateUsers=yes … system users will
  no longer be visible (and processes/files will appear as owned by 'nobody') in the user unit".
  There is therefore still no sound filesystem-mount confinement for an unprivileged `--user`
  service while custody stays byte-for-byte strict; the shipped unit keeps the process-level
  guards + `ProtectProc=invisible` and the registered-workspace model stays writable (the unit
  ships no `ProtectHome=`/`ProtectSystem=`/`ReadWritePaths=`/`ReadOnlyPaths=`/
  `InaccessiblePaths=`/`PrivateTmp=`, so dynamically registered workspaces under the user's home
  are never made read-only by the shipped unit — `render_systemd_user_unit` is render-tested for
  this contract).
- **Daemon-side reconciliation.** `ownmeshd` now reads `/proc/self/uid_map` at startup
  (`reconcile_user_namespace_sandbox` in `crates/ownmeshd/src/daemon.rs`). When the effective
  unit has put the daemon inside a user namespace that hides real host uids (any map other than
  the full identity `0 0 4294967295` — exactly what `PrivateUsers=yes`/the filesystem
  directives produce), the daemon logs an actionable warning before the first state access:
  custody cannot verify real ownership inside the namespace, it will fail closed with
  `ancestor is owned by untrusted uid 65534` unless every state/config ancestor is
  daemon-owned inside the namespace, and the remediation is to remove the namespacing
  directives / drop-in and re-run `ownmesh service install`. The check is diagnostic only:
  custody validation still enforces the boundary, so a drop-in that re-introduces the
  namespacing directives fails closed exactly as before. The pure predicate is unit-tested with
  synthetic uid maps (never the CI host's real map).
- **Registered-workspace model.** The unit's comment states the reconciliation explicitly
  (filesystem governance = daemon custody validation + registered-workspace model) and the
  render test `systemd_unit_keeps_registered_workspace_model_writable` pins that the unit never
  confines the user/workspace hierarchy. `ownmesh doctor` already discloses an effective unit
  that makes the user/workspace hierarchy read-only (`ProtectHome=`/`ReadOnlyPaths=`) and a
  unit that forces a user namespace, both read-only from `systemctl --user show` / the modeled
  search path.

## Context

The v1.2.12 shipped Linux systemd user unit for `ownmeshd` used the
filesystem namespacing directives `ProtectSystem=strict`,
`ProtectHome=read-only`, limited `ReadWritePaths`, and `PrivateTmp=true`. On
a normal Ubuntu user home the daemon failed to start repeatedly with:

```
prepare transition journal: ipc unauthorized: credential state ancestor is
owned by untrusted uid 65534: /home
```

systemd.exec(5) documents that the filesystem namespacing directives
(`ProtectSystem=`, `ProtectHome=`, `ReadWritePaths=`, `ReadOnlyPaths=`,
`InaccessiblePaths=`, `PrivateTmp=`, …) are only available for system
services, or for services in per-user instances of the service manager
**in which case `PrivateUsers=` is implicitly enabled** (systemd NEWS v254;
the exact option set is `exec_context_need_unprivileged_private_users()` /
`exec_needs_cap_sys_admin()` in systemd's src/core/execute.c, and it changes
across releases). That user namespace maps host-root-owned ancestors
(`/`, `/home`) to the overflow uid 65534 and omits the root mapping in
per-user instances, so OwnMesh's byte-for-byte custody validation — which
requires every state/config ancestor to be owned by the daemon's uid or host
root — fails with `ancestor is owned by untrusted uid 65534: /home`.

The v1.2.13 development cycle first reconciled this by removing the
namespacing directives entirely and keeping only the process-level guards,
with custody validation left byte-for-byte unchanged. Review rejected that
as "globally disabling hardening": the shipped unit must provide real
filesystem confinement, and the reconciliation must cover state/config/
runtime ownership and the registered-workspace model, not remove the
sandbox.

The v1.2.13 development cycle then shipped a unit that enables the sandbox
**explicitly** with `PrivateUsers=yes` plus the filesystem directives
verified to boot on systemd v259, and made custody validation
namespace-aware: the overflow uid 65534 was accepted as an ancestor owner
only inside the exact single-line self→self user-namespace shape
(`uid_map`/`gid_map` = `<euid> <euid> 1`, euid ≠ 0).

## Review finding (v1.2.13 review)

The namespace-aware acceptance is unsound. Inside a user namespace the
overflow uid 65534 is the **only** visible representation of *every* host
uid outside the mapping — host root and every other host user alike. The
daemon cannot distinguish a host-root-owned system directory (`/`, `/home`)
from an attacker-owned one. Concretely:

- A foreign-owned `01777` ancestor (e.g. an attacker-owned `/tmp`-style
  directory) passed because the sticky bit bypassed the group/other-write
  check; the *owner* of a sticky directory can still replace the daemon's
  state directory inside it.
- A foreign-owned `0755` ancestor passed because owner-write was not
  checked; the owner can write to their own directory and replace the
  daemon's state directory.

Both are reachable through path overrides (`OWNMESH_STATE_DIR=…` and
friends, `ownmesh-config/src/paths.rs`): a state directory placed under an
attacker-owned directory was accepted. This contradicts the ADR's earlier
claim that "an ancestor another host user could write is still rejected"
and weakens the documented A5 cross-user boundary. Unix custody is
explicitly not FD-pinned (`StateCustody::acquire` on Unix relies on the
owner/mode checks), so the owner/mode checks are the only defense.

There is no sound way to accept the overflow uid: any acceptance admits
attacker-owned ancestors, and rejecting owner-writable foreign ancestors
would also reject `/` and `/home` (0755, host-root-owned, reported as
65534 inside the namespace), breaking boot entirely. systemd itself advises
in man systemd.exec(5) to "not rely solely on user namespaces for
security" (systemd issue #34983 quotes this guidance).

## Second review finding (v1.2.13 review pass 2)

A follow-up review rejected the no-filesystem-confinement interim as
"globally disabling hardening": the shipped unit must provide real
filesystem confinement, and the reconciliation must cover state/config/
runtime ownership and the registered-workspace model, not remove the
sandbox. That demand is technically impossible to satisfy while custody
validation stays sound, and the impossibility is verified against the
systemd source, not assumed:

- systemd NEWS v254: "Behaviour of sandboxing options for the per-user
  service manager units has changed. They now imply PrivateUsers=yes …
  system users will no longer be visible (and processes/files will appear
  as owned by 'nobody') in the user unit."
- `exec_needs_cap_sys_admin()` in systemd's src/core/execute.c (v254:
  `exec_context_need_unprivileged_private_users()`; v259 renamed) lists
  every filesystem namespacing directive — `ProtectSystem=`,
  `ProtectHome=`, `ReadWritePaths=`, `ReadOnlyPaths=`, `InaccessiblePaths=`,
  `PrivateTmp=`, `PrivateDevices=`, `PrivateNetwork=`, `BindPaths=`,
  `BindReadOnlyPaths=`, `TemporaryFileSystem=`, `ProtectKernelTunables=`,
  `ProtectControlGroups=`, `ProtectClock=`, `ProtectHostname=`,
  `ProtectKernelLogs=`, `ProtectKernelModules=`, `MountAPIVFS=`,
  `PrivateMounts=`, `ExecPaths=`, `NoExecPaths=` — as forcing
  `PrivateUsers=yes` in a per-user service. `ProtectProc=` and
  `ProcSubset=` are **not** in that list (they need only a mount
  namespace, which an unprivileged user can create), which is why
  `ProtectProc=invisible` is shipped.
- Inside the resulting user namespace the uid_map is a single
  self→self line (`<euid> <euid> 1`); host root and every other host user
  map to the overflow uid 65534 (verified live on systemd v259). The
  daemon therefore cannot distinguish a host-root-owned ancestor from an
  attacker-owned one, and the Review finding above shows both are
  reachable via path overrides.

There is no third option: either the unit ships the filesystem
namespacing directives (forcing the user namespace and making custody
unsound), or it does not (no OS-level mount-namespace confinement). The
shipped unit chooses the sound side and keeps the maximum confinement that
works without a user namespace: `ProtectProc=invisible` (hidepid= on the
unit's /proc instance), `NoNewPrivileges=true`, `UMask=0077`,
`RestrictSUIDSGID=true`, `RestrictRealtime=true`, `LockPersonality=true`,
`SystemCallArchitectures=native`, and `RestrictNamespaces=yes`. Filesystem
governance for the daemon and its spawned sessions is the daemon's own
custody validation plus the registered-workspace model — sessions run
arbitrary user commands by design, so OS-level filesystem confinement of
the daemon would confine sessions and break the product. A future
per-session confinement mechanism (e.g. Landlock or seccomp filters
applied to spawned session processes, not to the daemon) is tracked as
roadmap work; it is out of scope for a patch release.

## Empirical facts (verified on systemd v259, unprivileged `systemd-run --user`)

All of the following were verified live with `systemd-run --user -p … sh -c '…'`:

- `PrivateUsers=yes` in a `--user` service maps the daemon's own uid/gid to
  themselves and **everything else — host root included — to the overflow
  uid 65534** (`uid_map: 1000 1000 1`, `gid_map: 1000 1000 1`). `/` and
  `/home` are reported as uid 65534 inside the namespace.
- Under `PrivateUsers=yes` the following filesystem/process directives
  **apply and boot successfully** on v259: `ProtectSystem=full`,
  `PrivateTmp=yes`, `ProtectKernelTunables=yes`, `ProtectControlGroups=yes`,
  `ProtectHostname=yes`, `ProtectProc=invisible`, `ReadOnlyPaths=`,
  `InaccessiblePaths=`, plus the process-level guards
  `NoNewPrivileges=`, `UMask=`, `RestrictSUIDSGID=`, `RestrictRealtime=`,
  `LockPersonality=`, `SystemCallArchitectures=native`,
  `RestrictNamespaces=yes`.
- The following directives **fail user-service startup with exit status
  218/CAPABILITIES even under `PrivateUsers=yes`** on v259 (systemd's
  exit-status table documents 218 as “Failed to drop capabilities, or apply
  ambient capabilities. See CapabilityBoundingSet=/AmbientCapabilities=”):
  any `CapabilityBoundingSet=` value (including the empty set),
  `ProtectClock=yes`, `ProtectKernelLogs=yes`, `ProtectKernelModules=yes`.
  This is platform/version-qualified: on other systemd versions or for
  root's user manager these may apply, but a unit that breaks boot on the
  current LTS cannot be the shipped default.
- `ProtectProc=invisible` alone (without `PrivateUsers=`) does **not**
  force a user namespace on v259 (`uid_map: 0 0 4294967295`), so it is a
  real process-visibility hardening that works even in a no-userns unit.
  systemd.exec(5) documents `ProtectProc=` as system-only; on versions
  where it is not applied in a per-user service it degrades to a no-op,
  never a boot failure.
- `PrivateUsers=identity`/`full` fail with exit status 217/USER for an
  unprivileged user manager (the per-user instance omits the root mapping,
  and mapping host root requires privileges the manager does not have), so
  host uids can never be observed from inside the namespace.

## Decision

1. **The shipped user unit does NOT force a user namespace.** It ships the
   process-level guards `NoNewPrivileges=true`, `UMask=0077`,
   `RestrictSUIDSGID=true`, `RestrictRealtime=true`, `LockPersonality=true`,
   `SystemCallArchitectures=native`, `RestrictNamespaces=yes`, plus
   `ProtectProc=invisible` (version-qualified: verified to boot on systemd
   v259; degrades to a no-op where a per-user service cannot apply it).
   This is a **scoped** reconciliation, not a complete OS-level sandbox:
   the unit provides process-level and proc-visibility confinement only and
   deliberately provides **no** filesystem confinement
   (`ProtectSystem=`, `ProtectHome=`, `ReadWritePaths=`, `ReadOnlyPaths=`,
   `InaccessiblePaths=`, `PrivateTmp=`, `ProtectKernelTunables=`,
   `ProtectControlGroups=`, `ProtectHostname=`, …) and no systemd workspace
   allow-list. A future per-session confinement mechanism (Landlock or
   seccomp applied to spawned session processes, not the daemon) is tracked
   as roadmap work; release notes and DOD state this limitation explicitly.
   `PrivateUsers=yes` and the filesystem namespacing directives are **not**
   shipped: they implicitly enable `PrivateUsers=` in a per-user service
   (systemd NEWS v254; systemd.exec(5)), which hides real uids and makes
   custody validation unsound (see Review finding). Registered workspaces
   live under the user's home and stay writable without any static
   `ReadWritePaths=` allow-list.
2. **Omitted with version/privilege-qualified rationale**: any
   `CapabilityBoundingSet=` value, `ProtectClock=`, `ProtectKernelLogs=`,
   `ProtectKernelModules=` (218/CAPABILITIES on v259 even under
   `PrivateUsers=yes`; systemd.exec(5) documents that an unset
   `CapabilityBoundingSet=` leaves the bounding set unmodified — the login
   session's set is inherited unchanged), `ProtectHome=` (a read-only home
   conflicts with the registered-workspace model), and
   `MemoryDenyWriteExecute=yes` (breaks JIT runtimes such as Node/V8 that
   spawned sessions rely on).
3. **Custody validation is byte-for-byte strict.** `ownmesh_ipc::
   validate_parent_custody` accepts only the daemon's own uid and host root
   as ancestor owners. The overflow uid 65534 is **never** accepted: inside
   a user namespace it is the only visible representation of every host uid
   outside the mapping, host root and attacker alike, so accepting it would
   let a foreign-owned 0755/01777 ancestor pass and its owner could replace
   the daemon's state directory (A5 cross-user boundary). A local drop-in
   that re-introduces `PrivateUsers=yes` or a filesystem namespacing
   directive fails closed at startup with `ancestor is owned by untrusted
   uid 65534` and is disclosed by `ownmesh doctor` (see 5).
4. **Registered-workspace writes are governed by the daemon's workspace
   model and custody attestation**, not by a systemd `ReadWritePaths=`
   allow-list (no `ProtectSystem=`/`ProtectHome=` means the user home stays
   writable, so dynamically registered workspaces are unaffected).
5. **Doctor discloses the effective hardening** read-only from the unit
   file plus drop-ins across the full user-manager search path
   (systemd.unit(5), honoring `SYSTEMD_UNIT_PATH`, type-level `service.d`
   and dash-prefix drop-in directories, same-named replacement semantics
   per systemd issue #13198, and `/dev/null`/empty masks), and reads
   **manager-effective properties** via `systemctl --user show` when
   available. The modeled search path matches `systemd-analyze --user
   unit-paths` (systemd resolves the unset `$XDG_CONFIG_DIRS` default to
   `/etc`, not `/etc/xdg`, so a phantom `/etc/xdg/systemd/user` entry is
   not searched), and the static fallback (used when `systemctl show` is
   unavailable) applies the same baseline predicate as the
   manager-effective path: a present-but-weak `UMask=` (e.g. `0002`) is
   disclosed as weakened, never counted as the shipped `0077` baseline.
   Local overrides that disable a baseline guard, re-introduce
   a start-breaking directive, or add a user-namespace-forcing directive
   are surfaced as warnings with the remediation `ownmesh service install`;
   a masked unit is disclosed explicitly. A unit that forces a user
   namespace is disclosed as start-breaking with the custody consequence
   (`ancestor is owned by untrusted uid 65534`), never silently accepted as
   hardening.

## Consequences

- The shipped user service boots on a normal Ubuntu user home **with**
  real process-level confinement (`NoNewPrivileges`, `UMask=0077`,
  seccomp guards, `RestrictNamespaces=yes`) and `ProtectProc=invisible`
  while OwnMesh custody validation remains byte-for-byte strict: every
  state/config ancestor must be owned by the daemon's uid or host root,
  and a foreign-owned ancestor (0755 or 01777) is rejected.
- The filesystem namespacing directives are not shipped because they force
  a user namespace that hides real uids; a drop-in that adds them is
  disclosed as start-breaking (the daemon fails to start with `ancestor is
  owned by untrusted uid 65534`) — never silently accepted as hardening.
- `CapabilityBoundingSet=` is not shipped and a drop-in that adds it is
  disclosed as start-breaking (218/CAPABILITIES on v259) — never silently
  accepted as hardening.
- Sessions that need namespace creation (rootless podman, docker, unshare,
  bwrap) can be enabled with a documented drop-in that sets
  `RestrictNamespaces=no`; doctor discloses the effective unit.
- No credentials or user data are logged; doctor surfaces counts/sizes of
  journals, never entry content.

## Alternatives considered

- **Keep the namespacing directives and disable custody validation.**
  Rejected: custody validation is a core security boundary; disabling it
  would be a net loss.
- **Remove all filesystem confinement, keep custody byte-for-byte (the
  v1.2.13 development interim).** Rejected by review: it "globally disables
  hardening"; the shipped unit must provide confinement. The final decision
  keeps the process-level guards and `ProtectProc=invisible`, which are
  real confinement that does not hide real uids. The second review pass
  repeated the demand for `ProtectSystem=`-style mount-namespace
  confinement; that is technically impossible without breaking custody
  (every filesystem namespacing directive forces `PrivateUsers=yes` in a
  per-user service — systemd NEWS v254 and `exec_needs_cap_sys_admin()` in
  systemd's src/core/execute.c — and inside that namespace the overflow uid
  is the only visible representation of every host uid outside the mapping,
  host root and attacker alike; see the Second review finding above).
  Per-session confinement (Landlock/seccomp applied to spawned session
  processes, not the daemon) is tracked as roadmap work.
- **`PrivateUsers=yes` with namespace-aware custody (the v1.2.13 interim).**
  Rejected by the v1.2.13 review: inside the namespace the overflow uid is
  the only visible representation of every host uid outside the mapping,
  host root and attacker alike, so accepting it lets a foreign-owned
  0755/01777 ancestor pass and its owner can replace the daemon's state
  directory (A5 cross-user boundary). There is no sound way to accept the
  overflow uid, and rejecting owner-writable foreign ancestors would also
  reject `/` and `/home` (0755, host-root-owned, reported as 65534 inside
  the namespace), breaking boot entirely.
- **`PrivateUsers=identity`/`full` with real host uids visible.**
  Rejected: the per-user instance omits the root mapping and unprivileged
  user managers cannot write an identity map (verified 217/USER on v259);
  host uids can never be observed from inside the namespace.
