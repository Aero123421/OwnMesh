# OwnMesh v1.2.22

OwnMesh v1.2.22 closes the nine open issues from the 2026-08-24 service and
endpoint audit (#147–#155). Every one is the same class of defect: displayed
state that was not the authoritative state. A service reported started that
never became usable, an uninstall reported complete while `ownmeshd` kept
serving remote execution, an install reported idempotent while the registered
descriptor came from an older release, an endpoint accepted at configuration
time that could never be bound, and a finished session reported live forever.

Each is closed by making the check authoritative rather than by relaxing the
claim. No policy default is loosened; every change either turns a
previously-swallowed failure into a reported one, or retains state that was
previously deleted before it was safe to delete. The machine-checked contract
remains [`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Fixed

- **`service start` and `stop` no longer report success without crossing the
  daemon IPC boundary (#154, #147).** Only `restart` verified the observable
  transition. Task Scheduler `/Run` can queue an action that dies immediately,
  `/End` acknowledges before the instance is released, and a macOS LaunchAgent
  with `KeepAlive=true` is relaunched the moment `SIGTERM` lands — so all three
  could return `ok: true` with `running: null` while nothing had happened. Every
  lifecycle verb now waits for the daemon's authenticated status endpoint to
  agree with the requested state, and a transition that cannot be confirmed
  returns `OWNMESH_E_SERVICE` annotated with the service manager's own
  installed/running facts.
- **macOS `service stop` actually stops the agent (#147).** The shipped
  LaunchAgent sets `KeepAlive=true`, so signalling the process was never a stop:
  launchd relaunched it immediately. `stop` now boots the job out of the user
  domain, which both ends the process and prevents the relaunch, leaving the
  plist installed so `start` can bootstrap it again. `start` re-enables and
  bootstraps idempotently rather than assuming a loaded job.
- **Uninstall no longer reports success while the daemon is still running
  (#149, #147).** `uninstall_linux` discarded every `systemctl --user` result,
  so a failed stop could be hidden by deleting the unit file. Each `stop`,
  `disable`, and `daemon-reload` result is now checked and reported, the
  descriptor and the install record are retained until the manager confirms the
  unit inactive, and `run_uninstall` rejects `running == Some(true)`. macOS no
  longer ignores a failed `bootout` or deletes the plist before launchd confirms
  the job is unloaded.
- **A probe that proves nothing is no longer read as proof (#149, #147).**
  `systemctl is-active` exits non-zero for every state except `active`, so
  keying on the exit status let `Failed to connect to bus` pass as "not active"
  and remove the unit of a still-running manager. Liveness is now classified by
  the reported state word only, with an unrecognized or empty answer treated as
  unknown and a `deactivating` unit polled within a bound. Likewise, only an
  explicitly reported absence from `launchctl print` counts as proof a job is
  gone; a permission, domain, or spawn failure retains the descriptor and fails.
- **`service install` detects and repairs stale descriptors (#153).** Install
  compared descriptor content only on Linux and treated macOS and Windows
  registrations as current whenever the path or task name matched, so service
  fixes in newer releases never reached existing installations and manual
  corruption could not be repaired by the documented idempotent command.
  Install now compares the descriptor actually registered with the OS against a
  versioned digest persisted in `user-service.json` — the systemd unit body, the
  macOS plist, and the Windows task's structural identity including action and
  trigger cardinality and every rendered setting, since Task Scheduler reformats
  imported XML. Hand-edited, prior-version, and unreadable descriptors are
  repaired; an unreadable descriptor is drift, never idempotent success.
  Descriptor identity is deliberately independent of whether the service is
  loaded, so a deliberate `service stop` survives a later `install`.
- **The Windows Scheduled Task binds the install-time layout (#148).** The task
  renderer computed the validated config/state/runtime paths and then discarded
  them, so an autostarted daemon discovered the default `%APPDATA%` layout
  instead of the custom one used at install — splitting one installation into two
  identities, with enrollment, credentials, and the IPC endpoint on one side and
  the autostarted daemon on the other. The task now binds all three through
  typed `ownmeshd run --config-dir/--state-dir/--runtime-dir` arguments, shared
  by the XML import and the `/TR` fallback so both registration paths are
  identical, and deliberately not through an injection-prone `cmd /c set … &&`
  wrapper. Typed arguments outrank `OWNMESH_*` environment variables.
- **Distinct Windows profiles no longer share one named pipe (#151).** The
  runtime "fingerprint" was not a fingerprint: it filtered the path down to
  alphanumerics and truncated at 40 characters, so `C:\OwnMesh\profiles\a-b\run`
  and `C:\OwnMesh\profiles\ab\run` produced the same pipe by construction, and
  any two long paths sharing a prefix collided. The key is now a SHA-256 digest
  of a normalized textual path (case, separators, redundant separators, verbatim
  prefixes), computed without resolving through reparse points.
- **A long but valid runtime path no longer produces an unbindable endpoint
  (#155).** Endpoints were derived by appending a socket basename to the runtime
  directory with no check against `sockaddr_un`, so a perfectly valid
  owner-controlled directory could yield a pathname the OS cannot bind — the
  daemon failed inside `bind` and every client independently derived the same
  unusable path and reported the service offline. Endpoints are now validated
  against the platform capacity (derived from the `sockaddr_un` layout and
  compile-time asserted per target) before bind. A default endpoint that would
  overflow falls back to a deterministic short owner-only pathname that every
  producer and consumer derives identically, created `0700` and re-attested on
  every bind; an explicitly configured path that cannot be bound is rejected up
  front with the required reduction rather than deferred to a generic
  disconnected error.
- **Structured-pipe sessions publish EOF and a real exit code (#152).** The
  stdout and stderr readers exited on EOF without recording it, so
  `is_exited()` stayed false forever: a completed child was reported live,
  `system.diagnose` could miss a stale sidecar, and completed hosts consumed the
  bounded supervisor quota until TTL. Each reader now marks its stream terminal
  on every exit path including panic, the child is reaped exactly once for its
  real exit code (`128 + signal` for signal death), and completion requires child
  exit plus both stream EOFs so an early EOF on one stream cannot truncate the
  other. A forced termination waits a bounded grace for the readers to publish
  EOF themselves and only seals the streams when they are parked on pipes a
  descendant still holds — publishing completion and refusing further appends in
  one critical section, with the loss disclosed rather than implied to be a clean
  EOF. A termination that failed publishes nothing at all.
- **The portable Linux installer sees a stale daemon whose image was replaced
  (#150).** Linux appends ` (deleted)` to `/proc/<pid>/exe` once the executable's
  pathname has been unlinked or replaced while the process still maps the old
  inode — exactly the stale daemon an upgrade must recover from. Exact string
  equality missed it, so the installer replaced all five binaries, skipped
  `service restart` and the live version check, and reported success while the
  old daemon kept running. The suffix is now stripped only after the remaining
  pathname matches the normalized install-dir daemon, so matching stays
  path-based and never selects an unrelated process by name; the installed user
  unit is consulted as a second, name-independent witness.

## Compatibility

- A configured `service_socket.path` that exceeds the platform socket limit is
  now rejected at resolution time instead of being accepted and failing later
  inside `bind`. This is a configuration-validation tightening: such a path
  never worked, but the failure now names the limit and the required reduction.
- Windows named-pipe endpoints change name for every profile. An upgraded CLI
  cannot reach a daemon still running from a release that predates the digest
  key; the connect failure names the remedy (`ownmesh service restart`).
- `ownmeshd run` accepts optional `--config-dir`, `--state-dir`, and
  `--runtime-dir` arguments. They are emitted by the Windows service descriptor
  and take precedence over the `OWNMESH_*` environment variables. Omitting them
  keeps the previous discovery behavior exactly.

## Verification

Every fix ships with a regression test placed next to the behavior, and each
was verified to fail against the pre-fix code rather than assumed to. Notable
coverage: an over-limit runtime directory binds and accepts end-to-end with the
listener and client deriving the same endpoint; a writer racing a forced session
cutoff proves no bytes appear after completion is published; a Windows task that
keeps the expected first action but appends a second is drift; an install after
a deliberate stop leaves the service stopped; a bus failure specifically at
`is-active` retains the unit; and a Linux integration test starts a real daemon
from the install directory, replaces its inode so `/proc/<pid>/exe` reports
`(deleted)`, and asserts the upgrade performs both the restart and the version
check.
