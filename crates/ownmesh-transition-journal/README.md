# ownmesh-transition-journal

Owner-only durable intent journal for sidecar controller transitions.

A record is written before the sidecar mutation, updated with the returned
binding, then cleared only after the `SessionManager` persistence succeeds.
The next daemon can enumerate an `intent`/`applied` entry and retry its
idempotent transition without inventing a second host generation.

The typed model and its validation live here (not in the daemon) so the
read-only `ownmesh doctor` observation performs *exactly* the same validation
as the daemon's loader: a journal the daemon would refuse to open is never
reported healthy by a diagnostic.

- `SessionTransitionJournal` — the daemon's owner-only persistence API
  (`open`/`begin`/`mark_applied`/`mark_terminal_applied`/`clear`/`pending`).
- `parse_and_validate` — pure, read-only full validation of a journal file
  (version, entry cap, map-key/record-id agreement, unknown-field rejection,
  invalid enums, identifier shape, epoch/expiry bounds, host-expiry coverage,
  binding invariants, phase consistency), shared with `ownmesh doctor`.
