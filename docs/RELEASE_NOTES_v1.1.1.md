# OwnMesh v1.1.1 — CI and OAuth correctness repair

v1.1.1 is a **CI and OAuth correctness/security repair** release on top of v1.1.0. It does not add product surfaces. The immutable `v1.1.0` tag is unchanged; this train fixes verified Linux/macOS Clippy and Windows test failures that blocked the v1.1.0 publish path, plus a verified consent-expiry route-boundary issue found during release review.

## Scope

- No new CLI commands, IPC methods, or distribution features.
- No Dependabot dependency merges.
- Security posture of owner-only DACL / reparse / non-regular rejection is retained (not relaxed).
- CLI surface contract is unchanged from v1.1.0: **32 explicit unsupported CLI surfaces** from the authoritative Rust registry plus 7 additional hard-error unsupported surfaces (**39 total**), machine-recorded in [`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## CI repairs

### ownmesh-config — transaction lock `OpenOptions`

Linux/macOS `cargo clippy -D warnings` failed on `clippy::suspicious_open_options`: the config+policy transaction lock opened with `create(true)` without an explicit truncate/append choice.

**Fix:** select crash-safe lock semantics explicitly — `create(true)` + `truncate(false)` on every platform. The lock node may be created if missing; existing lock contents are never wiped (mutual exclusion is the OS lock on the open handle). Covered by a regression test that seeds lock-file bytes and asserts they survive acquire/release.

### ownmesh-ipc — Windows registry custody identity/ownership

Windows `cargo test` rejected GitHub Actions Temp directories whose path form uses the 8.3 account segment `RUNNER~1`, and more generally failed when elevated tokens default new-object owner to `BUILTIN\Administrators` while attestation compared `TokenUser`.

**Fix:**

- Attest pinned-handle identity via **volume serial + file index** (handle-based), not lossy path-string comparison across short/long/`\\?\` aliases.
- Create and restrict state objects with an explicit SDDL **owner** (`O:{user-sid}`) plus protected owner-only DACL; `restrict_owner_only` applies owner + DACL through `SetNamedSecurityInfoW` using SID material from the process token (not path/user-name strings).
- Owner-only DACL, reparse rejection, and regular-file checks are unchanged and still fail closed.
- Regressions: short/long path alias open succeeds; a file owned by a different principal is rejected.

### OAuth consent expiration boundary

The consent transaction's five-minute lifetime is now captured at the Worker route boundary on GET receipt, before asynchronous form parsing, authentication, bootstrap, hashing, or persistence work. The timestamp is held in a request-identity keyed internal map; callers cannot supply an arbitrary clock or timestamp. A Worker-level delayed-`AUTH_PROVIDER` regression proves that the delay cannot extend expiry.

## Compatibility

- Behavior matches v1.1.0 except for the CI-blocking correctness fixes above.
- Consumers should treat v1.1.1 as the first green publish candidate for the 1.1 onboarding/distribution train when release automation is re-run against this tree (without moving `v1.1.0`).

## See also

- [`docs/RELEASE_NOTES_v1.1.0.md`](./RELEASE_NOTES_v1.1.0.md) — product scope for the 1.1 train
- [`CHANGELOG.md`](../CHANGELOG.md)
