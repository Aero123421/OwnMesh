# OwnMesh v1.1.1 — CI, Clippy, OAuth, and audit repair

v1.1.1 is a **CI / Clippy / OAuth / JS-audit correctness and security repair** release on top of v1.1.0. It does not add product surfaces. The immutable `v1.1.0` tag is unchanged; this train fixes verified Linux/macOS Clippy and Windows test failures that blocked the v1.1.0 publish path, a verified consent-expiry route-boundary issue found during release review, and high-severity transitive vulnerabilities under the control-plane `wrangler` 3.x devDependency graph.

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

### ownmesh-logs / ownmesh-broker — Unix Clippy under Rust 1.92 `-D warnings`

Linux/macOS `cargo clippy --workspace --all-targets --locked -- -D warnings` failed on cfg-skewed dead code and a few pedantic lints:

- `ownmesh-logs`: `WindowsEventLogProvider` import only used under `cfg(windows)`; `std::process::Command` and wevtutil helpers only used on Windows (still compiled + unit-tested via `cfg(any(test, windows))`).
- `ownmesh-broker`: macOS did not consume the Windows/Linux `--allowed-uid` CLI fold (LaunchDaemon uses separate plist entries); Linux `.map_err(|e| e.to_string())` on an already-`String` error; `uid_t`/`gid_t`→`u32` try_from was a same-type conversion on shipped Unix targets; signing-parent custody used an underscore-prefixed binding that Clippy rejected when read under `cfg(unix)`.

**Fix:** narrow cfg on imports/helpers, format allowed-uid CLI args via a shared helper with unit coverage, use peer uid/gid values directly, rename the signing-parent parameter, and drop the redundant `to_string`. Custody/OAuth fail-closed behavior is unchanged.

### control-plane — `pnpm audit --audit-level=high` (wrangler 3 → 4)

Security workflow job failed on high findings all reached through `packages/control-plane` devDependency `wrangler@3.114.17` → `miniflare@3` (`undici`, `ws`, `sharp`).

**Fix:** upgrade declared devDependencies to Wrangler 4 (`wrangler` `^4.116.0`) and matching `@cloudflare/workers-types` `^5.20260730.1`. Lockfile resolves a graph whose miniflare transitive set includes patched `undici` / `ws` / `sharp` (no `pnpm.auditConfig` ignores, no audit-level relaxation, no resolutions that fight declared peers). Worker `wrangler.jsonc` shape and existing config/deploy dry-run tests remain the compatibility gate.

## Compatibility

- Runtime product behavior matches v1.1.0 except for the CI-blocking correctness fixes above.
- Control-plane **deploy tooling** moves from Wrangler 3 to Wrangler 4 (devDependency only); Worker source and binding layout are unchanged.
- Consumers should treat v1.1.1 as the first green publish candidate for the 1.1 onboarding/distribution train when release automation is re-run against this tree (without moving `v1.1.0`).

## See also

- [`docs/RELEASE_NOTES_v1.1.0.md`](./RELEASE_NOTES_v1.1.0.md) — product scope for the 1.1 train
- [`CHANGELOG.md`](../CHANGELOG.md)
