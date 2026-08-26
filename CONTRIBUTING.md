# Contributing to OwnMesh

Thank you for your interest in OwnMesh. This project aims to stay readable, secure, and faithful to [`OWNMESH_SPECIFICATION.ja.md`](./OWNMESH_SPECIFICATION.ja.md).

## Code of conduct

Participation is governed by [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).

## Before you start

1. Read the relevant specification sections and the shipped-surface contract in [`release/SUPPORTED_SURFACES.json`](./release/SUPPORTED_SURFACES.json).
2. For security-sensitive changes, review [`docs/SECURITY_REVIEW_CHECKLIST.md`](./docs/SECURITY_REVIEW_CHECKLIST.md).
3. Breaking protocol, auth, policy-boundary, or official-profile changes require an **ADR** under `docs/adr/` (see `docs/adr/ADR_TEMPLATE.md`).

## Development setup

### Toolchain

- Rust **1.92.0** via `rust-toolchain.toml` (`rustfmt`, `clippy`)
- Node.js **≥ 22**, pnpm **9.15.0** (`packageManager` field / Corepack)

On Windows without Administrator rights, `corepack enable` may fail with
`EPERM` while trying to write shims under `C:\Program Files\nodejs`. That is a
local toolchain layout issue, not a repository defect. Install pnpm 9.15.0 on
`PATH` (for example via `npm install -g pnpm@9.15.0`) and either skip
`corepack enable` or use a user-writable Corepack shim earlier on `PATH`.
GitHub Actions runners are unaffected because they can install the shims.

### Bootstrap

```bash
# Rust
cargo build --workspace --locked
cargo test --workspace --all-targets --locked

# TypeScript monorepo packages
pnpm install --frozen-lockfile
pnpm -r test
pnpm -r typecheck
pnpm -r lint
```

### Quality gates (match CI)

```bash
cargo metadata --locked --format-version 1 --no-deps > /dev/null
cargo fmt --all --check # cargo-fmt never resolves dependencies and has no --locked option
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo test --workspace --all-targets --locked
pnpm install --frozen-lockfile
pnpm -r test
pnpm -r typecheck
pnpm -r lint
python scripts/check_release_quality.py
```

### Local validation and CI policy

Treat CI as the final cross-platform verification of a change, not as the
first place to discover failures that can be reproduced locally.

- Keep local commits small, coherent, and independently reviewable. Run the
  focused tests for the affected crate, package, script, or fixture after each
  logical change.
- Before opening or updating a pull request, run the complete quality gates
  above when the local environment supports them. Make several local commits
  if useful, then push a coherent batch so every small checkpoint does not
  trigger a separate CI run.
- If a local platform or toolchain cannot run a required gate, record exactly
  what was not run and leave that platform-specific verification to CI. Do not
  describe an unavailable or skipped gate as passing.
- Classify a CI failure before retrying it. Reproduce and fix change-related
  failures locally where possible, then push the tested fix. Rerun an unchanged
  job only when the evidence points to a transient infrastructure or confirmed
  flaky-test failure; do not repeatedly rerun an unexplained failure.
- Windows, macOS, Linux, hosted-service, permission, signing, provenance, and
  release-workflow checks that cannot be reproduced faithfully on one
  development machine remain required CI or release gates.

Workspace Rust lints forbid `unsafe_code` and enable Clippy `pedantic` (as warnings elevated to errors in CI via `-D warnings`).

Four crates opt out of the `unsafe_code` forbid because they bind OS APIs
directly: `ownmesh-ipc` (peer credentials), `ownmesh-fs` (handle-based path
custody), `ownmesh-broker` (Windows SCM and token APIs), and `ownmesh-exec`
(Windows code-page FFI plus the descriptor-bound Linux `pre_exec` handoff,
[ADR 0013](./docs/adr/0013-prepared-executable-custody.md)). Each re-declares
the workspace Clippy configuration so no lint coverage is lost, and each keeps
its `unsafe` confined to the platform module named in its `Cargo.toml` comment.
New `unsafe` outside those four crates is rejected by the compiler; adding a
fifth exception requires an ADR.

## Project layout

| Path | Responsibility |
| --- | --- |
| `crates/*` | Local runtime, CLI, TUI, IPC, policy, profiles, … |
| `packages/control-plane` | Cloudflare Workers control plane |
| `spec-bundle/schemas` | JSON Schema / catalogs shared by implementations |
| `spec-bundle/examples` | Example config / policy / profile TOML |
| `docs/adr` | Architecture decisions |

Prefer small, reviewable PRs that complete one clear behavior or boundary.

## Coding guidelines

- Keep UI, domain, protocol, OS adapters, privileged code, and external adapters separated.
- Do not commit secrets, tokens, private keys, `.env` files, or local runtime state.
- Avoid drive-by refactors unrelated to the change.
- Identifiers, API names, config keys, and error codes use **English** as the source of truth.
- Prefer tests or fixtures next to the behavior you change; schema changes should stay consistent across Rust, TypeScript, and `spec-bundle/schemas`.

## Commit authorship

Every commit must carry a real name and a reachable email address. Placeholder
identities (`*.local`, `test@`, `example.com`, bare `root`) are not accepted:
this project ships signed binaries that run privileged operations on other
people's machines, so the history has to say who wrote what.

```bash
git config user.name  "Your Name"
git config user.email "you@example.org"   # or your GitHub noreply address
```

Commits authored by an agent or automation must attribute the human who ran it
via `Co-Authored-By:`, so the responsible party stays identifiable.

Part of the history predating this rule was committed under a placeholder
identity. That history is preserved rather than rewritten — rewriting it would
invalidate every published release tag and the artifacts signed against those
commits. The rule applies from here forward.

## Pull requests

1. Fork and branch from `main`.
2. Make the change with tests where practical.
3. Ensure the quality gates above pass locally.
4. Describe **what** and **why**; link specifications or ADRs when relevant.
5. Call out security / privilege / protocol impact explicitly.

## Issues

- Bug reports: reproduction steps, OS, version/commit, expected vs actual.
- Security issues: follow [`SECURITY.md`](./SECURITY.md) — **not** public issues for sensitive detail.

## License

By contributing, you agree that your contributions are licensed under the **Apache License, Version 2.0**, matching this repository’s [`LICENSE`](./LICENSE).
