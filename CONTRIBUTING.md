# Contributing to OwnMesh

Thank you for your interest in OwnMesh. This project aims to stay readable, secure, and faithful to [`OWNMESH_SPECIFICATION.ja.md`](./OWNMESH_SPECIFICATION.ja.md).

## Code of conduct

Participation is governed by [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).

## Before you start

1. Read the relevant sections of the specification and [`IMPLEMENTATION_CHECKLIST.md`](./IMPLEMENTATION_CHECKLIST.md).
2. For security-sensitive changes, skim [`SECURITY_REVIEW_CHECKLIST.md`](./SECURITY_REVIEW_CHECKLIST.md).
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

Workspace Rust lints forbid `unsafe_code` and enable Clippy `pedantic` (as warnings elevated to errors in CI via `-D warnings`).

### Branch protection check-name migration

Commit `c37f5fc` consolidated and renamed required CI jobs. Repository administrators must update branch-protection required checks after the new workflow has run once; GitHub only offers check names it has observed. Do not remove an old required check until its replacement is selectable, and do not leave both generations required indefinitely (that deadlocks merges because old jobs no longer run).

| Remove legacy required check | Require current check |
| --- | --- |
| `Rust (Windows)` | `Rust 1.92 (Windows)` |
| `Rust (macOS, best-effort)` | `Rust 1.92 (macOS)` |
| `Rust (Linux, best-effort)` | `Rust 1.92 (Linux)` |
| `TypeScript / pnpm` and `Control Plane (Worker)` | `pnpm frozen quality gates` |
| _(new)_ | `Release claims and gate structure` |

If Security jobs are branch-protection requirements, also refresh renamed contexts such as `SAST (clippy -D warnings)` → `SAST (Rust 1.92 clippy -D warnings)`, `SAST (TypeScript typecheck)` → `SAST (TypeScript)`, and `SBOM (CycloneDX Rust + Node)` → `SBOM (strict CycloneDX Rust + Node)`. Keep the independent audit, gitleaks, retention/redaction, TUI i18n, and all matrix checks required according to repository policy.

## Project layout

| Path | Responsibility |
| --- | --- |
| `crates/*` | Local runtime, CLI, TUI, IPC, policy, profiles, … |
| `packages/control-plane` | Cloudflare Workers control plane |
| `spec-bundle/schemas` | JSON Schema / catalogs shared by implementations |
| `spec-bundle/examples` | Example config / policy / profile TOML |
| `docs/adr` | Architecture decisions |

Prefer small, reviewable PRs that complete a checklist item or a clear slice of one.

## Coding guidelines

- Keep UI, domain, protocol, OS adapters, privileged code, and external adapters separated.
- Do not commit secrets, tokens, private keys, `.env` files, or local runtime state.
- Avoid drive-by refactors unrelated to the change.
- Identifiers, API names, config keys, and error codes use **English** as the source of truth.
- Prefer tests or fixtures next to the behavior you change; schema changes should stay consistent across Rust, TypeScript, and `spec-bundle/schemas`.

## Pull requests

1. Fork and branch from `main`.
2. Make the change with tests where practical.
3. Ensure the quality gates above pass locally.
4. Describe **what** and **why**; link checklist sections or ADRs when relevant.
5. Call out security / privilege / protocol impact explicitly.

## Issues

- Bug reports: reproduction steps, OS, version/commit, expected vs actual.
- Security issues: follow [`SECURITY.md`](./SECURITY.md) — **not** public issues for sensitive detail.

## License

By contributing, you agree that your contributions are licensed under the **Apache License, Version 2.0**, matching this repository’s [`LICENSE`](./LICENSE).
