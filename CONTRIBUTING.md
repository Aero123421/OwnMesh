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

- Rust **1.85.0** via `rust-toolchain.toml` (`rustfmt`, `clippy`)
- Node.js **≥ 22**, pnpm **9.15.0** (`packageManager` field / Corepack)

### Bootstrap

```bash
# Rust
cargo build --workspace
cargo test --workspace

# TypeScript monorepo packages
pnpm install
pnpm -r typecheck
pnpm -r lint
```

### Quality gates (match CI)

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace
cargo test --workspace
pnpm -r typecheck
pnpm -r lint
```

Workspace Rust lints forbid `unsafe_code` and enable Clippy `pedantic` (as warnings elevated to errors in CI via `-D warnings`).

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
