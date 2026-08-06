# ENV_SMOKE_CHECK (env-00)

- **Date**: 2026-03-22
- **Executor**: pi + xai/grok native worker
- **Purpose**: Fail-fast verification that bash/shell, Rust toolchain, Node/pnpm, and git are usable before audit-01 and later tickets.
- **Result**: **PASS** — all required commands succeeded; repository is on `origin/main` at v1.0.0 (`38cd146`).

## Command results

| Check | Command | Exit | Output (summary) |
|-------|---------|------|------------------|
| sh | `sh -c 'echo ok'` | 0 | `ok` |
| bash | `bash -c 'echo ok'` | 0 | `ok` |
| cargo | `cargo --version` | 0 | `cargo 1.92.0 (344c4567c 2025-10-21)` |
| rustc | `rustc --version` | 0 | `rustc 1.92.0 (ded5c06cf 2025-12-08)` |
| pnpm | `pnpm --version` | 0 | `9.15.0` |
| node | `node --version` | 0 | `v24.12.0` |
| git | `git --version` | 0 | `git version 2.53.0.windows.2` |
| git status | `git status` | 0 | See below |
| git log | `git log -1` | 0 | See below |

## Git status

```
On branch main
Your branch is up to date with 'origin/main'.

nothing to commit, working tree clean
```

*(Recorded at smoke-check time, before this file was added.)*

## Git log -1

```
commit 38cd14635e1e648b01b43f41938edc87abd02d30
Author: OwnMesh Baseline <ownmesh-baseline@users.noreply.github.com>
Date:   Thu Aug 6 18:29:08 2026 +0900

    feat: OwnMesh 1.0 core runtime, control plane, and release prep
    
    Implement exec/fs/logs/policy/session/broker/profiles/transfer/update/
    diagnostics crates with tests; Cloudflare Worker MCP+OAuth+D1 migrations;
    TUI i18n (en/ja/zh-Hans/ru); docs and v1.0.0 release workflow.
```

## Baseline confirmation

| Item | Value |
|------|--------|
| Branch | `main` (tracking `origin/main`, up to date) |
| HEAD | `38cd14635e1e648b01b43f41938edc87abd02d30` |
| Tag | `v1.0.0` (`git describe --tags --always` → `v1.0.0`) |
| Tag ref | `9354adee5591a7e5e745f721ff427e33290391f8 refs/tags/v1.0.0` |
| Working tree (pre-doc) | clean |

**Conclusion**: Repository is on `origin/main` at v1.0.0 (`38cd146` series). Native worker toolchain is sufficient for subsequent tickets. No tools were missing; no environment changes were made.

## Scope / constraints observed

- Only this file (`docs/ENV_SMOKE_CHECK.md`) is in scope for env-00.
- No installs, no source/test/config edits, no writes outside the repo.
