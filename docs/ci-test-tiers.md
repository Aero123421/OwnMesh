# CI test tiers, responsibilities, and SLOs (Issue #230)

This is the operator contract for tiered CI. `CONTRIBUTING.md` holds the
contributor writing rules; this document holds the **where it runs** table,
SLOs, and nightly/weekly ownership.

## Tier responsibilities

| Tier | Purpose | Examples | Default run |
|---|---|---|---|
| Unit / contract | pure logic, parser, state transition, schema invariant | Rust `mod tests`, TS `*.test.ts` | relevant PR / Linux |
| Component integration | public crate boundary, temp SQLite/filesystem, loopback process | `crates/<crate>/tests/<domain>.rs`, `*.integration.test.ts` | relevant PR / Linux |
| Platform | native API, ACL, keychain, service manager, PTY, path custody | `tests/platform_<os>_<domain>.rs` | affected PR on owning OS + nightly |
| Security/adversarial | fail-closed, tamper, replay, redaction, fault | `security_*`, `adversarial_*` | affected PR + full weekly |
| Scale / soak | production limit, large FS/output, high concurrency | `tests/scale_*.rs` (`--ignored --test-threads=1`) | nightly/weekly/manual |
| E2E | real binaries + local workerd / multi-process | `scripts/tests/test_e*.py` | nightly/release |
| Release / supply chain | installer, archive, SBOM, provenance, graph mutation | `scripts/tests/test_release_*.py` | affected PR + release |

Security is orthogonal: `security_unit`, `security_platform`, `security_scale`
may all exist. Moving a test across tiers never deletes coverage.

## Label-driven CI

Standard PRs need no labels: `plan` (`scripts/ci/plan.py`, 4th argv =
comma-separated PR labels) selects path-filtered tiers.

| Label | Effect |
|---|---|
| (none) | path-filtered tiers (standard PR behavior, unchanged) |
| `review-ready` | full (heavier pre-merge signal; also triggers `@coderabbitai full review`) |
| `hotfix` | records `hotfix:true` only; no time-based (e.g. 3h) gates exist today so no exemption is granted (reserved branch point for future use) |
| `do-not-merge` | `CI / required` always fails (merge blocked; no new required context) |

Every plan emits `heavy_deferred:true`: heavy tiers (scale/soak, E2E
real-binary, security deep/full-history/strict-SBOM) never run as PR gates.
They stay nightly/weekly/release-only (see job map below). Enforced by
`plan.py`, this document, and `scripts/check_release_quality.py`.

## CodeRabbit automated operation

Manual `@coderabbitai` calls are no longer required (kept as a fallback):

- `coderabbit-call` (CI job, `pull-requests: write` only) fires on PR
  `opened` / `synchronize` / `labeled(review-ready)` only. It checks
  stargazers via `gh api repos/Aero123421/OwnMesh --jq .stargazers_count`
  (<10 stars has a manual-call restriction, so CI posts the call; >=10
  behaves identically) and posts `@coderabbitai review` (`full review` when
  `review-ready` is present). No token logging, no `secrets:inherit`, no new
  action pins (preinstalled `gh` + bash only).
- Bot-loop guard: the job never fires on `coderabbitai[bot]` actors/senders,
  and it skips re-posting when a call trace already exists in the PR body or
  comments (idempotent).
- `coderabbit-gate` (CI job, read-only) is fail-closed: it passes when a
  `@coderabbitai review` / `full review` call trace exists in the PR body or
  comments, or when a CodeRabbit review (author `coderabbitai`) exists;
  otherwise it fails. It is aggregated inside `CI / required` (no new
  required context; branch protection keeps exactly `CI / required` +
  `CI / security-required`).
- Exemptions: non-PR events pass; `draft` PRs pass (not mergeable yet);
  `do-not-merge` passes this gate but `required` still fails via the plan
  flag; `hotfix` has no exemption.
- `.coderabbit.yaml` runs `auto_review.enabled:true` +
  `auto_incremental_review:true`; `request_changes_workflow:false` keeps
  CodeRabbit advisory so CI's gate is the single blocker.

## Job map

| Job | Runs when | What it proves |
|---|---|---|
| `plan` | always | fail-closed tier booleans + labels (`hotfix`/`do_not_merge`/`heavy_deferred`) + `ci-plan.json` |
| `coderabbit-call` | PR opened/sync/labeled(review-ready) | auto-posts `@coderabbitai review` (star-limit bypass, idempotent) |
| `rust-linux` | Rust changes | sole full correctness (fmt/clippy/test/bins) |
| `rust-linux-stateful` | Rust changes | daemon/PTY phases, no test-binary rerun |
| `typescript` | TS/schema changes | test/typecheck/lint/dry-run, typecheck once |
| `platform-windows` / `platform-macos` | Rust changes | `cargo check` compat + affected native link/run |
| `security-fast` | always (fast subset) | changed-range gitleaks + affected boundary tests |
| `release-policy` | workflow/release changes | checker + mutation + installer, each once |
| `required` / `security-required` | always | fixed aggregators; required checks for branch ruleset (`required` also aggregates `coderabbit-gate` + `do-not-merge` block; no new contexts) |
| nightly `scale` | schedule/manual | production boundaries (25k spool, 4.5k pagination, etc.) |
| nightly `e2e-loopback` | schedule/manual | real binaries × local workerd |
| weekly `security` deep | schedule/manual | audits, full-history scan, strict SBOM, full adversarial |
| `release-eligibility` | tag | exact-SHA evidence verification (no CI re-run) |

## Canonical runner (single source of truth)

Suite commands live only in `scripts/ci/suites.toml`. `.github/workflows/ci.yml`
holds orchestration/permissions/OS only and invokes each suite via
`python3 scripts/ci/run.py <suite>`; `CONTRIBUTING.md` and local runs use the
same entrypoint. Do not duplicate suite commands directly in YAML.

| Suite | Invoked as | Source |
|---|---|---|
| `rust-linux` | `python3 scripts/ci/run.py rust-linux` | `suites.toml [rust-linux]` |
| `rust-linux-stateful` | `python3 scripts/ci/run.py rust-linux-stateful` | `suites.toml [rust-linux-stateful]` |
| `typescript` | `python3 scripts/ci/run.py typescript` | `suites.toml [typescript]` |
| `platform-windows` | `python3 scripts/ci/run.py platform-windows` | `suites.toml [platform-windows]` |
| `platform-macos` | `python3 scripts/ci/run.py platform-macos` | `suites.toml [platform-macos]` |
| `security-fast` | local `run.py security-fast`; CI wraps the same scan in the pinned gitleaks action for upload/summary | `suites.toml [security-fast]` |
| `security-boundary` | `python3 scripts/ci/run.py security-boundary` | `suites.toml [security-boundary]` |
| `release-policy` | `python3 scripts/ci/run.py release-policy` | `suites.toml [release-policy]` |
| `tui-i18n` | `python3 scripts/ci/run.py tui-i18n` | `suites.toml [tui-i18n]` |
| `scale-filesystem` | `python3 scripts/ci/run.py scale --suite filesystem` (nightly/weekly) | `suites.toml [scale-filesystem]` |

## SLOs (20 representative runs)

| Metric | Target |
|---|---|
| docs-only PR required checks | p95 ≤ 2 min |
| TypeScript-only PR required checks | p95 ≤ 5 min |
| Rust code PR critical path | p50 ≤ 6 min, p95 ≤ 10 min |
| target OS boundary PR | p95 ≤ 12 min |
| tag → release build matrix start | p95 ≤ 2 min |
| typical Rust/TS-only runner-minutes | ≥50% below pre-tier baseline |
| unchanged flaky retry | 0 (exceptions need Issue + owner + expiry) |

Never skip silently to meet an SLO. On miss, measure top slow suites and
cache ROI (`scripts/ci/duration_report.py`) and fix the design.

## Nightly/weekly ownership

- Nightly/weekly failures are not a PR merge gate, but blocking signals
  that require triage, with an owner and a triage Issue; “PR passed so
  ignore” is forbidden. Triage is required before any retry or quarantine.
- Owners (per `.github/CODEOWNERS`): `scale.yml` and `e2e-loopback.yml`
  are owned by `@Aero123421`. Each workflow has a `triage` job (`if: failure()`,
  no secrets) that publishes `owner` / `due` / `issue_title` outputs and a
  step-summary triage template (owner, 1-business-day due, Issue title/body
  template, run URL). Create the Issue from that template; do not rely on
  automatic issue writes.
- Temporary flaky quarantine is prohibited by default. If unavoidable: Issue
  number, owner, expiry, nightly execution required; never applies to
  security/release gates.
- `#[ignore]` is for permanent scale tests with `scale:` reason prefix only,
  never for hiding failures.

## Branch protection

Required contexts (exact fixed names):

- `CI / required`
- `CI / security-required`

Matrix job names must never become required contexts (renames would silently
unprotect `main`). Verify with `python scripts/ci/verify_ruleset.py --expect-ruleset`.
Tag move/delete is prohibited when tag rulesets are available.
