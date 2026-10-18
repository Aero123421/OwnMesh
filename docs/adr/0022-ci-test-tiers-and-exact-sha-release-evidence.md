# ADR 0022: CI test tiers and exact-SHA release evidence

- Status: Accepted
- Date: 2026-09-05
- Deciders: OwnMesh maintainers
- Relates: #230, ADR 0001 (release signing/SBOM/provenance)

## Context

CI ran the same quality proof on three OSes, in both CI and Security, and
again at release for the same SHA. The critical path was a Windows full
`cargo test` dominated by production-scale real-filesystem tests
(`ownmesh-fs` 25,050 files). `security.yml` re-ran CI's clippy/typecheck/
lint/tests; `release.yml` re-invoked both reusable workflows for the same
SHA; `check_release_quality.py` pinned the old duplicated graph as strings.

We need tiered execution without weakening fail-closed authorization, exact
action binding, idempotency, replay protection, signing, SBOM, or provenance
(ADR 0001).

## Decision

1. **Linux is the sole full Rust correctness tier** (fmt, clippy, full
   workspace tests, bins check). Windows/macOS provide compile compatibility
   (`cargo check --workspace --all-targets`) plus affected native link/run
   tests. Five-platform release builds are unchanged.
2. **Tests move tiers, never deleted.** Production-scale filesystem/soak,
   full cross-OS, and local workerd E2E move to nightly/weekly/manual/release.
   Changed security boundaries keep negative/fault tests in PR.
3. **Same SHA, one proof.** Release consumes exact-SHA `required` +
   `security-required` evidence (workflow path, run id, commit, toolchain,
   lockfile digests, test-plan version). It never re-runs `ci.yml` /
   `security.yml`. Stale/forged/missing/canceled/skipped evidence fails.
4. **Fail-closed path planning.** `scripts/ci/plan.py` maps diffs to tiers;
   unknown paths, planner errors, missing base SHA, and workflow/lockfile/root
   changes fall back to full. Required aggregators (`CI / required`,
   `CI / security-required`) always run and fail on missing/skipped/cancelled
   needed jobs.
5. **Thin canonical runner.** `scripts/ci/run.py` + `suites.toml` own suite
   names/commands/timeouts. YAML holds orchestration/permissions/OS only.
6. **SBOM twice.** Weekly continuous audit plus exact-tag-SHA release SBOM
   (missing/invalid fails publish). No PR-time duplicate SBOM generation.

## Consequences

- Typical PR runner-minutes drop ≥50%; Rust critical path p95 ≤10 min.
- Release starts within p95 ≤2 min of tag (no full CI re-run).
- Planner/eligibility mutations guard against silent skips and forged checks.
- Repository rulesets must pin the two aggregators as required checks;
  settings changes are verified by `scripts/ci/verify_ruleset.py`, not by PR
  merge alone.

## Alternatives considered

- Larger runners / sccache / nextest first: rejected as primary fix; allowed
  only after duplication removal with measured ROI.
- `paths-ignore` only: rejected; required workflows must start to keep
  required checks from pending.
- Deleting platform/security/scale tests for speed: rejected; tier move only.
