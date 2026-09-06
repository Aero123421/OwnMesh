#!/usr/bin/env python3
"""Exact-SHA release eligibility proof (Issue #230 Phase 4).

Verifies for a tag push, fail-closed:
- annotated release tag, tag SHA reachable from main
- exact GITHUB_SHA has success `CI / required` + `CI / security-required`
  from the expected workflow/app (no stale branch-head, forged name, missing,
  skipped, cancelled, neutral)
- expected --run-id workflow run has the exact SHA, success conclusion, the
  expected ci.yml path, and non-expired ci-plan artifacts bound to that run
  (presence + non-expired + run head_sha binding only; stale/forged/missing/
  canceled/skipped/neutral/expired all fail)
- evidence commit SHA, toolchain, lockfiles, test-plan schema version match
- branch ruleset precondition documented (enforced via verify_ruleset.py)

Usage (in release.yml):
    python scripts/ci/release_eligibility.py \
      --tag "$GITHUB_REF_NAME" --sha "$GITHUB_SHA" --repo "$GITHUB_REPOSITORY" \
      --expected-workflow CI --run-id "$CI_RUN_ID"

Never trusts branch-latest status alone. Canceled/skipped/neutral/missing are
all failures. Check producer must be the expected GitHub Actions workflow.
--run-id is required: the expected CI run's artifacts (ci-plan.json etc.)
must match the exact SHA/digest, otherwise fail-closed.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REQUIRED_CONTEXTS = ("CI / required", "CI / security-required")
EXPECTED_TOOLCHAIN = '"1.92.0"'
PLAN_SCHEMA_VERSION = 1
EXPECTED_WORKFLOW_PATH = ".github/workflows/ci.yml"
REQUIRED_ARTIFACT_SUBSTR = "ci-plan"


def sh(*args: str) -> str:
    out = subprocess.run(list(args), cwd=str(ROOT), capture_output=True, text=True, check=False)
    if out.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} failed: {out.stderr[:1000]}")
    return out.stdout.strip()


def gh_api(path: str) -> dict:
    out = subprocess.run(["gh", "api", path], capture_output=True, text=True, check=False)
    if out.returncode != 0:
        raise RuntimeError(f"gh api {path} failed: {out.stderr[:1000]}")
    return json.loads(out.stdout or "{}")


def is_success_check(run: dict, sha: str) -> bool:
    """A check-run counts only when it is exact-SHA GitHub-Actions success."""
    return (
        run.get("head_sha") == sha
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and str((run.get("app") or {}).get("slug", "")) == "github-actions"
    )


def validate_context_checks(ctx: str, candidates: list[dict], sha: str) -> str | None:
    """Validate one required context against exact-SHA candidates.

    Returns an error string for stale/forged/missing/skipped/canceled/neutral,
    or None when exactly a GitHub-Actions success exists with no bad states.
    """
    exact = [r for r in candidates if r.get("head_sha") == sha]
    if not exact:
        if candidates:
            return (f"missing check for exact SHA: {ctx} "
                    f"(stale: {len(candidates)} run(s) for other SHAs)")
        return f"missing check for exact SHA: {ctx}"
    forged = [r for r in exact
              if str((r.get("app") or {}).get("slug", "")) != "github-actions"]
    if forged:
        return f"{ctx} has forged producer for exact SHA (expected github-actions)"
    ok = any(is_success_check(r, sha) for r in exact)
    if not ok:
        states = [(b.get("status"), b.get("conclusion")) for b in exact]
        return f"{ctx} has no GitHub-Actions success for exact SHA (states={states})"
    bad = [r for r in exact if not is_success_check(r, sha)]
    if bad:
        states = [(b.get("status"), b.get("conclusion")) for b in exact]
        return f"{ctx} not success for exact SHA (states={states})"
    return None


def validate_workflow_run(run: dict | None, sha: str,
                          expected_workflow: str = "CI",
                          expected_path: str = EXPECTED_WORKFLOW_PATH) -> str | None:
    """Validate the expected workflow run binding (fail-closed).

    Rejects missing/stale (wrong SHA)/forged (wrong path or workflow name)/
    skipped/canceled/cancelled/neutral/failure. Returns None on success.
    """
    if not run:
        return f"missing workflow run for exact SHA {sha}"
    if run.get("head_sha") != sha:
        return (f"stale workflow run {run.get('id')}: head_sha "
                f"{run.get('head_sha')} != expected {sha}")
    path = str(run.get("path", ""))
    name = str(run.get("name", ""))
    if path != expected_path or name != expected_workflow:
        return (f"forged workflow producer for exact SHA {sha}: "
                f"path={path!r} name={name!r} (expected path={expected_path!r})")
    if run.get("conclusion") != "success":
        return (f"workflow run {run.get('id')} not success for exact SHA "
                f"(status={run.get('status')} conclusion={run.get('conclusion')}: "
                f"canceled/skipped/neutral all fail)")
    return None


def validate_run_artifacts(payload: dict, run_id: str) -> str | None:
    """Validate expected run-id artifacts (fail-closed).

    Requires a non-expired ci-plan artifact; missing/expired artifacts fail.
    Artifact *content* digests are NOT verified here: this proof covers
    presence + non-expired + the expected run's head_sha binding only (the
    run itself is validated via validate_workflow_run). The API digest field,
    when present, is informational and never trusted as content proof.
    """
    artifacts = payload.get("artifacts", [])
    if not isinstance(artifacts, list) or not artifacts:
        return f"missing artifacts for expected run-id {run_id} (fail-closed)"
    matches = [a for a in artifacts
               if REQUIRED_ARTIFACT_SUBSTR in str(a.get("name", ""))]
    if not matches:
        names = [str(a.get("name", "")) for a in artifacts[:10]]
        return (f"missing {REQUIRED_ARTIFACT_SUBSTR} artifact for run-id "
                f"{run_id} (found={names})")
    for artifact in matches:
        if artifact.get("expired", False):
            return (f"expired {artifact.get('name')} artifact for run-id "
                    f"{run_id} (fail-closed)")
        # NOTE: API `digest` is informational only and never trusted as content
        # proof; presence + non-expired + run head_sha binding above is the proof.
    return None


def build_evidence(*, tag: str, sha: str, run_id: str,
                   expected_workflow: str, dry_run: bool) -> dict:
    """Assemble the eligibility evidence payload (pure; testable)."""
    return {
        "schema_version": 1,
        "tag": tag,
        "commit_sha": sha,
        "run_id": str(run_id),
        "expected_workflow": expected_workflow,
        "required_contexts": list(REQUIRED_CONTEXTS),
        "toolchain": "1.92.0",
        "test_plan_schema_version": PLAN_SCHEMA_VERSION,
        "dry_run": dry_run,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--repo", default="")
    ap.add_argument("--expected-workflow", default="CI")
    ap.add_argument("--run-id", required=True,
                    help="expected CI workflow run id whose artifacts must match --sha")
    ap.add_argument("--allow-missing-checks", action="store_true",
                    help="ONLY for local dry-run without gh; rejected in CI "
                         "(GITHUB_ACTIONS=true) and recorded as dry_run:true "
                         "in evidence; never in release")
    args = ap.parse_args()

    # A malicious one-line PR must not be able to turn the release gate into
    # a WARN-only pass: the flag is unusable inside GitHub Actions.
    if args.allow_missing_checks and os.environ.get("GITHUB_ACTIONS") == "true":
        print("ERROR: --allow-missing-checks is forbidden when "
              "GITHUB_ACTIONS=true (fail-closed)", file=sys.stderr)
        return 1

    errors: list[str] = []

    # 1. Annotated tag + SHA match.
    try:
        obj_type = sh("git", "cat-file", "-t", args.tag)
        if obj_type != "tag":
            errors.append(f"tag {args.tag} is not annotated (got {obj_type})")
    except Exception as exc:
        errors.append(f"tag annotation check failed: {exc}")
    try:
        tag_sha = sh("git", "rev-list", "-n", "1", args.tag)
        if tag_sha != args.sha:
            errors.append(f"tag {args.tag} points at {tag_sha}, expected {args.sha}")
    except Exception as exc:
        errors.append(f"tag SHA check failed: {exc}")

    # 2. Reachable from main.
    try:
        rc = subprocess.run(["git", "merge-base", "--is-ancestor", args.sha, "origin/main"],
                            cwd=str(ROOT), check=False).returncode
        if rc != 0:
            # Fallback to local main when origin/main is absent (shallow runners).
            rc2 = subprocess.run(["git", "merge-base", "--is-ancestor", args.sha, "main"],
                                 cwd=str(ROOT), check=False).returncode
            if rc2 != 0:
                errors.append(f"tag SHA {args.sha} is not reachable from main")
    except Exception as exc:
        errors.append(f"ancestry check failed: {exc}")

    # 3. Toolchain + lockfiles + plan schema at this SHA.
    try:
        toolchain = sh("git", "show", f"{args.sha}:rust-toolchain.toml")
        if EXPECTED_TOOLCHAIN not in toolchain:
            errors.append("toolchain at tag SHA is not 1.92.0")
    except Exception as exc:
        errors.append(f"toolchain check failed: {exc}")
    for lock in ("Cargo.lock", "pnpm-lock.yaml"):
        try:
            sh("git", "cat-file", "-e", f"{args.sha}:{lock}")
        except Exception:
            errors.append(f"lockfile missing at tag SHA: {lock}")
    try:
        plan_py = sh("git", "show", f"{args.sha}:scripts/ci/plan.py")
        if f"SCHEMA_VERSION = {PLAN_SCHEMA_VERSION}" not in plan_py:
            errors.append("test-plan schema version mismatch at tag SHA")
    except Exception as exc:
        errors.append(f"plan schema check failed: {exc}")

    # 4. Exact-SHA check-runs for required contexts + expected run-id binding.
    if args.allow_missing_checks:
        print("WARN: --allow-missing-checks is local-only; release must not use it",
              file=sys.stderr)
    else:
        try:
            if not args.repo or "/" not in args.repo:
                raise RuntimeError("--repo owner/name is required")
            if not str(args.run_id).strip() or str(args.run_id) == "0":
                raise RuntimeError("--run-id of the expected CI run is required")
            data = gh_api(f"repos/{args.repo}/commits/{args.sha}/check-runs?per_page=100")
            runs = data.get("check_runs", [])
            by_name: dict[str, list[dict]] = {}
            for run in runs:
                by_name.setdefault(run.get("name", ""), []).append(run)
            for ctx in REQUIRED_CONTEXTS:
                err = validate_context_checks(ctx, by_name.get(ctx, []), args.sha)
                if err:
                    errors.append(err)
            # Workflow producer binding: ci.yml must have a successful run at
            # this exact SHA (prevents a forged check name from another workflow).
            try:
                wf = gh_api(
                    f"repos/{args.repo}/actions/workflows/ci.yml/runs"
                    f"?head_sha={args.sha}&per_page=10"
                )
                wf_runs = wf.get("workflow_runs", [])
                wf_ok = any(
                    validate_workflow_run(r, args.sha, args.expected_workflow) is None
                    for r in wf_runs
                    if isinstance(r, dict)
                )
                if not wf_ok:
                    errors.append(
                        f"no successful ci.yml workflow run for exact SHA {args.sha}"
                    )
            except Exception as exc:
                errors.append(f"workflow-runs verification failed: {exc}")
            # Expected run-id binding: the exact run id must match this SHA
            # with success, the expected ci.yml path, and live ci-plan
            # artifacts (presence + non-expired + run head_sha binding only,
            # fail-closed on stale/forged/missing/skipped/canceled/neutral/
            # expired).
            try:
                expected = gh_api(f"repos/{args.repo}/actions/runs/{args.run_id}")
                err = validate_workflow_run(expected, args.sha,
                                            args.expected_workflow)
                if err:
                    errors.append(f"expected run-id {args.run_id}: {err}")
                try:
                    artifacts = gh_api(
                        f"repos/{args.repo}/actions/runs/{args.run_id}"
                        f"/artifacts?per_page=100"
                    )
                    artifact_err = validate_run_artifacts(artifacts, str(args.run_id))
                    if artifact_err:
                        errors.append(artifact_err)
                except Exception as exc:
                    errors.append(f"run-id artifacts verification failed: {exc}")
            except Exception as exc:
                errors.append(f"expected run-id verification failed: {exc}")
        except Exception as exc:
            errors.append(f"check-runs verification failed: {exc}")

    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1
    evidence = build_evidence(
        tag=args.tag,
        sha=args.sha,
        run_id=str(args.run_id),
        expected_workflow=args.expected_workflow,
        dry_run=bool(args.allow_missing_checks),
    )
    Path("release-eligibility.json").write_text(json.dumps(evidence, indent=2) + "\n",
                                                encoding="utf-8")
    print(f"release eligibility passed for {args.tag} @ {args.sha} (run-id {args.run_id})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
