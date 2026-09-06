#!/usr/bin/env python3
"""Verify repository rulesets + required checks exist (Issue #230 Phase 5).

Read-only operator check (GET only, no secrets printed). Fails closed when
the ruleset or required contexts are absent so `main` protection cannot
silently drift. Requires `gh`.

It fetches the repository rulesets, resolves each ruleset protecting `main`,
parses the `required_status_checks` rules, and asserts the exact required
contexts are enforced. A missing/unparseable ruleset or a missing context
fails; `--expect-ruleset` additionally fails when no ruleset exists at all
(fresh forks may have none yet; release pipelines always pass the flag).

Usage:
    python scripts/ci/verify_ruleset.py --repo Aero123421/OwnMesh
    python scripts/ci/verify_ruleset.py --repo Aero123421/OwnMesh --expect-ruleset
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
import sys

REQUIRED_CONTEXTS = ("CI / required", "CI / security-required")


def fetch_json(args: list[str]) -> tuple[object | None, str]:
    """GET via `gh api`. Returns (payload, error); error is "" on success."""
    out = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if out.returncode != 0:
        return None, (out.stderr.strip()[:500] or f"gh exited {out.returncode}")
    try:
        return json.loads(out.stdout or "null"), ""
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON from gh: {exc}"


def ruleset_targets_main(detail: object) -> bool:
    """True when a ruleset object enforces branch rules that cover main."""
    if not isinstance(detail, dict):
        return False
    if detail.get("target") != "branch":
        return False
    if str(detail.get("enforcement", "active")).lower() == "disabled":
        return False
    conditions = detail.get("conditions", {})
    if not isinstance(conditions, dict):
        # Fail-closed: unparseable conditions cannot prove main is excluded, so treat as targeting main.
        return True
    ref = conditions.get("ref_name", {})
    if not isinstance(ref, dict):
        # Fail-closed: unparseable ref filter cannot prove main is excluded, so treat as targeting main.
        return True
    includes = ref.get("include", [])
    excludes = ref.get("exclude", [])
    if not isinstance(includes, list) or not includes:
        # Fail-closed: missing/empty include cannot prove main is excluded, so treat as targeting main.
        return True
    covered = any(
        isinstance(pat, str) and (
            pat in ("refs/heads/main", "~DEFAULT_BRANCH")
            or fnmatch.fnmatch("refs/heads/main", pat)
        )
        for pat in includes
    )
    if not covered:
        return False
    if isinstance(excludes, list):
        for pat in excludes:
            if isinstance(pat, str) and fnmatch.fnmatch("refs/heads/main", pat):
                return False
    return True


def collect_required_contexts(ruleset_details: list[object]) -> set[str]:
    """Collect required status-check contexts enforced on main.

    Only rulesets targeting `main` count; a context required solely on an
    unrelated ref must not satisfy the assertion.
    """
    contexts: set[str] = set()
    for detail in ruleset_details:
        if not isinstance(detail, dict) or not ruleset_targets_main(detail):
            continue
        rules = detail.get("rules", [])
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if rule.get("type") != "required_status_checks":
                continue
            params = rule.get("parameters", {})
            if not isinstance(params, dict):
                continue
            entries = params.get("required_status_checks", [])
            if not isinstance(entries, list):
                entries = []
            checks = params.get("checks", [])
            if isinstance(checks, list):
                entries = entries + checks
            for entry in entries:
                if isinstance(entry, dict):
                    ctx = entry.get("context", entry.get("check", entry.get("name")))
                    if isinstance(ctx, str) and ctx:
                        contexts.add(ctx)
                elif isinstance(entry, str) and entry:
                    contexts.add(entry)
            legacy = params.get("contexts", [])
            if isinstance(legacy, list):
                for ctx in legacy:
                    if isinstance(ctx, str) and ctx:
                        contexts.add(ctx)
    return contexts


def missing_contexts(collected: set[str]) -> list[str]:
    return [ctx for ctx in REQUIRED_CONTEXTS if ctx not in collected]


def resolve_repo(explicit: str) -> tuple[str, str | None]:
    """Return (repo_flag_value, error). Falls back to `gh repo view`."""
    if explicit:
        if "/" not in explicit:
            return "", f"--repo must be owner/name, got {explicit!r}"
        return explicit, None
    out = subprocess.run(
        ["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
        capture_output=True, text=True, check=False,
    )
    name = out.stdout.strip()
    if out.returncode != 0 or "/" not in name:
        return "", "cannot determine repo (pass --repo owner/name)"
    return name, None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="",
                    help="owner/name; defaults to `gh repo view`")
    ap.add_argument("--expect-ruleset", action="store_true",
                    help="fail when no branch ruleset protects main")
    args = ap.parse_args()

    repo, err = resolve_repo(args.repo)
    if err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 1 if args.expect_ruleset else 2

    rulesets, err = fetch_json(["api", f"repos/{repo}/rulesets"])
    if rulesets is None:
        print(f"ERROR: cannot list rulesets for {repo}: {err}",
              file=sys.stderr)
        print("verify_ruleset: ruleset state unverifiable (fail-closed only "
              "with --expect-ruleset)", file=sys.stderr)
        return 1 if args.expect_ruleset else 0
    if not isinstance(rulesets, list) or not rulesets:
        print(f"ERROR: no branch ruleset protects main in {repo}; "
              "enable per docs/ci-test-tiers.md", file=sys.stderr)
        return 1 if args.expect_ruleset else 0

    names = [str(r.get("name", r.get("id", "?"))) for r in rulesets
             if isinstance(r, dict)]
    print(f"rulesets ({len(rulesets)}): {', '.join(names)}")

    details: list[object] = []
    for entry in rulesets:
        if not isinstance(entry, dict) or "id" not in entry:
            continue
        detail, err = fetch_json(
            ["api", f"repos/{repo}/rulesets/{entry['id']}"])
        if detail is None:
            print(f"ERROR: cannot read ruleset {entry.get('id')}: {err} "
                  "(fail-closed)", file=sys.stderr)
            return 1
        details.append(detail)

    collected = collect_required_contexts(details)
    missing = missing_contexts(collected)
    print(f"required contexts enforced on main: "
          f"{', '.join(sorted(collected)) or '(none)'}")
    if missing:
        print(f"ERROR: required contexts missing from main rulesets: "
              f"{', '.join(missing)} (fail-closed)", file=sys.stderr)
        return 1
    print(f"verify_ruleset: {', '.join(REQUIRED_CONTEXTS)} enforced on main")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
