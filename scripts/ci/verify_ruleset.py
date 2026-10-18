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
import json
import re
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


def _path_glob_matches(pattern: str, ref: str) -> bool | None:
    """Match a GitHub ref glob using ``File::FNM_PATHNAME`` semantics.

    GitHub's ruleset patterns use fnmatch syntax with ``*`` and ``?`` unable
    to cross ``/``.  Only a ``**/`` component matches zero or more path
    components; terminal ``**`` remains path-local.  Backslash quoting,
    complemented character sets, and malformed character classes are rejected
    as unverifiable rather than treated as evidence.
    """
    if "\\" in pattern:
        return None
    regex: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "*":
            run_end = index
            while run_end < len(pattern) and pattern[run_end] == "*":
                run_end += 1
            run_length = run_end - index
            if run_length >= 2:
                component_start = index == 0 or pattern[index - 1] == "/"
                component_end = (
                    run_end == len(pattern) or pattern[run_end] == "/"
                )
                if run_length != 2 or not component_start or not component_end:
                    return None
                if run_end < len(pattern) and pattern[run_end] == "/":
                    regex.append(r"(?:[^/]+/)*")
                    index = run_end + 1
                else:
                    regex.append(r"[^/]*")
                    index = run_end
                continue
            regex.append(r"[^/]*")
        elif char == "?":
            regex.append(r"[^/]")
        elif char == "[":
            end = pattern.find("]", index + 1)
            if end == -1:
                return None
            contents = pattern[index + 1:end]
            if (
                not contents
                or contents.startswith(("!", "^"))
                or "/" in contents
            ):
                return None
            for offset in range(len(contents) - 2):
                if (
                    contents[offset + 1] == "-"
                    and contents[offset] <= "/" <= contents[offset + 2]
                ):
                    return None
            regex.append("[" + contents + "]")
            index = end
        else:
            regex.append(re.escape(char))
        index += 1
    try:
        return re.fullmatch("".join(regex), ref) is not None
    except re.error:
        return None


def _pattern_matches_main(pattern: str, default_branch: str | None) -> bool | None:
    """Return match, no-match, or unverifiable for a main-target pattern."""
    if pattern.startswith("~"):
        if pattern == "~ALL":
            return True
        if pattern == "~DEFAULT_BRANCH":
            if default_branch is None:
                return None
            return default_branch == "main"
        return None
    return _path_glob_matches(pattern, "refs/heads/main")


def ruleset_targets_main(detail: object, default_branch: str | None = None) -> bool:
    """Return whether a valid, active branch ruleset covers ``main``.

    GitHub's ``evaluate`` enforcement mode is a dry run and does not protect
    the branch.  Any omitted or malformed targeting field is unverifiable, so
    it cannot be used as evidence that ``main`` is protected.
    """
    if not isinstance(detail, dict):
        return False
    if detail.get("target") != "branch":
        return False
    enforcement = detail.get("enforcement")
    if enforcement != "active":
        return False
    conditions = detail.get("conditions")
    if not isinstance(conditions, dict):
        # Fail-closed: malformed conditions cannot prove main is covered.
        return False
    ref = conditions.get("ref_name")
    if not isinstance(ref, dict):
        # Fail-closed: malformed ref filters cannot prove main is covered.
        return False
    includes = ref.get("include")
    excludes = ref.get("exclude")
    if (not isinstance(includes, list) or not includes
            or not isinstance(excludes, list)):
        return False
    if any(not isinstance(pattern, str) for pattern in includes + excludes):
        return False

    include_matches = [
        _pattern_matches_main(pattern, default_branch) for pattern in includes
    ]
    exclude_matches = [
        _pattern_matches_main(pattern, default_branch) for pattern in excludes
    ]
    if any(match is None for match in include_matches + exclude_matches):
        return False
    covered = any(include_matches)
    if not covered:
        return False
    for match in exclude_matches:
        # Any matching exclusion removes main, including ~DEFAULT_BRANCH.
        if match:
            return False
    return True


def collect_required_contexts(
    ruleset_details: list[object], default_branch: str | None = None,
) -> set[str]:
    """Collect required status-check contexts enforced on main.

    Only rulesets targeting `main` count; a context required solely on an
    unrelated ref must not satisfy the assertion.
    """
    contexts: set[str] = set()
    for detail in ruleset_details:
        if (not isinstance(detail, dict)
                or not ruleset_targets_main(detail, default_branch)):
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

    metadata, metadata_err = fetch_json(["api", f"repos/{repo}"])
    default_branch: str | None = None
    if isinstance(metadata, dict):
        candidate = metadata.get("default_branch")
        if isinstance(candidate, str) and candidate:
            default_branch = candidate
    if default_branch is None:
        detail = metadata_err or "missing or malformed default_branch"
        print(f"ERROR: repository default branch is unverifiable: {detail} "
              "(~DEFAULT_BRANCH rules cannot prove coverage)",
              file=sys.stderr)

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

    collected = collect_required_contexts(details, default_branch)
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
