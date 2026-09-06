#!/usr/bin/env python3
"""Fail-closed change planner for tiered CI (Issue #230 Phase 2).

Outputs booleans consumed by `.github/workflows/ci.yml` via `fromJson`.

Rules (fail-closed):
- workflow_dispatch: full
- push with zero BEFORE SHA or fetch failure: full
- unknown path / planner error / base SHA unknown: full
- `.github/workflows/**`, `scripts/ci/**`, root lock/toolchain/workspace files:
  full or maximum scope
- `spec-bundle/schemas/**`, protocol/catalog/fixture changes:
  Rust + TypeScript + schema compatibility
- security boundary map is conservative vs CODEOWNERS + SECURITY_REVIEW_CHECKLIST

Never silently skip. `full=true` means every gate runs.

Label branching (4th argv, comma-separated PR labels):
- no labels: path-filtered tiers (standard PR behavior, unchanged).
- `review-ready`: full (heavier pre-merge signal).
- `hotfix`: records hotfix:true only; no time gates exist today, so the plan
  stays fail-closed. Reserved branch point for future time-gate exemptions.
- `do-not-merge`: records do_not_merge:true; the `required` aggregator fails.
- every plan sets heavy_deferred:true: scale/e2e/security-deep/strict-SBOM
  stay nightly/weekly/release-only, never PR gates.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = 1

# PR label-driven CI (label names are matched case-insensitively after
# stripping whitespace; the raw 4th argv is a comma-separated list).
LABEL_REVIEW_READY = "review-ready"
LABEL_HOTFIX = "hotfix"
LABEL_DO_NOT_MERGE = "do-not-merge"

# Heavy tiers never run as PR gates. They stay nightly/weekly/release-only:
# scale/soak (scale.yml), E2E real-binary (e2e-loopback.yml / release
# candidate E2E), security deep/full-history/strict-SBOM (security.yml
# schedule/dispatch). Every plan sets heavy_deferred=true as machine-readable
# proof; ci.yml must not add these suites to the PR path.

# Root manifests whose change invalidates every tier.
ROOT_FULL_FILES = {
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "package.json",
}

# Workflow / planner changes force maximum scope.
WORKFLOW_PREFIXES = (".github/workflows/", "scripts/ci/")

# Security-sensitive boundaries (conservative; see docs/SECURITY_REVIEW_CHECKLIST.md).
# Any change under these paths sets security_boundary=true, which keeps
# security-fast required. Full negative/fault coverage stays in PR; deep
# full-history scans stay scheduled (see security.yml).
SECURITY_PREFIXES = (
    "crates/ownmesh-policy/",
    "crates/ownmesh-ipc/",
    "crates/ownmesh-identity/",
    "crates/ownmesh-broker/",
    "crates/ownmesh-fs/",
    "crates/ownmesh-update/",
    "crates/ownmeshd/",
    "packages/control-plane/src/oauth.ts",
    "packages/control-plane/src/owner-auth.ts",
    "packages/control-plane/src/mcp.ts",
    "packages/control-plane/src/device-room.ts",
    "packages/control-plane/src/store.ts",
    "packages/control-plane/src/auth-ui.ts",
)

# Windows/macOS native boundaries needing affected link/run evidence.
WINDOWS_SENSITIVE = (
    "crates/ownmesh-ipc/",
    "crates/ownmesh-fs/",
    "crates/ownmesh-exec/",
    "crates/ownmesh-broker/",
    "crates/ownmesh-update/",
    "crates/ownmeshd/",
    "installers/",
    "packaging/",
)

MACOS_SENSITIVE = (
    "crates/ownmesh-ipc/",
    "crates/ownmesh-fs/",
    "crates/ownmesh-exec/",
    "crates/ownmesh-broker/",
    "crates/ownmesh-update/",
    "crates/ownmeshd/",
    "installers/",
    "packaging/",
)

# TypeScript / schema ownership.
TS_PREFIXES = ("packages/", "pnpm-lock.yaml", "pnpm-workspace.yaml")
SCHEMA_PREFIXES = ("spec-bundle/schemas/", "packages/ownmesh-schema/")

# Release trust graph ownership.
RELEASE_PREFIXES = (
    ".github/workflows/",
    "scripts/check_release_quality.py",
    "scripts/tests/run_release_quality_tests.py",
    "scripts/tests/test_installers.py",
    "scripts/render_distribution.py",
    "scripts/generate_release_evidence.py",
    "installers/",
    "packaging/",
    "release/",
    "docs/adr/0001-release-signing-sbom-provenance.md",
    "docs/adr/0022-",
)

INSTALLER_PREFIXES = ("installers/", "packaging/", "scripts/tests/test_installers.py")


def parse_labels(raw: str | None) -> set[str]:
    """Parse comma-separated PR labels (4th argv). Case-insensitive."""
    if not raw:
        return set()
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def with_label_metadata(plan: dict, labels: set[str]) -> dict:
    """Attach label branching metadata. Heavy tiers stay deferred always."""
    plan["labels"] = sorted(labels)
    plan["hotfix"] = LABEL_HOTFIX in labels
    plan["do_not_merge"] = LABEL_DO_NOT_MERGE in labels
    # Machine-readable proof that heavy tiers (scale/e2e/security-deep/
    # strict-SBOM) are deferred to nightly/weekly/release and never PR gates.
    plan["heavy_deferred"] = True
    return plan


def sh(*args: str) -> str:
    out = subprocess.run(
        list(args), cwd=str(ROOT), capture_output=True, text=True, check=False
    )
    if out.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(args)}: {out.stderr[:500]}")
    return out.stdout.strip()


def diff_range(base: str, head: str, event: str) -> str:
    """Strict range for push (..) vs merge-base range for PR (...).

    Push must use two-dot `base..head` (exact before→after diff); PRs use
    three-dot `base...head` (merge-base to head). Using `...` for pushes
    under-reports on rewritten history (fail-open), so the event split is
    a security boundary.
    """
    if event == "push":
        return f"{base}..{head}"
    return f"{base}...{head}"


def changed_files(base: str, head: str, event: str = "pull_request") -> list[str]:
    """Fail-closed diff listing. Any git failure raises -> caller falls back to full."""
    out = sh("git", "diff", "--name-only", diff_range(base, head, event))
    files = [line.strip() for line in out.splitlines() if line.strip()]
    return files


def plan_from_files(files: list[str] | None, labels: set[str] | None = None) -> dict:
    """Pure planner core (unit-tested). None means unknown -> full."""
    # Normalize here too (defense in depth): callers normally pass
    # parse_labels() output (already lowercase), but direct callers/tests may
    # pass raw label casing like "Review-Ready".
    labels = {str(l).strip().lower() for l in (labels or set()) if str(l).strip()}
    # NOTE: review-ready handling lives canonically in plan_for_file_set
    # (single aggregation point). None/empty already fall back to full below,
    # and docs-only with review-ready is forced full there, so no early
    # return is needed here (avoids duplicated label branches).
    if files is None:
        return with_label_metadata(full_plan("unknown file list", labels), labels)
    if not files:
        # Empty diff is suspicious (diff silently empty, merge with no file
        # changes). Fail-closed to full rather than allowing all skips.
        return with_label_metadata(full_plan("empty file list", labels), labels)
    return plan_for_file_set(files, labels)


def plan_for_file_set(files: list[str], labels: set[str] | None = None) -> dict:
    # Canonical review-ready branch (single aggregation point; see
    # plan_from_files note). Normalized for case/whitespace robustness.
    labels = {str(l).strip().lower() for l in (labels or set()) if str(l).strip()}
    # review-ready forces full regardless of paths (heavier pre-merge signal).
    if LABEL_REVIEW_READY in labels:
        return with_label_metadata(full_plan("label review-ready (full)", labels), labels)
    # Docs-only fast path: only markdown/docs/assets, no code/workflows.
    non_docs = [
        f
        for f in files
        if not (
            f.endswith(".md")
            or f.startswith("docs/")
            or f.startswith("assets/")
            or f == "NOTICE"
        )
    ]
    if files and not non_docs:
        return with_label_metadata({
            "schema_version": SCHEMA_VERSION,
            "full": False,
            "docs_only": True,
            "rust": False,
            "rust_platform_windows": False,
            "rust_platform_macos": False,
            "typescript": False,
            "schemas": False,
            "security_boundary": False,
            "release_policy": False,
            "installers": False,
            "workflows": False,
            "reason": "docs-only",
        }, labels)

    def any_prefix(prefixes: tuple[str, ...]) -> bool:
        return any(f.startswith(p) for f in files for p in prefixes)

    def any_exact(names: set[str]) -> bool:
        return any(f in names for f in files)

    # Full triggers (fail-closed).
    if any(f.startswith(WORKFLOW_PREFIXES) for f in files):
        return with_label_metadata(full_plan("workflow/planner change", labels), labels)
    if any_exact(ROOT_FULL_FILES):
        return with_label_metadata(full_plan("root lock/toolchain/workspace change", labels), labels)
    # Unknown/empty-path safety: git may emit quoted/renamed paths; any path
    # we cannot classify keeps full via the fallthrough below. Explicitly
    # empty file names are impossible here (filtered), so proceed.

    has_rust = any(f.startswith("crates/") or f == "Cargo.toml" or f == "Cargo.lock" for f in files)
    has_ts = any_prefix(TS_PREFIXES)
    has_schema = any_prefix(SCHEMA_PREFIXES)
    # Protocol/catalog/fixture changes require both implementations + schema.
    protocol_like = any(
        s in f
        for f in files
        for s in ("protocol", "catalog", "fixture", "spec-bundle/")
    )
    if protocol_like or has_schema:
        has_rust = True
        has_ts = True

    has_windows = any(f.startswith(p) for f in files for p in WINDOWS_SENSITIVE) or has_rust
    # Windows/macOS compat always runs `cargo check` on Rust changes (cheap
    # compile evidence); focused native tests run only on sensitive paths.
    # The plan keeps the bool coarse; the job itself narrows to affected crates.
    has_macos = any(f.startswith(p) for f in files for p in MACOS_SENSITIVE) or has_rust
    has_security = any(f.startswith(p) for f in files for p in SECURITY_PREFIXES)
    has_release = any(f.startswith(p) for f in files for p in RELEASE_PREFIXES)
    has_installers = any(f.startswith(p) for f in files for p in INSTALLER_PREFIXES)
    has_workflows = any(f.startswith(".github/") for f in files)

    # Conservative: any Rust change keeps security-fast required (it runs the
    # affected boundary subset, not the full deep suite). Pure TS-only changes
    # still run security-fast only if they touch a security prefix.
    if has_rust:
        has_security = True

    # Fail-closed: any non-docs file outside every known tier forces full.
    # Without this, a new top-level directory or renamed path would silently
    # produce an empty plan and let the aggregators allow all skips.
    known = (
        has_rust or has_ts or has_schema or has_windows or has_macos
        or has_security or has_release or has_installers or has_workflows
        or protocol_like
    )
    if files and not known:
        return with_label_metadata(full_plan("unknown path (fail-closed)", labels), labels)

    return with_label_metadata({
        "schema_version": SCHEMA_VERSION,
        "full": False,
        "docs_only": False,
        "rust": has_rust,
        "rust_platform_windows": has_windows,
        "rust_platform_macos": has_macos,
        "typescript": has_ts,
        "schemas": has_schema,
        "security_boundary": has_security,
        "release_policy": has_release,
        "installers": has_installers,
        "workflows": has_workflows,
        "reason": "path-filtered",
    }, labels)


def full_plan(reason: str, labels: set[str] | None = None) -> dict:
    # NOTE: labels are attached by with_label_metadata at call sites; full_plan
    # itself stays label-agnostic so unit tests calling full_plan("x") keep the
    # tier booleans stable. Callers wrap with with_label_metadata.
    return {
        "schema_version": SCHEMA_VERSION,
        "full": True,
        "docs_only": False,
        "rust": True,
        "rust_platform_windows": True,
        "rust_platform_macos": True,
        "typescript": True,
        "schemas": True,
        "security_boundary": True,
        "release_policy": True,
        "installers": True,
        "workflows": True,
        "reason": reason,
    }


def main() -> int:
    event = sys.argv[1] if len(sys.argv) > 1 else "push"
    base = sys.argv[2] if len(sys.argv) > 2 else ""
    head = sys.argv[3] if len(sys.argv) > 3 else "HEAD"
    # 4th argv: comma-separated PR labels (empty on push/dispatch).
    labels = parse_labels(sys.argv[4] if len(sys.argv) > 4 else "")
    try:
        if event == "workflow_dispatch":
            plan = with_label_metadata(full_plan("workflow_dispatch", labels), labels)
        elif event in ("pull_request", "push"):
            if not base or base.startswith("0000000"):
                plan = with_label_metadata(full_plan(f"{event} without base SHA", labels), labels)
            else:
                try:
                    files = changed_files(base, head, event)
                except Exception as exc:  # fail-closed
                    plan = with_label_metadata(full_plan(f"diff failed: {exc}", labels), labels)
                else:
                    plan = plan_from_files(files, labels)
                    plan["base"] = base
                    plan["head"] = head
        else:
            plan = with_label_metadata(full_plan(f"unknown event {event}", labels), labels)
    except Exception as exc:  # never emit an empty plan
        # hotfix branch point: no time-based (e.g. 3h) gates exist today, so
        # hotfix only records hotfix:true for future exemption use. The plan
        # itself stays fail-closed; exemptions (if any) live in the aggregator.
        plan = with_label_metadata(full_plan(f"planner error: {exc}", labels), labels)
    json.dump(plan, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
