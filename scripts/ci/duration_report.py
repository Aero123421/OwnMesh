#!/usr/bin/env python3
"""CI duration / runner-minute baseline collector (Issue #230 Phase 0).

Fetches the last N completed runs for a workflow via `gh` and prints
p50/p95 durations per job plus runner-minute estimates. No secrets are
printed. Used once to establish the SLO baseline, then weekly to track
the top slow suites and cache ROI.

SLO evaluation (docs/ci-test-tiers.md)::

    docs-only PR required checks      p95 <= 2 min
    Rust code PR critical path        p50 <= 6 min, p95 <= 10 min
    tag -> release build start        p95 <= 2 min
    typical Rust/TS-only runner-min   >=50% below pre-tier baseline

Usage:
    python scripts/ci/duration_report.py --workflow ci.yml --limit 20
    python scripts/ci/duration_report.py --current current.json \\
        --baseline baseline.json --check-slo --top 5
    python scripts/ci/duration_report.py --workflow ci.yml --limit 20 \\
        --json-output current.json
"""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
from pathlib import Path

# SLO thresholds from docs/ci-test-tiers.md (minutes / ratio). Single source
# for the operator contract; --check-slo enforces these fail-closed.
DOCS_ONLY_P95_MAX = 2.0
RUST_P50_MAX = 6.0
RUST_P95_MAX = 10.0
TAG_TO_BUILD_P95_MAX = 2.0
RUNNER_MIN_REDUCTION_MIN = 0.50


def gh(*args: str) -> str:
    out = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if out.returncode != 0:
        raise RuntimeError(out.stderr[:1000])
    return out.stdout


def percentile(sorted_vals: list[float], pct: float) -> float:
    """Nearest-rank percentile over an already-sorted list.

    Rank = ceil(pct/100 * N); the result is the rank-th 1-based value,
    i.e. index ``ceil(pct/100*N) - 1`` clamped into range.
    """
    if not sorted_vals:
        raise ValueError("empty data")
    rank = math.ceil(pct / 100.0 * len(sorted_vals))
    idx = min(len(sorted_vals) - 1, max(0, rank - 1))
    return sorted_vals[idx]


def summarize_durations(durations: list[float]) -> dict[str, float]:
    ordered = sorted(durations)
    return {
        "runs": float(len(ordered)),
        "p50": percentile(ordered, 50),
        "p95": percentile(ordered, 95),
        "max": ordered[-1],
    }


def load_json_file(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RuntimeError(f"metrics file not found: {path}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"metrics file {path} is not valid JSON: {exc}")


def get_number(metrics: dict, *keys: str) -> float | None:
    """Return the first present numeric key (supports legacy aliases)."""
    for key in keys:
        val = metrics.get(key)
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            return float(val)
    return None


def top_slow_suites(metrics: dict, limit: int) -> list[tuple[str, float]]:
    suites = metrics.get("suites", metrics.get("slow_suites", []))
    ranked: list[tuple[str, float]] = []
    if isinstance(suites, list):
        for entry in suites:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name", entry.get("suite", "unknown")))
            dur = entry.get("duration_min", entry.get("minutes", entry.get("p95")))
            if isinstance(dur, (int, float)) and not isinstance(dur, bool):
                ranked.append((name, float(dur)))
    ranked.sort(key=lambda item: item[1], reverse=True)
    return ranked[: max(0, limit)]


def format_top_suites(ranked: list[tuple[str, float]]) -> str:
    if not ranked:
        return "(no per-suite breakdown; use `gh run view <id> --json jobs` for top slow suites)"
    lines = ["top slow suites:"]
    for name, minutes in ranked:
        lines.append(f"  - {name}: {minutes:.1f} min")
    return "\n".join(lines)


def evaluate_slo(current: dict, baseline: dict | None) -> tuple[list[str], list[str]]:
    """Pure SLO evaluator. Returns (failures, passes); never touches network."""
    failures: list[str] = []
    passes: list[str] = []

    def check(label: str, value: float | None, maximum: float, unit: str = "min") -> None:
        if value is None:
            failures.append(f"{label}: missing metric (fail-closed)")
        elif value <= maximum:
            passes.append(f"{label}: {value:.2f}{unit} <= {maximum:.2f}{unit}")
        else:
            failures.append(f"{label}: {value:.2f}{unit} > {maximum:.2f}{unit}")

    check("docs-only p95", get_number(current, "docs_only_p95", "docs-only-p95",
                                      "docs_only_p95_min"), DOCS_ONLY_P95_MAX)
    check("Rust p95", get_number(current, "rust_p95", "rust-p95",
                                 "rust_p95_min"), RUST_P95_MAX)
    check("Rust p50", get_number(current, "rust_p50", "rust-p50",
                                  "rust_p50_min"), RUST_P50_MAX)
    check("tag-to-build p95", get_number(current, "tag_to_build_p95",
                                         "tag-to-build-p95", "tag_to_build_p95_min"),
          TAG_TO_BUILD_P95_MAX)

    baseline_minutes = None
    if baseline is not None:
        baseline_minutes = get_number(baseline, "runner_minutes_baseline",
                                      "runner_minutes", "baseline_runner_minutes")
    current_minutes = get_number(current, "runner_minutes_current",
                                 "runner_minutes", "current_runner_minutes")
    # Baseline file may itself carry both sides (previous report format).
    if baseline_minutes is None and baseline is not None:
        baseline_minutes = get_number(baseline, "runner_minutes_current",
                                      "runner_minutes")
    if baseline is None:
        passes.append("runner-min: skipped (no --baseline; needs pre-tier reference)")
    elif baseline_minutes is None or current_minutes is None:
        failures.append("runner-min: missing baseline/current minutes (fail-closed)")
    elif baseline_minutes <= 0:
        failures.append("runner-min: non-positive baseline (fail-closed)")
    else:
        reduction = (baseline_minutes - current_minutes) / baseline_minutes
        if reduction >= RUNNER_MIN_REDUCTION_MIN:
            passes.append(
                f"runner-min: {reduction * 100:.1f}% reduction "
                f"({baseline_minutes:.1f} -> {current_minutes:.1f} min) >= 50%"
            )
        else:
            failures.append(
                f"runner-min: {reduction * 100:.1f}% reduction "
                f"({baseline_minutes:.1f} -> {current_minutes:.1f} min) < 50%"
            )
    return failures, passes


def fetch_workflow_durations(workflow: str, limit: int) -> list[float]:
    runs_json = gh("run", "list", "--workflow", workflow, "--limit", str(limit),
                   "--json", "databaseId,status,conclusion,createdAt,updatedAt")
    runs = json.loads(runs_json)
    durations = []
    for run in runs:
        try:
            from datetime import datetime
            start = datetime.fromisoformat(run["createdAt"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(run["updatedAt"].replace("Z", "+00:00"))
            durations.append((end - start).total_seconds() / 60.0)
        except Exception:
            continue
    return durations


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workflow", default="ci.yml")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--baseline", default="",
                    help="baseline JSON file for runner-minute comparison")
    ap.add_argument("--current", default="",
                    help="current metrics JSON file (skips gh fetch; for tests/CI)")
    ap.add_argument("--check-slo", action="store_true",
                    help="evaluate SLOs fail-closed; non-zero exit on miss")
    ap.add_argument("--top", type=int, default=5,
                    help="number of slow suites to display on SLO miss")
    ap.add_argument("--json-output", default="",
                    help="write fetched summary metrics as JSON to PATH")
    args = ap.parse_args()

    baseline: dict | None = None
    if args.baseline:
        try:
            baseline = load_json_file(args.baseline)
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    current: dict | None = None
    if args.current:
        try:
            current = load_json_file(args.current)
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    if current is None and not args.check_slo:
        # Legacy collector path (best-effort; never fails the gate).
        try:
            durations = fetch_workflow_durations(args.workflow, args.limit)
        except RuntimeError as exc:
            print(f"duration fetch failed: {exc}", file=sys.stderr)
            return 1
        if not durations:
            print("no completed runs found")
            return 1
        summary = summarize_durations(durations)
        print(f"workflow={args.workflow} runs={len(durations)}")
        print(f"duration_min_p50={summary['p50']:.1f} "
              f"p95={summary['p95']:.1f} max={summary['max']:.1f}")
        print("note: per-job breakdown requires jobs API; "
              "use `gh run view <id> --json jobs` for top slow suites")
        if args.json_output:
            payload = {
                "workflow": args.workflow,
                "runs": len(durations),
                "duration_min_p50": summary["p50"],
                "duration_min_p95": summary["p95"],
                "duration_min_max": summary["max"],
            }
            Path(args.json_output).write_text(json.dumps(payload, indent=2) + "\n",
                                              encoding="utf-8")
            print(f"wrote {args.json_output}")
        if baseline is not None:
            print("note: --baseline comparison requires --current metrics with "
                  "runner_minutes; live workflow p95 alone cannot prove the "
                  "50% runner-minute SLO", file=sys.stderr)
        return 0

    # SLO evaluation path (fail-closed when --check-slo).
    if current is None:
        # No --current file: derive what we can from live gh data, then
        # fail-closed on the missing per-tier breakdown.
        try:
            durations = fetch_workflow_durations(args.workflow, args.limit)
        except RuntimeError as exc:
            print(f"ERROR: duration fetch failed: {exc}", file=sys.stderr)
            return 1
        if not durations:
            print("ERROR: no completed runs found", file=sys.stderr)
            return 1
        summary = summarize_durations(durations)
        current = {
            "workflow": args.workflow,
            "runs": len(durations),
            "rust_p95": summary["p95"],
            "rust_p50": summary["p50"],
        }
        print(f"workflow={args.workflow} runs={len(durations)} "
              f"p50={summary['p50']:.1f} p95={summary['p95']:.1f}")
        print("note: live gh summary lacks docs-only/tag-to-build/runner-min "
              "split; provide --current JSON for full SLO proof")

    failures, passes = evaluate_slo(current, baseline)
    for line in passes:
        print(f"PASS: {line}")
    ranked = top_slow_suites(current, args.top)
    if failures:
        for line in failures:
            print(f"SLO miss: {line}", file=sys.stderr)
        print(format_top_suites(ranked))
        if args.check_slo:
            return 1
        return 0
    print(format_top_suites(ranked) if ranked else "SLOs met")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
