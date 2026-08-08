#!/usr/bin/env python3
"""Mandatory v1.2 E2-E9 real binary x local Wrangler/workerd proof entrypoint.

The SFH verify gate requires this exact path. It always runs the production-path
E2/E3 loopback (public /mcp -> DeviceRoom -> Agent WSS -> ownmeshd runtime).

This file must not weaken gates:
  * any failure of the underlying E2/E3 proof exits non-zero
  * E4-E9 rows without real binary x workerd proof keep this entrypoint red
  * exit 0 is reserved for a complete E2-E9 acceptance set

Partial E2/E3 progress is reported honestly on stdout, but is never treated as
E2-E9 completion.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
E2 = ROOT / "scripts" / "tests" / "test_e2_workerd_loopback.py"
SURFACES = ROOT / "release" / "SUPPORTED_SURFACES.json"

# Acceptance rows that each require the same real binary x local workerd path.
# Do not mark complete from unit tests, parsers, schemas, or markers alone.
E4_E9_ACCEPTANCE_ROWS: tuple[tuple[str, str], ...] = (
    ("E4", "workspace CRUD/enforcement + handle-rooted custody"),
    ("E5", "cloud PTY sessions + controller lease + replay/spool"),
    ("E6", "nine official profile adapters + generic tool execution"),
    ("E7", "bounded unified-diff patch + Git review (no auto-merge)"),
    ("E8", "networkless elevated broker Full Access mint/custody"),
    ("E9", "authenticated resumable transfer send/get/list/status/cancel"),
)


def _registry_open_rows() -> list[str]:
    if not SURFACES.is_file():
        return []
    try:
        data = json.loads(SURFACES.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    open_rows: list[str] = []
    unsupported = data.get("explicit_unsupported") or data.get("unsupported") or []
    if isinstance(unsupported, list):
        for row in unsupported:
            if isinstance(row, str):
                open_rows.append(row)
            elif isinstance(row, dict):
                open_rows.append(str(row.get("id") or row.get("surface") or row))
    return open_rows


def main() -> int:
    if not E2.is_file():
        print(f"missing E2 proof script: {E2}", file=sys.stderr)
        return 1

    print(f"==> {E2.name} (E2/E3 production path)", flush=True)
    result = subprocess.run([sys.executable, str(E2)], cwd=ROOT, check=False)
    if result.returncode != 0:
        print("E2/E3 workerd loopback failed; v1.2 E2-E9 gate red", file=sys.stderr)
        return result.returncode

    print(
        "E2/E3 workerd path PASSED (public MCP write/read/command, resume, "
        "idempotency, cancel, binary cursor, bounds). "
        "This is necessary but not sufficient for E2-E9 completion."
    )

    # Proven real-path rows for this entrypoint. Only list rows with an actual
    # binary x workerd proof script that this gate invokes. Do not paper over.
    # Partial means production path evidence exists but the full acceptance
    # definition for that letter is not yet complete.
    proven_partial = {
        "E2": (
            "public MCP fs list/stat/read/write/patch/delete + structured command "
            "+ raw shell + binary cursor via real ownmeshd"
        ),
        "E3": (
            "exact-action hash + durable idempotency/cancel claim; runtime principal "
            "from bound_action; principal-namespaced journal; tenant_members handoff "
            "(partial - team admin UI still out of scope)"
        ),
        "E4": (
            "device workspaces.json + workspace_id selection + handle/hardlink "
            "custody; component-wise parent create with held-handle rename; "
            "session.open/list/show workspace bind+filter; directory full "
            "snapshot-then-sort cursors; restricted command.run fail-closed; "
            "CLI CRUD still unsupported"
        ),
        "E5": (
            "remote session.open owns live PTY/ConPTY in ownmeshd; public MCP replay "
            "surfaces real process output; attach(observer demote)/write-deny + workspace bind; "
            "input_seq/resize_seq gap/stale reject; two-principal give handoff; "
            "controller lease reconnect matrix still partial"
        ),
        "E7": (
            "MCP git status/diff + private integrity-bound diff spool + fsmonitor off; "
            "unified-diff apply + full review flow still open"
        ),
    }
    # Rows with no real binary×workerd proof yet (must keep gate red).
    still_open = (
        ("E6", "nine official profile adapters + generic tool execution"),
        ("E8", "networkless elevated broker Full Access mint/custody"),
        ("E9", "authenticated resumable transfer send/get/list/status/cancel"),
    )
    # E4/E5/E7 remain incomplete acceptance even with partial proof.
    incomplete_acceptance = (
        ("E4", "workspace CLI CRUD + full custody matrix promotion"),
        ("E5", "controller lease reconnect/handoff + multi-observer replay matrix"),
        ("E7", "bounded unified-diff patch apply + Git review (no auto-merge)"),
        *still_open,
    )

    print("Acceptance matrix:")
    for key, detail in sorted(proven_partial.items()):
        print(f"  [partial] {key}: {detail}")
    for key, detail in still_open:
        print(f"  [OPEN]    {key}: {detail}")

    open_rows = _registry_open_rows()
    if open_rows:
        preview = ", ".join(open_rows[:12])
        more = "" if len(open_rows) <= 12 else f" (+{len(open_rows) - 12} more)"
        print(f"Registry unsupported snapshot: {preview}{more}")

    if incomplete_acceptance:
        print(
            "E2-E9 workerd gate RED: E4-E9 real binary x local Wrangler/workerd "
            "acceptance is not yet complete (partial rows are not completion). "
            "Refusing exit 0 so incomplete work cannot look green.",
            file=sys.stderr,
        )
        print(
            "v1.2 E2-E9 workerd loopback entrypoint: E2/E3/E4/E5/E7 partial; "
            "E6/E8/E9 OPEN; gate fail-closed"
        )
        return 2

    print("v1.2 E2-E9 workerd loopback entrypoint completed (all rows evidenced)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
