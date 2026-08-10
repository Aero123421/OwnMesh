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
E9 = ROOT / "scripts" / "tests" / "test_e9_workerd_transfer.py"
SURFACES = ROOT / "release" / "SUPPORTED_SURFACES.json"

# Acceptance rows that each require the same real binary x local workerd path.
# Do not mark complete from unit tests, parsers, schemas, or markers alone.
E4_E9_ACCEPTANCE_ROWS: tuple[tuple[str, str], ...] = (
    ("E4", "workspace CRUD/enforcement + handle-rooted custody"),
    ("E5", "cloud PTY sessions + controller lease + replay/spool"),
    ("E6", "nine official profile adapters + generic tool execution"),
    ("E7", "bounded unified-diff patch + Git review (no auto-merge)"),
    (
        "E8",
        "networkless elevated broker Full Access mint/custody; Windows SCM dispatcher exists but SYSTEM enrollment migration/install is intentionally OPEN",
    ),
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

    if not E9.is_file():
        print(f"missing E9 proof script: {E9}", file=sys.stderr)
        return 1
    print(f"==> {E9.name} (E9 public two-Agent production path)", flush=True)
    result = subprocess.run([sys.executable, str(E9)], cwd=ROOT, check=False)
    if result.returncode != 0:
        print("E9 public two-Agent workerd proof failed; v1.2 E2-E9 gate red", file=sys.stderr)
        return result.returncode

    # Proven real-path rows for this entrypoint. Only list rows with an actual
    # binary x workerd proof script that this gate invokes. Do not paper over.
    # Partial means production path evidence exists but the full acceptance
    # definition for that letter is not yet complete.
    proven_complete = {
        "E4": (
            "workspace CRUD/enforcement + handle-rooted custody on the real "
            "public MCP/workerd/Agent/ownmeshd route"
        ),
        "E5": (
            "persistent sidecar PTY with exact controller leases, raw bounded "
            "cursor replay for multiple workspace-granted observers, daemon/Agent "
            "restart reattach retaining the same PTY PID and output, handoff/detach/"
            "expiry reclaim, and stale token/nonce mutation denial"
        ),
        "E6": (
            "nine official profile adapters plus a generic CLI through public "
            "MCP/workerd/Agent/ownmeshd: strict Codex and ACP handshakes, "
            "bounded raw cursor replay, delayed turn completion, safe auth "
            "status, native argv/negotiated resume, explicit unsupported "
            "resume rejection, and exact sidecar cleanup"
        ),
        "E7": (
            "nested temporary Git repository through public MCP/workerd/Agent/"
            "ownmeshd: pinned argv-only `git apply` changes two files without ref "
            "or index mutation; separate pass/fail tests; bounded status/diff and "
            "typed multi-page digest/cursor output; idempotency/conflict, ACL "
            "cross-workspace and invalid-repository rejection, stale-HEAD denial, "
            "and generic exact-bound cancellation reaching process-tree termination"
        ),
        "E9": (
            "public MCP/workerd/TransferRoom with two distinct real Agent/ownmeshd "
            "identities: bounded binary and zero-byte send/get/list/status, exact "
            "artifact paging/hash, 32 MiB destination disconnect/restart from the "
            "durable ACK cursor under a fresh epoch/fence, partial cancellation "
            "cleanup, no-overwrite and owner/tenant/workspace binding denials, plus "
            "stopped D1/DO SQLite integrity and secret/relay-byte at-rest inspection"
        ),
    }
    proven_partial = {
        "E2": (
            "public MCP fs list/stat/read/write/patch/delete + structured command "
            "+ raw shell + binary cursor via real ownmeshd"
        ),
        "E3": (
            "exact-action hash + durable idempotency/cancel claim; MCP per-tool arg "
            "allowlist; runtime principal from bound_action; principal-namespaced journal; "
            "session.open denied under recommended/workspace_only; recommended Ask retains "
            "remote operation_id; browser /approve recovery executes deferred side effect "
            "exactly once via device approval resolution; tenant_members handoff "
            "(partial - team admin UI still out of scope)"
        ),
    }
    # Rows with no complete real binary×workerd proof yet (must keep gate red).
    still_open = (
        (
            "E8",
            "networkless elevated broker Full Access mint/custody; Windows SCM dispatcher exists but SYSTEM enrollment migration/install is intentionally OPEN",
        ),
    )
    # E4-E7/E9 have real workerd acceptance; E8 stays fail-closed.
    incomplete_acceptance = (
        *still_open,
    )

    print("Acceptance matrix:")
    for key, detail in sorted(proven_complete.items()):
        print(f"  [PROVEN]  {key}: {detail}")
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
            "E2-E9 workerd gate RED: E8 real binary x local Wrangler/workerd "
            "acceptance is not yet complete (partial rows are not completion). "
            "Refusing exit 0 so incomplete work cannot look green.",
            file=sys.stderr,
        )
        print(
            "v1.2 E2-E9 workerd loopback entrypoint: E2-E7/E9 proven; "
            "E8 OPEN; gate fail-closed"
        )
        return 2

    print("v1.2 E2-E9 workerd loopback entrypoint completed (all rows evidenced)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
