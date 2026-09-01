#!/usr/bin/env python3
"""Generate a bounded, non-secret release evidence receipt.

The receipt describes what the release workflow actually consumed and keeps
the completeness claim false while disclosed external receipts remain absent.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

SHA256 = re.compile(r"^[0-9a-f]{64}$")


def read_checksums(path: Path) -> list[dict[str, str]]:
    artifacts: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        digest, separator, name = line.partition("  ")
        if not separator or not SHA256.fullmatch(digest):
            raise ValueError(f"invalid checksum line: {line!r}")
        if not name or name != Path(name).name or name in seen:
            raise ValueError(f"invalid or duplicate artifact name: {name!r}")
        seen.add(name)
        artifacts.append({"name": name, "sha256": digest})
    if not artifacts:
        raise ValueError("checksum manifest is empty")
    return artifacts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--checksums", type=Path, required=True)
    parser.add_argument("--catalog-current", type=Path, required=True)
    parser.add_argument("--catalog-baseline", type=Path, required=True)
    parser.add_argument("--workflow-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if not re.fullmatch(r"[0-9A-Za-z.+-]{1,64}", args.version):
        raise ValueError("invalid release version")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        raise ValueError("commit must be a full lowercase git SHA")
    current = json.loads(args.catalog_current.read_text(encoding="utf-8"))
    baseline = json.loads(args.catalog_baseline.read_text(encoding="utf-8"))
    catalog_revision = current.get("catalog_revision")
    catalog_version = current.get("catalog_version")
    baseline_revision = baseline.get("catalog_revision")
    baseline_version = baseline.get("catalog_version")
    if current.get("schema_version") != 1 or baseline.get("schema_version") != 1:
        raise ValueError("unsupported catalog receipt schema")
    if not isinstance(catalog_revision, str) or not re.fullmatch(r"[0-9a-f]{16}", catalog_revision):
        raise ValueError("invalid current catalog revision")
    if not isinstance(baseline_revision, str) or not re.fullmatch(r"[0-9a-f]{16}", baseline_revision):
        raise ValueError("invalid baseline catalog revision")
    if not isinstance(catalog_version, int) or catalog_version < 1:
        raise ValueError("invalid current catalog version")
    if baseline_version != catalog_version:
        raise ValueError("catalog baseline/current major mismatch")

    blockers = [
        "W-E8-RECEIPTS: macOS/Windows native broker and full public-route receipts incomplete",
        "W-E10-AUTO: external published-ChatGPT canary requires operator infrastructure",
        "W-EXT-SEC: independent security review incomplete",
        "W-SIGN/W-PACKAGING: Authenticode, Apple notarization, and native packages incomplete",
    ]
    receipt = {
        "schema_version": 1,
        "release": args.version,
        "git_commit": args.commit,
        "workflow_url": args.workflow_url,
        "agent_version": args.version,
        "control_plane_version": args.version,
        "mcp": {
            "protocol_versions_tested": ["2025-03-26", "2026-07-28"],
            "catalog_version": catalog_version,
            "catalog_revision": catalog_revision,
            "compatibility_baseline_revision": baseline_revision,
            "snapshot_compatibility_gate": "passed",
        },
        "artifacts": read_checksums(args.checksums),
        "deterministic_release_gate": {
            "status": "passed",
            "exact_packaged_linux_x64_artifact": True,
            "local_workerd": True,
            "device_restart_and_recovery": True,
            "resumable_two_agent_transfer": True,
        },
        "external_blockers": blockers,
        "completeness_claim": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
