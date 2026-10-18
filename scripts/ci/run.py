#!/usr/bin/env python3
"""Canonical CI runner (Issue #230).

Single source of truth for suite commands is `scripts/ci/suites.toml`.
`.github/workflows/ci.yml` holds orchestration/permissions/OS only and invokes
each suite via `python3 scripts/ci/run.py <suite>`; CONTRIBUTING.md and local
runs use the same entrypoint. Thin argv-list layer only.

Usage:
    python scripts/ci/run.py rust-linux
    python scripts/ci/run.py rust-linux-stateful
    python scripts/ci/run.py typescript
    python scripts/ci/run.py platform-windows
    python scripts/ci/run.py platform-macos
    python scripts/ci/run.py platform --os windows --scope affected
    python scripts/ci/run.py security-fast
    python scripts/ci/run.py security-boundary
    python scripts/ci/run.py scale --suite filesystem
    python scripts/ci/run.py release-policy
    python scripts/ci/run.py tui-i18n
    python scripts/ci/run.py --list
"""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11 fallback (runners use 3.11+)
    import tomli as tomllib  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[2]
SUITES = ROOT / "scripts" / "ci" / "suites.toml"


def load_suites() -> dict:
    with open(SUITES, "rb") as fh:
        return tomllib.load(fh)


def run_command(cmd: str) -> int:
    print(f"+ {cmd}", flush=True)
    proc = subprocess.run(shlex.split(cmd), cwd=str(ROOT), check=False)
    return proc.returncode


def cmd_rust_linux(suites: dict) -> list[str]:
    return list(suites["rust-linux"]["commands"])


def cmd_rust_linux_stateful(suites: dict) -> list[str]:
    return list(suites["rust-linux-stateful"]["commands"])


def cmd_typescript(suites: dict) -> list[str]:
    return list(suites["typescript"]["commands"])


def cmd_release_policy(suites: dict) -> list[str]:
    return list(suites["release-policy"]["commands"])


def cmd_security_fast(suites: dict) -> list[str]:
    # Single source of truth is scripts/ci/suites.toml [security-fast].
    # CI wraps the same scan in the pinned gitleaks action (upload/summary);
    # local runs execute this canonical command.
    return list(suites["security-fast"]["commands"])


def cmd_security_boundary(suites: dict) -> list[str]:
    return list(suites["security-boundary"]["commands"])


def cmd_platform(suites: dict, os_name: str) -> list[str]:
    # Single source is suites.toml [platform-windows]/[platform-macos].
    # The `platform --os` wrapper exists for local convenience only.
    key = "platform-windows" if os_name == "windows" else "platform-macos"
    return list(suites[key]["commands"])


def cmd_tui_i18n(suites: dict) -> list[str]:
    return list(suites["tui-i18n"]["commands"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OwnMesh canonical CI runner")
    parser.add_argument("--list", action="store_true", help="list known suites")
    parser.add_argument("suite", nargs="?", help="suite name")
    parser.add_argument("--os", dest="os", default="", help="platform OS for platform suite")
    parser.add_argument("--scope", default="affected", help="affected|full (platform only)")
    parser.add_argument("--suite-name", dest="scale_suite", default="filesystem",
                        help="scale suite name (scale only)")
    args = parser.parse_args(argv)

    suites = load_suites()
    if args.list:
        for name in sorted(suites):
            print(f"{name}: {suites[name].get('description', '')}")
        return 0

    if not args.suite:
        print("unknown suite: (empty)", file=sys.stderr)
        return 2

    commands: list[str] = []
    if args.suite == "rust-linux":
        commands = cmd_rust_linux(suites)
    elif args.suite == "rust-linux-stateful":
        commands = cmd_rust_linux_stateful(suites)
    elif args.suite == "typescript":
        commands = cmd_typescript(suites)
    elif args.suite == "release-policy":
        commands = cmd_release_policy(suites)
    elif args.suite == "platform-windows":
        commands = cmd_platform(suites, "windows")
    elif args.suite == "platform-macos":
        commands = cmd_platform(suites, "macos")
    elif args.suite == "platform":
        if args.os not in ("windows", "macos"):
            print(f"unknown platform os: {args.os!r}", file=sys.stderr)
            return 2
        if args.scope not in ("affected", "full"):
            print(f"unknown scope: {args.scope!r}", file=sys.stderr)
            return 2
        # Affected and full currently resolve to the same canonical
        # suites.toml set (check + affected native link/run evidence).
        # The flag is retained for forward compatibility; both stay
        # single-sourced from suites.toml via cmd_platform.
        commands = cmd_platform(suites, args.os)
    elif args.suite == "security-fast":
        # Changed-range secret scan. Full history scans and full adversarial
        # corpora stay in scheduled security.yml.
        commands = cmd_security_fast(suites)
    elif args.suite == "security-boundary":
        commands = cmd_security_boundary(suites)
    elif args.suite == "tui-i18n":
        commands = cmd_tui_i18n(suites)
    elif args.suite == "scale":
        if args.scale_suite == "filesystem":
            commands = list(suites["scale-filesystem"]["commands"])
        else:
            print(f"unknown scale suite: {args.scale_suite!r}", file=sys.stderr)
            return 2
    else:
        print(f"unknown suite: {args.suite!r}", file=sys.stderr)
        return 2

    rc = 0
    for cmd in commands:
        code = run_command(cmd)
        if code != 0:
            rc = code
            print(f"suite {args.suite} failed at: {cmd}", file=sys.stderr)
            break
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
