#!/usr/bin/env python3
"""Mandatory real-binary × local Wrangler/workerd loopback suite (E1 + E2/E3)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = [
    ROOT / "scripts" / "tests" / "test_e1_workerd_loopback.py",
    ROOT / "scripts" / "tests" / "test_e2_workerd_loopback.py",
]


def main() -> int:
    for test in TESTS:
        print(f"==> {test.name}")
        result = subprocess.run([sys.executable, str(test)], cwd=ROOT, check=False)
        if result.returncode != 0:
            return result.returncode
    print("E1+E2/E3 workerd loopback suite passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
