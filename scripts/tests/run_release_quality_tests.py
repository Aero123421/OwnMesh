#!/usr/bin/env python3
"""Runner for release-quality checker unit + mutation tests.

Invoked from CI (release-truthfulness job) and locally via:

    python scripts/tests/run_release_quality_tests.py
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
ROOT = TESTS_DIR.parents[1]
CHECKER = ROOT / "scripts" / "check_release_quality.py"


def main() -> int:
    failures = 0

    # 1. Live repository must satisfy the checker.
    print("==> check_release_quality (live repo)")
    live = subprocess.run(
        [sys.executable, str(CHECKER)],
        cwd=str(ROOT),
        check=False,
    )
    if live.returncode != 0:
        print("FAIL: live checker", file=sys.stderr)
        failures += 1
    else:
        print("PASS: live checker")

    # 2. Fixture + mutation tests under scripts/tests/.
    print("==> unittest discover scripts/tests")
    loader = unittest.TestLoader()
    suite = loader.discover(str(TESTS_DIR), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        print("FAIL: unittest discover", file=sys.stderr)
        failures += 1
    else:
        print("PASS: unittest discover")

    if failures:
        print(f"release-quality test runner failed ({failures} step(s))", file=sys.stderr)
        return 1
    print("release-quality test runner passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
