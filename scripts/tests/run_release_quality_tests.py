#!/usr/bin/env python3
"""Checker mutation suite only (Issue #230 Phase 3).

Responsibility split (no glob rediscovery):
- `python scripts/tests/test_installers.py` runs installer integration once.
- `python scripts/check_release_quality.py` runs the live checker once.
- This runner runs ONLY the checker unit/mutation tests
  (`test_mutations.py`, `test_action_pins.py`, `test_release_evidence.py`).

Invoked from CI (release-policy job) and locally via:

    python scripts/tests/run_release_quality_tests.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent


def main() -> int:
    print("==> checker mutation suite only (no installer/checker rediscovery)")
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    # Explicit module list: never glob-discover installer/E2E tests here.
    for module in ("test_mutations", "test_action_pins", "test_release_evidence"):
        try:
            suite.addTests(loader.loadTestsFromName(module))
        except Exception as exc:  # fail-closed
            print(f"FAIL: cannot load {module}: {exc}", file=sys.stderr)
            return 1
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        print("FAIL: checker mutation suite", file=sys.stderr)
        return 1
    print("release-quality mutation suite passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
