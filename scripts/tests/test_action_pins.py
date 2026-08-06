#!/usr/bin/env python3
"""Fixture tests for external Actions SHA-pin enforcement."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = TESTS_DIR.parent
FIXTURES = TESTS_DIR / "fixtures" / "workflows"
sys.path.insert(0, str(SCRIPTS_DIR))

from check_release_quality import find_action_uses, find_mutable_action_pins  # noqa: E402


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class ActionPinFixtureTests(unittest.TestCase):
    def test_detects_dash_uses_and_mapping_uses(self) -> None:
        text = _load("good_pins.yml")
        refs = find_action_uses(text)
        # one local reusable workflow + four external + one local composite
        self.assertEqual(len(refs), 6)
        self.assertTrue(any(r.startswith("actions/checkout@") for r in refs))
        self.assertTrue(any(r.startswith("./") for r in refs))
        # dash form
        self.assertIn(
            "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
            refs,
        )
        # mapping form (indented under - name:)
        self.assertIn(
            "dtolnay/rust-toolchain@6c977a6ca4077a0ceb28ffbe03f59d46e9ac8772",
            refs,
        )

    def test_good_pins_pass(self) -> None:
        mutable = find_mutable_action_pins(_load("good_pins.yml"))
        self.assertEqual(mutable, [], f"expected no mutable pins, got {mutable}")

    def test_local_refs_exempt(self) -> None:
        text = _load("good_pins.yml")
        refs = find_action_uses(text)
        locals_ = [r for r in refs if r.startswith("./")]
        self.assertGreaterEqual(len(locals_), 2)
        mutable = find_mutable_action_pins(text)
        for ref in locals_:
            self.assertNotIn(ref, mutable)

    def test_reject_tag_pin(self) -> None:
        mutable = find_mutable_action_pins(_load("bad_pin_tag.yml"))
        self.assertTrue(mutable, "tag pins must be rejected")
        self.assertTrue(any(r.endswith("@v4") for r in mutable), mutable)

    def test_reject_branch_pin(self) -> None:
        mutable = find_mutable_action_pins(_load("bad_pin_branch.yml"))
        self.assertTrue(mutable, "branch pins must be rejected")
        self.assertTrue(any("@main" in r or "@master" in r for r in mutable), mutable)

    def test_reject_short_sha(self) -> None:
        mutable = find_mutable_action_pins(_load("bad_pin_short_sha.yml"))
        self.assertTrue(mutable, "39-char SHAs must be rejected")
        for ref in mutable:
            pin = ref.rsplit("@", 1)[-1]
            self.assertEqual(len(pin), 39, ref)
            self.assertNotEqual(len(pin), 40)

    def test_reject_missing_pin(self) -> None:
        mutable = find_mutable_action_pins(_load("bad_pin_missing.yml"))
        self.assertTrue(mutable, "unpinned actions must be rejected")
        self.assertTrue(all("@" not in r for r in mutable), mutable)

    def test_dash_form_tag_is_not_missed(self) -> None:
        """Regression: old regex `^\\s*uses:` skipped `- uses:` lines entirely."""
        text = "jobs:\n  j:\n    steps:\n      - uses: actions/checkout@v4\n"
        mutable = find_mutable_action_pins(text)
        self.assertEqual(mutable, ["actions/checkout@v4"])


if __name__ == "__main__":
    raise SystemExit(0 if unittest.main(verbosity=2) is None else 1)
