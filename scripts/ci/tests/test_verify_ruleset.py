"""Unit tests for ruleset verification (Issue #230 Phase 5).

The verifier must assert — not merely print — that the exact required
contexts are enforced on main. These tests cover the pure parsers without
network; live API matching runs in release.yml via --expect-ruleset.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verify_ruleset as vr


def main_ruleset(name="main protection", rid=1, contexts=(),
                 include=("refs/heads/main",), enforcement="active"):
    return {
        "id": rid,
        "name": name,
        "target": "branch",
        "enforcement": enforcement,
        "conditions": {"ref_name": {"include": list(include), "exclude": []}},
        "rules": [{
            "type": "required_status_checks",
            "parameters": {
                "required_status_checks": [
                    {"context": c, "integration_id": 1} for c in contexts
                ],
            },
        }],
    }


class CollectContextsTests(unittest.TestCase):
    def test_collects_contexts_enforced_on_main(self):
        details = [main_ruleset(contexts=("CI / required",
                                          "CI / security-required"))]
        collected = vr.collect_required_contexts(details)
        self.assertEqual(vr.missing_contexts(collected), [])

    def test_missing_context_reported(self):
        details = [main_ruleset(contexts=("CI / required",))]
        missing = vr.missing_contexts(vr.collect_required_contexts(details))
        self.assertEqual(missing, ["CI / security-required"])

    def test_empty_rules_yield_all_missing(self):
        self.assertEqual(
            vr.missing_contexts(vr.collect_required_contexts([main_ruleset()])),
            list(vr.REQUIRED_CONTEXTS))

    def test_non_main_ruleset_does_not_count(self):
        details = [main_ruleset(contexts=vr.REQUIRED_CONTEXTS,
                                include=("refs/heads/release/*",))]
        missing = vr.missing_contexts(vr.collect_required_contexts(details))
        self.assertEqual(missing, list(vr.REQUIRED_CONTEXTS))

    def test_disabled_ruleset_does_not_count(self):
        details = [main_ruleset(contexts=vr.REQUIRED_CONTEXTS,
                                enforcement="disabled")]
        missing = vr.missing_contexts(vr.collect_required_contexts(details))
        self.assertEqual(missing, list(vr.REQUIRED_CONTEXTS))

    def test_non_branch_target_does_not_count(self):
        detail = main_ruleset(contexts=vr.REQUIRED_CONTEXTS)
        detail["target"] = "tag"
        missing = vr.missing_contexts(vr.collect_required_contexts([detail]))
        self.assertEqual(missing, list(vr.REQUIRED_CONTEXTS))

    def test_malformed_entries_ignored_fail_closed(self):
        details = [{"id": 1, "target": "branch", "rules": "not-a-list"},
                   {"id": 2}, "not-a-dict"]
        missing = vr.missing_contexts(vr.collect_required_contexts(details))
        self.assertEqual(missing, list(vr.REQUIRED_CONTEXTS))

    def test_script_documents_real_assertion(self):
        text = (Path(vr.__file__).read_text(encoding="utf-8"))
        for needle in ("required_status_checks", "missing", "fail-closed",
                       "rulesets/{", "REQUIRED_CONTEXTS"):
            self.assertIn(needle, text, needle)
        self.assertNotIn("contexts documented", text)

    def test_all_branches_include_covers_main(self):
        details = [main_ruleset(contexts=vr.REQUIRED_CONTEXTS,
                                include=("~ALL",))]
        self.assertEqual(vr.missing_contexts(vr.collect_required_contexts(details)), [])

    def test_all_branches_exclude_removes_main(self):
        detail = main_ruleset(contexts=vr.REQUIRED_CONTEXTS,
                              include=("~ALL",))
        detail["conditions"]["ref_name"]["exclude"] = ["~ALL"]
        missing = vr.missing_contexts(vr.collect_required_contexts([detail]))
        self.assertEqual(missing, list(vr.REQUIRED_CONTEXTS))


if __name__ == "__main__":
    unittest.main()
