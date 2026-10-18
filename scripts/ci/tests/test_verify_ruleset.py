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

    def test_only_explicit_active_enforcement_counts(self):
        for enforcement in ("evaluate", None, "unknown", "ACTIVE"):
            with self.subTest(enforcement=enforcement):
                details = [main_ruleset(contexts=vr.REQUIRED_CONTEXTS,
                                        enforcement=enforcement)]
                missing = vr.missing_contexts(
                    vr.collect_required_contexts(details))
                self.assertEqual(missing, list(vr.REQUIRED_CONTEXTS))

    def test_missing_enforcement_does_not_count(self):
        detail = main_ruleset(contexts=vr.REQUIRED_CONTEXTS)
        del detail["enforcement"]
        missing = vr.missing_contexts(vr.collect_required_contexts([detail]))
        self.assertEqual(missing, list(vr.REQUIRED_CONTEXTS))

    def test_malformed_ref_conditions_do_not_count(self):
        malformed = [
            None,
            {},
            {"ref_name": None},
            {"ref_name": {"include": []}},
            {"ref_name": {"include": "refs/heads/main", "exclude": []}},
            {"ref_name": {"include": ["refs/heads/main"],
                           "exclude": "refs/heads/release/*"}},
            {"ref_name": {"include": ["refs/heads/main", None],
                           "exclude": []}},
        ]
        for conditions in malformed:
            with self.subTest(conditions=conditions):
                detail = main_ruleset(contexts=vr.REQUIRED_CONTEXTS)
                detail["conditions"] = conditions
                missing = vr.missing_contexts(
                    vr.collect_required_contexts([detail]))
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

    def test_default_branch_include_and_exclude_are_consistent(self):
        included = main_ruleset(contexts=vr.REQUIRED_CONTEXTS,
                                include=("~DEFAULT_BRANCH",))
        self.assertEqual(
            vr.missing_contexts(vr.collect_required_contexts(
                [included], default_branch="main")), [])
        self.assertEqual(
            vr.missing_contexts(vr.collect_required_contexts(
                [included], default_branch="master")),
            list(vr.REQUIRED_CONTEXTS))
        self.assertEqual(
            vr.missing_contexts(vr.collect_required_contexts(
                [included], default_branch=None)),
            list(vr.REQUIRED_CONTEXTS))
        excluded = main_ruleset(contexts=vr.REQUIRED_CONTEXTS,
                                include=("~ALL",))
        excluded["conditions"]["ref_name"]["exclude"] = ["~DEFAULT_BRANCH"]
        self.assertEqual(
            vr.missing_contexts(vr.collect_required_contexts(
                [excluded], default_branch="main")),
            list(vr.REQUIRED_CONTEXTS))
        self.assertEqual(
            vr.missing_contexts(vr.collect_required_contexts(
                [excluded], default_branch="master")), [])

    def test_path_aware_ref_patterns(self):
        for pattern in ("refs/*", "*main", "refs/heads/release/*",
                        "refs**main", "refs/**main", "**", "refs/**",
                        "refs[!x]heads[!x]main"):
            with self.subTest(pattern=pattern):
                detail = main_ruleset(contexts=vr.REQUIRED_CONTEXTS,
                                      include=(pattern,))
                missing = vr.missing_contexts(vr.collect_required_contexts(
                    [detail], default_branch="main"))
                self.assertEqual(missing, list(vr.REQUIRED_CONTEXTS))

        # The same patterns must not exclude main merely because their
        # wildcard or class syntax is overbroad in Python's fnmatch.
        for pattern in ("refs/*", "*main", "refs/heads/release/*",
                        "**", "refs/**"):
            with self.subTest(exclude=pattern):
                detail = main_ruleset(contexts=vr.REQUIRED_CONTEXTS,
                                      include=("~ALL",))
                detail["conditions"]["ref_name"]["exclude"] = [pattern]
                self.assertEqual(
                    vr.missing_contexts(vr.collect_required_contexts(
                        [detail], default_branch="main")), [])

        # Unsupported forms are rejected conservatively, including in an
        # exclude filter, rather than being allowed to prove coverage.
        for pattern in ("refs**main", "refs/**main",
                        "refs[!x]heads[!x]main"):
            with self.subTest(unsupported_exclude=pattern):
                detail = main_ruleset(contexts=vr.REQUIRED_CONTEXTS,
                                      include=("~ALL",))
                detail["conditions"]["ref_name"]["exclude"] = [pattern]
                self.assertEqual(
                    vr.missing_contexts(vr.collect_required_contexts(
                        [detail], default_branch="main")),
                    list(vr.REQUIRED_CONTEXTS))

        detail = main_ruleset(contexts=vr.REQUIRED_CONTEXTS,
                              include=("refs/heads/*",))
        self.assertEqual(
            vr.missing_contexts(vr.collect_required_contexts(
                [detail], default_branch="main")), [])
        recursive = main_ruleset(contexts=vr.REQUIRED_CONTEXTS,
                                 include=("refs/heads/**/*",))
        self.assertEqual(
            vr.missing_contexts(vr.collect_required_contexts(
                [recursive], default_branch="main")), [])


if __name__ == "__main__":
    unittest.main()
