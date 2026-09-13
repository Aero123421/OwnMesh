"""Unit tests for the fail-closed change planner (Issue #230).

The planner must never silently skip a required gate. Every test below
asserts that an adversarial or malformed input falls back to full.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import plan


class PlannerTests(unittest.TestCase):
    def test_unknown_file_list_is_full(self):
        p = plan.plan_from_files(None)
        self.assertTrue(p["full"])
        self.assertTrue(p["rust"] and p["typescript"])

    def test_docs_only_is_light(self):
        p = plan.plan_from_files(["README.md", "docs/foo.md"])
        self.assertFalse(p["full"])
        self.assertTrue(p["docs_only"])
        self.assertFalse(p["rust"])
        self.assertFalse(p["typescript"])

    def test_workflow_change_is_full(self):
        p = plan.plan_from_files([".github/workflows/ci.yml"])
        self.assertTrue(p["full"])

    def test_planner_change_is_full(self):
        p = plan.plan_from_files(["scripts/ci/plan.py"])
        self.assertTrue(p["full"])

    def test_root_lockfile_is_full(self):
        for f in ("Cargo.lock", "pnpm-lock.yaml", "rust-toolchain.toml"):
            with self.subTest(f=f):
                self.assertTrue(plan.plan_from_files([f])["full"])

    def test_rust_change_keeps_security_and_platforms(self):
        p = plan.plan_from_files(["crates/ownmesh-fs/src/lib.rs"])
        self.assertTrue(p["rust"])
        self.assertTrue(p["rust_platform_windows"])
        self.assertTrue(p["rust_platform_macos"])
        self.assertTrue(p["security_boundary"])
        self.assertFalse(p["full"])

    def test_typescript_only_skips_rust(self):
        p = plan.plan_from_files(["packages/control-plane/src/mcp.ts"])
        self.assertFalse(p["rust"])
        self.assertTrue(p["typescript"])

    def test_security_boundary_cannot_be_skipped(self):
        # Auth/policy boundary change must keep security-fast required.
        p = plan.plan_from_files(["packages/control-plane/src/oauth.ts"])
        self.assertTrue(p["security_boundary"])
        self.assertTrue(p["typescript"])
        # OS-specific change keeps its owning-OS platform gate.
        q = plan.plan_from_files(["crates/ownmesh-ipc/src/auth.rs"])
        self.assertTrue(q["rust_platform_windows"])

    def test_schema_change_enables_both_implementations(self):
        p = plan.plan_from_files(["spec-bundle/schemas/mcp.json"])
        self.assertTrue(p["rust"] and p["typescript"] and p["schemas"])

    def test_schema_package_keeps_implementations_and_platforms(self):
        # Issue #246: packages/ownmesh-schema is the TS half of contracts the
        # Rust tests also enforce; the per-path classifier must not drop the
        # rust-derived OS/security gates for it.
        p = plan.plan_from_files(["packages/ownmesh-schema/src/envelope.ts"])
        self.assertTrue(p["rust"])
        self.assertTrue(p["typescript"])
        self.assertTrue(p["schemas"])
        self.assertTrue(p["rust_platform_windows"])
        self.assertTrue(p["rust_platform_macos"])
        self.assertTrue(p["security_boundary"])
        self.assertFalse(p["full"])

    def test_protocol_like_change_sets_schema_too(self):
        p = plan.plan_from_files(["crates/ownmesh-protocol/src/lib.rs"])
        self.assertTrue(p["rust"] and p["typescript"] and p["schemas"])

    def test_mixed_docs_path_names_do_not_add_tiers(self):
        p = plan.plan_from_files([
            "packages/control-plane/src/auth-ui.ts",
            "docs/protocol.md",
        ])
        self.assertTrue(p["typescript"])
        self.assertFalse(p["rust"])
        self.assertFalse(p["schemas"])

    def test_unknown_path_is_not_light(self):
        # A path outside every known prefix must fall back to full
        # (fail-closed); it must never produce an empty plan that lets the
        # aggregators allow all skips.
        p = plan.plan_from_files(["totally/new/area/file.xyz"])
        self.assertTrue(p["full"])
        self.assertFalse(p.get("docs_only", False))
        self.assertIn("reason", p)

    def test_empty_file_list_is_full(self):
        p = plan.plan_from_files([])
        self.assertTrue(p["full"])

    def test_windows_sensitive_keeps_windows(self):
        p = plan.plan_from_files(["installers/ownmesh-installer.sh"])
        self.assertTrue(p["installers"])
        self.assertTrue(p["release_policy"])

    def test_release_governance_sets_release_policy(self):
        for f in (".github/CODEOWNERS",
                  ".github/pull_request_template.md",
                  ".coderabbit.yaml"):
            with self.subTest(f=f):
                p = plan.plan_from_files([f])
                self.assertTrue(p["release_policy"], f)


class FailClosedAggregationTests(unittest.TestCase):
    """Issue #246: per-path classification; known paths never mask unknown."""

    UNKNOWN = "new-runtime/entry.py"
    KNOWN_TS = "packages/control-plane/src/auth-ui.ts"
    KNOWN_RUST = "crates/ownmesh-fs/src/lib.rs"
    KNOWN_RELEASE = "installers/ownmesh-installer.sh"
    DOCS = "docs/guide.md"

    def test_unknown_plus_known_is_full(self):
        for extra in (self.KNOWN_TS, self.KNOWN_RUST, self.KNOWN_RELEASE, self.DOCS):
            for files in ([self.UNKNOWN, extra], [extra, self.UNKNOWN]):
                with self.subTest(files=files):
                    self.assertTrue(plan.plan_from_files(files)["full"])

    def test_adding_unknown_never_reduces_required_gates(self):
        base = plan.plan_from_files([self.KNOWN_TS])
        self.assertFalse(base["full"])
        widened = plan.plan_from_files([self.KNOWN_TS, self.UNKNOWN])
        self.assertTrue(widened["full"])
        for key in ("typescript", "rust", "schemas", "security_boundary",
                    "release_policy", "installers", "workflows",
                    "rust_platform_windows", "rust_platform_macos"):
            if base[key]:
                self.assertTrue(widened[key], key)

    def test_order_independent(self):
        a = plan.plan_for_file_set([self.UNKNOWN, self.KNOWN_TS])
        b = plan.plan_for_file_set([self.KNOWN_TS, self.UNKNOWN])
        for key in ("full", "rust", "typescript", "schemas",
                    "security_boundary", "release_policy", "installers",
                    "workflows", "rust_platform_windows", "rust_platform_macos"):
            self.assertEqual(a[key], b[key], key)

    def test_fast_paths_stay_light_without_review_ready(self):
        docs = plan.plan_from_files([self.DOCS])
        self.assertTrue(docs["docs_only"])
        self.assertFalse(docs["full"])
        ts = plan.plan_from_files([self.KNOWN_TS])
        self.assertFalse(ts["rust"])
        self.assertTrue(ts["typescript"])
        rust = plan.plan_from_files([self.KNOWN_RUST])
        self.assertTrue(rust["rust"])
        self.assertFalse(rust["full"])

    def test_any_unknown_path_forces_full_regardless_of_known_set(self):
        known_sets = [
            [self.KNOWN_TS],
            [self.KNOWN_RUST],
            [self.DOCS],
            [self.KNOWN_TS, self.KNOWN_RUST],
        ]
        for known in known_sets:
            with self.subTest(known=known):
                p = plan.plan_from_files([*known, "mystery/tool.cfg"])
                self.assertTrue(p["full"])

    def test_classifier_returns_none_only_for_unowned_paths(self):
        self.assertIsNone(plan._classify_non_docs_path("totally/new/area/file.xyz"))
        for f in (self.KNOWN_TS, self.KNOWN_RUST, self.KNOWN_RELEASE):
            with self.subTest(f=f):
                self.assertTrue(plan._classify_non_docs_path(f))


class LabelBranchingTests(unittest.TestCase):
    def test_no_labels_is_path_filtered(self):
        p = plan.plan_from_files(["crates/ownmesh-fs/src/lib.rs"], set())
        self.assertFalse(p["full"])
        self.assertTrue(p["rust"])
        self.assertFalse(p["hotfix"])
        self.assertFalse(p["do_not_merge"])
        self.assertTrue(p["heavy_deferred"])

    def test_review_ready_forces_full(self):
        p = plan.plan_from_files(["README.md", "docs/foo.md"], {"review-ready"})
        self.assertTrue(p["full"])
        self.assertFalse(p.get("docs_only", False))
        self.assertTrue(p["rust"] and p["typescript"])

    def test_review_ready_labels_arg_parsing(self):
        labels = plan.parse_labels("review-ready, hotfix")
        self.assertIn("review-ready", labels)
        self.assertIn("hotfix", labels)
        self.assertEqual(plan.parse_labels(""), set())
        self.assertEqual(plan.parse_labels(None), set())

    def test_hotfix_records_flag_without_weakening(self):
        p = plan.plan_from_files(["crates/ownmesh-fs/src/lib.rs"], {"hotfix"})
        self.assertTrue(p["hotfix"])
        self.assertFalse(p["do_not_merge"])
        # No time gates exist today: hotfix must not skip tiers by itself.
        self.assertTrue(p["rust"])
        self.assertTrue(p["heavy_deferred"])

    def test_do_not_merge_records_flag(self):
        p = plan.plan_from_files(["crates/ownmesh-fs/src/lib.rs"], {"do-not-merge"})
        self.assertTrue(p["do_not_merge"])
        self.assertFalse(p["hotfix"])
        self.assertTrue(p["heavy_deferred"])

    def test_heavy_always_deferred(self):
        for files in (["crates/ownmesh-fs/src/lib.rs"], ["README.md"], None):
            p = plan.plan_from_files(files, set())
            self.assertTrue(p.get("heavy_deferred", False))

    def test_review_ready_case_insensitive_forces_full(self):
        # "Review-Ready" / padded casing must behave like "review-ready"
        # (plan.py lowercases; ci.yml normalizes via LABELS_LOWER in bash
        # because GitHub expressions have no toLower()).
        for raw in ("Review-Ready", "REVIEW-READY", " review-ready "):
            labels = plan.parse_labels(raw)
            p = plan.plan_from_files(["README.md", "docs/foo.md"], labels)
            with self.subTest(raw=raw):
                self.assertTrue(p["full"])
                self.assertFalse(p.get("docs_only", False))

    def test_plan_label_sets_normalized_directly(self):
        # Direct mixed-case sets are normalized inside the planner too.
        p = plan.plan_from_files(["README.md"], {"Review-Ready"})
        self.assertTrue(p["full"])
        q = plan.plan_for_file_set(["README.md"], {" Review-Ready "})
        self.assertTrue(q["full"])


class GateStrictMatchTests(unittest.TestCase):
    def test_ci_gate_uses_strict_bot_match(self):
        ci = (Path(__file__).parents[3] / ".github/workflows/ci.yml").read_text(
            encoding="utf-8")
        self.assertIn('login.lower() == "coderabbitai[bot]"', ci)
        self.assertNotIn('"coderabbitai" in login.lower()', ci)

    def test_ci_gate_checks_review_state(self):
        ci = (Path(__file__).parents[3] / ".github/workflows/ci.yml").read_text(
            encoding="utf-8")
        for needle in ("APPROVED", "CHANGES_REQUESTED", "COMMENTED"):
            self.assertIn(needle, ci, needle)

    def test_ci_plan_labels_via_env(self):
        ci = (Path(__file__).parents[3] / ".github/workflows/ci.yml").read_text(
            encoding="utf-8")
        self.assertIn("PLAN_LABELS:", ci)
        self.assertNotIn(
            'LABELS="${{ join(github.event.pull_request.labels', ci)

    def test_ci_call_label_match_case_insensitive(self):
        ci = (Path(__file__).parents[3] / ".github/workflows/ci.yml").read_text(
            encoding="utf-8")
        # GitHub Actions expressions have no toLower(): the job `if:` must
        # use an exact match on the canonical label name (see run
        # 34020313728 "Unrecognized function: 'toLower'"); case-insensitive
        # handling lives in bash (LABELS_LOWER) and plan.py.
        self.assertNotIn("toLower(github.event", ci)
        self.assertIn("github.event.label.name == 'review-ready'", ci)
        self.assertIn("LABELS_LOWER", ci)

    def test_ci_pr_types_include_labeled(self):
        # labeled/unlabeled/ready_for_review are non-default PR types; without
        # them the review-ready label and undraft never re-trigger the plan.
        ci = (Path(__file__).parents[3] / ".github/workflows/ci.yml").read_text(
            encoding="utf-8")
        for needle in ("labeled", "unlabeled", "ready_for_review"):
            self.assertIn(needle, ci, needle)

    def test_ci_required_asserts_heavy_deferred(self):
        ci = (Path(__file__).parents[3] / ".github/workflows/ci.yml").read_text(
            encoding="utf-8")
        self.assertIn('heavy_deferred', ci)

    def test_ci_call_full_review_not_suppressed_by_plain_review(self):
        ci = (Path(__file__).parents[3] / ".github/workflows/ci.yml").read_text(
            encoding="utf-8")
        # Full-review request needs its own idempotency needle: a prior plain
        # `review` call must not suppress the first `full review`.
        self.assertIn("REVIEW_CALL_GREPR", ci)
        self.assertIn("@coderabbitai full review", ci)
        self.assertIn('if [[ "$BODY" == *"full review"* ]]', ci)


class DiffRangeTests(unittest.TestCase):
    def test_push_uses_two_dot_strict_range(self):
        self.assertEqual(plan.diff_range("base", "head", "push"), "base..head")

    def test_pr_uses_three_dot_merge_base_range(self):
        self.assertEqual(
            plan.diff_range("base", "head", "pull_request"), "base...head")

    def test_changed_files_push_passes_two_dot_to_git(self):
        seen: list[list[str]] = []
        orig = plan.sh

        def fake(*args: str) -> str:
            seen.append(list(args))
            return "crates/ownmesh-fs/src/lib.rs\n"

        plan.sh = fake  # type: ignore[method-assign]
        try:
            files = plan.changed_files("base", "head", "push")
        finally:
            plan.sh = orig  # type: ignore[method-assign]
        self.assertEqual(files, ["crates/ownmesh-fs/src/lib.rs"])
        self.assertIn("base..head", seen[0])
        self.assertNotIn("base...head", seen[0])

    def test_changed_files_pr_passes_three_dot_to_git(self):
        seen: list[list[str]] = []
        orig = plan.sh

        def fake(*args: str) -> str:
            seen.append(list(args))
            return "crates/ownmesh-fs/src/lib.rs\n"

        plan.sh = fake  # type: ignore[method-assign]
        try:
            plan.changed_files("base", "head", "pull_request")
        finally:
            plan.sh = orig  # type: ignore[method-assign]
        self.assertIn("base...head", seen[0])


class SuitesTests(unittest.TestCase):
    def test_suites_toml_lists_required_suites(self):
        try:
            import tomllib
        except ModuleNotFoundError:
            import tomli as tomllib  # type: ignore[no-redef]
        suites = tomllib.load(open(Path(__file__).parents[1] / "suites.toml", "rb"))
        for name in ("rust-linux", "rust-linux-stateful", "typescript",
                     "platform-windows", "platform-macos", "security-fast",
                     "security-boundary", "release-policy", "tui-i18n",
                     "scale-filesystem"):
            self.assertIn(name, suites, name)

    def test_run_py_dispatches_all_suites(self):
        text = (Path(__file__).parents[1] / "run.py").read_text(encoding="utf-8")
        for name in ("rust-linux-stateful", "platform-windows", "platform-macos",
                     "security-boundary", "tui-i18n"):
            self.assertIn(name, text, name)

    def test_ci_invokes_via_canonical_runner(self):
        ci = (Path(__file__).parents[3] / ".github/workflows/ci.yml").read_text(
            encoding="utf-8")
        for needle in ("scripts/ci/run.py rust-linux",
                       "scripts/ci/run.py typescript",
                       "scripts/ci/run.py platform-windows",
                       "scripts/ci/run.py release-policy",
                       "scripts/ci/run.py tui-i18n",
                       "scripts/ci/run.py security-boundary"):
            self.assertIn(needle, ci, needle)
        for direct in ("run: cargo fmt --all --check",
                       "run: pnpm -r test",
                       "run: cargo run --locked -p ownmesh-tui"):
            self.assertNotIn(direct, ci, direct)


if __name__ == "__main__":
    unittest.main()
