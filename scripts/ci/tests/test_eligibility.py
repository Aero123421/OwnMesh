"""Unit tests for exact-SHA release eligibility (Issue #230 Phase 4).

Stale/forged/missing/canceled/skipped/neutral evidence must all be rejected.
These tests run the pure validation helpers without network by invoking
`release_eligibility.py --allow-missing-checks` only for tag/ancestry/toolchain
paths, plus direct mutation fixtures for the check-run logic.

`--allow-missing-checks` is local-dry-run-only: it is rejected when
GITHUB_ACTIONS=true and recorded as dry_run:true in evidence, so a
one-line PR cannot silently downgrade the release gate.
"""

import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "ci" / "release_eligibility.py"

sys.path.insert(0, str(ROOT / "scripts" / "ci"))
import release_eligibility as eligibility


SHA = "a" * 40
OTHER_SHA = "b" * 40


def good_check(name="CI / required", sha=SHA, run_id=123):
    return {
        "name": name,
        "head_sha": sha,
        "status": "completed",
        "conclusion": "success",
        "app": {"slug": "github-actions"},
        "html_url": f"https://github.com/owner/name/actions/runs/{run_id}/job/456",
    }


def good_workflow_run(sha=SHA, run_id=123):
    return {
        "id": run_id,
        "head_sha": sha,
        "status": "completed",
        "conclusion": "success",
        "path": ".github/workflows/ci.yml",
        "name": "CI",
    }


def run_eligibility(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )


class EligibilityStaticTests(unittest.TestCase):
    def test_script_exists_and_documents_fail_closed(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for needle in (
            "exact-SHA",
            "CANCELED",
            "canceled",
            "skipped",
            "neutral",
            "missing",
            "stale",
            "forged",
            "--allow-missing-checks",
        ):
            # Case-insensitive presence of fail-closed vocabulary.
            self.assertIn(needle.lower(), text.lower(), needle)

    def test_release_yml_has_no_reusable_gates(self):
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertNotIn("uses: ./.github/workflows/ci.yml", release)
        self.assertNotIn("uses: ./.github/workflows/security.yml", release)
        self.assertIn("scripts/ci/release_eligibility.py", release)
        self.assertIn("needs: [release-eligibility]", release)
        self.assertNotIn("if: always()", release.split("publish:")[1]
                         if "publish:" in release else release)

    def test_ci_aggregators_are_fixed_names(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("CI / required", ci)
        self.assertIn("CI / security-required", ci)
        self.assertIn("cancel-in-progress: ${{ github.event_name == 'pull_request' }}", ci)

    def test_windows_has_no_full_workspace_test(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        # Extract platform-windows job block coarsely.
        start = ci.find("platform-windows:")
        self.assertGreaterEqual(start, 0)
        block = ci[start:start + 6000]
        # Single source: CI invokes via run.py; commands live in suites.toml.
        self.assertIn("scripts/ci/run.py platform-windows", block)
        self.assertNotIn("cargo test --workspace --all-targets --locked", block)
        suites = (ROOT / "scripts/ci/suites.toml").read_text(encoding="utf-8")
        self.assertIn("cargo check --workspace --all-targets --locked", suites)
        win_section = suites.split("[platform-windows]")[1].split("[")[0]
        self.assertNotIn("cargo test --workspace --all-targets --locked", win_section)

    def test_run_id_is_required(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"--run-id"', text)
        self.assertIn("required=True", text)
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("--run-id", release)


class EligibilityFixtureTests(unittest.TestCase):
    """Stale/forged/missing/skipped/canceled/neutral fixtures: all rejected."""

    def test_accepts_exact_sha_success(self):
        self.assertIsNone(
            eligibility.validate_context_checks("CI / required", [good_check()], SHA))
        self.assertIsNone(eligibility.validate_workflow_run(good_workflow_run(), SHA))
        payload = {"artifacts": [{"name": "ci-plan", "expired": False}]}
        self.assertIsNone(eligibility.validate_run_artifacts(payload, "123"))

    def test_rejects_stale_check_run(self):
        stale = good_check()
        stale["head_sha"] = OTHER_SHA
        err = eligibility.validate_context_checks("CI / required", [stale], SHA)
        self.assertIsNotNone(err)
        self.assertIn("stale", err.lower() + "missing")

    def test_rejects_stale_workflow_run(self):
        run = good_workflow_run(sha=OTHER_SHA)
        err = eligibility.validate_workflow_run(run, SHA)
        self.assertIsNotNone(err)
        self.assertIn("stale", err.lower())

    def test_rejects_forged_check_producer(self):
        forged = good_check()
        forged["app"] = {"slug": "attacker-bot"}
        err = eligibility.validate_context_checks("CI / required", [forged], SHA)
        self.assertIsNotNone(err)
        self.assertIn("forged", err.lower())

    def test_rejects_forged_workflow_path(self):
        run = good_workflow_run()
        run["path"] = ".github/workflows/attacker.yml"
        run["name"] = "Attacker"
        err = eligibility.validate_workflow_run(run, SHA)
        self.assertIsNotNone(err)
        self.assertIn("forged", err.lower())

    def test_rejects_forged_workflow_path_only(self):
        # Single mismatch (path only) must still fail-closed.
        run = good_workflow_run()
        run["path"] = ".github/workflows/attacker.yml"
        err = eligibility.validate_workflow_run(run, SHA)
        self.assertIsNotNone(err)
        self.assertIn("forged", err.lower())

    def test_rejects_forged_workflow_name_only(self):
        # Single mismatch (name only) must still fail-closed.
        run = good_workflow_run()
        run["name"] = "Attacker"
        err = eligibility.validate_workflow_run(run, SHA)
        self.assertIsNotNone(err)
        self.assertIn("forged", err.lower())

    def test_rejects_missing_check_run(self):
        err = eligibility.validate_context_checks("CI / required", [], SHA)
        self.assertIsNotNone(err)
        self.assertIn("missing", err.lower())

    def test_rejects_missing_workflow_run(self):
        err = eligibility.validate_workflow_run(None, SHA)
        self.assertIsNotNone(err)
        self.assertIn("missing", err.lower())

    def test_rejects_missing_artifacts(self):
        err = eligibility.validate_run_artifacts({"artifacts": []}, "123")
        self.assertIsNotNone(err)
        self.assertIn("missing", err.lower())

    def test_rejects_skipped_check_run(self):
        skipped = good_check()
        skipped["conclusion"] = "skipped"
        err = eligibility.validate_context_checks("CI / required", [skipped], SHA)
        self.assertIsNotNone(err)

    def test_rejects_skipped_workflow_run(self):
        run = good_workflow_run()
        run["conclusion"] = "skipped"
        err = eligibility.validate_workflow_run(run, SHA)
        self.assertIsNotNone(err)
        self.assertIn("skipped", err.lower() + "not success")

    def test_rejects_canceled_check_run(self):
        canceled = good_check()
        canceled["conclusion"] = "cancelled"
        err = eligibility.validate_context_checks("CI / required", [canceled], SHA)
        self.assertIsNotNone(err)

    def test_rejects_canceled_workflow_run(self):
        run = good_workflow_run()
        run["conclusion"] = "cancelled"
        err = eligibility.validate_workflow_run(run, SHA)
        self.assertIsNotNone(err)
        self.assertIn("cancel", err.lower())

    def test_rejects_neutral_check_run(self):
        neutral = good_check()
        neutral["conclusion"] = "neutral"
        err = eligibility.validate_context_checks("CI / required", [neutral], SHA)
        self.assertIsNotNone(err)

    def test_rejects_neutral_workflow_run(self):
        run = good_workflow_run()
        run["conclusion"] = "neutral"
        err = eligibility.validate_workflow_run(run, SHA)
        self.assertIsNotNone(err)
        self.assertIn("neutral", err.lower())

    def test_rejects_expired_artifacts(self):
        payload = {"artifacts": [{"name": "ci-plan", "expired": True}]}
        err = eligibility.validate_run_artifacts(payload, "123")
        self.assertIsNotNone(err)
        self.assertIn("expired", err.lower())

    def test_mixed_success_plus_bad_still_rejected(self):
        bad = good_check()
        bad["conclusion"] = "cancelled"
        err = eligibility.validate_context_checks(
            "CI / required", [good_check(), bad], SHA)
        self.assertIsNotNone(err)

    def test_accepts_run_id_bound_success(self):
        self.assertIsNone(
            eligibility.validate_context_checks(
                "CI / required", [good_check(run_id=123)], SHA, "123"))

    def test_rejects_same_name_check_from_other_workflow_run(self):
        # Exact SHA + success but bound to a different run id: forged
        # same-name check from another workflow must not satisfy eligibility.
        other = good_check(run_id=999)
        err = eligibility.validate_context_checks(
            "CI / required", [other], SHA, "123")
        self.assertIsNotNone(err)
        self.assertIn("run-id", err.lower())

    def test_rejects_unbound_check_when_run_id_required(self):
        unbound = good_check()
        del unbound["html_url"]
        err = eligibility.validate_context_checks(
            "CI / required", [unbound], SHA, "123")
        self.assertIsNotNone(err)
        self.assertIn("run-id", err.lower())


class AllowMissingChecksGuardTests(unittest.TestCase):
    """--allow-missing-checks must never yield a success evidence in CI."""

    def _run_with_flag(self, github_actions: str | None) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        if github_actions is None:
            env.pop("GITHUB_ACTIONS", None)
        else:
            env["GITHUB_ACTIONS"] = github_actions
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--tag", "v0.0.0-test",
             "--sha", SHA, "--repo", "owner/name", "--run-id", "123",
             "--allow-missing-checks"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )

    def test_rejected_when_github_actions_true(self):
        proc = self._run_with_flag("true")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("allow-missing-checks", proc.stderr.lower())
        self.assertIn("fail-closed", proc.stderr.lower())

    def test_evidence_records_dry_run(self):
        evidence = eligibility.build_evidence(
            tag="v0.0.0-test", sha=SHA, run_id="123",
            expected_workflow="CI", dry_run=True)
        self.assertTrue(evidence["dry_run"])
        evidence = eligibility.build_evidence(
            tag="v0.0.0-test", sha=SHA, run_id="123",
            expected_workflow="CI", dry_run=False)
        self.assertFalse(evidence["dry_run"])

    def test_script_marks_dry_run_in_evidence(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"dry_run"', text)
        self.assertIn('GITHUB_ACTIONS', text)


if __name__ == "__main__":
    unittest.main()
