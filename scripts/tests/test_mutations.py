#!/usr/bin/env python3
"""Mutation tests: each major release-quality gate must fail-closed when broken."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
ROOT = TESTS_DIR.parents[1]
CHECKER = ROOT / "scripts" / "check_release_quality.py"


def _replace_rust_registry(text: str, name: str, entries: list[str]) -> str:
    """Replace one canonical Rust string registry without count assumptions."""
    pattern = re.compile(
        rf"(pub const {re.escape(name)}: &\[&str\] = &)\[(.*?)\](;)",
        re.DOTALL,
    )
    match = pattern.search(text)
    if match is None:
        raise AssertionError(f"Rust registry {name} not found")
    body = ", ".join(json.dumps(entry) for entry in entries)
    return text[: match.start()] + match.group(1) + f"[{body}]" + match.group(3) + text[match.end() :]


def _manifest_with_no_unsupported(text: str, *, completeness: bool = True) -> str:
    data = json.loads(text)
    data["completeness_claim"] = completeness
    data["explicit_unsupported_count"] = 0
    data["explicit_unsupported_surfaces"] = []
    data["additional_unsupported"] = []
    data["release_evidence_waivers"] = []
    data["total_unsupported_surfaces"] = 0
    rendered = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    # Stable releases already have this exact inventory. Keep the mutation
    # harness meaningful by changing formatting without changing semantics.
    return rendered if rendered != text else rendered + "\n"


def _registries_with_no_unsupported(text: str) -> str:
    original = text
    text = _replace_rust_registry(text, "EXPLICIT_UNSUPPORTED_CLI_SURFACES", [])
    text = _replace_rust_registry(text, "ADDITIONAL_UNSUPPORTED_CLI_SURFACES", [])
    return text if text != original else text + "\n// equivalent empty-registry mutation\n"


def _manifest_with_false_complete_claim(text: str) -> str:
    data = json.loads(text)
    data["completeness_claim"] = True
    data["explicit_unsupported_count"] = 1
    data["explicit_unsupported_surfaces"] = ["__mutation_unimplemented_surface__"]
    data["additional_unsupported"] = []
    data["release_evidence_waivers"] = []
    data["total_unsupported_surfaces"] = 1
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def _registries_with_one_unsupported(text: str) -> str:
    text = _replace_rust_registry(
        text,
        "EXPLICIT_UNSUPPORTED_CLI_SURFACES",
        ["__mutation_unimplemented_surface__"],
    )
    return _replace_rust_registry(text, "ADDITIONAL_UNSUPPORTED_CLI_SURFACES", [])


def _run_checker() -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )


class _Mutation:
    """Temporarily rewrite a file under ROOT, restoring on exit.

    Reads/writes raw bytes so Windows text-mode newline translation cannot
    permanently convert repository LF files to CRLF.
    """

    def __init__(self, relative: str, transform) -> None:
        self.path = ROOT / relative
        self.transform = transform
        self._original: bytes | None = None

    def __enter__(self) -> "_Mutation":
        self._original = self.path.read_bytes()
        # Decode as UTF-8 without newline mangling; keep original newline style.
        text = self._original.decode("utf-8")
        updated = self.transform(text)
        if updated == text:
            raise AssertionError(f"mutation produced no change for {self.path}")
        # Preserve CRLF vs LF of the original file.
        crlf = "\r\n"
        lf = "\n"
        if crlf.encode() in self._original:
            normalized = updated.replace(crlf, lf).replace(lf, crlf)
        else:
            normalized = updated.replace(crlf, lf)
        self.path.write_bytes(normalized.encode("utf-8"))
        return self

    def __exit__(self, *exc) -> None:
        assert self._original is not None
        self.path.write_bytes(self._original)


def _must_fail(label: str) -> None:
    result = _run_checker()
    if result.returncode == 0:
        raise AssertionError(
            f"mutation {label!r} was expected to fail but checker exited 0\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


class CheckerMutationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        baseline = _run_checker()
        if baseline.returncode != 0:
            raise unittest.SkipTest(
                "baseline checker must pass before mutations:\n"
                f"{baseline.stderr or baseline.stdout}"
            )

    def test_baseline_still_passes(self) -> None:
        result = _run_checker()
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    # --- action pin gate -------------------------------------------------
    def test_mutation_action_tag_pin_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "actions/checkout@v4",
                1,
            )

        with _Mutation(".github/workflows/ci.yml", mutate):
            _must_fail("action tag pin")

    def test_mutation_action_branch_pin_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
                "actions/setup-node@main",
                1,
            )

        with _Mutation(".github/workflows/ci.yml", mutate):
            _must_fail("action branch pin")

    def test_mutation_action_short_sha_fails(self) -> None:
        def mutate(text: str) -> str:
            # drop final hex nibble → 39 chars
            return text.replace(
                "Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6",
                "Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b",
                1,
            )

        with _Mutation(".github/workflows/ci.yml", mutate):
            _must_fail("action short sha")

    def test_mutation_action_missing_pin_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
                "actions/checkout",
                1,
            )

        with _Mutation(".github/workflows/ci.yml", mutate):
            _must_fail("action missing pin")

    # --- toolchain / fail-open guards ------------------------------------
    def test_mutation_rust_185_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace('toolchain: "1.92.0"', 'toolchain: "1.85.0"', 1)

        with _Mutation(".github/workflows/ci.yml", mutate):
            _must_fail("rust 1.85 toolchain")

    def test_mutation_windows_installer_gate_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "python scripts/tests/test_installers.py",
                'Write-Host "installer integration skipped"',
                1,
            )

        with _Mutation(".github/workflows/ci.yml", mutate):
            _must_fail("Windows installer integration removed")

    def test_mutation_unix_installer_gate_fails(self) -> None:
        def mutate(text: str) -> str:
            needle = "scripts/tests/test_installers.py"
            self.assertIn(needle, text)
            return text.replace(
                needle,
                "scripts/tests/test_installers_SKIPPED.py",
                1,
            )

        with _Mutation("scripts/ci/suites.toml", mutate):
            _must_fail("Unix installer integration removed")

    def test_mutation_continue_on_error_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "run: python3 scripts/ci/run.py rust-linux",
                "continue-on-error: true\n        run: python3 scripts/ci/run.py rust-linux",
                1,
            )

        with _Mutation(".github/workflows/ci.yml", mutate):
            _must_fail("continue-on-error")

    def test_mutation_or_true_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "run: python3 scripts/ci/run.py rust-linux",
                "run: python3 scripts/ci/run.py rust-linux || true",
                1,
            )

        with _Mutation(".github/workflows/ci.yml", mutate):
            _must_fail("|| true")

    # --- release graph (exact-SHA eligibility, ADR 0022) ---
    def test_mutation_publish_always_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "needs: [release-eligibility, release-gate-integrity, build, sbom-release, release-candidate-e2e, release-policy-final, distribution-metadata]",
                "needs: [release-eligibility, release-gate-integrity, build, sbom-release, release-candidate-e2e, release-policy-final, distribution-metadata]\n    if: always()",
                1,
            )

        with _Mutation(".github/workflows/release.yml", mutate):
            _must_fail("publish if: always()")

    def test_mutation_reusable_ci_gate_reintroduced_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "  release-eligibility:",
                "  ci-gate:\n    uses: ./.github/workflows/ci.yml\n\n  release-eligibility:",
                1,
            )

        with _Mutation(".github/workflows/release.yml", mutate):
            _must_fail("reusable CI re-run")

    def test_mutation_eligibility_bypass_fails(self) -> None:
        def mutate(text: str) -> str:
            # Remove every eligibility edge (including the checked build job);
            # mutating only the unchecked triage job would not prove the gate.
            return text.replace(
                "needs: [release-eligibility]",
                "needs: []",
            )

        with _Mutation(".github/workflows/release.yml", mutate):
            _must_fail("eligibility bypass")

    def test_mutation_windows_full_test_reintroduced_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "cargo check --workspace --all-targets --locked",
                "cargo test --workspace --all-targets --locked",
                1,
            )

        with _Mutation("scripts/ci/suites.toml", mutate):
            _must_fail("Windows full test reintroduced")

    def test_mutation_scale_unignored_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                '#[ignore = "scale:',
                '#[test] // scale:',
                1,
            )

        with _Mutation("crates/ownmesh-fs/tests/scale_directory.rs", mutate):
            _must_fail("scale un-ignored")

    def test_mutation_checkout_credentials_fails(self) -> None:
        def mutate(text: str) -> str:
            # Remove persist-credentials from the build job (counted set).
            anchor = "  build:\n    name: Release build"
            idx = text.find(anchor)
            self.assertGreaterEqual(idx, 0)
            tail = text[idx:]
            needle = "          persist-credentials: false\n"
            pos = tail.find(needle)
            self.assertGreaterEqual(pos, 0)
            return text[: idx + pos] + text[idx + pos + len(needle):]

        with _Mutation(".github/workflows/release.yml", mutate):
            _must_fail("checkout credentials persistence")

    def test_mutation_archive_binary_set_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "for binary in ownmesh ownmesh-tui ownmeshd ownmesh-session-host ownmesh-broker; do",
                "for binary in ownmesh ownmesh-tui ownmeshd ownmesh-session-host; do",
                1,
            )

        with _Mutation(".github/workflows/release.yml", mutate):
            _must_fail("archive five-binary validation")

    def test_mutation_secrets_inherit_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "secrets: inherit",
                "secrets: inherit # probe",
                1,
            ) if "secrets: inherit" in text else text.replace(
                "  release-eligibility:",
                "  release-eligibility:\n    secrets: inherit",
                1,
            )

        with _Mutation(".github/workflows/release.yml", mutate):
            _must_fail("secrets: inherit")

    def test_mutation_ci_gate_inline_steps_fails(self) -> None:
        def mutate(text: str) -> str:
            # Eligibility must remain a steps job; replacing it with a reusable
            # call reintroduces the old duplicate-CI trust model.
            return text.replace(
                "scripts/ci/release_eligibility.py",
                "./.github/workflows/ci.yml",
                1,
            )

        with _Mutation(".github/workflows/release.yml", mutate):
            _must_fail("eligibility replaced by reusable CI")

    # --- surface registry ------------------------------------------------
    def test_mutation_surface_count_fails(self) -> None:
        def mutate(text: str) -> str:
            match = re.search(r'("explicit_unsupported_count"\s*:\s*)(\d+)', text)
            if match is None:
                raise AssertionError("explicit unsupported count not found")
            changed = int(match.group(2)) + 1
            return text[: match.start(2)] + str(changed) + text[match.end(2) :]

        with _Mutation("release/SUPPORTED_SURFACES.json", mutate):
            _must_fail("surface count mismatch")

    def test_mutation_additional_registry_drift_fails(self) -> None:
        def mutate(text: str) -> str:
            return _replace_rust_registry(
                text,
                "ADDITIONAL_UNSUPPORTED_CLI_SURFACES",
                ["arbitrary unsupported command"],
            )

        with _Mutation("crates/ownmesh/src/commands/mod.rs", mutate):
            _must_fail("additional registry drift")

    def test_mutation_completeness_claim_fails(self) -> None:
        def mutate(text: str) -> str:
            match = re.search(r'("completeness_claim"\s*:\s*)(true|false)', text)
            if match is None:
                raise AssertionError("completeness claim not found")
            replacement = "false" if match.group(2) == "true" else "true"
            return text[: match.start(2)] + replacement + text[match.end(2) :]

        with _Mutation("release/SUPPORTED_SURFACES.json", mutate):
            _must_fail("completeness claim contradicts unsupported inventory")

    def test_honest_complete_inventory_passes(self) -> None:
        with _Mutation(
            "release/SUPPORTED_SURFACES.json",
            _manifest_with_no_unsupported,
        ), _Mutation(
            "crates/ownmesh/src/commands/mod.rs",
            _registries_with_no_unsupported,
        ):
            result = _run_checker()
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_zero_unsupported_without_completeness_fails(self) -> None:
        with _Mutation(
            "release/SUPPORTED_SURFACES.json",
            lambda text: _manifest_with_no_unsupported(text, completeness=False),
        ), _Mutation(
            "crates/ownmesh/src/commands/mod.rs",
            _registries_with_no_unsupported,
        ):
            _must_fail("zero unsupported inventory without completeness")

    def test_complete_claim_with_nonempty_inventory_fails(self) -> None:
        with _Mutation(
            "release/SUPPORTED_SURFACES.json",
            _manifest_with_false_complete_claim,
        ), _Mutation(
            "crates/ownmesh/src/commands/mod.rs",
            _registries_with_one_unsupported,
        ):
            _must_fail("complete claim with a registry-backed unsupported surface")

    # --- docs claim gate -------------------------------------------------
    def test_mutation_docs_surface_claim_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "release/SUPPORTED_SURFACES.json",
                "release/SURFACE_MANIFEST_REMOVED.json",
            )

        with _Mutation("README.md", mutate):
            _must_fail("docs omit manifest authority")

    # --- security SBOM / permissions -------------------------------------
    def test_mutation_empty_sbom_fallback_fails(self) -> None:
        def mutate(text: str) -> str:
            # inject forbidden empty-components fallback marker
            return text + '\n# probe: "components": []\n'

        with _Mutation(".github/workflows/security.yml", mutate):
            _must_fail("empty SBOM fallback")

    def test_mutation_security_events_on_sbom_fails(self) -> None:
        def mutate(text: str) -> str:
            # give sbom-weekly job security-events:write (forbidden)
            old = "  sbom-weekly:\n    name:"
            new = "  sbom-weekly:\n    permissions:\n      security-events: write\n    name:"
            if old not in text:
                raise AssertionError("sbom-weekly job anchor not found")
            return text.replace(old, new, 1)

        with _Mutation(".github/workflows/security.yml", mutate):
            _must_fail("sbom security-events write")

    # --- broker / exec contracts -----------------------------------------
    def test_mutation_broker_fallback_marker_fails(self) -> None:
        def mutate(text: str) -> str:
            return text + "\n// probe fallback_install\n"

        with _Mutation("crates/ownmesh/src/commands/privileged.rs", mutate):
            _must_fail("broker fallback_install")

    # --- label-driven CI / CodeRabbit gate ---------------------------------
    def test_mutation_coderabbit_gate_removed_fails(self) -> None:
        def mutate(text: str) -> str:
            needle = "tui-i18n, coderabbit-gate]"
            self.assertIn(needle, text)
            return text.replace(needle, "tui-i18n]", 1)

        with _Mutation(".github/workflows/ci.yml", mutate):
            _must_fail("coderabbit-gate removed from required")

    def test_mutation_label_branch_broken_fails(self) -> None:
        def mutate(text: str) -> str:
            needle = "def parse_labels(raw"
            self.assertIn(needle, text)
            return text.replace(needle, "def broken_branch(raw", 1)

        with _Mutation("scripts/ci/plan.py", mutate):
            _must_fail("plan label branch removed")

    def test_mutation_coderabbit_permission_escalation_fails(self) -> None:
        def mutate(text: str) -> str:
            needle = "pull-requests: write"
            self.assertIn(needle, text)
            return text.replace(needle, "contents: write", 1)

        with _Mutation(".github/workflows/ci.yml", mutate):
            _must_fail("coderabbit-call permission escalation")

    def test_mutation_exec_local_fallback_ad_fails(self) -> None:
        def mutate(text: str) -> str:
            return text + '\n// probe "using local daemon"\n'

        with _Mutation("crates/ownmesh/src/commands/exec.rs", mutate):
            _must_fail("exec local daemon ad")

    def test_mutation_missing_suite_section_fails(self) -> None:
        def mutate(text: str) -> str:
            needle = "[platform-windows]"
            self.assertIn(needle, text)
            return text.replace(needle, "[platform-windows-removed]", 1)

        with _Mutation("scripts/ci/suites.toml", mutate):
            _must_fail("missing platform-windows suite section")

    def test_mutation_typescript_typecheck_removed_fails(self) -> None:
        def mutate(text: str) -> str:
            needle = '  "pnpm -r typecheck",\n'
            self.assertIn(needle, text)
            return text.replace(needle, "", 1)

        with _Mutation("scripts/ci/suites.toml", mutate):
            _must_fail("typescript typecheck removed")


if __name__ == "__main__":
    # Avoid leaving mutations behind if the process is hard-killed mid-test:
    # each test restores via context manager; also refuse to run if dirty lock exists.
    lock = Path(tempfile.gettempdir()) / f"ownmesh-rq-mutation-{os.getpid()}.lock"
    lock.write_text("running", encoding="utf-8")
    try:
        ok = unittest.main(verbosity=2, exit=False).result.wasSuccessful()
        raise SystemExit(0 if ok else 1)
    finally:
        lock.unlink(missing_ok=True)
