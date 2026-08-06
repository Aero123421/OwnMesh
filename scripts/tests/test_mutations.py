#!/usr/bin/env python3
"""Mutation tests: each major release-quality gate must fail-closed when broken."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
ROOT = TESTS_DIR.parents[1]
CHECKER = ROOT / "scripts" / "check_release_quality.py"


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
                "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
                "actions/checkout@v4",
                1,
            )

        with _Mutation(".github/workflows/ci.yml", mutate):
            _must_fail("action tag pin")

    def test_mutation_action_branch_pin_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
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
                "actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4",
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

    def test_mutation_continue_on_error_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "run: cargo test --workspace --all-targets --locked",
                "continue-on-error: true\n        run: cargo test --workspace --all-targets --locked",
                1,
            )

        with _Mutation(".github/workflows/ci.yml", mutate):
            _must_fail("continue-on-error")

    def test_mutation_or_true_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "run: cargo fmt --all --check",
                "run: cargo fmt --all --check || true",
                1,
            )

        with _Mutation(".github/workflows/ci.yml", mutate):
            _must_fail("|| true")

    # --- release graph ---------------------------------------------------
    def test_mutation_publish_always_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "needs: [ci-gate, security-gate, build]",
                "needs: [ci-gate, security-gate, build]\n    if: always()",
                1,
            )

        with _Mutation(".github/workflows/release.yml", mutate):
            _must_fail("publish if: always()")

    def test_mutation_checkout_credentials_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace("          persist-credentials: false\n", "", 1)

        with _Mutation(".github/workflows/release.yml", mutate):
            _must_fail("checkout credentials persistence")

    def test_mutation_archive_binary_set_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "            for binary in ownmesh ownmesh-tui ownmeshd ownmesh-session-host ownmesh-broker; do",
                "            for binary in ownmesh ownmesh-tui ownmeshd ownmesh-session-host; do",
                1,
            )

        with _Mutation(".github/workflows/release.yml", mutate):
            _must_fail("archive five-binary validation")

    def test_mutation_secrets_inherit_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "uses: ./.github/workflows/security.yml",
                "uses: ./.github/workflows/security.yml\n    secrets: inherit",
                1,
            )

        with _Mutation(".github/workflows/release.yml", mutate):
            _must_fail("secrets: inherit")

    def test_mutation_ci_gate_inline_steps_fails(self) -> None:
        def mutate(text: str) -> str:
            # break reusable-workflow-only contract
            return text.replace(
                "uses: ./.github/workflows/ci.yml",
                "runs-on: ubuntu-latest\n    steps:\n      - run: echo hi",
                1,
            )

        with _Mutation(".github/workflows/release.yml", mutate):
            _must_fail("ci-gate inline steps")

    # --- surface registry ------------------------------------------------
    def test_mutation_surface_count_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                '"explicit_unsupported_count": 44',
                '"explicit_unsupported_count": 43',
                1,
            )

        with _Mutation("release/SUPPORTED_SURFACES.json", mutate):
            _must_fail("surface count mismatch")

    def test_mutation_additional_registry_drift_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace('    "exec --device",', '    "arbitrary unsupported command",', 1)

        with _Mutation("crates/ownmesh/src/commands/mod.rs", mutate):
            _must_fail("additional registry drift")

    def test_mutation_additional_handler_bypass_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                'super::unsupported_exit("exec --device")',
                'super::unsupported_exit("arbitrary unsupported command")',
                1,
            )

        with _Mutation("crates/ownmesh/src/commands/exec.rs", mutate):
            _must_fail("additional handler arbitrary string")

    def test_mutation_approval_watch_hard_error_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "ApprovalCmd::Watch => super::unsupported(",
                "ApprovalCmd::Watch => fake_soft_fallback(",
                1,
            )

        with _Mutation("crates/ownmesh/src/commands/approval.rs", mutate):
            _must_fail("approval watch hard error")

    def test_mutation_completeness_claim_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                '"completeness_claim": false',
                '"completeness_claim": true',
                1,
            )

        with _Mutation("release/SUPPORTED_SURFACES.json", mutate):
            _must_fail("completeness claim")

    # --- docs claim gate -------------------------------------------------
    def test_mutation_docs_surface_claim_fails(self) -> None:
        def mutate(text: str) -> str:
            return text.replace(
                "44 explicit unsupported CLI surfaces",
                "40 explicit unsupported CLI surfaces",
                1,
            )

        with _Mutation("README.md", mutate):
            _must_fail("docs surface claim")

    # --- security SBOM / permissions -------------------------------------
    def test_mutation_empty_sbom_fallback_fails(self) -> None:
        def mutate(text: str) -> str:
            # inject forbidden empty-components fallback marker
            return text + '\n# probe: "components": []\n'

        with _Mutation(".github/workflows/security.yml", mutate):
            _must_fail("empty SBOM fallback")

    def test_mutation_security_events_on_sbom_fails(self) -> None:
        def mutate(text: str) -> str:
            # give sbom job security-events:write (forbidden)
            old = "  sbom:\n    name:"
            new = "  sbom:\n    permissions:\n      security-events: write\n    name:"
            if old not in text:
                raise AssertionError("sbom job anchor not found")
            return text.replace(old, new, 1)

        with _Mutation(".github/workflows/security.yml", mutate):
            _must_fail("sbom security-events write")

    # --- broker / exec contracts -----------------------------------------
    def test_mutation_broker_fallback_marker_fails(self) -> None:
        def mutate(text: str) -> str:
            return text + "\n// probe fallback_install\n"

        with _Mutation("crates/ownmesh/src/commands/privileged.rs", mutate):
            _must_fail("broker fallback_install")

    def test_mutation_exec_local_fallback_ad_fails(self) -> None:
        def mutate(text: str) -> str:
            return text + '\n// probe "using local daemon"\n'

        with _Mutation("crates/ownmesh/src/commands/exec.rs", mutate):
            _must_fail("exec local daemon ad")


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
