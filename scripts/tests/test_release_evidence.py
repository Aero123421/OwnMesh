#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "generate_release_evidence.py"


class ReleaseEvidenceReceipt(unittest.TestCase):
    def test_receipt_binds_artifacts_and_keeps_completeness_false(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            checksums = root / "SHA256SUMS"
            checksums.write_text(f"{'a' * 64}  ownmesh-linux-x64.tar.gz\n", encoding="utf-8")
            catalog = root / "catalog.json"
            catalog.write_text(json.dumps({
                "schema_version": 1,
                "catalog_version": 2,
                "catalog_revision": "b" * 16,
            }), encoding="utf-8")
            output = root / "receipt.json"
            subprocess.run([
                sys.executable,
                str(SCRIPT),
                "--version", "1.2.25",
                "--commit", "c" * 40,
                "--checksums", str(checksums),
                "--catalog-current", str(catalog),
                "--catalog-baseline", str(catalog),
                "--workflow-url", "https://github.example/actions/runs/1",
                "--output", str(output),
            ], check=True, cwd=ROOT)
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(receipt["completeness_claim"])
            self.assertEqual(receipt["artifacts"][0]["sha256"], "a" * 64)
            self.assertEqual(receipt["mcp"]["catalog_revision"], "b" * 16)
            self.assertEqual(receipt["mcp"]["compatibility_baseline_revision"], "b" * 16)
            self.assertTrue(receipt["deterministic_release_gate"]["exact_packaged_linux_x64_artifact"])
            self.assertGreater(len(receipt["external_blockers"]), 0)
            self.assertNotIn("profile_evidence", receipt)
            self.assertFalse(any("W-E6" in blocker for blocker in receipt["external_blockers"]))

    def test_path_like_or_duplicate_artifact_names_fail(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            checksums = root / "SHA256SUMS"
            checksums.write_text(f"{'a' * 64}  ../escape\n", encoding="utf-8")
            catalog = root / "catalog.json"
            catalog.write_text(json.dumps({
                "schema_version": 1,
                "catalog_version": 2,
                "catalog_revision": "b" * 16,
            }), encoding="utf-8")
            result = subprocess.run([
                sys.executable,
                str(SCRIPT),
                "--version", "1.2.25",
                "--commit", "c" * 40,
                "--checksums", str(checksums),
                "--catalog-current", str(catalog),
                "--catalog-baseline", str(catalog),
                "--workflow-url", "https://github.example/actions/runs/1",
                "--output", str(root / "receipt.json"),
            ], check=False, cwd=ROOT, capture_output=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
