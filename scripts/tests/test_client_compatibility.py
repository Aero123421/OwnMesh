#!/usr/bin/env python3
"""Regression test for #199 deliverable 1 (docs/client-compatibility.md).

Guards the minimal slice: the matrix exists, covers every required client row
and column, never markets a static inspection as live support, and contains
no credentials or user-specific identifiers.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "client-compatibility.md"

REQUIRED_ROWS = [
    "ChatGPT",
    "Claude.ai",
    "Claude Code remote HTTP MCP",
    "plugin",
    "Perplexity custom remote connector",
    "Computer Skill",
    "MCP Inspector",
]

REQUIRED_COLUMNS = [
    "Transport",
    "OAuth registration",
    "Callback",
    "Refresh",
    "Scope step-up",
    "Tool classes",
    "timeout",
    "Catalog refresh",
    "Live receipt",
    "Status",
    "Known limitations",
]

ALLOWED_STATUSES = ("unverified", "experimental")

FORBIDDEN_SUPPORT_CLAIMS = [
    "fully supported",
    "verified working",
    "certified",
]

SECRET_PATTERNS = [
    r"sk-[A-Za-z0-9]{8,}",
    r"ghp_[A-Za-z0-9]{8,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    # Unified with test_integration_bundles.py: deployed hosts, local paths,
    # and real device IDs must never appear in client-facing docs. Placeholders
    # use <your-worker> / dev_... / dev_<id> and never match these classes.
    r"https://[A-Za-z0-9-]+\.workers\.dev",
    r"/Users/",
    r"dev_[A-Za-z0-9]{4,}",
]


def table_rows(text: str) -> list[str]:
    """Return only markdown table rows (lines starting with ``|``)."""
    return [line for line in text.splitlines() if line.startswith("|")]


def is_separator_row(row: str) -> bool:
    return re.fullmatch(r"\|[\s\-:|]+\|?", row.strip()) is not None


def data_rows(text: str) -> list[str]:
    rows = table_rows(text)
    return [row for row in rows if not row.startswith("| Client |") and not is_separator_row(row)]


def status_cells(text: str) -> list[str]:
    """Extract the Status column cell from each data row (fail-closed)."""
    rows = table_rows(text)
    header = next(line for line in rows if line.startswith("| Client |"))
    columns = [cell.strip() for cell in header.strip().strip("|").split("|")]
    status_index = columns.index("Status")
    cells: list[str] = []
    for row in data_rows(text):
        fields = [cell.strip() for cell in row.strip().strip("|").split("|")]
        cells.append(fields[status_index] if status_index < len(fields) else "")
    return cells


class ClientCompatibilityMatrix(unittest.TestCase):
    def test_matrix_covers_required_rows_columns_and_stays_honest(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        rows = data_rows(text)
        self.assertGreater(len(rows), 0, "matrix has no data rows")
        for row in REQUIRED_ROWS:
            self.assertTrue(
                any(row in table_row for table_row in rows),
                f"missing client row: {row}",
            )
        header = next(line for line in table_rows(text) if line.startswith("| Client |"))
        for column in REQUIRED_COLUMNS:
            self.assertIn(column, header, f"missing matrix column: {column}")
        # Status column must be exactly unverified/experimental until a live
        # receipt lands; exact match rejects suffix-attached claims like
        # "verified*" or "supported (live)".
        statuses = [cell.lower() for cell in status_cells(text)]
        self.assertGreater(len(statuses), 0, "matrix has no status cells")
        self.assertTrue(
            all(status in ALLOWED_STATUSES for status in statuses),
            f"unsupported support claim without live receipt: {statuses}",
        )
        lowered = text.lower()
        for claim in FORBIDDEN_SUPPORT_CLAIMS:
            self.assertNotIn(claim, lowered, f"marketing claim without evidence: {claim}")
        for pattern in SECRET_PATTERNS:
            self.assertIsNone(
                re.search(pattern, text),
                f"matrix must not contain credentials or device ids: {pattern}",
            )
        self.assertIn("ownmesh_list_operations", text)
        self.assertIn("catalog_revision", text)


if __name__ == "__main__":
    unittest.main()
