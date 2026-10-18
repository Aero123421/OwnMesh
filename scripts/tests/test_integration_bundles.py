#!/usr/bin/env python3
"""Regression test for #199 deliverables 4+6 (Claude plugin + Perplexity Skill).

Guards the minimal slice: versioned bundles exist, are generated from
checked-in placeholder-only sources, never auto-authorize or silently
enable destructive tools, and contain no credentials or user-specific
identifiers.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLAUDE = ROOT / "integrations" / "claude-ownmesh"
PERPLEXITY = ROOT / "integrations" / "perplexity-ownmesh"

CLAUDE_FILES = [
    CLAUDE / ".claude-plugin" / "plugin.json",
    CLAUDE / ".mcp.json",
    CLAUDE / "skills" / "ownmesh" / "SKILL.md",
    CLAUDE / "README.md",
]
PERPLEXITY_FILES = [
    PERPLEXITY / "SKILL.md",
    PERPLEXITY / "examples" / "connector-recipe.md",
    PERPLEXITY / "build-skill-zip.sh",
]

SECRET_PATTERNS = [
    r"sk-[A-Za-z0-9]{8,}",
    r"ghp_[A-Za-z0-9]{8,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"https://[A-Za-z0-9-]+\.workers\.dev",
    r"/Users/",
    # Real device IDs look like dev_<base62>; placeholders use dev_... or
    # dev_<id> (angle brackets / ellipsis never match this class).
    r"dev_[A-Za-z0-9]{4,}",
]

# Destructive tools must only appear next to an explicit confirmation /
# no-auto-approval statement, never next to a bypass phrase. Natural-language
# denials ("never ... skip approval", "never ... silently enable") are
# required elsewhere, so only code identifiers and positive bypass
# instructions are forbidden here.
FORBIDDEN_BYPASS = [
    "bypass_policy",
    "force_allow",
    "skip_approval",
    "enable without asking",
]

REQUIRED_SKILL_IDEAS = [
    "ownmesh_command_run",
    "async",
    "ownmesh_get_operation",
    "ownmesh_list_operations",
    "policy",
    "catalog_revision",
    "insufficient_scope",
]


def bundle_text(files: list[Path]) -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in files)


class IntegrationBundles(unittest.TestCase):
    def test_files_exist_and_json_parses(self) -> None:
        for path in (*CLAUDE_FILES, *PERPLEXITY_FILES):
            self.assertTrue(path.is_file(), f"missing bundle file: {path}")
        plugin = json.loads((CLAUDE / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
        for key in ("name", "version", "description"):
            self.assertTrue(plugin.get(key), f"plugin.json missing {key}")
        mcp = json.loads((CLAUDE / ".mcp.json").read_text(encoding="utf-8"))
        servers = mcp.get("mcpServers", {})
        self.assertIn("ownmesh", servers)
        url = servers["ownmesh"].get("url", "")
        self.assertIn("OWNMESH_WORKER_URL", url, "endpoint must stay an env placeholder")
        self.assertNotIn("secret", json.dumps(mcp).lower(), "mcp config must not carry secrets")

    def test_placeholders_only_no_secrets(self) -> None:
        text = bundle_text([*CLAUDE_FILES, *PERPLEXITY_FILES])
        for pattern in SECRET_PATTERNS:
            self.assertIsNone(
                re.search(pattern, text),
                f"bundle must not contain credentials/hosts/paths: {pattern}",
            )
        lowered = text.lower()
        for phrase in FORBIDDEN_BYPASS:
            self.assertNotIn(phrase, lowered, f"bypass phrase forbidden: {phrase}")
        # No-auto-approval invariant must be stated explicitly in both bundles.
        for bundle in (CLAUDE_FILES, PERPLEXITY_FILES):
            bundle_lowered = bundle_text(bundle).lower()
            self.assertIn("never auto", bundle_lowered, "bundle must forbid auto-authorization")

    def test_skill_guidance_and_connection_boundary(self) -> None:
        claude_skill = (CLAUDE / "skills" / "ownmesh" / "SKILL.md").read_text(encoding="utf-8")
        perplexity_skill = (PERPLEXITY / "SKILL.md").read_text(encoding="utf-8")
        for idea in REQUIRED_SKILL_IDEAS:
            self.assertIn(idea, claude_skill, f"claude skill missing: {idea}")
            self.assertIn(idea, perplexity_skill, f"perplexity skill missing: {idea}")
        # Product approval UI must never be presented as device authorization.
        for skill in (claude_skill, perplexity_skill):
            self.assertIn("final authority", skill.lower())
            self.assertIn("approval_required", skill)
        # Perplexity Skill must state it does not establish the connection.
        self.assertIn("does not establish", perplexity_skill.lower())
        self.assertIn("must already be configured", perplexity_skill.lower())
        # Claude README documents the manual OAuth login and experimental status.
        readme = (CLAUDE / "README.md").read_text(encoding="utf-8")
        self.assertIn("claude mcp login ownmesh", readme)
        self.assertIn("experimental", readme.lower())
        self.assertIn("client-compatibility.md", readme)
        # README shows a placeholder guard example (no real endpoint/secret).
        self.assertIn("OWNMESH_WORKER_URL", readme)
        self.assertIn("Guard example", readme)
        recipe = (PERPLEXITY / "examples" / "connector-recipe.md").read_text(encoding="utf-8")
        self.assertIn("oauth_callback", recipe)
        self.assertIn("experimental", recipe.lower())

    def test_zip_script_builds_from_checked_in_sources(self) -> None:
        script = (PERPLEXITY / "build-skill-zip.sh").read_text(encoding="utf-8")
        self.assertIn("set -eu", script)
        self.assertIn("SKILL.md", script)
        # ZIP root must be SKILL.md itself (-j junk-paths keeps it at root).
        self.assertIn("-j", script)
        # Deterministic build without overclaiming full reproducibility.
        self.assertIn("-X", script)
        self.assertNotIn("reproducible", script.lower())
        self.assertIn("deterministic", script.lower())
        # The script refuses credential-shaped sources before packaging.
        self.assertIn("refusing to package", script)


if __name__ == "__main__":
    unittest.main()
