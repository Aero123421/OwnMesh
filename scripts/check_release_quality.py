#!/usr/bin/env python3
"""Fail-closed static checks for OwnMesh release claims and workflow gates."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ERRORS: list[str] = []


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        ERRORS.append(message)


def require_text(text: str, needle: str, where: str) -> None:
    require(needle in text, f"{where}: missing {needle!r}")


def job_block(workflow: str, job_id: str) -> str:
    """Return one top-level Actions job using the repository's two-space style."""
    match = re.search(
        rf"(?ms)^  {re.escape(job_id)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    return match.group(1) if match else ""


def main() -> int:
    manifest = json.loads(read("release/SUPPORTED_SURFACES.json"))
    surfaces = manifest.get("explicit_stub_surfaces", [])
    expected = manifest.get("explicit_stub_count")
    require(expected == 43, "surface manifest must preserve the audited 43-stub baseline")
    require(len(surfaces) == expected, "surface manifest count does not match its entries")
    require(len(set(surfaces)) == len(surfaces), "surface manifest contains duplicate entries")
    require(manifest.get("completeness_claim") is False, "1.0.x must not claim completeness")
    additional = manifest.get("additional_unsupported", [])
    require(len(additional) == 5, "surface manifest must list five non-generic unsupported surfaces")
    require(manifest.get("total_unsupported_surfaces") == 48, "total unsupported count must be 48")

    commands = read("crates/ownmesh/src/commands/mod.rs")
    # There are 42 calls to the generic stub plus its function definition. The
    # no-argument TUI path is the 43rd explicit not_implemented surface.
    require(
        len(re.findall(r"\bstub\(", commands)) == 43,
        "generic stub call/definition count changed; update implementation and manifest together",
    )
    require(
        commands.count('"status": "not_implemented"') == 2,
        "expected machine-visible not_implemented responses for generic stubs and TUI",
    )
    for surface in surfaces:
        require(f'"{surface}"' in commands, f"manifest surface is not explicit in dispatch: {surface}")

    exec_source = read("crates/ownmesh/src/commands/exec.rs")
    device_guard = exec_source.find("if let Some(device) = &args.device")
    daemon_call = exec_source.find("let value = call_local_daemon")
    require(0 <= device_guard < daemon_call, "exec --device must be rejected before local IPC")
    guard_window = exec_source[device_guard:daemon_call]
    require("return Err(" in guard_window, "exec --device guard must return a hard error")
    require("using local daemon" not in exec_source, "exec --device still advertises local fallback")

    device_source = read("crates/ownmesh/src/commands/device_cmd.rs")
    require_text(device_source, "device_rename_not_supported", "device rename contract")
    require_text(device_source, "device_labels_not_supported", "device labels contract")
    policy_source = read("crates/ownmesh/src/commands/policy_cmd.rs")
    policy_rule = policy_source[policy_source.find("PolicyCmd::Rule"):policy_source.find("PolicyCmd::Validate")]
    require_text(policy_rule, '"status": "not_implemented"', "policy mutation JSON contract")
    require_text(policy_rule, "Err(ExitCode::ProfileUnavailable)", "policy mutation hard-error contract")
    session_source = read("crates/ownmesh/src/commands/session_cmd.rs")
    session_guard = session_source.find("device: Some(device)")
    session_call = session_source.find('call_local_daemon(\n                "session.open"')
    require(0 <= session_guard < session_call, "remote session target must fail before local IPC")
    require("Err(ExitCode::ProfileUnavailable)" in session_source[session_guard:session_call],
            "remote session target must return a hard error")

    ci = read(".github/workflows/ci.yml")
    security = read(".github/workflows/security.yml")
    release = read(".github/workflows/release.yml")
    workflows = ci + security + release
    require("1.85" not in workflows, "workflow toolchains must not reference Rust 1.85")
    require("continue-on-error" not in workflows, "required workflow jobs cannot continue on error")
    require("|| true" not in workflows, "workflow validation cannot discard failures")
    for workflow_name, workflow in (("CI", ci), ("Security", security)):
        require_text(workflow, "workflow_call:", workflow_name)
        require_text(workflow, 'toolchain: "1.92.0"', workflow_name)
        require_text(workflow, "pnpm install --frozen-lockfile", workflow_name)

    for command in (
        "cargo fmt --all --check",
        "cargo clippy --workspace --all-targets --locked -- -D warnings",
        "cargo build --workspace --locked",
        "cargo test --workspace --all-targets --locked",
        "pnpm -r test",
        "pnpm -r typecheck",
        "pnpm -r lint",
        "pnpm exec wrangler deploy --dry-run",
    ):
        require_text(ci, command, "CI")

    ci_gate = job_block(release, "ci-gate")
    security_gate = job_block(release, "security-gate")
    build_job = job_block(release, "build")
    publish_job = job_block(release, "publish")
    require_text(ci_gate, "uses: ./.github/workflows/ci.yml", "Release ci-gate")
    require_text(security_gate, "uses: ./.github/workflows/security.yml", "Release security-gate")
    require("steps:" not in ci_gate and "runs-on:" not in ci_gate, "ci-gate must remain a reusable workflow call")
    require("steps:" not in security_gate and "runs-on:" not in security_gate,
            "security-gate must remain a reusable workflow call")
    require_text(build_job, "needs: [ci-gate, security-gate]", "Release build")
    require_text(publish_job, "needs: [ci-gate, security-gate, build]", "Release publish")
    require("if: always()" not in publish_job, "publish must not run after failed prerequisites")
    for platform, runner in (("windows", "windows-latest"), ("linux", "ubuntu-latest"), ("macos", "macos-latest")):
        require_text(build_job, f"platform: {platform}", "Release matrix")
        require_text(build_job, f"os: {runner}", "Release matrix")
    require_text(publish_job, "for platform in windows linux macos; do", "Release artifact consumer")
    require_text(publish_job, 'test -s "dist/ownmesh-${GITHUB_REF_NAME}-${platform}.tar.gz"',
                 "Release artifact consumer")
    require_text(build_job, "if-no-files-found: error", "Release artifact upload")
    require_text(build_job, "name: release-${{ matrix.platform }}", "Release artifact producer")
    require_text(publish_job, "pattern: release-*", "Release artifact consumer")
    require_text(release, "test -s dist/sbom-rust.cdx.json", "Release artifact validation")
    require_text(release, "test -s dist/sbom-control-plane.cdx.json", "Release artifact validation")
    require_text(publish_job, "actions/attest-build-provenance@v2", "Release provenance")
    require_text(publish_job, "DEGRADED PRE-RELEASE", "Release signing waiver")
    require_text(publish_job, "prerelease: ${{ steps.signing.outputs.available != 'true' }}",
                 "Release signing waiver")
    require_text(publish_job, "docs/release-keys/minisign.pub", "Release signing trust root")
    require_text(publish_job, "minisign -Vm", "Release signature verification")
    require("RELEASE_NOTES_v1.0.1.md" not in release, "release body must not be fixed to v1.0.1")
    require_text(release, "RELEASE_NOTES_${GITHUB_REF_NAME}.md", "Release notes lookup")

    require_text(security, "Generate Rust workspace SBOM (validated, no fallback)", "Security SBOM")
    require_text(security, "Generate control-plane SBOM via cdxgen (validated, no fallback)", "Security SBOM")
    require(security.count("--fail-on-error --validate") == 2,
            "both SBOM generators must use cdxgen fail-fast schema validation")
    require('"components": []' not in security, "Security must not emit an empty SBOM")
    require_text(security, "assert isinstance(components, list) and components", "SBOM validation")

    cargo = read("Cargo.toml")
    version_match = re.search(r'^version = "([^"]+)"', cargo, re.MULTILINE)
    require(version_match is not None, "workspace version is missing")
    if version_match:
        current_notes = f"docs/RELEASE_NOTES_v{version_match.group(1)}.md"
        require((ROOT / current_notes).is_file(), f"missing current release notes: {current_notes}")
        claim_docs = ["README.md", "docs/DOD_1.0.md", current_notes]
        for path in claim_docs:
            text = read(path)
            require_text(text, "43 explicit generic-stub CLI surfaces", path)
            require_text(text, "48 total", path)
            require_text(text, "release/SUPPORTED_SURFACES.json", path)

    contributing = read("CONTRIBUTING.md")
    require("1.85" not in contributing, "CONTRIBUTING still documents Rust 1.85")
    require_text(contributing, "Rust **1.92", "CONTRIBUTING")

    if ERRORS:
        for error in ERRORS:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("release-quality checks passed: gates fail closed; 43 generic stubs / 48 unsupported surfaces are explicit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
