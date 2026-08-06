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
    surfaces = manifest.get("explicit_unsupported_surfaces", [])
    expected = manifest.get("explicit_unsupported_count")
    require(len(surfaces) == expected, "surface manifest count does not match its entries")
    require(len(set(surfaces)) == len(surfaces), "surface manifest contains duplicate entries")
    require(manifest.get("completeness_claim") is False, "1.0.x must not claim completeness")
    additional = manifest.get("additional_unsupported", [])
    require(len(set(additional)) == len(additional), "additional unsupported list contains duplicates")
    require(
        manifest.get("total_unsupported_surfaces") == len(surfaces) + len(additional),
        "total unsupported count must be derived from both manifest lists",
    )

    commands = read("crates/ownmesh/src/commands/mod.rs")
    registry_match = re.search(
        r"pub const EXPLICIT_UNSUPPORTED_CLI_SURFACES: &\[&str\] = &\[(.*?)\];",
        commands,
        re.DOTALL,
    )
    require(registry_match is not None, "canonical Rust unsupported-surface registry is missing")
    registry = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', registry_match.group(1)) if registry_match else []
    require(
        registry == surfaces,
        "manifest explicit unsupported surfaces must exactly match the ordered Rust registry",
    )
    require(
        "EXPLICIT_UNSUPPORTED_CLI_SURFACES.contains(&command)" in commands,
        "runtime unsupported helper must validate commands against the canonical registry",
    )
    approval_source = read("crates/ownmesh/src/commands/approval.rs")
    dispatched = re.findall(r'\bstub\(\s*cli,\s*"([^"]+)"', commands)
    dispatched += re.findall(r'\bunsupported\(\s*cli,\s*"([^"]+)"', commands)
    dispatched += re.findall(r'\bsuper::unsupported\(\s*cli,\s*"([^"]+)"', approval_source)
    require(len(dispatched) == len(set(dispatched)), "unsupported dispatch contains duplicate surfaces")
    require(
        set(dispatched) == set(registry),
        "every canonical unsupported surface must have exactly one literal dispatch call",
    )

    exec_source = read("crates/ownmesh/src/commands/exec.rs")
    device_guard = exec_source.find("if let Some(device) = &args.device")
    daemon_call = exec_source.find("let value = call_local_daemon")
    require(0 <= device_guard < daemon_call, "exec --device must be rejected before local IPC")
    guard_window = exec_source[device_guard:daemon_call]
    require("return Err(" in guard_window, "exec --device guard must return a hard error")
    require("using local daemon" not in exec_source, "exec --device still advertises local fallback")

    broker_install = read("crates/ownmesh-broker/src/install.rs")
    broker_cli = read("crates/ownmesh/src/commands/privileged.rs")
    require_text(broker_install, 'installed: false', "broker install fail-closed marker")
    require_text(broker_install, "no native service was activated or verified", "broker install hard error")
    require_text(broker_install, "native service absence cannot be verified", "broker uninstall hard error")
    require("fallback_install" not in broker_cli, "CLI must not create an installed fallback marker")
    require('"installed": true' not in broker_cli, "CLI must not synthesize installed=true")
    require_text(broker_cli, "native service absence is not independently verified", "broker CLI uninstall hard error")

    device_source = read("crates/ownmesh/src/commands/device_cmd.rs")
    require_text(device_source, "device_rename_not_supported", "device rename contract")
    require_text(device_source, "device_labels_not_supported", "device labels contract")
    policy_source = read("crates/ownmesh/src/commands/policy_cmd.rs")
    policy_rule = policy_source[policy_source.find("PolicyCmd::Rule"):policy_source.find("PolicyCmd::Validate")]
    require_text(policy_rule, '"status": "not_implemented"', "policy mutation JSON contract")
    require_text(policy_rule, "Err(ExitCode::ProfileUnavailable)", "policy mutation hard-error contract")
    approval_watch = approval_source[approval_source.find("ApprovalCmd::Watch"):]
    require_text(approval_watch, '"approval watch"', "approval watch contract")
    require_text(approval_watch, "super::unsupported", "approval watch hard-error contract")
    require("call_daemon" not in approval_watch, "approval watch must not silently perform a one-shot list")

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
    mutable_uses = re.findall(r"(?m)^\s*uses:\s*([^\s]+)@(?![0-9a-f]{40}(?:\s|$))([^\s#]+)", workflows)
    require(not mutable_uses, f"all external Actions must use immutable commit SHAs: {mutable_uses}")
    require("@master" not in workflows and "@main" not in workflows, "mutable action branches are forbidden")
    require("pnpm dlx @cyclonedx/cdxgen@11.0.1" in security, "cdxgen must be version-pinned")
    require_text(security, "tool: cargo-audit@0.22.2", "cargo-audit version pin")
    require(not re.search(r"cargo install\s+[^\s]+(?:\s|$)(?!.*--version)", workflows),
            "cargo install tools must specify --version")
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
    require_text(publish_job, 'archive="dist/ownmesh-${GITHUB_REF_NAME}-${platform}.tar.gz"',
                 "Release artifact consumer")
    require_text(publish_job, 'test -s "${archive}"', "Release artifact consumer")
    require_text(build_job, "if-no-files-found: error", "Release artifact upload")
    require_text(build_job, "name: release-${{ matrix.platform }}", "Release artifact producer")
    require_text(publish_job, "pattern: release-*", "Release artifact consumer")
    require_text(release, "test -s dist/sbom-rust.cdx.json", "Release artifact validation")
    require_text(release, "test -s dist/sbom-control-plane.cdx.json", "Release artifact validation")
    for packaged_file in ("LICENSE", "NOTICE", "README.md", "RELEASE_NOTES.md"):
        require_text(build_job, f'test -s "${{staging}}/{packaged_file}"', "Release archive metadata")
        require_text(
            publish_job,
            f'grep -Fxq "ownmesh-${{GITHUB_REF_NAME}}-${{platform}}/{packaged_file}"',
            "Published archive metadata validation",
        )
    require_text(
        publish_job,
        "actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be",
        "Release provenance",
    )
    require_text(publish_job, "DEGRADED PRE-RELEASE", "Release signing waiver")
    require_text(publish_job, "prerelease: ${{ steps.signing.outputs.available != 'true' }}",
                 "Release signing waiver")
    require_text(publish_job, "docs/release-keys/minisign.pub", "Release signing trust root")
    require_text(publish_job, "minisign -Vm", "Release signature verification")
    require("RELEASE_NOTES_v1.0.1.md" not in release, "release body must not be fixed to v1.0.1")
    require_text(release, "RELEASE_NOTES_${GITHUB_REF_NAME}.md", "Release notes lookup")

    require("secrets: inherit" not in release, "reusable Security gate must not inherit every repository secret")
    require(
        re.search(r"(?ms)^permissions:\n  contents: read\s*$", security) is not None,
        "Security workflow default permissions must remain contents:read",
    )
    secret_job = job_block(security, "secret-scanning")
    require_text(secret_job, "security-events: write", "Secret scanning permissions")
    for job_id in ("rust-dependency-audit", "js-dependency-audit", "sast-rust", "sast-typescript", "sbom", "audit-retention-and-redaction", "release-policy"):
        require("security-events: write" not in job_block(security, job_id),
                f"Security {job_id} must not receive security-events:write")

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
            require_text(text, "44 explicit unsupported CLI surfaces", path)
            require_text(text, "51 total", path)
            require_text(text, "release/SUPPORTED_SURFACES.json", path)

    contributing = read("CONTRIBUTING.md")
    require("1.85" not in contributing, "CONTRIBUTING still documents Rust 1.85")
    require_text(contributing, "Rust **1.92", "CONTRIBUTING")
    require_text(contributing, "Branch protection check-name migration", "CONTRIBUTING")
    require_text(contributing, "Rust 1.92 (Windows)", "CONTRIBUTING branch protection")
    require_text(contributing, "Release claims and gate structure", "CONTRIBUTING branch protection")

    if ERRORS:
        for error in ERRORS:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(
        f"release-quality checks passed: gates fail closed; "
        f"{len(surfaces)} registry-backed / {len(surfaces) + len(additional)} total unsupported surfaces"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
