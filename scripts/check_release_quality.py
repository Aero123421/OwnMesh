#!/usr/bin/env python3
"""Fail-closed static checks for OwnMesh release claims and workflow gates."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ERRORS: list[str] = []

# Step list form (`- uses:`) and mapping form (`uses:` under a named step).
# Local reusable workflow / action refs start with ./ and are exempt from SHA pins.
_USES_LINE_RE = re.compile(r"(?m)^[ \t]*(?:-\s+)?uses:\s*([^\s#]+)")
_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


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


def find_action_uses(workflow_text: str) -> list[str]:
    """Return every `uses:` ref in workflow YAML (step- and job-level)."""
    return _USES_LINE_RE.findall(workflow_text)


def rust_string_registry(source: str, const_name: str) -> list[str] | None:
    """Extract an ordered Rust ``&[&str]`` registry by constant name."""
    match = re.search(
        rf"pub const {re.escape(const_name)}: &\[&str\] = &\[(.*?)\];",
        source,
        re.DOTALL,
    )
    if match is None:
        return None
    return re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', match.group(1))


def find_mutable_action_pins(workflow_text: str) -> list[str]:
    """Return external action refs not pinned to a full 40-char lowercase commit SHA.

    Local refs (starting with ``./``) are excluded. Everything else must be
    ``owner/name[@/path]@<40-hex-sha>`` — tags, branches, short SHAs, and bare
    action names are rejected.
    """
    mutable: list[str] = []
    for ref in find_action_uses(workflow_text):
        if ref.startswith("./"):
            continue
        if "@" not in ref:
            mutable.append(ref)
            continue
        _action, pin = ref.rsplit("@", 1)
        if not _FULL_SHA_RE.fullmatch(pin):
            mutable.append(ref)
    return mutable


def main() -> int:
    ERRORS.clear()

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
    registry = rust_string_registry(commands, "EXPLICIT_UNSUPPORTED_CLI_SURFACES")
    additional_registry = rust_string_registry(commands, "ADDITIONAL_UNSUPPORTED_CLI_SURFACES")
    require(registry is not None, "canonical Rust explicit unsupported-surface registry is missing")
    require(additional_registry is not None, "canonical Rust additional unsupported-surface registry is missing")
    registry = registry or []
    additional_registry = additional_registry or []
    require(
        registry == surfaces,
        "manifest explicit unsupported surfaces must exactly match the ordered Rust registry",
    )
    require(
        additional_registry == additional,
        "manifest additional unsupported surfaces must exactly match the ordered Rust registry",
    )
    require(
        "EXPLICIT_UNSUPPORTED_CLI_SURFACES.contains(&command)" in commands
        and "ADDITIONAL_UNSUPPORTED_CLI_SURFACES.contains(&command)" in commands,
        "runtime unsupported helper must validate commands against both canonical registries",
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

    device_source = read("crates/ownmesh/src/commands/device_cmd.rs")
    exec_source = read("crates/ownmesh/src/commands/exec.rs")
    session_source = read("crates/ownmesh/src/commands/session_cmd.rs")
    policy_source = read("crates/ownmesh/src/commands/policy_cmd.rs")
    broker_cli = read("crates/ownmesh/src/commands/privileged.rs")
    additional_dispatched = re.findall(
        r'\bsuper::unsupported\(\s*cli,\s*"([^"]+)"', device_source
    )
    for source in (exec_source, session_source, policy_source, broker_cli):
        additional_dispatched += re.findall(r'\bsuper::unsupported_exit\("([^"]+)"\)', source)
    require(
        set(additional_dispatched) == set(additional_registry),
        "every additional registry surface must map to a real hard-error handler, and no arbitrary string may pass",
    )

    device_guard = exec_source.find("if let Some(device) = &args.device")
    daemon_call = exec_source.find("let value = call_local_daemon")
    require(0 <= device_guard < daemon_call, "exec --device must be rejected before local IPC")
    guard_window = exec_source[device_guard:daemon_call]
    require("return Err(" in guard_window, "exec --device guard must return a hard error")
    require("using local daemon" not in exec_source, "exec --device still advertises local fallback")

    broker_install = read("crates/ownmesh-broker/src/install.rs")
    require_text(broker_install, 'installed: false', "broker install fail-closed marker")
    require_text(broker_install, "no native service was activated or verified", "broker install hard error")
    require_text(broker_install, "native service absence cannot be verified", "broker uninstall hard error")
    require("fallback_install" not in broker_cli, "CLI must not create an installed fallback marker")
    require('"installed": true' not in broker_cli, "CLI must not synthesize installed=true")
    require_text(broker_cli, "native service absence is not independently verified", "broker CLI uninstall hard error")

    require_text(device_source, "device_rename_not_supported", "device rename contract")
    require_text(device_source, "device_labels_not_supported", "device labels contract")
    policy_rule = policy_source[policy_source.find("PolicyCmd::Rule"):policy_source.find("PolicyCmd::Validate")]
    require_text(policy_rule, '"status": "not_implemented"', "policy mutation JSON contract")
    require_text(policy_rule, 'super::unsupported_exit("policy rule mutation")', "policy mutation hard-error contract")
    approval_watch = approval_source[approval_source.find("ApprovalCmd::Watch"):]
    require_text(approval_watch, '"approval watch"', "approval watch contract")
    require_text(approval_watch, "super::unsupported", "approval watch hard-error contract")
    require("call_daemon" not in approval_watch, "approval watch must not silently perform a one-shot list")

    session_guard = session_source.find("device: Some(device)")
    session_call = session_source.find('call_local_daemon(\n                "session.open"')
    require(0 <= session_guard < session_call, "remote session target must fail before local IPC")
    require('super::unsupported_exit("session open <device>")' in session_source[session_guard:session_call],
            "remote session target must return a registry-backed hard error")

    ci = read(".github/workflows/ci.yml")
    security = read(".github/workflows/security.yml")
    release = read(".github/workflows/release.yml")
    workflow_dir = ROOT / ".github/workflows"
    workflow_paths = sorted([*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")])
    workflows = "\n".join(path.read_text(encoding="utf-8") for path in workflow_paths)
    require("1.85" not in workflows, "workflow toolchains must not reference Rust 1.85")
    require("continue-on-error" not in workflows, "required workflow jobs cannot continue on error")
    require("|| true" not in workflows, "workflow validation cannot discard failures")
    mutable_uses = find_mutable_action_pins(workflows)
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
    # Checkout must drop credentials; every build/publish checkout needs the flag.
    release_jobs = build_job + "\n" + publish_job
    checkout_count = len(re.findall(r"(?m)^\s*- uses:\s*actions/checkout@[0-9a-f]{40}", release_jobs))
    secure_checkout_count = len(
        re.findall(
            r"(?m)^(?P<i>\s*)- uses:\s*actions/checkout@[0-9a-f]{40}[^\n]*\n"
            r"(?P=i)  with:\n(?P=i)    persist-credentials:\s*false\s*$",
            release_jobs,
        )
    )
    require(checkout_count >= 2, "Release build/publish must checkout the repository")
    require(
        secure_checkout_count == checkout_count,
        "Every release build/publish checkout must set persist-credentials: false",
    )
    # Publish permissions stay narrowly scoped (no expansion beyond the three writes).
    require_text(publish_job, "contents: write", "Release publish permissions")
    require_text(publish_job, "attestations: write", "Release publish permissions")
    require_text(publish_job, "id-token: write", "Release publish permissions")
    pub_perm_match = re.search(r"(?ms)^    permissions:\n((?:      \S[^\n]*\n)+)", publish_job)
    require(pub_perm_match is not None, "Release publish must declare explicit permissions")
    if pub_perm_match is not None:
        perm_keys = set(re.findall(r"^      ([a-z-]+):", pub_perm_match.group(1), re.MULTILINE))
        require(
            perm_keys == {"contents", "attestations", "id-token"},
            "Release publish permissions must stay exactly "
            f"contents/attestations/id-token, got {sorted(perm_keys)}",
        )
    # Publish must verify the five required binaries inside each platform archive.
    require_text(
        publish_job,
        "for binary in ownmesh ownmesh-tui ownmeshd ownmesh-session-host ownmesh-broker; do",
        "Published archive binary validation",
    )
    require_text(
        publish_job,
        'grep -Fxq "ownmesh-${GITHUB_REF_NAME}-${platform}/${binary}${ext}" "${listing}"',
        "Published archive binary validation",
    )
    require_text(publish_job, 'ext=".exe"', "Published archive Windows binary extension")
    require_text(build_job, "binary_extension: .exe", "Release Windows binary extension")
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
