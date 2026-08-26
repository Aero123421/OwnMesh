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
    additional = manifest.get("additional_unsupported", [])
    expected = manifest.get("explicit_unsupported_count")
    require(isinstance(surfaces, list), "explicit unsupported surfaces must be an array")
    require(isinstance(additional, list), "additional unsupported surfaces must be an array")
    require(
        all(isinstance(surface, str) and surface for surface in surfaces),
        "explicit unsupported surfaces must be non-empty strings",
    )
    require(
        all(isinstance(surface, str) and surface for surface in additional),
        "additional unsupported surfaces must be non-empty strings",
    )
    require(len(surfaces) == expected, "surface manifest count does not match its entries")
    require(len(set(surfaces)) == len(surfaces), "surface manifest contains duplicate entries")
    require(len(set(additional)) == len(additional), "additional unsupported list contains duplicates")
    require(
        set(surfaces).isdisjoint(additional),
        "explicit and additional unsupported lists must not overlap",
    )
    total_unsupported = len(surfaces) + len(additional)
    require(
        manifest.get("total_unsupported_surfaces") == total_unsupported,
        "total unsupported count must be derived from both manifest lists",
    )
    completeness_claim = manifest.get("completeness_claim")
    require(isinstance(completeness_claim, bool), "completeness_claim must be a boolean")
    require(
        completeness_claim is (total_unsupported == 0),
        "completeness_claim must be true exactly when no unsupported surfaces remain",
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
    if registry or additional_registry:
        require(
            "EXPLICIT_UNSUPPORTED_CLI_SURFACES.contains(&command)" in commands
            and "ADDITIONAL_UNSUPPORTED_CLI_SURFACES.contains(&command)" in commands,
            "runtime unsupported helper must validate commands against both canonical registries",
        )
    exec_source = read("crates/ownmesh/src/commands/exec.rs")
    broker_cli = read("crates/ownmesh/src/commands/privileged.rs")
    require("using local daemon" not in exec_source, "exec --device still advertises local fallback")

    broker_install = read("crates/ownmesh-broker/src/install.rs")
    require_text(broker_install, 'installed: false', "broker install fail-closed marker")
    require("fallback_install" not in broker_cli, "CLI must not create an installed fallback marker")
    require('"installed": true' not in broker_cli, "CLI must not synthesize installed=true")
    require_text(broker_cli, "native service absence is not independently verified", "broker CLI uninstall hard error")

    ci = read(".github/workflows/ci.yml")
    security = read(".github/workflows/security.yml")
    release = read(".github/workflows/release.yml")
    installer_tests = read("scripts/tests/test_installers.py")
    attributes = read(".gitattributes")
    workflow_dir = ROOT / ".github/workflows"
    workflow_paths = sorted([*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")])
    workflows = "\n".join(path.read_text(encoding="utf-8") for path in workflow_paths)

    rust_job = job_block(ci, "rust")
    release_truthfulness_job = job_block(ci, "release-truthfulness")
    require_text(rust_job, "Windows portable installer integration", "Windows installer CI gate")
    require_text(rust_job, "python scripts/tests/test_installers.py", "Windows installer CI gate")
    require_text(
        rust_job,
        "b9c31c2c3034f81f0e5f5d92cbcc20e67a9671b6e5455661588638848dc58031",
        "Windows installer pinned minisign bootstrap",
    )
    require_text(
        release_truthfulness_job,
        "Unix portable installer integration",
        "Unix installer CI gate",
    )
    require_text(
        release_truthfulness_job,
        "python scripts/tests/test_installers.py",
        "Unix installer CI gate",
    )
    require_text(
        release_truthfulness_job,
        "f0a0954413df8531befed169e447a66da6868d79052ed7e892e50a4291af7ae0",
        "Unix installer pinned minisign bootstrap",
    )
    require_text(installer_tests, '["sh", "-n", str(SH_INSTALLER)]', "POSIX installer syntax gate")
    require_text(attributes, "*.sh text eol=lf", "POSIX installer line endings")
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
    dist_job = job_block(release, "distribution-metadata")
    publish_job = job_block(release, "publish")
    require_text(ci_gate, "uses: ./.github/workflows/ci.yml", "Release ci-gate")
    require_text(security_gate, "uses: ./.github/workflows/security.yml", "Release security-gate")
    require("steps:" not in ci_gate and "runs-on:" not in ci_gate, "ci-gate must remain a reusable workflow call")
    require("steps:" not in security_gate and "runs-on:" not in security_gate,
            "security-gate must remain a reusable workflow call")
    require_text(build_job, "needs: [ci-gate, security-gate]", "Release build")
    require_text(dist_job, "needs: [ci-gate, security-gate, build]", "Release distribution-metadata")
    require_text(publish_job, "needs: [ci-gate, security-gate, build, distribution-metadata]",
                 "Release publish")
    require("if: always()" not in publish_job, "publish must not run after failed prerequisites")
    for asset in (
        "ownmesh-windows-x64.zip",
        "ownmesh-macos-arm64.tar.gz",
        "ownmesh-macos-x64.tar.gz",
        "ownmesh-linux-x64.tar.gz",
        "ownmesh-linux-arm64.tar.gz",
    ):
        require_text(build_job, f"asset: {asset}", "Release matrix asset")
        require_text(publish_job, asset, "Release publish asset")
    require_text(build_job, "x86_64-unknown-linux-musl", "Release linux musl x64")
    require_text(build_job, "aarch64-unknown-linux-musl", "Release linux musl arm64")
    require_text(build_job, "aarch64-apple-darwin", "Release macos arm64")
    require_text(build_job, "x86_64-apple-darwin", "Release macos x64")
    require_text(build_job, "x86_64-pc-windows-msvc", "Release windows x64")
    require_text(build_job, "if-no-files-found: error", "Release artifact upload")
    require_text(build_job, "name: release-${{ matrix.platform }}", "Release artifact producer")
    require_text(publish_job, "pattern: release-*", "Release artifact consumer")
    require_text(release, "test -s dist/sbom-rust.cdx.json", "Release artifact validation")
    require_text(release, "test -s dist/sbom-control-plane.cdx.json", "Release artifact validation")
    for packaged_file in ("LICENSE", "NOTICE", "README.md", "RELEASE_NOTES.md"):
        require_text(build_job, packaged_file, "Release archive metadata")
        require_text(publish_job, packaged_file, "Published archive metadata validation")
    require_text(dist_job, "ownmesh-installer.sh", "Release installer asset")
    require_text(dist_job, "ownmesh-installer.ps1", "Release installer asset")
    require_text(dist_job, "scripts/render_distribution.py", "Release homebrew render")
    require_text(dist_job, "ownmesh.rb", "Release homebrew formula asset")
    require_text(publish_job, "ownmesh-release-meta.json", "Release meta asset")
    # Checkout must drop credentials; every build/publish/dist checkout needs the flag.
    release_jobs = build_job + "\n" + dist_job + "\n" + publish_job
    checkout_count = len(re.findall(r"(?m)^\s*- uses:\s*actions/checkout@[0-9a-f]{40}", release_jobs))
    secure_checkout_count = len(
        re.findall(
            r"(?m)^(?P<i>\s*)- uses:\s*actions/checkout@[0-9a-f]{40}[^\n]*\n"
            r"(?P=i)  with:\n(?P=i)    persist-credentials:\s*false\s*$",
            release_jobs,
        )
    )
    require(checkout_count >= 3, "Release build/dist/publish must checkout the repository")
    require(
        secure_checkout_count == checkout_count,
        "Every release build/dist/publish checkout must set persist-credentials: false",
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
    # Build and publish must cover the five required binaries.
    require_text(
        build_job,
        "for binary in ownmesh ownmesh-tui ownmeshd ownmesh-session-host ownmesh-broker; do",
        "Release archive binary packaging",
    )
    require_text(
        publish_job,
        '"ownmesh","ownmesh-tui","ownmeshd","ownmesh-session-host","ownmesh-broker"',
        "Published archive binary validation",
    )
    require_text(
        publish_job,
        "actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be",
        "Release provenance",
    )
    # Formal releases require minisign; degraded unsigned publish is forbidden.
    require("DEGRADED PRE-RELEASE" not in publish_job, "formal release must not allow degraded unsigned publish")
    require_text(publish_job, "MINISIGN_SECRET_KEY secret is required", "Release signing required")
    require_text(publish_job, "docs/release-keys/minisign.pub", "Release signing trust root")
    require_text(publish_job, "minisign -Vm", "Release signature verification")
    require_text(publish_job, "minisign -S", "Release signature creation")
    require_text(
        publish_job,
        "f0a0954413df8531befed169e447a66da6868d79052ed7e892e50a4291af7ae0",
        "Release publish pinned minisign bootstrap",
    )
    require("apt-get install -y minisign" not in publish_job,
            "Release publish must not install minisign via apt (can stall)")
    require_text(publish_job, "prerelease: false", "Formal release is not forced prerelease")
    require("RELEASE_NOTES_v1.0.1.md" not in release, "release body must not be fixed to v1.0.1")
    require_text(release, "RELEASE_NOTES_${GITHUB_REF_NAME}.md", "Release notes lookup")
    require((ROOT / "docs/release-keys/minisign.pub").is_file(), "minisign trust root must be tracked")
    require((ROOT / "installers/ownmesh-installer.sh").is_file(), "unix installer must exist")
    require((ROOT / "installers/ownmesh-installer.ps1").is_file(), "windows installer must exist")
    require((ROOT / "packaging/homebrew/ownmesh.rb.template").is_file(), "homebrew template must exist")

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
        ver = version_match.group(1)
        # Keep package milestone versions aligned with the workspace release train.
        root_pkg = read("package.json")
        cp_pkg = read("packages/control-plane/package.json")
        schema_pkg = read("packages/ownmesh-schema/package.json")
        surfaces_txt = read("release/SUPPORTED_SURFACES.json")
        for label, body in (
            ("package.json", root_pkg),
            ("packages/control-plane/package.json", cp_pkg),
            ("packages/ownmesh-schema/package.json", schema_pkg),
        ):
            m = re.search(r'"version"\s*:\s*"([^"]+)"', body)
            require(m is not None, f"{label} version missing")
            if m:
                require(
                    m.group(1) == ver,
                    f"{label} version {m.group(1)} must match workspace {ver}",
                )
        # MCP initialize/health surface SERVICE_VERSION — must match the train.
        util_ts = read("packages/control-plane/src/util.ts")
        svc_ver = re.search(
            r'export const SERVICE_VERSION\s*=\s*"([^"]+)"', util_ts
        )
        require(svc_ver is not None, "SERVICE_VERSION missing in util.ts")
        if svc_ver:
            require(
                svc_ver.group(1) == ver,
                f"SERVICE_VERSION {svc_ver.group(1)} must match workspace {ver}",
            )
        train = re.search(r'"release_train"\s*:\s*"([^"]+)"', surfaces_txt)
        require(train is not None, "release/SUPPORTED_SURFACES.json release_train missing")
        if train:
            require(
                train.group(1) == ver,
                f"release_train {train.group(1)} must match workspace {ver}",
            )
        current_notes = f"docs/RELEASE_NOTES_v{ver}.md"
        require((ROOT / current_notes).is_file(), f"missing current release notes: {current_notes}")
        claim_docs = ["README.md", "docs/DOD_1.0.md", current_notes]
        for path in claim_docs:
            text = read(path)
            require_text(text, "release/SUPPORTED_SURFACES.json", path)

    contributing = read("CONTRIBUTING.md")
    require("1.85" not in contributing, "CONTRIBUTING still documents Rust 1.85")
    require_text(contributing, "Rust **1.92", "CONTRIBUTING")

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
