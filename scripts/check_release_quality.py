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


def suite_section(suites_text: str, suite_name: str) -> str:
    """Return one TOML suite section body (fail-closed: empty when missing).

    Callers MUST NOT use the return value in a bare ``needle not in section``
    assertion: an empty (missing) section would vacuously pass. Assert
    presence first (``require(section != "", ...)``) or use require_text.
    """
    match = re.search(
        rf"(?ms)^\[{re.escape(suite_name)}\]\n(.*?)(?=^\[[^\]]+\]|\Z)",
        suites_text,
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
    evidence_waivers = manifest.get("release_evidence_waivers", [])
    expected = manifest.get("explicit_unsupported_count")
    require(isinstance(surfaces, list), "explicit unsupported surfaces must be an array")
    require(isinstance(additional, list), "additional unsupported surfaces must be an array")
    require(isinstance(evidence_waivers, list), "release evidence waivers must be an array")
    require(
        all(isinstance(surface, str) and surface for surface in surfaces),
        "explicit unsupported surfaces must be non-empty strings",
    )
    require(
        all(isinstance(surface, str) and surface for surface in additional),
        "additional unsupported surfaces must be non-empty strings",
    )
    require(
        all(isinstance(waiver, str) and waiver for waiver in evidence_waivers),
        "release evidence waivers must be non-empty strings",
    )
    require(len(surfaces) == expected, "surface manifest count does not match its entries")
    require(len(set(surfaces)) == len(surfaces), "surface manifest contains duplicate entries")
    require(len(set(additional)) == len(additional), "additional unsupported list contains duplicates")
    require(
        len(set(evidence_waivers)) == len(evidence_waivers),
        "release evidence waiver list contains duplicates",
    )
    require(
        set(surfaces).isdisjoint(additional),
        "explicit and additional unsupported lists must not overlap",
    )
    require(
        set(evidence_waivers).isdisjoint(surfaces)
        and set(evidence_waivers).isdisjoint(additional),
        "release evidence waivers must not overlap unsupported surface registries",
    )
    total_unsupported = len(surfaces) + len(additional) + len(evidence_waivers)
    require(
        manifest.get("total_unsupported_surfaces") == total_unsupported,
        "total unsupported count must include both registries and evidence waivers",
    )
    completeness_claim = manifest.get("completeness_claim")
    require(isinstance(completeness_claim, bool), "completeness_claim must be a boolean")
    require(
        completeness_claim is (total_unsupported == 0),
        "completeness_claim must be true exactly when no unsupported surfaces or evidence waivers remain",
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
    scale_wf = read(".github/workflows/scale.yml")
    installer_tests = read("scripts/tests/test_installers.py")
    attributes = read(".gitattributes")
    workflow_dir = ROOT / ".github/workflows"
    workflow_paths = sorted([*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")])
    workflows = "\n".join(path.read_text(encoding="utf-8") for path in workflow_paths)

    # --- Tiered CI structure (ADR 0022) ---
    plan_job = job_block(ci, "plan")
    rust_linux_job = job_block(ci, "rust-linux")
    ts_job = job_block(ci, "typescript")
    win_job = job_block(ci, "platform-windows")
    mac_job = job_block(ci, "platform-macos")
    sec_fast_job = job_block(ci, "security-fast")
    rel_policy_job = job_block(ci, "release-policy")
    required_job = job_block(ci, "required")
    secreq_job = job_block(ci, "security-required")
    require_text(plan_job, "scripts/ci/plan.py", "CI plan")
    require_text(plan_job, "ci-plan.json", "CI plan evidence")
    # Canonical runner: suite commands live only in suites.toml; ci.yml holds
    # orchestration/permissions/OS and invokes via run.py (no direct duplication).
    suites = read("scripts/ci/suites.toml")
    run_py = read("scripts/ci/run.py")
    # Linux is the sole full workspace test; Windows/macOS must not run it
    # (checked both in the runner invocation and in the canonical suite text).
    require_text(rust_linux_job, "scripts/ci/run.py rust-linux", "Linux via canonical runner")
    require_text(rust_linux_job, "scripts/ci/run.py rust-linux-stateful", "Linux stateful via canonical runner")
    require_text(suites, "cargo test --workspace --all-targets --locked", "Linux full test in suites.toml")
    require("cargo test --workspace --all-targets --locked" not in win_job,
            "Windows must not run full workspace test")
    require("cargo test --workspace --all-targets --locked" not in mac_job,
            "macOS must not run full workspace test")
    win_section = suite_section(suites, "platform-windows")
    mac_section = suite_section(suites, "platform-macos")
    require(win_section != "", "platform-windows suite section missing (fail-closed)")
    require(mac_section != "", "platform-macos suite section missing (fail-closed)")
    require("cargo test --workspace --all-targets --locked" not in win_section,
            "Windows suite must not run full workspace test")
    require("cargo test --workspace --all-targets --locked" not in mac_section,
            "macOS suite must not run full workspace test")
    require_text(win_job, "scripts/ci/run.py platform-windows", "Windows via canonical runner")
    require_text(mac_job, "scripts/ci/run.py platform-macos", "macOS via canonical runner")
    require_text(suites, "cargo check --workspace --all-targets --locked", "platform compat in suites.toml")
    # No separate full `cargo build --workspace` duplicate (clippy+test cover it).
    require("cargo build --workspace --locked" not in rust_linux_job,
            "Linux must not duplicate full cargo build")
    require("cargo build --workspace --locked" not in suites,
            "suites.toml must not duplicate full cargo build")
    # Direct command duplication in ci.yml is forbidden (single source is suites.toml).
    for direct in (
        "run: cargo fmt --all --check",
        "run: cargo clippy --workspace --all-targets",
        "run: cargo test --workspace --all-targets",
        "run: pnpm -r test",
        "run: pnpm -r typecheck",
        "run: pnpm -r lint",
        "run: cargo run --locked -p ownmesh-tui",
        "run: python3 scripts/check_release_quality.py",
        "run: python3 scripts/tests/run_release_quality_tests.py",
    ):
        require(direct not in ci, f"CI must invoke via run.py, not direct {direct!r}")
    # TUI snapshot duplication removed (only --check-i18n remains, via runner).
    tui_job = job_block(ci, "tui-i18n")
    require_text(tui_job, "scripts/ci/run.py tui-i18n", "TUI via canonical runner")
    require_text(suites, "--check-i18n", "TUI i18n unique gate in suites.toml")
    require("cargo test --locked -p ownmesh-tui" not in tui_job,
            "TUI snapshot must not duplicate workspace test")
    require("cargo test --locked -p ownmesh-tui" not in suites,
            "suites.toml must not duplicate TUI snapshot test")
    # TypeScript gates are single-sourced (runner dispatches; commands live in suites.toml).
    require_text(ts_job, "scripts/ci/run.py typescript", "TypeScript via canonical runner")
    # Security-fast: pinned action wraps the canonical gitleaks scan; boundary
    # tests run via the canonical runner (no direct cargo duplication).
    require_text(sec_fast_job, "scripts/ci/run.py security-boundary", "security boundary via canonical runner")
    require("cargo test --locked -p ownmesh-diagnostics" not in sec_fast_job,
            "security boundary must run via run.py, not direct cargo")
    require_text(suites, "cargo test --locked -p ownmesh-diagnostics", "security boundary in suites.toml")
    # TypeScript path-aware + single typecheck (schema package no longer embeds tsc).
    schema_pkg = read("packages/ownmesh-schema/package.json")
    require("tsc --noEmit &&" not in schema_pkg, "schema test must not duplicate typecheck")
    # Fixed aggregators are the only required checks.
    require_text(required_job, "CI / required", "required aggregator")
    require_text(secreq_job, "CI / security-required", "security-required aggregator")
    require_text(ci, "cancel-in-progress: ${{ github.event_name == 'pull_request' }}", "PR-only cancel")
    require("workflow_call" not in ci, "CI must not expose workflow_call (release consumes evidence, not reusable calls)")

    # --- Label-driven CI + CodeRabbit gate (fail-closed, least privilege) ---
    plan_py = read("scripts/ci/plan.py")
    require_text(plan_py, "def parse_labels", "plan label input")
    require_text(plan_py, "LABEL_REVIEW_READY", "plan review-ready label")
    require_text(plan_py, "LABEL_HOTFIX", "plan hotfix label")
    require_text(plan_py, "LABEL_DO_NOT_MERGE", "plan do-not-merge label")
    require_text(plan_py, '"hotfix"', "plan hotfix output")
    require_text(plan_py, '"do_not_merge"', "plan do-not-merge output")
    require_text(plan_py, '"heavy_deferred"', "plan heavy-deferred proof")
    require_text(plan_py, "label review-ready (full)", "plan review-ready forces full")
    require_text(plan_job, "join(github.event.pull_request.labels", "plan receives PR labels")
    require_text(plan_job, "hotfix", "plan exposes hotfix output")
    require_text(plan_job, "do_not_merge", "plan exposes do-not-merge output")
    call_job = job_block(ci, "coderabbit-call")
    gate_job = job_block(ci, "coderabbit-gate")
    require_text(call_job, "CodeRabbit auto-call", "coderabbit-call job")
    require_text(call_job, "stargazers_count", "coderabbit-call star check")
    require_text(call_job, "@coderabbitai review", "coderabbit-call posts review call")
    require_text(call_job, "full review", "coderabbit-call full review on review-ready")
    require_text(call_job, "coderabbitai[bot]", "coderabbit-call bot-loop guard")
    require_text(call_job, "pull-requests: write", "coderabbit-call least-privilege write")
    require("contents: write" not in call_job, "coderabbit-call must not escalate to contents:write")
    require("uses:" not in call_job, "coderabbit-call must use preinstalled gh only (SHA pins unchanged)")
    require("secrets: inherit" not in ci, "CI must not inherit every repository secret")
    require_text(gate_job, "fail-closed", "coderabbit-gate fail-closed")
    require_text(gate_job, "@coderabbitai", "coderabbit-gate call trace check")
    require_text(gate_job, "coderabbitai", "coderabbit-gate review-author check")
    require_text(gate_job, "pull-requests: read", "coderabbit-gate read-only")
    require("pull-requests: write" not in gate_job, "coderabbit-gate must stay read-only")
    require_text(gate_job, "do-not-merge", "coderabbit-gate do-not-merge handling")
    require_text(gate_job, "draft", "coderabbit-gate draft handling")
    require_text(required_job, "needs.get(\"coderabbit-gate\"", "required asserts coderabbit-gate result")
    require_text(ci, "tui-i18n, coderabbit-gate]", "required aggregates coderabbit-gate in needs")
    require_text(required_job, "do_not_merge", "required blocks do-not-merge")
    require_text(required_job, "do-not-merge label blocks merge", "required do-not-merge failure")
    # Branch protection keeps exactly the two aggregators (no new context).
    verify_ruleset = read("scripts/ci/verify_ruleset.py")
    require_text(verify_ruleset, '"CI / required"', "ruleset keeps CI / required")
    require_text(verify_ruleset, '"CI / security-required"', "ruleset keeps CI / security-required")
    require(verify_ruleset.count("CI / ") == 2, "branch protection must keep exactly two required contexts")
    coderabbit_cfg = read(".coderabbit.yaml")
    require_text(coderabbit_cfg, "enabled: true", "coderabbit auto_review enabled")
    require_text(coderabbit_cfg, "auto_incremental_review: true", "coderabbit incremental review")
    require_text(coderabbit_cfg, "request_changes_workflow: false", "coderabbit advisory request-changes (CI gate is the blocker)")
    # Heavy tiers stay nightly/weekly/release-only, never PR gates.
    e2e_wf = read(".github/workflows/e2e-loopback.yml")
    require("pull_request" not in scale_wf, "scale must not run on PRs (nightly/weekly only)")
    require("pull_request" not in e2e_wf, "e2e must not run on PRs (nightly/release only)")
    tiers_doc = read("docs/ci-test-tiers.md")
    require_text(tiers_doc, "review-ready", "tiers doc label table")
    require_text(tiers_doc, "do-not-merge", "tiers doc do-not-merge")
    require_text(tiers_doc, "heavy_deferred", "tiers doc heavy-deferred proof")
    require_text(tiers_doc, "coderabbit-call", "tiers doc CodeRabbit automation")
    require_text(tiers_doc, "coderabbit-gate", "tiers doc CodeRabbit gate")
    require_text(read("CONTRIBUTING.md"), "CodeRabbitレビューはCIが自動", "CONTRIBUTING automated CodeRabbit")
    require_text(read(".github/pull_request_template.md"), "CodeRabbit", "PR template CodeRabbit automation")
    # Installer gates: Windows installer only on installer/release changes; Unix once via release-policy suite.
    require_text(rust_job if (rust_job := job_block(ci, "rust")) == "" else rust_job, "", "placeholder") if False else None
    require_text(win_job, "python scripts/tests/test_installers.py", "Windows installer gate")
    require_text(rel_policy_job, "scripts/ci/run.py release-policy", "release-policy via canonical runner")
    # Release-policy runs each checker once (no glob rediscovery); commands live in suites.toml.
    require_text(suites, "scripts/tests/test_installers.py", "installer once in suites.toml")
    require_text(suites, "scripts/check_release_quality.py", "live checker once in suites.toml")
    require_text(suites, "scripts/tests/run_release_quality_tests.py", "mutation suite once in suites.toml")
    # The canonical runner must dispatch every suite CI invokes.
    for suite_name in (
        "rust-linux",
        "rust-linux-stateful",
        "typescript",
        "platform-windows",
        "platform-macos",
        "security-fast",
        "security-boundary",
        "release-policy",
        "tui-i18n",
        "scale-filesystem",
    ):
        require_text(run_py, suite_name, f"canonical runner dispatches {suite_name}")
    runner = read("scripts/tests/run_release_quality_tests.py")
    require("loader.discover" not in runner and "unittest discover" not in runner, "mutation runner must not glob-discover installer/E2E")
    require_text(runner, "test_mutations", "mutation-only runner")

    # --- Security deep/scheduled (no PR duplication) ---
    require("pull_request" not in security, "Security must not run on PRs (fast subset lives in CI)")
    require_text(security, 'cron: "17 5 * * 1"', "weekly schedule")
    require("cargo clippy --workspace --all-targets" not in security, "Security must not duplicate CI clippy")
    require("pnpm -r typecheck" not in security or "deep-adversarial" in security, "Security must not duplicate CI typecheck on PR path")
    require_text(security, "secret-scanning-full-history", "full-history secrets")
    require_text(security, "sbom-weekly", "weekly SBOM")
    require_text(security, "deep-adversarial", "weekly deep suite")

    # --- Scale tier ---
    require_text(scale_wf, "scale_directory", "scale workflow runs production boundaries")
    require_text(scale_wf, "--ignored --test-threads=1", "scale runs ignored single-threaded")
    fs_lib = read("crates/ownmesh-fs/src/lib.rs")
    require("const N: usize = 25_050" not in fs_lib, "default unit suite must not create 25k files")
    require("const N: usize = 4_500" not in fs_lib, "4.5k production test must live in scale tier")
    require_text(fs_lib, "DirectoryPagingLimits", "injectable paging limits")
    require_text(fs_lib, "spills_to_disk_after_memory_entry_limit", "small deterministic spill test")
    scale_test = read("crates/ownmesh-fs/tests/scale_directory.rs")
    require_text(scale_test, '#[ignore = "scale:', "scale tests are ignored by default")
    require(
        scale_test.count('#[ignore = "scale:') >= scale_test.count("fn production_"),
        "every production scale test must be #[ignore] (no un-ignored scale test)",
    )
    require(
        "#[test] // scale:" not in scale_test,
        "scale ignore must not be commented out",
    )
    require((ROOT / "scripts/ci/plan.py").is_file(), "planner must exist")
    require((ROOT / "scripts/ci/run.py").is_file(), "canonical runner must exist")
    require((ROOT / "scripts/ci/suites.toml").is_file(), "suite registry must exist")
    require((ROOT / "docs/adr/0022-ci-test-tiers-and-exact-sha-release-evidence.md").is_file(), "tier ADR must exist")
    require((ROOT / "docs/ci-test-tiers.md").is_file(), "tier responsibility doc must exist")
    contributing = read("CONTRIBUTING.md")
    require_text(contributing, "Test taxonomy", "CONTRIBUTING taxonomy")
    require_text(contributing, "DirectoryPagingLimits", "CONTRIBUTING scale example")
    pr_template = read(".github/pull_request_template.md")
    require_text(pr_template, "Test evidence", "PR evidence format")
    require_text(pr_template, "Added test tier", "PR tier record")
    codeowners = read(".github/CODEOWNERS")
    require_text(codeowners, "scripts/ci/", "supply-chain owner for planner")

    # --- Release exact-SHA eligibility (no reusable CI/Security re-run) ---
    require("uses: ./.github/workflows/ci.yml" not in release, "Release must not re-run CI")
    require("uses: ./.github/workflows/security.yml" not in release, "Release must not re-run Security")
    eligibility_job = job_block(release, "release-eligibility")
    sbom_job = job_block(release, "sbom-release")
    require_text(eligibility_job, "scripts/ci/release_eligibility.py", "eligibility proof")
    require_text(eligibility_job, "actions: read", "eligibility needs check-read")
    require_text(sbom_job, "cdxgen@11.0.1", "exact-SHA SBOM generation")
    require_text(sbom_job, "--fail-on-error --validate", "SBOM fail-fast validation")

    # Shared installer/pinning gates (unchanged trust).
    rust_job_old = job_block(ci, "rust")
    # Old `rust` matrix job is gone in tiered CI; installer pins now live in
    # platform-windows + release-policy. Assert pins where they now live.
    require_text(
        win_job,
        "b9c31c2c3034f81f0e5f5d92cbcc20e67a9671b6e5455661588638848dc58031",
        "Windows installer pinned minisign bootstrap",
    )
    require_text(
        rel_policy_job,
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
    require("pnpm dlx @cyclonedx/cdxgen@11.0.1" in workflows, "cdxgen must be version-pinned")
    require_text(security, "tool: cargo-audit@0.22.2", "cargo-audit version pin")
    require(not re.search(r"cargo install\s+[^\s]+(?:\s|$)(?!.*--version)", workflows),
            "cargo install tools must specify --version")

    for command in (
        "cargo fmt --all --check",
        "cargo clippy --workspace --all-targets --locked -- -D warnings",
        "cargo test --workspace --all-targets --locked",
        "pnpm -r test",
        "pnpm -r typecheck",
        "pnpm -r lint",
        "pnpm --dir packages/control-plane exec wrangler deploy --dry-run",
    ):
        require_text(suites, command, "suites.toml canonical commands")

    ci_gate = job_block(release, "ci-gate")
    security_gate = job_block(release, "security-gate")
    require(ci_gate == "" and security_gate == "", "reusable ci-gate/security-gate must not exist")
    build_job = job_block(release, "build")
    candidate_e2e_job = job_block(release, "release-candidate-e2e")
    dist_job = job_block(release, "distribution-metadata")
    publish_job = job_block(release, "publish")
    require_text(build_job, "needs: [release-eligibility]", "Release build eligibility")
    require_text(candidate_e2e_job, "needs: [release-eligibility, build]", "Release candidate E2E")
    require("if: always()" not in publish_job, "publish must not run after failed prerequisites")
    release_jobs_all = "\n".join([
        job_block(release, "release-eligibility"),
        build_job,
        job_block(release, "sbom-release"),
        candidate_e2e_job,
        job_block(release, "release-policy-final"),
        dist_job,
        publish_job,
    ])
    checkout_count = len(re.findall(r"(?m)^\s*- uses:\s*actions/checkout@[0-9a-f]{40}", release_jobs_all))
    secure_checkout_count = len(
        re.findall(
            r"(?m)^(?P<i>\s*)- uses:\s*actions/checkout@[0-9a-f]{40}[^\n]*\n"
            r"(?P=i)  with:\n(?P=i)    persist-credentials:\s*false\s*$",
            release_jobs_all,
        )
    )
    require(checkout_count >= 7, "Release eligibility/build/SBOM/E2E/policy/dist/publish must checkout")
    require(
        secure_checkout_count == checkout_count,
        "Every release checkout must set persist-credentials: false",
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
    secret_job = job_block(security, "secret-scanning-full-history")
    if secret_job == "":
        secret_job = job_block(security, "secret-scanning")
    require_text(secret_job, "security-events: write", "Secret scanning permissions")
    for job_id in ("rust-dependency-audit", "js-dependency-audit", "sbom-weekly", "deep-adversarial"):
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

    # --- Issue #159: machine endpoints must not require a browser signature ---
    # The edge (Cloudflare 1010) cannot be fixed in code, so the release gate
    # pins the three things code+docs CAN guarantee: a probe that distinguishes
    # edge from Worker on every required stack/handshake, docs that scope the
    # WAF skip narrowly without weakening auth/rate limits, and diagnostics
    # that keep Ray IDs but never log tokens or bodies.
    edge_probe = read("scripts/probe_machine_endpoints.py")
    require_text(edge_probe, "INITIALIZE_BODY", "edge probe must cover anonymous initialize")
    require_text(edge_probe, '"initialize"', "edge probe initialize handshake")
    require_text(edge_probe, "request_urllib", "edge probe required urllib stack")
    require_text(edge_probe, "request_curl", "edge probe required curl stack")
    require_text(edge_probe, "invalid bearer [curl]", "edge probe invalid bearer on both required stacks")
    for category in (
        "edge_1010",
        "edge_denial",
        "edge_origin_failure",
        "worker_auth_contract",
        "worker_5xx",
        "malformed_jsonrpc",
    ):
        require_text(edge_probe, category, "edge probe stable categories")
    require_text(edge_probe, "cf_ray", "edge probe must preserve Cloudflare Ray ID")
    require_text(edge_probe, "atk_probe_invalid_token", "edge probe uses a fixed invalid bearer, never real credentials")
    probe_result_block = re.search(r"(?ms)result = ProbeResult\((.*?)\)", edge_probe)
    require(probe_result_block is not None, "edge probe ProbeResult construction is missing")
    if probe_result_block is not None:
        block = probe_result_block.group(1)
        for forbidden in ("headers=", "body=", "payload="):
            require(forbidden not in block,
                    f"edge probe diagnostics must not store {forbidden.rstrip('=')} (Ray ID + bounded category only)")
    deploy_doc = read("docs/deploy-cloudflare.md")
    require_text(deploy_doc, "ownmesh machine endpoints", "deploy doc WAF skip rule")
    require_text(deploy_doc, "Browser Integrity Check", "deploy doc scoped skip products")
    require_text(deploy_doc, "do **not** skip rate limiting", "deploy doc must keep rate limiting")
    require_text(deploy_doc, "tools/call", "deploy doc fail-closed tools/call")
    require_text(deploy_doc, "two egress hosts", "deploy doc two egress locations")
    require_text(deploy_doc, "malformed JSON-RPC", "deploy doc malformed alert")
    require_text(deploy_doc, "cf-ray", "deploy doc Ray ID diagnostics")
    require("Skip all" not in deploy_doc and "skip all" not in deploy_doc,
            "deploy doc must not allow a zone-wide WAF skip")
    require("disable the WAF for the zone" in deploy_doc or "do not disable the WAF" in deploy_doc,
            "deploy doc must forbid disabling the WAF for the zone")

    if ERRORS:
        for error in ERRORS:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(
        f"release-quality checks passed: gates fail closed; "
        f"{len(surfaces)} registry-backed / {total_unsupported} total unsupported or evidence-waived surfaces"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
