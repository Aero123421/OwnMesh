# OwnMesh v1.0.2 — Release-quality remediation

v1.0.2 corrects release/CI behavior and narrows product claims to what is actually implemented. It is not a declaration that the full OwnMesh 1.0 specification is complete.

## Scope and compatibility

The CLI has **44 explicit unsupported CLI surfaces** from the authoritative Rust registry plus 7 additional hard-error unsupported surfaces (51 total), machine-recorded in [`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json). They return explicit machine-readable errors and are excluded from 1.0.x completeness. Supported areas are also listed in that manifest.

`ownmesh exec --device <id>` is unsupported in this release and now hard-fails before any daemon call. It never falls back to local execution. Local `ownmesh exec -- <command>` remains supported. Likewise, `ownmesh session open <device>` now hard-fails instead of silently opening a local session; local session operations remain supported. `ownmesh approval watch` now hard-fails instead of silently running one list query. Broker install/uninstall also fail closed until native service activation/removal can be verified; generated templates and markers are not installed-state evidence.

## Release and CI changes

- Rust toolchain references are unified on 1.92.0.
- Required CI runs Rust fmt, Clippy with `-D warnings`, locked build, and locked tests on Windows, Linux, and macOS. Linux/macOS are no longer best-effort.
- Required pnpm gates use a frozen lockfile and run recursive test, typecheck, and lint.
- Wrangler validation is blocking; validation failures are no longer discarded.
- A tag release invokes reusable CI and Security workflows first. Failed or cancelled gates prevent build and publish jobs through explicit `needs` dependencies.
- Release build uses a Windows/Linux/macOS matrix and fails if a required binary/archive is absent. Every portable archive must contain LICENSE, NOTICE, README, and current release notes.
- Release outputs are portable archives, not a Windows installer or a universal macOS package; those packaging requirements remain partial/unimplemented.
- The release fails if either Rust or control-plane CycloneDX SBOM is absent, invalid, or empty. There is no placeholder/empty SBOM fallback.
- GitHub build provenance is generated for release assets.
- Release notes are selected from the current tag rather than a fixed historical file.
- `scripts/check_release_quality.py` statically verifies release gate dependencies and the supported-surface contract in both CI and Security.

## Signing status and W-SIGN

Portable minisign signing is used only when `MINISIGN_SECRET_KEY` is configured **and** its matching trust root is committed at `docs/release-keys/minisign.pub`. The signature is verified against that tracked key before publish. No trust root is enrolled at this commit, so v1.0.2 is expected to be a **degraded pre-release** with an unsigned-artifact warning. SHA-256 checksums, SBOMs, and provenance remain required, but none is represented as a signature.

Authenticode and Apple notarization are not implemented. W-SIGN remains open even when portable minisign succeeds. Consumers must read the generated release banner for the actual signing state of a particular run.

## Honest DoD status

The specification-level DoD remains partial. Relay-off, telemetry-off, local-first persistence defaults, and repository licensing/docs are complete invariants; most end-to-end product items remain partial. W-LIVE-E2E, W-EXT-SEC, W-§12, W-§14, and W-SIGN are disclosures/deferrals, not completed work.

See [`docs/DOD_1.0.md`](./DOD_1.0.md) for the 18-item audit and [`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json) for the exact shipped CLI scope.

## Verification commands

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo test --workspace --all-targets --locked
pnpm install --frozen-lockfile
pnpm -r test
pnpm -r typecheck
pnpm -r lint
python scripts/check_release_quality.py
```

The attached release assets are produced only after these repository gates and the Security workflow pass. Live Cloudflare/ChatGPT account validation and external security review are not claimed.
