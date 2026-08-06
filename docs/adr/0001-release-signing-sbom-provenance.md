# ADR 0001: Release signing, SBOM, and provenance

- Status: Accepted
- Date: 2026-03-21
- Deciders: OwnMesh maintainers

## Context

OwnMesh 1.0 ships native binaries (CLI, TUI, daemon, session host, privileged broker) across Windows, macOS, and Linux, plus a Cloudflare Workers control plane. Users grant high capability—including optional Full Access and elevated broker operations—so supply-chain integrity is part of the security boundary, not an optional polish item.

We need a concrete, implementable approach for:

1. **Artifact signing** — verify that downloaded binaries/installers came from the OwnMesh release process.
2. **SBOM** — machine-readable inventory of shipped components and dependencies.
3. **Provenance** — attest how and from which source revision artifacts were built.

This ADR locks the *method* so packaging work (checklist chapter 16) and security hardening (chapter 15) share one contract. Implementation details may evolve; changing the trust model requires a new ADR.

## Decision

### 1. Signing

| Artifact class | Mechanism | Notes |
| --- | --- | --- |
| Windows binaries / installers | Authenticode (signtool) with an OV or EV code-signing certificate | Prefer EV when available for SmartScreen reputation; document certificate subject in release notes |
| macOS binaries / packages | Apple Developer ID Application (+ Installer when using pkg) and **notary** submission | Hardened Runtime enabled; stapled ticket where applicable |
| Linux archives / packages | **Minisign** (primary portable signature) and optional distribution-native signatures later | `SHA256SUMS` + `SHA256SUMS.minisig` published beside assets |
| Cross-platform checksums | `SHA256SUMS` for every published asset | Generated in CI; signed (minisign) as the portable root of trust |

- Release public keys (minisign, and pointers to Apple/Microsoft identity) live in-repo under `docs/release-keys/` once generated; rotation is announced in release notes and SECURITY.md.
- CI must **never** hold long-lived raw private keys in logs; use GitHub Actions OIDC-backed secrets or hardware/cloud HSM-backed signing where practical.
- Git tags for releases are annotated and, when maintainers have GPG/SSH signing configured, **tag-signed**. Tag signing complements but does not replace artifact signing.

### 2. SBOM

- Produce an SPDX 2.3 **or** CycloneDX 1.5 SBOM (JSON) per release train:
  - **Rust workspace:** `cargo-cyclonedx` or `cargo-auditable` + CycloneDX export for binary crates that ship.
  - **TypeScript control plane:** `pnpm` / `syft` / `@cyclonedx/pnpm` style generation for `packages/control-plane` deploy bundle.
- Attach SBOMs as release assets: `sbom-rust.cdx.json`, `sbom-control-plane.cdx.json` (names may gain version suffixes).
- SBOM generation is a required release-job step; missing SBOM fails the release pipeline.
- License field on all first-party crates/packages remains **Apache-2.0**.

### 3. Provenance

- Use **SLSA-style provenance** via GitHub Actions **Artifact Attestations** (`actions/attest-build-provenance`) for release binaries built on GitHub-hosted runners.
- Provenance statements bind: source repo, commit SHA, workflow path, and output digests.
- Consumers can verify with GitHub CLI (`gh attestation verify`) or cosign-compatible verification flows documented at release time.
- Cloudflare Worker deploy provenance is recorded as: git SHA deployed, `wrangler` version, and account/route config **without** embedding secrets; deploy logs retained by the operator’s Cloudflare/GitHub settings.

### 4. Verification UX

- `ownmesh update` / install docs MUST verify:
  1. checksum match against `SHA256SUMS`, and
  2. minisign (or OS-native) signature, and
  3. when available, GitHub attestation for the digest.
- Failure modes are fail-closed for `auto` update mode; `check`/`notify` modes report verification errors clearly.
- Documentation ships a short “Verify a release” section with copy-paste commands for each OS.

### 5. What we explicitly defer

- Reproducible/bit-identical builds across all three OS hosts (best-effort later; provenance + signing cover 1.0 trust).
- Sigstore keyless signing as the *only* root of trust (may be added later alongside minisign, not as a silent replacement).
- Hardware token requirements for every contributor (maintainers/release operators only).

## Consequences

### Positive

- One documented trust story for Windows, macOS, and Linux consumers.
- SBOM and attestations satisfy checklist chapters 15–16 and external review expectations.
- Portable minisign path works even when users cannot validate Authenticode/Notary online.

### Negative / costs

- Release CI becomes heavier (signing credentials, notary, SBOM tools).
- Certificate procurement (Apple Developer Program, Windows code signing) is an operational dependency.
- Key rotation and compromise response procedures must be maintained.

### Follow-ups

- Add `docs/release-keys/README.md` when the first minisign keypair is created.
- Wire chapter 16 packaging workflows to this ADR’s asset naming and verification steps.
- Ensure `ownmesh-update` implements the verification order above before enabling `auto` by default (default update mode remains conservative per specification).

## Alternatives considered

1. **Sigstore/cosign only** — excellent for container ecosystems; weaker end-user UX on Windows/macOS desktop installs without additional tooling. Rejected as sole mechanism; may complement later.
2. **Checksums without signatures** — insufficient against release-asset tampering or CDN compromise. Rejected.
3. **Vendor-only signing (Authenticode + Apple) without minisign** — leaves generic Linux `.tar.gz` users without a simple offline verify path. Rejected as primary-only approach.
4. **Fully reproducible builds before 1.0** — high engineering cost; deferred behind provenance + signing.
