# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| `main` (pre-1.0 development) | Yes — security fixes land here first |
| Released `1.x` tags (once published) | Yes — until superseded per release notes |
| Pre-release / experimental branches | Best effort only |

OwnMesh grants high capability to connected clients (optional Full Access and elevated broker operations). Treat supply-chain integrity, auth, and local IPC boundaries as part of the security surface.

## Reporting a vulnerability

**Do not** file a public GitHub issue for security-sensitive reports.

Please report vulnerabilities privately via one of:

1. **GitHub Security Advisories** — [Report a vulnerability](https://github.com/Aero123421/OwnMesh/security/advisories/new) on this repository (preferred when available).
2. **Maintainer contact** — open a minimal non-sensitive issue titled `SECURITY CONTACT` asking for a private channel if advisories are unavailable.

Include as much of the following as you can:

- Affected component (CLI, `ownmeshd`, broker, control plane, MCP, profile, …)
- OwnMesh version / git commit
- OS and architecture
- Reproduction steps or proof-of-concept (non-destructive preferred)
- Impact assessment (auth bypass, privilege escalation, data exposure, RCE, …)
- Any known mitigations

## What to expect

- Acknowledgement when maintainers are available (target: within 7 days)
- Coordinated disclosure; we may request time to ship a fix before public detail
- Credit in release notes if you want to be named (optional)

## Scope (high priority)

Reports in these areas are especially valuable:

- OAuth / token handling (theft, confusion, open redirect, PKCE bypass)
- Device enrollment, impersonation, or replay of device protocol messages
- Local IPC ACL / peer-credential bypass
- Privileged broker authorization or network exposure
- Path traversal, symlink/junction races, shell injection
- Policy engine bypass (unexpected allow under restrictive presets)
- Secret leakage in logs, support bundles, MCP results, or crash reports
- Supply-chain issues in release artifacts (signing, SBOM, provenance)

## Out of scope (typical)

- Denial of service requiring unrealistic local resources
- Issues only present with intentionally misconfigured Full Access **and** compromised local OS user (report still welcome if OwnMesh amplifies impact)
- Vulnerabilities in third-party CLIs invoked via profiles, unless OwnMesh mishandles their I/O or credentials
- Social engineering of the human operator

## Hardening defaults

- Telemetry and cloud file relay are **off** by default
- Secrets belong in the OS keychain / secure store, never in `config.toml` or git
- The privileged broker is **networkless** by design
- Release signing, SBOM, and provenance approach is recorded in [`docs/adr/0001-release-signing-sbom-provenance.md`](./docs/adr/0001-release-signing-sbom-provenance.md)

Thank you for helping keep OwnMesh and its users safe.

## Release signing (minisign)

OwnMesh portable release checksums are signed with minisign.

| Field | Value |
| --- | --- |
| Public key | [`docs/release-keys/minisign.pub`](./docs/release-keys/minisign.pub) |
| Key ID | `C596813EFB0946A4` |
| Fingerprint (SHA-256 of decoded public-key blob) | `1450496b7af985f57466b4b5f0b9c985d6c3e96ed66ee2cebb4f5a94ba5775d9` |

**Rotation:** announce a new key ID and fingerprint in this file and the next release notes, commit only the new public key, and update the `MINISIGN_SECRET_KEY` repository secret. Never commit private keys. Historical public keys should remain documented for at least one release train so older artifacts stay verifiable.

Consumers should verify in order: `SHA256SUMS.minisig` → `SHA256SUMS` → individual assets. The `ownmesh update` client embeds the tracked public key and enforces this order fail-closed.

