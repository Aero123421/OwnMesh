# OwnMesh Threat Model (v1.2.8)

**Status:** Published for release train v1.2.8
**Related:** [`SECURITY_REVIEW_CHECKLIST.md`](./SECURITY_REVIEW_CHECKLIST.md), [`SECURITY.md`](../SECURITY.md), ADR [`0001-release-signing-sbom-provenance.md`](./adr/0001-release-signing-sbom-provenance.md)  
**Method:** STRIDE-oriented asset / adversary / control mapping. Full Access is an intentional product mode; the trust boundary is integrity of authenticated intent, not “block the AI.”

## 1. Assets

| Asset | Why it matters |
| --- | --- |
| Device identity keys / enrollment proofs | Bind this machine to a control-plane principal |
| OAuth access / refresh tokens | Cloud authorization to operate the user’s devices |
| Local IPC peer identity + per-client credential | Proves CLI/TUI/MCP local callers are the same OS user session. The historical shared `daemon.token` file is legacy and is **not** an authentication input (`ownmesh-ipc/src/auth.rs`); identity comes from the OS-attested peer plus a server-issued per-client credential |
| Broker capability / MAC secret | Gates elevated (admin/root) execution |
| Policy + temporary grants | Machine-side authorization truth |
| Filesystem / process control on the device | Primary user capability OwnMesh exposes |
| Audit log + support bundle | Forensics; must not leak secrets when exported |
| Release artifacts / update metadata | Supply-chain integrity of the runtime itself |

## 2. Trust boundaries

```
[ChatGPT / external MCP client]
        |  HTTPS + OAuth (short-lived access token, scoped)
        v
[Cloudflare Control Plane Worker + DeviceRoom DO]
        |  Device WebSocket (envelope protocol, device key)
        v
[ownmeshd — unprivileged user daemon]
   |  local IPC             |  broker client (MAC + nonce)
   |  (OS peer cred +       |
   |   per-client secret)   |
   v                        v
[CLI / TUI]          [ownmesh-broker — elevated, networkless]
   |                        |
   +---- OS user perms -----+---- OS admin/root (explicit) ----
```

**In-boundary assumptions**

- The OS user who installed/runs OwnMesh can already read their own files and run their own processes.
- Full Access intentionally removes OwnMesh-level ask/deny friction for that user.
- Cloud and local policy composition remains most-restrictive when both apply; Full Access is an explicit local preset.

**Out-of-boundary (not trusted)**

- Arbitrary model text, repository contents, log lines, web pages (prompt-injection surface).
- Compromised third-party OAuth clients with over-broad scopes (scope enforcement still applies).
- Remote network peers claiming to be the broker (broker is networkless / loopback-or-local-IPC only).
- Unsigned or checksum-mismatched update artifacts.

### Surfaces added since v1.0.1

| Surface | Release | Primary new exposure | Where controls live |
| --- | --- | --- | --- |
| Agent transport (E1) | v1.2 | Structured adapter framing between daemon and coding-agent CLIs | `ownmeshd/src/structured_adapter.rs`, `agent_transport.rs` |
| Remote routing (E2) | v1.2 | Control-plane-routed device operations; no local fallback | `ownmeshd/src/runtime.rs`, `control-plane/src/device-room.ts` |
| Action binding (E3) | v1.2 | Approval decisions bound to an exact operation + payload hash | `control-plane/src/mcp.ts`, `ownmeshd/src/review_manifest.rs` |
| Workspace custody (E4) | v1.2 | Workspace-relative path authority and ACL | `control-plane/migrations/0011_workspace_acl.sql` |
| Windows daemon (E8) | v1.2 | LocalSystem SCM service + SID-bound named pipe | `ownmesh-broker/src/windows*.rs` |
| Resumable transfer (E9) | v1.2 | `TransferRoom` DO, ephemeral proofs, chunk resumption | `control-plane/src/transfer-room.ts`, `ownmeshd/src/transfer_crypto.rs` |

Each is exercised by the adversarial suites listed in
[`SECURITY_REVIEW_CHECKLIST.md`](./SECURITY_REVIEW_CHECKLIST.md); this table
records that they are in scope, not that every route has a live receipt — see
the release notes for the evidence split.

## 3. Adversaries

| Adversary | Goals | Primary controls |
| --- | --- | --- |
| A1 Remote unauthenticated | Reach device tools without OAuth | Worker authn, no public device admin API without token |
| A2 Stolen OAuth access token | Call MCP / device ops until expiry | Short TTL, audience/scope binding, revoke |
| A3 Stolen refresh token | Mint new access tokens | Rotation + reuse detection, keychain storage |
| A4 Prompt-injection (model/tool args) | “Always allow”, forge approval | Device policy is final; injection strings inert for authz |
| A5 Local cross-user | User B drives User A’s daemon | OS-attested peer credentials + pipe/socket ACL; per-client credential for privileged IPC methods |
| A6 Local malware same-user | Replay elevated broker ops | Broker MAC, nonce, expiry, replay cache; capability tokens |
| A7 Path / symlink attacker | Escape workspace in restricted presets | Canonicalize-then-authorize; Full Access is explicit non-enforce |
| A8 Command injection | Turn structured argv into shell metachar execution | Structured exec never invokes a shell |
| A9 Supply chain | Troianed dependency or release asset | `cargo audit` / pnpm audit, SBOM, checksums + signing (ADR-0001) |
| A10 Honest-but-curious operator | Learn secrets from telemetry/support | Telemetry default OFF; bundle redaction; audit local-first |

## 4. STRIDE summary

| Category | Example abuse | Residual risk / disposition |
| --- | --- | --- |
| Spoofing | Fake IPC client, forged broker caller, wrong OAuth client | Mitigated by tokens/MAC/PKCE; same-user malware remains in scope of OS user compromise |
| Tampering | Mutated WS envelope, patched binary, journal rewrite | Parser limits + signature/MAC; release signing partially waived (**W-SIGN**) |
| Repudiation | Deny an elevated run occurred | Local audit log append; CP audit metadata for cloud path |
| Information disclosure | Token in logs/MCP/support bundle | Secret newtypes, redaction helpers, checklist-linked tests |
| Denial of service | Giant frames, output bombs, hung adapters | Frame caps, output limits, adapter process isolation (no in-process plugin load) |
| Elevation of privilege | Unprivileged daemon → root without broker proof | Broker boundary + networkless bind; Full Access still requires valid broker crypto |

## 5. Control → test evidence map (harden-07)

| Control area | Primary automated evidence |
| --- | --- |
| Auth / token | `packages/control-plane/src/oauth.test.ts`, `security-harden.test.ts`; `crates/ownmesh/src/auth/tests/*`; `crates/ownmesh-identity/**` |
| Replay / idempotency | `crates/ownmesh-exec/tests/security_*.rs`, `ownmesh-broker*`, `ownmeshd` daemon idempotency tests |
| Path traversal / symlink | `crates/ownmesh-fs/tests/security_path.rs` |
| Command argument injection | `crates/ownmesh-exec/tests/security_command_injection.rs` |
| Broker boundary / networkless | `crates/ownmesh-broker/tests/security_boundary.rs`, `ownmesh-broker-client` |
| IPC spoofing | `crates/ownmesh-ipc/tests/security_spoofing.rs` |
| WS / envelope parser fuzz | `crates/ownmesh-protocol/tests/fuzz_harness_build.rs`, `ws_parser_fuzz.rs` |
| Adapter isolation | `crates/ownmesh-profiles/tests/adapter_isolation.rs` |
| Prompt injection | `packages/control-plane/src/mcp.test.ts`, `security-harden.test.ts`; `ownmeshd` policy tests |
| §12 relay fail-closed | `crates/ownmesh-transfer/**`, `packages/control-plane/src/wrangler-config.test.ts` |
| §14 telemetry OFF / redaction / audit keep | `crates/ownmesh-config/**`, `ownmesh-update/**`, `ownmesh-diagnostics/**`, `ownmesh-policy` Full Access tests |
| Dependency audit / SAST / secrets / SBOM | `.github/workflows/security.yml` |

See [`SECURITY_REVIEW_CHECKLIST.md`](./SECURITY_REVIEW_CHECKLIST.md) for per-checkbox deep links.

## 6. Explicit non-goals / waivers (v1.2.8)

| ID | Scope | Note |
| --- | --- | --- |
| **W-§12** | LAN discovery / direct P2P depth | Fail-closed relay OFF is locked; full LAN transfer deferred |
| **W-§14** | Update channels/rollback/doctor feature depth | Privacy defaults + redaction locked; feature sufficiency waived |
| **W-SIGN** | Multi-OS notarization / production signing keys | Checksums + workflow first; keys user-provided |
| **W-LIVE-E2E** | Live Cloudflare + live ChatGPT plugin | Automated harness substitutes this sprint |
| **W-EXT-SEC** | External firm review before 1.0 | Internal checklist + tests; noted in release process |

## 7. Findings log (critical / high)

No open **critical** or **high** product findings from harden-07 automated suites at publication time.

| ID | Severity | Summary | Disposition |
| --- | --- | --- | --- |
| — | — | — | Re-run `cargo test --workspace`, `pnpm -r test`, and `.github/workflows/security.yml` on each release candidate. Dependency advisories discovered by `cargo audit` / `pnpm audit` are triaged in the security workflow artifacts; break-glass acceptances must be recorded in release notes with CVE id + rationale. |

### How to reproduce the verification pack

```bash
cargo test --workspace
pnpm -r test
# CI-equivalent local checks (see security.yml for exact flags):
cargo deny check 2>/dev/null || cargo audit
pnpm -r exec npm audit --audit-level=high || true
```

## 8. Residual risk statement

OwnMesh intentionally concentrates power on a user-owned PC. A malicious process running **as the same OS user** that owns the daemon can often abuse that user’s ambient authority (files, processes). OwnMesh’s job is to ensure:

1. Remote parties cannot act without valid OAuth + device protocol state.
2. Local callers cannot skip IPC auth or forge broker elevation.
3. Model/tool text cannot become an authorization oracle.
4. Restricted presets enforce workspace path policy; Full Access does so only by explicit user choice — **with no hidden hard denies**.
5. Cloud relay and central telemetry stay **opt-in**.

Operators who need multi-user hardening must rely on OS account separation, disk encryption, and not sharing the OwnMesh runtime directory across users.
