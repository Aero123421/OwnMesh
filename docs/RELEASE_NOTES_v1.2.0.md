# OwnMesh v1.2.0

OwnMesh v1.2.0 is the first stable release of the v1.2 product surface. It
turns the beta transport, policy, profile, transfer, onboarding, and ChatGPT
work into one coherent self-hosted workflow with no intentionally unimplemented
entries in the shipped CLI registry.

The scope statement is precise: the supported-surface manifest is complete.
Optional native packaging/signing and specified external/native evidence remain
disclosed separately below.

## Install and first-run UX

- Signed one-line shell and PowerShell installers verify minisign and SHA-256
  before installing, then enforce a bounded archive allowlist.
- `ownmesh setup --quickstart` configures policy/privacy defaults, completes
  login, enrolls the current machine, and installs user-level autostart.
- Headless/SSH setup prints a verification URL and short code suitable for a
  phone or another computer.
- `ownmesh doctor` is read-only, has stable JSON/exit behavior, and does not load
  credential values.
- The bundled TUI launches from `ownmesh` on an interactive terminal and uses a
  consistent dark, Linux-tool-oriented design.

## ChatGPT, OAuth, and owner authentication

- A self-hosted Cloudflare Worker exposes MCP plus OAuth authorization,
  dynamic public-client registration, PKCE, exact callback validation, and
  rotating refresh tokens.
- Built-in single-owner authentication uses passkeys; no Google or mandatory
  OwnMesh-hosted account is required.
- Guided Cloudflare deployment creates/reuses D1, applies migrations, deploys
  the Worker/Durable Object, provisions required secrets, and prints the owner
  and ChatGPT connection URLs.
- A fresh passkey assertion is required for security-sensitive approval, policy,
  unlock, and token mutations. The proof is bound to the exact operation,
  principal/tenant, payload, decision, and expiry; execution is exactly once.
  A long-lived browser cookie or same-user local IPC connection is insufficient.
- OAuth/device credentials remain in the OS credential store. Tokens are not
  placed in configuration or stdout diagnostics.

## Completed CLI surface

- Device management now includes rename and bounded labels in addition to
  enroll/list/show/key rotation/revoke.
- `exec --device` and remote `session open` use authenticated MCP routing with
  explicit idempotency. They fail as remote when the target is unavailable and
  never run locally as a fallback.
- Structured remote execution supports exact argv and the explicit elevated
  request field. Raw-shell mode is separate and cannot request elevation.
- Profile scan/list/show/login/test/start/resume is wired through the persistent
  credential-isolated nine-adapter runtime.
- `approval watch` streams queue changes; approve/deny, bounded safe temporary
  grants, policy preset/rule, unlock, and token revoke use typed security-admin
  routes. Generic command/shell temporary grants remain deliberately forbidden;
  an exact one-shot approval is used instead.
- `ownmesh mcp serve --stdio` is a bounded JSONL bridge to the configured issuer.
  It disables redirects, refreshes authentication once on 401, and reserves
  stdout for protocol responses.
- Transfer plan/send/list/status/cancel uses the authenticated public MCP
  contract with immutable plans, mandatory mutation idempotency, bounded paths,
  and no overwrite/force or LAN-relay fallback.

## Runtime and acceptance improvements

- E5 hardens PTY/session behavior: bounded replay and live-ring continuation,
  fail-closed resize after recovery, process-tree termination, and bounded
  executable/journal/spool/state reads.
- E6 provides nine structured AI CLI adapters with real device detection,
  persistent sidecar framing, public MCP routing, safe auth status, and bounded
  cleanup/resume behavior.
- E7 provides bounded unified-diff review execution with exact-once/payload
  conflict handling, stale-HEAD rejection, workspace ACL enforcement, typed
  result paging, and no implicit Git ref/index mutation.
- E9 exercises authenticated resumable transfer between two enrolled Agents,
  including binary/zero-byte artifacts, durable 32 MiB restart/resume, partial
  cancellation cleanup, ownership denials, integrity checking, and stopped
  D1/Durable Object at-rest inspection.

## Security and release integrity

- Normal `ownmeshd` service management is current-user only on Windows, macOS,
  and Linux. Privileged work is isolated in a separate networkless broker.
- Remote and admin requests are typed and bounded; no arbitrary RPC
  method/parameter passthrough was introduced to complete the CLI.
- Telemetry, cloud relay, and automatic update network access remain off by
  default. Requested remote routes do not degrade to local execution.
- Release publication is blocked on reusable CI and Security workflows.
- Windows x64, macOS arm64/x64, and Linux musl arm64/x64 portable archives
  include LICENSE, NOTICE, README, current notes, non-empty CycloneDX SBOMs,
  checksums, mandatory minisign signature, and GitHub provenance.

## Evidence and distribution boundaries

- The privileged-broker lifecycle is implemented on Linux, macOS, and Windows.
  Linux has a native root/systemd receipt. macOS/Windows native release receipts
  and the complete public MCP → installed `ownmeshd` → native broker E8 receipt
  remain open evidence. This release does not label those unrecorded routes as
  live-proven.
- ChatGPT dynamic registration, OAuth, passkey return, refresh, and MCP linking
  have a manual live compatibility receipt. Reproducible local workerd suites
  cover the protocol, while a fully automated external ChatGPT E10 receipt
  remains open.
- Authenticode, Apple notarization, MSI/NSIS, and native/universal macOS packages
  are not part of the v1.2.0 distribution contract. Portable archives remain
  minisign-authenticated.

## Upgrade notes

- v1.2 beta configuration and enrolled-device data are retained. Run
  `ownmesh doctor --json` after upgrading.
- Re-run the guided control-plane deploy to apply current D1 migrations before
  using device labels or the final typed admin tools.
- Existing ChatGPT connectors continue through rotating refresh tokens unless
  the owner explicitly revokes access or changes the deployment issuer.
- Beta release notes remain in `docs/` as development history. This file is the
  tag-selected release note for `v1.2.0`.

The authoritative stable command list is
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).
