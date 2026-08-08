# Changelog

## v1.2.0-beta.4 — E3 action binding + bounded I/O

- Server-computed `payload_hash` and durable MCP operation action binding (E3 slice)
- Idempotency key reuse with drifted content fails closed; identical action replays
- Command output streamed into capped rings; cancel kills in-flight process trees
- MCP/DeviceRoom ingress byte caps before JSON parse; oversized WS frames rejected early
- MCP `ownmesh_fs_stat` / `ownmesh_fs_delete` / `ownmesh_fs_patch`; cursor-paginated `fs.list`
- Honest docs: E4–E9 and E10 remain open

## v1.2.0-beta.3 — E2 remote routing candidate

- Wire public Streamable HTTP `/mcp` through DeviceRoom to the real ownmeshd Agent and shared policy-gated `DaemonRuntime`.
- Emit `ownmesh.operation/1.0` requests with matching `correlation_id`/`operation_id`, `expires_at`, capability, idempotency key, and nested arguments; strip client-supplied authorization fields.
- Advertise `remote_routing_enabled: true` with filesystem/command/cancel capabilities; DeviceRoom only injects to routing-ready Agents.
- Execute direct fs list/stat/read-range/write/delete and structured/raw command paths with bounded read windows (`offset`/`max_bytes`, encoding, SHA-256, visible truncation).
- Persist Agent terminal replies before send; runtime idempotency journals prevent completed side-effect reruns across process restart.
- ChatGPT-primary action model: authenticated MCP invocation is the requested action; no invented ChatGPT confirmation attestation; optional local approval only when device policy asks.
- Real binary × local Wrangler/workerd proof: `scripts/tests/test_e2_workerd_loopback.py`.
- Routing notes: [`docs/V1.2_E2_REMOTE_ROUTING.md`](./docs/V1.2_E2_REMOTE_ROUTING.md).
- Does not promote CLI `exec --device`, cloud PTY, profiles, broker mint, transfer, or live-account E10 surfaces.

## v1.2.0-beta.2 — E1 Agent transport candidate

- Connect enrolled `ownmeshd` instances to the active control plane at `/agent/connect` over `wss://` (or loopback-only `ws://`) using the existing issuer/device-bound credential.
- Complete hello/challenge/Ed25519 proof/accepted/ready authentication without logging or persisting plaintext credentials outside the existing secret store.
- Persist outbound/inbound sequence state before side effects, reconnect with bounded backoff, advertise resume state, and deduplicate message IDs and operation correlations across reconnects.
- Keep pre-E2 remote routing fail-closed until the runtime handle is wired.
- A real local WebSocket test covers two authenticated connections, resume, and fresh-sequence cached-result replay. A real debug `ownmeshd` binary additionally authenticates twice against local Wrangler/workerd with temporary D1 state and an isolated native keychain namespace, proving process-restart resume.
- Enable the native `keyring` 3.x backends explicitly so production credentials persist in Windows Credential Manager, macOS Keychain, or Unix Secret Service instead of the crate's process-local mock. Live-account E2E remains open, so no supported surface is promoted.
- Transport notes: [`docs/V1.2_E1_AGENT_TRANSPORT.md`](./docs/V1.2_E1_AGENT_TRANSPORT.md).

## v1.2.0-beta.1 — E0 operation contract freeze

- Add the independent `ownmesh.operation/1.0` request/progress/event/result payload contract while retaining the `ownmesh.device/1.0` outer envelope.
- Require operation/correlation binding, request expiry and idempotency, exact payload fields, safe cross-runtime sequence integers, and fail-closed terminal result shapes.
- Add Rust/TypeScript typed parsers, a JSON Schema, and four shared golden fixtures with cross-language round-trip coverage.
- Reserve `workspace_id` for E4 without promoting workspace or remote-execution surfaces; the existing 39 hard-error unsupported surfaces remain unchanged.
- Contract notes: [`docs/V1.2_E0_OPERATION_CONTRACT.md`](./docs/V1.2_E0_OPERATION_CONTRACT.md).
- Beta notes: [`docs/RELEASE_NOTES_v1.2.0-beta.1.md`](./docs/RELEASE_NOTES_v1.2.0-beta.1.md).

## v1.1.3 — deterministic release gate

- Carry forward the v1.1.2 portable-installer repair without changing its security or compatibility scope.
- Make the Unix Docker-provider mock executable deterministic on hosted Linux filesystems by closing and syncing a staged script before atomically renaming it into place; this prevents the release gate from failing with transient `ETXTBSY` while preserving the same test assertions.
- Make the daemon restart regression wait for stopped connection tasks to release their fixed credential-registry lock, with a bounded timeout instead of an arbitrary sleep.
- Retain the immutable `v1.1.2` tag as a historical failed release candidate. Its fail-closed tag workflow published no GitHub Release or assets.
- Release notes: [`docs/RELEASE_NOTES_v1.1.3.md`](./docs/RELEASE_NOTES_v1.1.3.md).

## v1.1.2 — Unix installer repair

- Repair `ownmesh-installer.sh` so the declared `#!/bin/sh` path parses and runs under POSIX shells such as Ubuntu `dash`; add an unconditional `sh -n` regression that does not skip when Minisign is absent.
- Preserve fail-closed environment validation without Bash-only `$'...'` quoting, including CR/LF and shell-metacharacter rejection.
- Enroll the real pinned Minisign 0.11 Linux x64 archive digest and select the exact x86_64 binary from the multi-architecture bootstrap archive.
- Refuse pre-existing symlink, reparse-point, directory, or other non-file binary targets in both portable installers; validate final targets and remove newly written files during rollback so a failed update cannot leave a partial new binary set.
- Restore Windows backups with atomic same-volume replacement plus digest verification, clean private transaction files after success or safe failure, and retain backups only when rollback itself fails.
- Make signed Unix installer coverage a required Ubuntu release gate by provisioning a SHA-256-pinned Minisign 0.11 binary; missing signer/key generation is now a hard test failure instead of a skip.
- v1.1.1 remains immutable for auditability, with a release warning on its unusable Unix installer. Signed archives and the Windows installer were independently reverified before this patch train.
- Release notes: [`docs/RELEASE_NOTES_v1.1.2.md`](./docs/RELEASE_NOTES_v1.1.2.md).

## v1.1.1 — CI and security repair

- **ownmesh-config:** transaction lock `OpenOptions` now sets explicit `truncate(false)` with `create(true)` (crash-safe lock semantics; fixes `clippy::suspicious_open_options` under `-D warnings`).
- **ownmesh-ipc (Windows):** registry state custody pins and attests the directory handle before mutation, accepts only `TokenUser` or the same process token's stable `TokenOwner`, repairs that elevated-token owner case through the same handle, rejects every unrelated owner, and revalidates after acquiring the pinned registry lock namespace anchor; identity remains file-index based across genuine path aliases. CI explicitly enforces foreign-owner, reparse, and replacement regressions without relaxing owner-only DACL / non-regular checks.
- **control-plane OAuth:** consent expiry is captured at Worker GET receipt, before asynchronous form parsing/authentication; a delayed-auth-provider regression proves the five-minute lifetime cannot be extended by route work.
- **ownmesh-logs / ownmesh-broker (Linux/macOS Clippy):** cfg-gate Windows-only imports and helpers; drop useless `uid_t`/`gid_t`→`u32` conversions; fix underscore-prefixed binding use; remove redundant `String::to_string` map_err; keep macOS LaunchDaemon allowed-uid emission distinct from Windows/Linux CLI flag fold (with unit coverage).
- **control-plane devDependency:** upgrade `wrangler` 3.x → 4.x (and matching `@cloudflare/workers-types` 5.x) so `pnpm audit --audit-level=high` is clean of miniflare-transitives `undici` / `ws` / `sharp` highs; no audit ignores or threshold changes.
- Release notes: [`docs/RELEASE_NOTES_v1.1.1.md`](./docs/RELEASE_NOTES_v1.1.1.md).
- No Dependabot merges; `v1.1.0` tag left immutable.

## v1.1.0 — 2026-08-07

### Secure distribution

- Multi-arch portable archives: Windows x64, macOS arm64/x64, Linux musl arm64/x64.
- Required minisign signing of `SHA256SUMS` with immediate verify; no degraded unsigned formal release.
- Installers for macOS/Linux (`ownmesh-installer.sh`) and Windows (`ownmesh-installer.ps1`) **require** minisign verification of `SHA256SUMS.minisig` against the pinned trust root before trusting checksums (no SHA-only fallback; no `curl|sh` / `irm|iex`).
- Installers enforce the updater archive contract **before** extraction (entry/size caps, exact allow-list, no full `tar -xzf` / `Expand-Archive`); member-by-member staging + atomic install/rollback; fail closed when safe listing/extract is unavailable.
- Homebrew formula template + `scripts/render_distribution.py` checksum injection.
- Release assets include installers, `ownmesh.rb`, `ownmesh-release-meta.json`, SBOMs, provenance.

### Self-update

- Production `ownmesh update check|download|apply|channel` against official GitHub Releases.
- Embedded minisign trust root; verify order signature → checksums → archive.
- Fail-closed host allow-list, size/time/entry/uncompressed limits, downgrade refusal, protocol compatibility.
- Archive extraction permits only required binaries + declared docs; rejects bombs, duplicates, symlinks, traversal.
- Atomic multi-binary apply with backup/rollback; Homebrew self-update refused.

### Onboarding / local trust boundary

- `setup` config+policy journaled transaction under exclusive lock with durable recovery (no new-config + old-strong-policy window).
- Mandatory fail-closed recovery on every production config/policy load path (daemon start, CLI); recovery failure preserves journal and refuses operation; concurrent setup serialized.
- Strict control-plane `url::Url` validation (https / loopback-http only; reject userinfo/query/fragment); redacted errors.
- `doctor` never loads OS credentials; presence from non-secret metadata only.
- Human-operator IPC (`approval.approve|deny`, `policy.preset`, `daemon.unlock`, `token.revoke`) fail-closed until a distinct OS/UI presence proof exists (same-UID unauthenticated IPC is not human presence).

### Versioning

- Workspace / packages / control-plane service version aligned to **1.1.0**.

## v1.0.2

See [`docs/RELEASE_NOTES_v1.0.2.md`](./docs/RELEASE_NOTES_v1.0.2.md).
