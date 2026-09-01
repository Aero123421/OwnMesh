# ADR 0016: Dialect-aware adapter normalization and denial-only vendor requests

- Status: Superseded by [ADR 0018](./0018-generic-external-cli-sessions.md)
- Date: 2026-08-27
- Deciders: OwnMesh runtime maintainers

## Context

OwnMesh registers nine official coding CLI profiles. Their stdio protocols are
not one interchangeable JSON dialect: five currently speak ACP v1, Codex uses
an app-server JSONL variant, Claude and Antigravity use different stream-json
envelopes, and Pi has its own RPC/event model. A generic parser hid valid ACP
assistant updates, exposed misclassification risk, and could not express
permission or capability failures.

Vendor agents can also initiate permission, filesystem, terminal, or approval
requests. Those JSON objects describe a request; they are not an OwnMesh policy
decision, executable identity, exact action binding, or approval receipt.
Automatically accepting them would cross the device authorization boundary.

## Decision

1. Each official dialect has a dedicated bounded normalizer into a small stable
   public vocabulary. Unknown or malformed records remain visible as typed
   `adapter_error` events, while parsing continues at the next LF boundary.
2. User-message echoes and private reasoning are not converted into assistant
   text. Raw protocol bytes remain local, opt-in, bounded, and independently
   cursor-paged.
3. Executable presence, launchability, authentication, and structured-protocol
   readiness are separate evidence. A successful version probe establishes at
   most `installed`; it can never establish `ready` or `authenticated`.
4. Detection and spawn use the exact same pinned program and deterministic
   child path. Unix shebang dependencies are resolved before session creation.
5. OwnMesh advertises no ACP client filesystem or terminal capability. Any
   request for one receives a correlated `capability_not_advertised` error.
6. Vendor permission/approval requests are handled by a daemon-owned monotonic
   protocol pump. It may only deny: ACP selects a typed `reject_*` option or
   returns `cancelled`; Codex returns `decision: decline`. It never echoes the
   proposed command/path in its response and never converts vendor display
   text into authority.
7. Resume is emitted only through a documented argv contract or a capability-
   negotiated protocol method. Pi and Antigravity remain explicitly degraded
   where no safe cross-process contract is documented.

## Consequences

- Standard OpenCode/ACP answer chunks are available through normal replay, and
  all supported fixture events have deterministic public classifications.
- A tool that needs permission is explicitly denied instead of auto-approved
  or left indefinitely unanswered. Ordinary tool work requiring approval is
  therefore a visible degraded capability until a separately reviewed,
  operation-bound OwnMesh approval bridge is implemented.
- Provider updates can add unknown events without losing later output, but a
  required schema change becomes a fixture/test failure rather than a false
  success claim.
- Profile status is less optimistic and may require an explicit user session
  before it can become ready. Health checks remain free of hidden paid turns.

## Rejected alternatives

- **Treat every JSON object with shared field heuristics.** This caused the ACP
  replay failure and cannot safely distinguish reasoning, user echoes, tools,
  or lifecycle events.
- **Auto-approve vendor requests.** Vendor JSON lacks OwnMesh's exact action,
  workspace generation, controller epoch, expiry, and idempotency binding.
- **Silently fall back to PTY.** This changes the security and replay contract
  and makes structured capability failures invisible.
- **Infer login/readiness from version output or credential files.** Version is
  not auth evidence, and reading provider secrets violates credential custody.
