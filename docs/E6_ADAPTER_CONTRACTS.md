# E6 adapter contracts

Verified: 2026-08-27 (UTC). This registry records only current first-party
surfaces. Installed means only that the exact executable and version were
found; it is not authentication or protocol evidence. An undocumented
operation remains explicitly degraded.

## Common launch and safety boundary

- Detection, version probing, and launch use the same pinned executable and
  deterministic child `PATH`: the service path plus OwnMesh's approved
  user-local search directories. Shell startup files are never sourced.
- Unix `#!` wrappers are inspected before session creation. Direct
  interpreters and `/usr/bin/env` interpreters must resolve through that same
  child path; otherwise status reports `interpreter_not_found` and
  `adapter_degraded`.
- Every structured adapter uses child stdio, bounded LF records (64 KiB),
  bounded text, and cursor-paged replay. No adapter opens an inbound listener.
- Local CLI and authenticated remote sessions use the same persistent
  structured-pipe supervisor and bootstrap. `profile start/resume --prompt`
  passes prompt text as a JSON value, never shell syntax. Reusable Codex/ACP
  sessions may be opened without a prompt and do not create a hidden model
  turn; one-shot Claude/Agy sessions require an explicit prompt.
- Provider credential files and credential-bearing environment values are not
  read, copied to Cloudflare, or emitted in replay/audit data.
- ACP client filesystem and terminal capabilities are advertised as false.
  Agent requests for those capabilities receive a correlated JSON-RPC error
  with `capability_not_advertised`.
- Permission requests are never auto-approved. The shipped safe contract is a
  correlated typed
  denial: ACP selects a vendor-provided `reject_*` option (or returns the ACP
  `cancelled` outcome), and Codex app-server returns `decision: decline`.

ACP adapters use the stable [ACP v1 schema](https://agentclientprotocol.com/protocol/v1/schema).
`initialize` sends protocol version 1, explicit client capabilities, and
bounded client information. The peer must return version 1 and an
`agentCapabilities` object. `session/new` and capability-gated `session/load`
include the absolute workspace `cwd` and an empty MCP server list.

## Source-backed profile matrix

| Profile | Primary source | Start / event contract | Cancel / permission | Resume |
|---|---|---|---|---|
| Codex | [app-server README](https://github.com/openai/codex/blob/main/codex-rs/app-server/README.md) | `codex app-server`; stdio JSONL with JSON-RPC semantics but no `jsonrpc` member. `initialize` → `initialized` → `thread/start` → `turn/start`; `thread/*`, `turn/*`, `item/*`, warning, status, usage, and error families are normalized. | App-server approval requests are correlated and declined. `turn/interrupt` is bound to the observed thread and active turn; cancel is typed degraded when no reusable turn ID is available, while explicit session termination remains available. | `thread/resume` after initialize. |
| Claude Code | [CLI reference](https://docs.anthropic.com/en/docs/claude-code/cli-reference) | `claude -p <prompt> --output-format stream-json --verbose`; system, nested assistant blocks, tools, result, and errors are normalized. | Reusable wire cancellation is typed degraded; close/terminate cancels the one-shot process. | `-p <prompt> --resume <id> --output-format stream-json --verbose`. |
| Kimi Code | [command reference](https://github.com/MoonshotAI/kimi-cli/blob/main/docs/en/reference/kimi-command.md) | `kimi acp`; ACP v1 updates are normalized. Documented print JSONL remains a declared fallback only, never a silent downgrade. | ACP `session/cancel`; typed permission denial. | `session/load` only when advertised. |
| OpenCode | [CLI documentation](https://opencode.ai/docs/cli/) | `opencode acp`; ACP v1 `session/update`, including `agent_message_chunk`, tool updates, plans/status, usage, and completion. | ACP `session/cancel`; typed permission denial. | `session/load` only when advertised. |
| Pi | [RPC protocol](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/rpc.md) | `pi --mode rpc`; strict LF JSONL command responses plus agent, turn, message, tool, retry, session, and error events. | RPC `abort`; no documented client-side permission bridge is asserted. | Degraded: no safely addressable cross-process resume contract is asserted. |
| Antigravity (`agy`) | [Gemini CLI headless documentation](https://geminicli.com/docs/cli/headless/) and [first-party transition notice](https://github.com/google-gemini/gemini-cli/discussions/27274) | `agy --print <prompt> --output-format stream-json`; init, message, tool-use/result, error, and result families. | Reusable wire cancellation is typed degraded; close/terminate cancels the one-shot process. | Degraded unless a future documented session surface is verified. |
| Qwen Code | [ACP documentation](https://qwenlm.github.io/qwen-code-docs/en/users/features/acp/) | `qwen --acp`; ACP v1 updates. | ACP `session/cancel`; typed permission denial. | `session/load` only when advertised. |
| Hermes Agent | [ACP integration](https://hermes-agent.nousresearch.com/docs/developer-guide/programmatic-integration/) | `hermes acp`; ACP v1 updates. | ACP `session/cancel`; typed permission denial. | Process-local `session/load` only when advertised; no invented argv fallback. |
| Qoder | [ACP documentation](https://docs.qoder.com/en/cli/acp) | Current executable `qoder --acp`; historic `qodercli` remains detection-only compatibility fallback. ACP v1 updates. | ACP `session/cancel`; typed permission denial. | `session/load` only when advertised. |

The version-tagged fixture suite lives in
`crates/ownmesh-profiles/tests/fixtures/`. Fixtures cover all nine dialects;
they contain no credentials, absolute private paths, or hidden reasoning.
Real-provider and cross-platform receipts are release evidence, not CI inputs.

## Public normalized event vocabulary

Normal replay emits only bounded typed records: `session`, `status`,
`assistant_message`, `assistant_message_delta`, `tool_call`, `tool_result`,
`permission_request`, `usage`, `completed`, `error`, and `adapter_error`.
Vendor-private reasoning and user-message echoes are suppressed. Unknown,
malformed, and oversized future events become visible `adapter_error` records;
later valid LF records continue parsing. Raw protocol bytes remain device-local
and require the explicit independently cursor-paged raw replay option.

## Authoritative profile status

- `not_installed`: no launchable candidate was found.
- `installed`: exact binary, interpreter, child path, and supported version are
  launchable; authentication and protocol remain unknown.
- `needs_login` / `authenticated`: only a documented bounded read-only auth
  probe or explicit protocol result may establish these states.
- `adapter_degraded`: a required launch dependency or documented capability is
  unavailable. The notes carry a stable actionable reason.
- `ready`: both authentication and a protocol-only compatibility receipt are
  authoritative. It is never inferred from `--version`.
- `running`: an authenticated supervisor has attested the exact live child.

`ownmesh profile test` does not perform a paid prompt. It cannot report PASS
for an `installed`/`untested` profile; an explicit session is required to
create live provider evidence.
