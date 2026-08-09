# E6 adapter contracts

Confirmed: 2026-08-10 (UTC+09:00).  This file records only surfaces that are
described by the linked first-party documentation.  An unsupported or
undocumented operation is represented as a degraded capability; OwnMesh must
not invent a command line or protocol request for it.

## Common safety boundary

Every adapter uses an argv vector (never a shell), a bounded byte parser, and
an explicit transport.  Structured adapters are not silently changed into a
network listener: their only transport is the child process's stdio, except
OpenCode's documented local HTTP server mode.  Authentication probes may use
only the documented read-only status/version command; credential files,
environment values, and command output are never copied to audit or cloud
records.

| Profile | Official primary source | Verified contract | Resume contract OwnMesh may use |
|---|---|---|---|
| Codex | https://github.com/openai/codex/blob/main/codex-rs/app-server/README.md | `codex app-server` uses JSON-RPC 2.0 over default stdio JSONL; `initialize`, `thread/start`, `thread/resume`, and event notifications are documented. | `thread/resume` after initialize |
| Claude Code | https://docs.anthropic.com/en/docs/claude-code/cli-usage | `claude -p`, `--output-format stream-json`, and `--resume <id>` are documented. | `--resume <native-id>` |
| Kimi Code | https://github.com/MoonshotAI/kimi-code/blob/main/docs/en/reference/kimi-command.md | `kimi acp` is stdio JSON-RPC ACP; `--prompt ... --output-format stream-json` and `--session` are documented. | ACP session load only when capability is advertised; otherwise `--session <native-id>` / degraded |
| OpenCode | https://dev.opencode.ai/docs/cli/ and https://dev.opencode.ai/docs/server/ | `opencode run`, `opencode serve`, and session management are documented. `serve` is an HTTP server. | no CLI resume argv asserted; use documented server/session API only if negotiated, otherwise degraded/PTy |
| Pi | https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/README.md | `pi --mode rpc` is strict LF-delimited JSONL, not generic Unicode line splitting. | no undocumented argv resume is used; process/RPC capability decides |
| Antigravity (`agy`) | https://github.com/google-gemini/gemini-cli/discussions/27274 | current first-party transition notice confirms `agy` and headless output choices, including `stream-json`; the exact session-resume wire surface is not asserted. | degraded/PTy unless the discovered CLI advertises a safe resume surface |
| Qwen Code | https://github.com/QwenLM/qwen-code/blob/main/docs/users/configuration/settings.md and https://github.com/QwenLM/qwen-code/blob/main/docs/users/features/commands.md | `--acp`, `--output-format stream-json`, and `qwen sessions list --json` are documented. | ACP load/resume only after capability advertisement; otherwise explicit degraded |
| Hermes Agent | https://github.com/NousResearch/hermes-agent/blob/main/website/docs/developer-guide/programmatic-integration.md and https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/sessions.md | `hermes acp` is stdio JSON-RPC ACP; `--continue` / `--resume <id>` are documented. | ACP capability first, otherwise `--resume <native-id>` |
| Qoder | https://docs.qoder.com/en/cli/acp | `qodercli --acp` is stdio ACP.  Login is reused locally; token values are never read by OwnMesh. | ACP `session/load` only when advertised; otherwise explicit degraded/PTy |

## Parser and event contract

The adapter parser accepts raw bytes and tracks an absolute byte cursor.  A
record is delimited only by LF (`0x0a`); a CR before LF is payload whitespace,
not a second delimiter.  A line larger than 64 KiB is represented as a visible
adapter error and discarded through its LF boundary.  A page contains at most
256 events.  Malformed JSON is likewise a visible `adapter_error` event, never
silently treated as an assistant message.  Event text and raw type are bounded
copies; raw protocol bytes remain local to the session spool.

## Auth status contract

`AuthProbe` permits only a profile-declared argv (no shell) and returns an
exit/status classification.  stdout/stderr are each capped at 64 KiB before
redaction and are not a telemetry payload.  No adapter reads token files or
imports token-bearing environment variables into `LaunchPlan`.
