# ownmesh-profiles

Official and custom CLI profile detection, launch plans, event normalization, and fixture-based conformance.

## Official 9 (spec §13.1)

| id | binary |
|---|---|
| `codex` | `codex` |
| `claude-code` | `claude` |
| `kimi-code` | `kimi` |
| `opencode` | `opencode` |
| `pi` | `pi` |
| `agy` | `agy` |
| `qwen-code` | `qwen` |
| `hermes-agent` | `hermes` |
| `qoder` | `qodercli` |

Legacy aliases (`codex-cli`, `pi-coding-agent`, …) still resolve.

## Generic (no profile)

```rust
generic_launch("my-cli", vec!["--flag".into()], false);
generic_interactive_session("python", vec!["-i".into()], None);
```

## Tests

```bash
cargo test -p ownmesh-profiles
```
