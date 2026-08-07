# Audit-1: IPC Identity / Auth (要件 1)

Date: 2026-03-22
Scope: shared `daemon.token` abolition, OS peer principal mapping, revocation alias bypass
Status: **PASS** (gaps closed with attack-test coverage; residual notes below)

## Requirement checklist

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| 1.1 | Shared `daemon.token` is not an auth path | **PASS** | `AuthGate::resolve_principal` rejects non-empty `token`; client no longer reads token file; production clients (`ipc_util`, tui, session-host, ownmeshd probe) use OS peer only |
| 1.2 | Non-empty legacy shared token HELLO is rejected | **PASS** | Unit: `auth_gate_rejects_shared_token`, `rejects_shared_token_path`, `shared_token_rejected_even_when_os_peer_would_pass`; E2E: `shared_token_process_is_rejected`, `attack_shared_token_and_name_spoof_cannot_impersonate`, `attack_legacy_daemon_token_file_cannot_authenticate` |
| 1.3 | Startup deletes leftover `daemon.token` | **PASS** | `daemon.rs` removes `AUTH_TOKEN_FILE_NAME` before bind; `start_test_daemon` mirrors; E2E asserts file gone after start |
| 1.4 | Principal from OS peer credential (not self-reported name) | **PASS** | Unix `SO_PEERCRED` + `/proc/pid/exe`; Windows `GetNamedPipeClientProcessId` + `QueryFullProcessImageNameW`; `OsPeerIdentity::principal_key()`; HELLO stores server-assigned principal in `ClientIdentity.client_name` |
| 1.5 | Optional server-managed per-client credential mapping | **PASS** | `AuthGate::issue_client_credential` / `resolve_principal` binds secret → principal + OS user; unknown/mismatched user rejected |
| 1.6 | Same credential + different `client_name` cannot mint another principal | **PASS** | Name ignored; maps to credential principal only — `same_client_credential_different_names_map_to_same_principal`, alias revoke tests |
| 1.7 | Self-reported HELLO `client_name` is never trusted input | **PASS** | `handle_hello` does not use it for mapping; `self_reported_name_does_not_become_principal`; session spoof fields rejected in runtime |
| 1.8 | Revocation keys are mapped principal keys | **PASS** | `RevokedClients` docs + `is_revoked(principal)`; runtime `TOKEN_REVOKE` inserts principal key; dispatch/hello check that key |
| 1.9 | Alias / re-HELLO cannot bypass revocation | **PASS** | Second HELLO rejected while bound (`second_hello_cannot_switch_bound_identity`, `attack_rehello_cannot_switch_principal_or_bypass_revoke`); alias reconnect with same credential still `TOKEN_REVOKED` |

## Code map

- `crates/ownmesh-ipc/src/auth.rs` — `OsPeerIdentity`, `AuthGate`, token abolition, principal resolve
- `crates/ownmesh-ipc/src/transport.rs` — peer capture (Unix/Windows)
- `crates/ownmesh-ipc/src/server.rs` — `handle_hello`, immutable bind, revoke on dispatch
- `crates/ownmesh-ipc/src/client.rs` — no shared-token read; attack-only `with_legacy_shared_token`
- `crates/ownmeshd/src/daemon.rs` — legacy token delete at start; `AuthGate::local_user()`
- `crates/ownmeshd/src/runtime.rs` — principal-keyed revoked set + persist

## Residual notes (out of ticket-1 hard fail)

1. **Windows peer `user_id`** currently uses the daemon process username (`current_os_user_id`), not the client token SID. Principal discrimination on Windows relies on **PID + exe path** (as specified). Cross-user pipe ACL hardening is ticket (4).
2. **Per-client credentials** are in-memory for the daemon process lifetime (test/multi-agent issuance). Persistence of issued credentials is not required by req (1).
3. Token file helpers `read_token_file` / `write_token_file` remain for migration/redaction tests only and are not on the auth path.

## Test commands

```text
cargo test -p ownmesh-ipc -p ownmeshd
```

Result: green (ownmesh-ipc unit + security_spoofing; ownmeshd unit + adversarial_security including spoof / revoke / re-HELLO / legacy token attacks).
