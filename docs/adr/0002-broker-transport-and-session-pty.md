# ADR-0002: Privileged broker transport + session PTY/handoff

## Status

Accepted (broker-session-03)

## Context

OwnMesh 1.0 requires a **networkless** privileged broker and durable session
observer/controller handoff (IMPLEMENTATION_CHECKLIST §8/§9, DoD items 7/8/10).

## Decision

### Broker transport

| Platform | Production endpoint | Auth |
|---|---|---|
| Windows | Named Pipe (`\\.\pipe\ownmesh-privileged-*`) | Pipe SD/ACL (creator/admin/LocalSystem by default; tighten at service install) + MAC capability token |
| Linux | Unix socket mode `0600` | Socket ownership + MAC; `SO_PEERCRED` documented for service hardening ([socket(7)](https://www.man7.org/linux/man-pages/man7/socket.7.html), [unix(7)](https://www.man7.org/linux/man-pages/man7/unix.7.html)) |
| macOS | Unix socket mode `0600` + LaunchDaemon | Ownership/permission + code signature at install + MAC |
| Tests | Loopback TCP `127.0.0.1` / `::1` only | Same MAC stack |

Non-loopback TCP bind/connect is **hard-rejected** (`networkless` error).

Request envelope always includes: protocol version, operation id, caller
principal, capability token (optional→required when configured), nonce, expiry,
structured command, MAC. Replay cache keys `request_id:nonce`.

### Session / PTY

- `ownmesh-session` owns leases, observers, replay buffer, **JSON persistence**.
- `ownmesh-session-host` hosts PTY via `portable-pty` (Windows **ConPTY**, POSIX openpty) with pipe fallback.
- ConPTY reference: [Creating a Pseudoconsole session](https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session).
- Daemon restart reloads sessions; PTY FDs are not preserved across OS reboot (spec §12.7).

### CLI

- `ownmesh privileged install|status|uninstall`
- `ownmesh session *` → `session.*` IPC on ownmeshd

## Consequences

- Broker never opens outbound network or non-loopback listeners.
- Elevated exec prefers broker when secret+endpoint present; otherwise local fallback (ms1 compatibility).
- Handoff: give/claim/release with multi-observer read during controller transfer.

## References

- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew
- https://www.man7.org/linux/man-pages/man7/unix.7.html
- https://www.man7.org/linux/man-pages/man7/socket.7.html
- https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session
- https://learn.microsoft.com/en-us/windows/console/createpseudoconsole
