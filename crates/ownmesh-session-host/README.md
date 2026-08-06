# ownmesh-session-host

Detached session host (PTY supervisor) skeleton.

```bash
ownmesh-session-host status
ownmesh-session-host serve --session-id sess_x
```

Connects to `ownmeshd` over local IPC. Full PTY supervision arrives in chapter 9. Terminal raw mode is always restored on exit/panic.
