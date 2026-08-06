# ownmesh-tui

OwnMesh terminal UI (Ratatui + Crossterm).

```bash
ownmesh-tui              # brief skeleton frame + IPC status
ownmesh-tui --status     # one-shot status over IPC
```

Panic and normal exit always restore the terminal (raw mode / alternate screen).
