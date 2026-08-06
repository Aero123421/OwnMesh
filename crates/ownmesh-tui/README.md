# ownmesh-tui

OwnMesh terminal UI (Ratatui + Crossterm) with full §13 screens, setup wizard, Ctrl+K palette, and en-US / ja-JP / zh-Hans / ru-RU i18n.

```bash
ownmesh-tui                 # interactive UI
ownmesh-tui --status        # one-shot daemon status over IPC
ownmesh-tui --wizard        # open setup wizard
ownmesh-tui --lang ja-JP    # force language
ownmesh-tui --check-i18n    # translation completeness (CI)
```

## Screens

Dashboard · Devices · Workspaces · Sessions · Profiles · Approvals · Transfers · Activity · Diagnostics · Settings

## Keys

| Key | Action |
|-----|--------|
| `q` | Quit |
| `Ctrl+K` | Command palette |
| `F1` / `?` | Help |
| `Tab` / `←` `→` | Cycle screens |
| `1`–`0` | Jump to screen |
| `w` | Setup wizard |
| Approvals: `a` / `d` / `r` | Approve / Deny / Refresh |
| Settings: `l` / `p` / Enter | Language / Preset / Save |

## Transfers (facts only)

The Transfers screen mirrors `ownmesh-transfer` as shipped:

- Local plan + hash-verified local copy (`LocalLoopback`)
- Cloud relay **default OFF**, fail-closed when no direct path
- Does **not** advertise LAN discovery / direct encrypted P2P (deferred; W-§12)

## Tests

```bash
cargo test -p ownmesh-tui
```

Covers CJK width / Russian overflow snapshots at 80×24, wizard preset persistence (Recommended / Workspace Only / Full User / Full Access), and i18n completeness.

Panic and normal exit always restore the terminal (raw mode / alternate screen).
