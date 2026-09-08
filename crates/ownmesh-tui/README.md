# ownmesh-tui

OwnMesh terminal UI (Ratatui + Crossterm), with a setup wizard, command
palette, and en-US / ja-JP / zh-Hans / ru-RU translations. A screen's
presence does not imply that every operation in specification §13 is
implemented in the TUI; some views are read-only or informational.

```bash
ownmesh-tui                 # interactive UI; requires stdin and stdout TTYs
ownmesh-tui --status        # one-shot daemon status over IPC; pipes supported
ownmesh-tui --once          # equivalent one-shot mode
ownmesh-tui --wizard        # open setup wizard
ownmesh-tui --lang ja-JP     # language override
ownmesh-tui --check-i18n     # translation completeness (CI)
```

An interactive invocation with piped input/output is rejected before creating
OwnMesh directories or contacting the daemon. `--status` and `--once` remain
explicit, non-interactive status requests.

## Screens and navigation

Primary navigation cycles through Dashboard, Devices, Workspaces, Approvals,
and Settings. Sessions, Transfers, Activity, and Diagnostics are also reachable
through numeric shortcuts or the command palette.

| Key | Action |
|-----|--------|
| `Ctrl+C` | Emergency exit from any screen, overlay, or palette |
| `q` | Quit from a screen; close Help, Connector, or Custody Repair overlays |
| `Ctrl+K` | Open/close the command palette |
| `/` or `:` | Open the palette from a screen |
| `F1` / `?` | Open Help from a screen |
| Dashboard: `Tab` / `Shift+Tab`, `j` / `k`, `↓` / `↑` | Select the next/previous overview action |
| Dashboard: `Enter` | Run the selected overview action |
| Other screens: `Tab` / `Shift+Tab` | Cycle primary screens forward/backward |
| `←` / `→` | Cycle primary screens |
| `1` / `2` / `3` | Dashboard / Devices / Workspaces |
| `4` / `5` / `6` | Sessions / Approvals / Transfers |
| `7` / `8` / `9` or `0` | Activity / Diagnostics / Settings |
| `Esc` | Return to Dashboard; dismiss a dialog or go back one wizard step |
| `w` | Open the setup wizard from a screen |
| Dashboard / Diagnostics: `r` | Refresh local daemon and readiness/diagnostic observations |
| Sessions / Approvals: `r` | Refresh the local IPC list |
| Devices: `r` | Explicitly request Control Plane device inventory over the network |
| Approvals: `a` / `d` | Request browser/passkey approval or denial of the selected pending item |
| Settings: `l` / `p` / `Enter` | Select language / preset / save |

Plain shortcuts do not also run for Ctrl/Alt/Super-modified letters. For
example, `Ctrl+D` does not deny an approval. Reported key-repeat events move
cursors and edit text, but do not repeatedly confirm wizard steps or submit
actions. Terminals that report a held key as separate presses cannot be
distinguished from intentional presses by this filter.

The palette owns keyboard and paste focus while open. Cancelling it preserves
the underlying dialog; executing a command reveals its destination or opens
the requested dialog. Bracketed paste edits only the active text field, never
executes a command, and cannot change a wizard hidden beneath the palette.
Typed and pasted text share a 2,048-byte, UTF-8-safe limit and discard control
characters.

## Refresh semantics and remaining limitations

Views show snapshots, not a continuously live feed. Use the explicit refresh
keys above. Local Dashboard/Diagnostics refresh preserves the current language
override and unsaved settings/wizard edits; an IPC error is reported and the
agent is no longer presented as running. A failed Sessions refresh retains the
previous rows and displays the error rather than presenting an empty result as
success.

These refreshes still wait synchronously for the existing bounded IPC/network
requests. This change does not introduce background network polling or claim
that long-running refreshes are cancellable. Browser/passkey approval, exact
approval-ID binding, daemon authentication, and custody checks are unchanged.
The Activity feed is not populated by these refresh actions.

## Transfers (informational view)

The Transfers screen describes `ownmesh-transfer`; it is not a transfer
submission or progress interface:

- Local plan + hash-verified local copy (`LocalLoopback`).
- Cloud relay is default OFF, with fail-closed behavior when no direct path exists.
- LAN discovery / direct encrypted P2P remains deferred (W-§12).

## Tests

```bash
cargo fmt --all --check
cargo test --locked -p ownmesh-tui --all-targets
cargo clippy --locked -p ownmesh-tui --all-targets -- -D warnings
```

The existing suite covers CJK/Russian rendering, wizard preset persistence,
translation completeness, approval argument binding, and terminal lifecycle.
`src/interaction_tests.rs` adds isolated keyboard, repeat-event, overlay,
paste, UTF-8 input-boundary, and refresh-state regressions.
`tests/non_tty_preflight.rs` exercises the real binary with isolated,
initially absent directories and a bounded exit deadline.

The terminal guard handles raw-mode and alternate-screen restoration on
normal exit and panic. Interactive behavior across Windows, macOS, and Linux
still requires platform validation; unit tests are not a browser/passkey or
full-device end-to-end receipt.
