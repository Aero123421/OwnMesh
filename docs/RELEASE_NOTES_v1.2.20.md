# OwnMesh v1.2.20

OwnMesh v1.2.20 is a terminal-UI reliability patch. It preserves the v1.2.19
product surface, OAuth/passkey model, MCP protocol, and policy fail-closed
guarantees. The machine-checked contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Fixed

- **Ctrl+C is now a universal emergency exit (#136).** Raw mode delivers
  Ctrl+C as a regular key event, so the terminal driver never raises SIGINT.
  The TUI handled that combination nowhere and overlay handlers (setup
  wizard, command palette, help, connector) intercepted input first, leaving
  no escape hatch. Ctrl+C now quits immediately from every screen, overlay,
  wizard step, and palette state; `q` remains the documented normal quit.
  The always-visible command bar and the help text document both keys in all
  four UI languages.
- **A dead terminal can no longer leave an unresponsive TUI (#137).**
  `event::poll` / `event::read` errors (EOF, detached or broken TTY) were
  converted into idle iterations, so the loop kept redrawing forever while
  accepting no input, and `restore_terminal()` suppressed every cleanup
  failure while reporting success. Input failures are now a controlled exit,
  restoration attempts every pending step and returns the first error, and
  cleanup retries are preserved for partially failed restores. Non-interactive
  invocations without stdin/stdout TTYs fail closed with usage guidance before
  creating any configuration state.
- **Mouse capture stays off until mouse navigation actually exists (#134).**
  The TUI unconditionally enabled mouse capture while discarding clicks and
  blindly reusing scroll events as list-cursor mutations, which on macOS
  hijacked trackpad scrolling and native text selection with nothing gained.
  Capture is disabled by default (keyboard-only navigation is unchanged);
  enabling it again requires shipping real hit-testing first.
- **List selection is bounded and always visible (#135).** The shared list
  cursor grew without clamping to the item count and screens rendered
  stateless lists without a viewport offset, so selections could vanish past
  either edge and long lists never scrolled to follow the cursor. Cursor
  movement is now centralized and clamped per screen (`0..item_count`, empty
  lists pin at zero), every transition path — numeric shortcuts, Esc, palette,
  dashboard actions — resets it deterministically, shrinking refreshes clamp
  immediately, and lists render through Ratatui's stateful widget so the
  selected row scrolls into view.

## Compatibility and migration

- No D1 migration is required beyond v1.2.17's `0017`.
- No control-plane behavior change; `SERVICE_VERSION` moves to `1.2.20`, so
  redeploy the Worker if you rely on `ownmesh doctor --check-network` to show
  matching versions.
- Existing OAuth clients, passkeys, refresh tokens, enrolled devices,
  workspaces, policies, sessions, transfers, approvals, and ChatGPT
  connectors remain compatible.
- TUI keyboard contracts are unchanged apart from the new global Ctrl+C exit;
  mouse input was previously captured-but-unusable and is now passed through
  to the terminal.
- Authenticode, Apple notarization, MSI/NSIS, and native macOS packages
  remain out of scope.

## Upgrade

1. Run the v1.2.20 `ownmesh-installer.sh` / `ownmesh-installer.ps1` (or
   `ownmesh update`) on devices.
2. Optionally redeploy the control-plane Worker (`pnpm run deploy` in
   `packages/control-plane`) so `/health` reports `1.2.20`.
3. Confirm `ownmesh doctor --check-network` shows matching versions.
