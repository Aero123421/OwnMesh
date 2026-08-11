# OwnMesh v1.2.1

OwnMesh v1.2.1 is a stable patch release focused on first-run behavior,
machine-readable CLI output, and control-plane abuse limits. The supported
surface remains the complete contract recorded in
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Improvements

- Read-only commands no longer create default config or policy files, so running
  `status`, `doctor`, or inspection commands before setup cannot block the real
  setup flow.
- The onboarding order now deploys the self-hosted control plane before setup,
  and guided deployment and installers print the exact next command.
- `--json` failures emit one parseable terminal object. Nested IPC failures,
  offline fallbacks, Doctor reports, and richer command-specific results no
  longer produce two JSON documents.
- `ownmesh doctor` performs no network request by default. An explicit
  `--check-network` failure returns a non-zero status, while `--offline` remains
  a hard override even when a shell alias adds the probe flag.
- Existing v1.2 configuration with Unicode or space-containing instance aliases
  remains readable and selectable. New aliases use the portable strict syntax.
- Authenticated control-plane requests use per-credential limits plus a separate
  coarse IP ceiling. Unauthenticated bootstrap traffic cannot consume a valid
  credential's budget behind shared NAT egress.
- Duplicate MCP catalog aliases remain callable for compatibility but are no
  longer advertised as separate indistinguishable tools.
- Passkey and auth pages improve error guidance and text contrast, and CLI/TUI
  language handling preserves Unicode input.

## Security and compatibility

- No OAuth token, cookie, passkey material, or raw IP address is added to rate
  limit storage or diagnostics; only scoped digests reach Cloudflare counters.
- The release remains protocol-compatible with v1.2.0. Existing enrolled devices,
  OAuth refresh tokens, workspaces, policies, sessions, and transfers are kept.
- New instance aliases are validated at write time without invalidating legacy
  aliases already stored by v1.2.0.

## Upgrade

1. Upgrade the local binaries with the signed installer or release archive.
2. Re-run the guided control-plane deploy so the new rate-limit bindings and
   Worker code are applied.
3. Run `ownmesh doctor --json`; add `--check-network` when deployment reachability
   should be part of the check.

The v1.2.0 release notes remain available as the original stable baseline.
