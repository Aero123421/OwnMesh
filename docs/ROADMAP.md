# OwnMesh roadmap

**Baseline:** v1.2.3 · **Last updated:** 2026-08-12

Specification §31.3 asks for a public roadmap. This is it. It records what the
project intends to do next and, just as importantly, what it has decided not to
do — so a reader can tell a gap from a choice.

Two documents bound this one and win where they disagree:

- [`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json) is the
  machine-checked contract for what ships today.
- [`docs/DOD_1.0.md`](./DOD_1.0.md) holds the §33 Definition of Done audit and
  the `W-*` evidence waivers.

Nothing here is a dated commitment. Items are ordered by what would most improve
the product, not by effort.

## Now — the gap between what the presets promise and what they do

**A usable middle access preset.** Today `workspace_only` and `recommended` deny
command execution and interactive sessions outright, so anyone who wants ChatGPT
to run a test suite must choose `full_user_access`, which allows every user-level
action. There is no rung between "read and confirm writes" and "everything".
[ADR 0007](./adr/0007-restricted-presets-deny-command-execution.md) records why
the deny exists and lists the candidate designs; picking one is the open work.

**OS process confinement.** The reason the middle rung is hard: binding `cwd`
does not confine a spawned process, and a PTY's stdin is arbitrary execution.
Real confinement (namespaces/seccomp, Job Objects with restricted tokens, sandbox
profiles) is what would let a restricted preset honestly allow execution. It is
per-platform work, and the weakest platform sets the guarantee.

## Next — evidence, not implementation

These are the `W-*` waivers. The code exists; the receipt does not.

| Item | Waiver | What closing it means |
| --- | --- | --- |
| macOS/Windows native broker receipts | `W-E8-RECEIPTS` | Run the privileged lifecycle on real macOS/Windows hosts and publish the transcript, plus the full public MCP → agent → broker route |
| Automated external ChatGPT exercise | `W-E10-AUTO` | A reproducible harness against a live ChatGPT connector, replacing today's manual compatibility receipt |
| Independent security review | `W-EXT-SEC` | An external firm, not the internal checklist |
| Native signing and packaging | `W-SIGN`, `W-PACKAGING` | Authenticode, Apple notarization, MSI/NSIS, native macOS packages. Portable minisign archives stay the contract until then |
| Release tag signing | ADR 0001 follow-up | Annotated tags are already required; GPG/SSH tag signing is configured but not yet claimed as enforced |

## Then — depth the specification asks for and the product does not yet have

- **Localized CLI.** [ADR 0005](./adr/0005-i18n-compile-time-catalog.md) scopes
  localization to the TUI. Extending it means one mechanism shared by CLI and
  TUI plus placeholder validation, and a partial CLI translation is worse than
  none.
- **`ownmesh_search_files`, process tools, and remote log reads over MCP.**
  Tracked in §14.3's implementation-status note. Log bodies deliberately have no
  remote tool; changing that requires deciding where log content may be
  persisted.
- **Cloud-side policy documents.** [ADR 0008](./adr/0008-control-plane-authorization-scopes-and-binding.md)
  explains why the device is the only policy engine today. A multi-admin tenant
  that needs server-side restriction is the use case that would justify one.
- **LAN discovery and direct P2P transfer depth** (`W-§12`). Relay stays off by
  default regardless.
- **External adapter SDK** (§13.7) for community CLI adapters as separate
  processes.

## Explicitly not planned

- A vendor-hosted OwnMesh SaaS, or any mandatory central service.
- Telemetry, crash upload, or usage analytics enabled by default.
- Cloud file relay as an automatic fallback when direct transfer fails.
- Treating model judgment, tool argument text, or repository content as an
  authorization input.
- Hidden hard denies under Full Access.

## Working on one of these

Read [`CONTRIBUTING.md`](../CONTRIBUTING.md) first. Anything touching auth,
policy, privilege, or protocol boundaries needs an ADR under
[`docs/adr/`](./adr/) before the implementation, and the roadmap items above are
all in that category.
