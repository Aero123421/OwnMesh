# ADR 0007: Restricted presets deny command execution until OS confinement exists

- Status: Accepted
- Date: 2026-08-12
- Deciders: OwnMesh maintainers

## Context

`OWNMESH_SPECIFICATION.ja.md` §7.1 describes five access presets and promises
that **Recommended** allows ordinary user-scoped work while confirming
administrator operations, credentials, external transfer, and major OS changes.

The shipped presets do not match that description in two places:

1. `workspace_only` and `recommended` **deny** `command.run` and `session.open`
   outright (`ownmesh-policy` `preset_document`, priority 95). They are not
   `ask`; there is no approval that unlocks them.
2. Until this ADR, both presets allowed every `filesystem.read` inside the
   workspace with no confirmation, including `.env` files and private keys —
   the specific case §7.1 says Recommended confirms.

Neither divergence had a decision record, so the specification and the shipped
behavior disagreed and neither was clearly authoritative.

The reason for (1) is a real confinement gap, not an oversight:

- Restricted presets enforce workspace custody for **filesystem** operations by
  resolving every path against a registered root and revalidating the opened
  handle. That authority does not extend to a spawned process. Binding `cwd`
  does not stop `python -c`, an absolute path, or a `..` argument the daemon
  never interprets.
- `session.open` is command execution wearing a different name. A PTY's stdin
  accepts arbitrary commands after the session is authorized, so a session that
  is merely "opened in a workspace" is an unconfined shell.
- OwnMesh's own threat model (A7, A8) says restricted presets must actually
  enforce the workspace boundary. Allowing an escape hatch that the policy
  engine cannot see would make the restricted presets a claim we cannot keep.

Closing the gap properly needs OS-level process confinement (namespaces/seccomp,
Job Objects with restricted tokens, sandbox profiles). That is a substantial
platform-specific project and is explicitly out of scope for the v1.2 line.

## Decision

### 1. Restricted presets keep the deny, and the specification records it

`workspace_only` and `recommended` continue to deny `command.run` and
`session.open`. Failing closed is preferable to a preset that advertises
workspace confinement it cannot enforce.

§7.1 of the specification is updated with an implementation-status note in the
same style as §14.3 and §17.7, so the table stops reading as shipped behavior.

### 2. The credential-read promise is restored rather than dropped

§7.1's "credentials are confirmed" clause is implementable today without process
confinement, because it is a filesystem decision and the daemon already resolves
the path. Both restricted presets now carry a `filesystem.read` rule conditioned
on the machine-derived `reads_sensitive_location` tag
(`ownmesh_fs::looks_sensitive`), which turns a credential-like read into `Ask`.

Constraints on that mechanism:

- The tag is computed by the daemon from the resolved path. Clients never supply
  `tags`, so a model cannot suppress the classification by omitting a field, and
  cannot manufacture one either.
- It is an `Ask`, never a `Deny`. A false positive costs one confirmation.
- `full_user_access` and `full_access` do not carry the rule. Full Access
  keeping **no hidden ask or deny** is a stronger invariant than this heuristic
  and is enforced by `full_access_invariant.rs`.

### 3. The preset name does not change

`recommended` stays `recommended`. Renaming a preset written into every existing
`policy.toml` would break configurations for a naming improvement, and the setup
flow already states which presets permit command execution before the user
chooses.

### 4. The middle rung is an open product decision

The gap this ADR documents is real: there is no preset between "reads allowed,
writes confirmed, no execution" and "every user-level action allowed". Users who
want ChatGPT to run tests must select `full_user_access`. The candidates are
recorded here so the next decision starts from a shared list, and none of them
is adopted by this ADR:

| Option | Gains | Costs |
| --- | --- | --- |
| `command.run` / `session.open` become `Ask` in `recommended` | Human approves each execution; no new platform work | Approval fatigue — ADR 0006 forbids reusable command grants, so every command prompts. Once approved the process is still unconfined, so the preset's confinement claim weakens |
| New preset between recommended and full_user_access | Existing presets keep their meaning | A sixth preset to explain, translate, and test; the confinement claim question is unchanged |
| OS process confinement, then `Ask` or `Allow` | Restores §7.1 honestly | Large, per-platform, and the weakest link sets the guarantee |
| Executable allowlist + workspace `cwd` + `Ask` | Bounded blast radius without a sandbox | An allowlisted interpreter still runs arbitrary code (the argv problem from ADR 0006) |

## Consequences

- `recommended` is honestly described as a read-and-confirm posture, not as
  "ordinary work flows without friction". Documentation that implies otherwise
  is a defect.
- The MCP `ownmesh.exec` and `ownmesh.session` scopes are reachable only on
  devices set to `full_user_access` or `full_access`. Client documentation must
  say so, because the failure is a device-side policy denial that the OAuth
  scope check cannot predict.
- Adding `when_tag` to `PolicyRule` gives operators a general way to condition a
  rule on a machine fact. New tags must stay server-derived; a tag that a client
  could set would turn the policy engine into an authorization oracle for
  untrusted input.
- Reopening item 4 does not require reopening items 1–3.

## Alternatives considered

**Silently keep the divergence.** Rejected: the specification is the design
authority, and an unrecorded gap between it and the shipped presets is how
"recommended" came to promise something the product does not do.

**Delete the §7.1 promise.** Rejected: the goal is legitimate. The credential
clause was implementable and is now implemented; the execution clause is marked
as not yet shipped rather than deleted.

**Enforce the workspace boundary for processes by inspecting argv.** Rejected:
this is the argument ADR 0006 already settled for temporary grants. Argument
inspection cannot decide what an interpreter will do.
