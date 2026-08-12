# ADR 0006: Temporary grants carry a mandatory path scope

- Status: Accepted
- Date: 2026-08-12
- Deciders: OwnMesh maintainers

## Context

Approving an operation with `--grant` (CLI) or `temporary_grant: true` (MCP)
issues a time-bounded overlay that forces `Allow` for later matching operations
by the same principal, so a human is not re-prompted for every step of a task.

The shipped behavior was broader than the prompt implied. `handle_approval_approve`
minted non-command grants from a struct literal with `path_prefix: None`, and
`temporary_grant_matches` treats a `None` prefix as "match any path". Approving a
single write to one file therefore authorized **every** `filesystem.write` the
principal could reach, for up to 24 hours (`--grant-seconds` maximum 86400).
Under `full_user_access` or `full_access`, workspace enforcement is off, so the
reachable set was the whole user account.

Three factors made this hard to notice:

- The CLI help said only "Also issue a temporary capability grant."
- `docs/SECURITY_REVIEW_CHECKLIST.md` claimed grants carry a *target*, which the
  issued rows did not.
- `temporary_grant_from_facts`, which does derive a scope from the approved
  path, was unreachable: its only caller was guarded by the same condition that
  makes the function return `Err`, so the scoping code never executed.

Separately, matching compared `path_prefix` with a raw string `starts_with`, so
a scope of `proj` would also match `proj-secret`. And because filesystem paths
in `OperationFacts` are workspace-relative, an identical relative path in a
different workspace would match a scope minted in the first one.

## Decision

1. **`temporary_grant_from_facts` is the only issuance path.** The daemon no
   longer constructs `TemporaryGrant` literals. Hand-assembly is what produced
   the unscoped rows.
2. **Path-scoped capabilities require a scope.** `filesystem.*` grants fail
   closed at issuance without an approved path, and matching refuses any
   `filesystem.*` row whose `path_prefix` is absent — including legacy rows
   already persisted in `grants.json` and forged rows.
3. **Containment compares whole path components.** `path_scope_contains` splits
   on both separators and matches component-wise, so `proj` covers `proj` and
   `proj/src/x` but never `proj-secret`. A `..` component on either side fails
   closed.
4. **Scopes are workspace-bound.** `OperationFacts` and `TemporaryGrant` carry
   `workspace_id`. When a grant recorded one, an operation in a different
   workspace does not match.
5. **The issued scope is disclosed.** The approve result carries a `grant`
   object with `capability`, `scope`, `workspace_id`, and `expires_at_unix`, and
   the `--grant` help states what the grant covers.

`command.run` and `command.*` grants remain refused outright; that rule is
unchanged and independent of this one.

## Consequences

- Approving with `--grant` now authorizes the approved path subtree in the
  approved workspace, not the filesystem. Multi-directory tasks re-prompt once
  per directory. That is the intended trade: the prompt said "this operation",
  so the grant should mean roughly that.
- Grant rows persisted by v1.2.1 and earlier have no `path_prefix` and no
  `workspace_id`. For `filesystem.*` they now fail to match and the operation
  re-enters normal policy evaluation — an approval prompt rather than a silent
  allow. No migration is required and none is provided; failing closed on an
  ambiguous legacy row is the correct resolution.
- `workspace_id` is a new optional field on both structs. It is `#[serde(default)]`
  so existing state files deserialize unchanged.
- Capabilities that are not path-scoped (for example `logs.read`) still mint
  grants without a path, since there is no path to scope them by. If a future
  capability gains a resource identifier, it belongs in
  `temporary_grant_requires_path_scope`.

## Alternatives considered

**Keep unscoped grants but shorten the lifetime.** Rejected: a five-minute
unrestricted filesystem grant is still unrestricted, and the mismatch with what
the human approved remains.

**Scope to the parent directory rather than the exact approved path.** Rejected:
it widens a single-file approval to that file's siblings without saying so —
a smaller version of the same defect.

**Normalize legacy rows on load by inferring a scope.** Rejected: there is no
sound way to infer what a row with no recorded scope was approved for. Refusing
to match is the only fail-closed reading.

**Bind grants to an absolute canonical path instead of a workspace pair.**
Rejected for now: `OperationFacts.path` is workspace-relative by design, and
resolving it at issuance would record a path that a later workspace-root change
could silently invalidate. The `(workspace_id, relative path)` pair keeps the
grant meaningful under the same indirection the operation itself uses.
