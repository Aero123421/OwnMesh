# ADR 0007: Grant scopes and rule prefixes use different matchers

- Status: Accepted
- Date: 2026-08-12
- Deciders: OwnMesh maintainers
- Amends: [ADR 0006](./0006-temporary-grant-path-scope.md)

## Context

ADR 0006 introduced `path_scope_contains`, a component-wise containment check,
so a temporary grant scoped to `proj` could not capture `proj-secret`. The same
change also swapped `PolicyRule::matches` from a raw string prefix to that
function, on the assumption that a stricter matcher is always safer.

It is not. An adversarial review of the change found two regressions:

1. `path_components` fails closed on `..`, so a deny rule on `secrets` stopped
   matching `secrets/../secrets/key.pem`. The filesystem layer normalizes `..`
   by popping (`WorkspaceRoot::resolve`), so the read still landed on the
   guarded file — the rule simply no longer fired. Under `full_access` that is a
   silent Allow.
2. Component alignment made non-aligned prefixes inert. `.env` stopped covering
   `.env.production`, `secret` stopped covering `secrets.txt`, and prefixes of
   `/` or `.` normalized to zero components and matched *nothing at all*. No
   validation rejects such a rule, so `ownmesh policy rule add --path-prefix /`
   persisted successfully and did nothing.

Neither bites a built-in preset — none sets `path_prefix` — so the blast radius
was user-authored rules, which is precisely the documented mechanism for
protecting sensitive paths.

The review also found that a matching grant returned `Allow` *before* the
document was consulted, so a grant over `proj` silenced an explicit deny rule on
`proj/.env` inside it.

## Decision

### 1. Rules keep a raw string prefix; grants keep component containment

The two are not the same kind of predicate:

- A **grant** widens authority beyond a single approved operation. Over-matching
  is the failure mode, so it takes the strict, fail-closed matcher.
- A **rule** may widen *or* narrow. Tightening its matcher silently narrows every
  deny rule in the field. Its `path_prefix` is documented as a prefix and users
  rely on prefix semantics.

`PolicyRule::matches` therefore returns to `str::starts_with`, with a comment at
the call site explaining why the neighbouring grant code does something else,
and a regression test that pins all five prefix shapes plus the two traversal
cases.

### 2. A grant answers `Ask`, never `Deny`

`evaluate_with_grants` now evaluates the document first and returns immediately
on `Deny`. This restores the documented `deny > ask > allow` precedence: an
operation the policy denies could not have raised an approval prompt, so no
grant should exist that satisfies it.

### 3. Scope comparison does not normalize what the filesystem will not

`path_components` no longer trims, and grant issuance stores the approved path
verbatim. ` proj` is a different directory from `proj`, and the filesystem layer
does not trim either; normalizing here let a grant on `proj` match a path that
resolves elsewhere. Separator handling is delegated to `Path::components()`, so
`proj\x` is one component on Unix and two on Windows — matching what each
platform will actually open.

### 4. Operation facts carry the *resolved* workspace

The daemon populates `facts.workspace_id` with `canonical_workspace_id(...)`
rather than the caller's raw `Option`. Issuance requires a canonical `ws_...`
id, so without this a grant requested on the common path — where the client
omits `workspace_id` — would fail to issue at all. `policy explain` resolves the
same way, and gained `--path` / `--workspace-id`, so the auditing tool reports
the decision the real operation gets instead of one for an unscoped operation.

## Consequences

- Deny rules behave exactly as they did before ADR 0006. The pre-existing gap
  that a *leading* traversal (`foo/../secrets/x`) does not match a deny on
  `secrets` is unchanged and out of scope here; closing it means normalizing
  `facts.path` before evaluation, which needs its own analysis.
- A rule whose `path_prefix` cannot be expressed as a prefix is still accepted
  by `policy rule add`. Rejecting nonsensical prefixes at write time is worth
  doing and is not done here.
- A grant can no longer be used to reach a denied path inside a granted subtree.
  This is a narrowing; no configuration that previously worked as documented
  relied on it.
- `logs.read` grants remain unscoped, since there is no path to scope them by.
  Device log query is local-IPC only, so this is not remotely reachable.

## Alternatives considered

**Keep component matching for rules and normalize `facts.path` first.** The
principled fix, and probably the eventual one. Rejected for now because it
changes what every rule matches in a second way while a regression is live in a
shipped release; reverting to known-good semantics first is the smaller step.

**Validate `path_prefix` at rule-add time and keep component matching.** Would
catch `/` and `.`, but not the `..` bypass, and would break `.env` →
`.env.production` for anyone already relying on it.

**Let grants override deny for the approved operation only.** Adds a special
case to the precedence rule to preserve a behavior nobody asked for.
