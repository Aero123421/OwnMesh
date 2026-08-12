# ADR 0009: Rule prefixes and grant scopes use different path matching

- Status: Accepted
- Date: 2026-08-12
- Deciders: OwnMesh maintainers
- Amends: [ADR 0006](./0006-temporary-grant-path-scope.md)

## Context

ADR 0006 correctly changed temporary grants to component-bounded subtree
matching, so a grant for `proj` cannot authorize `proj-secret`. Applying the
same matcher to policy rules accidentally changed the documented textual
`path_prefix` behavior: rules for `.env` no longer covered `.env.production`.
It also made a deny rule miss an interior traversal such as
`secrets/../secrets/key.pem`, even though the filesystem walk resolves that path
back under `secrets`.

Returning blindly to raw `starts_with` would restore compatibility but would
let an allow rule for `proj` match `proj/../secrets`.

## Decision

- Temporary grants keep component-bounded subtree matching and continue to
  reject `..`.
- Policy rules retain textual prefix semantics for compatibility.
- When a candidate contains an interior `..`, the evaluator collapses it
  lexically before applying the textual prefix. A traversal that would climb
  above the path root matches no rule and is rejected later by workspace
  custody.
- Whitespace is never trimmed from a filesystem scope; it is part of the
  filename.

This preserves `.env` to `.env.production`, makes deny rules see the resolved
interior target, and prevents traversal from escaping an allow prefix.

## Consequences

Rule matching and grant matching are deliberately asymmetric because grants
only widen authority, while policy rules may ask or deny. No persisted format
or protocol version changes.
