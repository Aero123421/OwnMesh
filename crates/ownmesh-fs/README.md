# ownmesh-fs

Workspace-aware filesystem operations, patches, path safety, and read-only Git
status/diff (fixture-tested, entry/line cursor pagination aligned with log pages).

Git reads use a bounded private metadata view. They preserve the original
HEAD/index and linked-worktree identity, but do not run repository filters,
textconv, external diff drivers, or inherited Git configuration. Diffs show
raw content; custom filter conversions are not applied. Repositories whose
index contains submodules, or exceeds the bounded index capture, return an
explicit error instead of a potentially incomplete clean result. See
[ADR 0023](../../docs/adr/0023-read-only-git-helper-isolation.md).
