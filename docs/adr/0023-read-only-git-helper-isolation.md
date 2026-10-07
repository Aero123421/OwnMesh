# ADR 0023: Read-only Git helper isolation

Status: Accepted

## Context

`git_status`, `git_diff`, and the HEAD binding helper run under filesystem
authority. Restricted presets deny command execution. Git can nevertheless
execute repository-configured clean/process filters during status and diff,
and textconv during diff. Disabling external diff alone does not enforce this
boundary. Includes, per-worktree config, info attributes, and nested submodule
Git processes are additional representations of the same execution surface.

## Decision

Resolve Git from an absolute PATH entry before changing into the requested
directory. Remove inherited `GIT_*` variables, disable global/system config
and fsmonitor, and retain the existing timeout and bounded output drains.

Discover and validate the original worktree and Git directory, then create a
private temporary common directory. Copy only bounded metadata: benign core
settings, object format, branch/upstream mappings, shallow boundaries, local
exclusion rules, and a files-based ref/HEAD snapshot obtained through Git's
active ref backend. Pin the original object directory and index path (including
the split index's original parent); do not copy
executable config, includes, info attributes, or worktree-config extensions.
Disable filter attributes in the private view and pass `--no-ext-diff` and
`--no-textconv` to diff. Returned differences describe raw content rather than
repository-provided conversions.

Check the bounded index for gitlinks before capture and return an explicit
error for submodule repositories or an oversized index. Status and diff also
disable submodule recursion so a concurrent index change cannot start a child
Git outside the private view. Nested submodule status is unsupported by this
read-only path until it can be captured with equivalent isolation. A submodule
selected directly is treated as its own repository when it has no nested
gitlinks. This does not change command capability authorization.

## Consequences and validation

Ordinary status, staged/unstaged raw diffs, upstream reporting, shallow clones,
SHA-256 object format, reftable refs, and linked worktrees (including split
indexes) remain supported.
Filters that transform content may cause raw differences that a native Git
invocation would hide. Unsupported captures fail visibly instead of reporting
cleanliness without proof.

Regression fixtures in `crates/ownmesh-fs/src/git.rs` exercise textconv,
clean/process filters, included config, worktree config, info attributes,
workspace executable shadowing, submodule refusal, upstream/staged output,
SHA-256/reftable repositories, shallow boundaries, local exclusions, and
linked-worktree identity. Native Windows/macOS
execution remains part of the platform CI gates.
