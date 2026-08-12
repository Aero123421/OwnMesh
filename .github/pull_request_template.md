<!--
Describe what changed and why. Link the specification section or ADR when one
applies. Keep the PR to one clear behavior or boundary.
-->

## What

## Why

## Security, privilege, and protocol impact

<!--
State this explicitly, including "none". Reviewers rely on it. If this PR
changes an auth, policy, privilege, or protocol boundary, link the ADR under
docs/adr/ — CONTRIBUTING.md requires one.
-->

## Checks

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo test --workspace --all-targets --locked`
- [ ] `pnpm -r test && pnpm -r typecheck && pnpm -r lint`
- [ ] `python scripts/check_release_quality.py`
- [ ] Shipped-surface changes are reflected in `release/SUPPORTED_SURFACES.json`
- [ ] Behavior changes are covered by a test next to the behavior

## Commit authorship

<!--
Commits must carry a real name and a reachable email. Placeholder identities
are not accepted; see the authorship section in CONTRIBUTING.md.
-->

- [ ] Commits are authored under an identity I can be reached at
