# ADR 0005: Compile-time i18n catalog, and localization scope

- Status: Accepted
- Date: 2026-08-12
- Deciders: OwnMesh maintainers

## Context

`OWNMESH_SPECIFICATION.ja.md` §18.3 requires Fluent FTL for user-visible
strings, and §18.2 lists the surfaces that must be localized into the four
official languages: the TUI, CLI help, setup explanations, error messages,
approval text, OAuth/consent wording, and diagnostics.

The shipped implementation matches neither clause:

- `crates/ownmesh-tui/src/i18n/mod.rs` uses a Rust `enum Msg` with per-locale
  lookup tables. There is no `.ftl` file in the repository and no `fluent`
  dependency.
- Localization covers the TUI only. The `ownmesh` CLI crate has no i18n module.
  `--lang` is accepted, validated, stored in config, and forwarded to the TUI
  subprocess, but CLI help, prompts, errors, and `doctor` output are English.

Neither divergence had a decision record, so both read as unfinished work
rather than as choices.

## Decision

### 1. The compile-time catalog is the accepted mechanism

`enum Msg` plus per-locale tables replaces Fluent FTL. The deciding property is
that **a missing translation is a compile error, not a runtime fallback**. Every
`Msg` variant must be present in every locale table, and `ownmesh-tui
--check-i18n` plus a CI job enforce completeness across en-US, ja-JP, zh-Hans,
and ru-RU.

This keeps §18.3's substantive rules — no user-visible string literals inline,
no sentence assembly by concatenation, CJK width awareness, no layout breakage
on long Russian labels — all of which are covered by the TUI snapshot tests.
What it gives up is runtime-loadable translation files, which the project does
not currently need because translations ship in the binary.

§18.3 is updated to specify the compile-time catalog and to record Fluent as a
future option should runtime-loadable locales ever be required.

### 2. Localization scope is the TUI, and that is now stated

The CLI is not localized, and the specification is corrected to say so rather
than to promise four-language CLI output that does not exist.

The rationale is the one already encoded in §16.4: the CLI is the machine
surface. Its keys, enums, error codes, and exit codes are deliberately English
and locale-independent so scripts and AI clients parse one stable contract.
Localizing the prose around a deliberately stable machine format buys little and
risks users pasting localized text into bug reports that maintainers cannot
match to source strings.

`--lang` therefore has one documented effect on the CLI: it selects the TUI
language and is persisted to config. Its help text says so.

Reopening this means localizing CLI help, prompts, errors, and diagnostics
together — a partial CLI translation is worse than none, because users cannot
tell which output is translated.

## Consequences

- Adding a TUI string means adding an `enum Msg` variant and translating it into
  all four locales in the same commit. CI rejects the change otherwise. This is
  friction by design.
- Adding a language means adding a `Lang` variant and a full table; there is no
  partial-locale state.
- Translators cannot contribute without touching Rust. Accepted for now given
  four locales and in-binary shipping. Moving to Fluent later is a mechanical
  extraction of the existing tables and does not invalidate this ADR's
  completeness requirement.
- CLI users in non-English locales read English CLI output. Documented in
  `--lang` help rather than left to be discovered.

## Alternatives considered

**Adopt Fluent FTL as specified.** Rejected for now: Fluent's value is runtime
locale loading and translator-friendly files, neither of which applies while
translations ship compiled in. Its cost is losing compile-time completeness —
Fluent falls back to the message id at runtime, so a missing string becomes a
visible defect instead of a build failure.

**Localize the CLI too.** Deferred, not rejected. It is a real specification
goal; it is simply not shipped, and the specification should not claim it is.
Doing it properly means one mechanism shared by the CLI and TUI plus a
placeholder-validation CI gate for the four locales.

**Drop §18.2's CLI requirement from the specification.** Rejected: the goal is
legitimate. It is marked as not-yet-shipped instead of deleted.
