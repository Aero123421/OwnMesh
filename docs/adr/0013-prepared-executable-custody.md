# ADR 0013: Prepared executable custody

- Status: Accepted
- Date: 2026-08-19
- Amended: 2026-08-28
- Deciders: OwnMesh runtime maintainers

## Context

`command.run` records both the invocation path used as `argv[0]` and the
canonical backing executable identity. Two path-based gaps remained:

- a changed invocation could be replaced at runtime with a direct launch of
  the canonical backing, changing proxy/multicall semantics; and
- revalidating a path and later asking the OS to open that path for execution
  did not prove that both steps referred to the same immutable image.

The boundary includes structured commands, the OwnMesh-selected raw-shell
interpreter, and bounded review commands. Client-supplied kind, digest, or
identity fields are never authority.

## Decision

### 1. Invocation identity is part of the exact action

Durable server facts bind the requested argv, resolved absolute invocation
path, invocation directory-entry identity, symlink target relation, canonical
backing identity and digest, classification, cwd, and sanitized environment
overlay. Regular files and proxy entries carry platform identity fields
(Unix device/inode; Windows volume serial/file index).

Invocation drift never grants authority to launch the canonical backing
directly. Missing, deleted, recreated, retargeted, reclassified, or otherwise
mismatched invocation/backing state fails before spawn with
`OWNMESH_E_EXECUTABLE_IDENTITY_DRIFT`; a fresh request and authorization are
required.

### 2. Launch consumes a non-cloneable `PreparedExecutable`

Approval state remains serializable as `ExecutablePin`. Each execution attempt
must create a new, non-serializable and non-cloneable `PreparedExecutable` by
opening and verifying the invocation and backing relationship. The launcher
consumes that capability and keeps custody through the OS image-open step.

Platform implementations are:

- **Linux native images:** hash the exact stream while copying the
  identity-verified handle into an anonymous executable memfd, compare it with
  the approved digest, apply write/grow/shrink/seal
  seals, and call `fexecve` on that descriptor with the approved `argv[0]`.
  Later path or in-place inode changes cannot alter the image.
- **Linux shebang scripts:** treat the script and effective interpreter as one
  compound identity. Admission parses the verified shebang, resolves simple
  `/usr/bin/env <name>` through OwnMesh's deterministic execution path, and
  pins the interpreter invocation and canonical backing; unsupported `env`
  option syntax and nested shebang interpreters fail closed. Preparation
  re-parses the verified script, revalidates both identities, and executes
  sealed memfd copies of both interpreter and script. Shell interpreters read
  the inherited `/proc/self/fd/<n>` directly. Node interpreters use a bounded
  data-URL loader that maps the sealed bytes to the approved canonical module
  URL, preserving adjacent relative imports without reopening the mutable
  script as source. `process.execPath` is bound to `/proc/self/exe`, the
  kernel-held sealed image, so CLIs can securely spawn Node children. This
  avoids Node's `lstat '/memfd:… (deleted)'` failure;
  write, truncate, unlink, and retarget cannot alter the executed script bytes.
- **macOS:** ordinary user-controlled executables are copied from the verified
  handle into an atomically-created, owner-only private runtime directory. The
  create-new handle is retained, the copy is fsynced and re-hashed, the approved
  `argv[0]` is preserved, and custody remains live through `posix_spawn` before
  immediate cleanup. Darwin `SF_RESTRICTED` platform binaries use a narrower
  path: macOS 26 kills a byte-identical private copy even when its embedded code
  signature still verifies. For those images only, OwnMesh requires the open
  backing file to be root-owned, non-group/other-writable, and
  `SF_RESTRICTED`; requires every canonical ancestor to be root-owned,
  non-group/other-writable, non-symlink, and non-writable by the daemon after
  ACL evaluation; retains the invocation, backing, and opened ancestor handles;
  revalidates the pins; and launches the immutable verified backing path while
  keeping the approved invocation as `argv[0]`. A protected image whose custody
  cannot be proven fails before spawn. OwnMesh never rewrites or ad-hoc signs
  an approved executable.
- **Windows:** open the image, invocation entry, backing entry, and every
  ancestor without write/delete sharing; verify size, digest, volume serial,
  and file index from the held handles; then call `CreateProcess` with the
  exact invocation path while all locks remain held. Namespace replacement,
  junction retarget, in-place write, and delete are denied until image-open.
  For an approved `.cmd`/`.bat` invocation, the script path remains locked and
  the separately pinned absolute system `cmd.exe` is the held process image;
  existing fail-closed batch argv construction is preserved.

Raw-shell requests prepare `/bin/sh` or the absolute system `cmd.exe` in the
same way. Command text is still the separately approved action input.

### 3. Unsafe scope remains narrow and reviewed

`ownmesh-exec` is the fourth workspace crate allowed to contain `unsafe`.
The new use is one `CommandExt::pre_exec` closure whose only child-side action
is the safe `nix::unistd::fexecve` wrapper over preallocated C strings. The
existing Windows code-page FFI remains unchanged. No allocation, logging,
path lookup, or policy work occurs after fork in that closure.

## Consequences

- Proxy dispatch semantics remain compatible when the proxy is unchanged.
- A backing digest is evidence, not substitute execution authority.
- Preparation may copy up to the existing executable pin size limit. Linux
  uses sealed anonymous memory for native, interpreter, and script images;
  Node receives only a bounded loader plus the sealed descriptor. macOS
  briefly uses an owner-only private
  snapshot for ordinary images and immutable path custody for restricted
  platform images; Windows retains several read-only handles until spawn.
- macOS binaries that depend on their physical executable directory for
  adjacent resources may fail rather than run under changed semantics when
  they use snapshot custody. Restricted Apple platform binaries retain their
  protected physical backing path. Such a failure is preferable to reopening
  an attacker-writable path and is covered by the platform release matrix.
- Timeout, cancellation, output bounds, process-tree handling, and idempotency
  remain in the shared post-spawn runner.

## Alternatives considered

- **Launch the canonical backing when a proxy changes.** Rejected because it
  changes `argv[0]` and can select a different multicall branch than approved.
- **Hash immediately before ordinary path spawn.** Rejected because a second
  path open retains a verify-to-exec race.
- **Hold only a Linux read descriptor.** Rejected because another writer can
  mutate the same inode in place after verification.
- **Disable proxy executables.** Rejected because rustup and other supported
  toolchains legitimately dispatch by invocation name; their exact semantics
  can be preserved without weakening authorization.
