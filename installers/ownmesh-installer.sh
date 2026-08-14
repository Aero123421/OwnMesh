#!/bin/sh
# OwnMesh portable installer (macOS / Linux).
#
# Trust model (fail-closed):
#   1. Obtain SHA256SUMS.minisig and verify it with minisign against the pinned
#      OwnMesh public key (never trust checksums before the signature verifies).
#   2. Verify the archive digest from the now-trusted SHA256SUMS.
#   3. Extract only required top-level binaries.
#
# A curl|sh convenience bootstrap trusts GitHub TLS for this small script; the
# downloaded binaries still require the independent pinned minisign signature.
# The documented high-assurance flow additionally verifies this script first.
# Never pipe remote script in high-assurance or offline-verifiable deployments.
#
# Minisign is resolved automatically: a pinned, hash-verified binary on Linux,
# or Homebrew's package on macOS. Set OWNMESH_MINISIGN for an explicit path.

set -eu

# POSIX sh has no $'...' quoting. Keep literal line-break sentinels in variables
# so validation behaves the same under dash, BusyBox sh, and macOS /bin/sh.
LINE_FEED="$(printf '\n_')"
LINE_FEED="${LINE_FEED%_}"
CARRIAGE_RETURN="$(printf '\r_')"
CARRIAGE_RETURN="${CARRIAGE_RETURN%_}"

REPOSITORY="Aero123421/OwnMesh"
DEFAULT_INSTALL_DIR="${HOME:?HOME is required}/.local/bin"
REQUESTED_VERSION="${OWNMESH_VERSION:-latest}"
INSTALL_DIR="${OWNMESH_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
ASSET_DIR="${OWNMESH_ASSET_DIR:-}"
BASE_URL_OVERRIDE="${OWNMESH_BASE_URL:-}"
MINISIGN_BIN="${OWNMESH_MINISIGN:-}"
BOOTSTRAP_MINISIGN="${OWNMESH_BOOTSTRAP_MINISIGN:-auto}"
PATH_PROFILE_UPDATED=0
PATH_PROFILE=""
SERVICE_WAS_RUNNING=0

REQUIRED_BINARIES="ownmesh ownmesh-tui ownmeshd ownmesh-session-host ownmesh-broker"

# Pinned OwnMesh minisign trust root (docs/release-keys/minisign.pub).
# Key ID: C596813EFB0946A4
PINNED_MINISIGN_PUB_COMMENT="untrusted comment: minisign public key C596813EFB0946A4"
PINNED_MINISIGN_PUB_KEY="RWSkRgn7PoGWxQVPfPTcZzF3P8Wi5JMb+EOydWtYYosHDIEsLUnGl8eI"

# Pinned jedisct1/minisign 0.11 linux bootstrap (optional; independent of OwnMesh key).
# Only used when OWNMESH_BOOTSTRAP_MINISIGN=1 and no local minisign is available.
PINNED_MINISIGN_VERSION="0.11"
PINNED_MINISIGN_LINUX_X64_URL="https://github.com/jedisct1/minisign/releases/download/0.11/minisign-0.11-linux.tar.gz"
PINNED_MINISIGN_LINUX_X64_SHA256="f0a0954413df8531befed169e447a66da6868d79052ed7e892e50a4291af7ae0"

say() {
  printf '%s\n' "$*"
}

fail() {
  printf 'ownmesh installer: %s\n' "$*" >&2
  exit 1
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Reject env values that look like shell/URL injection.
reject_injection() {
  label="$1"
  value="$2"
  case "$value" in
    *'$('*|*'`'*|*'|'*|*';'*|*'>'*|*'<'*|*'&'*|*"$LINE_FEED"*|*"$CARRIAGE_RETURN"*)
      fail "refusing $label with shell metacharacters"
      ;;
  esac
}

reject_injection OWNMESH_VERSION "$REQUESTED_VERSION"
reject_injection OWNMESH_INSTALL_DIR "$INSTALL_DIR"
if [ -n "$ASSET_DIR" ]; then
  reject_injection OWNMESH_ASSET_DIR "$ASSET_DIR"
fi
if [ -n "$BASE_URL_OVERRIDE" ]; then
  reject_injection OWNMESH_BASE_URL "$BASE_URL_OVERRIDE"
  case "$BASE_URL_OVERRIDE" in
    https://github.com/*|https://objects.githubusercontent.com/*|https://release-assets.githubusercontent.com/*) ;;
    *) fail "OWNMESH_BASE_URL host is not on the GitHub release allow-list" ;;
  esac
  case "$BASE_URL_OVERRIDE" in
    *'@'*|*..*) fail "OWNMESH_BASE_URL refused (userinfo or ..)" ;;
  esac
fi

normalize_version() {
  case "$REQUESTED_VERSION" in
    latest)
      printf '%s\n' "latest"
      ;;
    *)
      if ! printf '%s\n' "$REQUESTED_VERSION" |
        grep -Eq '^v?[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$'; then
        fail "invalid OWNMESH_VERSION '$REQUESTED_VERSION' (expected latest, 1.2.3, or v1.2.3)"
      fi
      case "$REQUESTED_VERSION" in
        v*) printf '%s\n' "$REQUESTED_VERSION" ;;
        *) printf 'v%s\n' "$REQUESTED_VERSION" ;;
      esac
      ;;
  esac
}

select_asset() {
  os="$(uname -s 2>/dev/null || true)"
  arch="$(uname -m 2>/dev/null || true)"

  case "$arch" in
    x86_64 | amd64) suffix="x64" ;;
    arm64 | aarch64) suffix="arm64" ;;
    *) fail "unsupported CPU architecture '$arch'" ;;
  esac

  case "$os" in
    Linux) printf 'ownmesh-linux-%s.tar.gz\n' "$suffix" ;;
    Darwin) printf 'ownmesh-macos-%s.tar.gz\n' "$suffix" ;;
    *) fail "unsupported operating system '$os'; use ownmesh-installer.ps1 on Windows" ;;
  esac
}

assert_safe_url() {
  url="$1"
  case "$url" in
    https://github.com/*|https://objects.githubusercontent.com/*|https://release-assets.githubusercontent.com/*|https://github-releases.githubusercontent.com/*) ;;
    *) fail "refusing non-allow-listed URL" ;;
  esac
  case "$url" in
    *'@'*|*..*) fail "refusing URL with userinfo or .." ;;
  esac
}

fetch_asset() {
  name="$1"
  destination="$2"

  case "$name" in
    *'/'*|*'\\'*|*..*) fail "refusing unsafe asset name '$name'" ;;
  esac

  if [ -n "$ASSET_DIR" ]; then
    [ -d "$ASSET_DIR" ] || fail "OWNMESH_ASSET_DIR is not a directory: $ASSET_DIR"
    [ -f "$ASSET_DIR/$name" ] || fail "asset not found in OWNMESH_ASSET_DIR: $name"
    cp "$ASSET_DIR/$name" "$destination"
    return
  fi

  url="$BASE_URL/$name"
  assert_safe_url "$url"
  if command_exists curl; then
    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
      --retry 3 --max-redirs 5 --output "$destination" "$url" ||
      fail "download failed for $name (HTTP error or 404)"
  elif command_exists wget; then
    wget --https-only --quiet --tries=3 --max-redirect=5 --output-document="$destination" "$url" ||
      fail "download failed for $name (HTTP error or 404)"
  else
    fail "curl or wget is required"
  fi
}

sha256_file() {
  file="$1"
  if command_exists sha256sum; then
    sha256sum "$file" | awk '{print $1}'
  elif command_exists shasum; then
    shasum -a 256 "$file" | awk '{print $1}'
  elif command_exists openssl; then
    openssl dgst -sha256 "$file" | sed 's/^.*= //'
  else
    fail "sha256sum, shasum, or openssl is required to verify the download"
  fi
}

lookup_checksum() {
  sums_file="$1"
  asset_name="$2"
  # Accept "DIGEST  name" or "DIGEST *name"
  awk -v want="$asset_name" '
    $1 ~ /^[0-9a-fA-F]{64}$/ {
      name=$2
      sub(/^\*/,"",name)
      if (name == want) { print tolower($1); exit }
    }
  ' "$sums_file"
}

write_pinned_pubkey() {
  dest="$1"
  {
    printf '%s\n' "$PINNED_MINISIGN_PUB_COMMENT"
    printf '%s\n' "$PINNED_MINISIGN_PUB_KEY"
  } >"$dest"
}

resolve_minisign() {
  if [ -n "$MINISIGN_BIN" ]; then
    [ -x "$MINISIGN_BIN" ] || fail "OWNMESH_MINISIGN is not executable: $MINISIGN_BIN"
    printf '%s\n' "$MINISIGN_BIN"
    return
  fi
  if command_exists minisign; then
    command -v minisign
    return
  fi
  case "$BOOTSTRAP_MINISIGN" in
    auto)
      case "$(uname -s 2>/dev/null || true):$(uname -m 2>/dev/null || true)" in
        Linux:x86_64|Linux:amd64|Linux:aarch64|Linux:arm64) bootstrap_minisign; return ;;
        Darwin:*)
          command_exists brew || fail "Homebrew is required for the one-line macOS install (https://brew.sh)"
          printf '%s\n' "ownmesh installer: installing minisign with Homebrew" >&2
          brew install minisign >&2 || fail "Homebrew could not install minisign"
          command_exists minisign || fail "Homebrew completed but minisign is unavailable"
          command -v minisign
          return
          ;;
      esac
      ;;
    1|true|TRUE|yes|YES)
      bootstrap_minisign
      return
      ;;
  esac
  fail "minisign is required to verify SHA256SUMS.minisig (macOS: brew install minisign; Linux arm64: install the minisign package)"
}

bootstrap_minisign() {
  # Optional pinned bootstrap — never a silent skip. Hash must match exactly.
  os="$(uname -s 2>/dev/null || true)"
  arch="$(uname -m 2>/dev/null || true)"
  case "$os:$arch" in
    Linux:x86_64|Linux:amd64)
      url="$PINNED_MINISIGN_LINUX_X64_URL"
      expect="$PINNED_MINISIGN_LINUX_X64_SHA256"
      bootstrap_relpath="minisign-linux/x86_64/minisign"
      ;;
    Linux:aarch64|Linux:arm64)
      url="$PINNED_MINISIGN_LINUX_X64_URL"
      expect="$PINNED_MINISIGN_LINUX_X64_SHA256"
      bootstrap_relpath="minisign-linux/aarch64/minisign"
      ;;
    *)
      fail "OWNMESH_BOOTSTRAP_MINISIGN is not supported on $os/$arch; install minisign manually"
      ;;
  esac
  boot_dir="$TMP_DIR/minisign-boot"
  mkdir -p "$boot_dir"
  archive="$boot_dir/minisign.tgz"
  assert_safe_url "$url"
  if command_exists curl; then
    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
      --retry 3 --max-redirs 5 --output "$archive" "$url" ||
      fail "failed to download pinned minisign bootstrap"
  else
    fail "curl is required to bootstrap minisign"
  fi
  actual="$(sha256_file "$archive" | tr 'A-F' 'a-f')"
  [ "$actual" = "$expect" ] || fail "pinned minisign bootstrap SHA-256 mismatch"
  tar -xzf "$archive" -C "$boot_dir" || fail "extract minisign bootstrap failed"
  found="$boot_dir/$bootstrap_relpath"
  [ -f "$found" ] || fail "minisign binary missing from bootstrap archive"
  chmod 0755 "$found"
  printf '%s\n' "$found"
}

require_verify_minisign() {
  sums_file="$1"
  sig_file="$2"
  pubkey_file="$3"
  minisign_cmd="$4"
  [ -f "$sig_file" ] || fail "SHA256SUMS.minisig missing (signature required; refusing unsigned checksums)"
  [ -f "$pubkey_file" ] || fail "minisign public key missing"
  # Default trust root is the pinned OwnMesh key. OWNMESH_MINISIGN_PUB may point at an
  # alternate file only when the operator explicitly opts in (offline/test). Signature
  # verification is never skipped.
  if [ -z "${OWNMESH_MINISIGN_PUB:-}" ]; then
    if ! grep -Fq "$PINNED_MINISIGN_PUB_KEY" "$pubkey_file"; then
      fail "minisign public key does not match the pinned OwnMesh trust root"
    fi
  fi
  "$minisign_cmd" -Vm "$sums_file" -p "$pubkey_file" -x "$sig_file" >/dev/null ||
    fail "minisign verification failed for SHA256SUMS"
  say "minisign: SHA256SUMS signature ok"
}

# Archive contract (identical security intent to ownmesh-update):
# - max entry count / per-entry / total uncompressed sizes
# - exact allow-list: five required binaries + declared docs only
# - reject duplicates, symlinks/hardlinks/devices, traversal, unexpected members
# - never full-extract (`tar -xzf archive` without member list)
# - member-by-member streaming into a private staging dir
MAX_ARCHIVE_ENTRIES=64
MAX_ENTRY_UNCOMPRESSED_BYTES=268435456
MAX_TOTAL_UNCOMPRESSED_BYTES=536870912
ALLOWED_DOC_FILES="LICENSE NOTICE README.md RELEASE_NOTES.md CHANGELOG.md"

is_allowed_member_base() {
  base="$1"
  for bin in $REQUIRED_BINARIES; do
    [ "$base" = "$bin" ] && return 0
  done
  for doc in $ALLOWED_DOC_FILES; do
    [ "$base" = "$doc" ] && return 0
  done
  return 1
}

# Normalize archive member path to a single base name; empty => reject.
safe_member_base() {
  member="$1"
  case "$member" in
    ''|*..*|/*|\\*|*\\*|*"$LINE_FEED"*|*"$CARRIAGE_RETURN"*) return 1 ;;
  esac
  # Strip a single optional directory prefix (release wrapper dir).
  case "$member" in
    */*/*) return 1 ;;
    */*)
      prefix="${member%%/*}"
      base="${member#*/}"
      case "$prefix" in ''|'.'|'..') return 1 ;; esac
      case "$base" in ''|*/*|*\\*|*..*) return 1 ;; esac
      printf '%s\n' "$base"
      ;;
    *)
      printf '%s\n' "$member"
      ;;
  esac
}

# Validate the full tar.gz contract, then stream allowed members one-by-one.
# Uses `tar -tvzf` listing (GNU/BSD). Fails closed when the listing cannot be parsed
# safely or when any contract check fails — never falls back to full extraction.
safe_extract() {
  archive="$1"
  dest="$2"
  list_file="$TMP_DIR/tar-tv.txt"
  names_file="$TMP_DIR/tar-names.txt"
  seen_file="$TMP_DIR/tar-seen.txt"
  : >"$seen_file"

  # Verbose listing carries type + size; plain -tzf is insufficient for bomb/type checks.
  if ! tar -tvzf "$archive" >"$list_file" 2>/dev/null; then
    fail "unable to list archive with tar -tvzf (safe extractor unavailable; refusing)"
  fi
  tar -tzf "$archive" >"$names_file" || fail "unable to list archive member names"

  entry_count=0
  total_uncompressed=0
  # shellcheck disable=SC2162
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    entry_count=$((entry_count + 1))
    if [ "$entry_count" -gt "$MAX_ARCHIVE_ENTRIES" ]; then
      fail "archive entry count exceeds limit $MAX_ARCHIVE_ENTRIES"
    fi

    # First field is the mode string on both GNU and BSD tar -tv output.
    mode="${line%% *}"
    case "$mode" in
      d*) continue ;; # directory headers are ignored (no payload retained)
      l*|h*) fail "refusing symlink/hardlink archive member" ;;
      c*|b*|p*|s*) fail "refusing special archive member type ($mode)" ;;
      -*) ;; # regular file
      *) fail "refusing unknown archive member type ($mode)" ;;
    esac

    # Member name is the final field; BSD links append " -> target" which we reject above.
    name="${line##* }"
    case "$name" in
      *'->'*) fail "refusing link-style archive member '$name'" ;;
    esac

    base="$(safe_member_base "$name")" || fail "archive refuses member '$name' (traversal/nested)"
    if ! is_allowed_member_base "$base"; then
      fail "refusing unexpected archive member $base"
    fi
    if grep -Fxq "$base" "$seen_file"; then
      fail "refusing duplicate archive member $base"
    fi
    printf '%s\n' "$base" >>"$seen_file"

    # Size from tar -tv listing:
    # GNU: permissions owner/group size date time name
    # BSD: permissions links owner group size mon day time name
    # Never scan "last integer" (BSD day-of-month would win over size).
    size="$(printf '%s\n' "$line" | awk '
      {
        if ($2 ~ /\//) { size = $3 } else { size = $5 }
        if (size !~ /^[0-9]+$/ || length(size) > 12) { exit 2 }
        print size
      }
    ')" || fail "unable to parse size for archive member $base (safe extractor unavailable)"
    case "$size" in
      ''|*[!0-9]*) fail "invalid size for archive member $base" ;;
    esac
    if [ "$size" -gt "$MAX_ENTRY_UNCOMPRESSED_BYTES" ]; then
      fail "archive member $base exceeds per-entry limit $MAX_ENTRY_UNCOMPRESSED_BYTES"
    fi
    total_uncompressed=$((total_uncompressed + size))
    if [ "$total_uncompressed" -gt "$MAX_TOTAL_UNCOMPRESSED_BYTES" ]; then
      fail "archive total uncompressed size exceeds limit $MAX_TOTAL_UNCOMPRESSED_BYTES"
    fi
  done <"$list_file"

  # Require all five binaries (docs optional).
  for bin in $REQUIRED_BINARIES; do
    grep -Fxq "$bin" "$seen_file" || fail "archive missing required binary $bin"
  done

  mkdir -p "$dest"
  # Map base name -> exact member path for extraction.
  for bin in $REQUIRED_BINARIES; do
    member="$(
      awk -v b="$bin" '
        $0 == b { print; exit }
        {
          n = split($0, a, "/")
          if (n == 2 && a[2] == b && a[1] != ".." && a[1] != "" && a[1] != ".") { print; exit }
        }
      ' "$names_file"
    )"
    [ -n "$member" ] || fail "archive missing required binary $bin"
    base="$(safe_member_base "$member")" || fail "archive refuses member '$member'"
    [ "$base" = "$bin" ] || fail "archive member mapping mismatch for $bin"

    # Stream a single member to a private regular file (no full-archive extract).
    out="$dest/$bin"
    # tar -xOf writes member bytes to stdout; reject if the tool cannot isolate the member.
    if ! tar -xOf "$archive" "$member" >"$out" 2>/dev/null; then
      # Some tar builds need -z explicitly for gzip when using -O.
      tar -xOzf "$archive" "$member" >"$out" || fail "extract failed for $member"
    fi
    [ -f "$out" ] || fail "extracted $bin is not a regular file"
    if [ -L "$out" ]; then
      fail "extracted $bin resolved to a symlink; refusing"
    fi
    actual_size="$(wc -c <"$out" | tr -d ' ')"
    case "$actual_size" in
      ''|*[!0-9]*) fail "unable to measure extracted size for $bin" ;;
    esac
    if [ "$actual_size" -le 0 ]; then
      fail "archive member $bin is empty"
    fi
    if [ "$actual_size" -gt "$MAX_ENTRY_UNCOMPRESSED_BYTES" ]; then
      fail "extracted $bin exceeds per-entry limit $MAX_ENTRY_UNCOMPRESSED_BYTES"
    fi
    chmod 0755 "$out"
  done

  # Optional docs: extract when present (still allow-listed and size-checked above).
  for doc in $ALLOWED_DOC_FILES; do
    grep -Fxq "$doc" "$seen_file" || continue
    member="$(
      awk -v b="$doc" '
        $0 == b { print; exit }
        {
          n = split($0, a, "/")
          if (n == 2 && a[2] == b && a[1] != ".." && a[1] != "" && a[1] != ".") { print; exit }
        }
      ' "$names_file"
    )"
    [ -n "$member" ] || continue
    out="$dest/$doc"
    if ! tar -xOf "$archive" "$member" >"$out" 2>/dev/null; then
      tar -xOzf "$archive" "$member" >"$out" || fail "extract failed for $member"
    fi
    if [ -L "$out" ]; then
      fail "extracted $doc resolved to a symlink; refusing"
    fi
  done
}

maybe_add_to_path() {
  case ":${PATH:-}:" in
    *":$INSTALL_DIR:"*) return ;;
  esac

  export PATH="$INSTALL_DIR:${PATH:-}"

  case "${OWNMESH_NO_MODIFY_PATH:-}" in
    1 | true | TRUE | yes | YES)
      say "Installed directory is not persisted on PATH because OWNMESH_NO_MODIFY_PATH is set."
      return
      ;;
  esac

  if [ "$INSTALL_DIR" != "$DEFAULT_INSTALL_DIR" ]; then
    # Quote-safe guidance for unusual install dirs.
    say "Add this directory to PATH for future shells: \"$INSTALL_DIR\""
    return
  fi

  shell_name="$(basename "${SHELL:-sh}")"
  case "$shell_name" in
    zsh) profile="$HOME/.zshrc" ;;
    bash) profile="$HOME/.bashrc" ;;
    fish)
      if command_exists fish; then
        # shellcheck disable=SC2016
        fish -c 'fish_add_path --path "$HOME/.local/bin"'
        say "Added $DEFAULT_INSTALL_DIR to the fish user PATH."
      else
        say "Add this directory to PATH for future shells: \"$DEFAULT_INSTALL_DIR\""
      fi
      return
      ;;
    *) profile="$HOME/.profile" ;;
  esac

  # shellcheck disable=SC2016
  path_line='export PATH="$HOME/.local/bin:$PATH"'
  if [ ! -f "$profile" ] || ! grep -Fqx "$path_line" "$profile"; then
    {
      printf '\n# Added by the ownmesh installer\n'
      printf '%s\n' "$path_line"
    } >>"$profile"
    PATH_PROFILE_UPDATED=1
    PATH_PROFILE="$profile"
    say "Added $DEFAULT_INSTALL_DIR to PATH in $profile."
  fi
}

VERSION="$(normalize_version)"
ASSET="$(select_asset)"

if [ -n "$BASE_URL_OVERRIDE" ]; then
  BASE_URL="${BASE_URL_OVERRIDE%/}"
elif [ "$VERSION" = "latest" ]; then
  BASE_URL="https://github.com/$REPOSITORY/releases/latest/download"
else
  BASE_URL="https://github.com/$REPOSITORY/releases/download/$VERSION"
fi
assert_safe_url "$BASE_URL/SHA256SUMS"

command_exists tar || fail "tar is required"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ownmesh-install.XXXXXX")"
BACKUP_DIR=""
STAGED_FILE=""
KEEP_BACKUP=0
cleanup() {
  if [ -n "$STAGED_FILE" ]; then
    rm -f "$STAGED_FILE"
  fi
  if [ "$KEEP_BACKUP" -ne 1 ] && [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
    rm -rf "$BACKUP_DIR"
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ARCHIVE="$TMP_DIR/$ASSET"
SUMS="$TMP_DIR/SHA256SUMS"
SIG="$TMP_DIR/SHA256SUMS.minisig"
EXTRACT_DIR="$TMP_DIR/extract"
PUBKEY="$TMP_DIR/minisign.pub"

# Resolve minisign before trusting any checksum file.
MINISIGN_CMD="$(resolve_minisign)"

say "Downloading $ASSET..."
fetch_asset "$ASSET" "$ARCHIVE"
fetch_asset "SHA256SUMS" "$SUMS"

# Signature is mandatory — never trust SHA256SUMS without minisig verification.
if [ -n "$ASSET_DIR" ] && [ -f "$ASSET_DIR/SHA256SUMS.minisig" ]; then
  cp "$ASSET_DIR/SHA256SUMS.minisig" "$SIG"
else
  fetch_asset "SHA256SUMS.minisig" "$SIG"
fi

# Public key: explicit override, asset dir, repo-tracked key, or embedded pin.
if [ -n "${OWNMESH_MINISIGN_PUB:-}" ]; then
  [ -f "$OWNMESH_MINISIGN_PUB" ] || fail "OWNMESH_MINISIGN_PUB is not a file"
  cp "$OWNMESH_MINISIGN_PUB" "$PUBKEY"
elif [ -n "$ASSET_DIR" ] && [ -f "$ASSET_DIR/minisign.pub" ]; then
  cp "$ASSET_DIR/minisign.pub" "$PUBKEY"
elif [ -f "$(dirname "$0")/../docs/release-keys/minisign.pub" ]; then
  cp "$(dirname "$0")/../docs/release-keys/minisign.pub" "$PUBKEY"
elif [ -f "$(dirname "$0")/minisign.pub" ]; then
  cp "$(dirname "$0")/minisign.pub" "$PUBKEY"
else
  write_pinned_pubkey "$PUBKEY"
fi

require_verify_minisign "$SUMS" "$SIG" "$PUBKEY" "$MINISIGN_CMD"

EXPECTED="$(lookup_checksum "$SUMS" "$ASSET")"
if ! printf '%s\n' "$EXPECTED" | grep -Eq '^[0-9a-f]{64}$'; then
  fail "SHA256SUMS missing entry for $ASSET"
fi
ACTUAL="$(sha256_file "$ARCHIVE" | tr 'A-F' 'a-f')"
[ "$ACTUAL" = "$EXPECTED" ] ||
  fail "SHA-256 mismatch for $ASSET (expected $EXPECTED, got $ACTUAL)"

safe_extract "$ARCHIVE" "$EXTRACT_DIR"

# Unix permits replacing a running executable, so the old daemon can otherwise
# survive the install and report the previous version indefinitely. Detect only
# the exact installed ownmeshd image; never select a process by name alone.
if [ -f "$INSTALL_DIR/ownmeshd" ]; then
  if [ -d /proc ]; then
    for exe in /proc/[0-9]*/exe; do
      resolved="$(readlink "$exe" 2>/dev/null || true)"
      if [ "$resolved" = "$INSTALL_DIR/ownmeshd" ]; then
        SERVICE_WAS_RUNNING=1
        break
      fi
    done
  elif command_exists pgrep; then
    for pid in $(pgrep -x ownmeshd 2>/dev/null || true); do
      command_line="$(ps -p "$pid" -o command= 2>/dev/null || true)"
      case "$command_line" in
        "$INSTALL_DIR/ownmeshd"|"$INSTALL_DIR/ownmeshd"\ *)
          SERVICE_WAS_RUNNING=1
          break
          ;;
      esac
    done
  fi
fi

# Backup existing binaries, then atomic replace per binary.
mkdir -p "$INSTALL_DIR"
BACKUP_DIR="$(mktemp -d "$INSTALL_DIR/.ownmesh-backup.XXXXXX")" ||
  fail "failed to create private backup directory"
for bin in $REQUIRED_BINARIES; do
  if [ -L "$INSTALL_DIR/$bin" ]; then
    fail "refusing existing symlink at $INSTALL_DIR/$bin"
  fi
  if [ -e "$INSTALL_DIR/$bin" ] && [ ! -f "$INSTALL_DIR/$bin" ]; then
    fail "refusing existing non-file at $INSTALL_DIR/$bin"
  fi
  if [ -f "$INSTALL_DIR/$bin" ]; then
    cp "$INSTALL_DIR/$bin" "$BACKUP_DIR/$bin" || fail "backup $bin failed"
  fi
done

INSTALLED_BINARIES=""
rollback_install() {
  restore_rc=0
  for b in $REQUIRED_BINARIES; do
    case " $INSTALLED_BINARIES " in
      *" $b "*) ;;
      *) continue ;;
    esac
    target="$INSTALL_DIR/$b"
    if [ -f "$BACKUP_DIR/$b" ]; then
      if [ -L "$target" ] || { [ -e "$target" ] && [ ! -f "$target" ]; }; then
        say "rollback refused unsafe target for $b" >&2
        restore_rc=1
      elif ! mv -f "$BACKUP_DIR/$b" "$target"; then
        say "rollback failed for $b" >&2
        restore_rc=1
      fi
    elif [ -e "$target" ] || [ -L "$target" ]; then
      if ! rm -f "$target"; then
        say "rollback failed to remove newly installed $b" >&2
        restore_rc=1
      fi
    fi
  done
  [ "$restore_rc" -eq 0 ]
}

for bin in $REQUIRED_BINARIES; do
  [ -f "$EXTRACT_DIR/$bin" ] || fail "partial extract: missing $bin"
  staged="$INSTALL_DIR/.${bin}.new.$$"
  STAGED_FILE="$staged"
  if ! cp "$EXTRACT_DIR/$bin" "$staged" || ! chmod 0755 "$staged"; then
    rm -f "$staged"
    STAGED_FILE=""
    if ! rollback_install; then
      KEEP_BACKUP=1
      fail "failed to stage $bin; backup rollback also failed (backup left at $BACKUP_DIR)"
    fi
    rm -rf "$BACKUP_DIR"
    fail "failed to stage $bin; previous binaries restored"
  fi
  move_ok=0
  if mv -f "$staged" "$INSTALL_DIR/$bin"; then
    move_ok=1
    STAGED_FILE=""
    INSTALLED_BINARIES="$INSTALLED_BINARIES $bin"
  fi
  if [ "$move_ok" -ne 1 ] || [ ! -f "$INSTALL_DIR/$bin" ] || [ -L "$INSTALL_DIR/$bin" ]; then
    say "atomic install failed; restoring backup"
    rm -f "$staged"
    STAGED_FILE=""
    if ! rollback_install; then
      KEEP_BACKUP=1
      fail "failed to install $bin; backup rollback also failed (backup left at $BACKUP_DIR)"
    fi
    rm -rf "$BACKUP_DIR"
    fail "failed to install $bin; previous binaries restored"
  fi
done

maybe_add_to_path

if ! INSTALLED_VERSION="$("$INSTALL_DIR/ownmesh" --version 2>/dev/null)"; then
  if rollback_install; then
    "$INSTALL_DIR/ownmesh" service start >/dev/null 2>&1 || true
    rm -rf "$BACKUP_DIR"
    fail "installed binary did not start; previous binaries restored"
  fi
  KEEP_BACKUP=1
  fail "installed binary did not start and rollback failed (backup left at $BACKUP_DIR)"
fi
if [ "$SERVICE_WAS_RUNNING" -eq 1 ]; then
  if ! "$INSTALL_DIR/ownmesh" service restart >/dev/null 2>&1; then
    if rollback_install; then
      "$INSTALL_DIR/ownmesh" service start >/dev/null 2>&1 || true
      rm -rf "$BACKUP_DIR"
      fail "updated service did not restart; previous binaries restored"
    fi
    KEEP_BACKUP=1
    fail "updated service did not restart and rollback failed (backup left at $BACKUP_DIR)"
  fi
  expected_version="${INSTALLED_VERSION##* }"
  status_json="$("$INSTALL_DIR/ownmesh" --json status 2>/dev/null || true)"
  if ! printf '%s' "$status_json" | grep -Fq "\"version\":\"$expected_version\""; then
    "$INSTALL_DIR/ownmesh" service stop >/dev/null 2>&1 || true
    if rollback_install; then
      "$INSTALL_DIR/ownmesh" service start >/dev/null 2>&1 || true
      rm -rf "$BACKUP_DIR"
      fail "updated daemon health check failed; previous binaries restored"
    fi
    KEEP_BACKUP=1
    fail "updated daemon health check failed and rollback failed (backup left at $BACKUP_DIR)"
  fi
fi
rm -rf "$BACKUP_DIR"
say "Installed $INSTALLED_VERSION to $INSTALL_DIR/ownmesh"
for bin in $REQUIRED_BINARIES; do
  say "  - $INSTALL_DIR/$bin"
done

say ""
if [ "$PATH_PROFILE_UPDATED" = "1" ]; then
  say "Open a new shell (or 'source $PATH_PROFILE') so 'ownmesh' resolves."
fi
say "Next steps:"
say "  1. Deploy your own control plane, if you have not already:"
say "       git clone https://github.com/$REPOSITORY && cd OwnMesh/packages/control-plane"
say "       corepack enable && pnpm install --frozen-lockfile && pnpm run deploy:guided"
say "  2. Connect this machine to it:"
say "       ownmesh setup --control-plane-url <your-worker-url> --quickstart"
say "  3. Check the result without changing anything:"
say "       ownmesh doctor"
