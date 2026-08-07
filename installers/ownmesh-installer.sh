#!/bin/sh
# OwnMesh portable installer (macOS / Linux).
#
# Trust model (fail-closed):
#   1. Obtain SHA256SUMS.minisig and verify it with minisign against the pinned
#      OwnMesh public key (never trust checksums before the signature verifies).
#   2. Verify the archive digest from the now-trusted SHA256SUMS.
#   3. Extract only required top-level binaries (never pipe remote script into a shell).
#
# Installer integrity: download this script, inspect it, then execute it from a
# local path. Prefer verifying the script against the release SHA256SUMS after
# signature verification. Never pipe remote script text into a shell.
#
# Minisign: provide `minisign` on PATH, or set OWNMESH_MINISIGN to a binary.
# Optional bootstrap: set OWNMESH_BOOTSTRAP_MINISIGN=1 to fetch a pinned minisign
# release binary (hash-verified) when none is available.

set -eu

REPOSITORY="Aero123421/OwnMesh"
DEFAULT_INSTALL_DIR="${HOME:?HOME is required}/.local/bin"
REQUESTED_VERSION="${OWNMESH_VERSION:-latest}"
INSTALL_DIR="${OWNMESH_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
ASSET_DIR="${OWNMESH_ASSET_DIR:-}"
BASE_URL_OVERRIDE="${OWNMESH_BASE_URL:-}"
MINISIGN_BIN="${OWNMESH_MINISIGN:-}"
BOOTSTRAP_MINISIGN="${OWNMESH_BOOTSTRAP_MINISIGN:-0}"

REQUIRED_BINARIES="ownmesh ownmesh-tui ownmeshd ownmesh-session-host ownmesh-broker"

# Pinned OwnMesh minisign trust root (docs/release-keys/minisign.pub).
# Key ID: C596813EFB0946A4
PINNED_MINISIGN_PUB_COMMENT="untrusted comment: minisign public key C596813EFB0946A4"
PINNED_MINISIGN_PUB_KEY="RWSkRgn7PoGWxQVPfPTcZzF3P8Wi5JMb+EOydWtYYosHDIEsLUnGl8eI"

# Pinned jedisct1/minisign 0.11 linux bootstrap (optional; independent of OwnMesh key).
# Only used when OWNMESH_BOOTSTRAP_MINISIGN=1 and no local minisign is available.
PINNED_MINISIGN_VERSION="0.11"
PINNED_MINISIGN_LINUX_X64_URL="https://github.com/jedisct1/minisign/releases/download/0.11/minisign-0.11-linux.tar.gz"
PINNED_MINISIGN_LINUX_X64_SHA256="0c2c0d6e8c5e0d7d3f0e5c5b1f5e6c2c0d6e8c5e0d7d3f0e5c5b1f5e6c2c0d6e"

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
    *'$('*|*'`'*|*'|'*|*';'*|*'>'*|*'<'*|*&&*|*||*|*$'\n'*|*$'\r'*)
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
    1|true|TRUE|yes|YES)
      bootstrap_minisign
      return
      ;;
  esac
  fail "minisign is required to verify SHA256SUMS.minisig (install minisign, set OWNMESH_MINISIGN, or OWNMESH_BOOTSTRAP_MINISIGN=1)"
}

bootstrap_minisign() {
  # Optional pinned bootstrap — never a silent skip. Hash must match exactly.
  os="$(uname -s 2>/dev/null || true)"
  arch="$(uname -m 2>/dev/null || true)"
  case "$os:$arch" in
    Linux:x86_64|Linux:amd64)
      url="$PINNED_MINISIGN_LINUX_X64_URL"
      expect="$PINNED_MINISIGN_LINUX_X64_SHA256"
      ;;
    *)
      fail "OWNMESH_BOOTSTRAP_MINISIGN is not supported on $os/$arch; install minisign manually"
      ;;
  esac
  # Placeholder pin refuses bootstrap until operators set a real digest (fail-closed).
  case "$expect" in
    0c2c0d6e8c5e0d7d3f0e5c5b1f5e6c2c0d6e8c5e0d7d3f0e5c5b1f5e6c2c0d6e)
      fail "OWNMESH_BOOTSTRAP_MINISIGN pin is not enrolled for this build; install minisign or set OWNMESH_MINISIGN"
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
  found="$(find "$boot_dir" -type f -name minisign | head -n 1)"
  [ -n "$found" ] || fail "minisign binary missing from bootstrap archive"
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

# Extract only required top-level binaries; refuse path traversal.
safe_extract() {
  archive="$1"
  dest="$2"
  list_file="$TMP_DIR/tar-list.txt"
  tar -tzf "$archive" >"$list_file" || fail "unable to list archive"

  # Fail closed on any traversal-like member names.
  while IFS= read -r member; do
    [ -n "$member" ] || continue
    case "$member" in
      *..*|/*|\\*|*\\*) fail "archive refuses member '$member' (traversal)" ;;
    esac
  done <"$list_file"

  mkdir -p "$dest"
  for bin in $REQUIRED_BINARIES; do
    member="$(
      awk -v b="$bin" '
        $0 == b { print; exit }
        {
          n=split($0, a, "/")
          if (n == 2 && a[2] == b && a[1] != ".." && a[1] != "" && a[1] != ".") { print; exit }
        }
      ' "$list_file"
    )"
    [ -n "$member" ] || fail "archive missing required binary $bin"
    case "$member" in
      *..*|/*) fail "archive refuses member '$member'" ;;
    esac
    tar -xzf "$archive" -C "$dest" "$member" || fail "extract failed for $member"
    if [ ! -f "$dest/$bin" ]; then
      # Flatten single directory prefix.
      if [ -f "$dest/$member" ]; then
        mv "$dest/$member" "$dest/$bin"
        # Best-effort cleanup of empty prefix dir.
        prefix="${member%/*}"
        if [ "$prefix" != "$member" ] && [ -d "$dest/$prefix" ]; then
          rmdir "$dest/$prefix" 2>/dev/null || true
        fi
      else
        fail "extracted $bin not found"
      fi
    fi
    chmod 0755 "$dest/$bin"
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
cleanup() {
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

# Backup existing binaries, then atomic replace per binary.
mkdir -p "$INSTALL_DIR"
BACKUP_DIR="$INSTALL_DIR/.ownmesh-backup.$$"
mkdir -p "$BACKUP_DIR"
for bin in $REQUIRED_BINARIES; do
  if [ -f "$INSTALL_DIR/$bin" ]; then
    cp "$INSTALL_DIR/$bin" "$BACKUP_DIR/$bin" || fail "backup $bin failed"
  fi
done

for bin in $REQUIRED_BINARIES; do
  [ -f "$EXTRACT_DIR/$bin" ] || fail "partial extract: missing $bin"
  staged="$INSTALL_DIR/.${bin}.new.$$"
  cp "$EXTRACT_DIR/$bin" "$staged"
  chmod 0755 "$staged"
  mv -f "$staged" "$INSTALL_DIR/$bin" || {
    say "atomic install failed; restoring backup"
    for b in $REQUIRED_BINARIES; do
      if [ -f "$BACKUP_DIR/$b" ]; then
        mv -f "$BACKUP_DIR/$b" "$INSTALL_DIR/$b" || true
      fi
    done
    fail "failed to install $bin"
  }
done
rm -rf "$BACKUP_DIR"

maybe_add_to_path

INSTALLED_VERSION="$("$INSTALL_DIR/ownmesh" --version 2>/dev/null)" ||
  fail "installed binary did not start (--version smoke failed)"
say "Installed $INSTALLED_VERSION to $INSTALL_DIR/ownmesh"
for bin in $REQUIRED_BINARIES; do
  say "  - $INSTALL_DIR/$bin"
done
