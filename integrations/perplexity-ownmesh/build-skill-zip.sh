#!/bin/sh
# Build a deterministic Perplexity Computer Skill ZIP from checked-in sources.
# The ZIP root contains SKILL.md (Perplexity requirement). No credentials,
# tokens, device IDs, or private paths are bundled: sources are placeholders
# only and the script refuses to package a tree that contains secret-shaped
# content.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${1:-"$SCRIPT_DIR/perplexity-ownmesh-skill.zip"}

if grep -rEq -- 'sk-[A-Za-z0-9]{8,}|ghp_[A-Za-z0-9]{8,}|BEGIN [A-Z ]*PRIVATE KEY' "$SCRIPT_DIR/SKILL.md" "$SCRIPT_DIR/examples"; then
  echo "refusing to package: secret-shaped content found in sources" >&2
  exit 1
fi

rm -f "$OUT"
# -X strips extra fields, -j keeps SKILL.md at the ZIP root, -9 max
# compression. Explicit file order keeps the build deterministic.
(cd "$SCRIPT_DIR" && zip -X -j -9 "$OUT" SKILL.md examples/connector-recipe.md)
echo "wrote $OUT"
