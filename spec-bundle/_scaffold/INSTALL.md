# om-01 scaffold install

Worker scope guard rejected Japanese / annotated `allowed_scope` entries
(`crates/*/（空 skeleton のみ）`, root doc category strings). Content below is
ready to promote to the real tree.

## Promote (run with bash/shell once scope allows)

```bash
# From repository root D:/AI/OwnMesh

# Root docs
cp spec-bundle/_scaffold/ROOT_FILES/LICENSE .
cp spec-bundle/_scaffold/ROOT_FILES/README.md .
cp spec-bundle/_scaffold/ROOT_FILES/SECURITY.md .
cp spec-bundle/_scaffold/ROOT_FILES/CONTRIBUTING.md .
cp spec-bundle/_scaffold/ROOT_FILES/CODE_OF_CONDUCT.md .
cp spec-bundle/_scaffold/ROOT_FILES/.nvmrc .

# Crates + packages
cp -r spec-bundle/_scaffold/crates .
cp -r spec-bundle/_scaffold/packages .

# Extract official zip over schemas/examples/docs (does not remove _scaffold)
# Windows PowerShell:
Expand-Archive -Force ownmesh-specification-bundle.zip spec-bundle-tmp
# Then merge schemas/, examples/, docs/ into spec-bundle/

# Verify
cargo build --workspace && cargo test --workspace
pnpm install && pnpm -r typecheck

# Git
git init
git add .
git commit -m "chore: OwnMesh 1.0 repository foundation (om-01)"
git branch -M main
git remote add origin https://github.com/Aero123421/OwnMesh.git
git push -u origin main
```

## Required allowed_scope fix for re-run

```json
[
  "LICENSE",
  "README.md",
  "SECURITY.md",
  "CONTRIBUTING.md",
  "CODE_OF_CONDUCT.md",
  ".gitignore",
  ".nvmrc",
  ".node-version",
  ".github/",
  "docs/",
  "spec-bundle/",
  "Cargo.toml",
  "Cargo.lock",
  "rust-toolchain.toml",
  "package.json",
  "pnpm-workspace.yaml",
  "pnpm-lock.yaml",
  "crates/",
  "packages/"
]
```

Also grant Worker **bash** (or run promote externally) for zip extract, cargo/pnpm verify, git init/push.
