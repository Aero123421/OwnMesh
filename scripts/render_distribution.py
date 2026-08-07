#!/usr/bin/env python3
"""Render Homebrew metadata from one release checksum set."""

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.-]+)?$")
PLACEHOLDER_RE = re.compile(r"\{\{[A-Z0-9_]+\}\}")

CHECKSUM_ASSETS = {
    "MACOS_ARM64_SHA256": "ownmesh-macos-arm64.tar.gz",
    "MACOS_X64_SHA256": "ownmesh-macos-x64.tar.gz",
    "LINUX_ARM64_SHA256": "ownmesh-linux-arm64.tar.gz",
    "LINUX_X64_SHA256": "ownmesh-linux-x64.tar.gz",
}


def read_checksum(directory: Path, asset: str) -> str:
    sidecar = directory / f"{asset}.sha256"
    try:
        fields = sidecar.read_text(encoding="ascii").split()
    except FileNotFoundError as error:
        raise SystemExit(f"missing checksum file: {sidecar}") from error

    if len(fields) < 2 or fields[1].lstrip("*") != asset:
        raise SystemExit(f"{sidecar} must contain '<sha256>  {asset}'")
    checksum = fields[0]
    if not SHA256_RE.fullmatch(checksum):
        raise SystemExit(f"invalid SHA-256 in {sidecar}: {checksum!r}")
    return checksum.lower()


def render(template: Path, destination: Path, values: dict[str, str]) -> None:
    content = template.read_text(encoding="utf-8")
    for key, value in values.items():
        content = content.replace(f"{{{{{key}}}}}", value)
    unresolved = sorted(set(PLACEHOLDER_RE.findall(content)))
    if unresolved:
        raise SystemExit(
            f"unresolved placeholders in {template}: {', '.join(unresolved)}"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8", newline="\n")
    print(destination)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Render Homebrew metadata for an OwnMesh release."
    )
    parser.add_argument("--version", required=True, help="release version without v")
    parser.add_argument(
        "--checksums-dir",
        required=True,
        type=Path,
        help="directory containing release asset .sha256 files",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="directory to receive the homebrew/ tree",
    )
    parser.add_argument(
        "--release-assets-dir",
        type=Path,
        help="also stage ownmesh.rb for GitHub Releases",
    )
    args = parser.parse_args()

    if not VERSION_RE.fullmatch(args.version):
        raise SystemExit(f"invalid release version: {args.version!r}")

    values = {"VERSION": args.version}
    values.update(
        {
            placeholder: read_checksum(args.checksums_dir, asset)
            for placeholder, asset in CHECKSUM_ASSETS.items()
        }
    )

    formula = args.output_dir / "homebrew/Formula/ownmesh.rb"
    render(
        ROOT / "packaging/homebrew/ownmesh.rb.template",
        formula,
        values,
    )

    if args.release_assets_dir:
        args.release_assets_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(formula, args.release_assets_dir / "ownmesh.rb")


if __name__ == "__main__":
    main()
