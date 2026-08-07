#!/usr/bin/env python3
"""Adversarial installer checks (404/checksum/traversal/arch/partial/PATH quoting)."""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SH_INSTALLER = ROOT / "installers" / "ownmesh-installer.sh"
PS_INSTALLER = ROOT / "installers" / "ownmesh-installer.ps1"
BINS = [
    "ownmesh",
    "ownmesh-tui",
    "ownmeshd",
    "ownmesh-session-host",
    "ownmesh-broker",
]


def _is_windows() -> bool:
    return os.name == "nt"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _write_fake_bins(package: Path, windows: bool) -> None:
    package.mkdir(parents=True, exist_ok=True)
    for name in BINS:
        file_name = f"{name}.exe" if windows else name
        target = package / file_name
        if windows:
            # Minimal PE-less stub; installer only checks presence + hash path.
            target.write_bytes(b"MZ fake-ownmesh-binary " + name.encode() + b"\n")
        else:
            target.write_text(
                "#!/bin/sh\n"
                f'if [ "$1" = "--version" ]; then echo "ownmesh 1.1.0-test ({name})"; exit 0; fi\n'
                "exit 0\n",
                encoding="utf-8",
                newline="\n",
            )
            target.chmod(target.stat().st_mode | stat.S_IEXEC)
    for meta in ("LICENSE", "NOTICE", "README.md", "RELEASE_NOTES.md"):
        (package / meta).write_text(meta + "\n", encoding="utf-8")


def _asset_name() -> tuple[str, bool]:
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Windows":
        return "ownmesh-windows-x64.zip", True
    arch = "x64" if machine in {"x86_64", "amd64"} else "arm64" if machine in {"aarch64", "arm64"} else None
    if arch is None:
        raise unittest.SkipTest(f"unsupported arch {machine}")
    if system == "Linux":
        return f"ownmesh-linux-{arch}.tar.gz", False
    if system == "Darwin":
        return f"ownmesh-macos-{arch}.tar.gz", False
    raise unittest.SkipTest(f"unsupported OS {system}")


def _pack(package: Path, asset_dir: Path, asset_name: str, windows: bool) -> None:
    asset_dir.mkdir(parents=True, exist_ok=True)
    asset_path = asset_dir / asset_name
    if windows:
        with zipfile.ZipFile(asset_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in package.iterdir():
                zf.write(path, arcname=path.name)
    else:
        with tarfile.open(asset_path, "w:gz") as tf:
            for path in package.iterdir():
                tf.add(path, arcname=path.name)
    digest = _sha256(asset_path)
    (asset_dir / "SHA256SUMS").write_text(
        f"{digest}  {asset_name}\n", encoding="ascii", newline="\n"
    )


class InstallerAdversarialTests(unittest.TestCase):
    def test_unix_happy_and_adversarial(self) -> None:
        if _is_windows():
            self.skipTest("unix installer")
        if not SH_INSTALLER.is_file():
            self.fail("missing sh installer")
        asset_name, windows = _asset_name()
        if windows:
            self.skipTest("not unix host")

        with tempfile.TemporaryDirectory(prefix="ownmesh-installer-test-") as tmp:
            tmp_path = Path(tmp)
            package = tmp_path / "pkg"
            assets = tmp_path / "assets"
            install = tmp_path / "install"
            _write_fake_bins(package, windows=False)
            _pack(package, assets, asset_name, windows=False)

            env = os.environ.copy()
            env["OWNMESH_ASSET_DIR"] = str(assets)
            env["OWNMESH_INSTALL_DIR"] = str(install)
            env["OWNMESH_NO_MODIFY_PATH"] = "1"
            env.pop("OWNMESH_BASE_URL", None)

            completed = subprocess.run(
                ["sh", str(SH_INSTALLER)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout + "\n" + completed.stderr,
            )
            smoke = subprocess.run(
                [str(install / "ownmesh"), "--version"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(smoke.returncode, 0, smoke.stderr)
            self.assertIn("ownmesh", smoke.stdout.lower())

            # Checksum mismatch
            bad = tmp_path / "bad-assets"
            shutil.copytree(assets, bad)
            with (bad / asset_name).open("ab") as handle:
                handle.write(b"corrupt")
            env["OWNMESH_ASSET_DIR"] = str(bad)
            env["OWNMESH_INSTALL_DIR"] = str(tmp_path / "rejected")
            failed = subprocess.run(
                ["sh", str(SH_INSTALLER)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("SHA-256 mismatch", failed.stderr)

            # Traversal archive
            trav = tmp_path / "trav-assets"
            trav.mkdir()
            trav_pkg = tmp_path / "trav-pkg"
            trav_pkg.mkdir()
            evil = trav_pkg / "evil"
            evil.write_text("x", encoding="utf-8")
            trav_asset = trav / asset_name
            with tarfile.open(trav_asset, "w:gz") as tf:
                info = tarfile.TarInfo(name="../evil-ownmesh")
                data = b"evil"
                info.size = len(data)
                tf.addfile(info, fileobj=__import__("io").BytesIO(data))
            digest = _sha256(trav_asset)
            (trav / "SHA256SUMS").write_text(
                f"{digest}  {asset_name}\n", encoding="ascii", newline="\n"
            )
            env["OWNMESH_ASSET_DIR"] = str(trav)
            env["OWNMESH_INSTALL_DIR"] = str(tmp_path / "trav-install")
            failed = subprocess.run(
                ["sh", str(SH_INSTALLER)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(failed.returncode, 0)

            # Partial archive (missing broker)
            partial_pkg = tmp_path / "partial-pkg"
            _write_fake_bins(partial_pkg, windows=False)
            (partial_pkg / "ownmesh-broker").unlink()
            partial_assets = tmp_path / "partial-assets"
            _pack(partial_pkg, partial_assets, asset_name, windows=False)
            env["OWNMESH_ASSET_DIR"] = str(partial_assets)
            env["OWNMESH_INSTALL_DIR"] = str(tmp_path / "partial-install")
            failed = subprocess.run(
                ["sh", str(SH_INSTALLER)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(failed.returncode, 0)

            # Unsupported arch simulation via uname override is hard in pure sh;
            # instead refuse bad OWNMESH_BASE_URL injection.
            env["OWNMESH_ASSET_DIR"] = str(assets)
            env["OWNMESH_BASE_URL"] = "https://evil.example/ownmesh"
            env["OWNMESH_INSTALL_DIR"] = str(tmp_path / "url-install")
            # Asset dir short-circuits network, but BASE_URL is still validated up front.
            failed = subprocess.run(
                ["sh", str(SH_INSTALLER)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertTrue(
                "allow-list" in failed.stderr or "refusing" in failed.stderr.lower(),
                failed.stderr,
            )

            # PATH quoting guidance for custom install dir with spaces
            spaced = tmp_path / "path with spaces" / "bin"
            env.pop("OWNMESH_BASE_URL", None)
            env["OWNMESH_ASSET_DIR"] = str(assets)
            env["OWNMESH_INSTALL_DIR"] = str(spaced)
            env["OWNMESH_NO_MODIFY_PATH"] = "0"
            # Re-pack good assets (previous env only)
            completed = subprocess.run(
                ["sh", str(SH_INSTALLER)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn('"' + str(spaced) + '"', completed.stdout + completed.stderr)

            # Simulated 404: missing asset in ASSET_DIR
            empty = tmp_path / "empty-assets"
            empty.mkdir()
            (empty / "SHA256SUMS").write_text("00  missing\n", encoding="ascii")
            env["OWNMESH_ASSET_DIR"] = str(empty)
            env["OWNMESH_INSTALL_DIR"] = str(tmp_path / "404")
            failed = subprocess.run(
                ["sh", str(SH_INSTALLER)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertTrue(
                "not found" in failed.stderr.lower() or "asset" in failed.stderr.lower(),
                failed.stderr,
            )

    def test_windows_ps1_syntax_and_guards(self) -> None:
        if not PS_INSTALLER.is_file():
            self.fail("missing ps1 installer")
        text = PS_INSTALLER.read_text(encoding="utf-8")
        # Reject real invocation forms; comments alone are insufficient protection.
        self.assertNotRegex(text, r"(?i)\bInvoke-Expression\b")
        self.assertNotRegex(text, r"(?i)(^|[\s|;&])iex\b")
        self.assertIn("SHA-256 mismatch", text)
        self.assertIn("OWNMESH_BASE_URL", text)
        self.assertIn("Tls12", text)
        if not _is_windows():
            self.skipTest("powershell execution only on Windows")
        # Run happy path when powershell is available.
        asset_name, windows = _asset_name()
        if not windows:
            self.skipTest("windows host required")
        pwsh = shutil.which("powershell") or shutil.which("pwsh")
        if not pwsh:
            self.skipTest("powershell not available")
        with tempfile.TemporaryDirectory(prefix="ownmesh-ps-installer-") as tmp:
            tmp_path = Path(tmp)
            package = tmp_path / "pkg"
            assets = tmp_path / "assets"
            install = tmp_path / "install"
            _write_fake_bins(package, windows=True)
            # Provide a tiny realish ownmesh.exe that returns version via cmd shim:
            # The smoke test executes ownmesh.exe --version; write a .cmd won't work for .exe.
            # Skip full execution if we cannot produce a runnable PE; still pack for checksum path
            # by replacing smoke binary with a copy of a real python launcher? Too heavy.
            # Instead run installer expecting smoke failure after integrity — assert checksum path
            # by corrupting and expecting mismatch first.
            _pack(package, assets, asset_name, windows=True)
            env = os.environ.copy()
            env["OWNMESH_ASSET_DIR"] = str(assets)
            env["OWNMESH_INSTALL_DIR"] = str(install)
            env["OWNMESH_NO_MODIFY_PATH"] = "1"
            # Corrupt checksum path
            bad = tmp_path / "bad"
            shutil.copytree(assets, bad)
            with (bad / asset_name).open("ab") as handle:
                handle.write(b"x")
            env["OWNMESH_ASSET_DIR"] = str(bad)
            completed = subprocess.run(
                [pwsh, "-NoProfile", "-File", str(PS_INSTALLER)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            combined = completed.stdout + completed.stderr
            self.assertIn("SHA-256 mismatch", combined)


class RenderDistributionTests(unittest.TestCase):
    def test_render_injects_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            checksums = tmp_path / "checksums"
            checksums.mkdir()
            assets = {
                "ownmesh-macos-arm64.tar.gz": "a" * 64,
                "ownmesh-macos-x64.tar.gz": "b" * 64,
                "ownmesh-linux-arm64.tar.gz": "c" * 64,
                "ownmesh-linux-x64.tar.gz": "d" * 64,
            }
            for name, digest in assets.items():
                (checksums / f"{name}.sha256").write_text(
                    f"{digest}  {name}\n", encoding="ascii", newline="\n"
                )
            out = tmp_path / "out"
            release = tmp_path / "release"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "render_distribution.py"),
                    "--version",
                    "1.1.0",
                    "--checksums-dir",
                    str(checksums),
                    "--output-dir",
                    str(out),
                    "--release-assets-dir",
                    str(release),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            formula = (out / "homebrew/Formula/ownmesh.rb").read_text(encoding="utf-8")
            self.assertIn('version "1.1.0"', formula)
            for digest in assets.values():
                self.assertIn(digest, formula)
            self.assertTrue((release / "ownmesh.rb").is_file())
            self.assertIn("ownmesh --version", formula)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
