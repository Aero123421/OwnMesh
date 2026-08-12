#!/usr/bin/env python3
"""Adversarial installer checks (404/checksum/traversal/arch/partial/PATH quoting)."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shlex
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


def _require_minisign() -> str:
    """Locate minisign, or skip unless this run is required to have it.

    The installers' whole point is signature verification, so CI must never
    report green without exercising it: `OWNMESH_REQUIRE_MINISIGN=1` (set by the
    workflows that install the pinned binary) turns a missing minisign into a
    failure. A developer running the suite locally gets a skip instead, matching
    how the PowerShell cases already behave when pwsh is absent.
    """
    path = shutil.which("minisign")
    if path:
        return path
    if os.environ.get("OWNMESH_REQUIRE_MINISIGN") == "1":
        raise AssertionError(
            "minisign is required for installer trust tests "
            "(OWNMESH_REQUIRE_MINISIGN=1)"
        )
    raise unittest.SkipTest(
        "minisign not found; install it or set OWNMESH_REQUIRE_MINISIGN=1 to require it"
    )


def _generate_trust(asset_dir: Path) -> tuple[Path, Path]:
    """Create an ephemeral minisign trust root and return (pub, secret)."""
    minisign = _require_minisign()
    key_dir = asset_dir / ".keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    pub = key_dir / "minisign.pub"
    sec = key_dir / "minisign.key"
    # minisign -G refuses overwrite; use unique paths.
    completed = subprocess.run(
        [minisign, "-G", "-p", str(pub), "-s", str(sec), "-W"],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"minisign keygen failed: {completed.stderr or completed.stdout}"
        )
    return pub, sec


def _sign_sums(sums_path: Path, secret: Path, sig_path: Path) -> None:
    minisign = _require_minisign()
    completed = subprocess.run(
        [minisign, "-S", "-s", str(secret), "-m", str(sums_path), "-x", str(sig_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"minisign sign failed: {completed.stderr or completed.stdout}"
        )


def _pack(package: Path, asset_dir: Path, asset_name: str, windows: bool) -> tuple[Path, Path]:
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
    sums_path = asset_dir / "SHA256SUMS"
    sums_path.write_text(f"{digest}  {asset_name}\n", encoding="ascii", newline="\n")
    pub, sec = _generate_trust(asset_dir)
    # Publish the test trust root beside assets (operator override via OWNMESH_MINISIGN_PUB).
    published_pub = asset_dir / "minisign.pub"
    published_pub.write_bytes(pub.read_bytes())
    sig_path = asset_dir / "SHA256SUMS.minisig"
    _sign_sums(sums_path, sec, sig_path)
    return published_pub, sec


class InstallerAdversarialTests(unittest.TestCase):
    def test_unix_installer_is_posix_sh_and_rejects_line_breaks(self) -> None:
        if _is_windows():
            self.skipTest("unix installer")

        syntax = subprocess.run(
            ["sh", "-n", str(SH_INSTALLER)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stdout + syntax.stderr)

        for unsafe in ("/tmp/ownmesh\nbad", "/tmp/ownmesh\rbad", "/tmp/ownmesh&bad"):
            env = os.environ.copy()
            env["OWNMESH_INSTALL_DIR"] = unsafe
            failed = subprocess.run(
                ["sh", str(SH_INSTALLER)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("shell metacharacters", failed.stderr)

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
            pub, _sec = _pack(package, assets, asset_name, windows=False)

            env = os.environ.copy()
            env["OWNMESH_ASSET_DIR"] = str(assets)
            env["OWNMESH_INSTALL_DIR"] = str(install)
            env["OWNMESH_NO_MODIFY_PATH"] = "1"
            env["OWNMESH_MINISIGN_PUB"] = str(pub)
            env.pop("OWNMESH_BASE_URL", None)

            completed = subprocess.run(
                ["sh", str(SH_INSTALLER)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout + "\n" + completed.stderr,
            )
            self.assertIn("minisign: SHA256SUMS signature ok", completed.stdout + completed.stderr)
            smoke = subprocess.run(
                [str(install / "ownmesh"), "--version"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(smoke.returncode, 0, smoke.stderr)
            self.assertIn("ownmesh", smoke.stdout.lower())
            for binary in (
                "ownmesh",
                "ownmesh-tui",
                "ownmeshd",
                "ownmesh-session-host",
                "ownmesh-broker",
            ):
                self.assertTrue((install / binary).is_file(), binary)

            # Checksum mismatch (signature still verifies; archive digest fails).
            bad = tmp_path / "bad-assets"
            shutil.copytree(assets, bad)
            with (bad / asset_name).open("ab") as handle:
                handle.write(b"corrupt")
            env["OWNMESH_ASSET_DIR"] = str(bad)
            env["OWNMESH_INSTALL_DIR"] = str(tmp_path / "rejected")
            env["OWNMESH_MINISIGN_PUB"] = str(bad / "minisign.pub")
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

            # Missing signature fails closed (never trusts bare SHA256SUMS).
            unsigned = tmp_path / "unsigned-assets"
            shutil.copytree(assets, unsigned)
            (unsigned / "SHA256SUMS.minisig").unlink()
            env["OWNMESH_ASSET_DIR"] = str(unsigned)
            env["OWNMESH_INSTALL_DIR"] = str(tmp_path / "unsigned-install")
            env["OWNMESH_MINISIGN_PUB"] = str(unsigned / "minisign.pub")
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
                "minisig" in failed.stderr.lower() or "signature" in failed.stderr.lower(),
                failed.stderr,
            )

            # Tampered signature / wrong key fails closed.
            evil = tmp_path / "evil-sig"
            shutil.copytree(assets, evil)
            (evil / "SHA256SUMS.minisig").write_text("untrusted comment: corrupt\nbad\n", encoding="ascii")
            env["OWNMESH_ASSET_DIR"] = str(evil)
            env["OWNMESH_INSTALL_DIR"] = str(tmp_path / "evil-install")
            env["OWNMESH_MINISIGN_PUB"] = str(evil / "minisign.pub")
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
                "minisign" in failed.stderr.lower() or "signature" in failed.stderr.lower(),
                failed.stderr,
            )

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
            sums = trav / "SHA256SUMS"
            sums.write_text(f"{digest}  {asset_name}\n", encoding="ascii", newline="\n")
            pub_trav, sec_trav = _generate_trust(trav)
            (trav / "minisign.pub").write_bytes(pub_trav.read_bytes())
            _sign_sums(sums, sec_trav, trav / "SHA256SUMS.minisig")
            env["OWNMESH_ASSET_DIR"] = str(trav)
            env["OWNMESH_INSTALL_DIR"] = str(tmp_path / "trav-install")
            env["OWNMESH_MINISIGN_PUB"] = str(trav / "minisign.pub")
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
            pub_partial, _ = _pack(partial_pkg, partial_assets, asset_name, windows=False)
            env["OWNMESH_ASSET_DIR"] = str(partial_assets)
            env["OWNMESH_INSTALL_DIR"] = str(tmp_path / "partial-install")
            env["OWNMESH_MINISIGN_PUB"] = str(pub_partial)
            failed = subprocess.run(
                ["sh", str(SH_INSTALLER)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(failed.returncode, 0)

            # Entry-count bomb
            bomb_assets = tmp_path / "bomb-assets"
            bomb_assets.mkdir()
            bomb_asset = bomb_assets / asset_name
            with tarfile.open(bomb_asset, "w:gz") as tf:
                for i in range(80):
                    # Directory headers are otherwise ignored by the allow-list,
                    # so this reaches the independent entry-count gate.
                    info = tarfile.TarInfo(name=f"pad-{i}/")
                    info.type = tarfile.DIRTYPE
                    tf.addfile(info)
            digest = _sha256(bomb_asset)
            sums = bomb_assets / "SHA256SUMS"
            sums.write_text(f"{digest}  {asset_name}\n", encoding="ascii", newline="\n")
            pub_bomb, sec_bomb = _generate_trust(bomb_assets)
            (bomb_assets / "minisign.pub").write_bytes(pub_bomb.read_bytes())
            _sign_sums(sums, sec_bomb, bomb_assets / "SHA256SUMS.minisig")
            env["OWNMESH_ASSET_DIR"] = str(bomb_assets)
            env["OWNMESH_INSTALL_DIR"] = str(tmp_path / "bomb-install")
            env["OWNMESH_MINISIGN_PUB"] = str(bomb_assets / "minisign.pub")
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
                "entry count" in failed.stderr.lower() or "limit" in failed.stderr.lower(),
                failed.stderr,
            )

            # Oversized member (declared size over per-entry limit). Zeros compress tightly.
            class _ZeroReader:
                def __init__(self, n: int) -> None:
                    self.left = n

                def read(self, size: int = -1) -> bytes:
                    if self.left <= 0:
                        return b""
                    take = self.left if size < 0 else min(size, self.left)
                    self.left -= take
                    return b"\0" * take

            huge_assets = tmp_path / "huge-assets"
            huge_assets.mkdir()
            huge_asset = huge_assets / asset_name
            huge_size = 257 * 1024 * 1024  # just over 256 MiB cap
            with tarfile.open(huge_asset, "w:gz") as tf:
                info = tarfile.TarInfo(name="ownmesh")
                info.size = huge_size
                tf.addfile(info, fileobj=_ZeroReader(huge_size))
            digest = _sha256(huge_asset)
            sums = huge_assets / "SHA256SUMS"
            sums.write_text(f"{digest}  {asset_name}\n", encoding="ascii", newline="\n")
            pub_huge, sec_huge = _generate_trust(huge_assets)
            (huge_assets / "minisign.pub").write_bytes(pub_huge.read_bytes())
            _sign_sums(sums, sec_huge, huge_assets / "SHA256SUMS.minisig")
            env["OWNMESH_ASSET_DIR"] = str(huge_assets)
            env["OWNMESH_INSTALL_DIR"] = str(tmp_path / "huge-install")
            env["OWNMESH_MINISIGN_PUB"] = str(huge_assets / "minisign.pub")
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
                "per-entry" in failed.stderr.lower() or "limit" in failed.stderr.lower(),
                failed.stderr,
            )

            # Duplicate required binary
            dup_pkg = tmp_path / "dup-pkg"
            _write_fake_bins(dup_pkg, windows=False)
            dup_assets = tmp_path / "dup-assets"
            dup_assets.mkdir()
            dup_asset = dup_assets / asset_name
            with tarfile.open(dup_asset, "w:gz") as tf:
                for path in dup_pkg.iterdir():
                    tf.add(path, arcname=path.name)
                # Second ownmesh under wrapper prefix — same base name after normalize.
                info = tarfile.TarInfo(name="wrapper/ownmesh")
                data = b"duplicate-ownmesh"
                info.size = len(data)
                tf.addfile(info, fileobj=__import__("io").BytesIO(data))
            digest = _sha256(dup_asset)
            sums = dup_assets / "SHA256SUMS"
            sums.write_text(f"{digest}  {asset_name}\n", encoding="ascii", newline="\n")
            pub_dup, sec_dup = _generate_trust(dup_assets)
            (dup_assets / "minisign.pub").write_bytes(pub_dup.read_bytes())
            _sign_sums(sums, sec_dup, dup_assets / "SHA256SUMS.minisig")
            env["OWNMESH_ASSET_DIR"] = str(dup_assets)
            env["OWNMESH_INSTALL_DIR"] = str(tmp_path / "dup-install")
            env["OWNMESH_MINISIGN_PUB"] = str(dup_assets / "minisign.pub")
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
                "duplicate" in failed.stderr.lower() or "unexpected" in failed.stderr.lower(),
                failed.stderr,
            )

            # Symlink member
            link_assets = tmp_path / "link-assets"
            link_assets.mkdir()
            link_asset = link_assets / asset_name
            with tarfile.open(link_asset, "w:gz") as tf:
                info = tarfile.TarInfo(name="ownmesh")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                info.size = 0
                tf.addfile(info)
            digest = _sha256(link_asset)
            sums = link_assets / "SHA256SUMS"
            sums.write_text(f"{digest}  {asset_name}\n", encoding="ascii", newline="\n")
            pub_link, sec_link = _generate_trust(link_assets)
            (link_assets / "minisign.pub").write_bytes(pub_link.read_bytes())
            _sign_sums(sums, sec_link, link_assets / "SHA256SUMS.minisig")
            env["OWNMESH_ASSET_DIR"] = str(link_assets)
            env["OWNMESH_INSTALL_DIR"] = str(tmp_path / "link-install")
            env["OWNMESH_MINISIGN_PUB"] = str(link_assets / "minisign.pub")
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
                "symlink" in failed.stderr.lower() or "link" in failed.stderr.lower(),
                failed.stderr,
            )

            # Unexpected member beside required set
            unexp_pkg = tmp_path / "unexp-pkg"
            _write_fake_bins(unexp_pkg, windows=False)
            (unexp_pkg / "evil-extra.so").write_bytes(b"evil")
            unexp_assets = tmp_path / "unexp-assets"
            pub_unexp, _ = _pack(unexp_pkg, unexp_assets, asset_name, windows=False)
            env["OWNMESH_ASSET_DIR"] = str(unexp_assets)
            env["OWNMESH_INSTALL_DIR"] = str(tmp_path / "unexp-install")
            env["OWNMESH_MINISIGN_PUB"] = str(pub_unexp)
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
                "unexpected" in failed.stderr.lower() or "refusing" in failed.stderr.lower(),
                failed.stderr,
            )

            # Non-file destinations fail before any binary replacement.
            rollback_pkg = tmp_path / "rollback-pkg"
            _write_fake_bins(rollback_pkg, windows=False)
            rollback_assets = tmp_path / "rollback-assets"
            pub_rb, _ = _pack(rollback_pkg, rollback_assets, asset_name, windows=False)
            rb_install = tmp_path / "rollback-install"
            rb_install.mkdir()
            old_bin = rb_install / "ownmesh"
            old_bin.write_text(
                "#!/bin/sh\necho ownmesh-old-marker\n",
                encoding="utf-8",
                newline="\n",
            )
            old_bin.chmod(old_bin.stat().st_mode | stat.S_IEXEC)
            tui_blocker = rb_install / "ownmesh-tui"
            tui_blocker.mkdir()
            (tui_blocker / "nested").write_text("x", encoding="utf-8")
            env["OWNMESH_ASSET_DIR"] = str(rollback_assets)
            env["OWNMESH_INSTALL_DIR"] = str(rb_install)
            env["OWNMESH_MINISIGN_PUB"] = str(pub_rb)
            env["OWNMESH_NO_MODIFY_PATH"] = "1"
            failed = subprocess.run(
                ["sh", str(SH_INSTALLER)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("non-file", failed.stderr.lower())
            self.assertIn("ownmesh-old-marker", old_bin.read_text(encoding="utf-8"))
            self.assertEqual(list(rb_install.glob(".ownmesh-backup.*")), [])

            # Force the second atomic move to fail after ownmesh was replaced. Rollback
            # must restore the marker and remove every binary that had no predecessor.
            shutil.rmtree(tui_blocker)
            shim_dir = tmp_path / "rollback-shim"
            shim_dir.mkdir()
            real_mv = shutil.which("mv")
            self.assertIsNotNone(real_mv)
            mv_shim = shim_dir / "mv"
            mv_shim.write_text(
                "#!/bin/sh\n"
                'if [ "$3" = "$OWNMESH_TEST_FAIL_DEST" ]; then exit 91; fi\n'
                f"exec {shlex.quote(real_mv or '/bin/mv')} \"$@\"\n",
                encoding="utf-8",
                newline="\n",
            )
            mv_shim.chmod(mv_shim.stat().st_mode | stat.S_IEXEC)
            env["PATH"] = str(shim_dir) + os.pathsep + env["PATH"]
            env["OWNMESH_TEST_FAIL_DEST"] = str(rb_install / "ownmesh-tui")
            failed = subprocess.run(
                ["sh", str(SH_INSTALLER)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("previous binaries restored", failed.stderr.lower())
            self.assertIn("ownmesh-old-marker", old_bin.read_text(encoding="utf-8"))
            for binary in BINS[1:]:
                self.assertFalse((rb_install / binary).exists(), binary)
            self.assertEqual(list(rb_install.glob(".ownmesh-backup.*")), [])
            self.assertEqual(list(rb_install.glob(".*.new.*")), [])
            env["PATH"] = os.environ["PATH"]
            env.pop("OWNMESH_TEST_FAIL_DEST", None)

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
            env["OWNMESH_MINISIGN_PUB"] = str(pub)
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
            env.pop("OWNMESH_MINISIGN_PUB", None)
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
                "not found" in failed.stderr.lower()
                or "asset" in failed.stderr.lower()
                or "minisign" in failed.stderr.lower()
                or "minisig" in failed.stderr.lower(),
                failed.stderr,
            )

    def test_windows_ps1_syntax_and_guards(self) -> None:
        if not PS_INSTALLER.is_file():
            self.fail("missing ps1 installer")
        text = PS_INSTALLER.read_text(encoding="utf-8")
        # Reject real invocation forms; comments alone are insufficient protection.
        # Reject real invocation forms; comments alone mentioning the banned names are OK
        # only when not used as executable statements.
        self.assertNotRegex(text, r"(?im)^\s*Invoke-Expression\b")
        self.assertNotRegex(text, r"(?im)^\s*iex\b")
        self.assertNotRegex(text, r"(?i)\|\s*iex\b")
        self.assertNotRegex(text, r"(?i)\birm\b[^\n]*\|\s*iex\b")
        self.assertIn("SHA-256 mismatch", text)
        self.assertIn("OWNMESH_BASE_URL", text)
        self.assertIn("Tls12", text)
        self.assertIn("SHA256SUMS.minisig", text)
        self.assertIn("minisign", text.lower())
        self.assertIn("pinned OwnMesh trust root", text)
        # Must not full-extract before validation.
        self.assertNotRegex(text, r"(?im)^\s*Expand-Archive\b")
        self.assertIn("Assert-ArchiveContractAndExtract", text)
        self.assertIn("MaxArchiveEntries", text)
        self.assertIn("MaxEntryUncompressedBytes", text)
        self.assertIn("MaxTotalUncompressedBytes", text)
        self.assertIn("duplicate archive member", text)
        self.assertIn("unexpected archive member", text)
        self.assertIn("Refusing existing non-file", text)
        self.assertIn("Refusing existing reparse point", text)
        self.assertIn("[IO.File]::Replace", text)

    def test_sh_installer_requires_minisig_and_forbids_curl_pipe(self) -> None:
        text = SH_INSTALLER.read_text(encoding="utf-8")
        self.assertIn("SHA256SUMS.minisig", text)
        self.assertIn("require_verify_minisign", text)
        self.assertIn(
            'PINNED_MINISIGN_LINUX_X64_SHA256="f0a0954413df8531befed169e447a66da6868d79052ed7e892e50a4291af7ae0"',
            text,
        )
        self.assertIn('bootstrap_relpath="minisign-linux/x86_64/minisign"', text)
        self.assertIn("PINNED_MINISIGN_PUB_KEY", text)
        # No executable curl|sh pipeline (comments may discuss the anti-pattern).
        self.assertNotRegex(text, r"(?m)^[^#\n]*curl[^\n]*\|\s*sh")
        self.assertIn("Never pipe remote script", text)
        # Bounded member-by-member extract; no full-archive tar -xzf without member list.
        self.assertIn("MAX_ARCHIVE_ENTRIES", text)
        self.assertIn("MAX_ENTRY_UNCOMPRESSED_BYTES", text)
        self.assertIn("MAX_TOTAL_UNCOMPRESSED_BYTES", text)
        self.assertIn("safe_extract", text)
        self.assertIn("tar -tvzf", text)
        self.assertIn("tar -xOzf", text)
        # OwnMesh payload extract must stream single members (`$member`), not full-archive xzf.
        self.assertIn('tar -xOzf "$archive" "$member"', text)
        self.assertNotRegex(
            text,
            r'(?m)^(?!\s*#)\s*tar\s+-xzf\s+"\$archive"\s*$',
        )
        if not _is_windows():
            self.skipTest("powershell execution only on Windows")
        # Run happy path when powershell is available.
        asset_name, windows = _asset_name()
        if not windows:
            self.skipTest("windows host required")
        # Prefer PowerShell 7 so a pwsh-hosted CI process does not pass a PS7-only
        # PSModulePath into Windows PowerShell 5.1 and break cmdlet auto-loading.
        pwsh = shutil.which("pwsh") or shutil.which("powershell")
        if not pwsh:
            self.skipTest("powershell not available")
        with tempfile.TemporaryDirectory(prefix="ownmesh-ps-installer-") as tmp:
            tmp_path = Path(tmp)
            package = tmp_path / "pkg"
            assets = tmp_path / "assets"
            install = tmp_path / "install"
            package.mkdir()
            for binary in BINS:
                source = ROOT / "target" / "debug" / f"{binary}.exe"
                self.assertTrue(source.is_file(), f"cargo build must produce {source}")
                shutil.copy2(source, package / f"{binary}.exe")
            for meta in ("LICENSE", "NOTICE", "README.md", "RELEASE_NOTES.md"):
                source = ROOT / meta
                if source.is_file():
                    shutil.copy2(source, package / meta)
                else:
                    (package / meta).write_text(meta + "\n", encoding="utf-8")
            pub, _ = _pack(package, assets, asset_name, windows=True)
            env = os.environ.copy()
            env["OWNMESH_ASSET_DIR"] = str(assets)
            env["OWNMESH_INSTALL_DIR"] = str(install)
            env["OWNMESH_NO_MODIFY_PATH"] = "1"
            env["OWNMESH_MINISIGN_PUB"] = str(pub)

            completed = subprocess.run(
                [pwsh, "-NoProfile", "-File", str(PS_INSTALLER)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn(
                "minisign: SHA256SUMS signature ok",
                completed.stdout + completed.stderr,
            )
            version_match = re.search(
                r'(?m)^version = "([^"]+)"$',
                (ROOT / "Cargo.toml").read_text(encoding="utf-8"),
            )
            self.assertIsNotNone(version_match)
            expected_version = version_match.group(1) if version_match else ""
            for binary in BINS:
                installed = install / f"{binary}.exe"
                self.assertTrue(installed.is_file(), binary)
                smoke = subprocess.run(
                    [str(installed), "--version"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(smoke.returncode, 0, smoke.stdout + smoke.stderr)
                self.assertIn(binary, smoke.stdout.lower())
                self.assertIn(expected_version, smoke.stdout)

            # A file reparse point must be rejected before replacing any target.
            reparse_install = tmp_path / "reparse-install"
            reparse_install.mkdir()
            old_reparse_ownmesh = reparse_install / "ownmesh.exe"
            shutil.copy2(sys.executable, old_reparse_ownmesh)
            old_reparse_hash = _sha256(old_reparse_ownmesh)
            os.symlink(sys.executable, reparse_install / "ownmesh-tui.exe")
            env["OWNMESH_INSTALL_DIR"] = str(reparse_install)
            completed = subprocess.run(
                [pwsh, "-NoProfile", "-File", str(PS_INSTALLER)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("reparse point", (completed.stdout + completed.stderr).lower())
            self.assertEqual(_sha256(old_reparse_ownmesh), old_reparse_hash)
            self.assertEqual(list(reparse_install.glob(".ownmesh-backup-*")), [])

            # Deny deletion of the second existing target so Move-Item fails after
            # ownmesh.exe was replaced. The first target must be restored and no
            # later binary may remain as a partial new installation.
            import ctypes
            from ctypes import wintypes

            rollback_install = tmp_path / "rollback-install"
            rollback_install.mkdir()
            old_ownmesh = rollback_install / "ownmesh.exe"
            old_tui = rollback_install / "ownmesh-tui.exe"
            shutil.copy2(sys.executable, old_ownmesh)
            shutil.copy2(sys.executable, old_tui)
            old_ownmesh_hash = _sha256(old_ownmesh)
            old_tui_hash = _sha256(old_tui)
            create_file = ctypes.windll.kernel32.CreateFileW
            create_file.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            create_file.restype = wintypes.HANDLE
            close_handle = ctypes.windll.kernel32.CloseHandle
            close_handle.argtypes = [wintypes.HANDLE]
            close_handle.restype = wintypes.BOOL
            locked_handle = create_file(
                str(old_tui),
                0x80000000,  # GENERIC_READ
                0x00000001,  # FILE_SHARE_READ (deny replacement/delete)
                None,
                3,  # OPEN_EXISTING
                0x00000080,  # FILE_ATTRIBUTE_NORMAL
                None,
            )
            invalid_handle = ctypes.c_void_p(-1).value
            self.assertNotEqual(locked_handle, invalid_handle)
            env["OWNMESH_INSTALL_DIR"] = str(rollback_install)
            try:
                completed = subprocess.run(
                    [pwsh, "-NoProfile", "-File", str(PS_INSTALLER)],
                    cwd=str(ROOT),
                    env=env,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    check=False,
                )
            finally:
                close_handle(locked_handle)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "Atomic install failed; restoring backup",
                completed.stdout + completed.stderr,
            )
            self.assertEqual(_sha256(old_ownmesh), old_ownmesh_hash)
            self.assertEqual(_sha256(old_tui), old_tui_hash)
            for binary in BINS[2:]:
                self.assertFalse((rollback_install / f"{binary}.exe").exists(), binary)
            self.assertEqual(list(rollback_install.glob(".ownmesh-backup-*")), [])
            self.assertEqual(list(rollback_install.glob(".*.new-*")), [])
            self.assertEqual(list(rollback_install.glob(".*.restore-*")), [])
            self.assertEqual(list(rollback_install.glob(".*.failed-*")), [])

            # A signed checksum with a corrupted archive still fails before extraction.
            bad = tmp_path / "bad"
            shutil.copytree(assets, bad)
            with (bad / asset_name).open("ab") as handle:
                handle.write(b"x")
            env["OWNMESH_ASSET_DIR"] = str(bad)
            env["OWNMESH_INSTALL_DIR"] = str(tmp_path / "bad-install")
            env["OWNMESH_MINISIGN_PUB"] = str(bad / "minisign.pub")
            completed = subprocess.run(
                [pwsh, "-NoProfile", "-File", str(PS_INSTALLER)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
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
