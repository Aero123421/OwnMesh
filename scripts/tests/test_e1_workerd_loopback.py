#!/usr/bin/env python3
"""Real debug ownmeshd binary × local Wrangler/workerd E1 smoke.

The test provisions an isolated loopback-only keychain service, inserts a
matching active device/credential into a temporary local D1 database, starts
Wrangler in local mode, and requires the production binary to authenticate and
reach ready twice. No remote Cloudflare resource is accessed.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parents[2]
CONTROL_PLANE = ROOT / "packages" / "control-plane"


class RetryingTemporaryDirectory(tempfile.TemporaryDirectory[str]):
    """Allow Windows a moment to release terminated workerd SQLite handles."""

    @classmethod
    def _rmtree(
        cls,
        name: str,
        ignore_errors: bool = False,
        repeated: bool = False,
    ) -> None:
        deadline = time.monotonic() + 8
        while True:
            try:
                super()._rmtree(name, ignore_errors=ignore_errors, repeated=repeated)
                return
            except PermissionError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.25)


def executable(name: str) -> str:
    value = shutil.which(name)
    if value is None and os.name == "nt":
        value = shutil.which(f"{name}.cmd") or shutil.which(f"{name}.exe")
    if value is None:
        raise RuntimeError(f"required executable not found: {name}")
    return value


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run_checked(args: list[str], *, cwd: Path, env: dict[str, str], capture: bool = False) -> str:
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {args[0]}\n{result.stderr[-4000:]}"
        )
    return result.stdout.strip() if capture and result.stdout else ""


def wrangler(corepack: str, *args: str) -> list[str]:
    return [corepack, "pnpm@9.15.0", "exec", "wrangler", *args]


def wait_for_health(issuer: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"wrangler exited before health check ({process.returncode})")
        try:
            with urllib.request.urlopen(f"{issuer}/health", timeout=1) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(0.25)
    raise RuntimeError("timed out waiting for local workerd health")


def wait_for_ready(process: subprocess.Popen[bytes], log_path: Path) -> dict[str, object]:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            text = log_path.read_text(encoding="utf-8", errors="replace")
            raise RuntimeError(f"ownmeshd exited before ready ({process.returncode})\n{text[-4000:]}")
        text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
        if "Agent WebSocket authenticated and ready" in text:
            return json.loads((log_path.parent / "state" / "agent-transport-state.json").read_text())
        time.sleep(0.2)
    text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    raise RuntimeError(f"timed out waiting for ownmeshd ready\n{text[-4000:]}")


def stop_process(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    if os.name == "nt":
        # Wrangler is a Node wrapper and local workerd is its child. Killing only
        # the wrapper leaves workerd holding the temporary Miniflare SQLite files.
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=8)
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=8)


def main() -> int:
    cargo = executable("cargo")
    corepack = executable("corepack")
    port = free_port()
    issuer = f"http://127.0.0.1:{port}"
    device_id = f"dev_e1_{uuid.uuid4().hex}"
    credential = f"dcred_{secrets.token_urlsafe(32)}"
    credential_hash = hashlib.sha256(credential.encode()).hexdigest()
    service = f"dev.ownmesh.loopback-test.{uuid.uuid4().hex}"
    session_secret = secrets.token_hex(32)
    owner_token_hash = secrets.token_hex(32)
    password = secrets.token_urlsafe(32)
    wrangler_process: subprocess.Popen[bytes] | None = None
    daemon_process: subprocess.Popen[bytes] | None = None

    with RetryingTemporaryDirectory(prefix="ownmesh-e1-workerd-") as temp_raw:
        temp = Path(temp_raw)
        persist = temp / "wrangler-state"
        config_dir = temp / "config"
        state_dir = temp / "state"
        runtime_dir = temp / "runtime"
        cache_dir = temp / "cache"
        keystore_dir = state_dir / "keystore"
        for directory in [persist, config_dir, state_dir, runtime_dir, cache_dir, keystore_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        (config_dir / "config.toml").write_text(
            "\n".join(
                [
                    "schema_version = 1",
                    'active_instance = "local"',
                    'lang = "en-US"',
                    "",
                    "[[instances]]",
                    'id = "local"',
                    f'base_url = "{issuer}"',
                    'display_name = "E1 workerd loopback"',
                    "",
                ]
            ),
            encoding="utf-8",
        )

        base_env = os.environ.copy()
        base_env.update(
            {
                "OWNMESH_CONFIG_DIR": str(config_dir),
                "OWNMESH_STATE_DIR": str(state_dir),
                "OWNMESH_RUNTIME_DIR": str(runtime_dir),
                "OWNMESH_CACHE_DIR": str(cache_dir),
                "OWNMESH_KEYSTORE_PASSWORD": password,
                "OWNMESH_LOOPBACK_TEST_KEYCHAIN_SERVICE": service,
                "OWNMESH_E1_TEST_KEYSTORE_DIR": str(keystore_dir),
                "OWNMESH_E1_TEST_ISSUER": issuer,
                "OWNMESH_E1_TEST_DEVICE_ID": device_id,
                "OWNMESH_E1_TEST_CREDENTIAL": credential,
                "RUST_LOG": "ownmeshd=info",
            }
        )

        try:
            run_checked([cargo, "build", "-p", "ownmeshd", "--bin", "ownmeshd", "--example", "e1_loopback_provision"], cwd=ROOT, env=base_env)
            public_key = run_checked(
                [cargo, "run", "-q", "-p", "ownmeshd", "--example", "e1_loopback_provision", "--", "provision"],
                cwd=ROOT,
                env=base_env,
                capture=True,
            )
            if len(public_key) != 64:
                raise RuntimeError("loopback provisioner returned an invalid public key")
            verified = run_checked(
                [cargo, "run", "-q", "-p", "ownmeshd", "--example", "e1_loopback_provision", "--", "verify"],
                cwd=ROOT,
                env=base_env,
                capture=True,
            )
            if verified != "present":
                raise RuntimeError("loopback provisioner could not reload its isolated credential")

            run_checked(
                wrangler(corepack, "d1", "migrations", "apply", "DB", "--local", "--persist-to", str(persist)),
                cwd=CONTROL_PLANE,
                env=base_env,
            )
            now = "2026-08-08T00:00:00.000Z"
            expires = "2099-01-01T00:00:00.000Z"
            sql = " ".join(
                [
                    "INSERT OR IGNORE INTO tenants (id,name,created_at) VALUES ('ten_default','Default'," + repr(now) + ");",
                    "INSERT OR IGNORE INTO principals (id,tenant_id,kind,display_name,created_at) VALUES ('prin_dev','ten_default','human','Dev User'," + repr(now) + ");",
                    "INSERT INTO devices (id,tenant_id,principal_id,name,public_key,revoked,created_at,status) VALUES ("
                    + repr(device_id) + ",'ten_default','prin_dev','E1 binary'," + repr(public_key) + ",0," + repr(now) + ",'active');",
                    "INSERT INTO device_credentials (credential_hash,device_id,tenant_id,principal_id,role,expires_at,revoked,created_at) VALUES ("
                    + repr(credential_hash) + "," + repr(device_id) + ",'ten_default','prin_dev','agent'," + repr(expires) + ",0," + repr(now) + ");",
                ]
            )
            run_checked(
                wrangler(corepack, "d1", "execute", "DB", "--local", "--persist-to", str(persist), "--command", sql),
                cwd=CONTROL_PLANE,
                env=base_env,
            )

            wrangler_log = (temp / "wrangler.log").open("wb")
            wrangler_process = subprocess.Popen(
                wrangler(
                    corepack,
                    "dev",
                    "--local",
                    "--ip",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--persist-to",
                    str(persist),
                    "--var",
                    f"OAUTH_ISSUER:{issuer}",
                    "--var",
                    "OWNMESH_DEV_AUTH_BYPASS:true",
                    "--var",
                    f"SESSION_SECRET:{session_secret}",
                    "--var",
                    f"OWNER_TOKEN_HASH:{owner_token_hash}",
                    "--var",
                    f"OWNMESH_ALLOWED_ORIGINS:{issuer}",
                    "--log-level",
                    "info",
                    "--show-interactive-dev-session",
                    "false",
                ),
                cwd=CONTROL_PLANE,
                env=base_env,
                stdout=wrangler_log,
                stderr=subprocess.STDOUT,
            )
            wrangler_log.close()
            wait_for_health(issuer, wrangler_process)

            binary = ROOT / "target" / "debug" / ("ownmeshd.exe" if os.name == "nt" else "ownmeshd")
            states: list[dict[str, object]] = []
            for attempt in range(2):
                log_path = temp / f"ownmeshd-{attempt}.log"
                with log_path.open("wb") as log:
                    daemon_process = subprocess.Popen(
                        [str(binary), "run"],
                        cwd=ROOT,
                        env=base_env,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                    )
                    states.append(wait_for_ready(daemon_process, log_path))
                    stop_process(daemon_process)
                    daemon_process = None
            if int(states[1]["next_outbound_seq"]) <= int(states[0]["next_outbound_seq"]):
                raise RuntimeError("outbound sequence did not advance across binary reconnect")
            if int(states[1]["last_server_seq"]) <= int(states[0]["last_server_seq"]):
                raise RuntimeError("server resume sequence did not advance across binary reconnect")
            print("E1 workerd loopback passed: real ownmeshd authenticated and resumed twice")
            return 0
        finally:
            stop_process(daemon_process)
            stop_process(wrangler_process)
            cleanup_env = base_env.copy()
            cleanup_env.pop("OWNMESH_E1_TEST_CREDENTIAL", None)
            subprocess.run(
                [cargo, "run", "-q", "-p", "ownmeshd", "--example", "e1_loopback_provision", "--", "cleanup"],
                cwd=ROOT,
                env=cleanup_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"E1 workerd loopback failed: {error}", file=sys.stderr)
        raise SystemExit(1)
