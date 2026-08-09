#!/usr/bin/env python3
"""Real debug ownmeshd binary × local Wrangler/workerd E2 routing smoke.

Proves the production path:

  public /mcp → Worker → DeviceRoom → Agent WSS → ownmeshd runtime → result

Exercises real temporary-directory filesystem write/read and a structured
command, then restarts the binary to prove correlation dedup across resume.
No remote Cloudflare resource is accessed.
"""

from __future__ import annotations

import base64
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
import urllib.error
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parents[2]
CONTROL_PLANE = ROOT / "packages" / "control-plane"
E6_FIXTURE = ROOT / "scripts" / "tests" / "fixtures" / "e6_adapter_fixture.py"


def install_e6_profile_fixtures(directory: Path) -> None:
    """Create exact-name executable wrappers placed ahead of PATH for E6.

    The production profile resolver still performs normal PATH discovery; only
    the executable implementation is deterministic. Each wrapper selects a
    strict wire validator in the checked-in fixture, so no runtime handler is
    bypassed.
    """
    directory.mkdir(parents=True, exist_ok=True)
    names = {
        "codex": "codex", "claude": "claude-code", "kimi": "kimi-code",
        "opencode": "opencode", "pi": "pi", "agy": "agy",
        "qwen": "qwen-code", "hermes": "hermes-agent", "qodercli": "qoder",
    }
    if os.name == "nt":
        for executable_name, profile in names.items():
            (directory / f"{executable_name}.cmd").write_text(
                "@echo off\r\n"
                f"set E6_PROFILE={profile}\r\n"
                f'"{sys.executable}" "{E6_FIXTURE}" %*\r\n',
                encoding="utf-8",
            )
    else:
        for executable_name, profile in names.items():
            path = directory / executable_name
            path.write_text(
                "#!/bin/sh\n"
                f"E6_PROFILE='{profile}' exec '{sys.executable}' '{E6_FIXTURE}' \"$@\"\n",
                encoding="utf-8",
            )
            path.chmod(0o700)


def session_id_from_operation(value: dict[str, object]) -> str:
    """Extract a production session id without depending on envelope nesting."""
    import re

    match = re.search(r"ses_[0-9a-fA-F]+", json.dumps(value))
    if not match:
        raise RuntimeError(f"session open missing session id: {value}")
    return match.group(0)


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
            state_path = log_path.parent / "state" / "agent-transport-state.json"
            # State is JSON UTF-8; never decode with the Windows ANSI code page.
            return json.loads(state_path.read_text(encoding="utf-8"))
        time.sleep(0.2)
    text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    raise RuntimeError(f"timed out waiting for ownmeshd ready\n{text[-4000:]}")


def stop_process(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    if os.name == "nt":
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


def stop_daemon_only(process: subprocess.Popen[bytes] | None) -> None:
    """Stop ownmeshd without recursively killing its detached session sidecar."""
    if process is None or process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=8)


def stop_session_sidecars(state_dir: Path) -> None:
    """Best-effort explicit cleanup of only this test's uniquely-rooted sidecar."""
    needle = str(state_dir / "session-supervisor")
    pids: list[int] = []
    if os.name == "nt":
        query = (
            "$p=Get-CimInstance Win32_Process | Where-Object { "
            "$_.Name -eq 'ownmesh-session-host.exe' -and $_.CommandLine -like '*"
            + needle.replace("'", "''")
            + "*' }; $p | ForEach-Object { $_.ProcessId }"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", query],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        pids = [int(line) for line in result.stdout.splitlines() if line.strip().isdigit()]
    else:
        result = subprocess.run(
            ["ps", "-eo", "pid=,args="],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        for line in result.stdout.splitlines():
            parts = line.strip().split(maxsplit=1)
            if len(parts) == 2 and "ownmesh-session-host" in parts[1] and needle in parts[1]:
                pids.append(int(parts[0]))
    for pid in pids:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        else:
            subprocess.run(["kill", "-TERM", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def start_daemon(binary: Path, env: dict[str, str], log_path: Path) -> subprocess.Popen[bytes]:
    with log_path.open("wb") as log:
        return subprocess.Popen([str(binary), "run"], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)


def http_json(url: str, *, method: str = "GET", headers: dict[str, str] | None = None, body: object | None = None) -> tuple[int, object]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("accept", "application/json, text/event-stream")
    if body is not None:
        req.add_header("content-type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        try:
            parsed: object = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"raw": raw}
        return error.code, parsed


def mcp_call(issuer: str, token: str, name: str, arguments: dict[str, object], rpc_id: int = 1) -> dict[str, object]:
    status, body = http_json(
        f"{issuer}/mcp",
        method="POST",
        headers={"authorization": f"Bearer {token}"},
        body={
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )
    if status != 200:
        raise RuntimeError(f"mcp {name} HTTP {status}: {body}")
    if not isinstance(body, dict):
        raise RuntimeError(f"mcp {name} returned non-object body: {body!r}")
    if body.get("error"):
        raise RuntimeError(f"mcp {name} JSON-RPC error: {body['error']}")
    result = body.get("result")
    if not isinstance(result, dict):
        raise RuntimeError(f"mcp {name} missing result: {body}")
    return result


def mcp_expect_rejected(issuer: str, token: str, name: str, arguments: dict[str, object], rpc_id: int) -> dict[str, object]:
    """Assert a pre-route MCP authorization rejection (no synthetic operation)."""
    status, body = http_json(
        f"{issuer}/mcp",
        method="POST",
        headers={"authorization": f"Bearer {token}"},
        body={
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )
    if status != 200 or not isinstance(body, dict) or not isinstance(body.get("error"), dict):
        raise RuntimeError(f"expected pre-route rejection from {name}: HTTP={status} body={body}")
    return body


def structured(result: dict[str, object]) -> dict[str, object]:
    sc = result.get("structuredContent")
    if not isinstance(sc, dict):
        raise RuntimeError(f"missing structuredContent: {result}")
    return sc


def find_value(value: object, key: str) -> object | None:
    if isinstance(value, dict):
        if key in value:
            return value[key]
        for child in value.values():
            found = find_value(child, key)
            if found is not None:
                return found
    if isinstance(value, list):
        for child in value:
            found = find_value(child, key)
            if found is not None:
                return found
    return None


def review_chunk_bytes(value: object) -> tuple[list[dict[str, object]], bytes]:
    """Collect typed review chunks without assuming an MCP envelope nesting."""
    chunks: list[dict[str, object]] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            kind = node.get("kind")
            raw = node.get("bytes")
            if isinstance(kind, str) and isinstance(raw, list) and all(isinstance(x, int) and 0 <= x <= 255 for x in raw):
                chunks.append(node)
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(value)
    return chunks, b"".join(bytes(chunk["bytes"]) for chunk in chunks)


def sidecar_bytes(value: object) -> bytes:
    encoded = find_value(value, "sidecar_bytes_base64")
    if not isinstance(encoded, str):
        return b""
    try:
        return base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise RuntimeError(f"invalid sidecar replay base64: {error}") from error


def wait_operation(issuer: str, token: str, operation_id: str, *, want: set[str], timeout_s: float = 30.0) -> dict[str, object]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, object] | None = None
    rpc_id = 100
    while time.monotonic() < deadline:
        rpc_id += 1
        sc = structured(
            mcp_call(
                issuer,
                token,
                "ownmesh_get_operation",
                {"operation_id": operation_id},
                rpc_id=rpc_id,
            )
        )
        last = sc
        status = str(sc.get("status") or "")
        if status in want:
            return sc
        if status in {"failed", "denied", "cancelled", "device_offline"} and status not in want:
            raise RuntimeError(f"operation {operation_id} terminal failure: {sc}")
        time.sleep(0.25)
    raise RuntimeError(f"timed out waiting for {operation_id} in {want}; last={last}")


def main() -> int:
    cargo = executable("cargo")
    corepack = executable("corepack")
    port = free_port()
    issuer = f"http://127.0.0.1:{port}"
    device_id = f"dev_e2_{uuid.uuid4().hex}"
    credential = f"dcred_{secrets.token_urlsafe(32)}"
    credential_hash = hashlib.sha256(credential.encode()).hexdigest()
    access_token = f"atk_{secrets.token_urlsafe(24)}"
    access_hash = hashlib.sha256(access_token.encode()).hexdigest()
    access_token_other = f"atk_{secrets.token_urlsafe(24)}"
    access_hash_other = hashlib.sha256(access_token_other.encode()).hexdigest()
    refresh_token = f"rtk_{secrets.token_urlsafe(24)}"
    refresh_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    refresh_token_other = f"rtk_{secrets.token_urlsafe(24)}"
    refresh_hash_other = hashlib.sha256(refresh_token_other.encode()).hexdigest()
    service = f"dev.ownmesh.loopback-test.{uuid.uuid4().hex}"
    session_secret = secrets.token_hex(32)
    password = secrets.token_urlsafe(32)
    marker = f"ownmesh-e2-{uuid.uuid4().hex}"
    wrangler_process: subprocess.Popen[bytes] | None = None
    daemon_process: subprocess.Popen[bytes] | None = None

    with RetryingTemporaryDirectory(prefix="ownmesh-e2-workerd-") as temp_raw:
        temp = Path(temp_raw)
        persist = temp / "wrangler-state"
        config_dir = temp / "config"
        state_dir = temp / "state"
        runtime_dir = temp / "runtime"
        cache_dir = temp / "cache"
        fixture_bin_dir = temp / "e6-profile-bin"
        keystore_dir = state_dir / "keystore"
        workspace_dir = state_dir / "workspace"
        workspace_alt = state_dir / "workspace-alt"
        for directory in [
            persist,
            config_dir,
            state_dir,
            runtime_dir,
            cache_dir,
            keystore_dir,
            workspace_dir,
            workspace_alt,
            fixture_bin_dir,
        ]:
            directory.mkdir(parents=True, exist_ok=True)
        install_e6_profile_fixtures(fixture_bin_dir)
        # Device-local workspace registry (E4): default + alt roots for selection proof.
        (state_dir / "workspaces.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "workspaces": [
                        {
                            "id": "ws_default",
                            "root": str(workspace_dir.resolve()),
                            "label": "Default",
                        },
                        {
                            "id": "ws_alt",
                            "root": str(workspace_alt.resolve()),
                            "label": "Alt",
                        },
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

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
                    'display_name = "E2 workerd loopback"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        # full_user_access: no hidden path deny; writes/commands allowed without ask
        # (elevated still asks). Required so the loopback MCP path can prove side effects.
        (config_dir / "policy.toml").write_text(
            "\n".join(
                [
                    "schema_version = 1",
                    'preset = "full_user_access"',
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
        base_env["PATH"] = str(fixture_bin_dir) + os.pathsep + base_env.get("PATH", "")

        try:
            run_checked(
                [cargo, "build", "-p", "ownmeshd", "--bin", "ownmeshd", "--example", "e1_loopback_provision"],
                cwd=ROOT,
                env=base_env,
            )
            run_checked(
                [cargo, "build", "-p", "ownmesh-session-host", "--bin", "ownmesh-session-host"],
                cwd=ROOT,
                env=base_env,
            )
            public_key = run_checked(
                [cargo, "run", "-q", "-p", "ownmeshd", "--example", "e1_loopback_provision", "--", "provision"],
                cwd=ROOT,
                env=base_env,
                capture=True,
            )
            if len(public_key) != 64:
                raise RuntimeError("loopback provisioner returned an invalid public key")

            run_checked(
                wrangler(corepack, "d1", "migrations", "apply", "DB", "--local", "--persist-to", str(persist)),
                cwd=CONTROL_PLANE,
                env=base_env,
            )
            now = "2026-08-08T00:00:00.000Z"
            expires = "2099-01-01T00:00:00.000Z"
            scope = "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device offline_access"
            sql = " ".join(
                [
                    "INSERT OR IGNORE INTO tenants (id,name,created_at) VALUES ('ten_default','Default',"
                    + repr(now)
                    + ");",
                    "INSERT OR IGNORE INTO principals (id,tenant_id,kind,display_name,created_at) VALUES ('prin_dev','ten_default','human','Dev User',"
                    + repr(now)
                    + ");",
                    "INSERT OR IGNORE INTO principals (id,tenant_id,kind,display_name,created_at) VALUES ('prin_other','ten_default','human','Other User',"
                    + repr(now)
                    + ");",
                    "INSERT OR IGNORE INTO oauth_clients (client_id,tenant_id,client_name,redirect_uris,created_at) VALUES ("
                    + "'client_ownmesh_cli','ten_default','OwnMesh CLI',"
                    + repr(json.dumps(["http://127.0.0.1:8750/callback"]))
                    + ","
                    + repr(now)
                    + ");",
                    "INSERT OR IGNORE INTO tenant_members (tenant_id,principal_id,role,created_at) VALUES ('ten_default','prin_dev','owner',"
                    + repr(now)
                    + ");",
                    "INSERT OR IGNORE INTO tenant_members (tenant_id,principal_id,role,created_at) VALUES ('ten_default','prin_other','member',"
                    + repr(now)
                    + ");",
                    "INSERT INTO oauth_tokens (access_token_hash,refresh_token_hash,client_id,principal_id,scope,refresh_family,refresh_used,revoked,expires_at,created_at) VALUES ("
                    + repr(access_hash)
                    + ","
                    + repr(refresh_hash)
                    + ",'client_ownmesh_cli','prin_dev',"
                    + repr(scope)
                    + ",'fam_e2',0,0,"
                    + repr(expires)
                    + ","
                    + repr(now)
                    + ");",
                    "INSERT INTO oauth_tokens (access_token_hash,refresh_token_hash,client_id,principal_id,scope,refresh_family,refresh_used,revoked,expires_at,created_at) VALUES ("
                    + repr(access_hash_other)
                    + ","
                    + repr(refresh_hash_other)
                    + ",'client_ownmesh_cli','prin_other',"
                    + repr(scope)
                    + ",'fam_e2_other',0,0,"
                    + repr(expires)
                    + ","
                    + repr(now)
                    + ");",
                    "INSERT INTO devices (id,tenant_id,principal_id,name,public_key,revoked,created_at,status) VALUES ("
                    + repr(device_id)
                    + ",'ten_default','prin_dev','E2 binary',"
                    + repr(public_key)
                    + ",0,"
                    + repr(now)
                    + ",'active');",
                    "INSERT INTO device_credentials (credential_hash,device_id,tenant_id,principal_id,role,expires_at,revoked,created_at) VALUES ("
                    + repr(credential_hash)
                    + ","
                    + repr(device_id)
                    + ",'ten_default','prin_dev','agent',"
                    + repr(expires)
                    + ",0,"
                    + repr(now)
                    + ");",
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
            log_path = temp / "ownmeshd-0.log"
            daemon_process = start_daemon(binary, base_env, log_path)
            state0 = wait_for_ready(daemon_process, log_path)

            # Discovery through public MCP (control-plane local).
            listed = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_list_devices",
                    {},
                    rpc_id=1,
                )
            )
            if listed.get("status") != "completed":
                raise RuntimeError(f"list_devices failed: {listed}")
            devices = (listed.get("data") or {}).get("devices") if isinstance(listed.get("data"), dict) else None
            if not isinstance(devices, list) or not any(d.get("id") == device_id for d in devices if isinstance(d, dict)):
                raise RuntimeError(f"device {device_id} missing from list_devices: {listed}")

            # E4 cloud custody bootstrap for the two device-local roots used by
            # this real-path proof. MCP owns tenant/device/principal/version;
            # ownmeshd canonicalizes and upserts the corresponding local root.
            for rpc_id, workspace_id, workspace_path in (
                (96, "ws_default", workspace_dir),
                (97, "ws_alt", workspace_alt),
            ):
                ws_sc = structured(
                    mcp_call(
                        issuer,
                        access_token,
                        "ownmesh_workspace_add",
                        {
                            "device_id": device_id,
                            "id": workspace_id,
                            "path": str(workspace_path.resolve()),
                            "async": True,
                            "idempotency_key": f"idem_workspace_bootstrap_{workspace_id}_{marker}",
                        },
                        rpc_id=rpc_id,
                    )
                )
                ws_done = wait_operation(
                    issuer, access_token, str(ws_sc.get("operation_id") or ""), want={"completed"}
                )
                if workspace_id not in json.dumps(ws_done):
                    raise RuntimeError(f"workspace custody bootstrap failed: {ws_done}")
            # Explicit E4 collaboration grant: tenant membership alone is not a
            # workspace grant. The second principal used for E5 handoff gets
            # only the default-root membership, never implicit device-wide ACL.
            subprocess.run(
                wrangler(
                    corepack,
                    "d1",
                    "execute",
                    "DB",
                    "--local",
                    "--persist-to",
                    str(persist),
                    "--command",
                    "INSERT OR IGNORE INTO workspace_members (workspace_id,principal_id,created_at) VALUES ('ws_default','prin_other','2026-08-08T00:00:00.000Z');",
                ),
                cwd=CONTROL_PLANE,
                env=base_env,
                check=True,
                stdout=subprocess.DEVNULL,
            )

            # E6 real path: every official profile is discovered from the
            # daemon's actual PATH, then opened through public MCP → workerd →
            # Agent WSS → production ownmeshd. The fixture binaries are strict
            # protocol peers, not an alternate runtime implementation.
            profile_catalog_pending = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_list_profiles",
                    {"device_id": device_id, "limit": 16},
                    rpc_id=4000,
                )
            )
            profile_catalog = wait_operation(
                issuer,
                access_token,
                str(profile_catalog_pending.get("operation_id") or ""),
                want={"completed"},
            )
            profile_dump = json.dumps(profile_catalog)
            profile_ids = [
                "codex", "claude-code", "kimi-code", "opencode", "pi", "agy",
                "qwen-code", "hermes-agent", "qoder",
            ]
            for profile_id in profile_ids:
                if profile_id not in profile_dump:
                    raise RuntimeError(f"E6 live profile detection omitted {profile_id}: {profile_catalog}")

            e6_sessions: dict[str, tuple[str, str, int]] = {}
            for offset, profile_id in enumerate(profile_ids):
                started = time.monotonic()
                opened = structured(
                    mcp_call(
                        issuer,
                        access_token,
                        "ownmesh_session_open",
                        {
                            "device_id": device_id,
                            "workspace_id": "ws_default",
                            "title": f"e6-{profile_id}-{marker}",
                            "profile_id": profile_id,
                            "prompt": f"fixture prompt {profile_id}",
                            "adapter_mode": "structured",
                            "async": True,
                            "idempotency_key": f"idem_e6_{profile_id}_{marker}",
                        },
                        rpc_id=4010 + offset,
                    )
                )
                opened_done = wait_operation(
                    issuer, access_token, str(opened.get("operation_id") or ""), want={"completed"}
                )
                if profile_id == "codex" and time.monotonic() - started >= 3.15:
                    raise RuntimeError("E6 Codex open waited for delayed turn completion")
                session_id = session_id_from_operation(opened_done)
                lease_id = find_value(opened_done, "lease_id")
                controller_epoch = find_value(opened_done, "controller_epoch")
                if not isinstance(lease_id, str) or not isinstance(controller_epoch, int):
                    raise RuntimeError(f"E6 session open omitted exact controller facts: {opened_done}")
                e6_sessions[profile_id] = (session_id, lease_id, controller_epoch)

            # Profile show is also public-device routed. No adapter in this
            # test has a source-backed read-only credential probe, so the
            # production response must explicitly refuse credential discovery.
            profile_show = structured(
                mcp_call(
                    issuer, access_token, "ownmesh_profile_show",
                    {"device_id": device_id, "id": "codex", "async": True,
                     "idempotency_key": f"idem_e6_show_{marker}"}, rpc_id=4040,
                )
            )
            profile_show_done = wait_operation(
                issuer, access_token, str(profile_show.get("operation_id") or ""), want={"completed"}
            )
            if "unknown_no_credential_probe" not in json.dumps(profile_show_done):
                raise RuntimeError(f"E6 profile.show must not probe credentials: {profile_show_done}")

            # Every opened profile must yield its fixture's unique marker on
            # bounded public replay. This catches argv/frame failure even when
            # a structured session became open-ready before a child exits.
            output_markers = {
                "codex": "codex-delayed-output", "claude-code": "claude-code-output",
                "kimi-code": "kimi-code-output", "opencode": "opencode-output",
                "pi": "pi-output", "agy": "agy-output", "qwen-code": "qwen-code-output",
                "hermes-agent": "hermes-agent-output", "qoder": "qoder-output",
            }
            for index, profile_id in enumerate(profile_ids):
                replay_seen = False
                session_id, _, _ = e6_sessions[profile_id]
                for attempt in range(20):
                    replay = structured(
                        mcp_call(
                            issuer,
                            access_token,
                            "ownmesh_session_replay",
                            {
                                "device_id": device_id, "workspace_id": "ws_default",
                                "session_id": session_id, "sidecar_cursor": 0, "async": True,
                                "idempotency_key": f"idem_e6_{profile_id}_replay_{marker}_{attempt}",
                            },
                            rpc_id=4050 + index * 32 + attempt,
                        )
                    )
                    replay_done = wait_operation(
                        issuer, access_token, str(replay.get("operation_id") or ""), want={"completed"}
                    )
                    replay_dump = json.dumps(replay_done)
                    if output_markers[profile_id] in replay_dump or output_markers[profile_id].encode() in sidecar_bytes(replay_done):
                        if profile_id != "codex" or "delayed fixture error" in replay_dump:
                            replay_seen = True
                            break
                    time.sleep(0.25)
                if not replay_seen:
                    raise RuntimeError(f"E6 {profile_id} output/error was not visible through public replay")

            # Keep the real supervisor/session quotas bounded while proving the
            # second (resume) matrix. These exact terminal operations also
            # prove the initial profile sessions are not fixture leaks.
            for index, (profile_id, (session_id, lease_id, controller_epoch)) in enumerate(e6_sessions.items()):
                terminated = structured(
                    mcp_call(
                        issuer,
                        access_token,
                        "ownmesh_session_terminate",
                        {
                            "device_id": device_id, "workspace_id": "ws_default", "session_id": session_id,
                            "lease_id": lease_id, "controller_epoch": controller_epoch, "async": True,
                            "idempotency_key": f"idem_e6_{profile_id}_terminate_{marker}",
                        },
                        rpc_id=4350 + index,
                    )
                )
                wait_operation(
                    issuer, access_token, str(terminated.get("operation_id") or ""), want={"completed"}
                )

            # Resume paths are exercised through the same public route. The
            # fixture rejects either a missing prompt/stream-json Claude argv,
            # a double ACP load after Kimi/Hermes argv resume, or an invented
            # negotiated RPC method. Replay is deliberately required: a ready
            # operation alone cannot prove the child accepted its resume wire.
            resume_native_ids = {
                "codex": "native_codex",
                "claude-code": "native_claude_code",
                "kimi-code": "native_kimi_code",
                "opencode": "native_opencode",
                "qwen-code": "native_qwen_code",
                "hermes-agent": "native_hermes_agent",
                "qoder": "native_qoder",
            }
            e6_resumed: dict[str, tuple[str, str, int]] = {}
            for offset, (profile_id, native_session_id) in enumerate(resume_native_ids.items()):
                resumed = structured(
                    mcp_call(
                        issuer,
                        access_token,
                        "ownmesh_session_open",
                        {
                            "device_id": device_id,
                            "workspace_id": "ws_default",
                            "title": f"e6-resume-{profile_id}-{marker}",
                            "profile_id": profile_id,
                            "prompt": f"fixture resume {profile_id}",
                            "native_session_id": native_session_id,
                            "adapter_mode": "structured",
                            "async": True,
                            "idempotency_key": f"idem_e6_resume_{profile_id}_{marker}",
                        },
                        rpc_id=4200 + offset,
                    )
                )
                resumed_done = wait_operation(
                    issuer, access_token, str(resumed.get("operation_id") or ""), want={"completed"}
                )
                resumed_id = session_id_from_operation(resumed_done)
                lease_id = find_value(resumed_done, "lease_id")
                controller_epoch = find_value(resumed_done, "controller_epoch")
                if not isinstance(lease_id, str) or not isinstance(controller_epoch, int):
                    raise RuntimeError(f"E6 resumed {profile_id} omitted exact lease facts: {resumed_done}")
                e6_resumed[profile_id] = (resumed_id, lease_id, controller_epoch)

            for index, profile_id in enumerate(resume_native_ids):
                resumed_id, _, _ = e6_resumed[profile_id]
                marker_text = output_markers[profile_id]
                for attempt in range(20):
                    replay = structured(
                        mcp_call(
                            issuer, access_token, "ownmesh_session_replay",
                            {
                                "device_id": device_id, "workspace_id": "ws_default",
                                "session_id": resumed_id, "sidecar_cursor": 0, "async": True,
                                "idempotency_key": f"idem_e6_resume_replay_{profile_id}_{marker}_{attempt}",
                            },
                            rpc_id=4250 + index * 32 + attempt,
                        )
                    )
                    replay_done = wait_operation(
                        issuer, access_token, str(replay.get("operation_id") or ""), want={"completed"}
                    )
                    if marker_text in json.dumps(replay_done) or marker_text.encode() in sidecar_bytes(replay_done):
                        break
                    time.sleep(0.25)
                else:
                    raise RuntimeError(f"E6 native resume {profile_id} did not reach public replay")

            # Profiles whose official contracts have no resume surface must
            # reject an invented native id rather than silently starting a
            # different native conversation.
            for offset, profile_id in enumerate(("pi", "agy")):
                rejected = structured(
                    mcp_call(
                        issuer, access_token, "ownmesh_session_open",
                        {
                            "device_id": device_id, "workspace_id": "ws_default",
                            "profile_id": profile_id, "prompt": "must reject",
                            "native_session_id": "invented_native", "adapter_mode": "structured",
                            "async": True, "idempotency_key": f"idem_e6_reject_{profile_id}_{marker}",
                        },
                        rpc_id=4320 + offset,
                    )
                )
                rejected_done = wait_operation(
                    issuer, access_token, str(rejected.get("operation_id") or ""), want={"failed"}
                )
                if "no source-backed native resume" not in json.dumps(rejected_done):
                    raise RuntimeError(f"E6 {profile_id} accepted invented native id: {rejected_done}")

            for index, (profile_id, (session_id, lease_id, controller_epoch)) in enumerate(e6_resumed.items()):
                terminated = structured(
                    mcp_call(
                        issuer,
                        access_token,
                        "ownmesh_session_terminate",
                        {
                            "device_id": device_id, "workspace_id": "ws_default", "session_id": session_id,
                            "lease_id": lease_id, "controller_epoch": controller_epoch, "async": True,
                            "idempotency_key": f"idem_e6_resume_{profile_id}_terminate_{marker}",
                        },
                        rpc_id=4380 + index,
                    )
                )
                wait_operation(
                    issuer, access_token, str(terminated.get("operation_id") or ""), want={"completed"}
                )

            # Direct write via public MCP → DeviceRoom → real binary runtime.
            write_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_fs_write",
                    {
                        "device_id": device_id,
                        "path": "e2-marker.txt",
                        "content": marker,
                        "async": True,
                        "idempotency_key": f"idem_write_{marker}",
                    },
                    rpc_id=2,
                )
            )
            write_op = str(write_sc.get("operation_id") or "")
            if not write_op.startswith("op_"):
                raise RuntimeError(f"write missing operation_id: {write_sc}")
            if write_sc.get("correlation_id") not in (None, write_op) and write_sc.get("correlation_id") != write_op:
                raise RuntimeError(f"correlation_id must equal operation_id: {write_sc}")
            write_done = wait_operation(issuer, access_token, write_op, want={"completed"})
            on_disk = (workspace_dir / "e2-marker.txt").read_text(encoding="utf-8")
            if on_disk != marker:
                raise RuntimeError(f"workspace file mismatch: disk={on_disk!r} want={marker!r} op={write_done}")

            # Direct read of the same file through MCP.
            read_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_fs_read",
                    {
                        "device_id": device_id,
                        "path": "e2-marker.txt",
                        "async": True,
                        "idempotency_key": f"idem_read_{marker}",
                    },
                    rpc_id=3,
                )
            )
            read_op = str(read_sc.get("operation_id") or "")
            read_done = wait_operation(issuer, access_token, read_op, want={"completed"})
            read_data = read_done.get("data") if isinstance(read_done.get("data"), dict) else {}
            content = str(read_data.get("content") or "")
            if content != marker:
                raise RuntimeError(f"read content mismatch: {read_done}")

            # Structured command through the same production path, with a bound env fact.
            env_marker = f"E2ENV_{marker}"
            if os.name == "nt":
                program = "cmd.exe"
                args = ["/c", "echo", f"{marker}-%OWNMESH_E2_ENV%"]
            else:
                program = "/bin/sh"
                args = ["-c", f'printf "%s" "{marker}-$OWNMESH_E2_ENV"']
            cmd_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_command_run",
                    {
                        "device_id": device_id,
                        "program": program,
                        "args": args,
                        "env": {"OWNMESH_E2_ENV": env_marker},
                        "async": True,
                        "idempotency_key": f"idem_cmd_{marker}",
                    },
                    rpc_id=4,
                )
            )
            cmd_op = str(cmd_sc.get("operation_id") or "")
            cmd_done = wait_operation(issuer, access_token, cmd_op, want={"completed"})
            # Runtime nests RunResult under result for allow path; applyMcp flattens payload.result.
            dumped = json.dumps(cmd_done)
            if marker not in dumped:
                raise RuntimeError(f"command result missing marker: {cmd_done}")
            if env_marker not in dumped:
                raise RuntimeError(f"command result missing bound env marker: {cmd_done}")

            # Idempotent replay of the same write key must not rewrite after completion.
            # Restart binary and prove completed correlation is replayed, not re-executed.
            stop_process(daemon_process)
            daemon_process = None
            # Mutate on-disk content after first completion; a re-execution would overwrite.
            (workspace_dir / "e2-marker.txt").write_text(f"post-restart-{marker}", encoding="utf-8")

            log_path2 = temp / "ownmeshd-1.log"
            with log_path2.open("wb") as log:
                daemon_process = subprocess.Popen(
                    [str(binary), "run"],
                    cwd=ROOT,
                    env=base_env,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
                state1 = wait_for_ready(daemon_process, log_path2)

            if int(state1["next_outbound_seq"]) <= int(state0["next_outbound_seq"]):
                raise RuntimeError("outbound sequence did not advance across binary reconnect")
            if int(state1["last_server_seq"]) <= int(state0["last_server_seq"]):
                raise RuntimeError("server resume sequence did not advance across binary reconnect")

            # Re-issue the same idempotency key + byte-identical action. Control plane must
            # replay the prior authoritative row without re-dispatch (disk stays mutated).
            # Changed-content mismatch is asserted separately below (rpc_id=8).
            rewrite_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_fs_write",
                    {
                        "device_id": device_id,
                        "path": "e2-marker.txt",
                        "content": marker,
                        "async": True,
                        "idempotency_key": f"idem_write_{marker}",
                    },
                    rpc_id=5,
                )
            )
            rewrite_op = str(rewrite_sc.get("operation_id") or "")
            if rewrite_op != write_op:
                raise RuntimeError(
                    f"identical action should replay prior operation_id={write_op}, got {rewrite_op}"
                )
            if str(rewrite_sc.get("status") or "") != "completed":
                rewrite_done = wait_operation(issuer, access_token, rewrite_op, want={"completed"})
            else:
                rewrite_done = rewrite_sc
            after = (workspace_dir / "e2-marker.txt").read_text(encoding="utf-8")
            if after != f"post-restart-{marker}":
                raise RuntimeError(
                    f"idempotent write re-executed side effect: disk={after!r} op={rewrite_done}"
                )

            # Cancel path: start a long command and require terminal cancelled promptly.
            if os.name == "nt":
                long_program = "cmd.exe"
                long_args = ["/c", "ping", "-n", "60", "127.0.0.1"]
            else:
                long_program = "/bin/sleep"
                long_args = ["60"]
            long_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_command_run",
                    {
                        "device_id": device_id,
                        "program": long_program,
                        "args": long_args,
                        "async": True,
                        "idempotency_key": f"idem_long_{marker}",
                    },
                    rpc_id=6,
                )
            )
            long_op = str(long_sc.get("operation_id") or "")
            time.sleep(0.8)
            cancel_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_cancel_operation",
                    {"operation_id": long_op},
                    rpc_id=7,
                )
            )
            cancel_status = str(cancel_sc.get("status") or "")
            if cancel_status not in {"cancel_requested", "cancelled", "completed"}:
                raise RuntimeError(f"unexpected cancel status: {cancel_sc}")
            long_done = wait_operation(
                issuer,
                access_token,
                long_op,
                want={"cancelled", "failed", "completed"},
                timeout_s=20,
            )
            long_status = str(long_done.get("status") or "")
            if long_status not in {"cancelled", "failed"}:
                # completed only acceptable if the short window already finished; still fail closed.
                raise RuntimeError(
                    f"long command was not cancelled promptly: status={long_status} op={long_done}"
                )

            # E3: same idempotency key with different content must not reuse prior result.
            mismatch_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_fs_write",
                    {
                        "device_id": device_id,
                        "path": "e2-marker.txt",
                        "content": f"mismatched-action-{marker}",
                        "async": True,
                        "idempotency_key": f"idem_write_{marker}",
                    },
                    rpc_id=8,
                )
            )
            mismatch_status = str(mismatch_sc.get("status") or "")
            mismatch_data = mismatch_sc.get("data") or {}
            mismatch_err = (mismatch_data.get("error") or {}) if isinstance(mismatch_data, dict) else {}
            if mismatch_status != "failed" or str(mismatch_err.get("code") or "") != "OWNMESH_E_IDEMPOTENCY_MISMATCH":
                raise RuntimeError(
                    f"expected idempotency mismatch fail-closed, got: {mismatch_sc}"
                )

            # Binary retrieval: write non-UTF8 bytes via raw workspace then read through MCP.
            # Runtime must label encoding=base64 (RFC4648 padded) and preserve byte next_offset.
            binary_name = "e2-binary.bin"
            binary_bytes = bytes([0x00, 0xFF, 0x10, 0x80, 0xFE]) + marker.encode("utf-8") + bytes([0x01, 0x02])
            (workspace_dir / binary_name).write_bytes(binary_bytes)
            bin_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_fs_read",
                    {
                        "device_id": device_id,
                        "path": binary_name,
                        "offset": 0,
                        "max_bytes": 4,
                        "async": True,
                        "idempotency_key": f"idem_bin_{marker}",
                    },
                    rpc_id=9,
                )
            )
            bin_op = str(bin_sc.get("operation_id") or "")
            bin_done = wait_operation(issuer, access_token, bin_op, want={"completed"})
            bin_data = bin_done.get("data") if isinstance(bin_done.get("data"), dict) else {}
            if str(bin_data.get("encoding") or "") != "base64":
                raise RuntimeError(f"expected base64 encoding for binary read: {bin_done}")
            chunk = base64.b64decode(str(bin_data.get("content") or ""))
            if chunk != binary_bytes[:4]:
                raise RuntimeError(f"binary chunk mismatch: got={chunk!r} want={binary_bytes[:4]!r}")
            if int(bin_data.get("returned_bytes") or -1) != 4:
                raise RuntimeError(f"returned_bytes mismatch: {bin_done}")
            if int(bin_data.get("next_offset") or -1) != 4:
                raise RuntimeError(f"next_offset must be byte cursor 4: {bin_done}")
            next_cursor = bin_done.get("next_cursor")
            if next_cursor not in (None, "off_4") and str(next_cursor) != "off_4":
                # Prefer explicit off_N; tolerate null when only next_offset is present.
                if "cur_" in str(next_cursor):
                    raise RuntimeError(f"binary next_cursor must not be text cur_N: {bin_done}")

            # 512 KiB binary retrieval via multiple bounded public-MCP chunks (no rerun of a
            # single giant result; each hop stays under durable/Agent budgets).
            big_name = "e2-binary-512k.bin"
            big_bytes = bytes((i * 17 + 3) & 0xFF for i in range(512 * 1024))
            (workspace_dir / big_name).write_bytes(big_bytes)
            assembled = bytearray()
            offset = 0
            chunk_i = 0
            while offset < len(big_bytes):
                want = min(64 * 1024, len(big_bytes) - offset)
                page_sc = structured(
                    mcp_call(
                        issuer,
                        access_token,
                        "ownmesh_fs_read",
                        {
                            "device_id": device_id,
                            "path": big_name,
                            "offset": offset,
                            "max_bytes": want,
                            "async": True,
                            "idempotency_key": f"idem_bin512_{marker}_{chunk_i}",
                        },
                        rpc_id=100 + chunk_i,
                    )
                )
                page_op = str(page_sc.get("operation_id") or "")
                page_done = wait_operation(issuer, access_token, page_op, want={"completed"})
                page_data = page_done.get("data") if isinstance(page_done.get("data"), dict) else {}
                # Durable truncation must still expose cursor facts — never a bare wipe.
                if page_data.get("durable_truncated") is True and page_data.get("content") in (None, ""):
                    if page_data.get("next_offset") is None and page_done.get("next_cursor") is None:
                        raise RuntimeError(f"durable truncate dropped cursors: {page_done}")
                    raise RuntimeError(
                        f"single 64KiB chunk should fit durable budget without content loss: {page_done}"
                    )
                enc = str(page_data.get("encoding") or "")
                raw_content = str(page_data.get("content") or "")
                if enc == "base64":
                    piece = base64.b64decode(raw_content)
                elif enc in ("utf-8", "utf8", ""):
                    piece = raw_content.encode("utf-8")
                else:
                    raise RuntimeError(f"unexpected encoding on large binary page: {page_done}")
                if piece != big_bytes[offset : offset + len(piece)]:
                    raise RuntimeError(
                        f"512k chunk mismatch at offset={offset} got={len(piece)} bytes"
                    )
                assembled.extend(piece)
                returned = int(page_data.get("returned_bytes") or len(piece))
                if returned <= 0:
                    raise RuntimeError(f"no progress on 512k read at offset={offset}: {page_done}")
                nxt = page_data.get("next_offset")
                if nxt is None:
                    offset = offset + returned
                else:
                    offset = int(nxt)
                chunk_i += 1
                if chunk_i > 64:
                    raise RuntimeError("512k paging failed to terminate")
            if bytes(assembled) != big_bytes:
                raise RuntimeError(
                    f"512k assembled mismatch: got={len(assembled)} want={len(big_bytes)} "
                    f"sha_got={hashlib.sha256(assembled).hexdigest()[:16]} "
                    f"sha_want={hashlib.sha256(big_bytes).hexdigest()[:16]}"
                )

            # list / stat / delete through the same public MCP production path.
            (workspace_dir / "e2-list-a.txt").write_text("a", encoding="utf-8")
            (workspace_dir / "e2-list-b.txt").write_text("b", encoding="utf-8")
            list_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_fs_list",
                    {
                        "device_id": device_id,
                        "path": ".",
                        "async": True,
                        "idempotency_key": f"idem_list_{marker}",
                    },
                    rpc_id=20,
                )
            )
            list_op = str(list_sc.get("operation_id") or "")
            list_done = wait_operation(issuer, access_token, list_op, want={"completed"})
            list_dump = json.dumps(list_done)
            if "e2-list-a.txt" not in list_dump or "e2-list-b.txt" not in list_dump:
                raise RuntimeError(f"list missing entries: {list_done}")

            stat_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_fs_stat",
                    {
                        "device_id": device_id,
                        "path": "e2-list-a.txt",
                        "async": True,
                        "idempotency_key": f"idem_stat_{marker}",
                    },
                    rpc_id=21,
                )
            )
            stat_op = str(stat_sc.get("operation_id") or "")
            stat_done = wait_operation(issuer, access_token, stat_op, want={"completed"})
            stat_data = stat_done.get("data") if isinstance(stat_done.get("data"), dict) else {}
            if int(stat_data.get("size") or -1) != 1 and '"size":1' not in json.dumps(stat_done):
                # Runtime may nest under result; accept either shape via dump.
                if "e2-list-a.txt" not in json.dumps(stat_done):
                    raise RuntimeError(f"stat missing path/size: {stat_done}")

            del_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_fs_delete",
                    {
                        "device_id": device_id,
                        "path": "e2-list-b.txt",
                        "async": True,
                        "idempotency_key": f"idem_del_{marker}",
                    },
                    rpc_id=22,
                )
            )
            del_op = str(del_sc.get("operation_id") or "")
            wait_operation(issuer, access_token, del_op, want={"completed"})
            if (workspace_dir / "e2-list-b.txt").exists():
                raise RuntimeError("delete did not remove e2-list-b.txt on disk")

            # Hash-checked patch (ownmesh_fs_patch) through the same production path.
            patch_path = "e2-patch.txt"
            (workspace_dir / patch_path).write_text("before-patch", encoding="utf-8")
            expected_hash = hashlib.sha256(b"before-patch").hexdigest()
            patch_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_fs_patch",
                    {
                        "device_id": device_id,
                        "path": patch_path,
                        "content": f"after-patch-{marker}",
                        "expected_sha256": expected_hash,
                        "async": True,
                        "idempotency_key": f"idem_patch_{marker}",
                    },
                    rpc_id=30,
                )
            )
            patch_op = str(patch_sc.get("operation_id") or "")
            patch_done = wait_operation(issuer, access_token, patch_op, want={"completed"})
            on_disk_patch = (workspace_dir / patch_path).read_text(encoding="utf-8")
            if on_disk_patch != f"after-patch-{marker}":
                raise RuntimeError(f"patch did not update disk: {on_disk_patch!r} op={patch_done}")
            # Stale expected hash must fail closed (no overwrite).
            bad_patch_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_fs_patch",
                    {
                        "device_id": device_id,
                        "path": patch_path,
                        "content": "should-not-apply",
                        "expected_sha256": expected_hash,
                        "async": True,
                        "idempotency_key": f"idem_patch_bad_{marker}",
                    },
                    rpc_id=31,
                )
            )
            bad_patch_op = str(bad_patch_sc.get("operation_id") or "")
            bad_patch_done = wait_operation(
                issuer, access_token, bad_patch_op, want={"failed", "denied"}, timeout_s=20
            )
            if (workspace_dir / patch_path).read_text(encoding="utf-8") != f"after-patch-{marker}":
                raise RuntimeError(f"stale patch overwrote file: {bad_patch_done}")

            # Raw shell is a separately authorized action from structured command.
            if os.name == "nt":
                shell_cmd = f"echo shell-{marker}"
            else:
                shell_cmd = f'printf "%s" "shell-{marker}"'
            shell_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_command_shell",
                    {
                        "device_id": device_id,
                        "command": shell_cmd,
                        "async": True,
                        "idempotency_key": f"idem_shell_{marker}",
                    },
                    rpc_id=32,
                )
            )
            shell_op = str(shell_sc.get("operation_id") or "")
            shell_done = wait_operation(issuer, access_token, shell_op, want={"completed"})
            if f"shell-{marker}" not in json.dumps(shell_done):
                raise RuntimeError(f"raw shell result missing marker: {shell_done}")

            # E4 workspace selection: write into alt root; default root must not see it.
            alt_marker = f"alt-{marker}"
            alt_write = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_fs_write",
                    {
                        "device_id": device_id,
                        "workspace_id": "ws_alt",
                        "path": "alt-only.txt",
                        "content": alt_marker,
                        "async": True,
                        "idempotency_key": f"idem_ws_alt_{marker}",
                    },
                    rpc_id=33,
                )
            )
            alt_op = str(alt_write.get("operation_id") or "")
            wait_operation(issuer, access_token, alt_op, want={"completed"})
            if not (workspace_alt / "alt-only.txt").is_file():
                raise RuntimeError("alt workspace write missing on disk")
            if (workspace_dir / "alt-only.txt").exists():
                raise RuntimeError("alt write leaked into default workspace root")
            cross_read = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_fs_read",
                    {
                        "device_id": device_id,
                        "workspace_id": "ws_default",
                        "path": "alt-only.txt",
                        "async": True,
                        "idempotency_key": f"idem_ws_cross_{marker}",
                    },
                    rpc_id=34,
                )
            )
            cross_op = str(cross_read.get("operation_id") or "")
            cross_done = wait_operation(
                issuer, access_token, cross_op, want={"failed", "denied", "completed"}, timeout_s=20
            )
            cross_dump = json.dumps(cross_done)
            if alt_marker in cross_dump and str(cross_done.get("status")) == "completed":
                raise RuntimeError(f"cross-workspace read returned alt content: {cross_done}")
            if str(cross_done.get("status")) == "completed":
                # completed empty/not-found is also acceptable fail-closed surface
                cross_data = cross_done.get("data") if isinstance(cross_done.get("data"), dict) else {}
                content = str(cross_data.get("content") or "")
                if content:
                    raise RuntimeError(f"cross-workspace read leaked content: {cross_done}")
            # Positive control: alt workspace reads its own file.
            alt_read = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_fs_read",
                    {
                        "device_id": device_id,
                        "workspace_id": "ws_alt",
                        "path": "alt-only.txt",
                        "async": True,
                        "idempotency_key": f"idem_ws_alt_read_{marker}",
                    },
                    rpc_id=35,
                )
            )
            alt_read_op = str(alt_read.get("operation_id") or "")
            alt_read_done = wait_operation(issuer, access_token, alt_read_op, want={"completed"})
            if alt_marker not in json.dumps(alt_read_done):
                raise RuntimeError(f"alt workspace read missed content: {alt_read_done}")
            # Unknown workspace_id fails closed.
            bad_ws = mcp_expect_rejected(
                issuer,
                access_token,
                "ownmesh_fs_list",
                {
                    "device_id": device_id,
                    "workspace_id": "ws_does_not_exist",
                    "path": ".",
                    "async": True,
                    "idempotency_key": f"idem_ws_bad_{marker}",
                },
                rpc_id=36,
            )
            if "workspace_not_available" not in json.dumps(bad_ws).lower():
                raise RuntimeError(f"unknown workspace_id must reject before routing: {bad_ws}")

            # E5 session open via public MCP with a real live PTY host in ownmeshd.
            # E4: workspace_id is bound onto the session record at open.
            import sys as _sys
            if _sys.platform.startswith("win"):
                ses_program = "cmd.exe"
                ses_args = ["/Q", "/C", f"echo E5_LIVE_PTY_{marker}"]
            else:
                ses_program = "/bin/sh"
                ses_args = ["-c", f"printf 'E5_LIVE_PTY_{marker}\\n'"]
            ses_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_open",
                    {
                        "device_id": device_id,
                        "title": f"e2-ses-{marker}",
                        "workspace_id": "ws_default",
                        "program": ses_program,
                        "args": ses_args,
                        "async": True,
                        "idempotency_key": f"idem_ses_{marker}",
                    },
                    rpc_id=37,
                )
            )
            ses_op = str(ses_sc.get("operation_id") or "")
            ses_done = wait_operation(issuer, access_token, ses_op, want={"completed"})
            ses_dump = json.dumps(ses_done)
            if "ses_" not in ses_dump:
                raise RuntimeError(f"session open missing session id: {ses_done}")
            if "ws_default" not in ses_dump:
                raise RuntimeError(
                    f"session open must persist workspace_id binding: {ses_done}"
                )
            if "live_pty" not in ses_dump.lower() and "\"live_pty\":true" not in ses_dump.lower().replace(" ", ""):
                # Accept host_pid presence as evidence of a live host when live_pty flag is nested.
                if "host_pid" not in ses_dump and "pty_" not in ses_dump:
                    raise RuntimeError(f"session open must report live PTY host: {ses_done}")
            # Extract session id from completed result payload.
            ses_id = None
            for node in (ses_done, ses_done.get("data") if isinstance(ses_done.get("data"), dict) else {}):
                if not isinstance(node, dict):
                    continue
                for key in ("id", "session_id"):
                    val = node.get(key)
                    if isinstance(val, str) and val.startswith("ses_"):
                        ses_id = val
                        break
                if ses_id:
                    break
                nested = node.get("session") if isinstance(node.get("session"), dict) else None
                if nested and isinstance(nested.get("id"), str) and nested["id"].startswith("ses_"):
                    ses_id = nested["id"]
                    break
            if not ses_id:
                # Fallback: scan dump for ses_ token.
                import re as _re
                m = _re.search(r"ses_[0-9a-fA-F]+", ses_dump)
                if not m:
                    raise RuntimeError(f"could not parse session id from {ses_done}")
                ses_id = m.group(0)

            # E5: replay must surface real process output from the live PTY host.
            import time as _time
            live_marker = f"E5_LIVE_PTY_{marker}"
            saw_live = live_marker in ses_dump or live_marker.encode() in sidecar_bytes(ses_done)
            if not saw_live:
                for attempt in range(12):
                    rep_sc = structured(
                        mcp_call(
                            issuer,
                            access_token,
                            "ownmesh_session_replay",
                            {
                                "device_id": device_id,
                                "session_id": ses_id,
                                "workspace_id": "ws_default",
                                "from_seq": 1,
                                "async": True,
                                "idempotency_key": f"idem_ses_rep_{marker}_{attempt}",
                            },
                            rpc_id=40 + attempt,
                        )
                    )
                    rep_op = str(rep_sc.get("operation_id") or "")
                    rep_done = wait_operation(issuer, access_token, rep_op, want={"completed"})
                    if live_marker in json.dumps(rep_done) or live_marker.encode() in sidecar_bytes(rep_done):
                        saw_live = True
                        break
                    _time.sleep(0.25)
            if not saw_live:
                raise RuntimeError(
                    f"live PTY session must produce real process output containing {live_marker}"
                )

            # E5 multi-observer: the explicitly workspace-granted second
            # principal attaches read-only to the same live process and receives
            # its bounded replay. It cannot acquire controller implicitly.
            other_obs_sc = structured(
                mcp_call(
                    issuer,
                    access_token_other,
                    "ownmesh_session_attach",
                    {
                        "device_id": device_id,
                        "session_id": ses_id,
                        "role": "observer",
                        "workspace_id": "ws_default",
                        "async": True,
                        "idempotency_key": f"idem_ses_other_obs_{marker}",
                    },
                    rpc_id=98,
                )
            )
            other_obs_done = wait_operation(
                issuer, access_token_other, str(other_obs_sc.get("operation_id") or ""), want={"completed"}
            )
            if "observer" not in json.dumps(other_obs_done).lower():
                raise RuntimeError(f"second principal observer attach failed: {other_obs_done}")
            other_rep_sc = structured(
                mcp_call(
                    issuer,
                    access_token_other,
                    "ownmesh_session_replay",
                    {
                        "device_id": device_id,
                        "session_id": ses_id,
                        "workspace_id": "ws_default",
                        "from_seq": 1,
                        "max_chunks": 1,
                        "async": True,
                        "idempotency_key": f"idem_ses_other_replay_{marker}",
                    },
                    rpc_id=99,
                )
            )
            other_rep_done = wait_operation(
                issuer, access_token_other, str(other_rep_sc.get("operation_id") or ""), want={"completed"}
            )
            other_rep_dump = json.dumps(other_rep_done)
            if live_marker not in other_rep_dump and live_marker.encode() not in sidecar_bytes(other_rep_done):
                raise RuntimeError(f"observer replay must expose live process output: {other_rep_done}")

            # Second session for observer lease checks (interactive shell).
            lease_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_open",
                    {
                        "device_id": device_id,
                        "title": f"e2-ses-lease-{marker}",
                        "workspace_id": "ws_default",
                        "async": True,
                        "idempotency_key": f"idem_ses_lease_{marker}",
                    },
                    rpc_id=55,
                )
            )
            lease_op = str(lease_sc.get("operation_id") or "")
            lease_done = wait_operation(issuer, access_token, lease_op, want={"completed"})
            lease_dump = json.dumps(lease_done)
            import re as _re2
            m2 = _re2.search(r"ses_[0-9a-fA-F]+", lease_dump)
            if not m2:
                raise RuntimeError(f"could not parse lease session id from {lease_done}")
            lease_ses_id = m2.group(0)

            # E5: observer attach must not retain controller rights (exact-action).
            obs_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_attach",
                    {
                        "device_id": device_id,
                        "session_id": lease_ses_id,
                        "role": "observer",
                        "workspace_id": "ws_default",
                        "async": True,
                        "idempotency_key": f"idem_ses_obs_{marker}",
                    },
                    rpc_id=38,
                )
            )
            obs_op = str(obs_sc.get("operation_id") or "")
            obs_done = wait_operation(issuer, access_token, obs_op, want={"completed"})
            obs_dump = json.dumps(obs_done).lower()
            if "observer" not in obs_dump and '"read_only": true' not in obs_dump and '"read_only":true' not in obs_dump:
                raise RuntimeError(f"observer attach must report observer/read_only: {obs_done}")

            # Observer must not be able to write stdin / resize.
            bad_write = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_write",
                    {
                        "device_id": device_id,
                        "session_id": lease_ses_id,
                        "workspace_id": "ws_default",
                        "data": "should-deny",
                        "input_seq": 1,
                        "async": True,
                        "idempotency_key": f"idem_ses_write_obs_{marker}",
                    },
                    rpc_id=39,
                )
            )
            bad_write_op = str(bad_write.get("operation_id") or "")
            bad_write_done = wait_operation(
                issuer, access_token, bad_write_op, want={"failed", "denied"}, timeout_s=20
            )
            if str(bad_write_done.get("status")) not in {"failed", "denied"}:
                raise RuntimeError(f"observer session.write must fail closed: {bad_write_done}")

            # Mismatched workspace_id on session write must fail closed.
            bad_ws_write = mcp_expect_rejected(
                issuer,
                access_token,
                "ownmesh_session_write",
                {
                    "device_id": device_id,
                    "session_id": lease_ses_id,
                    "workspace_id": "ws_does_not_match",
                    "data": "x",
                    "input_seq": 1,
                    "async": True,
                    "idempotency_key": f"idem_ses_ws_mismatch_{marker}",
                },
                rpc_id=56,
            )
            if "workspace_not_available" not in json.dumps(bad_ws_write).lower():
                raise RuntimeError(
                    f"session.write workspace mismatch must reject before routing: {bad_ws_write}"
                )

            # E4: session list/show must bind workspace — alt session is invisible under default.
            alt_ses_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_open",
                    {
                        "device_id": device_id,
                        "title": f"e2-ses-alt-{marker}",
                        "workspace_id": "ws_alt",
                        "async": True,
                        "idempotency_key": f"idem_ses_alt_{marker}",
                    },
                    rpc_id=57,
                )
            )
            alt_ses_op = str(alt_ses_sc.get("operation_id") or "")
            alt_ses_done = wait_operation(issuer, access_token, alt_ses_op, want={"completed"})
            alt_ses_dump = json.dumps(alt_ses_done)
            m_alt = _re2.search(r"ses_[0-9a-fA-F]+", alt_ses_dump)
            if not m_alt:
                raise RuntimeError(f"could not parse alt session id from {alt_ses_done}")
            alt_ses_id = m_alt.group(0)

            list_default_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_list",
                    {
                        "device_id": device_id,
                        "workspace_id": "ws_default",
                        "async": True,
                        "idempotency_key": f"idem_ses_list_def_{marker}",
                    },
                    rpc_id=58,
                )
            )
            list_default_done = wait_operation(
                issuer, access_token, str(list_default_sc.get("operation_id") or ""), want={"completed"}
            )
            list_default_dump = json.dumps(list_default_done)
            if alt_ses_id in list_default_dump:
                raise RuntimeError(
                    f"session.list(ws_default) must not expose alt workspace session: {list_default_done}"
                )

            bad_show_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_show",
                    {
                        "device_id": device_id,
                        "session_id": alt_ses_id,
                        "workspace_id": "ws_default",
                        "async": True,
                        "idempotency_key": f"idem_ses_show_mismatch_{marker}",
                    },
                    rpc_id=59,
                )
            )
            bad_show_done = wait_operation(
                issuer,
                access_token,
                str(bad_show_sc.get("operation_id") or ""),
                want={"failed", "denied"},
                timeout_s=20,
            )
            if str(bad_show_done.get("status")) not in {"failed", "denied"}:
                raise RuntimeError(
                    f"session.show cross-workspace must fail closed: {bad_show_done}"
                )

            # E5: ordered controller input_seq — gap/stale rejected; seq=1 then 2 accepted.
            # Open a short-lived interactive shell for write/resize sequence proof.
            if _sys.platform.startswith("win"):
                seq_program = "cmd.exe"
                seq_args = ["/K"]
            else:
                seq_program = "/bin/sh"
                seq_args = []
            seq_open_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_open",
                    {
                        "device_id": device_id,
                        "title": f"e2-ses-seq-{marker}",
                        "workspace_id": "ws_default",
                        "program": seq_program,
                        "args": seq_args,
                        "async": True,
                        "idempotency_key": f"idem_ses_seq_open_{marker}",
                    },
                    rpc_id=60,
                )
            )
            seq_open_done = wait_operation(
                issuer, access_token, str(seq_open_sc.get("operation_id") or ""), want={"completed"}
            )
            m_seq = _re2.search(r"ses_[0-9a-fA-F]+", json.dumps(seq_open_done))
            if not m_seq:
                raise RuntimeError(f"could not parse seq session id from {seq_open_done}")
            seq_ses_id = m_seq.group(0)
            seq_dump = json.dumps(seq_open_done)
            seq_lease = _re2.search(r"lease_[0-9a-fA-F]+", seq_dump)
            seq_epoch = _re2.search(r'"epoch"\s*:\s*(\d+)', seq_dump)
            if not seq_lease or not seq_epoch:
                raise RuntimeError(f"session.open must return controller lease token+epoch: {seq_open_done}")
            seq_lease_id = seq_lease.group(0)
            seq_controller_epoch = int(seq_epoch.group(1))

            # Gap: input_seq=2 before 1 must fail.
            gap_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_write",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "data": "gap\n",
                        "input_seq": 2,
                        "async": True,
                        "idempotency_key": f"idem_ses_seq_gap_{marker}",
                    },
                    rpc_id=61,
                )
            )
            gap_done = wait_operation(
                issuer,
                access_token,
                str(gap_sc.get("operation_id") or ""),
                want={"failed", "denied"},
                timeout_s=20,
            )
            if str(gap_done.get("status")) not in {"failed", "denied"}:
                raise RuntimeError(f"input_seq gap must fail closed: {gap_done}")

            restart_marker = f"E5_RESTART_CONTINUITY_{marker}"
            restart_command = f"echo {restart_marker}\n"
            w1_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_write",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "data": restart_command,
                        "input_seq": 1,
                        "lease_id": seq_lease_id,
                        "controller_epoch": seq_controller_epoch,
                        "async": True,
                        "idempotency_key": f"idem_ses_seq_w1_{marker}",
                    },
                    rpc_id=62,
                )
            )
            w1_done = wait_operation(
                issuer, access_token, str(w1_sc.get("operation_id") or ""), want={"completed"}
            )
            if "accepted" not in json.dumps(w1_done).lower() and str(w1_done.get("status")) != "completed":
                raise RuntimeError(f"input_seq=1 write must complete: {w1_done}")

            # E5 persistent-supervisor acceptance: kill only ownmeshd/Agent,
            # leaving the detached sidecar and its PTY alive. A fresh Agent
            # connection must reattach the same host without spawning another.
            show_before_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_show",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "async": True,
                        "idempotency_key": f"idem_ses_restart_show_before_{marker}",
                    },
                    rpc_id=620,
                )
            )
            show_before = wait_operation(
                issuer, access_token, str(show_before_sc.get("operation_id") or ""), want={"completed"}
            )
            before_pid = find_value(show_before, "host_pid")
            if not isinstance(before_pid, int) or before_pid <= 0:
                raise RuntimeError(f"persistent session must expose host_pid before daemon restart: {show_before}")

            stop_daemon_only(daemon_process)
            log_path = temp / "ownmeshd-restart.log"
            daemon_process = start_daemon(binary, base_env, log_path)
            wait_for_ready(daemon_process, log_path)

            show_after_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_show",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "async": True,
                        "idempotency_key": f"idem_ses_restart_show_after_{marker}",
                    },
                    rpc_id=621,
                )
            )
            show_after = wait_operation(
                issuer, access_token, str(show_after_sc.get("operation_id") or ""), want={"completed"}, timeout_s=45.0
            )
            restart_replay_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_replay",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "from_seq": 1,
                        "sidecar_cursor": 0,
                        "max_bytes": 1024,
                        "async": True,
                        "idempotency_key": f"idem_ses_restart_replay_{marker}",
                    },
                    rpc_id=622,
                )
            )
            restart_replay = wait_operation(
                issuer, access_token, str(restart_replay_sc.get("operation_id") or ""), want={"completed"}, timeout_s=45.0
            )
            if restart_marker.encode() not in sidecar_bytes(restart_replay):
                raise RuntimeError(
                    f"sidecar cursor replay must retain pre-restart PTY output: {restart_replay}"
                )
            # The replay above lazy-bootstraps the supervisor and reattaches its
            # exact host binding. Verify the reattached status is now durable
            # and reports the same process, not a replacement PTY.
            show_reattached_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_show",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "async": True,
                        "idempotency_key": f"idem_ses_restart_show_reattached_{marker}",
                    },
                    rpc_id=623,
                )
            )
            show_reattached = wait_operation(
                issuer, access_token, str(show_reattached_sc.get("operation_id") or ""), want={"completed"}
            )
            after_pid = find_value(show_reattached, "host_pid")
            if after_pid != before_pid:
                raise RuntimeError(
                    f"sidecar reattach must retain the exact PTY PID across daemon restart: before={before_pid} after={after_pid}"
                )

            # Stale replay of seq=1 must fail (outer idempotency key differs).
            stale_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_write",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "data": "stale\n",
                        "input_seq": 1,
                        "async": True,
                        "idempotency_key": f"idem_ses_seq_stale_{marker}",
                    },
                    rpc_id=63,
                )
            )
            stale_done = wait_operation(
                issuer,
                access_token,
                str(stale_sc.get("operation_id") or ""),
                want={"failed", "denied"},
                timeout_s=20,
            )
            if str(stale_done.get("status")) not in {"failed", "denied"}:
                raise RuntimeError(f"stale input_seq must fail closed: {stale_done}")

            w2_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_write",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "data": "second\n",
                        "input_seq": 2,
                        "lease_id": seq_lease_id,
                        "controller_epoch": seq_controller_epoch,
                        "async": True,
                        "idempotency_key": f"idem_ses_seq_w2_{marker}",
                    },
                    rpc_id=64,
                )
            )
            w2_done = wait_operation(
                issuer, access_token, str(w2_sc.get("operation_id") or ""), want={"completed"}
            )
            if str(w2_done.get("status")) != "completed":
                raise RuntimeError(f"input_seq=2 write must complete: {w2_done}")

            rz_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_resize",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "cols": 100,
                        "rows": 30,
                        "resize_seq": 1,
                        "lease_id": seq_lease_id,
                        "controller_epoch": seq_controller_epoch,
                        "async": True,
                        "idempotency_key": f"idem_ses_rz1_{marker}",
                    },
                    rpc_id=65,
                )
            )
            rz_done = wait_operation(
                issuer, access_token, str(rz_sc.get("operation_id") or ""), want={"completed"}
            )
            if str(rz_done.get("status")) != "completed":
                raise RuntimeError(f"resize_seq=1 must complete: {rz_done}")

            # E3/E5: second tenant member is not controller until give; cannot write.
            other_write_sc = structured(
                mcp_call(
                    issuer,
                    access_token_other,
                    "ownmesh_session_write",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "data": "intruder\n",
                        "input_seq": 3,
                        "async": True,
                        "idempotency_key": f"idem_ses_other_write_{marker}",
                    },
                    rpc_id=66,
                )
            )
            other_write_done = wait_operation(
                issuer,
                access_token_other,
                str(other_write_sc.get("operation_id") or ""),
                want={"failed", "denied"},
                timeout_s=20,
            )
            if str(other_write_done.get("status")) not in {"failed", "denied"}:
                raise RuntimeError(
                    f"non-controller principal must not write session: {other_write_done}"
                )

            # Cross-principal operation get must not leak owner's op result.
            foreign_status, foreign_body = http_json(
                f"{issuer}/mcp",
                method="POST",
                headers={"authorization": f"Bearer {access_token_other}"},
                body={
                    "jsonrpc": "2.0",
                    "id": 67,
                    "method": "tools/call",
                    "params": {
                        "name": "ownmesh_get_operation",
                        "arguments": {"operation_id": ses_op},
                    },
                },
            )
            if foreign_status != 200:
                raise RuntimeError(f"foreign get_operation HTTP {foreign_status}: {foreign_body}")
            foreign_dump = json.dumps(foreign_body).lower()
            if "e5_live_pty" in foreign_dump or (
                isinstance(foreign_body, dict)
                and "completed" in foreign_dump
                and ses_id
                and ses_id.lower() in foreign_dump
            ):
                # Accept only explicit not-found / denied shapes.
                if "not found" not in foreign_dump and "denied" not in foreign_dump and "failed" not in foreign_dump:
                    raise RuntimeError(
                        f"cross-principal get_operation must not leak owner result: {foreign_body}"
                    )

            give_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_give",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "to": "prin_other",
                        "lease_id": seq_lease_id,
                        "controller_epoch": seq_controller_epoch,
                        "async": True,
                        "idempotency_key": f"idem_ses_give_{marker}",
                    },
                    rpc_id=68,
                )
            )
            give_done = wait_operation(
                issuer, access_token, str(give_sc.get("operation_id") or ""), want={"completed"}
            )
            if str(give_done.get("status")) != "completed":
                raise RuntimeError(f"session.give to member must complete: {give_done}")
            give_dump = json.dumps(give_done)
            other_lease = _re2.search(r"lease_[0-9a-fA-F]+", give_dump)
            other_epoch = _re2.search(r'"epoch"\s*:\s*(\d+)', give_dump)
            if not other_lease or not other_epoch:
                raise RuntimeError(f"session.give must return new lease token+epoch: {give_done}")
            other_lease_id = other_lease.group(0)
            other_controller_epoch = int(other_epoch.group(1))

            # After handoff, former controller cannot write; new controller can (seq continues).
            owner_after_give_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_write",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "data": "owner-after\n",
                        "input_seq": 3,
                        "lease_id": other_lease_id,
                        "controller_epoch": other_controller_epoch,
                        "async": True,
                        "idempotency_key": f"idem_ses_owner_after_{marker}",
                    },
                    rpc_id=69,
                )
            )
            owner_after_give_done = wait_operation(
                issuer,
                access_token,
                str(owner_after_give_sc.get("operation_id") or ""),
                want={"failed", "denied"},
                timeout_s=20,
            )
            if str(owner_after_give_done.get("status")) not in {"failed", "denied"}:
                raise RuntimeError(
                    f"former controller must lose write after give: {owner_after_give_done}"
                )

            other_ctrl_sc = structured(
                mcp_call(
                    issuer,
                    access_token_other,
                    "ownmesh_session_write",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "data": "member-ctrl\n",
                        "input_seq": 3,
                        "lease_id": other_lease_id,
                        "controller_epoch": other_controller_epoch,
                        "async": True,
                        "idempotency_key": f"idem_ses_other_ctrl_{marker}",
                    },
                    rpc_id=70,
                )
            )
            other_ctrl_done = wait_operation(
                issuer,
                access_token_other,
                str(other_ctrl_sc.get("operation_id") or ""),
                want={"completed"},
            )
            if str(other_ctrl_done.get("status")) != "completed":
                raise RuntimeError(
                    f"handoff recipient must write with next input_seq: {other_ctrl_done}"
                )

            # E5 stale-connection regression: the old principal/seat cannot
            # claim, attach-as-controller, legacy-release, or hand off the
            # successor seat. Each call still traverses public MCP/Worker/DO.
            stale_calls = [
                ("ownmesh_session_claim", {"session_id": seq_ses_id}),
                ("ownmesh_session_attach", {"session_id": seq_ses_id, "role": "controller"}),
                ("ownmesh_session_release", {"session_id": seq_ses_id}),
                (
                    "ownmesh_session_give",
                    {
                        "session_id": seq_ses_id,
                        "to": "prin_other",
                        "lease_id": seq_lease_id,
                        "controller_epoch": seq_controller_epoch,
                    },
                ),
            ]
            for stale_i, (stale_tool, stale_args) in enumerate(stale_calls, start=71):
                stale_args = {
                    "device_id": device_id,
                    "workspace_id": "ws_default",
                    "async": True,
                    "idempotency_key": f"idem_ses_stale_{stale_tool}_{marker}",
                    **stale_args,
                }
                stale_sc = structured(
                    mcp_call(issuer, access_token, stale_tool, stale_args, rpc_id=stale_i)
                )
                stale_done = wait_operation(
                    issuer,
                    access_token,
                    str(stale_sc.get("operation_id") or ""),
                    want={"failed", "denied"},
                    timeout_s=20,
                )
                if str(stale_done.get("status")) not in {"failed", "denied"}:
                    raise RuntimeError(
                        f"stale same-principal {stale_tool} must fail closed: {stale_done}"
                    )

            # Exact detach retains the PTY while clearing the seat. The prior
            # token must not mutate, renew, or detach after the transition.
            detach_sc = structured(
                mcp_call(
                    issuer,
                    access_token_other,
                    "ownmesh_session_detach",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "lease_id": other_lease_id,
                        "controller_epoch": other_controller_epoch,
                        "async": True,
                        "idempotency_key": f"idem_ses_detach_{marker}",
                    },
                    rpc_id=75,
                )
            )
            detach_done = wait_operation(
                issuer, access_token_other, str(detach_sc.get("operation_id") or ""), want={"completed"}
            )
            if str(detach_done.get("status")) != "completed":
                raise RuntimeError(f"exact session.detach must complete: {detach_done}")

            for stale_i, stale_tool, stale_args in [
                (76, "ownmesh_session_write", {"data": "old\n", "input_seq": 4}),
                (77, "ownmesh_session_resize", {"cols": 101, "rows": 31, "resize_seq": 2}),
                (78, "ownmesh_session_renew", {"ttl_secs": 60}),
                (79, "ownmesh_session_detach", {}),
            ]:
                stale_sc = structured(
                    mcp_call(
                        issuer,
                        access_token_other,
                        stale_tool,
                        {
                            "device_id": device_id,
                            "session_id": seq_ses_id,
                            "workspace_id": "ws_default",
                            "lease_id": other_lease_id,
                            "controller_epoch": other_controller_epoch,
                            "async": True,
                            "idempotency_key": f"idem_ses_old_{stale_tool}_{marker}",
                            **stale_args,
                        },
                        rpc_id=stale_i,
                    )
                )
                stale_done = wait_operation(
                    issuer,
                    access_token_other,
                    str(stale_sc.get("operation_id") or ""),
                    want={"failed", "denied"},
                    timeout_s=20,
                )
                if str(stale_done.get("status")) not in {"failed", "denied"}:
                    raise RuntimeError(
                        f"old lease {stale_tool} must fail closed after detach: {stale_done}"
                    )

            reclaim_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_claim",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "async": True,
                        "idempotency_key": f"idem_ses_reclaim_{marker}",
                    },
                    rpc_id=80,
                )
            )
            reclaim_done = wait_operation(
                issuer, access_token, str(reclaim_sc.get("operation_id") or ""), want={"completed"}
            )
            reclaim_dump = json.dumps(reclaim_done)
            reclaim_lease_m = _re2.search(r"lease_[0-9a-fA-F]+", reclaim_dump)
            reclaim_epoch_m = _re2.search(r'"epoch"\s*:\s*(\d+)', reclaim_dump)
            if (
                not reclaim_lease_m
                or not reclaim_epoch_m
                or int(reclaim_epoch_m.group(1)) <= other_controller_epoch
            ):
                raise RuntimeError(f"detach reclaim must increment controller epoch: {reclaim_done}")
            reclaim_lease_id = reclaim_lease_m.group(0)
            reclaim_epoch = int(reclaim_epoch_m.group(1))

            # Natural lease expiry is a second recovery path: a one-second
            # renewal expires without a disconnect, its old exact token cannot
            # renew, and the retained reader can reclaim a newer epoch.
            short_renew_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_renew",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "lease_id": reclaim_lease_id,
                        "controller_epoch": reclaim_epoch,
                        "ttl_secs": 1,
                        "async": True,
                        "idempotency_key": f"idem_ses_short_renew_{marker}",
                    },
                    rpc_id=81,
                )
            )
            short_renew_done = wait_operation(
                issuer, access_token, str(short_renew_sc.get("operation_id") or ""), want={"completed"}
            )
            if str(short_renew_done.get("status")) != "completed":
                raise RuntimeError(f"short session.renew must complete: {short_renew_done}")
            time.sleep(2.1)

            expired_renew_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_renew",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "lease_id": reclaim_lease_id,
                        "controller_epoch": reclaim_epoch,
                        "ttl_secs": 60,
                        "async": True,
                        "idempotency_key": f"idem_ses_expired_renew_{marker}",
                    },
                    rpc_id=82,
                )
            )
            expired_renew_done = wait_operation(
                issuer,
                access_token,
                str(expired_renew_sc.get("operation_id") or ""),
                want={"failed", "denied"},
                timeout_s=20,
            )
            if str(expired_renew_done.get("status")) not in {"failed", "denied"}:
                raise RuntimeError(f"expired lease renewal must fail closed: {expired_renew_done}")

            natural_reclaim_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_claim",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "async": True,
                        "idempotency_key": f"idem_ses_natural_reclaim_{marker}",
                    },
                    rpc_id=83,
                )
            )
            natural_reclaim_done = wait_operation(
                issuer, access_token, str(natural_reclaim_sc.get("operation_id") or ""), want={"completed"}
            )
            natural_epoch_m = _re2.search(r'"epoch"\s*:\s*(\d+)', json.dumps(natural_reclaim_done))
            if not natural_epoch_m or int(natural_epoch_m.group(1)) <= reclaim_epoch:
                raise RuntimeError(
                    f"natural expiry reclaim must increment controller epoch: {natural_reclaim_done}"
                )

            # E3/E4/E5: session scope must NOT bypass command policy in Recommended.
            # E4: public MCP workspace CRUD against device-local registry.
            extra_ws = workspace_dir.parent / "ws-extra-e4"
            extra_ws.mkdir(parents=True, exist_ok=True)
            ws_add_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_workspace_add",
                    {
                        "device_id": device_id,
                        "path": str(extra_ws.resolve()),
                        "id": "ws_extra_e4",
                        "label": "e4-extra",
                        "async": True,
                        "idempotency_key": f"idem_ws_add_{marker}",
                    },
                    rpc_id=91,
                )
            )
            ws_add_op = str(ws_add_sc.get("operation_id") or "")
            ws_add_done = wait_operation(issuer, access_token, ws_add_op, want={"completed"}, timeout_s=60.0)
            if "ws_extra_e4" not in json.dumps(ws_add_done):
                raise RuntimeError(f"workspace.add missing id: {ws_add_done}")
            ws_list_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_workspace_list",
                    {
                        "device_id": device_id,
                        "async": True,
                        "idempotency_key": f"idem_ws_list_{marker}",
                    },
                    rpc_id=92,
                )
            )
            ws_list_op = str(ws_list_sc.get("operation_id") or "")
            ws_list_done = wait_operation(issuer, access_token, ws_list_op, want={"completed"}, timeout_s=60.0)
            if "ws_extra_e4" not in json.dumps(ws_list_done).lower():
                raise RuntimeError(f"workspace.list missing ws_extra_e4: {ws_list_done}")
            # Prove selection: write into the newly registered root.
            ws_write_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_fs_write",
                    {
                        "device_id": device_id,
                        "workspace_id": "ws_extra_e4",
                        "path": "e4-ws.txt",
                        "content": "from-extra-ws",
                        "async": True,
                        "idempotency_key": f"idem_ws_write_{marker}",
                    },
                    rpc_id=93,
                )
            )
            ws_write_op = str(ws_write_sc.get("operation_id") or "")
            ws_write_done = wait_operation(issuer, access_token, ws_write_op, want={"completed"}, timeout_s=60.0)
            if not (extra_ws / "e4-ws.txt").exists():
                raise RuntimeError(f"workspace-scoped write missing on disk; op={ws_write_done}")
            ws_rm_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_workspace_remove",
                    {
                        "device_id": device_id,
                        "id": "ws_extra_e4",
                        "async": True,
                        "idempotency_key": f"idem_ws_rm_{marker}",
                    },
                    rpc_id=94,
                )
            )
            ws_rm_op = str(ws_rm_sc.get("operation_id") or "")
            ws_rm_done = wait_operation(issuer, access_token, ws_rm_op, want={"completed"}, timeout_s=60.0)
            if str(ws_rm_done.get("status")) != "completed":
                raise RuntimeError(f"workspace.remove failed: {ws_rm_done}")

            # Restart ownmeshd under recommended; session.open with external marker
            # command must fail closed and must not create the marker file.
            (config_dir / "policy.toml").write_text(
                "\n".join(
                    [
                        "schema_version = 1",
                        'preset = "recommended"',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            stop_process(daemon_process)
            daemon_process = None
            if os.name == "nt":
                bypass_marker = Path(tempfile.gettempdir()) / f"ownmesh-policy-bypass-{marker}.txt"
                bypass_cmd = str(bypass_marker)
                ses_bypass_program = "cmd.exe"
                ses_bypass_args = ["/C", "echo", "bypass", ">", bypass_cmd]
            else:
                bypass_marker = Path(f"/tmp/ownmesh-policy-bypass-{marker}")
                ses_bypass_program = "/bin/sh"
                ses_bypass_args = ["-c", f"touch '{bypass_marker}'"]
            if bypass_marker.exists():
                bypass_marker.unlink()
            log_path_rec = temp / "ownmeshd-recommended.log"
            with log_path_rec.open("wb") as log_rec:
                daemon_process = subprocess.Popen(
                    [str(binary), "run"],
                    cwd=ROOT,
                    env=base_env,
                    stdout=log_rec,
                    stderr=subprocess.STDOUT,
                )
                wait_for_ready(daemon_process, log_path_rec)
            # Hidden command/cwd args must be stripped by MCP allowlist and never authorize.
            bypass_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_open",
                    {
                        "device_id": device_id,
                        "workspace_id": "ws_default",
                        "idempotency_key": f"idem_ses_bypass_{marker}",
                        "async": True,
                        "command": [ses_bypass_program, *ses_bypass_args],
                        "cwd": str(Path(tempfile.gettempdir())),
                        "program": ses_bypass_program,
                        "args": ses_bypass_args,
                        "title": f"bypass-{marker}",
                    },
                    rpc_id=90,
                )
            )
            bypass_op = str(bypass_sc.get("operation_id") or "")
            bypass_done = wait_operation(
                issuer, access_token, bypass_op, want={"failed", "denied"}, timeout_s=30
            )
            if str(bypass_done.get("status")) not in {"failed", "denied"}:
                raise RuntimeError(
                    f"session.open under recommended must fail closed: {bypass_done}"
                )
            if bypass_marker.exists():
                raise RuntimeError(
                    f"session scope bypassed policy and created external marker: {bypass_marker}"
                )
            dump_bypass = json.dumps(bypass_done).lower()
            if "session.open denied" not in dump_bypass and "confinement" not in dump_bypass and "policy" not in dump_bypass:
                # Accept any fail-closed deny/failed surface that did not spawn.
                if str(bypass_done.get("status")) not in {"failed", "denied"}:
                    raise RuntimeError(f"unexpected session bypass result: {bypass_done}")

            # E3: Recommended write must surface approval_required with the *same*
            # MCP operation_id (no DeviceRoom operation_id_mismatch drop). Browser
            # recovery /approve then executes the deferred write exactly once.
            ask_name = f"ask-approve-{marker}.txt"
            ask_path = workspace_dir / ask_name
            if ask_path.exists():
                ask_path.unlink()
            ask_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_fs_write",
                    {
                        "device_id": device_id,
                        "path": ask_name,
                        "content": f"approved-{marker}",
                        "async": True,
                        "idempotency_key": f"idem_ask_write_{marker}",
                    },
                    rpc_id=91,
                )
            )
            ask_op = str(ask_sc.get("operation_id") or "")
            if not ask_op.startswith("op_"):
                raise RuntimeError(f"ask write missing operation_id: {ask_sc}")
            ask_done = wait_operation(
                issuer,
                access_token,
                ask_op,
                want={"approval_required", "failed", "denied", "completed"},
                timeout_s=45.0,
            )
            ask_status = str(ask_done.get("status") or "")
            if ask_status != "approval_required":
                raise RuntimeError(
                    f"recommended write must reach approval_required (got {ask_status}): {ask_done}"
                )
            if ask_path.exists():
                raise RuntimeError("ask write must not land before approval")
            device_apr = ask_done.get("approval_id") or (ask_done.get("data") or {}).get("approval_id")
            if not device_apr:
                # approval_id may only be nested under data.error.details
                dump_ask = json.dumps(ask_done)
                if "apr_" not in dump_ask:
                    raise RuntimeError(f"approval_required missing approval_id: {ask_done}")

            # Browser recovery path (dev bypass principal; no bearer self-approve).
            import re as _re
            req = urllib.request.Request(
                f"{issuer}/approve?operation_id={ask_op}",
                method="GET",
                headers={
                    "x-ownmesh-dev-principal": "prin_dev",
                    "accept": "text/html",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=20) as resp:
                    html = resp.read().decode("utf-8", errors="replace")
                    get_status = resp.status
            except urllib.error.HTTPError as error:
                html = error.read().decode("utf-8", errors="replace")
                get_status = error.code
            if get_status != 200:
                raise RuntimeError(f"GET /approve failed {get_status}: {html[:800]}")
            tx_m = _re.search(r'name="transaction_id"\s+value="([^"]+)"', html)
            csrf_m = _re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
            if not tx_m or not csrf_m:
                raise RuntimeError(f"GET /approve missing csrf fields: {html[:500]}")
            post_status, post_body = http_json(
                f"{issuer}/approve?operation_id={ask_op}",
                method="POST",
                headers={
                    "x-ownmesh-dev-principal": "prin_dev",
                    "content-type": "application/json",
                    "accept": "application/json",
                    "origin": issuer,
                },
                body={
                    "decision": "approve",
                    "transaction_id": tx_m.group(1),
                    "csrf_token": csrf_m.group(1),
                    "operation_id": ask_op,
                },
            )
            if post_status != 200:
                raise RuntimeError(f"POST /approve failed {post_status}: {post_body}")
            if not isinstance(post_body, dict) or post_body.get("ok") is not True:
                raise RuntimeError(f"POST /approve not ok: {post_body}")
            approved_done = wait_operation(
                issuer,
                access_token,
                ask_op,
                want={"completed", "failed", "denied"},
                timeout_s=60.0,
            )
            if str(approved_done.get("status")) != "completed":
                raise RuntimeError(
                    f"approved ask write did not complete: {approved_done} post={post_body}"
                )
            if not ask_path.is_file():
                raise RuntimeError(f"approved write missing on disk: {ask_path}")
            if ask_path.read_text(encoding="utf-8") != f"approved-{marker}":
                raise RuntimeError(f"approved write content mismatch: {ask_path.read_text(encoding='utf-8')!r}")

            # E3 ChatGPT-primary delegated policy: restart with the explicit
            # device-owner configuration and prove the same public MCP →
            # Worker/DO → Agent WSS → ownmeshd path executes a recommended Ask
            # without an OwnMesh approval page. The previous exact-bound write
            # proved non-delegated Ask/recovery; this one proves delegation is
            # opt-in and only applies after Agent binding verification.
            (config_dir / "policy.toml").write_text(
                "\n".join(
                    [
                        "schema_version = 1",
                        'preset = "recommended"',
                        "delegate_remote_mcp = true",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            stop_process(daemon_process)
            daemon_process = None
            log_path_delegated = temp / "ownmeshd-delegated.log"
            with log_path_delegated.open("wb") as log_delegated:
                daemon_process = subprocess.Popen(
                    [str(binary), "run"],
                    cwd=ROOT,
                    env=base_env,
                    stdout=log_delegated,
                    stderr=subprocess.STDOUT,
                )
                wait_for_ready(daemon_process, log_path_delegated)
            delegated_name = f"delegated-{marker}.txt"
            delegated_path = workspace_dir / delegated_name
            delegated_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_fs_write",
                    {
                        "device_id": device_id,
                        "path": delegated_name,
                        "content": f"delegated-{marker}",
                        "async": True,
                        "idempotency_key": f"idem_delegated_write_{marker}",
                    },
                    rpc_id=95,
                )
            )
            delegated_op = str(delegated_sc.get("operation_id") or "")
            delegated_done = wait_operation(
                issuer, access_token, delegated_op, want={"completed", "approval_required"}, timeout_s=45.0
            )
            if str(delegated_done.get("status")) != "completed":
                raise RuntimeError(
                    f"delegated recommended write must complete without OwnMesh approval: {delegated_done}"
                )
            if delegated_path.read_text(encoding="utf-8") != f"delegated-{marker}":
                raise RuntimeError("delegated recommended write missing or corrupt on disk")

            # E7 invokes an argv-only process, which is deliberately unavailable
            # under restricted workspace policy until OS confinement exists.
            # Restart into the explicit Full User Access fixture policy; this
            # remains workspace-custodied context while permitting the user's
            # exact, separately authorized structured command.
            (config_dir / "policy.toml").write_text(
                "\n".join(["schema_version = 1", 'preset = "full_user_access"', ""]),
                encoding="utf-8",
            )
            stop_process(daemon_process)
            daemon_process = None
            log_path_e7 = temp / "ownmeshd-e7.log"
            daemon_process = start_daemon(binary, base_env, log_path_e7)
            wait_for_ready(daemon_process, log_path_e7)

            # E7: exercise the production review path end-to-end, not a direct
            # runtime call.  The nested disposable repository gives status/diff a
            # real repository identity and lets this fixture prove that review
            # execution never creates a commit or changes a ref on its own.
            git = executable("git")
            review_root = workspace_dir / "e7-nested" / "review-repo"
            review_root.mkdir(parents=True, exist_ok=True)
            run_checked([git, "init"], cwd=review_root, env=base_env)
            run_checked([git, "config", "user.email", "e7@example.invalid"], cwd=review_root, env=base_env)
            run_checked([git, "config", "user.name", "OwnMesh E7 fixture"], cwd=review_root, env=base_env)
            (review_root / "one.txt").write_text("base-one\n", encoding="utf-8")
            (review_root / "two.txt").write_text("base-two\n", encoding="utf-8")
            run_checked([git, "add", "one.txt", "two.txt"], cwd=review_root, env=base_env)
            run_checked([git, "commit", "-m", "fixture baseline"], cwd=review_root, env=base_env)
            head_before_review = run_checked([git, "rev-parse", "HEAD"], cwd=review_root, env=base_env, capture=True)
            # The review command itself applies this bounded, workspace-local
            # two-file patch. `git apply` alters neither index nor refs, and all
            # later status/diff/test evidence is therefore a result of the public
            # review command rather than fixture setup.
            one_new = "changed-one-" + marker * 5000
            two_new = "changed-two-" + marker * 5000
            patch_file = review_root.parent / "review.patch"
            patch_file.write_text(
                "\n".join([
                    "diff --git a/one.txt b/one.txt", "--- a/one.txt", "+++ b/one.txt", "@@ -1 +1 @@", "-base-one", f"+{one_new}",
                    "diff --git a/two.txt b/two.txt", "--- a/two.txt", "+++ b/two.txt", "@@ -1 +1 @@", "-base-two", f"+{two_new}", "",
                ]),
                encoding="utf-8",
            )

            review_args: dict[str, object] = {
                "device_id": device_id,
                "workspace_id": "ws_default",
                "path": "e7-nested/review-repo",
                "command": {"program": git, "args": ["apply", "--", "../review.patch"], "timeout_ms": 30_000},
                "tests": [
                    {"program": git, "args": ["status", "--porcelain=v1"], "timeout_ms": 30_000},
                    {"program": git, "args": ["diff", "--check"], "timeout_ms": 30_000},
                    {"program": git, "args": ["diff", "--exit-code"], "timeout_ms": 30_000},
                ],
                "async": True,
                "idempotency_key": f"idem_review_{marker}",
            }
            review_sc = structured(mcp_call(issuer, access_token, "ownmesh_review_start", review_args, rpc_id=96))
            review_op = str(review_sc.get("operation_id") or "")
            review_done = wait_operation(issuer, access_token, review_op, want={"completed"}, timeout_s=60.0)
            review_id = find_value(review_done, "review_id")
            if not isinstance(review_id, str) or not review_id.startswith("rev_"):
                raise RuntimeError(f"review.start missing durable receipt: {review_done}")
            if find_value(review_done, "phase") != "failed":
                raise RuntimeError(f"review must retain failed test result separately: {review_done}")
            if run_checked([git, "rev-parse", "HEAD"], cwd=review_root, env=base_env, capture=True) != head_before_review:
                raise RuntimeError("review implicitly changed Git HEAD/ref")
            if subprocess.run([git, "diff", "--cached", "--quiet"], cwd=review_root, env=base_env, check=False).returncode != 0:
                raise RuntimeError("review command implicitly changed Git index")

            # The same exact MCP idempotency key reuses the original operation;
            # a changed payload must be rejected before another review is routed.
            review_retry = structured(mcp_call(issuer, access_token, "ownmesh_review_start", review_args, rpc_id=97))
            if str(review_retry.get("operation_id") or "") != review_op:
                raise RuntimeError(f"review idempotency did not reuse operation: {review_retry}")
            conflict_args = dict(review_args)
            conflict_args["path"] = "e7-nested"
            conflict = structured(mcp_call(issuer, access_token, "ownmesh_review_start", conflict_args, rpc_id=98))
            if "idempotency" not in json.dumps(conflict).lower():
                raise RuntimeError(f"review payload conflict was not rejected: {conflict}")

            # Public git reads retain their own cursors before the review
            # aggregates the same snapshots into its typed, digest-bound spool.
            status_sc = structured(
                mcp_call(issuer, access_token, "ownmesh_git_status", {
                    "device_id": device_id, "workspace_id": "ws_default", "path": "e7-nested/review-repo",
                    "limit": 1, "async": True, "idempotency_key": f"idem_review_status_{marker}",
                }, rpc_id=99)
            )
            status_done = wait_operation(issuer, access_token, str(status_sc.get("operation_id") or ""), want={"completed"})
            status_data = status_done.get("data") if isinstance(status_done.get("data"), dict) else {}
            if status_data.get("next_cursor") in {None, ""}:
                raise RuntimeError(f"git status missing pagination cursor: {status_done}")
            diff_sc = structured(
                mcp_call(issuer, access_token, "ownmesh_git_diff", {
                    "device_id": device_id, "workspace_id": "ws_default", "path": "e7-nested/review-repo",
                    "limit": 10, "max_bytes": 128, "async": True, "idempotency_key": f"idem_review_diff_{marker}",
                }, rpc_id=100)
            )
            diff_done = wait_operation(issuer, access_token, str(diff_sc.get("operation_id") or ""), want={"completed"})
            diff_data = diff_done.get("data") if isinstance(diff_done.get("data"), dict) else {}
            if diff_data.get("next_cursor") in {None, ""} or diff_data.get("truncated") is not True:
                raise RuntimeError(f"git diff missing bounded pagination: {diff_done}")

            page_started = structured(mcp_call(issuer, access_token, "ownmesh_review_page", {
                "device_id": device_id, "review_id": review_id, "cursor": 0, "max_bytes": 1,
                "idempotency_key": f"idem_review_page_{marker}",
            }, rpc_id=101))
            page_sc = wait_operation(issuer, access_token, str(page_started.get("operation_id") or ""), want={"completed"})
            page_data = page_sc.get("data") if isinstance(page_sc.get("data"), dict) else {}
            page_dump = json.dumps(page_data)
            page_digest = page_data.get("sha256")
            if not isinstance(page_digest, str) or len(page_digest) != 64 or page_data.get("next_cursor") != 1 or '"truncated": true' not in page_dump:
                raise RuntimeError(f"review page missing bounded cursor/digest: {page_sc}")
            full_started = structured(mcp_call(issuer, access_token, "ownmesh_review_page", {
                "device_id": device_id, "review_id": review_id, "cursor": 0, "max_bytes": 49_152,
                "idempotency_key": f"idem_review_page_full_{marker}",
            }, rpc_id=102))
            full_page = wait_operation(issuer, access_token, str(full_started.get("operation_id") or ""), want={"completed"})
            full_page_data = full_page.get("data") if isinstance(full_page.get("data"), dict) else {}
            tail_started = structured(mcp_call(issuer, access_token, "ownmesh_review_page", {
                "device_id": device_id, "review_id": review_id, "cursor": int(full_page_data.get("next_cursor") or 0), "max_bytes": 49_152,
                "idempotency_key": f"idem_review_page_tail_{marker}",
            }, rpc_id=103))
            tail_page = wait_operation(issuer, access_token, str(tail_started.get("operation_id") or ""), want={"completed"})
            typed_chunks, typed_bytes = review_chunk_bytes(full_page_data)
            tail_data = tail_page.get("data") if isinstance(tail_page.get("data"), dict) else {}
            tail_chunks, tail_bytes = review_chunk_bytes(tail_data)
            typed_chunks.extend(tail_chunks)
            typed_bytes += tail_bytes
            final_started = structured(mcp_call(issuer, access_token, "ownmesh_review_page", {
                "device_id": device_id, "review_id": review_id, "cursor": int(tail_data.get("next_cursor") or 0), "max_bytes": 49_152,
                "idempotency_key": f"idem_review_page_final_{marker}",
            }, rpc_id=104))
            final_page = wait_operation(issuer, access_token, str(final_started.get("operation_id") or ""), want={"completed"})
            final_data = final_page.get("data") if isinstance(final_page.get("data"), dict) else {}
            final_chunks, final_bytes = review_chunk_bytes(final_data)
            typed_chunks.extend(final_chunks)
            typed_bytes += final_bytes
            if (
                not {int(chunk["test_index"]) for chunk in typed_chunks if chunk.get("kind") == "test_stdout" and isinstance(chunk.get("test_index"), int)}.issuperset({0, 2})
                or b"test[1]: exit=Some(0)" not in typed_bytes
            ):
                raise RuntimeError(f"review output did not preserve capped pass/fail test streams: {full_page}")

            # An invalid repository fails on the real device route.  Full User
            # Access intentionally does not turn workspace context into a hidden
            # filesystem deny, so cross-workspace rejection is asserted at the
            # authoritative control-plane ACL boundary with the member who owns
            # ws_default but has no grant for ws_alt.
            bad_sc = structured(mcp_call(issuer, access_token, "ownmesh_review_start", {
                "device_id": device_id, "workspace_id": "ws_default", "path": "e7-nested/not-a-repo", "tests": [],
                "async": True, "idempotency_key": f"idem_review_bad_105_{marker}",
            }, rpc_id=105))
            bad_done = wait_operation(issuer, access_token, str(bad_sc.get("operation_id") or ""), want={"failed", "denied"})
            if str(bad_done.get("status")) not in {"failed", "denied"}:
                raise RuntimeError(f"invalid repository review unexpectedly ran: {bad_done}")
            cross_rejected = mcp_expect_rejected(issuer, access_token_other, "ownmesh_review_start", {
                "device_id": device_id, "workspace_id": "ws_alt", "path": "e7-nested/review-repo", "tests": [],
                "async": True, "idempotency_key": f"idem_review_cross_workspace_{marker}",
            }, rpc_id=106)
            if "workspace" not in json.dumps(cross_rejected).lower():
                raise RuntimeError(f"cross-workspace review was not rejected by ACL: {cross_rejected}")

            # A stale HEAD invalidates the receipt rather than replaying old
            # status/diff bytes under a new repository state.
            run_checked([git, "add", "one.txt", "two.txt"], cwd=review_root, env=base_env)
            run_checked([git, "commit", "-m", "fixture stale head"], cwd=review_root, env=base_env)
            stale_show_started = structured(mcp_call(issuer, access_token, "ownmesh_review_show", {
                "device_id": device_id, "review_id": review_id, "idempotency_key": f"idem_review_stale_show_{marker}",
            }, rpc_id=107))
            stale_show = wait_operation(issuer, access_token, str(stale_show_started.get("operation_id") or ""), want={"failed", "denied"})
            stale_page_started = structured(mcp_call(issuer, access_token, "ownmesh_review_page", {
                "device_id": device_id, "review_id": review_id, "cursor": 0, "max_bytes": 8,
                "idempotency_key": f"idem_review_stale_page_{marker}",
            }, rpc_id=108))
            stale_page = wait_operation(issuer, access_token, str(stale_page_started.get("operation_id") or ""), want={"failed", "denied"})
            if "head changed" not in (json.dumps(stale_show) + json.dumps(stale_page)).lower():
                raise RuntimeError(f"stale review receipt remained readable: show={stale_show} page={stale_page}")

            # Cancellation remains the generic exact-bound operation.  The
            # review is deliberately async, so this cancel reaches the live
            # Agent registry and its process-tree kill handle while sleep/ping is
            # running; no shell string is used anywhere in the fixture.
            if os.name == "nt":
                slow_program, slow_args = executable("ping"), ["-n", "30", "127.0.0.1"]
            else:
                slow_program, slow_args = executable("sleep"), ["30"]
            cancel_review_sc = structured(mcp_call(issuer, access_token, "ownmesh_review_start", {
                "device_id": device_id, "workspace_id": "ws_default", "path": "e7-nested/review-repo",
                "tests": [{"program": slow_program, "args": slow_args, "timeout_ms": 60_000}],
                "async": True, "idempotency_key": f"idem_review_cancel_{marker}",
            }, rpc_id=109))
            cancel_review_op = str(cancel_review_sc.get("operation_id") or "")
            time.sleep(0.5)
            cancel_sc = structured(mcp_call(issuer, access_token, "ownmesh_cancel_operation", {
                "operation_id": cancel_review_op, "device_id": device_id,
                "idempotency_key": f"idem_cancel_review_{marker}",
            }, rpc_id=110))
            if "cancel" not in json.dumps(cancel_sc).lower():
                raise RuntimeError(f"review cancel request was rejected: {cancel_sc}")
            cancelled_done = wait_operation(issuer, access_token, cancel_review_op, want={"completed"}, timeout_s=45.0)
            cancel_review_id = find_value(cancelled_done, "review_id")
            cancel_page_started = structured(mcp_call(issuer, access_token, "ownmesh_review_page", {
                "device_id": device_id, "review_id": cancel_review_id, "cursor": 0, "max_bytes": 49_152,
                "idempotency_key": f"idem_review_cancel_page_{marker}",
            }, rpc_id=111))
            cancel_page = wait_operation(issuer, access_token, str(cancel_page_started.get("operation_id") or ""), want={"completed"})
            cancel_page_data = cancel_page.get("data") if isinstance(cancel_page.get("data"), dict) else {}
            _, cancel_bytes = review_chunk_bytes(cancel_page_data)
            if find_value(cancelled_done, "phase") != "cancelled" or b"process tree termination requested" not in cancel_bytes:
                raise RuntimeError(f"review cancellation did not terminate active process tree: {cancelled_done}")

            # Restore full_user_access for any later local inspection (cleanup path).
            (config_dir / "policy.toml").write_text(
                "\n".join(
                    [
                        "schema_version = 1",
                        'preset = "full_user_access"',
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            # Missing idempotency_key on mutating tool must fail closed before route.
            missing_key_status, missing_key_body = http_json(
                f"{issuer}/mcp",
                method="POST",
                headers={"authorization": f"Bearer {access_token}"},
                body={
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/call",
                    "params": {
                        "name": "ownmesh_fs_write",
                        "arguments": {
                            "device_id": device_id,
                            "path": "no-key.txt",
                            "content": "x",
                            "async": True,
                        },
                    },
                },
            )
            if missing_key_status != 200:
                raise RuntimeError(f"missing-key HTTP {missing_key_status}: {missing_key_body}")
            if not isinstance(missing_key_body, dict) or not missing_key_body.get("error"):
                raise RuntimeError(f"expected JSON-RPC error for missing idempotency_key: {missing_key_body}")
            err_msg = str((missing_key_body.get("error") or {}).get("message") or "")
            if "idempotency_key" not in err_msg.lower():
                raise RuntimeError(f"missing-key error message unexpected: {missing_key_body}")

            print(
                "E2/E3 workerd loopback passed: public MCP wrote/read/ran via real ownmeshd; "
                f"env+resume+idempotency+bound-cancel+mismatch+binary+512k-pages+list/stat/delete+"
                f"patch+shell+workspace-select+live-pty+session-open+observer-deny-write+"
                f"(write_op={write_op}, read_op={read_op}, cmd_op={cmd_op}, long_op={long_op}, bin_op={bin_op}, "
                f"list_op={list_op}, patch_op={patch_op}, shell_op={shell_op}, ses_op={ses_op}, chunks={chunk_i})"
                f"workspace-list/show+workspace-CRUD+input_seq+two-principal-handoff+required-key+session-policy-deny+ask-approve+delegated-MCP held "
                f"(write_op={write_op}, read_op={read_op}, cmd_op={cmd_op}, long_op={long_op}, bin_op={bin_op}, "
                f"list_op={list_op}, patch_op={patch_op}, shell_op={shell_op}, ses_op={ses_op}, delegated_op={delegated_op}, chunks={chunk_i})"
                f"(write_op={write_op}, read_op={read_op}, cmd_op={cmd_op}, long_op={long_op}, bin_op={bin_op}, "
                f"list_op={list_op}, patch_op={patch_op}, shell_op={shell_op}, ses_op={ses_op}, chunks={chunk_i})"
            )
            return 0
        finally:
            stop_process(daemon_process)
            stop_session_sidecars(state_dir)
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
        print(f"E2 workerd loopback failed: {error}", file=sys.stderr)
        raise SystemExit(1)
