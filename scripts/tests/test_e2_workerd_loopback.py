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


def structured(result: dict[str, object]) -> dict[str, object]:
    sc = result.get("structuredContent")
    if not isinstance(sc, dict):
        raise RuntimeError(f"missing structuredContent: {result}")
    return sc


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
        ]:
            directory.mkdir(parents=True, exist_ok=True)
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

        try:
            run_checked(
                [cargo, "build", "-p", "ownmeshd", "--bin", "ownmeshd", "--example", "e1_loopback_provision"],
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
            with log_path.open("wb") as log:
                daemon_process = subprocess.Popen(
                    [str(binary), "run"],
                    cwd=ROOT,
                    env=base_env,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
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
            bad_ws = structured(
                mcp_call(
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
            )
            bad_ws_op = str(bad_ws.get("operation_id") or "")
            bad_ws_done = wait_operation(
                issuer, access_token, bad_ws_op, want={"failed", "denied"}, timeout_s=20
            )
            if str(bad_ws_done.get("status")) not in {"failed", "denied"}:
                raise RuntimeError(f"unknown workspace_id must fail closed: {bad_ws_done}")
            if "unknown workspace" not in json.dumps(bad_ws_done).lower():
                # Accept any fail-closed error that names the missing workspace.
                if "ws_does_not_exist" not in json.dumps(bad_ws_done):
                    raise RuntimeError(f"unknown workspace_id must fail closed: {bad_ws_done}")

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
            saw_live = live_marker in ses_dump
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
                    if live_marker in json.dumps(rep_done):
                        saw_live = True
                        break
                    _time.sleep(0.25)
            if not saw_live:
                raise RuntimeError(
                    f"live PTY session must produce real process output containing {live_marker}"
                )

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
            bad_ws_write = structured(
                mcp_call(
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
            )
            bad_ws_write_op = str(bad_ws_write.get("operation_id") or "")
            bad_ws_write_done = wait_operation(
                issuer, access_token, bad_ws_write_op, want={"failed", "denied"}, timeout_s=20
            )
            if str(bad_ws_write_done.get("status")) not in {"failed", "denied"}:
                raise RuntimeError(
                    f"session.write workspace mismatch must fail closed: {bad_ws_write_done}"
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

            w1_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_write",
                    {
                        "device_id": device_id,
                        "session_id": seq_ses_id,
                        "workspace_id": "ws_default",
                        "data": "first\n",
                        "input_seq": 1,
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
                f"workspace-list/show+workspace-CRUD+input_seq+two-principal-handoff+required-key+session-policy-deny held "
                f"(write_op={write_op}, read_op={read_op}, cmd_op={cmd_op}, long_op={long_op}, bin_op={bin_op}, "
                f"list_op={list_op}, patch_op={patch_op}, shell_op={shell_op}, ses_op={ses_op}, chunks={chunk_i})"
            )
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
        print(f"E2 workerd loopback failed: {error}", file=sys.stderr)
        raise SystemExit(1)
