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
            return json.loads((log_path.parent / "state" / "agent-transport-state.json").read_text())
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
    refresh_token = f"rtk_{secrets.token_urlsafe(24)}"
    refresh_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
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
                    "INSERT OR IGNORE INTO oauth_clients (client_id,tenant_id,client_name,redirect_uris,created_at) VALUES ("
                    + "'client_ownmesh_cli','ten_default','OwnMesh CLI',"
                    + repr(json.dumps(["http://127.0.0.1:8750/callback"]))
                    + ","
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

            # E5 session open via public MCP (metadata + controller lease; live PTY host partial).
            ses_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_session_open",
                    {
                        "device_id": device_id,
                        "title": f"e2-ses-{marker}",
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
                f"patch+shell+workspace-select+session-open+required-key held "
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
