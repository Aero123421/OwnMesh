#!/usr/bin/env python3
"""Real debug ownmeshd binary × local Wrangler/workerd E2 routing smoke.

Proves the production path:

  public /mcp → Worker → DeviceRoom → Agent WSS → ownmeshd runtime → result

Exercises real temporary-directory filesystem write/read and a structured
command, then restarts the binary to prove correlation dedup across resume.
No remote Cloudflare resource is accessed.
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
        for directory in [persist, config_dir, state_dir, runtime_dir, cache_dir, keystore_dir, workspace_dir]:
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

            # Structured command through the same production path.
            if os.name == "nt":
                program = "cmd.exe"
                args = ["/c", "echo", marker]
            else:
                program = "/bin/echo"
                args = [marker]
            cmd_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_command_run",
                    {
                        "device_id": device_id,
                        "program": program,
                        "args": args,
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

            # Re-issue the same idempotency key + identical action. Control plane must
            # replay the prior authoritative row without re-dispatch (disk stays mutated).
            rewrite_sc = structured(
                mcp_call(
                    issuer,
                    access_token,
                    "ownmesh_fs_write",
                    {
                        "device_id": device_id,
                        "path": "e2-marker.txt",
                        "content": f"e2-ok-{marker}",
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

            print(
                "E2/E3 workerd loopback passed: public MCP wrote/read/ran via real ownmeshd; "
                f"resume+idempotency+cancel+mismatch held "
                f"(write_op={write_op}, read_op={read_op}, cmd_op={cmd_op}, long_op={long_op})"
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
