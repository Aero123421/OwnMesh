#!/usr/bin/env python3
"""E9 public-path transfer acceptance (two real ownmeshd Agents).

This deliberately uses no mock Agent, direct runtime IPC, or synthetic DeviceRoom
message.  Both identities are independently provisioned and connect to local
Wrangler/workerd.  The only control surface is public ``/mcp``.

The test is intentionally fail-closed: it proves the cases that a production
client can drive without obtaining an internal bearer.  Fault injection that
would require a transfer ticket is recorded as a coverage gap rather than
pretended to be a public-path proof.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid

from test_e2_workerd_loopback import (
    CONTROL_PLANE,
    ROOT,
    RetryingTemporaryDirectory,
    executable,
    free_port,
    mcp_call,
    mcp_expect_rejected,
    run_checked,
    start_daemon,
    stop_process,
    structured,
    wait_for_health,
    wait_operation,
    wrangler,
)


def wait_agent(
    process: subprocess.Popen[bytes], log_path: Path, state_dir: Path, *, after_bytes: int = 0
) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
            raise RuntimeError(f"Agent exited before ready ({process.returncode}): {text[-3000:]}")
        if log_path.exists() and "Agent WebSocket authenticated and ready" in log_path.read_bytes()[after_bytes:].decode("utf-8", errors="replace"):
            if (state_dir / "agent-transport-state.json").is_file():
                return
        time.sleep(0.2)
    text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    raise RuntimeError(f"timed out waiting for Agent readiness: {text[-3000:]}")


def restart_daemon(binary: Path, env: dict[str, str], log_path: Path) -> subprocess.Popen[bytes]:
    """Restart without erasing the first process's bounded diagnostic history."""
    with log_path.open("ab") as log:
        return subprocess.Popen(
            [str(binary), "run"], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT
        )


def daemon_env(
    *, root: Path, issuer: str, device_id: str, credential: str, service: str, password: str
) -> dict[str, str]:
    config = root / "config"
    state = root / "state"
    runtime = root / "runtime"
    cache = root / "cache"
    keystore = state / "keystore"
    workspace = state / "workspace"
    for path in (config, state, runtime, cache, keystore, workspace):
        path.mkdir(parents=True, exist_ok=True)
    (state / "workspaces.json").write_text(json.dumps({"schema_version": 1, "workspaces": [{
        "id": f"ws_{device_id}", "root": str(workspace.resolve()), "label": device_id,
    }]}), encoding="utf-8")
    (config / "config.toml").write_text(
        "\n".join([
            "schema_version = 1", 'active_instance = "local"', "",
            "[[instances]]", 'id = "local"', f'base_url = "{issuer}"', "",
        ]),
        encoding="utf-8",
    )
    (config / "policy.toml").write_text('schema_version = 1\npreset = "full_user_access"\n', encoding="utf-8")
    env = os.environ.copy()
    env.update({
        "OWNMESH_CONFIG_DIR": str(config), "OWNMESH_STATE_DIR": str(state),
        "OWNMESH_RUNTIME_DIR": str(runtime), "OWNMESH_CACHE_DIR": str(cache),
        "OWNMESH_KEYSTORE_PASSWORD": password, "OWNMESH_LOOPBACK_TEST_KEYCHAIN_SERVICE": service,
        "OWNMESH_E1_TEST_KEYSTORE_DIR": str(keystore), "OWNMESH_E1_TEST_ISSUER": issuer,
        "OWNMESH_E1_TEST_DEVICE_ID": device_id, "OWNMESH_E1_TEST_CREDENTIAL": credential,
        "RUST_LOG": "ownmeshd=info",
    })
    return env


def op_id(value: dict[str, object]) -> str:
    operation_id = value.get("operation_id")
    if not isinstance(operation_id, str) or not operation_id:
        raise RuntimeError(f"public MCP response omitted operation_id: {value}")
    return operation_id


def public_call(issuer: str, token: str, name: str, args: dict[str, object], rpc: int) -> dict[str, object]:
    return structured(mcp_call(issuer, token, name, args, rpc_id=rpc))


def assert_workspace_ready(
    issuer: str,
    token: str,
    device: str,
    workspace: str,
    path: Path,
    marker: str,
    rpc: int,
) -> None:
    # The ready handshake publishes and activates the pre-seeded device-local
    # registry before exposing the Agent as ready. Re-adding the same id through
    # MCP is therefore a real conflict. Route a list through the live Agent and
    # verify both the authoritative root and Control Plane activation instead.
    started = public_call(issuer, token, "ownmesh_workspace_list", {
        "device_id": device, "async": True,
        "idempotency_key": f"e9-workspace-list-{marker}-{device}",
    }, rpc)
    done = wait_operation(issuer, token, op_id(started), want={"completed"}, timeout_s=45)
    data = done.get("data")
    workspaces = data.get("workspaces") if isinstance(data, dict) else None
    expected_root = str(path.resolve())
    matches = [
        row
        for row in workspaces if isinstance(row, dict) and row.get("id") == workspace
    ] if isinstance(workspaces, list) else []
    if len(matches) != 1 or matches[0].get("root") != expected_root:
        raise RuntimeError(
            f"ready handshake omitted authoritative workspace {workspace} at {expected_root}: {done}"
        )
    if matches[0].get("activation_state") != "active":
        raise RuntimeError(f"workspace {workspace} was not activated before ready: {done}")


def advance_until_terminal(issuer: str, token: str, transfer_id: str, marker: str) -> dict[str, object]:
    """The public coordinator is deliberately stepwise; drive only its MCP API."""
    last: dict[str, object] = {}
    # A deliberately killed Agent can leave the peer waiting for the bounded
    # 30-second Room ACK timeout before both retry receipts are durable. Allow
    # several fresh-fence generations without weakening any product deadline.
    for attempt in range(480):
        status = public_call(issuer, token, "ownmesh_transfer_status", {"transfer_id": transfer_id}, 3000 + attempt)
        transfer = (status.get("data") or {}).get("transfer") if isinstance(status.get("data"), dict) else None
        if isinstance(transfer, dict):
            state = str(transfer.get("state") or "")
            if state in {"completed", "failed", "cancelled"}:
                return status
        last = status
        public_call(issuer, token, "ownmesh_transfer_send", {
            # A send idempotency key binds the entire state-machine advance;
            # retries must carry the original key rather than creating a new
            # public mutation identity for every polling iteration.
            "transfer_id": transfer_id, "idempotency_key": f"e9-send-{marker}",
        }, 4000 + attempt)
        time.sleep(0.25)
    raise RuntimeError(f"transfer did not reach terminal state: {last}")


def transfer_state(status: dict[str, object]) -> tuple[str, dict[str, object]]:
    data = status.get("data")
    transfer = data.get("transfer") if isinstance(data, dict) else None
    if not isinstance(transfer, dict):
        raise RuntimeError(f"public transfer status omitted transfer metadata: {status}")
    return str(transfer.get("state") or ""), transfer


def advance_until_state(
    issuer: str, token: str, transfer_id: str, marker: str, wanted: set[str]
) -> dict[str, object]:
    """Advance through public send calls, stopping before the wanted state mutates again."""
    last: dict[str, object] = {}
    for attempt in range(80):
        status = public_call(
            issuer, token, "ownmesh_transfer_status", {"transfer_id": transfer_id}, 6000 + attempt
        )
        state, _ = transfer_state(status)
        if state in wanted:
            return status
        if state in {"completed", "failed", "cancelled"}:
            raise RuntimeError(f"transfer reached {state} before {sorted(wanted)}: {status}")
        last = status
        public_call(
            issuer,
            token,
            "ownmesh_transfer_send",
            {"transfer_id": transfer_id, "idempotency_key": f"e9-send-{marker}"},
            7000 + attempt,
        )
        time.sleep(0.2)
    raise RuntimeError(f"transfer did not reach {sorted(wanted)}: {last}")


def artifact_bytes(issuer: str, token: str, transfer_id: str) -> bytes:
    output = bytearray()
    offset = 0
    for page in range(128):
        requested = public_call(issuer, token, "ownmesh_transfer_get", {
            "transfer_id": transfer_id, "offset": offset, "max_bytes": 32768,
        }, 5000 + page)
        completed = wait_operation(issuer, token, op_id(requested), want={"completed"}, timeout_s=45)
        data = completed.get("data") if isinstance(completed.get("data"), dict) else {}
        encoded = data.get("content_base64") if isinstance(data, dict) else None
        if not isinstance(encoded, str):
            raise RuntimeError(f"artifact page omitted bounded bytes: {completed}")
        raw = base64.b64decode(encoded, validate=True)
        if hashlib.sha256(raw).hexdigest() != data.get("page_sha256"):
            raise RuntimeError("artifact page hash mismatch")
        output.extend(raw)
        next_offset = data.get("next_offset")
        if next_offset is None:
            return bytes(output)
        if not isinstance(next_offset, int) or next_offset != offset + len(raw):
            raise RuntimeError(f"artifact cursor is not contiguous: {completed}")
        offset = next_offset
    raise RuntimeError("artifact paging exceeded bounded page budget")


def local_plan_id_for_destination(
    state_root: Path, destination_path: str, *, required_local_suffix: str
) -> str:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        transfers = state_root / "transfers"
        for plan_path in transfers.glob(".*.plan.json"):
            try:
                plan = json.loads(plan_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            binding = plan.get("binding") if isinstance(plan, dict) else None
            if isinstance(binding, dict) and binding.get("destination_relative_path") == destination_path:
                name = plan_path.name
                plan_id = name[1 : -len(".plan.json")]
                # Preflight and final start plans can share the same public
                # destination path while having distinct grant identities.
                # Select the live data-plane plan by its role-specific durable
                # custody marker, never by directory enumeration order.
                if (transfers / f".{plan_id}{required_local_suffix}").exists():
                    return plan_id
        time.sleep(0.02)
    raise RuntimeError(f"destination transfer plan not found for {destination_path}")


def read_json_retry(path: Path, timeout_s: float = 5) -> dict[str, object]:
    """Tolerate the short Windows replace/share window of an atomic journal write."""
    deadline = time.monotonic() + timeout_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, dict):
                return value
            last = ValueError("JSON root is not an object")
        except (OSError, json.JSONDecodeError) as error:
            last = error
        time.sleep(0.01)
    raise RuntimeError(f"could not read stable JSON journal {path.name}: {last}")


def bounded_local_transfer_diagnostics(state_root: Path) -> dict[str, object]:
    transfers = state_root / "transfers"
    journals: list[dict[str, object]] = []
    for path in sorted(transfers.glob(".*.json"))[:32]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            journals.append({"read": "unavailable"})
            continue
        journals.append({key: value.get(key) for key in (
            "schema", "epoch", "fence", "state", "contiguous_ack", "bytes_received",
        )})
    part_sizes: list[int] = []
    for path in sorted(transfers.glob(".*.part"))[:32]:
        try:
            part_sizes.append(path.stat().st_size)
        except OSError:
            part_sizes.append(-1)
    return {"journals": journals, "part_count": len(part_sizes), "part_sizes": part_sizes}


def bounded_log_diagnostics(path: Path) -> dict[str, object]:
    """Return counts/classes only; never preserve raw paths, frames or bodies."""
    text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    error_classes: set[str] = set()
    for token in text.replace("\x1b", " ").replace("=", " ").split():
        candidate = token.strip("[](){}:,;\"'")
        if candidate.startswith("OWNMESH_E_") and len(candidate) <= 96 \
                and all(char.isupper() or char.isdigit() or char == "_" for char in candidate):
            error_classes.add(candidate)
    return {
        "agent_ready_events": text.count("Agent WebSocket authenticated and ready"),
        "warning_events": text.count(" WARN "),
        "error_events": text.count(" ERROR "),
        "error_classes": sorted(error_classes)[:32],
    }


def bounded_operation_diagnostics(stdout: str) -> list[dict[str, object]]:
    """Extract only tool/status/error class from Wrangler's JSON response."""
    start = stdout.find("[")
    if start < 0:
        return [{"diagnostic": "query_output_unavailable"}]
    try:
        parsed = json.loads(stdout[start:])
    except json.JSONDecodeError:
        return [{"diagnostic": "query_output_invalid"}]
    safe: list[dict[str, object]] = []

    def visit(value: object) -> None:
        if isinstance(value, dict):
            tool, status = value.get("tool"), value.get("status")
            if isinstance(tool, str) and isinstance(status, str) \
                    and len(tool) <= 96 and len(status) <= 48:
                code = value.get("error_code")
                safe.append({
                    "tool": tool,
                    "status": status,
                    "error_code": code if isinstance(code, str) and code.startswith("OWNMESH_E_") else None,
                })
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(parsed)
    return safe[:256]


def audit_durable_state(
    persist: Path,
    *,
    artifact_hashes: set[str],
    secrets_forbidden: tuple[str, ...],
    payload_probes: tuple[bytes, ...],
    logs: tuple[Path, ...],
) -> None:
    """Inspect actual stopped D1/DO SQLite cells, not merely source code."""
    databases = sorted(persist.rglob("*.sqlite"))
    if not databases:
        raise RuntimeError("Wrangler durable-state audit found no SQLite databases")
    snapshot_root = persist.parent / "durable-audit-snapshot"
    snapshot_root.mkdir()
    forbidden_text = (
        '"ticket":', '"jti":', "ephemeral_private", "private_ephemeral",
        '"ciphertext_base64":', "relay_ciphertext",
    ) + secrets_forbidden
    artifact_rows = 0
    for index, database in enumerate(databases):
        # workerd is force-stopped on Windows; copying the durable database and
        # its WAL/rollback journal into a fresh directory avoids a stale shared-
        # memory lock while retaining every committed durable byte for review.
        snapshot = snapshot_root / f"store-{index}.sqlite"
        shutil.copyfile(database, snapshot)
        for suffix in ("-wal", "-journal"):
            sidecar = Path(f"{database}{suffix}")
            if sidecar.is_file():
                shutil.copyfile(sidecar, Path(f"{snapshot}{suffix}"))
        connection = sqlite3.connect(snapshot)
        try:
            if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise RuntimeError("Wrangler durable-state SQLite integrity check failed")
            tables = [row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )]
            for table in tables:
                quoted = '"' + str(table).replace('"', '""') + '"'
                columns = [row[1] for row in connection.execute(f"PRAGMA table_info({quoted})")]
                rows = connection.execute(f"SELECT * FROM {quoted}")
                for row in rows:
                    record = dict(zip(columns, row))
                    artifact_record = (
                        table == "mcp_operations"
                        and record.get("tool") == "__transfer_artifact_get"
                        and record.get("status") == "completed"
                    )
                    for column, value in zip(columns, row):
                        raw = bytes(value) if isinstance(value, (bytes, bytearray, memoryview)) else str(value).encode("utf-8", "replace")
                        lowered = raw.lower()
                        for forbidden in forbidden_text:
                            if forbidden and forbidden.encode("utf-8").lower() in lowered:
                                raise RuntimeError(
                                    f"forbidden transfer secret/material persisted in {database.name}:{table}.{column}"
                                )
                        if not (artifact_record and column == "data_json"):
                            for probe in payload_probes:
                                encoded_probe = base64.b64encode(probe)
                                if probe in raw or encoded_probe in raw:
                                    raise RuntimeError(
                                        f"non-artifact transfer plaintext/cipher bytes persisted in {database.name}:{table}.{column}"
                                    )
                    if table == "mcp_operations" and "tool" in columns and "data_json" in columns:
                        if artifact_record:
                            data_raw = record.get("data_json")
                            if not isinstance(data_raw, str) or len(data_raw.encode()) > 256_000:
                                raise RuntimeError("artifact D1 row exceeds bounded JSON budget")
                            data = json.loads(data_raw)
                            encoded = data.get("content_base64")
                            if not isinstance(encoded, str):
                                raise RuntimeError("completed artifact D1 row omitted content_base64")
                            page = base64.b64decode(encoded, validate=True)
                            if len(page) > 64 * 1024 or hashlib.sha256(page).hexdigest() != data.get("page_sha256"):
                                raise RuntimeError("artifact D1 page violates 64KiB/hash contract")
                            if data.get("sha256") not in artifact_hashes:
                                raise RuntimeError("artifact D1 row is not bound to an expected completed artifact")
                            expires_at = record.get("expires_at")
                            if not isinstance(expires_at, str):
                                raise RuntimeError("artifact D1 row omitted expiry")
                            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                            remaining = (expiry - datetime.now(timezone.utc)).total_seconds()
                            if remaining <= 0 or remaining > 3_700:
                                raise RuntimeError("artifact D1 row exceeds transfer TTL bound")
                            artifact_rows += 1
        finally:
            connection.close()
    if artifact_rows == 0:
        raise RuntimeError("durable-state audit found no user-requested bounded artifact page")
    for log_path in logs:
        raw = log_path.read_bytes() if log_path.is_file() else b""
        lowered = raw.lower()
        for forbidden in forbidden_text:
            if forbidden and forbidden.encode("utf-8").lower() in lowered:
                raise RuntimeError(f"forbidden transfer secret/material appeared in {log_path.name}")
        for probe in payload_probes:
            if probe in raw or base64.b64encode(probe) in raw:
                raise RuntimeError(f"transfer plaintext/cipher bytes appeared in {log_path.name}")


def main() -> int:
    cargo = executable("cargo")
    corepack = executable("corepack")
    port = free_port()
    issuer = f"http://127.0.0.1:{port}"
    marker = uuid.uuid4().hex
    device_source, device_destination = f"dev_e9_source_{marker}", f"dev_e9_destination_{marker}"
    credential_source, credential_destination = f"dcred_{secrets.token_urlsafe(32)}", f"dcred_{secrets.token_urlsafe(32)}"
    access = f"atk_{secrets.token_urlsafe(24)}"
    member = f"atk_{secrets.token_urlsafe(24)}"
    foreign = f"atk_{secrets.token_urlsafe(24)}"
    session_secret = secrets.token_hex(32)
    owner_token_hash = secrets.token_hex(32)
    password = secrets.token_urlsafe(32)
    wrangler_process: subprocess.Popen[bytes] | None = None
    source_process: subprocess.Popen[bytes] | None = None
    destination_process: subprocess.Popen[bytes] | None = None
    succeeded = False

    with RetryingTemporaryDirectory(prefix="ownmesh-e9-workerd-") as raw:
        temp = Path(raw)
        persist = temp / "wrangler-state"
        # Separate runtime roots feed the production default endpoint resolver:
        # Windows hashes each root into a distinct bounded pipe name, while Unix
        # relocates an overlong default socket to its owner-scoped short path.
        source_root, destination_root = temp / "s", temp / "d"
        source_env = daemon_env(root=source_root, issuer=issuer, device_id=device_source, credential=credential_source,
                                service=f"dev.ownmesh.loopback-test.e9.source.{marker}", password=password)
        destination_env = daemon_env(root=destination_root, issuer=issuer, device_id=device_destination, credential=credential_destination,
                                     service=f"dev.ownmesh.loopback-test.e9.destination.{marker}", password=password)
        try:
            run_checked([cargo, "build", "-p", "ownmeshd", "--bin", "ownmeshd", "--example", "e1_loopback_provision"], cwd=ROOT, env=source_env)
            source_key = run_checked([cargo, "run", "-q", "-p", "ownmeshd", "--example", "e1_loopback_provision", "--", "provision"], cwd=ROOT, env=source_env, capture=True)
            destination_key = run_checked([cargo, "run", "-q", "-p", "ownmeshd", "--example", "e1_loopback_provision", "--", "provision"], cwd=ROOT, env=destination_env, capture=True)
            if len(source_key) != 64 or len(destination_key) != 64 or source_key == destination_key:
                raise RuntimeError("independent Agent enrollment keys were not produced")
            run_checked(wrangler(corepack, "d1", "migrations", "apply", "DB", "--local", "--persist-to", str(persist)), cwd=CONTROL_PLANE, env=source_env)
            now, expires = "2026-08-10T00:00:00.000Z", "2099-01-01T00:00:00.000Z"
            digest = lambda value: hashlib.sha256(value.encode()).hexdigest()
            scope = "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device offline_access"
            sql = " ".join([
                "INSERT INTO tenants (id,name,created_at) VALUES ('ten_e9','E9'," + repr(now) + ");",
                "INSERT INTO tenants (id,name,created_at) VALUES ('ten_foreign','Foreign'," + repr(now) + ");",
                "INSERT INTO principals (id,tenant_id,kind,display_name,created_at) VALUES ('prin_e9','ten_e9','human','E9'," + repr(now) + ");",
                "INSERT INTO principals (id,tenant_id,kind,display_name,created_at) VALUES ('prin_member','ten_e9','human','Member'," + repr(now) + ");",
                "INSERT INTO principals (id,tenant_id,kind,display_name,created_at) VALUES ('prin_foreign','ten_foreign','human','Foreign'," + repr(now) + ");",
                "INSERT INTO oauth_clients (client_id,tenant_id,client_name,redirect_uris,created_at) VALUES ('client_e9','ten_e9','E9'," + repr(json.dumps(["http://127.0.0.1:8750/callback"])) + "," + repr(now) + ");",
                "INSERT INTO oauth_clients (client_id,tenant_id,client_name,redirect_uris,created_at) VALUES ('client_member','ten_e9','Member'," + repr(json.dumps(["http://127.0.0.1:8750/callback"])) + "," + repr(now) + ");",
                "INSERT INTO oauth_clients (client_id,tenant_id,client_name,redirect_uris,created_at) VALUES ('client_foreign','ten_foreign','Foreign'," + repr(json.dumps(["http://127.0.0.1:8750/callback"])) + "," + repr(now) + ");",
                "INSERT INTO tenant_members (tenant_id,principal_id,role,created_at) VALUES ('ten_e9','prin_e9','owner'," + repr(now) + ");",
                "INSERT INTO tenant_members (tenant_id,principal_id,role,created_at) VALUES ('ten_e9','prin_member','member'," + repr(now) + ");",
                "INSERT INTO tenant_members (tenant_id,principal_id,role,created_at) VALUES ('ten_foreign','prin_foreign','owner'," + repr(now) + ");",
                "INSERT INTO oauth_tokens (access_token_hash,client_id,principal_id,scope,refresh_family,refresh_used,revoked,expires_at,created_at) VALUES (" + repr(digest(access)) + ",'client_e9','prin_e9'," + repr(scope) + ",'e9',0,0," + repr(expires) + "," + repr(now) + ");",
                "INSERT INTO oauth_tokens (access_token_hash,client_id,principal_id,scope,refresh_family,refresh_used,revoked,expires_at,created_at) VALUES (" + repr(digest(member)) + ",'client_member','prin_member'," + repr(scope) + ",'member',0,0," + repr(expires) + "," + repr(now) + ");",
                "INSERT INTO oauth_tokens (access_token_hash,client_id,principal_id,scope,refresh_family,refresh_used,revoked,expires_at,created_at) VALUES (" + repr(digest(foreign)) + ",'client_foreign','prin_foreign'," + repr(scope) + ",'foreign',0,0," + repr(expires) + "," + repr(now) + ");",
                *["INSERT INTO devices (id,tenant_id,principal_id,name,public_key,revoked,created_at,status) VALUES (" + repr(device) + ",'ten_e9','prin_e9'," + repr(device) + "," + repr(key) + ",0," + repr(now) + ",'active');" for device, key in ((device_source, source_key), (device_destination, destination_key))],
                *["INSERT INTO device_credentials (credential_hash,device_id,tenant_id,principal_id,role,expires_at,revoked,created_at) VALUES (" + repr(digest(credential)) + "," + repr(device) + ",'ten_e9','prin_e9','agent'," + repr(expires) + ",0," + repr(now) + ");" for device, credential in ((device_source, credential_source), (device_destination, credential_destination))],
            ])
            run_checked(wrangler(corepack, "d1", "execute", "DB", "--local", "--persist-to", str(persist), "--command", sql), cwd=CONTROL_PLANE, env=source_env)
            log = (temp / "wrangler.log").open("wb")
            wrangler_process = subprocess.Popen(wrangler(corepack, "dev", "--local", "--ip", "127.0.0.1", "--port", str(port), "--persist-to", str(persist), "--var", f"OAUTH_ISSUER:{issuer}", "--var", "OWNMESH_DEV_AUTH_BYPASS:true", "--var", f"SESSION_SECRET:{session_secret}", "--var", f"OWNER_TOKEN_HASH:{owner_token_hash}", "--var", f"OWNMESH_ALLOWED_ORIGINS:{issuer}", "--log-level", "info", "--show-interactive-dev-session", "false"), cwd=CONTROL_PLANE, env=source_env, stdout=log, stderr=subprocess.STDOUT)
            log.close(); wait_for_health(issuer, wrangler_process)
            binary = ROOT / "target" / "debug" / ("ownmeshd.exe" if os.name == "nt" else "ownmeshd")
            source_log, destination_log = temp / "source.log", temp / "destination.log"
            source_process = start_daemon(binary, source_env, source_log); destination_process = start_daemon(binary, destination_env, destination_log)
            wait_agent(source_process, source_log, source_root / "state"); wait_agent(destination_process, destination_log, destination_root / "state")
            source_ws, destination_ws = f"ws_{device_source}", f"ws_{device_destination}"
            assert_workspace_ready(issuer, access, device_source, source_ws, source_root / "state" / "workspace", marker, 10)
            assert_workspace_ready(issuer, access, device_destination, destination_ws, destination_root / "state" / "workspace", marker, 11)
            content = hashlib.shake_256((marker + "-primary").encode()).digest(196_864) + b"\x00E9\xff\x00tail"  # 196,873 bytes: >=3 64-KiB chunks
            source_file = source_root / "state" / "workspace" / "input.bin"; source_file.write_bytes(content)
            planned = public_call(issuer, access, "ownmesh_transfer_plan", {"source_device_id": device_source, "destination_device_id": device_destination, "source_workspace_id": source_ws, "destination_workspace_id": destination_ws, "source_path": "input.bin", "destination_path": "output.bin", "idempotency_key": f"e9-plan-{marker}"}, 20)
            transfer_id = op_id(planned)
            terminal = advance_until_terminal(issuer, access, transfer_id, marker)
            transfer = ((terminal.get("data") or {}).get("transfer") if isinstance(terminal.get("data"), dict) else None)
            if not isinstance(transfer, dict) or transfer.get("state") != "completed":
                raise RuntimeError(f"real two-Agent transfer did not complete: {terminal}")
            received = artifact_bytes(issuer, access, transfer_id)
            if received != content or hashlib.sha256(received).hexdigest() != hashlib.sha256(content).hexdigest():
                raise RuntimeError("public artifact pages did not reconstruct source bytes exactly")
            if (destination_root / "state" / "workspace" / "output.bin").read_bytes() != content:
                raise RuntimeError("destination file differs from public artifact")
            # Empty artifacts still use the authenticated finish/finish_ack
            # protocol; they must not be synthesized as a metadata-only
            # completion by the coordinator.
            (source_root / "state" / "workspace" / "empty.bin").write_bytes(b"")
            empty_plan = public_call(issuer, access, "ownmesh_transfer_plan", {
                "source_device_id": device_source, "destination_device_id": device_destination,
                "source_workspace_id": source_ws, "destination_workspace_id": destination_ws,
                "source_path": "empty.bin", "destination_path": "empty-output.bin",
                "idempotency_key": f"e9-empty-plan-{marker}",
            }, 24)
            empty_transfer_id = op_id(empty_plan)
            empty_terminal = advance_until_terminal(issuer, access, empty_transfer_id, marker + "-empty")
            if "completed" not in json.dumps(empty_terminal) or artifact_bytes(issuer, access, empty_transfer_id) != b"":
                raise RuntimeError(f"zero-byte public transfer failed: {empty_terminal}")
            if (destination_root / "state" / "workspace" / "empty-output.bin").read_bytes() != b"":
                raise RuntimeError("zero-byte destination artifact was not published")

            # Kill the destination only after a durable non-zero ACK cursor is
            # visible.  Restart the same real Agent identity/state and require
            # a fresh epoch/fence to resume, rather than retransferring from 0.
            resume_content = hashlib.shake_256((marker + "-resume").encode()).digest(32 * 1024 * 1024) + b"\x00resume\xff"  # >32 MiB
            (source_root / "state" / "workspace" / "resume.bin").write_bytes(resume_content)
            resume_plan = public_call(issuer, access, "ownmesh_transfer_plan", {
                "source_device_id": device_source, "destination_device_id": device_destination,
                "source_workspace_id": source_ws, "destination_workspace_id": destination_ws,
                "source_path": "resume.bin", "destination_path": "resume-output.bin",
                "idempotency_key": f"e9-resume-plan-{marker}",
            }, 29)
            resume_transfer_id = op_id(resume_plan)
            advance_until_state(
                issuer, access, resume_transfer_id, marker + "-resume", {"destination_preflight"}
            )
            # A public send may return after dispatching the source-boundary
            # revalidation while the transfer still reports destination_preflight.
            # Wait on the public state machine instead of assuming runner timing.
            resume_started = advance_until_state(
                issuer, access, resume_transfer_id, marker + "-resume", {"sending"}
            )
            started_state, started_meta = transfer_state(resume_started)
            if started_state != "sending" or started_meta.get("epoch") != 1 or started_meta.get("fence") != 1:
                raise RuntimeError(f"restart transfer did not enter first sending generation: {resume_started}")
            resume_source_plan_id = local_plan_id_for_destination(
                source_root / "state", "resume-output.bin", required_local_suffix=".source"
            )
            resume_plan_id = local_plan_id_for_destination(
                destination_root / "state", "resume-output.bin", required_local_suffix=".json"
            )
            transfer_state_root = destination_root / "state" / "transfers"
            resume_journal = transfer_state_root / f".{resume_plan_id}.json"
            resume_cursor = 0
            resume_part: Path | None = None
            cursor_deadline = time.monotonic() + 8
            while time.monotonic() < cursor_deadline:
                if resume_journal.is_file():
                    try:
                        journal = read_json_retry(resume_journal, 0.05)
                    except RuntimeError:
                        continue
                    journal_epoch = int(journal.get("epoch") or 0)
                    candidate_part = transfer_state_root / f".{resume_plan_id}.{journal_epoch}.part"
                    if not candidate_part.is_file():
                        time.sleep(0.01)
                        continue
                    resume_part = candidate_part
                    resume_cursor = int(journal.get("bytes_received") or 0)
                    if 0 < resume_cursor < len(resume_content):
                        break
                time.sleep(0.01)
            if resume_part is None or not 0 < resume_cursor < len(resume_content):
                raise RuntimeError("could not interrupt restart case after a durable partial ACK cursor")
            stop_process(destination_process); destination_process = None
            if (destination_root / "state" / "workspace" / "resume-output.bin").exists():
                raise RuntimeError("restart fault was injected after destination publication")
            restart_log_offset = destination_log.stat().st_size
            destination_process = restart_daemon(binary, destination_env, destination_log)
            wait_agent(
                destination_process, destination_log, destination_root / "state",
                after_bytes=restart_log_offset,
            )
            resume_terminal = advance_until_terminal(
                issuer, access, resume_transfer_id, marker + "-resume"
            )
            resume_state, resume_meta = transfer_state(resume_terminal)
            if resume_state != "completed" or int(resume_meta.get("epoch") or 0) < 2 or int(resume_meta.get("fence") or 0) < 2:
                raise RuntimeError(f"restart did not fence into a fresh generation: {resume_terminal}")
            resumed_bytes = (destination_root / "state" / "workspace" / "resume-output.bin").read_bytes()
            if resumed_bytes != resume_content:
                raise RuntimeError("restart/resume destination reconstruction differs from source")
            resumed_journal = read_json_retry(resume_journal)
            if int(resumed_journal.get("bytes_received") or -1) != len(resume_content):
                raise RuntimeError("restart/resume journal did not converge from durable ACK cursor")
            if int(resumed_journal.get("epoch") or 0) < 2 or int(resumed_journal.get("fence") or 0) < 2:
                raise RuntimeError("restart/resume journal did not retain its fresh generation")
            if list(transfer_state_root.glob(f".{resume_plan_id}.*.part")):
                raise RuntimeError("restart/resume left an active or retired generation part")
            source_transfer_root = source_root / "state" / "transfers"
            source_plan = source_transfer_root / f".{resume_source_plan_id}.plan.json"
            source_snapshot = source_transfer_root / f".{resume_source_plan_id}.source"
            # The parent operation, cleanup child and local filesystem are
            # observed through independent requests. Require physical absence
            # under a short hard deadline; never accept a receipt alone as
            # custody cleanup.
            cleanup_deadline = time.monotonic() + 5
            while (source_plan.exists() or source_snapshot.exists()) \
                    and time.monotonic() < cleanup_deadline:
                time.sleep(0.02)
            if source_plan.exists() or source_snapshot.exists():
                raise RuntimeError("completed restart/resume left source plan or snapshot custody")

            # Cancel another real transfer after at least one durable partial
            # chunk. The final destination must remain absent, the private part
            # must be removed, and only a bounded cancelled replay journal may remain.
            cancel_content = hashlib.shake_256((marker + "-cancel").encode()).digest(32 * 1024 * 1024) + b"\x00cancel\xfe"
            (source_root / "state" / "workspace" / "cancel.bin").write_bytes(cancel_content)
            cancel_plan = public_call(issuer, access, "ownmesh_transfer_plan", {
                "source_device_id": device_source, "destination_device_id": device_destination,
                "source_workspace_id": source_ws, "destination_workspace_id": destination_ws,
                "source_path": "cancel.bin", "destination_path": "cancel-output.bin",
                "idempotency_key": f"e9-cancel-plan-{marker}",
            }, 31)
            cancel_transfer_id = op_id(cancel_plan)
            advance_until_state(
                issuer, access, cancel_transfer_id, marker + "-cancel", {"destination_preflight"}
            )
            advance_until_state(
                issuer, access, cancel_transfer_id, marker + "-cancel", {"sending"}
            )
            cancel_plan_id = local_plan_id_for_destination(
                destination_root / "state", "cancel-output.bin", required_local_suffix=".json"
            )
            cancel_journal = destination_root / "state" / "transfers" / f".{cancel_plan_id}.json"
            partial = 0
            cancel_part: Path | None = None
            partial_deadline = time.monotonic() + 8
            while time.monotonic() < partial_deadline:
                if cancel_journal.is_file():
                    try:
                        journal = read_json_retry(cancel_journal, 0.05)
                    except RuntimeError:
                        continue
                    journal_epoch = int(journal.get("epoch") or 0)
                    candidate_part = transfer_state_root / f".{cancel_plan_id}.{journal_epoch}.part"
                    if not candidate_part.is_file():
                        time.sleep(0.01)
                        continue
                    cancel_part = candidate_part
                    partial = int(journal.get("bytes_received") or 0)
                    if 0 < partial < len(cancel_content):
                        break
                time.sleep(0.01)
            if cancel_part is None or not 0 < partial < len(cancel_content):
                raise RuntimeError("could not cancel after a durable partial chunk")
            public_call(issuer, access, "ownmesh_transfer_cancel", {
                "transfer_id": cancel_transfer_id,
                "idempotency_key": f"e9-cancel-{marker}",
            }, 33)
            cancel_terminal: dict[str, object] = {}
            for attempt in range(120):
                cancel_terminal = public_call(
                    issuer, access, "ownmesh_transfer_status", {"transfer_id": cancel_transfer_id},
                    8000 + attempt,
                )
                state, _ = transfer_state(cancel_terminal)
                if state in {"cancelled", "failed", "completed"}:
                    break
                time.sleep(0.25)
            cancel_state, _ = transfer_state(cancel_terminal)
            if cancel_state != "cancelled":
                raise RuntimeError(f"partial transfer cancellation did not converge: {cancel_terminal}")
            if (destination_root / "state" / "workspace" / "cancel-output.bin").exists():
                raise RuntimeError("partial cancellation left a destination or private part")
            if list(transfer_state_root.glob(f".{cancel_plan_id}.*.part")):
                raise RuntimeError("partial cancellation left an active or retired generation part")
            cancelled_journal = read_json_retry(cancel_journal)
            if str(cancelled_journal.get("state") or "").lower() != "cancelled":
                raise RuntimeError("partial cancellation did not leave a bounded replay tombstone")

            listed = public_call(issuer, access, "ownmesh_transfer_list", {"limit": 50}, 25)
            listed_text = json.dumps(listed)
            if any(item not in listed_text for item in (
                transfer_id, empty_transfer_id, resume_transfer_id, cancel_transfer_id
            )):
                raise RuntimeError(f"public transfer list omitted completed plans: {listed}")
            # Cross-tenant principal cannot observe or invoke a transfer by opaque ID.
            mcp_expect_rejected(issuer, foreign, "ownmesh_transfer_status", {"transfer_id": transfer_id}, rpc_id=21)
            mcp_expect_rejected(issuer, foreign, "ownmesh_transfer_plan", {"source_device_id": device_source, "destination_device_id": device_destination, "source_workspace_id": source_ws, "destination_workspace_id": destination_ws, "source_path": "input.bin", "destination_path": "foreign.bin", "idempotency_key": f"foreign-{marker}"}, rpc_id=22)
            # A member of the correct tenant is still not the device/workspace
            # owner and cannot use or observe the owner's transfer custody.
            mcp_expect_rejected(issuer, member, "ownmesh_transfer_status", {"transfer_id": transfer_id}, rpc_id=34)
            mcp_expect_rejected(issuer, member, "ownmesh_transfer_plan", {
                "source_device_id": device_source, "destination_device_id": device_destination,
                "source_workspace_id": source_ws, "destination_workspace_id": destination_ws,
                "source_path": "input.bin", "destination_path": "member.bin",
                "idempotency_key": f"member-{marker}",
            }, rpc_id=35)
            # Device/workspace/role bindings are server-owned.  A source cannot
            # nominate the destination's workspace, use one device for both
            # roles, or escape either registered root.
            mcp_expect_rejected(issuer, access, "ownmesh_transfer_plan", {
                "source_device_id": device_source, "destination_device_id": device_destination,
                "source_workspace_id": destination_ws, "destination_workspace_id": destination_ws,
                "source_path": "input.bin", "destination_path": "binding.bin",
                "idempotency_key": f"wrong-source-workspace-{marker}",
            }, rpc_id=26)
            mcp_expect_rejected(issuer, access, "ownmesh_transfer_plan", {
                "source_device_id": device_source, "destination_device_id": device_source,
                "source_workspace_id": source_ws, "destination_workspace_id": source_ws,
                "source_path": "input.bin", "destination_path": "same-device.bin",
                "idempotency_key": f"same-device-{marker}",
            }, rpc_id=27)
            mcp_expect_rejected(issuer, access, "ownmesh_transfer_plan", {
                "source_device_id": device_source, "destination_device_id": device_destination,
                "source_workspace_id": source_ws, "destination_workspace_id": destination_ws,
                "source_path": "../input.bin", "destination_path": "escape.bin",
                "idempotency_key": f"path-escape-{marker}",
            }, rpc_id=28)
            # Destination pre-exists: transfer must fail; it must never overwrite.
            protected = destination_root / "state" / "workspace" / "protected.bin"; protected.write_bytes(b"do-not-overwrite")
            blocked = public_call(issuer, access, "ownmesh_transfer_plan", {"source_device_id": device_source, "destination_device_id": device_destination, "source_workspace_id": source_ws, "destination_workspace_id": destination_ws, "source_path": "input.bin", "destination_path": "protected.bin", "idempotency_key": f"e9-no-overwrite-{marker}"}, 23)
            blocked_terminal = advance_until_terminal(issuer, access, op_id(blocked), marker + "-blocked")
            if protected.read_bytes() != b"do-not-overwrite" or "failed" not in json.dumps(blocked_terminal):
                raise RuntimeError(f"no-overwrite custody check failed: {blocked_terminal}")

            # Stop writers first, then inspect the actual Wrangler D1/DO SQLite
            # cells. User-requested artifact pages are the only allowed durable
            # byte payload and remain independently capped, hashed and TTL-bound.
            stop_process(source_process); source_process = None
            stop_process(destination_process); destination_process = None
            stop_process(wrangler_process); wrangler_process = None
            # taskkill /T has returned for the Wrangler/workerd process tree;
            # allow Windows to release the final mapped SQLite/WAL handles
            # before taking the immutable audit snapshot.
            time.sleep(0.5)
            audit_durable_state(
                persist,
                artifact_hashes={hashlib.sha256(content).hexdigest(), hashlib.sha256(b"").hexdigest()},
                secrets_forbidden=(
                    access, member, foreign, credential_source, credential_destination,
                    session_secret, password,
                ),
                payload_probes=(
                    content[8_192:12_288],
                    resume_content[8_192:12_288],
                    cancel_content[8_192:12_288],
                ),
                logs=(temp / "wrangler.log", source_log, destination_log),
            )
            diagnostics = ROOT / "target" / "e9-harness-diagnostics"
            if diagnostics.is_dir():
                for name in ("wrangler.log", "source.log", "destination.log", "operations.txt", "run.json", "local-state.json"):
                    (diagnostics / name).unlink(missing_ok=True)
                try:
                    diagnostics.rmdir()
                except OSError:
                    # Never remove unexpected diagnostic material owned by a
                    # different run or tool.
                    pass
            print(
                "E9 public two-Agent transfer passed "
                f"(transfer_id={transfer_id}, bytes={len(content)}, restart_cursor={resume_cursor})"
            )
            succeeded = True
            return 0
        finally:
            stop_process(source_process); stop_process(destination_process); stop_process(wrangler_process)
            if not succeeded:
                # Preserve only bounded text diagnostics in a fixed latest-run
                # directory.  Never retain workerd state, credentials, ticket
                # material, workspace bytes, or keychain contents on failure.
                diagnostics = ROOT / "target" / "e9-harness-diagnostics"
                diagnostics.mkdir(parents=True, exist_ok=True)
                for name in ("wrangler.log", "source.log", "destination.log"):
                    (diagnostics / name).write_text(
                        json.dumps(bounded_log_diagnostics(temp / name), indent=2),
                        encoding="utf-8",
                    )
                # Preserve only non-bearer operation diagnostics.  The select
                # deliberately excludes action/outbox/result bodies, proofs,
                # tickets, keys, and artifact content.
                try:
                    diagnostic_result = subprocess.run(
                        wrangler(
                            corepack, "d1", "execute", "DB", "--local",
                            "--persist-to", str(persist), "--command",
                            "SELECT tool,status,"
                            "json_extract(data_json,'$.error.code') AS error_code "
                            "FROM mcp_operations WHERE tool LIKE '%transfer%' ORDER BY created_at;",
                        ), cwd=CONTROL_PLANE, env=source_env, check=False,
                        text=True, encoding="utf-8", errors="replace",
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    )
                    operation_diagnostics = bounded_operation_diagnostics(diagnostic_result.stdout)
                except Exception:
                    operation_diagnostics = [{"diagnostic": "query_failed"}]
                (diagnostics / "operations.txt").write_text(
                    json.dumps(operation_diagnostics, indent=2), encoding="utf-8"
                )
                (diagnostics / "run.json").write_text(
                    json.dumps({"phase": "e9_public_transfer",
                                "run_digest": hashlib.sha256(marker.encode()).hexdigest()[:16]}, indent=2),
                    encoding="utf-8",
                )
                (diagnostics / "local-state.json").write_text(
                    json.dumps({
                        "source": bounded_local_transfer_diagnostics(source_root / "state"),
                        "destination": bounded_local_transfer_diagnostics(destination_root / "state"),
                    }, indent=2),
                    encoding="utf-8",
                )
            for env in (source_env, destination_env):
                cleanup = env.copy(); cleanup.pop("OWNMESH_E1_TEST_CREDENTIAL", None)
                subprocess.run([cargo, "run", "-q", "-p", "ownmeshd", "--example", "e1_loopback_provision", "--", "cleanup"], cwd=ROOT, env=cleanup, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"E9 public transfer acceptance failed: {error}", file=sys.stderr)
        raise SystemExit(1)
