#!/usr/bin/env python3
"""Deterministic stdio fixtures for the nine E6 production adapter paths.

The wrapper executable name selects `E6_PROFILE`.  These are intentionally
strict: a wrong argv, JSON-RPC header, ordering, or ACP-v1 required fact exits
non-zero instead of making a permissive mock look like a conformance proof.
"""
from __future__ import annotations

import json
import os
import sys
import time


PROFILE = os.environ.get("E6_PROFILE", "")
ARGS = sys.argv[1:]
ACP = {"kimi-code", "opencode", "qwen-code", "hermes-agent", "qoder"}
DELAYED_COMPLETION_SECONDS = 5.0


def fail(message: str) -> None:
    print(json.dumps({"type": "error", "text": f"fixture: {message}"}), flush=True)
    raise SystemExit(17)


def read() -> dict[str, object]:
    line = sys.stdin.buffer.readline(65537)
    if not line or len(line) > 65536 or not line.endswith(b"\n"):
        fail("missing bounded LF frame")
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        fail("invalid JSON")
    if not isinstance(value, dict):
        fail("JSON object required")
    return value


def emit(value: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def codex() -> None:
    require(ARGS == ["app-server"], f"argv {ARGS!r}")
    first = read()
    require(first.get("id") == 1 and first.get("method") == "initialize" and "jsonrpc" not in first, "headerless initialize")
    emit({"id": 1, "result": {}})
    initialized = read()
    require(initialized.get("method") == "initialized" and "jsonrpc" not in initialized, "initialized after ack")
    thread = read()
    require(thread.get("id") == 2 and thread.get("method") in {"thread/start", "thread/resume"} and "jsonrpc" not in thread, "thread request")
    if thread.get("method") == "thread/resume":
        thread_params = thread.get("params") if isinstance(thread.get("params"), dict) else {}
        require(thread_params.get("threadId") == "native_codex", "Codex resume native id")
    emit({"id": 2, "result": {"thread": {"id": "native_codex"}}})
    turn = read()
    require(turn.get("id") == 3 and turn.get("method") == "turn/start" and "jsonrpc" not in turn, "turn start")
    # Longer than ownmeshd's three-second structured-bootstrap deadline. A
    # successful session.open therefore proves that open-ready does not wait
    # for the turn response, without depending on runner startup speed.
    time.sleep(DELAYED_COMPLETION_SECONDS)
    emit({"id": 3, "error": {"code": -32001, "message": "delayed fixture error"}})
    emit({"type": "message", "text": "codex-delayed-output", "native_session_id": "native_codex"})
    time.sleep(60)


def acp() -> None:
    expected = ["--acp"] if PROFILE in {"qwen-code", "qoder"} else ["acp"]
    require(ARGS == expected, f"argv {ARGS!r}")
    first = read()
    params = first.get("params") if isinstance(first.get("params"), dict) else {}
    require(first.get("jsonrpc") == "2.0" and first.get("id") == 1 and first.get("method") == "initialize", "ACP initialize")
    require(params.get("protocolVersion") == 1 and isinstance(params.get("clientCapabilities"), dict) and isinstance(params.get("clientInfo"), dict), "ACP v1 facts")
    # Every official ACP adapter uses capability-negotiated session/load for
    # native resume. None consume a second, hidden argv resume contract.
    can_load = True
    emit({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": 1, "agentCapabilities": {"loadSession": can_load}}})
    session = read()
    params2 = session.get("params") if isinstance(session.get("params"), dict) else {}
    method = session.get("method")
    require(session.get("jsonrpc") == "2.0" and session.get("id") == 2, "ACP session request id")
    require(method in {"session/new", "session/load"}, "ACP session/new or session/load")
    require(isinstance(params2.get("cwd"), str) and os.path.isabs(params2["cwd"]) and params2.get("mcpServers") == [], "ACP cwd/mcpServers")
    if method == "session/load":
        require(can_load and params2.get("sessionId") == f"native_{PROFILE.replace('-', '_')}", "ACP negotiated load")
        native = params2["sessionId"]
        emit({"jsonrpc": "2.0", "id": 2, "result": {}})
    else:
        native = f"native_{PROFILE.replace('-', '_')}"
        emit({"jsonrpc": "2.0", "id": 2, "result": {"sessionId": native}})
    prompt = read()
    require(prompt.get("jsonrpc") == "2.0" and prompt.get("id") == 3 and prompt.get("method") == "session/prompt", "ACP prompt")
    time.sleep(DELAYED_COMPLETION_SECONDS if PROFILE == "kimi-code" else 0.05)
    emit({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": native,
            "update": {
                "sessionUpdate": "agent_message_chunk",
                "content": {"type": "text", "text": f"{PROFILE}-output"},
            },
        },
    })
    emit({"jsonrpc": "2.0", "id": 3, "result": {"stopReason": "end_turn"}})
    time.sleep(60)


def pi() -> None:
    require(ARGS == ["--mode", "rpc"], f"argv {ARGS!r}")
    prompt = read()
    require(prompt == {"id": "ownmesh-prompt-1", "type": "prompt", "message": prompt.get("message")}, "strict Pi prompt")
    emit({
        "type": "message_update",
        "assistantMessageEvent": {"type": "text_delta", "delta": "pi-output"},
    })
    time.sleep(60)


def stream_json() -> None:
    if PROFILE == "claude-code":
        require(
            len(ARGS) >= 4 and ARGS[0] == "-p" and bool(ARGS[1])
            and "--output-format" in ARGS and "stream-json" in ARGS,
            f"argv {ARGS!r}",
        )
        if "--resume" in ARGS:
            resume_at = ARGS.index("--resume")
            require(resume_at + 1 < len(ARGS) and ARGS[resume_at + 1] == "native_claude_code", "Claude resume id")
    else:
        require(len(ARGS) >= 4 and ARGS[0] == "--print" and "--output-format" in ARGS and "stream-json" in ARGS, f"argv {ARGS!r}")
    native = f"native_{PROFILE.replace('-', '_')}"
    if PROFILE == "claude-code":
        emit({
            "type": "assistant",
            "session_id": native,
            "message": {"content": [{"type": "text", "text": "claude-code-output"}]},
        })
    else:
        emit({
            "type": "message",
            "role": "assistant",
            "content": "agy-output",
            "session_id": native,
        })
    time.sleep(60)


if PROFILE == "codex":
    codex()
elif PROFILE in ACP:
    acp()
elif PROFILE == "pi":
    pi()
elif PROFILE in {"claude-code", "agy"}:
    stream_json()
else:
    fail(f"unknown profile {PROFILE!r}")
