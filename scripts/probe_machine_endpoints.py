#!/usr/bin/env python3
"""Verify that machine-to-machine OwnMesh endpoints are reachable client-agnostically.

Background (#159): MCP discovery and the OAuth metadata endpoints are called by
programs, never by browsers. A Cloudflare zone rule that classifies clients by
browser signature can reject a perfectly valid JSON-RPC request with an
edge-generated ``HTTP 403 / Error 1010`` before it ever reaches the Worker. That
failure is invisible in Worker logs, carries no ``WWW-Authenticate`` challenge
(so OAuth refresh cannot recover it), and removes the whole tool catalog from
the client rather than failing one operation.

This probe sends the *same* request from several HTTP stacks and User-Agents and
reports which layer answered, so an edge rejection can never be mistaken for a
Worker problem. It is read-only: it performs anonymous discovery and one
deliberately invalid bearer request, and never sends credentials.

Usage::

    python scripts/probe_machine_endpoints.py https://<worker>.workers.dev
    python scripts/probe_machine_endpoints.py https://<worker>.workers.dev --json

Exit status is 0 only when every probe reached the Worker.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Any

DISCOVERY_BODY = json.dumps(
    {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
).encode("utf-8")

# A browser-like agent is included on purpose: when only this one succeeds, the
# zone is classifying clients by browser signature and the fix is a Cloudflare
# rule, not a code change.
USER_AGENTS = [
    ("python-urllib-default", None),
    ("curl-like", "curl/8.5.0"),
    ("openai-mcp", "OpenAI-MCP/1.0"),
    ("browser-like", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"),
]

# Every endpoint an MCP client touches without a human browser present.
MACHINE_PATHS = [
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/health",
]


@dataclass
class ProbeResult:
    name: str
    method: str
    path: str
    status: int | None
    layer: str
    category: str
    detail: str
    attempts: int = 1
    retry_exhausted: bool = False
    cf_ray: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.layer == "worker" and self.category in {"ok", "worker_auth_contract"}


def classify(status: int | None, headers: dict[str, str], body: bytes) -> tuple[str, str]:
    """Return ``(layer, detail)`` for one response.

    The distinction that matters is *who answered*: Cloudflare's edge or the
    Worker. A Worker 401 is a correct, recoverable protocol answer; an edge 403
    is an outage for every client with the wrong fingerprint.

    Classification is by *shape*, not by status code. Cloudflare's block,
    challenge, and origin-error pages span 403, 429, 503 and 520-527, and this
    endpoint only ever answers JSON — so an HTML body carrying a ``cf-ray`` is
    a far more reliable edge signal than any status allowlist. Keying on
    status alone is how a managed challenge or an IP block gets filed as
    ``unknown`` and never reaches the operator as a WAF-rule problem.
    """
    if status is None:
        return "transport", "no response"
    text = body[:4096].decode("utf-8", "replace")
    lowered = text.lower()
    content_type = headers.get("content-type", "")
    is_json = "application/json" in content_type
    # `<!doctype html` rather than `<!DOCTYPE html>`: the declaration is
    # case-insensitive and the closing bracket may be preceded by attributes.
    looks_like_html = "<!doctype html" in lowered or "<html" in lowered

    if "1010" in lowered and ("error 1010" in lowered or "error code: 1010" in lowered):
        return "edge", "Cloudflare Error 1010 (browser signature)"
    if not is_json and (looks_like_html or "cf-mitigated" in headers):
        # Cloudflare's own origin errors are 520-527 and are edge-generated,
        # so this must be decided before any 5xx is attributed to the Worker.
        if 520 <= status <= 527:
            return "edge", f"Cloudflare origin error {status} (Worker not reached)"
        if "cf-ray" in headers or "cf-mitigated" in headers:
            return "edge", f"Cloudflare challenge/block page (HTTP {status})"
        return "unknown", f"HTTP {status} returned HTML from an unidentified layer"
    if 520 <= status <= 527:
        return "edge", f"Cloudflare origin error {status} (Worker not reached)"
    if status == 429 and "cf-ray" in headers and not is_json:
        return "edge", "edge rate limit"
    if status == 401 and "www-authenticate" in headers:
        return "worker", "HTTP 401 with Bearer challenge (correct refresh contract)"
    if 500 <= status < 600:
        return "worker", f"Worker {status}"
    if is_json:
        try:
            # Shape detection is bounded above, but protocol validation must
            # parse the complete body: a normal tools/list is larger than the
            # 4 KiB HTML-sniff prefix and truncating it creates a false outage.
            json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return "worker", f"HTTP {status} with malformed JSON body"
        return "worker", f"HTTP {status}"
    return "unknown", f"HTTP {status} ({content_type or 'no content-type'})"


def category_for(
    status: int | None, layer: str, detail: str, body: bytes
) -> str:
    """Stable monitoring category, separate from human-readable detail."""
    text = body[:4096].decode("utf-8", "replace").lower()
    if status is None:
        if any(value in text for value in ("timed out", "timeout")):
            return "connect_timeout"
        if any(value in text for value in ("name or service not known", "nodename nor servname", "could not resolve", "temporary failure in name resolution")):
            return "dns_failure"
        if any(value in text for value in ("certificate", "ssl", "tls", "wrong version number")):
            return "tls_failure"
        return "connect_failure"
    if layer == "edge":
        if "1010" in detail:
            return "edge_1010"
        if 520 <= status <= 527:
            return "edge_origin_failure"
        return "edge_denial"
    if layer == "worker":
        if status == 401 and "correct refresh contract" in detail:
            return "worker_auth_contract"
        if 400 <= status < 500:
            return "worker_protocol_4xx"
        if status >= 500:
            return "worker_5xx"
        if "malformed" in detail:
            return "malformed_jsonrpc"
        return "ok"
    return "unknown_response"


def request_urllib(
    url: str, *, method: str, body: bytes | None, headers: dict[str, str]
) -> tuple[int | None, dict[str, str], bytes]:
    req = urllib.request.Request(url, data=body, method=method)
    for key, value in headers.items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:  # noqa: S310 - operator-supplied origin
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read()
    except urllib.error.HTTPError as error:
        return error.code, {k.lower(): v for k, v in error.headers.items()}, error.read()
    except urllib.error.URLError as error:
        return None, {}, str(error.reason).encode("utf-8", "replace")
    except TimeoutError as error:
        return None, {}, str(error).encode("utf-8", "replace")


def request_curl(
    url: str, *, method: str, body: bytes | None, headers: dict[str, str]
) -> tuple[int | None, dict[str, str], bytes]:
    """Second, independent HTTP stack.

    curl and Python differ in TLS library and header ordering, which is exactly
    the kind of difference a fingerprinting rule keys on.
    """
    argv = ["curl", "--silent", "--show-error", "--include", "--max-time", "20", "-X", method]
    for key, value in headers.items():
        argv += ["-H", f"{key}: {value}"]
    if body is not None:
        argv += ["--data-binary", "@-"]
    argv.append(url)
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, operator-supplied origin only
            argv, input=body, capture_output=True, timeout=30, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, {}, b""
    if proc.returncode != 0:
        return None, {}, proc.stderr
    raw = proc.stdout
    # Proxies and interim responses can prepend more than one HTTP header
    # block. Use the last consecutive block; parsing only the first can mistake
    # `200 Connection established` for the Worker response.
    parts = raw.split(b"\r\n\r\n")
    index = 0
    last_lines: list[str] = []
    while index < len(parts) - 1:
        lines = parts[index].decode("utf-8", "replace").splitlines()
        if not lines or not lines[0].startswith("HTTP/"):
            break
        last_lines = lines
        index += 1
    payload = b"\r\n\r\n".join(parts[index:])
    if not last_lines:
        return None, {}, payload
    try:
        status = int(last_lines[0].split()[1])
    except (IndexError, ValueError):
        return None, {}, payload
    parsed: dict[str, str] = {}
    for line in last_lines[1:]:
        key, _, value = line.partition(":")
        if value:
            parsed[key.strip().lower()] = value.strip()
    return status, parsed, payload


def probe(
    origin: str,
    *,
    expected_catalog_revision: str | None = None,
    max_attempts: int = 1,
) -> list[ProbeResult]:
    origin = origin.rstrip("/")
    results: list[ProbeResult] = []

    def record(
        name: str, method: str, path: str, sender: Any, headers: dict[str, str], body: bytes | None
    ) -> None:
        attempts = 0
        while True:
            attempts += 1
            status, response_headers, payload = sender(
                f"{origin}{path}", method=method, body=body, headers=headers
            )
            if status is not None or attempts >= max_attempts:
                break
            time.sleep(0.25 * attempts)
        layer, detail = classify(status, response_headers, payload)
        category = category_for(status, layer, detail, payload)
        if category == "worker_auth_contract" and not name.startswith("invalid bearer"):
            category = "worker_protocol_4xx"
            detail = "unexpected Bearer challenge on an anonymous machine endpoint"
        result = ProbeResult(
            name=name,
            method=method,
            path=path,
            status=status,
            layer=layer,
            category=category,
            detail=detail,
            attempts=attempts,
            retry_exhausted=status is None and attempts >= max_attempts and max_attempts > 1,
            cf_ray=response_headers.get("cf-ray"),
        )
        if layer == "worker" and path == "/mcp" and method == "POST" and status == 200:
            try:
                decoded = json.loads(payload)
                tools = decoded.get("result", {}).get("tools", [])
                meta = decoded.get("result", {}).get("_meta", {})
                result.notes.append(f"tools={len(tools)}")
                revision = meta.get("ownmesh/catalog_revision")
                if isinstance(revision, str) and revision:
                    # #158: comparable against the client's loaded catalog.
                    result.notes.append(f"catalog_revision={revision}")
                if expected_catalog_revision and revision != expected_catalog_revision:
                    result.category = "catalog_digest_mismatch"
                    result.detail = (
                        "published catalog revision is missing or differs from expected release"
                    )
            except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
                result.layer = "worker"
                result.category = "malformed_jsonrpc"
                result.detail = "HTTP 200 with malformed JSON-RPC body"
        results.append(result)

    # Anonymous MCP discovery from every stack and User-Agent.
    for label, agent in USER_AGENTS:
        headers = {
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
        }
        if agent:
            headers["user-agent"] = agent
        record(f"tools/list [urllib:{label}]", "POST", "/mcp", request_urllib, headers, DISCOVERY_BODY)
        record(f"tools/list [curl:{label}]", "POST", "/mcp", request_curl, headers, DISCOVERY_BODY)

    # An invalid bearer must reach the Worker and produce the 401 + challenge
    # refresh contract. An edge 403 here silently breaks OAuth recovery.
    record(
        "invalid bearer [urllib]",
        "POST",
        "/mcp",
        request_urllib,
        {
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
            "authorization": "Bearer atk_probe_invalid_token",
        },
        DISCOVERY_BODY,
    )

    for path in MACHINE_PATHS:
        record(f"metadata {path} [urllib]", "GET", path, request_urllib, {"accept": "application/json"}, None)

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("origin", help="Control plane origin, e.g. https://ownmesh.example.workers.dev")
    parser.add_argument("--json", action="store_true", help="emit machine-readable results")
    parser.add_argument(
        "--expected-catalog-revision",
        help="classify a successful tools/list with a different digest as catalog_digest_mismatch",
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=1,
        choices=range(1, 4),
        metavar="1..3",
        help="bounded attempts for transport failures (default: 1)",
    )
    args = parser.parse_args()

    results = probe(
        args.origin,
        expected_catalog_revision=args.expected_catalog_revision,
        max_attempts=args.attempts,
    )
    if args.json:
        categories: dict[str, int] = {}
        for result in results:
            categories[result.category] = categories.get(result.category, 0) + 1
        print(json.dumps({
            "schema_version": 1,
            "ok": all(result.ok for result in results),
            "categories": categories,
            "results": [asdict(result) for result in results],
        }, indent=2))
    else:
        width = max(len(r.name) for r in results)
        for r in results:
            status = r.status if r.status is not None else "---"
            mark = "ok  " if r.ok else "FAIL"
            notes = f"  {' '.join(r.notes)}" if r.notes else ""
            ray = f"  cf-ray={r.cf_ray}" if r.cf_ray and not r.ok else ""
            print(f"{mark} {r.name:<{width}}  {status:>4}  {r.layer:<9} {r.category:<24} {r.detail}{notes}{ray}")

    blocked = [r for r in results if r.layer == "edge"]
    failed = [r for r in results if not r.ok]
    if blocked:
        print(
            "\nEdge rejection detected: valid protocol requests are being answered by Cloudflare\n"
            "before the Worker sees them. Add a WAF custom rule that skips browser-integrity /\n"
            "bot-signature checks for the machine endpoints (see docs/deploy-cloudflare.md,\n"
            "'Machine endpoints must not require a browser signature'). Keep the Ray IDs above.",
            file=sys.stderr,
        )
    elif failed:
        print("\nSome probes did not reach the Worker; see the layer column.", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
