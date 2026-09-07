#!/usr/bin/env python3
"""Which layer answered? — classification tests for the machine-endpoint probe.

The probe (#159) exists to tell a Cloudflare edge rejection apart from a Worker
fault. A classifier that only recognizes the one page containing the literal
string ``Error 1010`` files every other challenge, block, and origin-error page
as ``unknown``, which excludes it from the blocked set and silently withholds
the WAF-rule guidance the operator needs. These cases pin the distinction.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROBE_PATH = ROOT / "scripts" / "probe_machine_endpoints.py"

_spec = importlib.util.spec_from_file_location("ownmesh_probe", PROBE_PATH)
assert _spec and _spec.loader
probe = importlib.util.module_from_spec(_spec)
# Registered before exec so the module's dataclasses can resolve their own
# module namespace under `from __future__ import annotations`.
sys.modules["ownmesh_probe"] = probe
_spec.loader.exec_module(probe)

HTML = {"cf-ray": "8f00deadbeef", "content-type": "text/html; charset=UTF-8"}
JSON_CT = {"content-type": "application/json"}


class EdgeRejectionIsRecognized(unittest.TestCase):
    """Every edge-generated answer must be attributed to the edge."""

    def assert_edge(self, status: int, headers: dict[str, str], body: bytes) -> None:
        layer, detail = probe.classify(status, headers, body)
        self.assertEqual(layer, "edge", f"HTTP {status} classified as {layer}: {detail}")

    def test_error_1010_browser_signature(self) -> None:
        self.assert_edge(403, HTML, b"<!DOCTYPE html><title>Error 1010</title>")

    def test_error_1010_lowercase_variant(self) -> None:
        self.assert_edge(403, HTML, b"<html>error code: 1010</html>")

    def test_managed_challenge(self) -> None:
        # The regression: `"<!DOCTYPE html>" in text.upper()` could never match,
        # because the needle kept lowercase `html>` while the haystack was
        # uppercased. Only the literal 1010 page was recognized.
        self.assert_edge(403, HTML, b"<!DOCTYPE html>\n<html>Attention Required! Cloudflare</html>")

    def test_js_challenge(self) -> None:
        self.assert_edge(503, HTML, b"<!doctype html>\n<html>Checking your browser</html>")

    def test_ip_or_asn_block_without_doctype(self) -> None:
        self.assert_edge(403, HTML, b"<html><body>Access denied</body></html>")

    def test_cloudflare_origin_errors_are_not_the_worker(self) -> None:
        # 520-527 are edge-generated. Attributing them to the Worker sends an
        # operator to debug code that was never reached.
        for status in (520, 521, 522, 523, 524, 525, 526, 527):
            self.assert_edge(status, HTML, b"<!DOCTYPE html><html>Web server is down</html>")

    def test_edge_rate_limit(self) -> None:
        self.assert_edge(429, {"cf-ray": "x", "content-type": "text/plain"}, b"rate limited")


class WorkerAnswersAreNotBlamedOnTheEdge(unittest.TestCase):
    """A Worker answer must never be reported as an edge rejection."""

    def assert_worker(self, status: int, headers: dict[str, str], body: bytes) -> None:
        layer, detail = probe.classify(status, headers, body)
        self.assertEqual(layer, "worker", f"HTTP {status} classified as {layer}: {detail}")

    def test_invalid_bearer_challenge_is_the_correct_contract(self) -> None:
        self.assert_worker(
            401,
            {"www-authenticate": 'Bearer resource_metadata="..."', **JSON_CT},
            b'{"error":"invalid_token"}',
        )

    def test_successful_discovery(self) -> None:
        self.assert_worker(200, JSON_CT, b'{"result":{"tools":[]}}')
        large = b'{"result":{"tools":["' + (b"x" * 8192) + b'"]}}'
        layer, detail = probe.classify(200, JSON_CT, large)
        self.assertEqual((layer, detail), ("worker", "HTTP 200"))

    def test_worker_5xx_stays_the_worker(self) -> None:
        self.assert_worker(500, JSON_CT, b'{"error":"internal"}')

    def test_malformed_json_rpc_is_a_worker_regression(self) -> None:
        layer, detail = probe.classify(200, JSON_CT, b"{not json")
        self.assertEqual(layer, "worker")
        self.assertIn("malformed", detail)


class MachineCategoriesAreStable(unittest.TestCase):
    def test_transport_failures_are_distinguished(self) -> None:
        cases = [
            (b"Could not resolve host", "dns_failure"),
            (b"certificate verify failed", "tls_failure"),
            (b"operation timed out", "connect_timeout"),
            (b"connection refused", "connect_failure"),
        ]
        for body, expected in cases:
            self.assertEqual(probe.category_for(None, "transport", "no response", body), expected)

    def test_worker_and_edge_categories_are_machine_readable(self) -> None:
        self.assertEqual(probe.category_for(403, "edge", probe.EDGE_1010_DETAIL, b""), "edge_1010")
        self.assertEqual(
            probe.category_for(
                401,
                "worker",
                "HTTP 401 with Bearer challenge (correct refresh contract)",
                b"",
            ),
            "worker_auth_contract",
        )
        self.assertEqual(
            probe.category_for(401, "worker", "HTTP 401 without challenge", b""),
            "worker_protocol_4xx",
        )
        self.assertEqual(probe.category_for(422, "worker", "schema", b""), "worker_protocol_4xx")
        self.assertEqual(probe.category_for(503, "worker", "failure", b""), "worker_5xx")


    def test_anonymous_discovery_cannot_pass_as_the_invalid_bearer_contract(self) -> None:
        def challenge(*_args: object, **_kwargs: object) -> tuple[int, dict[str, str], bytes]:
            return (
                401,
                {"content-type": "application/json", "www-authenticate": "Bearer"},
                b'{"error":"invalid_token"}',
            )

        original_urllib, original_curl = probe.request_urllib, probe.request_curl
        probe.request_urllib = challenge
        probe.request_curl = challenge
        try:
            results = probe.probe("https://cp.test")
        finally:
            probe.request_urllib = original_urllib
            probe.request_curl = original_curl
        invalid = next(result for result in results if result.name == "invalid bearer [urllib]")
        anonymous = next(result for result in results if result.name.startswith("tools/list"))
        self.assertTrue(invalid.ok)
        self.assertFalse(anonymous.ok)
        self.assertEqual(anonymous.category, "worker_protocol_4xx")


class UnknownStaysUnknown(unittest.TestCase):
    def test_no_response_is_transport(self) -> None:
        layer, _ = probe.classify(None, {}, b"")
        self.assertEqual(layer, "transport")

    def test_html_without_edge_headers_is_not_asserted_as_edge(self) -> None:
        # No cf-ray and no cf-mitigated: something answered with HTML, but
        # claiming it was Cloudflare would be a guess.
        layer, _ = probe.classify(403, {"content-type": "text/html"}, b"<html>nope</html>")
        self.assertEqual(layer, "unknown")


class DiscoveryCoversBothHandshakesOnBothStacks(unittest.TestCase):
    """#159: anonymous `initialize` and `tools/list` must be probed together."""

    def test_initialize_body_is_valid_anonymous_handshake(self) -> None:
        import json

        decoded = json.loads(probe.INITIALIZE_BODY)
        self.assertEqual(decoded["method"], "initialize")
        self.assertEqual(decoded["params"]["protocolVersion"], "2025-03-26")

    def test_probe_issues_initialize_and_invalid_bearer_on_urllib_and_curl(self) -> None:
        import json

        seen: list[str] = []

        def ok_discovery(*_args: object, **kwargs: object) -> tuple[int, dict[str, str], bytes]:
            body = kwargs.get("body", b"")
            if not isinstance(body, (bytes, bytearray)):
                return 200, {"content-type": "application/json"}, b"{}"
            try:
                method = json.loads(body).get("method", "")
            except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
                method = ""
            if method == "initialize":
                payload = b'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"ownmesh","version":"t"},"capabilities":{},"_meta":{"ownmesh/catalog_revision":"abc"}} }'
            else:
                payload = b'{"jsonrpc":"2.0","id":1,"result":{"tools":[],"_meta":{"ownmesh/catalog_revision":"abc"}}}'
            return 200, {"content-type": "application/json"}, payload

        def invalid_bearer(*_args: object, **_kwargs: object) -> tuple[int, dict[str, str], bytes]:
            return (
                401,
                {"content-type": "application/json", "www-authenticate": "Bearer"},
                b'{"error":"invalid_token"}',
            )

        def dispatch(url: str, *, method: str, body: bytes | None, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
            seen.append(f"{method} {url.split('/')[-1]} {headers.get('authorization', '')[:6]}")
            if headers.get("authorization", "").startswith("Bearer"):
                return invalid_bearer()
            return ok_discovery(body=body)

        original_urllib, original_curl = probe.request_urllib, probe.request_curl
        original_requests, original_node = probe.requests_available, probe.node_available
        probe.request_urllib = dispatch
        probe.request_curl = dispatch
        probe.requests_available = lambda: False
        probe.node_available = lambda: False
        try:
            results = probe.probe("https://cp.test")
        finally:
            probe.request_urllib = original_urllib
            probe.request_curl = original_curl
            probe.requests_available = original_requests
            probe.node_available = original_node
        names = [result.name for result in results]
        self.assertIn("initialize [urllib:python-urllib-default]", names)
        self.assertIn("initialize [curl:python-urllib-default]", names)
        self.assertIn("invalid bearer [urllib]", names)
        self.assertIn("invalid bearer [curl]", names)
        # An initialize answer must not be misread as an empty tool catalog.
        initialize = next(r for r in results if r.name == "initialize [urllib:python-urllib-default]")
        self.assertTrue(initialize.ok)
        self.assertFalse(any(note.startswith("tools=") for note in initialize.notes))
        listed = next(r for r in results if r.name.startswith("tools/list [urllib:"))
        self.assertIn("tools=0", listed.notes)
        for name in ("invalid bearer [urllib]", "invalid bearer [curl]"):
            invalid = next(r for r in results if r.name == name)
            self.assertTrue(invalid.ok)
            self.assertEqual(invalid.category, "worker_auth_contract")

    def test_optional_stacks_are_skipped_without_failing_when_absent(self) -> None:
        def ok(*_args: object, **kwargs: object) -> tuple[int, dict[str, str], bytes]:
            body = kwargs.get("body", b"")
            if b"initialize" in (body or b""):
                return 200, {"content-type": "application/json"}, b'{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{},"capabilities":{}}}'
            if kwargs.get("headers", {}).get("authorization", "").startswith("Bearer"):
                return 401, {"content-type": "application/json", "www-authenticate": "Bearer"}, b"{}"
            return 200, {"content-type": "application/json"}, b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'

        original_urllib, original_curl = probe.request_urllib, probe.request_curl
        original_requests, original_node = probe.requests_available, probe.node_available
        probe.request_urllib = ok
        probe.request_curl = ok
        probe.requests_available = lambda: False
        probe.node_available = lambda: False
        try:
            results = probe.probe("https://cp.test")
        finally:
            probe.request_urllib = original_urllib
            probe.request_curl = original_curl
            probe.requests_available = original_requests
            probe.node_available = original_node
        self.assertTrue(all(result.ok for result in results))
        self.assertFalse(any("requests" in r.name or "node" in r.name for r in results))

    def test_diagnostics_keep_ray_id_without_tokens_or_bodies(self) -> None:
        import json

        def edge(*_args: object, **_kwargs: object) -> tuple[int, dict[str, str], bytes]:
            return 403, {"cf-ray": "ray-123", "content-type": "text/html"}, b"<html>error code: 1010</html>"

        original_urllib, original_curl = probe.request_urllib, probe.request_curl
        original_requests, original_node = probe.requests_available, probe.node_available
        probe.request_urllib = edge
        probe.request_curl = edge
        probe.requests_available = lambda: False
        probe.node_available = lambda: False
        try:
            results = probe.probe("https://cp.test")
        finally:
            probe.request_urllib = original_urllib
            probe.request_curl = original_curl
            probe.requests_available = original_requests
            probe.node_available = original_node
        dumped = json.dumps([{"name": r.name, "status": r.status, "layer": r.layer, "category": r.category, "detail": r.detail, "cf_ray": r.cf_ray, "notes": r.notes} for r in results])
        self.assertIn("ray-123", dumped)
        self.assertIn("edge_1010", dumped)
        self.assertNotIn("atk_probe_invalid_token", dumped)
        self.assertNotIn("error code: 1010</html>", dumped)


class ProbeSmallContracts(unittest.TestCase):
    """#159 SHOULD: digest mismatch, bounded retries, and proxy preamble."""

    def _isolate_stacks(self):  # type: ignore[no-untyped-def]
        original_urllib, original_curl = probe.request_urllib, probe.request_curl
        original_requests, original_node = probe.requests_available, probe.node_available
        probe.requests_available = lambda: False
        probe.node_available = lambda: False
        return original_urllib, original_curl, original_requests, original_node

    def _restore_stacks(self, saved):  # type: ignore[no-untyped-def]
        original_urllib, original_curl, original_requests, original_node = saved
        probe.request_urllib = original_urllib
        probe.request_curl = original_curl
        probe.requests_available = original_requests
        probe.node_available = original_node

    def test_catalog_digest_mismatch_on_revision_skew(self) -> None:
        def revision_abc(*_args: object, **kwargs: object) -> tuple[int, dict[str, str], bytes]:
            body = kwargs.get("body", b"")
            method = ""
            try:
                import json as _json

                method = str(_json.loads(body).get("method", ""))  # type: ignore[union-attr]
            except Exception:
                method = ""
            if method == "initialize":
                payload = b'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{},"capabilities":{},"_meta":{"ownmesh/catalog_revision":"abc"}}}'
            elif kwargs.get("headers", {}).get("authorization", "").startswith("Bearer"):
                return 401, {"content-type": "application/json", "www-authenticate": "Bearer"}, b"{}"
            else:
                payload = b'{"jsonrpc":"2.0","id":1,"result":{"tools":[],"_meta":{"ownmesh/catalog_revision":"abc"}}}'
            return 200, {"content-type": "application/json"}, payload

        saved = self._isolate_stacks()
        probe.request_urllib = revision_abc  # type: ignore[method-assign]
        probe.request_curl = revision_abc  # type: ignore[method-assign]
        try:
            results = probe.probe("https://cp.test", expected_catalog_revision="xyz")
        finally:
            self._restore_stacks(saved)
        mismatched = [r for r in results if r.category == "catalog_digest_mismatch"]
        self.assertTrue(mismatched, "revision skew must surface as catalog_digest_mismatch")
        self.assertFalse(any(r.ok for r in mismatched))

    def test_bounded_attempts_record_retry_exhaustion(self) -> None:
        calls = {"n": 0}

        def always_transport_fail(*_args: object, **_kwargs: object) -> tuple[None, dict[str, str], bytes]:
            calls["n"] += 1
            return None, {}, b"connection refused"

        saved = self._isolate_stacks()
        probe.request_urllib = always_transport_fail  # type: ignore[method-assign]
        probe.request_curl = always_transport_fail  # type: ignore[method-assign]
        try:
            results = probe.probe("https://cp.test", max_attempts=2)
        finally:
            self._restore_stacks(saved)
        first = next(r for r in results if r.name.startswith("tools/list [urllib:"))
        self.assertEqual(first.attempts, 2)
        self.assertTrue(first.retry_exhausted)
        self.assertEqual(first.category, "connect_failure")

    def test_curl_proxy_preamble_uses_last_header_block(self) -> None:
        import subprocess

        raw = (
            b"HTTP/1.1 200 Connection established\r\nProxy-Agent: test\r\n\r\n"
            b"HTTP/1.1 403 Forbidden\r\ncontent-type: text/html\r\ncf-ray: proxy-ray-1\r\n\r\n"
            b"<html>blocked</html>"
        )
        real_run = subprocess.run

        def fake_run(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
            class Completed:
                returncode = 0
                stdout = raw
                stderr = b""

            return Completed()

        subprocess.run = fake_run  # type: ignore[method-assign]
        try:
            status, headers, payload = probe.request_curl(
                "https://cp.test/mcp", method="POST", body=b"{}", headers={"content-type": "application/json"}
            )
        finally:
            subprocess.run = real_run  # type: ignore[method-assign]
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("cf-ray"), "proxy-ray-1")
        self.assertIn(b"blocked", payload)

    def test_json_mentioning_1010_is_not_an_edge_block(self) -> None:
        # 1010 guard lives behind the non-JSON HTML shape: a Worker JSON body
        # that merely mentions 1010 stays a Worker answer.
        layer, _ = probe.classify(403, {"content-type": "application/json"}, b'{"error":"error 1010 in tool output"}')
        self.assertEqual(layer, "worker")
        category = probe.category_for(403, layer, "HTTP 403", b'{"error":"error 1010"}')
        self.assertEqual(category, "worker_protocol_4xx")

    def test_catalog_digest_match_stays_ok(self) -> None:
        # Normal case for the skew test above: agreeing revision is ok.

        def revision_abc(*_args: object, **kwargs: object) -> tuple[int, dict[str, str], bytes]:
            body = kwargs.get("body", b"")
            method = ""
            try:
                import json as _json

                method = str(_json.loads(body).get("method", ""))  # type: ignore[union-attr]
            except Exception:
                method = ""
            if method == "initialize":
                payload = b'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{},"capabilities":{},"_meta":{"ownmesh/catalog_revision":"abc"}}}'
            elif kwargs.get("headers", {}).get("authorization", "").startswith("Bearer"):
                return 401, {"content-type": "application/json", "www-authenticate": "Bearer"}, b"{}"
            else:
                payload = b'{"jsonrpc":"2.0","id":1,"result":{"tools":[],"_meta":{"ownmesh/catalog_revision":"abc"}}}'
            return 200, {"content-type": "application/json"}, payload

        saved = self._isolate_stacks()
        probe.request_urllib = revision_abc  # type: ignore[method-assign]
        probe.request_curl = revision_abc  # type: ignore[method-assign]
        try:
            results = probe.probe("https://cp.test", expected_catalog_revision="abc")
        finally:
            self._restore_stacks(saved)
        self.assertFalse(
            [r for r in results if r.category == "catalog_digest_mismatch"],
            "agreeing revision must not mismatch",
        )
        listed = next(r for r in results if r.name.startswith("tools/list [urllib:"))
        self.assertTrue(listed.ok)

    def test_bounded_attempts_boundaries_1_and_3(self) -> None:
        calls = {"n": 0}

        def always_transport_fail(*_args: object, **_kwargs: object) -> tuple[None, dict[str, str], bytes]:
            calls["n"] += 1
            return None, {}, b"connection refused"

        saved = self._isolate_stacks()
        probe.request_urllib = always_transport_fail  # type: ignore[method-assign]
        probe.request_curl = always_transport_fail  # type: ignore[method-assign]
        try:
            single = probe.probe("https://cp.test", max_attempts=1)
        finally:
            self._restore_stacks(saved)
        first_single = next(r for r in single if r.name.startswith("tools/list [urllib:"))
        self.assertEqual(first_single.attempts, 1)
        self.assertFalse(first_single.retry_exhausted, "max_attempts=1 never exhausts a retry")
        self.assertEqual(first_single.category, "connect_failure")

        calls["n"] = 0
        saved = self._isolate_stacks()
        probe.request_urllib = always_transport_fail  # type: ignore[method-assign]
        probe.request_curl = always_transport_fail  # type: ignore[method-assign]
        try:
            triple = probe.probe("https://cp.test", max_attempts=3)
        finally:
            self._restore_stacks(saved)
        first_triple = next(r for r in triple if r.name.startswith("tools/list [urllib:"))
        self.assertEqual(first_triple.attempts, 3)
        self.assertTrue(first_triple.retry_exhausted)
        self.assertEqual(first_triple.category, "connect_failure")

    def test_bounded_attempts_success_after_one_retry(self) -> None:
        calls = {"n": 0}

        def flaky(*_args: object, **kwargs: object) -> tuple[int | None, dict[str, str], bytes]:
            calls["n"] += 1
            if calls["n"] == 1:
                return None, {}, b"connection refused"
            body = kwargs.get("body", b"")
            if kwargs.get("headers", {}).get("authorization", "").startswith("Bearer"):
                return 401, {"content-type": "application/json", "www-authenticate": "Bearer"}, b"{}"
            if b"initialize" in (body or b""):
                return 200, {"content-type": "application/json"}, b'{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{},"capabilities":{}}}'
            return 200, {"content-type": "application/json"}, b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'

        saved = self._isolate_stacks()
        probe.request_urllib = flaky  # type: ignore[method-assign]
        probe.request_curl = flaky  # type: ignore[method-assign]
        try:
            results = probe.probe("https://cp.test", max_attempts=3)
        finally:
            self._restore_stacks(saved)
        first = next(r for r in results if r.name.startswith("tools/list [urllib:"))
        self.assertEqual(first.attempts, 2)
        self.assertFalse(first.retry_exhausted)
        self.assertTrue(first.ok)

    def test_curl_nonzero_returncode_is_transport(self) -> None:
        import subprocess

        real_run = subprocess.run

        def fake_fail(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
            class Completed:
                returncode = 6
                stdout = b""
                stderr = b"curl: (6) Could not resolve host"

            return Completed()

        subprocess.run = fake_fail  # type: ignore[method-assign]
        try:
            status, _, payload = probe.request_curl(
                "https://cp.test/mcp", method="POST", body=b"{}", headers={"content-type": "application/json"}
            )
        finally:
            subprocess.run = real_run  # type: ignore[method-assign]
        self.assertIsNone(status)
        self.assertIn(b"Could not resolve host", payload)
        self.assertEqual(probe.category_for(status, "transport", "no response", payload), "dns_failure")

    def test_curl_empty_output_is_transport(self) -> None:
        import subprocess

        real_run = subprocess.run

        def fake_empty(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
            class Completed:
                returncode = 0
                stdout = b""
                stderr = b""

            return Completed()

        subprocess.run = fake_empty  # type: ignore[method-assign]
        try:
            status, headers, _ = probe.request_curl(
                "https://cp.test/mcp", method="POST", body=b"{}", headers={"content-type": "application/json"}
            )
        finally:
            subprocess.run = real_run  # type: ignore[method-assign]
        self.assertIsNone(status)
        self.assertEqual(headers, {})


if __name__ == "__main__":
    unittest.main()
