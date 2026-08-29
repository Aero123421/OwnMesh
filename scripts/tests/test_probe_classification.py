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
        self.assertEqual(probe.category_for(403, "edge", "Cloudflare Error 1010", b""), "edge_1010")
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


if __name__ == "__main__":
    unittest.main()
