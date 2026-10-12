import hashlib
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from exposedapi.cli import main, parse_header
from exposedapi.scanner import RESEARCH_ORIGIN, _RateLimiter, host_in_scope, scan_endpoint, scan_targets, validate_target


class ScopeTests(unittest.TestCase):
    def test_exact_and_wildcard_scope(self):
        self.assertTrue(host_in_scope("api.example.com", ["api.example.com"]))
        self.assertTrue(host_in_scope("v1.api.example.com", ["*.api.example.com"]))
        self.assertFalse(host_in_scope("api.example.com", ["*.api.example.com"]))
        self.assertFalse(host_in_scope("example.net", ["*.example.com"]))

    def test_rejects_out_of_scope_and_embedded_credentials(self):
        with self.assertRaises(ValueError):
            validate_target("https://outside.example.net/x", ["api.example.com"])
        with self.assertRaises(ValueError):
            validate_target("https://user:pass@api.example.com/x", ["api.example.com"])


class ScannerTests(unittest.TestCase):
    def test_cors_reflection_is_a_candidate_and_redirects_are_disabled(self):
        response = Mock()
        response.status_code = 200
        response.content = b'{"ok":true}'
        response.headers = {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": RESEARCH_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        }
        session = Mock()
        session.get.return_value = response
        result = scan_endpoint("https://api.example.com/profile", ["api.example.com"], {}, 5, session)
        self.assertEqual(result.classification, "CORS origin-reflection review candidate")
        self.assertEqual(result.confidence, "medium")
        self.assertEqual(result.body_sha256, hashlib.sha256(response.content).hexdigest())
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])

    def test_rate_limiter_enforces_a_shared_start_interval(self):
        limiter = _RateLimiter(2)
        with patch("exposedapi.scanner.time.monotonic", side_effect=[0.0, 0.1, 0.5]), \
             patch("exposedapi.scanner.time.sleep") as sleep:
            limiter.wait()
            limiter.wait()
            limiter.wait()
        self.assertEqual(sleep.call_count, 2)
        self.assertAlmostEqual(sleep.call_args_list[0].args[0], 0.4)
        self.assertAlmostEqual(sleep.call_args_list[1].args[0], 0.5)

    def test_parallel_scan_preserves_input_order(self):
        targets = [
            "https://api.example.com/first",
            "https://api.example.com/second",
            "https://api.example.com/third",
        ]
        with patch("exposedapi.scanner.scan_endpoint", side_effect=lambda url, *_args: url), \
             patch("exposedapi.scanner.time.sleep"):
            results = scan_targets(targets, ["api.example.com"], {}, 5, 10, workers=3)
        self.assertEqual(results, targets)

    def test_dry_run_sends_no_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            targets = os.path.join(directory, "targets.txt")
            scope = os.path.join(directory, "scope.txt")
            with open(targets, "w", encoding="utf-8") as handle:
                handle.write("https://api.example.com/health\n")
            with open(scope, "w", encoding="utf-8") as handle:
                handle.write("api.example.com\n")
            self.assertEqual(main(["--targets", targets, "--scope", scope, "--dry-run", "--acknowledge-authorization"]), 0)


class CliTests(unittest.TestCase):
    def test_header_parser(self):
        self.assertEqual(parse_header("X-Test: value"), ("X-Test", "value"))


if __name__ == "__main__":
    unittest.main()
