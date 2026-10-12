import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from exposedapi.compare import _safe_targets, compare_hars
from exposedapi.scanner import HttpResponse


def entry(method, url, cookie="session=test"):
    return {"request": {"method": method, "url": url, "headers": [{"name": "Cookie", "value": cookie}]}}


class FakeClient:
    def get(self, url, headers, timeout, allow_redirects=False):
        body = b"private-response-body" if "/shared" in url else headers["Cookie"].encode()
        return HttpResponse(200, body, {"Content-Type": "application/json"})


class RecordingClient:
    def __init__(self):
        self.cookies = []

    def get(self, url, headers, timeout, allow_redirects=False):
        self.cookies.append(headers["Cookie"])
        return HttpResponse(200, b"same", {"Content-Type": "application/json"})


class CompareHarTests(unittest.TestCase):
    def test_filters_dangerous_and_out_of_scope_requests(self):
        entries = [
            entry("GET", "https://console.circle.com/api/shared"),
            entry("POST", "https://console.circle.com/api/change"),
            entry("GET", "https://console.circle.com/api/auth/callback?code=secret"),
            entry("GET", "https://console.circle.com/smart-contracts/contracts"),
            entry("GET", "https://example.com/api/shared"),
        ]
        self.assertEqual(len(_safe_targets(entries, ["console.circle.com"])), 1)
    def test_rejects_shared_sensitive_query_names(self):
        entries = [
            entry("GET", "https://console.circle.com/api/shared?api_key=secret"),
            entry("GET", "https://console.circle.com/api/shared?password=secret"),
        ]
        self.assertEqual(_safe_targets(entries, ["console.circle.com"]), [])

    @patch("exposedapi.compare.UrllibClient", return_value=FakeClient())
    @patch("exposedapi.compare.time.sleep", return_value=None)
    def test_comparison_never_writes_cookies_or_bodies(self, _sleep, _client):
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory) / "a.har", Path(directory) / "b.har"
            a.write_text(json.dumps({"log": {"entries": [entry("GET", "https://console.circle.com/api/shared", "session=a")]}}))
            b.write_text(json.dumps({"log": {"entries": [entry("GET", "https://console.circle.com/api/shared", "session=b")]}}))
            result = compare_hars(str(a), str(b), ["console.circle.com"], 10, 1)
        serialized = json.dumps(result)
        self.assertEqual(result["results"][0]["classification"], "same-response review candidate")
        self.assertNotIn("session=a", serialized)
        self.assertNotIn("session=b", serialized)
        self.assertNotIn("private-response-body", serialized)

    @patch("exposedapi.compare.time.sleep", return_value=None)
    def test_uses_endpoint_specific_cookies_for_each_account(self, _sleep):
        account_a = [
            entry("GET", "https://console.circle.com/api/first", "session=a1"),
            entry("GET", "https://console.circle.com/api/second", "session=a2"),
        ]
        account_b = [
            entry("GET", "https://console.circle.com/api/first", "session=b1"),
            entry("GET", "https://console.circle.com/api/second", "session=b2"),
        ]
        client = RecordingClient()
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory) / "a.har", Path(directory) / "b.har"
            a.write_text(json.dumps({"log": {"entries": account_a}}), encoding="utf-8")
            b.write_text(json.dumps({"log": {"entries": account_b}}), encoding="utf-8")
            with patch("exposedapi.compare.UrllibClient", return_value=client):
                result = compare_hars(str(a), str(b), ["console.circle.com"], 10, 1)
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(client.cookies, ["session=a1", "session=b1", "session=a2", "session=b2"])

    @patch("exposedapi.compare.time.sleep", return_value=None)
    def test_skips_ambiguous_endpoint_cookies(self, _sleep):
        entries_a = [
            entry("GET", "https://console.circle.com/api/shared", "session=a1"),
            entry("GET", "https://console.circle.com/api/shared", "session=a2"),
        ]
        entries_b = [entry("GET", "https://console.circle.com/api/shared", "session=b")]
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory) / "a.har", Path(directory) / "b.har"
            a.write_text(json.dumps({"log": {"entries": entries_a}}), encoding="utf-8")
            b.write_text(json.dumps({"log": {"entries": entries_b}}), encoding="utf-8")
            with patch("exposedapi.compare.UrllibClient", return_value=RecordingClient()):
                result = compare_hars(str(a), str(b), ["console.circle.com"], 10, 1)
        self.assertEqual(result["results"], [])


if __name__ == "__main__":
    unittest.main()
