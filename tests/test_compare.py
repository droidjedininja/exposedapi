import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from exposedapi.compare import _cookies_by_host, _safe_targets, compare_hars
from exposedapi.scanner import HttpResponse


def entry(method, url, cookie="session=test"):
    return {"request": {"method": method, "url": url, "headers": [{"name": "Cookie", "value": cookie}]}}


class FakeClient:
    def get(self, url, headers, timeout, allow_redirects=False):
        body = b"private-response-body" if "/shared" in url else headers["Cookie"].encode()
        return HttpResponse(200, body, {"Content-Type": "application/json"})


class CompareHarTests(unittest.TestCase):
    def test_filters_dangerous_and_out_of_scope_requests(self):
        entries = [
            entry("GET", "https://console.circle.com/api/shared"),
            entry("POST", "https://console.circle.com/api/change"),
            entry("GET", "https://console.circle.com/api/auth/callback?code=secret"),
            entry("GET", "https://example.com/api/shared"),
        ]
        self.assertEqual(len(_safe_targets(entries, ["console.circle.com"])), 1)
        self.assertEqual(_cookies_by_host(entries)["console.circle.com"], "session=test")

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


if __name__ == "__main__":
    unittest.main()
