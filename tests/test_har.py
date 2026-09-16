import json
import tempfile
import unittest
from pathlib import Path

from exposedapi.har import import_har


class HarImportTests(unittest.TestCase):
    def test_redacts_secrets_filters_scope_and_deduplicates(self):
        har = {"log": {"entries": [
            {"request": {"method": "GET", "url": "https://console.circle.com/api/wallets/1234567890123456?token=secret", "headers": [{"name": "Cookie", "value": "secret"}]}, "response": {"status": 200, "content": {"text": "private"}}},
            {"request": {"method": "GET", "url": "https://console.circle.com/api/wallets/1234567890123456?token=other"}, "response": {"status": 403}},
            {"request": {"method": "POST", "url": "https://console.circle.com/api/delete"}, "response": {"status": 200}},
            {"request": {"method": "GET", "url": "https://example.com/api/data"}, "response": {"status": 200}},
            {"request": {"method": "GET", "url": "https://console.circle.com/app.js"}, "response": {"status": 200}},
        ]}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.har"
            path.write_text(json.dumps(har), encoding="utf-8")
            result = import_har(str(path), ["console.circle.com"])
        self.assertEqual(result["summary"]["unique_safe_endpoints"], 1)
        endpoint = result["endpoints"][0]
        self.assertEqual(endpoint["occurrences"], 2)
        self.assertEqual(endpoint["query_parameter_names"], ["token"])
        serialized = json.dumps(result)
        self.assertNotIn("secret", serialized)
        self.assertNotIn("private", serialized)


if __name__ == "__main__":
    unittest.main()
