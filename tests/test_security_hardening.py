import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from exposedapi.cli import main, parse_header_env
from exposedapi.scanner import ScanConfig, contains_credentials, validate_target


class SecurityHardeningTests(unittest.TestCase):
    def test_scan_config_enforces_safe_bounds(self):
        self.assertEqual(ScanConfig(timeout=5, rate_limit=2, workers=4).workers, 4)
        for options in (
            {"timeout": float("nan")},
            {"rate_limit": float("inf")},
            {"workers": 0},
            {"workers": 9},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                ScanConfig(**options)

    def test_sensitive_query_values_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "sensitive query parameter"):
            validate_target(
                "https://api.example.com/profile?access_token=secret",
                ["api.example.com"],
                reject_sensitive_query=True,
            )

    def test_https_is_required_for_credentials(self):
        self.assertTrue(contains_credentials({"authorization": "Bearer secret"}))
        with self.assertRaisesRegex(ValueError, "HTTPS is required"):
            validate_target("http://api.example.com/profile", ["api.example.com"], require_https=True)

    def test_environment_header_parser(self):
        self.assertEqual(parse_header_env("X-API-Key=TEST_API_KEY"), ("X-API-Key", "TEST_API_KEY"))

    @patch("exposedapi.cli.scan_targets", return_value=[])
    def test_secret_header_is_loaded_from_environment(self, scan_targets):
        with tempfile.TemporaryDirectory() as directory:
            targets, scope = Path(directory) / "targets.txt", Path(directory) / "scope.txt"
            targets.write_text("https://api.example.com/profile\n", encoding="utf-8")
            scope.write_text("api.example.com\n", encoding="utf-8")
            output = str(Path(directory) / "result.json")
            with patch.dict(os.environ, {"TEST_API_KEY": "secret-value"}):
                self.assertEqual(main(["--targets", str(targets), "--scope", str(scope), "--header-env",
                                       "X-API-Key=TEST_API_KEY", "--output", output,
                                       "--acknowledge-authorization"]), 0)
        self.assertEqual(scan_targets.call_args.args[2]["X-API-Key"], "secret-value")


if __name__ == "__main__":
    unittest.main()
