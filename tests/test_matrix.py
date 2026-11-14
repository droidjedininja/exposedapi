import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from exposedapi.cli import main
from exposedapi.matrix import prepare_matrix, run_matrix
from exposedapi.scanner import HttpResponse


class MatrixTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"MATRIX_A": "Bearer secret-a", "MATRIX_B": "session=secret-b"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.document = {
            "accounts": {"owner": {"headers_env": {"Authorization": "MATRIX_A"}},
                         "other": {"headers_env": {"Cookie": "MATRIX_B"}}},
            "resources": [{"url": "https://api.example.com/objects/123?view=private-value",
                           "allowed_accounts": ["owner"]}]}
        self.scope = ["api.example.com"]

    def run_responses(self, statuses, bodies=None):
        responses = [HttpResponse(status, body, {}) for status, body in
                     zip(statuses, bodies or [b"private-body"] * len(statuses))]
        with patch("exposedapi.matrix.UrllibClient") as client, patch("exposedapi.matrix._RateLimiter.wait") as wait:
            client.return_value.get.side_effect = responses
            report = run_matrix(self.document, self.scope)
            calls = client.return_value.get.call_args_list
            self.assertEqual(wait.call_count, len(statuses))
        return report, calls

    def test_cross_account_and_anonymous_use_same_resource_without_credential_leak(self):
        report, calls = self.run_responses([200, 200, 403])
        self.assertEqual([row["classification"] for row in report["results"]],
                         ["expected access observed", "unexpected access review candidate", "expected denial observed"])
        self.assertTrue(report["results"][1]["matches_allowed_baseline"])
        self.assertEqual(calls[0].kwargs["headers"]["Authorization"], "Bearer secret-a")
        self.assertEqual(calls[1].kwargs["headers"]["Cookie"], "session=secret-b")
        self.assertNotIn("Authorization", calls[2].kwargs["headers"])
        self.assertNotIn("Cookie", calls[2].kwargs["headers"])
        for call in calls:
            self.assertEqual(call.args[0], self.document["resources"][0]["url"])
            self.assertFalse(call.kwargs["allow_redirects"])
        for secret in ("secret-a", "secret-b", "private-body", "private-value"):
            self.assertNotIn(secret, json.dumps(report))

    def test_failed_baseline_does_not_create_candidate(self):
        report, _ = self.run_responses([401, 200, 302])
        self.assertEqual(report["results"][1]["classification"], "inconclusive access result")
        self.assertEqual(report["results"][2]["classification"], "inconclusive access result")

    def test_anonymous_exposure_and_different_body_are_candidates(self):
        report, _ = self.run_responses([200, 200, 200], [b"owner", b"other", b"owner"])
        self.assertFalse(report["results"][1]["matches_allowed_baseline"])
        self.assertEqual(report["results"][2]["classification"], "unexpected access review candidate")

    def test_all_resources_validated_before_any_requests(self):
        for url in ("http://api.example.com/item", "https://outside.example/item",
                    "https://api.example.com/item?token=secret", "https://api.example.com/%6cogout"):
            with self.subTest(url=url), patch("exposedapi.matrix.UrllibClient") as client:
                document = copy.deepcopy(self.document)
                document["resources"].append({"url": url, "allowed_accounts": ["owner"]})
                with self.assertRaises(ValueError):
                    run_matrix(document, self.scope)
                client.assert_not_called()

    def test_invalid_expectations_and_credentials(self):
        for allowed in ([], ["missing"], ["owner", "owner"], "owner", [{}]):
            document = copy.deepcopy(self.document)
            document["resources"][0]["allowed_accounts"] = allowed
            with self.subTest(allowed=allowed), self.assertRaises(ValueError):
                prepare_matrix(document, self.scope)
        with patch.dict(os.environ, {"MATRIX_A": "bad\r\nheader"}), self.assertRaises(ValueError):
            prepare_matrix(self.document, self.scope)

    def test_cli_dry_run_and_report(self):
        with tempfile.TemporaryDirectory() as directory:
            matrix, scope, output = [Path(directory) / name for name in ("matrix.json", "scope.txt", "report.json")]
            matrix.write_text(json.dumps(self.document))
            scope.write_text("api.example.com\n")
            args = ["account-matrix", "--matrix", str(matrix), "--scope", str(scope),
                    "--output", str(output), "--acknowledge-authorization"]
            with patch("exposedapi.matrix.UrllibClient") as client:
                self.assertEqual(main(args + ["--dry-run"]), 0)
                client.assert_not_called()
            with patch("exposedapi.matrix.UrllibClient") as client, patch("exposedapi.matrix._RateLimiter.wait"):
                client.return_value.get.return_value = HttpResponse(200, b"body", {})
                self.assertEqual(main(args), 0)
            self.assertEqual(len(json.loads(output.read_text())["results"]), 3)
            with self.assertRaises(SystemExit):
                main(args[:-1])
