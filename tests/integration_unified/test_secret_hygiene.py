"""Secret hygiene: normalized documents and publisher logs must not carry captured secrets."""
import json
import os
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import dystopia_contract as dc  # noqa: E402

CANARY = "SYNTHETIC-CANARY-PASSWORD-6bc1-NOT-A-SECRET"


class DocumentHygieneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native, cls.cowrie = dc.normalize_fixture_documents()
        cls.documents = cls.native + cls.cowrie

    def test_normalized_documents_have_no_secret_fields(self):
        for document in self.documents:
            with self.subTest(event_id=document["event"]["id"]):
                self.assertEqual(dc.scan_for_secrets(document, (CANARY,)), [])

    def test_captured_password_and_command_are_not_copied(self):
        serialized = json.dumps(self.documents, sort_keys=True)
        self.assertNotIn(CANARY, serialized)
        self.assertNotIn("uname -a", serialized)
        for document in self.documents:
            self.assertNotIn("password", dc.canonical_payload(document).lower())

    def test_scanner_detects_secrets_without_echoing_them(self):
        dirty = {
            "event": {"message": f"password={CANARY}"},
            "headers": {"authorization": "Bearer abcdefghijklmnop"},
            "url": "https://lab-user:lab-pass@example.invalid/login",
            "pem": "-----BEGIN PRIVATE KEY-----",
            "cloud": "AKIAABCDEFGHIJKLMNOP",
        }
        findings = dc.scan_for_secrets(dirty)
        self.assertGreaterEqual(len(findings), 5)
        joined = "\n".join(findings)
        for secret in (CANARY, "abcdefghijklmnop", "lab-pass", "AKIAABCDEFGHIJKLMNOP"):
            self.assertNotIn(secret, joined, "findings must not echo secret values")

    def test_scanner_flags_raw_cowrie_password(self):
        raw = dc.load_jsonl("events_cowrie.jsonl")
        findings = dc.scan_for_secrets(raw, (CANARY,))
        self.assertTrue(findings)
        self.assertTrue(any("secret-bearing field" in item for item in findings))

    def test_clean_publisher_log_passes_scan(self):
        path = HERE / "fixtures" / "logs" / "publisher_clean.log"
        findings = dc.scan_log_lines(path.read_text(encoding="utf-8").splitlines(), (CANARY,))
        self.assertEqual(findings, [])

    def test_log_scanner_catches_dirty_lines(self):
        lines = [
            f"2026-10-29T10:00:00Z INFO login password={CANARY}",
            "2026-10-29T10:00:00Z INFO Authorization: Bearer abcdefghijklmnop",
            "2026-10-29T10:00:00Z INFO elastic https://lab:lab-pass@10.0.0.2:9200",
            "2026-10-29T10:00:00Z INFO key AKIAABCDEFGHIJKLMNOP",
        ]
        findings = dc.scan_log_lines(lines, (CANARY,))
        self.assertGreaterEqual(len(findings), 4)
        self.assertNotIn(CANARY, "\n".join(findings))


class LabScenarioHygieneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scenario = dc.load_json("lab_scenario.example.json")

    def test_no_inline_credential_values(self):
        forbidden = {"password", "passwd", "secret", "token", "api_key", "apikey"}

        def walk(value, path="$"):
            if isinstance(value, dict):
                for key, nested in value.items():
                    self.assertNotIn(key.lower(), forbidden, f"inline credential key at {path}")
                    walk(nested, f"{path}.{key}")
            elif isinstance(value, list):
                for index, nested in enumerate(value):
                    walk(nested, f"{path}[{index}]")

        walk(self.scenario)

    def test_token_files_are_absolute_operator_paths(self):
        for section in ("dystopia", "elasticsearch", "kibana"):
            token_file = self.scenario[section]["token_file"]
            self.assertTrue(token_file.startswith("/"), f"{section} token_file must be absolute")
            self.assertFalse(
                Path(token_file).is_relative_to(ROOT),
                f"{section} token_file must not live in the repository",
            )

    def test_scenario_opens_no_ssh_and_sends_no_credentials(self):
        ssh = self.scenario["ssh"]
        self.assertNotIn("password", ssh)
        self.assertNotIn("private_key", ssh)
        self.assertEqual(ssh["performed_env"], "DYSTOPIA_LAB_SSH_PERFORMED")
        self.assertIn("synthetic", ssh["performed_token"].lower())

    def test_scenario_mentions_only_lab_targets(self):
        for host in self.scenario["targets"]:
            self.assertTrue(
                host.startswith(("10.", "172.", "192.168.", "127.")),
                f"example target {host} must be RFC1918/loopback",
            )


class OptionalLogArtifactTests(unittest.TestCase):
    def test_external_log_artifact_if_provided(self):
        path = os.environ.get("DYSTOPIA_LOG_ARTIFACT")
        if not path:
            self.skipTest(
                "set DYSTOPIA_LOG_ARTIFACT to an operator-provided publisher log to scan it"
            )
        target = Path(path)
        if not target.is_file():
            self.fail(f"DYSTOPIA_LOG_ARTIFACT does not exist: {path}")
        canaries = tuple(
            item for item in os.environ.get("DYSTOPIA_LOG_CANARIES", "").split(",") if item
        )
        findings = dc.scan_log_lines(
            target.read_text(encoding="utf-8", errors="replace").splitlines(), canaries
        )
        self.assertEqual(findings, [], "\n".join(findings))


if __name__ == "__main__":
    unittest.main()
