"""Fail-closed gate tests (offline; no sockets are opened)."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import lab_gate  # noqa: E402


def scenario(host="10.20.30.40", authorization_id="AUTH-LAB-001"):
    return {
        "lab": {"purpose": lab_gate.PURPOSE, "authorization_id": authorization_id},
        "targets": [host],
        "dystopia": {"base_url": f"https://{host}:8099"},
        "elasticsearch": {"base_url": f"https://{host}:9200"},
        "kibana": {"base_url": f"https://{host}:5601"},
        "event": {
            "device_id": "srv-files-01",
            "segment_id": "seg-lab-edge",
            "instance_id": "cell-lab-01",
            "persona": "linux-file-server",
        },
        "poll": {"timeout_seconds": 1, "interval_seconds": 1},
    }


class LabGateTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dystopia-lab-gate-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write_case(self, data, targets="10.20.30.40", marker_auth="AUTH-LAB-001"):
        scenario_path = self.tmp / "scenario.json"
        scenario_path.write_text(json.dumps(data), encoding="utf-8")
        marker = self.tmp / "marker"
        marker.write_text(
            f"purpose={lab_gate.PURPOSE}\nauthorization_id={marker_auth}\n",
            encoding="utf-8",
        )
        os.chmod(marker, 0o600)
        return {
            "DYSTOPIA_LAB_E2E": "preflight",
            "DYSTOPIA_LAB_CONFIRM": lab_gate.CONFIRM_VALUE,
            "DYSTOPIA_LAB_SCENARIO": str(scenario_path),
            "DYSTOPIA_LAB_MARKER": str(marker),
            "DYSTOPIA_LAB_TARGETS": targets,
        }

    def test_disabled_by_default(self):
        self.assertIsNone(lab_gate.LabGate.from_environ({}))
        self.assertIsNone(lab_gate.LabGate.from_environ({"DYSTOPIA_LAB_E2E": ""}))

    def test_requires_explicit_confirmation(self):
        env = self.write_case(scenario())
        env.pop("DYSTOPIA_LAB_CONFIRM")
        with self.assertRaisesRegex(lab_gate.LabGateError, "CONFIRM"):
            lab_gate.LabGate.from_environ(env)

    def test_requires_marker_and_scenario(self):
        env = self.write_case(scenario())
        with self.assertRaisesRegex(lab_gate.LabGateError, "SCENARIO"):
            lab_gate.LabGate.from_environ({**env, "DYSTOPIA_LAB_SCENARIO": ""})
        with self.assertRaisesRegex(lab_gate.LabGateError, "MARKER"):
            lab_gate.LabGate.from_environ({**env, "DYSTOPIA_LAB_MARKER": ""})

    def test_rejects_unknown_mode(self):
        env = self.write_case(scenario())
        env["DYSTOPIA_LAB_E2E"] = "yes-please"
        with self.assertRaisesRegex(lab_gate.LabGateError, "preflight"):
            lab_gate.LabGate.from_environ(env)

    def test_rejects_public_and_documentation_targets(self):
        for host in ("203.0.113.5", "198.51.100.10", "8.8.8.8"):
            with self.subTest(host=host):
                data = scenario(host=host)
                env = self.write_case(data, targets=host)
                with self.assertRaisesRegex(lab_gate.LabGateError, "disposable-lab"):
                    lab_gate.LabGate.from_environ(env)

    def test_rejects_metadata_link_local_address(self):
        host = "169.254.169.254"
        env = self.write_case(scenario(host=host), targets=host)
        with self.assertRaisesRegex(lab_gate.LabGateError, "disposable-lab"):
            lab_gate.LabGate.from_environ(env)

    def test_rejects_host_not_in_explicit_allowlist(self):
        env = self.write_case(scenario(), targets="10.20.30.41")
        with self.assertRaisesRegex(lab_gate.LabGateError, "DYSTOPIA_LAB_TARGETS"):
            lab_gate.LabGate.from_environ(env)

    def test_rejects_url_with_embedded_credentials(self):
        data = scenario()
        data["elasticsearch"]["base_url"] = "https://user:secret@10.20.30.40:9200"
        env = self.write_case(data)
        with self.assertRaisesRegex(lab_gate.LabGateError, "credentials"):
            lab_gate.LabGate.from_environ(env)

    def test_rejects_plain_http_outside_loopback(self):
        data = scenario()
        data["elasticsearch"]["base_url"] = "http://10.20.30.40:9200"
        env = self.write_case(data)
        with self.assertRaisesRegex(lab_gate.LabGateError, "plain HTTP"):
            lab_gate.LabGate.from_environ(env)

    def test_rejects_inline_credentials_in_scenario(self):
        data = scenario()
        data["dystopia"]["password"] = "not-allowed-here"
        env = self.write_case(data)
        with self.assertRaisesRegex(lab_gate.LabGateError, "inline credentials"):
            lab_gate.LabGate.from_environ(env)

    def test_rejects_authorization_mismatch(self):
        data = scenario(authorization_id="AUTH-LAB-OTHER")
        env = self.write_case(data)
        with self.assertRaisesRegex(lab_gate.LabGateError, "authorization_id"):
            lab_gate.LabGate.from_environ(env)

    def test_rejects_wrong_marker_purpose(self):
        data = scenario()
        env = self.write_case(data)
        marker = Path(env["DYSTOPIA_LAB_MARKER"])
        marker.write_text("purpose=production\nauthorization_id=AUTH-LAB-001\n", encoding="utf-8")
        os.chmod(marker, 0o600)
        with self.assertRaisesRegex(lab_gate.LabGateError, "purpose"):
            lab_gate.LabGate.from_environ(env)

    def test_rejects_world_readable_token_file(self):
        data = scenario()
        token = self.tmp / "elastic.token"
        token.write_text("lab-api-key\n", encoding="utf-8")
        os.chmod(token, 0o644)
        data["elasticsearch"]["token_file"] = str(token)
        env = self.write_case(data)
        with self.assertRaisesRegex(lab_gate.LabGateError, "owner-only"):
            lab_gate.LabGate.from_environ(env)

    def test_accepts_private_lab_and_redacts_token(self):
        data = scenario()
        token = self.tmp / "elastic.token"
        token.write_text("lab-api-key\n", encoding="utf-8")
        os.chmod(token, 0o600)
        data["elasticsearch"]["token_file"] = str(token)
        gate = lab_gate.LabGate.from_environ(self.write_case(data))
        self.assertEqual(gate.mode, "preflight")
        self.assertEqual(gate.summary()["authorization_id"], "AUTH-LAB-001")
        self.assertEqual(gate.token("elasticsearch"), "Bearer lab-api-key")
        self.assertNotIn("lab-api-key", json.dumps(gate.summary()))

    def test_accepts_loopback_plain_http(self):
        data = scenario(host="127.0.0.1")
        for section in ("dystopia", "elasticsearch", "kibana"):
            data[section]["base_url"] = data[section]["base_url"].replace(
                "https://127.0.0.1", "http://127.0.0.1"
            )
        gate = lab_gate.LabGate.from_environ(self.write_case(data, targets="127.0.0.1"))
        self.assertEqual(gate.targets, {"127.0.0.1"})

    def test_example_scenario_is_inert(self):
        example = HERE / "fixtures" / "lab_scenario.example.json"
        data = json.loads(example.read_text(encoding="utf-8"))
        self.assertEqual(data["lab"]["purpose"], lab_gate.PURPOSE)
        # Without the explicit environment the harness must stay disabled.
        self.assertIsNone(lab_gate.LabGate.from_environ({}))

    def test_example_scenario_covers_required_flow_steps(self):
        example = HERE / "fixtures" / "lab_scenario.example.json"
        data = json.loads(example.read_text(encoding="utf-8"))
        names = " ".join(
            str(check.get("name", "")).lower() for check in data["dystopia"]["checks"]
        )
        self.assertIn("device", names)
        self.assertIn("cowrie", names)
        self.assertIn("activation", names)
        self.assertIn("restart_path", data["publisher"])
        self.assertIn("performed_env", data["ssh"])
        self.assertIn("persistence_check", data["dystopia"])


if __name__ == "__main__":
    unittest.main()


class LabHarnessHelperTests(unittest.TestCase):
    def test_resolve_pointer(self):
        document = {"devices": [{"id": "srv-files-01"}], "nested": {"state": "authorized"}}
        self.assertEqual(lab_gate.resolve_pointer(document, "nested.state"), "authorized")
        self.assertEqual(lab_gate.resolve_pointer(document, "devices[0].id"), "srv-files-01")
        self.assertIsNone(lab_gate.resolve_pointer(document, "devices[9].id"))

    def test_check_operators(self):
        document = {"state": "authorized", "devices": [{"id": "srv-files-01"}]}
        self.assertTrue(
            lab_gate.evaluate_check(document, {"pointer": "state", "op": "in", "value": ["authorized"]})
        )
        self.assertTrue(
            lab_gate.evaluate_check(
                document,
                {"pointer": "devices", "op": "contains_value", "value": "srv-files-01"},
            )
        )
        self.assertFalse(
            lab_gate.evaluate_check(document, {"pointer": "state", "op": "equals", "value": "active"})
        )
        with self.assertRaises(lab_gate.LabGateError):
            lab_gate.evaluate_check(document, {"pointer": "state", "op": "unknown"})

    def test_kibana_filter_translation(self):
        query = lab_gate.kibana_filter_to_es(
            {"field": "dystopia.device_id", "op": "eq", "value": "srv-files-01"}
        )
        self.assertEqual(query, {"term": {"dystopia.device_id": "srv-files-01"}})
        window = lab_gate.kibana_filter_to_es(
            {
                "field": "@timestamp",
                "op": "gte_lte",
                "value": "2026-10-29T10:00:00Z",
                "upper": "2026-10-29T11:00:00Z",
            }
        )
        self.assertIn("range", window)

    def test_client_refuses_path_that_is_an_absolute_url(self):
        client = lab_gate.LabClient("dystopia", "https://10.20.30.40:8099")
        with self.assertRaisesRegex(lab_gate.LabGateError, "absolute"):
            client.request("GET", "http://203.0.113.5:9200/_search")
