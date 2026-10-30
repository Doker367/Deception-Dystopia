"""Contract schema tests: fixtures must satisfy both Dystopia v1 and ECS-shape rules."""
import sys
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

import dystopia_contract as dc  # noqa: E402
from runtime import contracts as runtime_contracts  # noqa: E402


class FixtureSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topology = dc.load_topology()
        cls.native_raw = dc.load_jsonl("events_native.jsonl")
        cls.cowrie_raw = dc.load_jsonl("events_cowrie.jsonl")
        cls.native_docs = [
            dc.normalize_native(event, cls.topology) for event in cls.native_raw
        ]
        cls.cowrie_docs = [
            dc.normalize_cowrie(raw, cls.topology, "srv-files-01")
            for raw in cls.cowrie_raw
        ]

    def test_native_fixtures_are_valid_runtime_v1_events(self):
        for event in self.native_raw:
            with self.subTest(event_id=event.get("event_id")):
                runtime_contracts.validate_event(event)
                self.assertEqual(event["device_id"], "srv-files-01")
                self.assertIn(event["type"], runtime_contracts.TYPES)

    def test_cowrie_fixtures_have_stable_raw_identity(self):
        ids = [raw["eventid"] for raw in self.cowrie_raw]
        self.assertEqual(len(ids), len(set(ids)), "fixture eventids must be unique")
        for raw in self.cowrie_raw:
            self.assertEqual(str(dc.UUID(raw["eventid"])), raw["eventid"])
            self.assertIn("timestamp", raw)
            self.assertIn("session", raw)

    def test_reference_documents_validate_against_contract(self):
        for document in self.native_docs + self.cowrie_docs:
            with self.subTest(event_id=document["event"]["id"]):
                self.assertTrue(dc.validate_document(document, require_optional=True))

    def test_documents_carry_topology_provenance(self):
        docs = self.native_docs + self.cowrie_docs
        for document in docs:
            device_id = document["dystopia"]["device_id"]
            device = dc.topology_device(self.topology, device_id)
            self.assertEqual(document["dystopia"]["schema_version"], dc.SCHEMA_VERSION)
            self.assertEqual(document["dystopia"]["segment_id"], device["segment_id"])
            self.assertEqual(document["dystopia"]["instance_id"], device["instance_id"])
            self.assertEqual(document["dystopia"]["persona"], device["persona"])
            self.assertEqual(document["destination"]["ip"], device["destination_ip"])

    def test_cowrie_and_native_share_the_required_schema(self):
        required = set(dc.REQUIRED_FIELDS)
        for document in self.native_docs + self.cowrie_docs:
            for path in required:
                self.assertIsNotNone(
                    dc.get_path(document, path),
                    f"{document['event']['id']} lacks {path}",
                )

    def test_missing_or_malformed_cowrie_id_is_rejected(self):
        base = dict(self.cowrie_raw[0])
        for mutation in ("missing", "random", "not-canonical"):
            raw = dict(base)
            if mutation == "missing":
                raw.pop("eventid")
            elif mutation == "random":
                raw["eventid"] = "generated-on-the-fly"
            else:
                raw["eventid"] = base["eventid"].upper()
            with self.subTest(mutation=mutation):
                with self.assertRaises(dc.ContractError):
                    dc.normalize_cowrie(raw, self.topology, "srv-files-01")

    def test_cowrie_device_association_must_match_topology(self):
        raw = dict(self.cowrie_raw[0])
        raw["dst_ip"] = "192.0.2.99"
        with self.assertRaises(dc.ContractError):
            dc.normalize_cowrie(raw, self.topology, "srv-files-01")

    def test_timestamp_requires_explicit_timezone(self):
        raw = dict(self.cowrie_raw[0])
        raw["timestamp"] = "2026-10-29T10:05:00"
        with self.assertRaises(dc.ContractError):
            dc.normalize_cowrie(raw, self.topology, "srv-files-01")

    def test_source_address_must_be_literal_and_canonical(self):
        raw = dict(self.cowrie_raw[0])
        raw["src_ip"] = "203.0.113.9; DROP TABLE events"
        with self.assertRaises(dc.ContractError):
            dc.normalize_cowrie(raw, self.topology, "srv-files-01")

    def test_unknown_device_is_rejected(self):
        event = dict(self.native_raw[0])
        event["device_id"] = "unknown-device"
        with self.assertRaises(dc.ContractError):
            dc.normalize_native(event, self.topology)

    def test_documents_reject_missing_required_fields(self):
        document = dict(self.cowrie_docs[0])
        document["dystopia"] = dict(document["dystopia"])
        document["dystopia"].pop("segment_id")
        with self.assertRaises(dc.ContractError) as raised:
            dc.validate_document(document)
        self.assertIn("dystopia.segment_id", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
