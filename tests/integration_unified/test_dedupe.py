"""Deduplication: stable event identity, idempotent replay, conflict rejection."""
import json
import sys
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import dystopia_contract as dc  # noqa: E402


class DeduplicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topology = dc.load_topology()
        cls.cowrie_raw = dc.load_jsonl("events_cowrie.jsonl")
        cls.cowrie_docs = [
            dc.normalize_cowrie(raw, cls.topology, "srv-files-01")
            for raw in cls.cowrie_raw
        ]
        cls.scenario = dc.load_json("duplicates_scenario.json")

    def test_fixture_replay_scenario_counts(self):
        deduper = dc.Deduper()
        for batch in self.scenario["batches"]:
            selected = self.cowrie_docs
            subset = batch.get("subset_event_ids")
            if subset:
                selected = [
                    document
                    for document in self.cowrie_docs
                    if document["event"]["id"] in set(subset)
                ]
            for document in selected:
                deduper.add(document)
        expected = self.scenario["expected"]
        self.assertEqual(deduper.new, expected["unique_documents"])
        self.assertEqual(deduper.duplicates, expected["duplicate_deliveries"])
        self.assertEqual(len(deduper.keys), expected["unique_documents"])

    def test_event_id_is_stable_across_normalization_runs(self):
        first = [
            dc.normalize_cowrie(raw, self.topology, "srv-files-01")
            for raw in self.cowrie_raw
        ]
        second = [
            dc.normalize_cowrie(raw, self.topology, "srv-files-01")
            for raw in self.cowrie_raw
        ]
        self.assertEqual(
            [doc["event"]["id"] for doc in first],
            [doc["event"]["id"] for doc in second],
        )
        self.assertEqual(
            [dc.canonical_payload(doc) for doc in first],
            [dc.canonical_payload(doc) for doc in second],
        )

    def test_indexing_twice_is_idempotent(self):
        index = dc.InMemoryIndex()
        for document in self.cowrie_docs:
            self.assertEqual(index.index(document), "created")
        self.assertEqual(index.count(), len(self.cowrie_docs))
        for document in self.cowrie_docs:
            self.assertEqual(index.index(document), "duplicate")
        self.assertEqual(index.count(), len(self.cowrie_docs))

    def test_publisher_restart_replay_adds_no_documents(self):
        index = dc.InMemoryIndex()
        for document in self.cowrie_docs:
            index.index(document)
        before = index.count()
        self.assertEqual(before, len(self.cowrie_docs))
        # A new publisher process re-reads the same spool from the beginning.
        for _ in range(3):
            for document in self.cowrie_docs:
                index.index(document)
        self.assertEqual(index.count(), before)
        for key in [dc.document_key(document) for document in self.cowrie_docs]:
            self.assertEqual(index.count("event.id", key), 1)

    def test_event_id_must_be_globally_unique(self):
        # The _id is event.id alone. If a producer reuses an ID while changing
        # provenance, that is a conflict, not a second document.
        document = self.cowrie_docs[0]
        clone = json.loads(dc.canonical_payload(document))
        clone["observer"]["name"] = "cowrie-lab-02"
        index = dc.InMemoryIndex()
        index.index(document)
        with self.assertRaises(dc.ConflictError):
            index.index(clone)
        self.assertEqual(index.count(), 1)

    def test_conflicting_payload_is_rejected_not_overwritten(self):
        document = self.cowrie_docs[1]
        mutated = json.loads(dc.canonical_payload(document))
        mutated["source"]["ip"] = self.scenario["conflict_case"]["mutated_value"]
        index = dc.InMemoryIndex()
        index.index(document)
        with self.assertRaises(dc.ConflictError):
            index.index(mutated)
        self.assertEqual(index.count(), 1)
        stored = index.search("event.id", "eq", document["event"]["id"])[0]
        self.assertEqual(stored["source"]["ip"], document["source"]["ip"])

    def test_deduper_rejects_conflict(self):
        deduper = dc.Deduper()
        document = self.cowrie_docs[0]
        deduper.add(document)
        mutated = json.loads(dc.canonical_payload(document))
        mutated["session"]["id"] = "different-session"
        with self.assertRaises(dc.ConflictError):
            deduper.add(mutated)

    def test_index_refuses_document_without_identity(self):
        document = json.loads(dc.canonical_payload(self.cowrie_docs[0]))
        document["event"].pop("id")
        with self.assertRaises(dc.ContractError):
            dc.InMemoryIndex().index(document)

    def test_search_by_dystopia_device(self):
        index = dc.InMemoryIndex()
        for document in self.cowrie_docs:
            index.index(document)
        found = index.search("dystopia.device_id", "eq", "srv-files-01")
        self.assertEqual(len(found), len(self.cowrie_docs))
        self.assertEqual(index.search("dystopia.device_id", "eq", "absent"), [])


if __name__ == "__main__":
    unittest.main()
