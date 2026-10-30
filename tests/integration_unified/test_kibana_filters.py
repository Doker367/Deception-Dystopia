"""Kibana filter contract: filters must resolve against emitted documents."""
import sys
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import dystopia_contract as dc  # noqa: E402


class KibanaFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kibana = dc.load_json("kibana_filters.json")
        cls.mapping = dc.load_json("mapping_expected.json")
        cls.flat = dc.flatten_mapping(dc.extract_mapping_properties(cls.mapping))
        native, cowrie = dc.normalize_fixture_documents()
        cls.documents = native + cowrie
        cls.by_id = {doc["event"]["id"]: doc for doc in cls.documents}

    def test_data_view_points_at_unified_events(self):
        view = self.kibana["data_view"]
        self.assertIn(view["title"], self.mapping["accepted_index_patterns"])
        self.assertEqual(view["time_field"], "@timestamp")
        self.assertTrue(view["id"])

    def test_filters_only_reference_mapped_fields(self):
        for filter_spec in self.kibana["filters"]:
            with self.subTest(filter=filter_spec["label"]):
                self.assertIn(filter_spec["field"], self.flat)
                self.assertIn(filter_spec["op"], {"eq", "ne", "in", "prefix", "contains", "gte", "lte", "gte_lte"})

    def test_each_filter_returns_expected_documents(self):
        for filter_spec in self.kibana["filters"]:
            with self.subTest(filter=filter_spec["label"]):
                matched = dc.filter_documents(self.documents, filter_spec)
                actual = sorted(document["event"]["id"] for document in matched)
                self.assertEqual(actual, sorted(filter_spec["expected_event_ids"]))

    def test_filter_combinations_narrow_results(self):
        filters = self.kibana["filters"]
        device = next(item for item in filters if item["field"] == "dystopia.device_id")
        source = next(item for item in filters if item["field"] == "source.ip")
        selected = [
            document
            for document in self.documents
            if dc.apply_filter(document, device) and dc.apply_filter(document, source)
        ]
        self.assertEqual(len(selected), 7)
        self.assertNotIn(
            "639c61c2-9c6b-4a20-8b20-1fade65b3c5b",
            {document["event"]["id"] for document in selected},
            "scanner source must be filtered out",
        )

    def test_time_window_filter_is_inclusive(self):
        window = next(item for item in self.kibana["filters"] if item["op"] == "gte_lte")
        matched = dc.filter_documents(self.documents, window)
        self.assertEqual(len(matched), 5)
        self.assertTrue(all(document["event"]["dataset"] == "cowrie" for document in matched))

    def test_filter_by_stable_event_id(self):
        target = self.documents[0]["event"]["id"]
        matched = dc.filter_documents(
            self.documents, {"field": "event.id", "op": "eq", "value": target}
        )
        self.assertEqual([doc["event"]["id"] for doc in matched], [target])

    def test_no_filter_uses_captured_content(self):
        forbidden = ("password", "passwd", "input", "command_line", "dystopia.payload")
        for filter_spec in self.kibana["filters"]:
            for needle in forbidden:
                self.assertNotIn(needle, filter_spec["field"].lower())


if __name__ == "__main__":
    unittest.main()
