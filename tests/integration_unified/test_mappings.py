"""Mapping contract: test-owned expectation and any production templates present."""
import re
import sys
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import dystopia_contract as dc  # noqa: E402
import mapping_check  # noqa: E402

ACCEPTED_EVENT_PATTERNS = {"deception-events-*", "deception-events*", "logstash-*"}
SECRET_FIELD_RE = re.compile(r"(?i)(^|\.)(password|passwd|pwd|secret|token|api[_-]?key)$")


def leaf_paths(value, prefix=""):
    paths = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            path = f"{prefix}.{key}" if prefix else key
            paths.update(leaf_paths(nested, path))
    elif isinstance(value, list):
        paths.add(prefix)
    else:
        paths.add(prefix)
    return paths


def node_at(root, path):
    current = root
    for part in path.split("."):
        current = (current.get("properties") or {}).get(part)
        if not isinstance(current, dict):
            return None
    return current


class ExpectedMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mapping = dc.load_json("mapping_expected.json")
        cls.flat = dc.flatten_mapping(dc.extract_mapping_properties(cls.mapping))
        cls.native, cls.cowrie = dc.normalize_fixture_documents()
        cls.documents = cls.native + cls.cowrie

    def test_expected_mapping_satisfies_required_contract(self):
        self.assertTrue(dc.validate_expected_mapping(self.mapping))

    def test_expected_mapping_declares_every_emitted_field(self):
        for document in self.documents:
            for path in leaf_paths(document):
                self.assertIn(path, self.flat, f"document emits undeclared field {path}")

    def test_expected_mapping_does_not_index_captured_secrets(self):
        offenders = [path for path in self.flat if SECRET_FIELD_RE.search(path)]
        self.assertEqual(offenders, [], f"secret-bearing indexed fields: {offenders}")

    def test_mapping_and_data_view_use_deception_events_index(self):
        self.assertIn(self.mapping["index_pattern"], ACCEPTED_EVENT_PATTERNS)
        kibana = dc.load_json("kibana_filters.json")
        self.assertIn(kibana["data_view"]["title"], ACCEPTED_EVENT_PATTERNS)
        self.assertEqual(kibana["data_view"]["time_field"], "@timestamp")

    def test_every_kibana_filter_field_is_mapped(self):
        kibana = dc.load_json("kibana_filters.json")
        for filter_spec in kibana["filters"]:
            with self.subTest(filter=filter_spec["label"]):
                self.assertIn(filter_spec["field"], self.flat)


class ProductionTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = mapping_check.template_paths()

    def test_templates_satisfy_core_required_fields(self):
        if not self.paths:
            self.skipTest(
                "no production Elasticsearch templates found yet "
                "(looked for config/elasticsearch/templates/*.json, deploy/elastic/**)"
            )
        failures = []
        checked = 0
        for path in self.paths:
            template = mapping_check.load_template(path)
            patterns = mapping_check.index_patterns(template)
            if not patterns:
                continue
            root = mapping_check.mapping_root(template)
            errors = dc.mapping_contract_errors(root.get("properties", {}))
            if errors:
                failures.append(f"{path.name}: " + "; ".join(errors))
            checked += 1
        if checked == 0:
            self.skipTest("template files exist but none declares index_patterns")
        self.assertEqual(failures, [], "\n".join(failures))

    def test_event_template_pattern_is_supported(self):
        if not self.paths:
            self.skipTest("no production Elasticsearch templates found yet")
        event_templates = []
        for path in self.paths:
            template = mapping_check.load_template(path)
            patterns = mapping_check.index_patterns(template)
            if any("events" in pattern for pattern in patterns):
                event_templates.append((path, patterns))
        if not event_templates:
            self.skipTest("no events index template found yet")
        for path, patterns in event_templates:
            with self.subTest(template=path.name):
                self.assertTrue(
                    set(patterns) & ACCEPTED_EVENT_PATTERNS,
                    f"{path.name} patterns {patterns} do not include a supported event pattern",
                )

    def test_event_template_declares_stable_identity_and_topology(self):
        if not self.paths:
            self.skipTest("no production Elasticsearch templates found yet")
        event_templates = []
        for path in self.paths:
            template = mapping_check.load_template(path)
            patterns = mapping_check.index_patterns(template)
            if any("events" in pattern for pattern in patterns):
                event_templates.append((path, mapping_check.mapping_root(template)))
        if not event_templates:
            self.skipTest("no events index template found yet")
        for path, root in event_templates:
            with self.subTest(template=path.name):
                self.assertEqual(root.get("dynamic"), "false")
                self.assertIsNotNone(node_at(root, "event.id"))
                self.assertIsNotNone(node_at(root, "dystopia.schema_version"))
                self.assertEqual(node_at(root, "dystopia").get("dynamic"), "strict")

    def test_templates_do_not_index_secret_fields(self):
        if not self.paths:
            self.skipTest("no production Elasticsearch templates found yet")
        failures = []
        for path in self.paths:
            root = mapping_check.mapping_root(mapping_check.load_template(path))
            for declared in sorted(mapping_check.declared_paths(root)):
                if not SECRET_FIELD_RE.search(declared):
                    continue
                node = node_at(root, declared) or {}
                if node.get("index") is not False:
                    failures.append(f"{path.name}: {declared} is indexed")
        self.assertEqual(failures, [], "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
