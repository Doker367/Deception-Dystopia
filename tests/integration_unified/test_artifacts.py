"""Artifact-level integration checks.

These tests read production artifacts when they exist and exercise production
normalizer/publisher code with in-process fakes. They never open a socket or
start a service. A failure here is an integration finding, not a test-fixture
problem: report it to the owning agent.
"""
from fnmatch import fnmatch
import json
import logging
import sys
import tempfile
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

import dystopia_contract as dc  # noqa: E402
import mapping_check  # noqa: E402

CANARY = "SYNTHETIC-CANARY-PASSWORD-6bc1-NOT-A-SECRET"


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _index_matches(index, patterns, aliases=()):
    """Accept a backing-index pattern, its data-stream name or rollover alias."""
    if index in aliases:
        return True
    for pattern in patterns:
        if fnmatch(index, pattern):
            return True
        if pattern.endswith("-*") and index == pattern[:-2]:
            return True
    return False


def _rollover_alias(template):
    settings = ((template.get("template") or {}).get("settings") or {})
    lifecycle = ((settings.get("index") or {}).get("lifecycle") or {})
    alias = lifecycle.get("rollover_alias")
    return {alias} if isinstance(alias, str) and alias else set()


def _event_template():
    for path in mapping_check.template_paths():
        template = _load(path)
        if any("events" in pattern for pattern in mapping_check.index_patterns(template)):
            return path, template
    return None, None


def _production_cowrie():
    from app.services.deception.integrations import cowrie_svc

    return cowrie_svc


def _resolver():
    from app.services.deception.integrations.ecs import StaticMetadata

    return StaticMetadata(
        devices={
            "srv-files-01": {
                "id": "srv-files-01",
                "segment": "seg-lab-edge",
                "ip": "192.0.2.10",
                "persona": {"vendor": "linux", "os": "ubuntu", "hostname": "srv-files-01"},
            }
        },
        segments={"seg-lab-edge": {"id": "seg-lab-edge", "vlan": 110}},
    )


def _normalize_fixture_cowrie():
    cowrie = _production_cowrie()
    resolver = _resolver()
    documents = []
    for line, raw in enumerate(dc.load_jsonl("events_cowrie.jsonl"), 1):
        document = cowrie.normalize(
            raw,
            resolver=resolver,
            instance_id="cell-lab-01",
            default_device="srv-files-01",
            raw_reference={"source": "events_cowrie.jsonl", "line": line},
        )
        assert document is not None
        documents.append(document)
    return documents


class ProductionNormalizerTests(unittest.TestCase):
    def test_production_cowrie_id_is_stable(self):
        first = _normalize_fixture_cowrie()
        second = _normalize_fixture_cowrie()
        self.assertEqual(
            [doc["event"]["id"] for doc in first],
            [doc["event"]["id"] for doc in second],
        )
        for document in first:
            self.assertTrue(document["event"]["id"])
            self.assertLessEqual(len(document["event"]["id"]), 512)

    def test_production_cowrie_keeps_captured_secret_out_of_the_document(self):
        document = _normalize_fixture_cowrie()[1]
        # The mapping declares dystopia.decoy_credentials as a keyword, and the
        # published document/log output must never contain the captured value.
        self.assertNotIn(CANARY, json.dumps(document, sort_keys=True, default=str))
        credentials = document.get("dystopia", {}).get("decoy_credentials")
        if hasattr(credentials, "get") and hasattr(credentials, "lower"):
            # Trusted in-process handlers may still resolve the captured value;
            # JSON serialisation above must not include it.
            captured = credentials.get("password")
            if captured is not None:
                self.assertEqual(captured, CANARY)

    def test_production_cowrie_topology_provenance(self):
        for document in _normalize_fixture_cowrie():
            self.assertEqual(document["dystopia"]["device_id"], "srv-files-01")
            self.assertEqual(document["dystopia"]["segment_id"], "seg-lab-edge")
            self.assertEqual(document["dystopia"]["instance_id"], "cell-lab-01")


class ProductionMappingCompatibilityTests(unittest.TestCase):
    def test_production_document_matches_event_template(self):
        path, template = _event_template()
        if template is None:
            self.skipTest("no production events index template found yet")
        root = mapping_check.mapping_root(template)
        failures = []
        for document in _normalize_fixture_cowrie():
            errors, warnings = mapping_check.check_document(document, root)
            for error in errors:
                failures.append(f"{path.name}: {error}")
            # Warnings are intentional for dynamic=false (stored, not indexed).
        unique = sorted(set(failures))
        self.assertEqual(unique, [], "\n".join(unique))

    def test_expected_fixture_documents_match_production_template(self):
        path, template = _event_template()
        if template is None:
            self.skipTest("no production events index template found yet")
        root = mapping_check.mapping_root(template)
        native, cowrie = dc.normalize_fixture_documents()
        failures = []
        for document in native + cowrie:
            errors, _ = mapping_check.check_document(document, root)
            failures.extend(f"{path.name}: {error}" for error in errors)
        unique = sorted(set(failures))
        self.assertEqual(unique, [], "\n".join(unique))


class ElasticConfigIntegrationTests(unittest.TestCase):
    def test_publisher_default_index_matches_template_and_role(self):
        from app.services.deception.integrations.elastic_svc import ElasticsearchConfig

        index = ElasticsearchConfig.from_env({}).index
        _path, template = _event_template()
        if template is None:
            self.skipTest("no production events index template found yet")
        patterns = mapping_check.index_patterns(template)
        aliases = _rollover_alias(template)
        self.assertTrue(patterns, "events template declares no index pattern")
        self.assertTrue(
            _index_matches(index, patterns, aliases),
            f"publisher default index {index!r} matches none of template patterns "
            f"{patterns} or aliases {sorted(aliases)}",
        )
        role_path = ROOT / "deploy/elastic/roles/deception-ingest-writer.json"
        if role_path.is_file():
            role = _load(role_path)
            resources = []
            for privilege in role.get("indices", []):
                resources.extend(privilege.get("names", []))
            self.assertTrue(
                _index_matches(index, resources),
                f"publisher index {index!r} is not allowed by {role_path.name}: {resources}",
            )

    def test_publisher_is_disabled_by_default(self):
        from app.services.deception.integrations.elastic_svc import (
            ElasticPublisher,
            ElasticsearchConfig,
            PublisherDisabled,
        )

        config = ElasticsearchConfig.from_env({})
        self.assertFalse(config.enabled)
        publisher = ElasticPublisher(config)
        with self.assertRaises(PublisherDisabled):
            publisher.publish({"event": {"id": "x"}})


class FakeTransport:
    """In-process Elasticsearch substitute: create-only by document id."""

    def __init__(self, status=None):
        self.documents = {}
        self.calls = []
        self.status = status

    def index(self, event_id, document, timeout):
        self.calls.append(event_id)
        if self.status is not None:
            return self.status
        payload = json.dumps(document, sort_keys=True, separators=(",", ":"))
        if event_id in self.documents:
            return 409
        self.documents[event_id] = payload
        return 201


class ProductionPublisherTests(unittest.TestCase):
    def config(self, **overrides):
        from app.services.deception.integrations.elastic_svc import ElasticsearchConfig

        values = dict(
            enabled=True,
            url="http://127.0.0.1:9200",
            index="dystopia-events-v1",
            timeout=1.0,
            max_retries=0,
            backoff=0,
            batch_size=200,
        )
        values.update(overrides)
        return ElasticsearchConfig(**values).validate()

    def test_publish_twice_creates_one_document(self):
        from app.services.deception.integrations.elastic_svc import ElasticPublisher

        transport = FakeTransport()
        publisher = ElasticPublisher(self.config(), transport=transport, sleep=lambda _: None)
        documents = _normalize_fixture_cowrie()
        for document in documents:
            self.assertTrue(publisher.publish(document))
        self.assertEqual(len(transport.documents), len(documents))
        # Restart: a new publisher replays the same spool against the same index.
        restarted = ElasticPublisher(self.config(), transport=transport, sleep=lambda _: None)
        for document in documents:
            self.assertTrue(restarted.publish(document))
        self.assertEqual(len(transport.documents), len(documents))

    def test_durable_queue_survives_publisher_restart(self):
        from app.services.deception.integrations.elastic_svc import ElasticPublisher

        with tempfile.TemporaryDirectory() as temporary:
            queue = Path(temporary) / "elastic-queue.db"
            first = ElasticPublisher(self.config(queue_path=queue), transport=FakeTransport())
            documents = _normalize_fixture_cowrie()
            for document in documents:
                self.assertTrue(first.enqueue(document))
            transport = FakeTransport()
            second = ElasticPublisher(self.config(queue_path=queue), transport=transport)
            self.assertEqual(second.flush(), len(documents))
            self.assertEqual(len(transport.documents), len(documents))
            self.assertEqual(second.health()["queued"], 0)

    def test_conflicting_queued_payload_is_rejected(self):
        from app.services.deception.integrations.elastic_svc import (
            DocumentConflict,
            ElasticPublisher,
        )

        transport = FakeTransport(status=503)
        publisher = ElasticPublisher(self.config(), transport=transport, sleep=lambda _: None)
        document = _normalize_fixture_cowrie()[0]
        self.assertFalse(publisher.publish(document))
        mutated = json.loads(json.dumps(document))
        mutated["source"]["ip"] = "198.51.100.77"
        with self.assertRaises(DocumentConflict):
            publisher.enqueue(mutated)

    def test_captured_secret_is_not_logged_on_rejection(self):
        from app.services.deception.integrations.elastic_svc import ElasticPublisher

        transport = FakeTransport(status=400)
        publisher = ElasticPublisher(self.config(), transport=transport, sleep=lambda _: None)
        document = _normalize_fixture_cowrie()[1]
        logger = logging.getLogger("app.services.deception.integrations.elastic_svc")
        with self.assertLogs(logger, level="ERROR") as captured:
            self.assertFalse(publisher.publish(document))
        output = "\n".join(captured.output)
        self.assertNotIn(CANARY, output)
        self.assertIn("elastic_rejected", output)


class KibanaArtifactTests(unittest.TestCase):
    def test_saved_objects_if_present(self):
        paths = []
        for pattern in (
            "deploy/kibana-dashboards/**/*.ndjson",
            "config/kibana/**/*.ndjson",
            "deploy/**/*.ndjson",
        ):
            paths.extend(ROOT.glob(pattern))
        paths = sorted({path for path in paths if path.is_file()})
        if not paths:
            self.skipTest("no Kibana NDJSON artifacts found yet")
        data_views = []
        for path in paths:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if record.get("type") in {"index-pattern", "data-view"}:
                    data_views.append((path, record))
        if not data_views:
            self.skipTest("Kibana artifacts exist but declare no data view/index-pattern")
        accepted = set(dc.load_json("mapping_expected.json")["accepted_index_patterns"])
        for path, record in data_views:
            attributes = record.get("attributes") or {}
            title = attributes.get("title")
            with self.subTest(artifact=path.name, title=title):
                self.assertIn(
                    title,
                    accepted,
                    f"{path.name} data view {title!r} is outside the documented contract",
                )
                self.assertEqual(
                    attributes.get("timeFieldName", "@timestamp"), "@timestamp"
                )


    def test_bundle_uses_kibana9_import_shape(self):
        path = ROOT / "deploy/kibana-dashboards/artifacts/deception-kibana-bundle.ndjson"
        if not path.is_file():
            self.skipTest("canonical Kibana bundle not generated yet")
        objects = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        by_id = {obj["id"]: obj for obj in objects}
        for obj in objects:
            if obj["type"] != "visualization":
                continue
            attrs = obj.get("attributes") or {}
            with self.subTest(vis=obj["id"]):
                self.assertNotIn("searchSourceJSON", attrs)
                meta = attrs.get("kibanaSavedObjectMeta") or {}
                source = json.loads(meta.get("searchSourceJSON", "{}"))
                self.assertEqual(
                    source.get("indexRefName"),
                    "kibanaSavedObjectMeta.searchSourceJSON.index",
                )
                state = json.loads(attrs["visState"])
                if state.get("type") in {"line", "histogram"}:
                    series = state.get("params", {}).get("seriesParams") or []
                    self.assertTrue(series, "line/histogram needs seriesParams")
                    self.assertIn("id", series[0].get("data", {}))
                self.assertTrue(obj.get("references"), "visualization lacks references")
        for obj in objects:
            if obj["type"] != "dashboard":
                continue
            attrs = obj.get("attributes") or {}
            panels = json.loads(attrs["panelsJSON"])
            refs = {ref["name"]: ref["id"] for ref in obj.get("references", [])}
            self.assertTrue(json.loads(attrs["kibanaSavedObjectMeta"]["searchSourceJSON"]) == {})
            for panel in panels:
                with self.subTest(dashboard=obj["id"], panel=panel.get("panelIndex")):
                    ref_name = panel.get("panelRefName")
                    self.assertIn(ref_name, refs)
                    self.assertIn(refs[ref_name], by_id)


if __name__ == "__main__":
    unittest.main()
