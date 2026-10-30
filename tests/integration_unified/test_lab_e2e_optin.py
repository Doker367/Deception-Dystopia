"""Opt-in, disposable-lab end-to-end scenario. SKIPPED unless explicitly enabled.

Offline default: every test in this module skips because ``DYSTOPIA_LAB_E2E``
is unset. Enabling requires the fail-closed gate in ``lab_gate.py`` (explicit
confirmation string, operator marker with an authorization id, explicit
RFC1918/loopback target allowlist, owner-only token files, no public or
metadata destinations).

Flow verified when enabled in ``full`` mode:
  1. preflight reachability and operator-defined Dystopia checks (device,
     Cowrie association, authorized activation);
  2. an operator-performed benign SSH login to the lab honeypot (the harness
     NEVER opens SSH, sends credentials or attacks anything);
  3. the event is persisted and indexed in Elasticsearch;
  4. the Kibana data view points at the mapped index and configured filters
     return the expected documents;
  5. restarting the publisher creates no duplicate document.

The harness sends only health/read requests and a publisher restart POST to
explicitly allowlisted lab addresses. It contains no credentials or exploits.
"""
from datetime import datetime, timedelta, timezone
import os
import sys
import time
from pathlib import Path
from urllib.parse import quote
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import dystopia_contract as dc  # noqa: E402
import lab_gate  # noqa: E402


def _iso_now_minus(seconds):
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z"
    )


class LabOptInTests(unittest.TestCase):
    def setUp(self):
        if not os.environ.get("DYSTOPIA_LAB_E2E"):
            self.skipTest(
                "opt-in lab E2E disabled: set DYSTOPIA_LAB_E2E, "
                "DYSTOPIA_LAB_CONFIRM=DISPOSABLE-LAB-ONLY, DYSTOPIA_LAB_MARKER, "
                "DYSTOPIA_LAB_TARGETS and DYSTOPIA_LAB_SCENARIO to enable"
            )
        # A mode was requested: misconfiguration is an error, not a skip.
        self.gate = lab_gate.LabGate.from_environ(os.environ)
        self.scenario = self.gate.scenario
        self.index_pattern = self.scenario["elasticsearch"].get("index_pattern", "logstash-*")
        self.poll_timeout = float(self.scenario.get("poll", {}).get("timeout_seconds", 90))
        self.poll_interval = float(self.scenario.get("poll", {}).get("interval_seconds", 3))

    # -- helpers ---------------------------------------------------------- #
    def _poll(self, operation, description):
        deadline = time.monotonic() + self.poll_timeout
        last_error = None
        while time.monotonic() < deadline:
            try:
                result = operation()
            except lab_gate.LabGateError as exc:
                last_error = str(exc)
            else:
                if result:
                    return result
            time.sleep(self.poll_interval)
        detail = f": {last_error}" if last_error else ""
        self.fail(f"timed out after {self.poll_timeout:.0f}s waiting for {description}{detail}")

    def _count(self, client, query):
        status, payload = client.request(
            "POST",
            f"/{lab_gate.quote_index(self.index_pattern)}/_count",
            body=query,
        )
        self.assertEqual(status, 200)
        self.assertIsInstance(payload, dict)
        return int(payload.get("count", 0))

    def _search(self, client, query):
        status, payload = client.request(
            "POST",
            f"/{lab_gate.quote_index(self.index_pattern)}/_search",
            body=query,
        )
        self.assertEqual(status, 200)
        self.assertIsInstance(payload, dict)
        return payload

    # -- preflight -------------------------------------------------------- #
    def test_preflight_and_topology_checks(self):
        dystopia = self.gate.client("dystopia")
        status, _ = dystopia.request(
            "GET", self.scenario["dystopia"].get("health_path", "/api/health")
        )
        self.assertEqual(status, 200)

        elasticsearch = self.gate.client("elasticsearch")
        status, _ = elasticsearch.request("GET", "/_cluster/health")
        self.assertIn(status, (200, 204))

        kibana = self.gate.client("kibana")
        status, _ = kibana.request("GET", "/api/status")
        self.assertEqual(status, 200)

        for check in self.scenario["dystopia"].get("checks", []):
            with self.subTest(check=check.get("name", check.get("path"))):
                method = check.get("method", "GET").upper()
                status, payload = dystopia.request(method, check["path"])
                self.assertIn(status, (200, 204))
                self.assertTrue(
                    lab_gate.evaluate_check(payload, check),
                    f"check failed: {check.get('name')} "
                    f"(pointer={check.get('pointer')!r}, op={check.get('op')!r})",
                )

    # -- full flow -------------------------------------------------------- #
    def test_full_flow_after_authorized_synthetic_ssh(self):
        if self.gate.mode != "full":
            self.skipTest("preflight mode selected; set DYSTOPIA_LAB_E2E=full for the full flow")

        ssh = self.scenario.get("ssh") or {}
        env_name = ssh.get("performed_env", "DYSTOPIA_LAB_SSH_PERFORMED")
        expected = ssh.get("performed_token")
        performed = os.environ.get(env_name)
        if not performed or (expected and performed != expected):
            self.skipTest(
                "operator has not confirmed the authorized benign SSH login: "
                f"set {env_name}={expected or '<token>'} after performing it"
            )

        elasticsearch = self.gate.client("elasticsearch")
        dystopia = self.gate.client("dystopia")
        event = self.scenario["event"]
        since = os.environ.get("DYSTOPIA_LAB_SINCE") or _iso_now_minus(
            max(600, self.poll_timeout + 300)
        )
        filters = [
            {"term": {"dystopia.device_id": event["device_id"]}},
            {"term": {"dystopia.segment_id": event["segment_id"]}},
            {"range": {"@timestamp": {"gte": since}}},
        ]
        if event.get("observer_name"):
            filters.append({"term": {"observer.name": event["observer_name"]}})
        query = {
            "size": 20,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"filter": filters}},
        }

        hits = self._poll(
            lambda: self._search(elasticsearch, query).get("hits", {}).get("hits", []),
            "the lab SSH interaction to be indexed in Elasticsearch",
        )
        event_ids = []
        for hit in hits:
            document = hit.get("_source") or {}
            with self.subTest(event_id=document.get("event", {}).get("id")):
                dc.validate_document(document, require_optional=True)
                event_ids.append(document["event"]["id"])
                self.assertTrue(document["session"]["id"])
                self.assertEqual(document["dystopia"]["device_id"], event["device_id"])
                self.assertEqual(document["dystopia"]["segment_id"], event["segment_id"])

        self.assertEqual(
            len(event_ids),
            len(set(event_ids)),
            "the same event.id appears more than once in one search response",
        )

        # The Dystopia telemetry store must have persisted the interaction too;
        # the scenario supplies the operator-specific endpoint/pointer.
        persistence = self.scenario["dystopia"].get("persistence_check")
        if persistence:
            def persisted():
                status, payload = dystopia.request(
                    persistence.get("method", "GET").upper(),
                    persistence["path"],
                    params=persistence.get("params"),
                )
                self.assertIn(status, (200, 204))
                return payload if lab_gate.evaluate_check(payload, persistence) else None

            self._poll(persisted, "the event to appear in Dystopia telemetry")

        # Deduplication at rest: each event ID is exactly one document.
        for event_id in event_ids[:5]:
            with self.subTest(dedupe_event_id=event_id):
                count = self._count(
                    elasticsearch, {"query": {"term": {"event.id": event_id}}}
                )
                self.assertEqual(count, 1)

        # Deployed mapping satisfies the required contract.
        status, mapping_payload = elasticsearch.request(
            "GET", f"/{lab_gate.quote_index(self.index_pattern)}/_mapping"
        )
        self.assertEqual(status, 200)
        checkable = 0
        for index_name, index_body in (mapping_payload or {}).items():
            root = (index_body or {}).get("mappings") or {}
            if "properties" not in root:
                continue
            errors = dc.mapping_contract_errors(root["properties"])
            self.assertEqual(errors, [], f"{index_name}: " + "; ".join(errors))
            checkable += 1
        self.assertGreater(checkable, 0, "no concrete index mapping was returned")

        # Kibana data view (modern API, legacy saved object fallback).
        data_view_id = self.scenario["kibana"].get("data_view_id", "dystopia-events-lab")
        data_view = None
        for path in (
            f"/api/data_views/data_view/{quote(data_view_id, safe='')}",
            f"/api/saved_objects/index-pattern/{quote(data_view_id, safe='')}",
        ):
            try:
                status, payload = self.gate.client("kibana").request("GET", path)
            except lab_gate.LabGateError:
                continue
            if status == 200:
                data_view = payload
                break
        self.assertIsNotNone(data_view, "Kibana data view is not readable")
        view = data_view.get("data_view") or data_view.get("attributes") or data_view
        title = view.get("title")
        time_field = view.get("timeFieldName") or view.get("time_field")
        self.assertEqual(title, self.index_pattern)
        self.assertEqual(time_field, "@timestamp")

        # Configured filters return at least the expected number of documents.
        for filter_spec in self.scenario.get("filters", []):
            with self.subTest(filter=filter_spec.get("label")):
                count = self._count(
                    elasticsearch,
                    {"query": lab_gate.kibana_filter_to_es(filter_spec)},
                )
                self.assertGreaterEqual(count, int(filter_spec.get("min_count", 1)))

        # Publisher restart: same event ID must remain a single document.
        target_event_id = event_ids[0]
        before = self._count(
            elasticsearch, {"query": {"term": {"event.id": target_event_id}}}
        )
        self.assertEqual(before, 1)
        publisher = self.scenario.get("publisher") or {}
        restart_path = publisher.get("restart_path")
        if not restart_path:
            self.fail("scenario.publisher.restart_path is required for the full flow")
        status, _ = self.gate.client("dystopia").request(
            publisher.get("restart_method", "POST").upper(), restart_path, body={}
        )
        self.assertIn(status, (200, 202, 204))
        time.sleep(float(publisher.get("restart_settle_seconds", 20)))
        after = self._poll(
            lambda: self._count(
                elasticsearch, {"query": {"term": {"event.id": target_event_id}}}
            ),
            "the publisher to settle after restart",
        )
        self.assertEqual(after, before, "publisher restart duplicated the event document")


if __name__ == "__main__":
    unittest.main()
