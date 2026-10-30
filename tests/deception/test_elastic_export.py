"""Unit tests for the runtime EventStore -> ECS -> Elasticsearch bridge.

No Elasticsearch, socket or service is contacted: the publisher transport is
injected and every database lives under pytest's temporary directory.
"""

import importlib.util
import json
import logging
from pathlib import Path
import stat
import sys
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.services.deception.integrations import native_svc
from app.services.deception.integrations.ecs import StaticMetadata
from app.services.deception.integrations.elastic_svc import (
    ElasticPublisher,
    ElasticsearchConfig,
)
from app.services.deception.integrations.exporter_svc import NativeExporter
from runtime.contracts import encode, validate_event
from runtime.storage import EventStore, database

SENSOR = "sensor-a"
SECRET = "SYNTHETIC-SECRET-NOT-FOR-EXPORT"

TOPOLOGY = StaticMetadata(
    devices={
        "decoy-a": {
            "id": "decoy-a",
            "segment_id": "seg-lab",
            "instance_id": "cell-1",
            "persona": "linux-file-server",
            "destination_ip": "192.0.2.10",
        }
    },
    segments={"seg-lab": {"id": "seg-lab", "name": "LAB"}},
)


def runtime_event(**changes):
    event = {
        "event_id": str(uuid4()),
        "device_id": "decoy-a",
        "observed_at": "2026-10-29T10:00:00+00:00",
        "src_ip": "198.51.100.9",
        "type": "login_attempt",
        "proto": "ssh",
        "src_port": 40123,
        "detail": {
            "username": "root",
            "password": SECRET,
            "session": "session-1",
        },
    }
    event.update(changes)
    return validate_event(event)


def seed(path, events, sensor=SENSOR):
    store = EventStore(path, max_bytes=8 * 1024 * 1024)
    return store.ingest(sensor, events)


def elastic(queue_path, transport):
    config = ElasticsearchConfig(
        enabled=True,
        url="https://127.0.0.1:9200",
        index="deception-events",
        queue_path=queue_path,
        max_retries=0,
        backoff=0.0,
        max_backoff=0.0,
        batch_size=1000,
    )
    return ElasticPublisher(config, transport=transport, sleep=lambda _: None)


class FakeTransport:
    """Deterministic in-memory replacement for the HTTP ``_create`` call."""

    def __init__(self, *responses, existing=()):
        self.responses = list(responses)
        self.existing = set(existing)
        self.calls = []

    def index(self, event_id, document, timeout):
        self.calls.append({"id": event_id, "document": document, "timeout": timeout})
        if event_id in self.existing:
            return 409
        response = self.responses.pop(0) if self.responses else 201
        if isinstance(response, BaseException):
            raise response
        if 200 <= response < 300:
            self.existing.add(event_id)
        return response

    def documents(self):
        return [call["document"] for call in self.calls]


def test_first_export_normalizes_metadata_and_never_leaks_credentials(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    events = tmp_path / "events.db"
    state = tmp_path / "export-cursor.db"
    seed(events, [runtime_event(), runtime_event(type="command", detail={
        "command": "id", "session": "session-2",
    })])

    transport = FakeTransport()
    publisher = elastic(tmp_path / "elastic-queue.db", transport)
    exporter = NativeExporter(
        events, state, publisher=publisher, resolver=TOPOLOGY, batch_size=10
    )
    summary = exporter.run_once()

    assert summary["enabled"] is True
    assert summary["stopped"] is None
    assert (summary["read"], summary["enqueued"], summary["delivered"]) == (2, 2, 2)
    assert summary["cursor"]["sensor"] == SENSOR
    assert len(transport.calls) == 2
    assert len({call["id"] for call in transport.calls}) == 2

    doc = transport.documents()[0]
    assert doc["dystopia"]["device_id"] == "decoy-a"
    assert doc["dystopia"]["segment_id"] == "seg-lab"
    assert doc["dystopia"]["instance_id"] == "cell-1"
    assert doc["dystopia"]["persona"] == "linux-file-server"
    assert doc["dystopia"]["ingest_source"] == SENSOR
    assert doc["destination"]["ip"] == "192.0.2.10"
    assert doc["source"]["ip"] == "198.51.100.9"
    assert doc["network"]["protocol"] == "ssh"
    assert doc["network"]["transport"] == "tcp"
    assert doc["event"]["action"] in {"login", "command"}

    rendered = json.dumps(transport.documents(), sort_keys=True)
    assert SECRET not in rendered
    assert "password" not in rendered
    assert SECRET not in caplog.text
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    assert publisher.health()["queued"] == 0


def test_document_id_is_stable_and_independent_of_topology_changes(tmp_path):
    events = tmp_path / "events.db"
    event = runtime_event()
    seed(events, [event])
    transport = FakeTransport()
    NativeExporter(
        events, tmp_path / "state.db",
        publisher=elastic(tmp_path / "queue.db", transport), resolver=TOPOLOGY,
    ).run_once()
    document = transport.documents()[0]
    assert document["event"]["id"] == native_svc.runtime_document_id(
        SENSOR, event["event_id"]
    )
    assert native_svc.runtime_document_id(SENSOR, event["event_id"]) == (
        native_svc.runtime_document_id(SENSOR, event["event_id"])
    )


def test_restart_does_not_re_read_or_republish(tmp_path):
    events = tmp_path / "events.db"
    state = tmp_path / "state.db"
    queue = tmp_path / "queue.db"
    seed(events, [runtime_event(), runtime_event(type="connect")])

    first_transport = FakeTransport()
    NativeExporter(
        events, state,
        publisher=elastic(queue, first_transport), resolver=TOPOLOGY,
    ).run_once()
    assert len(first_transport.calls) == 2
    assert len(first_transport.existing) == 2

    second_transport = FakeTransport()
    summary = NativeExporter(
        events, state,
        publisher=elastic(queue, second_transport), resolver=TOPOLOGY,
    ).run_once()

    assert summary["read"] == 0
    assert summary["enqueued"] == 0
    assert second_transport.calls == []
    assert len(first_transport.existing) == 2


def test_replay_after_lost_cursor_creates_no_duplicate_document(tmp_path):
    events = tmp_path / "events.db"
    state = tmp_path / "state.db"
    queue = tmp_path / "queue.db"
    seed(events, [runtime_event(), runtime_event(type="port_scan")])

    first_transport = FakeTransport()
    NativeExporter(
        events, state,
        publisher=elastic(queue, first_transport), resolver=TOPOLOGY,
    ).run_once()
    existing = set(first_transport.existing)
    assert len(existing) == 2

    # Simulate a crash after Elasticsearch acknowledged the writes but before
    # the cursor commit: the cursor file is gone, the documents are not.
    state.unlink()
    replay_transport = FakeTransport(existing=existing)
    publisher = elastic(queue, replay_transport)
    summary = NativeExporter(
        events, state, publisher=publisher, resolver=TOPOLOGY,
    ).run_once()

    assert {call["id"] for call in replay_transport.calls} == existing
    assert summary["enqueued"] == 2
    assert summary["delivered"] == 2
    assert publisher.health()["duplicates_since_start"] == 2
    assert publisher.health()["queued"] == 0
    assert replay_transport.existing == existing


def test_elastic_outage_keeps_events_queued_and_does_not_touch_ingestion(tmp_path):
    events = tmp_path / "events.db"
    state = tmp_path / "state.db"
    queue = tmp_path / "queue.db"
    stored = [runtime_event(), runtime_event(type="file_download", detail={
        "url": "http://203.0.113.5/payload", "session": "s3",
    })]
    seed(events, stored)
    before = EventStore(events, max_bytes=8 * 1024 * 1024).health()["events"]

    down_transport = FakeTransport(OSError("elastic down"), OSError("elastic down"))
    publisher = elastic(queue, down_transport)
    summary = NativeExporter(
        events, state, publisher=publisher, resolver=TOPOLOGY,
    ).run_once()

    assert summary["enqueued"] == 2
    assert summary["delivered"] == 0
    assert summary["stopped"] is None
    assert summary["cursor"] is not None
    assert publisher.health()["queued"] == 2
    assert EventStore(events, max_bytes=8 * 1024 * 1024).health()["events"] == before

    # A new process drains the durable queue without re-reading events.
    healthy_transport = FakeTransport()
    healthy_publisher = elastic(queue, healthy_transport)
    recovered = NativeExporter(
        events, state, publisher=healthy_publisher, resolver=TOPOLOGY,
    ).run_once()

    assert recovered["read"] == 0
    assert recovered["delivered"] == 2
    assert healthy_publisher.health()["queued"] == 0
    assert {call["id"] for call in healthy_transport.calls} == set(
        native_svc.runtime_document_id(SENSOR, event["event_id"]) for event in stored
    )


def test_stale_pending_enrichment_does_not_block_or_duplicate(tmp_path):
    events = tmp_path / "events.db"
    state = tmp_path / "state.db"
    queue = tmp_path / "queue.db"
    event = runtime_event()
    seed(events, [event])

    # A pending queue row for the same stored event, but with older enrichment
    # (for example a topology edit while Elasticsearch was unreachable).
    stale = native_svc.normalize(event, resolver=TOPOLOGY, sensor=SENSOR)
    stale["source"]["ip"] = "203.0.113.200"
    transport = FakeTransport()
    publisher = elastic(queue, transport)
    assert publisher.enqueue(stale) is True

    summary = NativeExporter(
        events, state, publisher=publisher, resolver=TOPOLOGY,
    ).run_once()

    assert summary["read"] == 1
    assert summary["conflicts"] == 1
    assert summary["stopped"] is None
    assert summary["cursor"] is not None
    assert [call["id"] for call in transport.calls] == [stale["event"]["id"]]
    assert publisher.health()["queued"] == 0


def test_batch_size_is_a_hard_bound(tmp_path):
    events = tmp_path / "events.db"
    state = tmp_path / "state.db"
    queue = tmp_path / "queue.db"
    stored = [runtime_event(type="connect") for _ in range(5)]
    seed(events, stored)

    transport = FakeTransport()
    exporter = NativeExporter(
        events, state,
        publisher=elastic(queue, transport), resolver=TOPOLOGY, batch_size=2,
    )
    counts = []
    for _ in range(4):
        summary = exporter.run_once()
        counts.append((summary["read"], len(transport.calls)))
    assert counts == [(2, 2), (2, 4), (1, 5), (0, 5)]
    assert len({call["id"] for call in transport.calls}) == 5
    assert {call["id"] for call in transport.calls} == {
        native_svc.runtime_document_id(SENSOR, event["event_id"]) for event in stored
    }


def test_unknown_runtime_type_is_preserved_as_ecs_other(tmp_path):
    direct = native_svc.normalize(
        {
            "event_id": str(uuid4()), "device_id": "decoy-a",
            "observed_at": "2026-10-29T10:00:00+00:00",
            "src_ip": "198.51.100.44", "type": "mystery_event", "proto": "tcp",
            "detail": {},
        },
        resolver=TOPOLOGY, sensor=SENSOR,
    )
    assert direct is not None
    assert direct["event"]["action"] == "other"
    assert direct["event"]["category"] == ["host"]
    assert direct["dystopia"]["device_id"] == "decoy-a"

    events = tmp_path / "events.db"
    EventStore(events, max_bytes=8 * 1024 * 1024)
    raw = {
        "event_id": str(uuid4()), "device_id": "decoy-a",
        "observed_at": "2026-10-29T10:00:00+00:00",
        "src_ip": "198.51.100.44", "type": "mystery_event", "proto": "tcp",
        "src_port": 1234, "detail": {"note": "opaque"},
    }
    with database(events, 8 * 1024 * 1024) as db:
        db.execute(
            "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
            (
                SENSOR, raw["event_id"], raw["device_id"], raw["observed_at"],
                1.0, raw["observed_at"], "mystery_event", raw["src_ip"], encode(raw),
            ),
        )

    transport = FakeTransport()
    summary = NativeExporter(
        events, tmp_path / "state.db",
        publisher=elastic(tmp_path / "queue.db", transport), resolver=TOPOLOGY,
    ).run_once()

    assert summary["read"] == 1
    assert summary["delivered"] == 1
    assert transport.documents()[0]["event"]["action"] == "other"
    assert transport.documents()[0]["event"]["id"] == native_svc.runtime_document_id(
        SENSOR, raw["event_id"]
    )


def test_missing_topology_metadata_never_drops_the_event(tmp_path):
    event = runtime_event(device_id="unmapped-device")
    document = native_svc.normalize(event, resolver=StaticMetadata(), sensor=SENSOR)
    assert document is not None
    assert document["dystopia"]["device_id"] == "unmapped-device"
    assert document["dystopia"]["segment_id"] == "unknown"
    assert document["dystopia"]["instance_id"] == "unassigned"
    assert document["source"]["ip"] == "198.51.100.9"


def test_export_is_disabled_without_an_enabled_publisher(tmp_path):
    events = tmp_path / "events.db"
    state = tmp_path / "state.db"
    seed(events, [runtime_event()])
    assert ElasticsearchConfig.from_env({}).enabled is False

    transport = FakeTransport()
    disabled = ElasticPublisher(ElasticsearchConfig.from_env({}), transport=transport)
    summary = NativeExporter(
        events, state, publisher=disabled, resolver=TOPOLOGY,
    ).run_once()

    assert summary["enabled"] is False
    assert summary["read"] == 0
    assert transport.calls == []
    assert state.exists() is False


def test_memory_only_queue_cannot_advance_the_cursor(tmp_path):
    events = tmp_path / "events.db"
    state = tmp_path / "state.db"
    seed(events, [runtime_event()])
    publisher = ElasticPublisher(
        ElasticsearchConfig(
            enabled=True, url="https://127.0.0.1:9200", index="deception-events",
            queue_path=None, max_retries=0, backoff=0.0, max_backoff=0.0,
        ),
        transport=FakeTransport(),
    )
    exporter = NativeExporter(events, state, publisher=publisher, resolver=TOPOLOGY)
    with pytest.raises(ValueError):
        exporter.run_once()
    assert state.exists() is False


def test_runner_is_disabled_by_default(tmp_path, capsys):
    events = tmp_path / "events.db"
    state = tmp_path / "state.db"
    seed(events, [runtime_event()])

    spec = importlib.util.spec_from_file_location(
        "run_elastic_export", ROOT / "scripts" / "run_elastic_export.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.main(["--events", str(events), "--state", str(state)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["enabled"] is False
    assert state.exists() is False
