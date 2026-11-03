"""Offline end-to-end and ingest-semantics tests for the runtime data plane.

The receiver is exercised through FastAPI's TestClient (no listening socket) and
the sensor spool is drained through a fake transport that forwards to it, so the
full path — declared logs -> normalize -> spool -> ingest -> outbox discharge —
runs with fixtures only.
"""
from urllib.error import HTTPError
from uuid import uuid4

from fastapi.testclient import TestClient

from runtime.contracts import validate_event
from runtime.dataplane import DataPlane
from runtime.ingest import create_app
from runtime.logreader import LogReader, Source, Sources, resolve_sources
from runtime.sensor import Spool


def event(**changes):
    result = {"event_id": str(uuid4()), "device_id": "srv-files-01",
              "observed_at": "2026-10-28T21:14:03+00:00", "src_ip": "203.0.113.9",
              "type": "connect", "proto": "tcp", "detail": {}}
    result.update(changes)
    return result


class IngestForward:
    """Fake transport that forwards the batch to the receiver TestClient."""

    def __init__(self, client, token):
        self.client = client
        self.token = token
        self.sent = 0

    def send(self, events):
        response = self.client.post(
            "/v1/events", json={"version": 1, "events": events},
            headers={"Authorization": "Bearer " + self.token},
        )
        if response.status_code != 200:
            # Mirror runtime.sensor.Transport: a non-2xx is raised as an
            # HTTPError so the spool can quarantine permanent rejects.
            raise HTTPError("https://ingest.invalid/v1/events",
                            response.status_code, response.text,
                            response.headers, None)
        self.sent += len(events)


def test_full_pipeline_logs_to_persisted_events(inventory_path, sensor_token, event_store, tmp_path):
    registry, token = sensor_token
    spool = Spool(tmp_path / "spool.db", max_bytes=8 * 1024 * 1024)
    with TestClient(create_app(registry, event_store), base_url="https://ingest.invalid") as client:
        transport = IngestForward(client, token)
        plane = DataPlane(resolve_sources(inventory_path), spool, transport)
        while True:
            result = plane.step()
            if result["collected"] == 0:
                break
    assert plane.normalized == 22  # every fixture record except endlessh TOTALS
    assert plane.skipped == 1
    assert plane.failed == 0
    assert spool.health()["queued"] == 0  # fully drained
    assert event_store.health()["events"] == 22
    # The reader's cursor is drained: another poll on the same reader is empty.
    assert plane.step()["collected"] == 0


def test_dataplane_counts_a_bad_log_and_keeps_healthy_records(tmp_path):
    good = tmp_path / "cowrie.jsonl"
    good.write_text(
        '{"eventid":"cowrie.session.connect","src_ip":"203.0.113.9",'
        '"timestamp":"2026-10-28T21:14:03Z"}\n', encoding="utf-8")
    bad = tmp_path / "opencanary.jsonl"
    bad.write_text("NOT JSON\n", encoding="utf-8")
    reader = LogReader(Sources([
        Source("cowrie", str(good), "jsonl", "srv-files-01"),
        Source("opencanary", str(bad), "jsonl", "sw-access-01"),
    ]))
    spool = Spool(tmp_path / "spool.db", max_bytes=8 * 1024 * 1024)
    plane = DataPlane(reader, spool)
    result = plane.step()
    assert result["collected"] == 1
    assert result["normalized"] == 1
    assert result["read_failed"] == 1
    assert result["failed"] == 0
    assert result["paused"] is False
    assert result["errors"][0]["engine"] == "opencanary"
    assert spool.health()["queued"] == 1


def test_replay_same_logs_is_idempotent(inventory_path, sensor_token, event_store, tmp_path):
    registry, token = sensor_token
    spool = Spool(tmp_path / "spool.db", max_bytes=8 * 1024 * 1024)
    with TestClient(create_app(registry, event_store), base_url="https://ingest.invalid") as client:
        transport = IngestForward(client, token)
        for _ in range(2):
            plane = DataPlane(resolve_sources(inventory_path), spool, transport)
            while True:
                result = plane.step()
                if result["collected"] == 0:
                    break
    assert event_store.health()["events"] == 22  # no duplicates on replay


def test_ingest_accepts_only_assigned_devices(sensor_token, event_store, tmp_path):
    registry, token = sensor_token
    spool = Spool(tmp_path / "spool.db")
    with TestClient(create_app(registry, event_store), base_url="https://ingest.invalid") as client:
        transport = IngestForward(client, token)
        spool.submit(event())  # srv-files-01 is assigned
        assert spool.flush_once(transport) is True
        assert event_store.health()["events"] == 1
        spool.submit(event(device_id="unassigned-device"))
        # flush_once leaves the rejected batch quarantined, never silently dropped.
        assert spool.flush_once(transport) is False
        assert spool.health()["quarantined"] == 1
        assert event_store.health()["events"] == 1


def test_ingest_deduplicates_per_sensor_and_discharges_outbox(sensor_token, event_store, tmp_path):
    registry, token = sensor_token
    spool = Spool(tmp_path / "spool.db")
    with TestClient(create_app(registry, event_store), base_url="https://ingest.invalid") as client:
        transport = IngestForward(client, token)
        e = event(type="login_success")
        spool.submit(e)
        spool.submit(e)  # identical re-submission is a duplicate, not a conflict
        assert spool.flush_once(transport) is True
        assert event_store.health()["events"] == 1
        assert event_store.health()["outbox_pending"] == 1  # login_success raises a rule
        delivered = []
        while event_store.deliver_one(delivered.append):
            pass
        assert delivered == [{"sensor_id": "sensor-lab", "event_id": e["event_id"], "rule": "login_success"}]
        assert event_store.health()["outbox_pending"] == 0


def test_brute_force_cohort_is_counted_within_window(sensor_token, event_store, tmp_path):
    registry, token = sensor_token
    spool = Spool(tmp_path / "spool.db")
    with TestClient(create_app(registry, event_store), base_url="https://ingest.invalid") as client:
        transport = IngestForward(client, token)
        attempts = [event(type="login_attempt", src_ip="198.51.100.7") for _ in range(5)]
        for attempt in attempts:
            spool.submit(attempt)
        assert spool.flush_once(transport) is True
        assert event_store.health()["events"] == 5
        delivered = []
        while event_store.deliver_one(delivered.append):
            pass
        brute = [m for m in delivered if m["rule"] == "brute_force"]
        assert len(brute) == 1  # the 5th attempt trips the 5-in-60s cohort


def test_conflicting_event_id_is_rejected(sensor_token, event_store, tmp_path):
    registry, token = sensor_token
    spool = Spool(tmp_path / "spool.db")
    with TestClient(create_app(registry, event_store), base_url="https://ingest.invalid") as client:
        transport = IngestForward(client, token)
        e = event(type="connect")
        spool.submit(e)
        assert spool.flush_once(transport) is True
        conflicting = {**e, "type": "command"}
        assert validate_event(conflicting) == conflicting
        response = client.post("/v1/events", json={"version": 1, "events": [conflicting]},
                               headers={"Authorization": "Bearer " + token})
        assert response.status_code == 409
        assert event_store.health()["events"] == 1


def test_sensor_module_dependency_boundary_still_holds():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    for name in ("logreader.py", "normalize.py", "dataplane.py", "sensor.py", "ingest.py"):
        source = (root / "runtime" / name).read_text()
        assert "from app." not in source and "import app." not in source
        assert "NETPULSE_JWT_SECRET" not in source
        assert "app.core.settings" not in source
