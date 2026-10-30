"""Prepared offline unit/ASGI tests. TestClient does not open a listening socket."""
from datetime import datetime
import json
from pathlib import Path
import sqlite3
import threading
from uuid import uuid4
from urllib.error import HTTPError

import pytest
from fastapi.testclient import TestClient

from runtime.contracts import decode_batch, encode, MAX_BATCH_BYTES
from runtime.identity import Registry
from runtime.ingest import create_app
from runtime.sensor import Spool, Transport
from runtime.storage import CapacityError, EventStore, database


def event(**changes):
    result = {"event_id": str(uuid4()), "device_id": "decoy-a", "observed_at": "2000-01-01T00:00:00+00:00",
              "src_ip": "10.23.4.5", "type": "connect", "proto": "tcp", "detail": {}}
    result.update(changes)
    return result


@pytest.fixture
def plane(tmp_path):
    registry = Registry(tmp_path / "identity.db")
    token = registry.rotate("sensor-a", ["decoy-a"])
    store = EventStore(tmp_path / "events.db", max_bytes=8*1024*1024)
    with TestClient(create_app(registry, store), base_url="https://ingestion.invalid") as client:
        yield registry, token, store, client


def post(client, token, events, **extra):
    return client.post("/v1/events", json={"version": 1, "events": events, **extra},
                       headers={"Authorization": "Bearer " + token})


def test_sensor_cannot_impersonate_or_claim_unassigned_devices(plane):
    _, token, store, client = plane
    assert post(client, token, [event(sensor_id="sensor-b")]).status_code == 422
    assert post(client, token, [event()], sensor_id="sensor-b").status_code == 422
    assert post(client, token, [event(device_id="decoy-b")]).status_code == 403
    assert post(client, token, [event(detail={"simulated": "true"})]).status_code == 422
    assert store.health()["events"] == 0


def test_invalid_revoked_rotated_expired_credentials(plane):
    registry, token, _, client = plane
    assert post(client, "invalid", [event()]).status_code == 401
    second = registry.rotate("sensor-a", ["decoy-a"])
    assert post(client, token, [event()]).status_code == 401
    assert post(client, second, [event()]).status_code == 200
    registry.revoke("sensor-a")
    assert post(client, second, [event()]).status_code == 401
    with database(registry.path, 8*1024*1024) as db:
        db.execute("UPDATE credentials SET revoked=0,expires=0")
    assert post(client, second, [event()]).status_code == 401


def test_no_administrative_or_plaintext_ingestion(plane):
    _, token, _, client = plane
    assert client.post("http://ingestion.invalid/v1/events", json={}).status_code == 426
    assert client.post("http://ingestion.invalid/v1/events", headers={"X-Forwarded-Proto": "https"}).status_code == 426
    assert client.get("/api/auth/me").status_code == 404
    assert post(client, "administrative-jwt-is-not-a-sensor-key", [event()]).status_code == 401
    assert client.post("/v1/events", content=b"x"*(MAX_BATCH_BYTES+1), headers={
        "Authorization": "Bearer " + token, "Content-Type": "application/json"}).status_code == 413
    assert post(client, token, [event() for _ in range(65)]).status_code == 422


def test_persistence_dedup_time_and_conflicts(plane):
    _, token, store, client = plane
    e = event()
    assert post(client, token, [e]).json()["accepted"] == 1
    assert post(client, token, [e]).json()["duplicates"] == 1
    assert post(client, token, [{**e, "type": "command"}]).status_code == 409
    with store.connect() as db:
        row = db.execute("SELECT sensor,received_at,observed_at FROM events").fetchone()
    assert row[0] == "sensor-a"
    assert datetime.fromisoformat(row[1]).year >= 2026
    assert row[1] != row[2]
    assert store.health()["events"] == 1  # includes events with no alert


def test_failed_ai_cannot_affect_rules_or_isolation(tmp_path, monkeypatch):
    # New processing path has no AI dependency. Poison legacy decision function
    # through import interception to ensure ingestion never tries to import it.
    import builtins
    original = builtins.__import__
    def guarded(name, *args, **kwargs):
        if name.startswith("app.services.ai") or name.startswith("runtime.isolation"):
            raise AssertionError("ingestion tried to use AI or isolation authority")
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", guarded)
    store = EventStore(tmp_path / "events.db", max_bytes=8*1024*1024)
    for _ in range(5):
        store.ingest("sensor-a", [event(type="login_attempt")])
    store.ingest("sensor-a", [event(type="command", detail={"command": "SENSITIVE-FIXTURE", "password": "SYNTHETIC-ONLY"})])
    assert store.health()["outbox_pending"] == 2
    messages = []
    while store.deliver_one(messages.append):
        pass
    assert len(messages) == 2
    assert "SENSITIVE" not in json.dumps(messages)
    assert "password" not in json.dumps(messages)


def test_notification_failure_preserves_events(tmp_path):
    store = EventStore(tmp_path / "events.db", max_bytes=8*1024*1024)
    store.ingest("sensor-a", [event(type="login_success")])
    def fail(_):
        raise ConnectionError("synthetic failure")
    assert not store.deliver_one(fail)
    assert store.health()["events"] == 1
    assert store.health()["outbox_pending"] == 1
    with store.connect() as db:
        assert db.execute("SELECT attempts,delivered FROM outbox").fetchone() == (1, 0)


def test_bounded_store_and_spool_report_backpressure(tmp_path, caplog):
    store = EventStore(tmp_path / "events.db", max_events=1, max_bytes=8*1024*1024)
    store.ingest("sensor-a", [event()])
    with pytest.raises(CapacityError):
        store.ingest("sensor-a", [event()])
    assert store.health()["rejected_since_start"] == 1
    spool = Spool(tmp_path / "spool.db", max_events=1)
    spool.submit(event())
    with pytest.raises(CapacityError):
        spool.submit(event())
    assert spool.health()["queued"] == 1
    assert spool.health()["storage_exhausted"]
    assert spool.health()["discarded_persisted"] == 1
    assert "sensor_spool_capacity_exhausted" in caplog.text


def test_retries_and_permanent_batch_quarantine(tmp_path):
    spool = Spool(tmp_path / "spool.db")
    e = event()
    spool.submit(e)
    class Fail:
        def send(self, _):
            raise ConnectionError("offline")
    assert not spool.flush_once(Fail())
    assert spool.health()["disconnected"]
    assert spool.health()["queued"] == 1
    spool.next_retry = 0
    class Rejected:
        def send(self, _):
            raise HTTPError("https://invalid/v1/events", 403, "rejected", {}, None)
    assert not spool.flush_once(Rejected())
    assert spool.health()["quarantined"] == 1
    spool.submit(event())
    class Ack:
        def send(self, events):
            assert len(events) == 1 and events[0]["event_id"] != e["event_id"]
    assert spool.flush_once(Ack())
    assert spool.health()["queued"] == 1  # quarantine retained, not silently deleted


def test_contract_canonical_and_no_ambiguous_json():
    with pytest.raises(ValueError):
        decode_batch(b'{"version":1,"version":1,"events":[]}')
    for changes in ({"src_ip": "2001:0db8::1"}, {"observed_at": "2026-01-01"},
                    {"observed_at": "0001-01-01T00:00:00+14:00"},
                    {"observed_at": "9999-12-31T23:59:59-14:00"},
                    {"proto": []}, {"detail": {"x": {"nested": "not allowed"}}}):
        with pytest.raises(ValueError):
            decode_batch(encode({"version": 1, "events": [event(**changes)]}))


def test_rotation_does_not_revoke_when_token_file_cannot_publish(tmp_path):
    registry = Registry(tmp_path / "identity.db")
    old = registry.rotate("sensor-a", ["decoy-a"])
    with pytest.raises(FileNotFoundError):
        registry.rotate("sensor-a", ["decoy-a"], output=tmp_path / "missing" / "token")
    assert registry.authenticate(old)[0] == "sensor-a"


def test_authorized_transaction_serializes_revocation(tmp_path):
    registry = Registry(tmp_path / "identity.db")
    token = registry.rotate("sensor-a", ["decoy-a"])
    entered, done = threading.Event(), threading.Event()
    errors = []
    def revoke():
        entered.set()
        try:
            registry.revoke("sensor-a")
        except Exception as exc:
            errors.append(exc)
        finally:
            done.set()
    with registry.authorized(token):
        thread = threading.Thread(target=revoke)
        thread.start()
        assert entered.wait(1)
        assert not done.is_set()
    thread.join(3)
    assert not errors and done.is_set()
    with pytest.raises(PermissionError):
        registry.authenticate(token)


def test_existing_sqlite_page_size_cannot_bypass_disk_cap(tmp_path):
    path = tmp_path / "oversized.db"
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA page_size=65536")
        db.execute("CREATE TABLE t(x BLOB)")
        db.execute("INSERT INTO t VALUES(?)", (b"x"*131072,))
    path.chmod(0o600)
    with pytest.raises(CapacityError):
        with database(path, max_bytes=65536):
            pass


def test_sensor_dependency_boundary_and_no_cleartext_endpoint():
    root = Path(__file__).resolve().parents[2]
    for name in ("sensor.py", "contracts.py", "storage.py", "localfiles.py"):
        source = (root / "runtime" / name).read_text()
        assert "from app." not in source and "import app." not in source
        assert "NETPULSE_JWT_SECRET" not in source
    with pytest.raises(ValueError):
        Transport("http://192.0.2.2/v1/events", "missing-ca", "missing-token")
