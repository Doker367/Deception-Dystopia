"""RT-07: quarantine has its own budget and never blocks the live spool."""
import json
from email.message import Message
import sqlite3
from urllib.error import HTTPError
from uuid import uuid4

import pytest

from runtime.sensor import Spool
from runtime.storage import CapacityError


def event(**changes):
    result = {"event_id": str(uuid4()), "device_id": "decoy-a",
              "observed_at": "2000-01-01T00:00:00+00:00",
              "src_ip": "10.23.4.5", "type": "connect", "proto": "tcp",
              "detail": {}}
    result.update(changes)
    return result


class Rejected:
    def __init__(self, code=403):
        self.code = code
        self.sent = []

    def send(self, events):
        self.sent.append(events)
        raise HTTPError("https://invalid/v1/events", self.code, "rejected", Message(), None)


class Ack:
    def __init__(self):
        self.sent = []

    def send(self, events):
        self.sent.append(events)


def reject_batch(spool, code=403):
    transport = Rejected(code)
    assert spool.flush_once(transport) is False
    return transport


def test_quarantine_does_not_consume_the_live_budget(tmp_path):
    spool = Spool(tmp_path / "spool.db", max_events=2, max_quarantine_events=8)
    first, second = event(), event()
    spool.submit(first)
    spool.submit(second)

    reject_batch(spool)
    health = spool.health()
    assert health["queued"] == 2
    assert health["pending"] == 0
    assert health["quarantined"] == 2
    assert health["operator_action_required"] is True
    assert health["storage_exhausted"] is False

    # Both live slots are free again: valid telemetry keeps flowing.
    third, fourth = event(), event()
    spool.submit(third)
    spool.submit(fourth)
    spool.submit(first)  # idempotent replay of a quarantined id is not duplicated
    assert spool.health()["pending"] == 2
    assert spool.health()["queued"] == 4

    ack = Ack()
    assert spool.flush_once(ack) is True
    assert {item["event_id"] for item in ack.sent[0]} == {third["event_id"],
                                                          fourth["event_id"]}
    health = spool.health()
    assert health["pending"] == 0
    assert health["quarantined"] == 2
    assert health["storage_exhausted"] is False


def test_quarantine_pressure_dead_letters_oldest_and_keeps_accepting(tmp_path):
    spool = Spool(tmp_path / "spool.db", max_events=2,
                  max_quarantine_events=1, max_quarantine_bytes=1024 * 1024)
    oldest, newest = event(), event()
    spool.submit(oldest)
    spool.submit(newest)

    reject_batch(spool)
    health = spool.health()
    assert health["quarantined"] == 1
    assert health["dead_lettered_persisted"] == 1
    assert health["operator_action_required"] is True
    assert health["storage_exhausted"] is False
    # The newest rejected record survives; the oldest is explicitly counted.
    assert [record["event_id"] for record in spool.quarantine_records()] == [
        newest["event_id"]]

    # The live budget was never charged for quarantine, so new data still flows.
    spool.submit(event())
    assert spool.health()["pending"] == 1
    ack = Ack()
    assert spool.flush_once(ack) is True
    assert spool.health()["pending"] == 0
    assert spool.health()["quarantined"] == 1


def test_operator_export_drain_and_purge(tmp_path):
    spool = Spool(tmp_path / "spool.db", max_quarantine_events=10)
    spool.submit(event())
    spool.submit(event())
    reject_batch(spool)
    assert spool.health()["quarantined"] == 2

    exported = tmp_path / "quarantine-export.jsonl"
    assert spool.export_quarantine(exported) == 2
    lines = exported.read_text().splitlines()
    assert len(lines) == 2
    assert all(json.loads(line)["event_id"] for line in lines)
    assert spool.health()["quarantined"] == 2  # export is non-destructive

    drained = tmp_path / "quarantine-drain.jsonl"
    assert spool.drain_quarantine(drained, limit=1) == 1
    assert len(drained.read_text().splitlines()) == 1
    assert spool.health()["quarantined"] == 1

    assert spool.purge_quarantine() == 1
    health = spool.health()
    assert health["quarantined"] == 0
    assert health["operator_action_required"] is False
    assert health["purged_persisted"] == 1


def test_old_spool_schema_is_migrated_without_losing_quarantine(tmp_path):
    path = tmp_path / "legacy-spool.db"
    db = sqlite3.connect(path)
    db.executescript(
        "CREATE TABLE queue(event_id TEXT PRIMARY KEY, queued REAL NOT NULL, "
        "payload BLOB NOT NULL, quarantined INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL);")
    db.commit()
    db.close()
    path.chmod(0o600)

    spool = Spool(path)
    columns = {row[1] for row in sqlite3.connect(path).execute("PRAGMA table_info(queue)")}
    assert {"quarantined", "quarantined_at"} <= columns
    assert spool.health()["quarantined"] == 0


def test_spool_still_rejects_when_the_live_budget_is_full(tmp_path):
    spool = Spool(tmp_path / "spool.db", max_events=1, max_quarantine_events=1)
    spool.submit(event())
    with pytest.raises(CapacityError):
        spool.submit(event())
    assert spool.health()["storage_exhausted"] is True


def test_cli_drain_reports_counts_not_payloads(tmp_path, capsys):
    from runtime.cli import main
    path = tmp_path / "spool.db"
    spool = Spool(path, max_quarantine_events=5)
    spool.submit(event(detail={"password": "SYNTHETIC-NOT-IN-OUTPUT"}))
    reject_batch(spool)

    output = tmp_path / "quarantine.jsonl"
    assert main(["sensor-quarantine", "--spool", str(path),
                 "--output", str(output), "--drain"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["action"] == "drained"
    assert report["events"] == 1
    assert report["health"]["quarantined"] == 0
    assert "SYNTHETIC-NOT-IN-OUTPUT" not in json.dumps(report)
