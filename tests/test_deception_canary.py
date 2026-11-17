"""Canary/honeytoken tests: fake-fs content, normalization, alerts and rules."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from app.models.deception import DeceptionEventIn, DeceptionEventType
from app.services import audit_svc, notifications_svc
from app.services.deception import alert_svc, store_svc
from runtime import canary
from runtime.normalize import normalize_raw
from runtime.storage import EventStore

REPO_ROOT = Path(__file__).resolve().parent.parent
PATCH_PATH = REPO_ROOT / "docker" / "deception" / "cowrie" / "patch_process.py"


def _load_patch():
    spec = importlib.util.spec_from_file_location("cowrie_patch_process", PATCH_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_canary_constants_and_fake_fs_node_are_in_sync():
    patch = _load_patch()
    assert patch.CANARY_ID == canary.CANARY_ID
    assert patch.CANARY_PATH == canary.CANARY_PATH
    assert patch.CANARY_TOKEN == canary.CANARY_TOKEN
    assert patch.CANARY_CONTENT == canary.CANARY_CONTENT

    root = ["/", patch.T_DIR, 0, 0, 4096, 0o40755, 0.0, [], None, None]
    patch.add_canary_file(root)
    node = patch.node_at(root, patch.CANARY_PATH)
    assert node is not None
    assert node[patch.A_TYPE] == patch.T_FILE
    assert node[patch.A_SIZE] == len(canary.CANARY_CONTENT.encode())
    assert node[patch.A_CONTENTS] == canary.CANARY_CONTENT.encode()
    assert canary.match(f"cat {canary.CANARY_PATH}") == canary.CANARY_ID
    assert canary.match("cat /etc/hostname") is None


def test_cowrie_command_normalizes_with_canary_marker():
    event = normalize_raw(
        "cowrie",
        "srv-files-01",
        {
            "eventid": "cowrie.command.input",
            "input": f"cat {canary.CANARY_PATH}",
            "src_ip": "203.0.113.9",
            "src_port": 41234,
            "dst_ip": "10.20.0.10",
            "dst_port": 2222,
            "session": "6f1c2a4e-1d3b-4f7a-9c2e-8b5d0a1f3c11",
            "timestamp": "2026-11-16T09:55:34Z",
            "protocol": "telnet",
        },
    )
    assert event is not None
    assert event["detail"]["canary"] == canary.CANARY_ID
    assert canary.CANARY_TOKEN not in str(event)


def test_canary_access_is_a_critical_alert(tmp_path, monkeypatch):
    monkeypatch.setattr(store_svc, "DB_PATH", tmp_path / "deception.db")
    monkeypatch.setattr(audit_svc, "AUDIT_DIR", tmp_path / "audit")
    monkeypatch.setattr(audit_svc, "AUDIT_DB", tmp_path / "audit" / "audit.db")
    monkeypatch.setattr(alert_svc, "DECEPTION_ALERTS_ENABLED", True)
    monkeypatch.setattr(alert_svc, "DECEPTION_ALERT_COOLDOWN", 60)
    monkeypatch.setattr(
        notifications_svc, "notify_event", lambda event_type, data: None
    )
    alert_svc._last_fired.clear()

    record = store_svc.log_event(
        DeceptionEventIn(
            device_id="srv-files-01",
            src_ip="203.0.113.9",
            proto="telnet",
            type=DeceptionEventType.COMMAND,
            detail={"command": f"cat {canary.CANARY_PATH}", "canary": canary.CANARY_ID},
        )
    )
    fired = alert_svc.evaluate(record)
    assert len(fired) == 1
    assert fired[0]["rule"] == "canary_access"
    assert fired[0]["severity"] == "critical"
    alert_svc._last_fired.clear()


def test_canary_hits_are_queryable(tmp_path, monkeypatch):
    monkeypatch.setattr(store_svc, "DB_PATH", tmp_path / "deception.db")
    store_svc.log_event(
        DeceptionEventIn(
            device_id="srv-files-01",
            src_ip="203.0.113.9",
            proto="telnet",
            type=DeceptionEventType.COMMAND,
            detail={"command": f"cat {canary.CANARY_PATH}", "canary": canary.CANARY_ID},
        )
    )
    store_svc.log_event(
        DeceptionEventIn(
            device_id="srv-files-01",
            src_ip="203.0.113.10",
            proto="telnet",
            type=DeceptionEventType.COMMAND,
            detail={"command": "uname -a"},
        )
    )
    hits = store_svc.get_canary_hits()
    assert len(hits) == 1
    assert hits[0]["detail"]["canary"] == canary.CANARY_ID


def test_v1_outbox_uses_canary_rule(tmp_path):
    store = EventStore(tmp_path / "events.db", max_bytes=8 * 1024 * 1024)
    event = {
        "event_id": "4b9f9e5e-1111-4111-8111-111111111111",
        "device_id": "srv-files-01",
        "observed_at": "2026-11-16T09:55:34+00:00",
        "src_ip": "203.0.113.9",
        "type": "command",
        "proto": "telnet",
        "detail": {"command": f"cat {canary.CANARY_PATH}", "canary": canary.CANARY_ID},
    }
    store.ingest("sensor-a", [event])
    with store.connect() as db:
        row = db.execute("SELECT rule FROM outbox").fetchone()
    assert row is not None and row[0] == "canary_access"
