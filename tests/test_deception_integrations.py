"""Tests de integraciones de honeypots reales (Fase C): parsers y tailer."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.deception import store_svc
from app.services.deception.integrations import (
    cowrie_svc,
    opencanary_svc,
    tailer_svc,
)


@pytest.fixture()
def db_path(tmp_path, monkeypatch):
    db = tmp_path / "deception.db"
    monkeypatch.setattr(store_svc, "DB_PATH", db)
    return db


# ── Parsers ──────────────────────────────────────────────────


def test_cowrie_login_failed():
    raw = {
        "eventid": "cowrie.login.failed", "src_ip": "203.0.113.9",
        "src_port": 41234, "username": "root", "password": "123456",
        "session": "abc", "timestamp": "2026-09-24T10:00:00Z",
    }
    parsed = cowrie_svc.parse(raw, "srv-files-01")
    assert parsed["device_id"] == "srv-files-01"
    assert parsed["event_type"] == "login_attempt"
    assert parsed["username"] == "root"
    assert parsed["detail"]["password"] == "123456"
    assert parsed["success"] is False


def test_cowrie_command():
    parsed = cowrie_svc.parse(
        {"eventid": "cowrie.command.input", "src_ip": "1.2.3.4", "input": "uname -a"},
        "srv-01",
    )
    assert parsed["event_type"] == "command"
    assert parsed["detail"]["command"] == "uname -a"


def test_cowrie_ignora_no_relevante():
    assert cowrie_svc.parse({"eventid": "cowrie.client.version"}, "x") is None


def test_opencanary_http():
    raw = {
        "src_host": "198.51.100.7", "src_port": 55000, "dst_host": "10.40.0.11",
        "dst_port": 80, "logtype": 3000, "msg": "GET /admin HTTP/1.1",
        "utc_time": "2026-09-24 10:00:00",
    }
    parsed = opencanary_svc.parse(raw, "sw-access-01")
    assert parsed["proto"] == "http"
    assert parsed["device_id"] == "sw-access-01"
    assert parsed["event_type"] == "connect"


def test_opencanary_snmp_y_login():
    snmp = opencanary_svc.parse({"src_host": "1.1.1.1", "dst_port": 161, "msg": "SNMP request"}, "x")
    assert snmp["proto"] == "snmp" and snmp["event_type"] == "snmp_query"

    login = opencanary_svc.parse(
        {"src_host": "1.1.1.1", "dst_port": 22, "msg": "Login attempt with password"}, "x"
    )
    assert login["event_type"] == "login_attempt"


# ── Tailer ───────────────────────────────────────────────────


def test_tailer_retirado(db_path):
    """La ingesta de logs vive en el sensor independiente, no en el control."""
    assert tailer_svc.is_running() is False
    result = tailer_svc.start()
    assert result["status"] == "blocked"
    assert "runtime.sensor" in result["reason"]
    assert tailer_svc.status() == {"running": False, "state": "blocked", "sources": []}
    assert store_svc.get_events() == []
