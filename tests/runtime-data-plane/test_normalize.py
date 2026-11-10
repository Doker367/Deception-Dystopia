"""Offline tests for raw -> v1 event normalization (the sensor's collector half)."""
import json
from datetime import datetime
from uuid import UUID

import pytest

from runtime.contracts import validate_event
from runtime.logreader import resolve_sources
from runtime.normalize import (
    NormalizeError,
    normalize_raw,
    normalize_timestamp,
    stable_event_id,
)


@pytest.fixture(scope="module")
def normalized(inventory_path):
    reader = resolve_sources(inventory_path)
    records = reader.step()
    events = []
    for engine, device_id, _fmt, record in records:
        event = normalize_raw(engine, device_id, record)
        if event is not None:
            events.append((engine, event))
    return events


def test_every_record_normalizes_to_a_valid_v1_event(normalized):
    assert len(normalized) == 22  # 23 records minus the endlessh TOTALS line
    for engine, event in normalized:
        assert validate_event(event) == event  # idempotent, canonical
        assert event["device_id"]
        assert event["event_id"]
        UUID(event["event_id"])


def test_expected_type_and_proto_mapping(normalized):
    by_engine = {}
    for engine, event in normalized:
        by_engine.setdefault(engine, []).append(event)

    assert [e["type"] for e in by_engine["cowrie"]] == [
        "connect", "other", "login_attempt", "command", "file_download",
    ]
    assert all(e["proto"] == "ssh" for e in by_engine["cowrie"])

    opencanary = by_engine["opencanary"]
    assert [e["type"] for e in opencanary] == ["http_request", "login_attempt", "login_attempt"]
    assert [e["proto"] for e in opencanary] == ["http", "ssh", "mysql"]

    assert [e["type"] for e in by_engine["dionaea"]] == ["login_attempt", "login_attempt", "file_download"]
    assert [e["proto"] for e in by_engine["dionaea"]] == ["tcp", "ftp", "tcp"]

    assert all(e["type"] == "login_attempt" for e in by_engine["heralding"])

    redis = by_engine["redishoneypot"]
    assert [e["type"] for e in redis] == ["connect", "command", "command", "command", "disconnect"]

    endlessh = by_engine["endlessh"]
    assert [e["type"] for e in endlessh] == ["connect", "disconnect", "connect", "disconnect"]
    assert all(e["proto"] == "ssh" for e in endlessh)


def test_event_id_is_deterministic_across_reread(inventory_path):
    reader = resolve_sources(inventory_path)
    first = {}
    for engine, device_id, _fmt, record in reader.step():
        if engine == "cowrie":
            event = normalize_raw(engine, device_id, record)
            first[event["event_id"]] = event
    # A fresh reader over the same files yields the exact same ids and content.
    second_reader = resolve_sources(inventory_path)
    second = {}
    for engine, device_id, _fmt, record in second_reader.step():
        if engine == "cowrie":
            event = normalize_raw(engine, device_id, record)
            second[event["event_id"]] = event
    assert first == second and len(first) == 5


def test_stable_event_id_is_canonical_uuid4():
    event_id = stable_event_id("cowrie", "srv-files-01", {"eventid": "cowrie.session.connect"})
    uuid = UUID(event_id)
    assert uuid.version == 4 and str(uuid) == event_id
    assert stable_event_id("cowrie", "srv-files-01", {"eventid": "cowrie.session.connect"}) == event_id


def test_passwords_never_reach_the_event(normalized):
    for engine, event in normalized:
        assert "demo-not-a-real-password" not in json.dumps(event)
        detail = event.get("detail", {})
        assert "password" not in detail
        for value in detail.values():
            assert isinstance(value, str)


def test_detail_is_bounded_and_string_only(normalized):
    for engine, event in normalized:
        detail = event.get("detail", {})
        assert len(detail) <= 16
        for value in detail.values():
            assert isinstance(value, str) and len(value.encode()) <= 2048


def test_command_and_download_capture_redacted(normalized):
    events = [e for _, e in normalized]
    command = next(e for e in events if e["type"] == "command")
    assert "command" in command["detail"]
    download = next(e for e in events if e["type"] == "file_download")
    assert "url" in download["detail"] or "file" in download["detail"]


def test_timestamp_normalization_is_utc_aware():
    utc = normalize_timestamp("2026-10-28T21:14:03.123456Z")
    assert utc.endswith("+00:00")
    datetime.fromisoformat(utc)  # tz-aware, parseable
    # RedisHoneyPot native "YYYY-MM-DD HH:MM:SS" without zone becomes UTC.
    naive = normalize_timestamp("2026-10-28 21:18:01")
    assert naive.endswith("+00:00")
    assert normalize_timestamp(None)  # falls back to now, still tz-aware


def test_multicast_or_unspecified_source_is_rejected():
    record = {"eventid": "cowrie.session.connect", "src_ip": "224.0.0.1"}
    with pytest.raises(NormalizeError):
        normalize_raw("cowrie", "srv-files-01", record)
    with pytest.raises(NormalizeError):
        normalize_raw("cowrie", "srv-files-01", {"eventid": "cowrie.session.connect"})


def test_unknown_engine_or_non_object_record_is_rejected():
    with pytest.raises(NormalizeError):
        normalize_raw("telnetd", "srv-files-01", {"src_ip": "203.0.113.9"})
    with pytest.raises(NormalizeError):
        normalize_raw("cowrie", "srv-files-01", 42)


def test_blank_text_line_is_skipped():
    assert normalize_raw("endlessh", "fw-edge-01", "   \n") is None


def test_redis_addr_field_is_parsed_as_source_and_port():
    from runtime.normalize import normalize_raw

    raw = ('{"action":"PING","addr":"203.0.113.50:41234",'
           '"time":"2026-11-09 06:00:49"}')
    event = normalize_raw("redishoneypot", "srv-db-01", raw)
    assert event is not None
    assert event["src_ip"] == "203.0.113.50"
    assert event["src_port"] == 41234
    assert event["type"] == "connect"


def test_cowrie_http_probe_is_not_a_login_success():
    raw = {
        "eventid": "cowrie.login.success", "protocol": "telnet",
        "src_ip": "203.0.113.9", "src_port": 40001,
        "dst_ip": "172.19.0.2", "dst_port": 2223,
        "username": "GET / HTTP/1.0", "password": "",
        "timestamp": "2026-11-09T22:47:49.534339Z",
        "message": "login attempt [GET / HTTP/1.0/] succeeded",
    }
    event = normalize_raw("cowrie", "srv-files-01", raw)
    assert event is not None
    assert event["type"] == "connect"
    assert event["dst_ip"] == "172.19.0.2"
    assert event["dst_port"] == 2223
    assert event["detail"]["classification"] == "protocol_probe"
    assert event["detail"]["mitre"] == "T1046"
    assert "succeeded" not in event["detail"]["message"].lower()


def test_cowrie_real_login_success_keeps_type():
    raw = {
        "eventid": "cowrie.login.success", "protocol": "ssh",
        "src_ip": "203.0.113.10", "src_port": 40002,
        "dst_ip": "172.19.0.2", "dst_port": 2222,
        "username": "root", "password": "demo-password",
        "timestamp": "2026-11-09T22:48:00Z",
        "message": "login attempt [root/demo-password] succeeded",
    }
    event = normalize_raw("cowrie", "srv-files-01", raw)
    assert event is not None
    assert event["type"] == "login_success"
    assert event["detail"]["mitre"] == "T1110"
    assert "demo-password" not in json.dumps(event)


def test_opencanary_http_access_becomes_http_request():
    raw = {
        "src_host": "203.0.113.9", "src_port": -1, "dst_host": "",
        "dst_port": 80, "logtype": 3000, "utc_time": "2026-11-09T23:30:00+00:00",
        "logdata": {"PATH": "/probe-8bec7707", "USERAGENT": "deception-test/8bec7707",
                    "METHOD": "GET", "STATUS": "404", "PROTO": "HTTP/1.1"},
        "message": '"203.0.113.9" - - [09/Nov/2026:23:30:00 +0000] "GET /probe-8bec7707 HTTP/1.1" 404 266 "-" "deception-test/8bec7707"',
    }
    event = normalize_raw("opencanary", "sw-access-01", raw)
    assert event is not None
    assert event["type"] == "http_request"
    assert event["proto"] == "http"
    assert event["detail"]["path"] == "/probe-8bec7707"
    assert event["detail"]["useragent"] == "deception-test/8bec7707"
    assert event["detail"]["method"] == "GET"
    assert event["detail"]["mitre"] == "T1190"


def test_opencanary_access_shim_parses_twisted_line():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "docker/deception/opencanary/access_shim.py"
    spec = importlib.util.spec_from_file_location("opencanary_access_shim", path)
    assert spec and spec.loader
    shim = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shim)
    record = shim.access_record(
        '2026-11-09T23:30:00+0000 [twisted.python.log#info] '
        '"203.0.113.9" - - [09/Nov/2026:23:30:00 +0000] '
        '"GET /probe-8bec7707 HTTP/1.1" 404 266 "-" "deception-test/8bec7707"'
    )
    assert record is not None
    assert record["src_host"] == "203.0.113.9"
    assert record["dst_port"] == 80
    assert record["logdata"]["PATH"] == "/probe-8bec7707"
    assert record["logdata"]["USERAGENT"] == "deception-test/8bec7707"
    assert shim.access_record(
        '"203.0.113.9" - - [09/Nov/2026:23:30:00 +0000] '
        '"POST /__fp HTTP/1.1" 204 0 "-" "deception-test/8bec7707"'
    ) is None


def test_opencanary_fingerprint_detail_is_preserved():
    raw = {
        "src_host": "203.0.113.9", "src_port": 55000, "dst_port": 80,
        "logtype": 3000, "utc_time": "2026-11-09T23:40:00+00:00",
        "logdata": {"PATH": "/__fp", "METHOD": "POST", "USERAGENT": "Mozilla/5.0",
                    "FINGERPRINT": '{"client":"{\\"cores\\":8,\\"memory\\":8}","headers":{}}'},
    }
    event = normalize_raw("opencanary", "sw-access-01", raw)
    assert event is not None
    assert event["type"] == "http_request"
    assert event["detail"]["path"] == "/__fp"
    assert "cores" in event["detail"]["fingerprint"]
