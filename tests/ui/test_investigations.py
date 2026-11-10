"""Investigation APIs preserve evidence and cannot start containers."""
import csv
from datetime import datetime, timezone
from io import StringIO
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client_roles(tmp_path, monkeypatch):
    import yaml
    from app.core.security import hash_password
    from app.core.limiter import limiter
    from app.middleware import audit
    from app.routers import auth, admin_users
    from app.services import analytics_svc, investigation_svc
    from app.main import app

    monkeypatch.setattr(limiter, "enabled", False)
    monkeypatch.setattr(audit, "_log_async", lambda **kwargs: None)
    monkeypatch.setenv("NETPULSE_JWT_SECRET", "synthetic-investigation-test-secret-0123456789")
    users = tmp_path / "users.yaml"
    users.write_text(yaml.safe_dump({"users": [
        {"username": role, "role": role, "name": role,
         "password_hash": hash_password("synthetic-password-0123456789")}
        for role in ("admin", "operator", "viewer")]}))
    users.chmod(0o600)
    monkeypatch.setattr(auth, "USERS_FILE", users)
    monkeypatch.setattr(admin_users, "USERS_FILE", users)
    monkeypatch.setattr(investigation_svc, "DB_PATH", tmp_path / "investigations.db")
    db = tmp_path / "events.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE deception_events(id INTEGER PRIMARY KEY, ts TEXT, device_id TEXT, src_ip TEXT, src_port INTEGER, proto TEXT, event_type TEXT, username TEXT, success INTEGER, detail TEXT)")
        conn.execute("INSERT INTO deception_events VALUES(1,?,?,?,?,?,?,?,?,?)", (
            datetime.now(timezone.utc).isoformat(), "srv-files-01", "203.0.113.7", 55444,
            "ssh", "command", "root", 1, '{"engine":"cowrie","command":"id"}'))
    monkeypatch.setattr(analytics_svc, "_service", analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig(db_path=db)))
    with TestClient(app) as client:
        tokens = {}
        for role in ("admin", "operator", "viewer"):
            result = client.post("/api/auth/login", json={"username": role, "password": "synthetic-password-0123456789"})
            assert result.status_code == 200
            tokens[role] = {"Authorization": "Bearer " + result.json()["access_token"]}
        yield client, tokens, db, tmp_path


def test_attacker_profile_evidence_roles_and_conflicts(client_roles):
    client, tokens, db, tmp_path = client_roles
    path = "/api/investigations/attackers/203.0.113.7"
    assert client.get(path).status_code == 401
    assert client.get("/api/investigations/attackers/not-an-ip", headers=tokens["viewer"]).status_code == 422
    profile = client.get(path, headers=tokens["viewer"])
    assert profile.status_code == 200
    assert profile.headers["cache-control"] == "no-store"
    assert profile.json()["total"] == 1
    assert profile.json()["items"][0]["detail"]["command"] == "id"
    assert profile.json()["items"][0]["detail"]["username"] == "root"
    assert client.get(path + "/history", headers=tokens["viewer"]).json()["items"] == []
    assert not (tmp_path / "investigations.db").exists()  # GET is side-effect free
    body = {"revision": 0, "alias": "Origen A", "classification": "scanner", "tags": ["ssh"], "notes": "revisar"}
    assert client.put(path + "/annotation", json=body, headers=tokens["viewer"]).status_code == 403
    saved = client.put(path + "/annotation", json=body, headers=tokens["operator"])
    assert saved.status_code == 200
    assert saved.json()["revision"] == 1
    assert (tmp_path / "investigations.db").stat().st_mode & 0o077 == 0
    assert client.put(path + "/annotation", json=body, headers=tokens["operator"]).status_code == 409
    assert client.put(path + "/annotation", json={**body, "revision": 1, "tags": ["ssh", "ssh"]}, headers=tokens["admin"]).status_code == 422
    assert client.get(path, headers=tokens["viewer"]).json()["annotation"]["notes"] == "revisar"
    trail = client.get(path + "/history", headers=tokens["viewer"]).json()["items"]
    assert len(trail) == 1
    assert trail[0]["actor"] == "operator" and trail[0]["revision"] == 1
    assert {change["field"] for change in trail[0]["changes"]} == {"alias", "classification", "handling", "handling_target", "tags", "notes"}
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT detail FROM deception_events WHERE id=1").fetchone()[0] == '{"engine":"cowrie","command":"id"}'


def test_source_query_not_lost_when_global_window_is_full(client_roles, monkeypatch):
    from app.services import analytics_svc
    client, tokens, db, _ = client_roles
    with sqlite3.connect(db) as conn:
        conn.executemany("INSERT INTO deception_events(ts,device_id,src_ip,src_port,proto,event_type,username,success,detail) VALUES(?,?,?,?,?,?,?,?,?)", [
            (datetime.now(timezone.utc).isoformat(), "other", "198.51.100.9", 40, "tcp", "connect", None, None, "{}")
            for _ in range(150)
        ])
    monkeypatch.setattr(analytics_svc, "_service", analytics_svc.AnalyticsService(
        analytics_svc.AnalyticsConfig(db_path=db, max_rows=100)))
    response = client.get("/api/investigations/attackers/203.0.113.7", headers=tokens["viewer"])
    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_export_csv_quotes_evidence_and_does_not_modify_store(client_roles):
    client, tokens, db, tmp_path = client_roles
    message = 'A command, with "quotes"\nand a second line'
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO deception_events VALUES(2,?,?,?,?,?,?,?,?,?)", (
            datetime.now(timezone.utc).isoformat(), "srv-files-01", "203.0.113.7", 23,
            "tcp", "command", None, None, json.dumps({"message": message, "engine": "cowrie"})))
        original = conn.execute("SELECT * FROM deception_events ORDER BY id").fetchall()
    path = "/api/investigations/attackers/203.0.113.7/export"
    response = client.get(path + "?format=csv", headers=tokens["viewer"])
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/csv; charset=utf-8"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"].startswith('attachment; filename="dystopia-203.0.113.7-')
    assert response.headers["x-export-rows"] == "2"
    assert response.headers["x-export-truncated"] == "false"
    assert b'"A command, with ""quotes""\nand a second line"' in response.content
    rows = list(csv.reader(StringIO(response.content.decode("utf-8"), newline="")))
    assert rows[0] == ["timestamp", "sensor", "device", "kind", "action", "proto", "port", "severity", "message", "event_id"]
    assert rows[1][1:] == ["cowrie", "srv-files-01", "command", "Comando ejecutado", "tcp", "23", "high", message, "evt_2"]
    assert rows[2][-1] == "evt_1"
    assert client.get(path + "?format=json", headers=tokens["viewer"]).json()["total"] == 2
    assert not (tmp_path / "investigations.db").exists()
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT * FROM deception_events ORDER BY id").fetchall() == original


def test_export_csv_inert_spreadsheet_formula(client_roles):
    client, tokens, db, _ = client_roles
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO deception_events VALUES(2,?,?,?,?,?,?,?,?,?)", (
            datetime.now(timezone.utc).isoformat(), "srv-files-01", "203.0.113.7", 23,
            "tcp", "command", None, None, json.dumps({"message": '=HYPERLINK("https://example.invalid")'})))
    response = client.get("/api/investigations/attackers/203.0.113.7/export?format=csv", headers=tokens["viewer"])
    assert response.status_code == 200
    rows = list(csv.reader(StringIO(response.text, newline="")))
    assert rows[1][8] == "'=HYPERLINK(\"https://example.invalid\")"


def test_export_json_limits_sample_and_validation(client_roles, monkeypatch):
    from app.services import analytics_svc
    from app.services.security import api_keys_svc

    client, tokens, db, tmp_path = client_roles
    path = "/api/investigations/attackers/203.0.113.7/export"
    with sqlite3.connect(db) as conn:
        conn.executemany("INSERT INTO deception_events(ts,device_id,src_ip,src_port,proto,event_type,username,success,detail) VALUES(?,?,?,?,?,?,?,?,?)", [
            (datetime.now(timezone.utc).isoformat(), "srv-files-01", "203.0.113.7", 42, "tcp", "connect", None, None, "{}")
            for _ in range(3)
        ])
    response = client.get(path + "?format=json&limit=2", headers=tokens["viewer"])
    assert response.status_code == 200
    data = response.json()
    assert data["source"] == "203.0.113.7"
    assert data["exported_at"] and data["window"]["from"] and data["window"]["to"]
    assert data["total"] == client.get(path.removesuffix("/export"), headers=tokens["viewer"]).json()["total"] == 4
    assert data["exported"] == len(data["items"]) == 2 and data["truncated"] is True
    assert set(data["items"][0]) == {"id", "timestamp", "sensor", "device", "kind", "action", "proto", "port", "dst_ip", "dst_port", "severity", "message", "detail"}
    assert response.headers["x-export-rows"] == "2" and response.headers["x-export-truncated"] == "true"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"].endswith('.json"')
    assert client.get(path).status_code == 401
    monkeypatch.setattr(api_keys_svc, "validate_api_key", lambda key: {"name": "test", "role": "viewer", "id": "synthetic"})
    assert client.get(path, headers={"Authorization": "Bearer np_synthetic"}).status_code == 403
    assert client.get("/api/investigations/attackers/not-an-ip/export", headers=tokens["viewer"]).status_code == 422
    assert client.get(path + "?format=xml", headers=tokens["viewer"]).status_code == 422
    for invalid in ("0", "10001", "abc"):
        assert client.get(path + f"?limit={invalid}", headers=tokens["viewer"]).status_code == 422
    monkeypatch.setattr(analytics_svc, "_service", analytics_svc.AnalyticsService(
        analytics_svc.AnalyticsConfig(db_path=db, max_rows=2)))
    capped = client.get(path + "?format=json&limit=10000", headers=tokens["viewer"]).json()
    assert capped["total"] == capped["exported"] == 2
    assert len(capped["items"]) == 2
    assert not (tmp_path / "investigations.db").exists()


def test_export_missing_event_store_does_not_create_database(client_roles, monkeypatch, tmp_path):
    from app.services import analytics_svc

    client, tokens, _, _ = client_roles
    missing = tmp_path / "missing-events.db"
    monkeypatch.setattr(analytics_svc, "_service", analytics_svc.AnalyticsService(
        analytics_svc.AnalyticsConfig(db_path=missing)))
    response = client.get("/api/investigations/attackers/203.0.113.7/export?format=json", headers=tokens["viewer"])
    assert response.status_code == 200 and response.json()["total"] == 0
    assert not missing.exists()


def test_sensor_draft_admin_only_and_apply_blocked(client_roles):
    client, tokens, _, _ = client_roles
    path = "/api/investigations/honeypots/cowrie"
    body = {"revision": 0, "display_name": "SSH", "description": "Laboratorio", "memory_mib": 512, "cpus": 0.5, "pids_limit": 256}
    assert client.get(path, headers=tokens["viewer"]).json()["draft"] is None
    baseline = client.get(path + "/plan", headers=tokens["viewer"])
    assert baseline.status_code == 200
    assert baseline.json()["baseline"]["display_name"] == "Cowrie"
    assert baseline.json()["changes"] == []
    assert len(baseline.json()["plan_sha256"]) == 64
    assert baseline.json()["activation"] == "blocked"
    assert client.put(path, json=body, headers=tokens["operator"]).status_code == 403
    assert client.put(path, json={**body, "memory_mib": 99999}, headers=tokens["admin"]).status_code == 422
    response = client.put(path, json=body, headers=tokens["admin"])
    assert response.status_code == 200
    assert response.json()["draft"]["revision"] == 1
    assert response.json()["application"] == "blocked"
    assert {change["field"] for change in response.json()["plan"]["changes"]} == {"display_name", "description"}
    assert response.json()["plan"]["plan_sha256"] != baseline.json()["plan_sha256"]
    assert client.put(path, json=body, headers=tokens["admin"]).status_code == 409
    assert client.get(path, headers=tokens["viewer"]).json()["draft"]["description"] == "Laboratorio"
    trail = client.get(path + "/history", headers=tokens["viewer"]).json()["items"]
    assert len(trail) == 1 and trail[0]["actor"] == "admin" and trail[0]["revision"] == 1
    assert client.post(path + "/apply", headers=tokens["viewer"]).status_code == 403
    assert client.post(path + "/apply", headers=tokens["admin"]).status_code == 409
    assert client.get("/api/investigations/honeypots/unknown", headers=tokens["admin"]).status_code == 404


def test_attacker_timeline_utc_buckets_and_empty(client_roles):
    from datetime import timedelta
    client, tokens, db, tmp_path = client_roles
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    earlier = now - timedelta(hours=2)
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO deception_events VALUES(2,?,?,?,?,?,?,?,?,?)", (
            earlier.isoformat(), "srv", "198.51.100.88", 12, "tcp", "connect", None, None, "{}"))
        conn.execute("INSERT INTO deception_events VALUES(3,?,?,?,?,?,?,?,?,?)", (
            now.isoformat(), "srv", "198.51.100.88", 12, "tcp", "connect", None, None, "{}"))
    url = "/api/investigations/attackers/198.51.100.88/timeline"
    result = client.get(url, headers=tokens["viewer"])
    assert result.status_code == 200
    assert result.json()["interval"] == "1h"
    assert result.json()["total"] == 2
    assert result.json()["buckets"] == [
        {"at": earlier.replace(minute=0).isoformat(), "count": 1},
        {"at": now.replace(minute=0).isoformat(), "count": 1},
    ]
    empty = client.get("/api/investigations/attackers/198.51.100.77/timeline", headers=tokens["viewer"])
    assert empty.status_code == 200 and empty.json()["buckets"] == [] and empty.json()["total"] == 0
    assert client.get(url + "?interval=1m", headers=tokens["viewer"]).status_code == 422
    assert client.get(url).status_code == 401
    assert not (tmp_path / "investigations.db").exists()


def test_attacker_prefix_search_validation_and_bound(client_roles, monkeypatch, tmp_path):
    from app.services import analytics_svc
    client, tokens, db, investigation_dir = client_roles
    with sqlite3.connect(db) as conn:
        conn.executemany("INSERT INTO deception_events(ts,device_id,src_ip,src_port,proto,event_type,username,success,detail) VALUES(?,?,?,?,?,?,?,?,?)", [
            (datetime.now(timezone.utc).isoformat(), "srv", f"203.0.113.{ip}", 12, "tcp", "connect", None, None, "{}")
            for ip in (8, 9, 10)
        ])
    url = "/api/investigations/attackers"
    assert client.get(url).status_code == 401
    for query in ("1", "abc", "1%", "1_", "12\n", "1' OR 1=1", "1" * 46):
        assert client.get(url, params={"query": query}, headers=tokens["viewer"]).status_code == 422
    assert client.get(url, headers=tokens["viewer"]).status_code == 422
    result = client.get(url, params={"query": "203.0.113.", "limit": 2}, headers=tokens["viewer"])
    assert result.status_code == 200
    assert len(result.json()["items"]) == 2
    assert all(item["source"].startswith("203.0.113.") for item in result.json()["items"])
    assert result.json()["scanned_limit"] == 20_000
    assert not (investigation_dir / "investigations.db").exists()
    missing = tmp_path / "missing-events.db"
    monkeypatch.setattr(analytics_svc, "_service", analytics_svc.AnalyticsService(
        analytics_svc.AnalyticsConfig(db_path=missing)))
    assert client.get(url, params={"query": "203"}, headers=tokens["viewer"]).json()["items"] == []
    assert client.get("/api/investigations/attackers/203.0.113.7/timeline", headers=tokens["viewer"]).json()["total"] == 0
    assert not missing.exists()


def test_attacker_handling_is_validated_and_audited(client_roles):
    client, tokens, _, _ = client_roles
    path = "/api/investigations/attackers/203.0.113.7/annotation"
    base = {"revision": 0, "alias": "watch", "classification": "other",
            "handling": "redirect", "handling_target": "unknown", "tags": [], "notes": ""}
    assert client.put(path, json=base, headers=tokens["operator"]).status_code == 422
    base["handling_target"] = "cowrie"
    saved = client.put(path, json=base, headers=tokens["operator"])
    assert saved.status_code == 200
    assert saved.json()["handling"] == "redirect"
    assert saved.json()["handling_target"] == "cowrie"

    monitor = {**base, "revision": 1, "handling": "monitor", "handling_target": ""}
    updated = client.put(path, json=monitor, headers=tokens["operator"])
    assert updated.status_code == 200
    assert updated.json()["handling"] == "monitor"
    assert updated.json()["handling_target"] == ""
    trail = client.get(path.replace("/annotation", "/history"), headers=tokens["viewer"]).json()["items"]
    assert any(change["field"] == "handling" for change in trail[0]["changes"])
