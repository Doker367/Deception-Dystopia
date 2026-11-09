"""Bounded investigation pagination, audit retention and search regressions."""
from datetime import datetime, timezone
import sqlite3

import test_investigations

client_roles = test_investigations.client_roles  # shared isolated API fixture


def test_pages_bounded_and_disjoint_with_tied_timestamps(client_roles, monkeypatch):
    from app.services import analytics_svc
    from app.services.deception import store_svc

    with sqlite3.connect(":memory:") as empty:
        empty.executescript(store_svc._SCHEMA)
        assert empty.execute("SELECT 1 FROM sqlite_master WHERE type='index' "
                             "AND name='idx_deception_events_src_ts_id'").fetchone() == (1,)

    client, tokens, db, _ = client_roles
    stamp = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(db) as conn:
        conn.executemany(
            "INSERT INTO deception_events(ts,device_id,src_ip,src_port,proto,event_type,username,success,detail) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            [(stamp, "sensor", "203.0.113.7", 1000, "tcp", "connect", None, None, "{}")
             for _ in range(129)],
        )
        conn.execute("CREATE INDEX source_order ON deception_events(src_ip, ts DESC, id DESC)")
        plan = conn.execute(
            "EXPLAIN QUERY PLAN SELECT id FROM deception_events WHERE src_ip=? AND ts>=? "
            "AND ts<=? ORDER BY ts DESC,id DESC LIMIT ? OFFSET ?",
            ("203.0.113.7", stamp, stamp, 10, 10),
        ).fetchall()
        assert any("source_order" in row[3] for row in plan)
    monkeypatch.setattr(analytics_svc, "_service", analytics_svc.AnalyticsService(
        analytics_svc.AnalyticsConfig(db_path=db, max_rows=100)))
    path = "/api/investigations/attackers/203.0.113.7"
    pages = [client.get(path, params={"offset": offset, "limit": 40},
                        headers=tokens["viewer"]) for offset in (0, 40, 80, 120)]
    assert all(response.status_code == 200 for response in pages)
    assert [response.json()["total"] for response in pages] == [100] * 4
    ids = [item["id"] for response in pages for item in response.json()["items"]]
    assert len(ids) == len(set(ids)) == 100
    assert [len(response.json()["items"]) for response in pages] == [40, 40, 20, 0]
    assert ids == [f"evt_{value}" for value in range(130, 30, -1)]
    assert all(response.json()["scanned_limit"] == 100 for response in pages)
    slim = client.get(path, params={"offset": 40, "limit": 40, "summary": "false"},
                      headers=tokens["viewer"])
    assert slim.status_code == 200
    assert [row["id"] for row in slim.json()["items"]] == ids[40:80]
    assert slim.json()["total"] == 100 and "protocols" not in slim.json()
    assert pages[0].json()["protocols"] == {"tcp": 100}
    assert client.get(path, params={"offset": -1}, headers=tokens["viewer"]).status_code == 422
    assert client.get(path, params={"limit": 101}, headers=tokens["viewer"]).status_code == 422


def test_audit_retention_only_deletes_old_audit_rows(client_roles, monkeypatch):
    from app.services import investigation_svc

    client, tokens, events, tmp_path = client_roles
    monkeypatch.setattr(investigation_svc, "AUDIT_MAX_ROWS", 3)
    path = "/api/investigations/attackers/203.0.113.7/annotation"
    with sqlite3.connect(events) as conn:
        before = conn.execute("SELECT * FROM deception_events").fetchall()
    for revision in range(5):
        response = client.put(path, json={"revision": revision, "alias": f"alias-{revision}"},
                              headers=tokens["operator"])
        assert response.status_code == 200
    sensor = "/api/investigations/honeypots/cowrie"
    saved = client.put(sensor, json={"revision": 0, "display_name": "Cowrie",
                                     "memory_mib": 512, "cpus": 0.5, "pids_limit": 256},
                       headers=tokens["admin"])
    assert saved.status_code == 200
    with sqlite3.connect(tmp_path / "investigations.db") as conn:
        assert conn.execute("SELECT id FROM audit ORDER BY id").fetchall() == [(4,), (5,), (6,)]
        assert conn.execute("SELECT revision FROM profiles").fetchone() == (5,)
        assert conn.execute("SELECT revision FROM sensor_drafts").fetchone() == (1,)
    with sqlite3.connect(events) as conn:
        assert conn.execute("SELECT * FROM deception_events").fetchall() == before
    history = client.get(path.removesuffix("/annotation") + "/history", headers=tokens["viewer"])
    assert [item["revision"] for item in history.json()["items"]] == [5, 4]
    assert client.post(sensor + "/apply", headers=tokens["admin"]).status_code == 409


def test_bounded_global_search_and_readonly_missing_tables(client_roles, monkeypatch):
    from app.services.security import api_keys_svc

    client, tokens, events, tmp_path = client_roles
    monkeypatch.setattr(api_keys_svc, "validate_api_key",
                        lambda key: {"name": "test", "role": "viewer", "id": "synthetic"})
    key_headers = {"Authorization": "Bearer np_synthetic"}
    for restricted in ("/api/investigations/attackers/203.0.113.7/history",
                       "/api/investigations/honeypots/cowrie/plan",
                       "/api/investigations/honeypots/cowrie/history"):
        assert client.get(restricted, headers=key_headers).status_code == 403
    with sqlite3.connect(events) as conn:
        conn.executemany(
            "INSERT INTO deception_events(ts,device_id,src_ip,src_port,proto,event_type,username,success,detail) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            [(datetime.now(timezone.utc).isoformat(), "device", "198.51.100.8", 1234,
              "tcp", "connect", None, None, '{"message":"needle"}') for _ in range(120)],
        )
    path = "/api/analytics/events"
    assert client.get(path, params={"q": "needle"}).status_code == 401
    search = client.get(path, params={"q": "198.51.100.8", "limit": 10}, headers=tokens["viewer"])
    assert search.status_code == 200
    assert search.json()["total"] == 120
    assert len(search.json()["items"]) == 10
    assert client.get(path, params={"q": "not-in-sample"}, headers=tokens["viewer"]).json()["items"] == []
    assert client.get(path, params={"limit": 101}, headers=tokens["viewer"]).status_code == 422
    assert not (tmp_path / "investigations.db").exists()
    private_db = tmp_path / "investigations.db"
    with sqlite3.connect(private_db):
        pass
    private_db.chmod(0o600)
    before = private_db.stat().st_mtime_ns
    assert client.get("/api/investigations/attackers/203.0.113.7",
                      headers=tokens["viewer"]).status_code == 200
    assert client.get("/api/investigations/attackers/203.0.113.7/history",
                      headers=tokens["viewer"]).json()["items"] == []
    with sqlite3.connect(private_db) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == []
    assert private_db.stat().st_mtime_ns == before
