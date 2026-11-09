"""Offline contract tests for the local SQLite analytics service."""

import sqlite3
from pathlib import Path

import pytest

from app.services import analytics_svc
from app.services.deception import geoip_svc


def _control_db(path: Path) -> None:
    with sqlite3.connect(path) as conn:
        conn.executescript("""
            CREATE TABLE deception_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                device_id TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                src_port INTEGER,
                proto TEXT DEFAULT '',
                event_type TEXT NOT NULL,
                username TEXT,
                success INTEGER,
                detail TEXT DEFAULT '{}'
            );
        """)
        conn.execute(
            "INSERT INTO deception_events(ts,device_id,src_ip,src_port,proto,event_type,username,success,detail) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (
                "2026-11-05T12:00:00+00:00", "srv-files-01", "203.0.113.7", 55555,
                "ssh", "login_attempt", "admin", 0, '{"engine":"cowrie"}',
            ),
        )
        conn.execute(
            "INSERT INTO deception_events(ts,device_id,src_ip,src_port,proto,event_type,username,success,detail) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (
                "2026-11-05T12:05:00+00:00", "srv-files-01", "203.0.113.7", 55555,
                "ssh", "command", "root", 1, '{"engine":"cowrie","command":"id"}',
            ),
        )


def _runtime_db(path: Path) -> None:
    with sqlite3.connect(path) as conn:
        conn.executescript("""
            CREATE TABLE events (
                sensor TEXT NOT NULL, event_id TEXT NOT NULL, device TEXT NOT NULL,
                received_at TEXT NOT NULL, received_epoch REAL NOT NULL,
                observed_at TEXT NOT NULL, kind TEXT NOT NULL, source TEXT NOT NULL,
                payload BLOB NOT NULL, PRIMARY KEY(sensor,event_id)
            );
        """)
        payload = (
            '{"event_id":"6f7a7f0a-0a2a-4b15-9c12-6c577f9b0f22",'
            '"device_id":"srv-files-01","observed_at":"2026-11-05T12:10:00+00:00",'
            '"src_ip":"203.0.113.7","type":"login_success","proto":"ssh","src_port":55555,'
            '"detail":{"command":"id"}}'
        )
        conn.execute(
            "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
            (
                "cowrie", "6f7a7f0a-0a2a-4b15-9c12-6c577f9b0f22", "srv-files-01",
                "2026-11-05T12:10:01+00:00", 0.0, "2026-11-05T12:10:00+00:00",
                "login_success", "203.0.113.7", payload.encode(),
            ),
        )


@pytest.fixture
def geo(monkeypatch):
    monkeypatch.setattr(
        geoip_svc,
        "lookup",
        lambda ip: {
            "country_code": "US",
            "country": "United States",
            "city": "Ashburn",
            "lat": 39.04,
            "lon": -77.48,
        },
    )


def test_control_schema_overview_timeline_and_origins(tmp_path, geo):
    path = tmp_path / "events.db"
    _control_db(path)
    service = analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig(db_path=path))
    window = ("2026-11-05T11:00:00+00:00", "2026-11-05T13:00:00+00:00")
    overview = service.overview(*window)
    assert overview["total_events"] == 2
    assert overview["unique_sources"] == 1
    assert overview["alerts"] == 0
    assert overview["protocols"] == [{"name": "ssh", "value": 2}]
    assert overview["datasets"] == [{"name": "cowrie", "value": 2}]

    timeline = service.timeline(*window, interval="1h")
    assert len(timeline["buckets"]) == 3
    assert sum(bucket["count"] for bucket in timeline["buckets"]) == 2

    origins = service.origins(*window)
    assert origins["origins"][0]["countryCode"] == "US"
    assert origins["origins"][0]["lat"] == 39.04
    assert origins["origins"][0]["severity"] == "high"

    events = service.events(*window, limit=10)
    assert events["total"] == 2
    assert events["items"][0]["sensor"] == "cowrie"
    assert events["items"][0]["severity"] == "high"


def test_origins_split_by_us_state(tmp_path, monkeypatch):
    path = tmp_path / "events.db"
    _control_db(path)
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO deception_events(ts,device_id,src_ip,src_port,proto,event_type,username,success,detail) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            ("2026-11-05T12:01:00+00:00", "srv-files-01", "198.51.100.20", 44444,
             "ssh", "connect", None, None, '{"engine":"cowrie"}'),
        )
    states = {"203.0.113.7": ("California", "CA", 34.05, -118.0),
              "198.51.100.20": ("Texas", "TX", 30.27, -97.74)}

    def lookup(ip):
        name, code, lat, lon = states[ip]
        return {"country_code": "US", "country": "United States", "subdivision": name,
                "subdivision_code": code, "city": name, "lat": lat, "lon": lon}

    monkeypatch.setattr(geoip_svc, "lookup", lookup)
    service = analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig(db_path=path))
    origins = service.origins("2026-11-05T11:00:00+00:00", "2026-11-05T13:00:00+00:00")["origins"]
    assert len(origins) == 2
    by_state = {origin["regionCode"]: origin for origin in origins}
    assert set(by_state) == {"CA", "TX"}
    assert all(origin["countryCode"] == "US" for origin in origins)
    assert by_state["CA"]["region"] == "California"
    assert by_state["CA"]["ip"] == "203.0.113.7"
    assert by_state["CA"]["events"] == 2
    assert by_state["CA"]["uniqueSources"] == 1
    assert by_state["CA"]["lng"] == -118.0  # regresión: no descartar longitudes negativas
    assert by_state["TX"]["region"] == "Texas"
    assert by_state["TX"]["ip"] == "198.51.100.20"
    assert by_state["TX"]["events"] == 1
    assert by_state["TX"]["uniqueSources"] == 1
    assert by_state["TX"]["lng"] == -97.74


def test_runtime_schema_is_supported(tmp_path, geo):
    path = tmp_path / "runtime.db"
    _runtime_db(path)
    service = analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig(db_path=path))
    window = ("2026-11-05T11:00:00+00:00", "2026-11-05T13:00:00+00:00")
    events = service.events(*window, limit=10)
    assert events["total"] == 1
    assert events["items"][0]["sensor"] == "cowrie"
    assert events["items"][0]["severity"] == "critical"
    assert events["items"][0]["source"] == "203.0.113.7"


def test_missing_store_is_empty_not_an_error(tmp_path):
    service = analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig(db_path=tmp_path / "missing.db"))
    overview = service.overview("2026-11-05T11:00:00+00:00", "2026-11-05T13:00:00+00:00")
    assert overview["total_events"] == 0
    assert service.origins("2026-11-05T11:00:00+00:00", "2026-11-05T13:00:00+00:00")["origins"] == []
    assert service.health()["status"] == "empty"


def test_health_reports_resolved_db_path(tmp_path):
    path = tmp_path / "missing.db"
    service = analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig(db_path=path))
    health = service.health()
    assert health["db"] == str(path.resolve())
    assert health["db_exists"] is False

    existing = tmp_path / "existing.db"
    _control_db(existing)
    health = analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig(db_path=existing)).health()
    assert health["db"] == str(existing.resolve())
    assert health["db_exists"] is True


def test_analytics_and_store_resolve_the_same_control_plane_db():
    from app.core import settings
    from app.services.deception import store_svc

    default = analytics_svc.AnalyticsConfig.from_env({})
    assert default.db_path == settings.DECEPTION_DB
    assert default.db_path == store_svc.DB_PATH
    assert analytics_svc.AnalyticsConfig().db_path == store_svc.DB_PATH
    # An empty override must not silently point analytics at a second store.
    empty = analytics_svc.AnalyticsConfig.from_env({"DYSTOPIA_ANALYTICS_DB": "  "})
    assert empty.db_path == settings.DECEPTION_DB


def test_analytics_db_override_is_opt_in(tmp_path):
    override = tmp_path / "analytics.db"
    config = analytics_svc.AnalyticsConfig.from_env({"DYSTOPIA_ANALYTICS_DB": str(override)})
    assert config.db_path == override


def test_invalid_window_is_rejected(tmp_path):
    service = analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig(db_path=tmp_path / "missing.db"))
    with pytest.raises(ValueError):
        service.overview("2026-11-05T13:00:00+00:00", "2026-11-05T11:00:00+00:00")
    with pytest.raises(ValueError):
        service.timeline(None, None, "2h")


def test_control_schema_wins_when_both_tables_exist(tmp_path, geo):
    """El colector escribe deception_events: si hay tabla runtime obsoleta,
    analytics no debe leerla por prioridad."""
    path = tmp_path / "both.db"
    _control_db(path)
    with sqlite3.connect(path) as conn:
        conn.executescript("""
            CREATE TABLE events (
                sensor TEXT, event_id TEXT, device TEXT, observed_at TEXT,
                kind TEXT, source TEXT, severity TEXT, message TEXT, payload TEXT
            );
        """)
        conn.execute(
            "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
            ("cowrie", "legacy-1", "srv-files-01", "2026-11-05T12:00:00+00:00",
             "login_attempt", "198.51.100.9", "critical", "", "{}"),
        )
    service = analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig(db_path=path))
    window = ("2026-11-05T11:00:00+00:00", "2026-11-05T13:00:00+00:00")
    overview = service.overview(*window)
    assert overview["total_events"] == 2  # solo deception_events
    events = service.events(*window, limit=10)
    assert events["total"] == 2
    assert {e["source"] for e in events["items"]} == {"203.0.113.7"}
