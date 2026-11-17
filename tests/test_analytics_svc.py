"""Offline contract tests for the local SQLite analytics service."""

import json
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
    assert events["items"][0]["source"] == "203.0.113.7"
    assert events["items"][0]["country"] == "United States"
    assert events["items"][0]["countryCode"] == "US"
    assert events["facets"]["severity"]["high"] == 1
    assert events["facets"]["severity"]["low"] == 1
    assert events["facets"]["protocol"]["ssh"] == 2


def test_events_filtra_altos_en_servidor_aunque_haya_mas_recientes(tmp_path):
    """El explorador no debe perder un comando alto por un flujo de conexiones."""
    path = tmp_path / "events.db"
    _control_db(path)
    with sqlite3.connect(path) as conn:
        conn.executemany(
            "INSERT INTO deception_events(ts,device_id,src_ip,src_port,proto,event_type,"
            "username,success,detail) VALUES(?,?,?,?,?,?,?,?,?)",
            [
                (
                    f"2026-11-05T12:{index // 60:02d}:{index % 60:02d}+00:00",
                    "srv-files-01", "198.51.100.9", 40000 + index, "ssh",
                    "connect", None, 0, '{"engine":"cowrie"}',
                )
                for index in range(150)
            ],
        )
    service = analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig(db_path=path))
    window = ("2026-11-05T00:00:00+00:00", "2026-11-06T00:00:00+00:00")
    filtered = service.events(*window, severity="high", limit=12)
    assert filtered["total"] == 1
    assert filtered["items"][0]["kind"] == "command"
    assert filtered["facets"]["severity"]["high"] == 1
    assert filtered["facets"]["severity"]["low"] == 151


def test_source_is_recovered_from_detail_when_the_column_is_unusable(tmp_path, monkeypatch):
    path = tmp_path / "events.db"
    _control_db(path)
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO deception_events(ts,device_id,src_ip,src_port,proto,event_type,username,success,detail) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            ("2026-11-05T12:06:00+00:00", "srv-files-01", "0.0.0.0", None,
             "ssh", "connect", None, None,
             '{"engine":"cowrie","message":"New connection: 198.51.100.7:44321 (10.0.0.2:2222)"}'),
        )
    monkeypatch.setattr(geoip_svc, "lookup", lambda ip: {
        "country_code": "US", "country": "United States", "lat": 39.0, "lon": -77.0,
    })
    service = analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig(db_path=path))
    items = service.events(
        "2026-11-05T11:00:00+00:00", "2026-11-05T13:00:00+00:00", limit=10,
    )["items"]
    recovered = next(item for item in items if item["kind"] == "connect")
    assert recovered["source"] == "198.51.100.7"

    # The stored row is not rewritten by the read-only analytics path.
    with sqlite3.connect(path) as conn:
        assert conn.execute(
            "SELECT src_ip FROM deception_events WHERE event_type='connect'"
        ).fetchone() == ("0.0.0.0",)


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


def test_origins_split_by_mexican_state(tmp_path, monkeypatch):
    path = tmp_path / "mexico.db"
    _control_db(path)  # Dos eventos de una IP de documentación en Chiapas.
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO deception_events(ts,device_id,src_ip,src_port,proto,event_type,username,success,detail) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            ("2026-11-05T12:01:00+00:00", "srv-files-01", "198.51.100.20", 44444,
             "ssh", "connect", None, None, '{"engine":"cowrie"}'),
        )
    states = {
        "203.0.113.7": ("Chiapas", "CHP", "Tuxtla Gutiérrez", 16.75, -93.12),
        "198.51.100.20": ("Jalisco", "JAL", "Guadalajara", 20.66, -103.35),
    }

    def lookup(ip):
        name, code, city, lat, lon = states[ip]
        return {"country_code": "MX", "country": "Mexico", "subdivision": name,
                "subdivision_code": code, "city": city, "lat": lat, "lon": lon}

    monkeypatch.setattr(geoip_svc, "lookup", lookup)
    service = analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig(db_path=path))
    origins = service.origins("2026-11-05T11:00:00+00:00", "2026-11-05T13:00:00+00:00")["origins"]
    assert len(origins) == 2  # No se fusionan los tres eventos por país.
    by_state = {origin["regionCode"]: origin for origin in origins}
    assert set(by_state) == {"CHP", "JAL"}
    assert all(origin["countryCode"] == "MX" for origin in origins)
    assert by_state["CHP"]["region"] == "Chiapas"
    assert by_state["CHP"]["events"] == 2
    assert by_state["JAL"]["city"] == "Guadalajara"
    assert by_state["JAL"]["events"] == 1
    assert by_state["JAL"]["lng"] == -103.35


def test_origins_limit_keeps_high_severity(tmp_path, monkeypatch):
    """El corte por volumen no debe ocultar orígenes de severidad alta.

    Con ventanas largas los escaneos masivos (medium) superan el límite y el
    globo se quedaría entero amarillo si el recorte solo considerara eventos.
    """
    path = tmp_path / "events.db"
    _control_db(path)  # IP de 203.0.113.7 con login_attempt + command (high).
    with sqlite3.connect(path) as conn:
        conn.executemany(
            "INSERT INTO deception_events(ts,device_id,src_ip,src_port,proto,event_type,"
            "username,success,detail) VALUES(?,?,?,?,?,?,?,?,?)",
            [
                (f"2026-11-05T12:{minute:02d}:00+00:00", "srv-files-01", ip, 443, "tcp",
                 "http_request", None, None, '{"engine":"nginx"}')
                for ip in ("198.51.100.20", "198.51.100.21", "198.51.100.22")
                for minute in range(5)
            ],
        )
    places = {
        "203.0.113.7": ("Ashburn", "VA", 39.04, -77.48),
        "198.51.100.20": ("Austin", "TX", 30.27, -97.74),
        "198.51.100.21": ("Dallas", "TX", 32.78, -96.80),
        "198.51.100.22": ("Houston", "TX", 29.76, -95.37),
    }

    def lookup(ip):
        name, code, lat, lon = places[ip]
        return {"country_code": "US", "country": "United States", "subdivision": name,
                "subdivision_code": code, "city": name, "lat": lat, "lon": lon}

    monkeypatch.setattr(geoip_svc, "lookup", lookup)
    service = analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig(db_path=path))
    origins = service.origins(
        "2026-11-05T11:00:00+00:00", "2026-11-05T13:00:00+00:00", limit=2,
    )["origins"]
    assert len(origins) == 2
    # Sin la reserva de cupos el origen high (2 eventos) queda fuera del corte
    # por volumen y la respuesta sería solo de severidad medium.
    assert "high" in {origin["severity"] for origin in origins}
    assert {origin["ip"] for origin in origins} == {"203.0.113.7", "198.51.100.20"}


def test_runtime_schema_is_supported(tmp_path, geo):
    path = tmp_path / "runtime.db"
    _runtime_db(path)
    service = analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig(db_path=path))
    window = ("2026-11-05T11:00:00+00:00", "2026-11-05T13:00:00+00:00")
    events = service.events(*window, limit=10)
    assert events["total"] == 1
    assert events["items"][0]["sensor"] == "cowrie"
    assert events["items"][0]["severity"] == "medium"
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


def test_attacker_profile_keeps_fingerprint_outside_evidence_page(tmp_path, geo):
    """La huella no debe desaparecer cuando el atacante genera más de 50 eventos."""
    path = tmp_path / "events.db"
    _control_db(path)
    fingerprint = '{"client":"{\\"os\\":\\"Linux\\",\\"cores\\":8}","headers":{}}'
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO deception_events(ts,device_id,src_ip,src_port,proto,event_type,"
            "username,success,detail) VALUES(?,?,?,?,?,?,?,?,?)",
            ("2026-11-05T12:10:00+00:00", "srv-files-01", "203.0.113.7", 443,
             "http", "http_request", None, 0, json.dumps({"fingerprint": fingerprint})),
        )
        conn.executemany(
            "INSERT INTO deception_events(ts,device_id,src_ip,src_port,proto,event_type,"
            "username,success,detail) VALUES(?,?,?,?,?,?,?,?,?)",
            [("2026-11-05T12:11:00+00:00", "srv-files-01", "203.0.113.7", 22,
              "ssh", "connect", None, 0, "{}") for _ in range(60)],
        )
    service = analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig(db_path=path))
    profile = service.attacker("203.0.113.7", limit=5)
    assert profile["fingerprint"] == fingerprint
    assert len(profile["items"]) == 5


def test_attacker_profile_reports_post_login_movements(tmp_path, geo):
    """La ficha debe mostrar qué comandos siguieron a un acceso aceptado."""
    path = tmp_path / "events.db"
    _control_db(path)
    rows = [
        ("2026-11-05T12:20:00+00:00", "connect", None, 0, {"session": "s1"}),
        ("2026-11-05T12:21:00+00:00", "login_success", "root", 1, {"session": "s1", "username": "root"}),
        ("2026-11-05T12:22:00+00:00", "command", None, 0, {"session": "s1", "command": "id"}),
        ("2026-11-05T12:22:30+00:00", "command", None, 0, {"session": "s1", "command": "id"}),
        ("2026-11-05T12:23:00+00:00", "command", None, 0, {"session": "s1", "command": "cat /etc/passwd"}),
        ("2026-11-05T12:24:00+00:00", "login_success", "admin", 1, {"session": "s2", "username": "admin"}),
    ]
    with sqlite3.connect(path) as conn:
        conn.executemany(
            "INSERT INTO deception_events(ts,device_id,src_ip,src_port,proto,event_type,"
            "username,success,detail) VALUES(?,?,?,?,?,?,?,?,?)",
            [(ts, "srv-files-01", "203.0.113.7", 2223, "telnet", kind, user, ok,
              json.dumps(detail)) for ts, kind, user, ok, detail in rows],
        )
    service = analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig(db_path=path))
    movements = service.attacker("203.0.113.7", limit=5)["movements"]
    assert [item["session"] for item in movements] == ["s2", "s1"]
    first = next(item for item in movements if item["session"] == "s1")
    assert first["username"] == "root"
    assert first["commands"] == 3
    assert [(step["command"], step["count"]) for step in first["steps"]] == [
        ("id", 2), ("cat /etc/passwd", 1),
    ]
    second = next(item for item in movements if item["session"] == "s2")
    assert second["username"] == "admin"
    assert second["steps"] == []


def test_movement_context_for_ai_is_bounded_and_redacted(monkeypatch):
    """El contexto del RAG sale del servidor, con comandos y salidas del señuelo."""
    profile = {"movements": [{
        "session": "s1", "username": "root", "proto": "telnet",
        "device": "srv-files-01", "commands": 2,
        "steps": [
            {"command": "id", "response": "uid=0(root) gid=0(root)"},
            {"command": "echo password=hunter2", "response": "password=hunter2"},
        ],
    }]}

    class FakeService:
        def attacker(self, source, limit=1):
            assert source == "203.0.113.7" and limit == 1
            return profile

    monkeypatch.setattr(analytics_svc, "AnalyticsService", lambda: FakeService())
    text = analytics_svc.movement_context("203.0.113.7")
    assert "Las respuestas siguientes son salida emulada del señuelo" in text
    assert "Sesión s1 · usuario root · telnet · srv-files-01" in text
    assert "$ id" in text and "uid=0(root) gid=0(root)" in text
    assert "hunter2" not in text and "password=[REDACTED]" in text


def test_movement_context_is_empty_without_successful_login(monkeypatch):
    class FakeService:
        def attacker(self, source, limit=1):
            return {"movements": []}

    monkeypatch.setattr(analytics_svc, "AnalyticsService", lambda: FakeService())
    assert analytics_svc.movement_context("203.0.113.7") == ""


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
