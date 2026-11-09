"""Offline API service contract: new real source, no rewriting old events."""

import sqlite3

from app.services import analytics_svc
from app.services.deception import geoip_svc


def test_event_source_and_subdivision_reach_events_and_origins(tmp_path, monkeypatch):
    database = tmp_path / "events.db"
    with sqlite3.connect(database) as connection:
        connection.executescript("""
            CREATE TABLE deception_events (
                id INTEGER PRIMARY KEY, ts TEXT, device_id TEXT, src_ip TEXT,
                src_port INTEGER, proto TEXT, event_type TEXT,
                username TEXT, success INTEGER, detail TEXT
            );
        """)
        connection.executemany(
            "INSERT INTO deception_events VALUES (?,?,?,?,?,?,?,?,?,?)",
            [
                (1, "2026-11-05T12:01:00+00:00", "decoy", "10.66.0.1", 51234,
                 "ssh", "connect", None, None, "{}"),
                (2, "2026-11-05T12:02:00+00:00", "decoy", "203.0.113.7", 51235,
                 "ssh", "connect", None, None, "{}"),
            ],
        )

    def geo(ip):
        if ip != "203.0.113.7":
            return None
        return {"country_code": "US", "country": "United States", "subdivision": "California",
                "subdivision_code": "CA", "lat": 34.05, "lon": -118.0}

    monkeypatch.setattr(geoip_svc, "lookup", geo)
    service = analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig(db_path=database))
    window = ("2026-11-05T12:00:00+00:00", "2026-11-05T12:05:00+00:00")
    events = service.events(*window)["items"]
    assert [(item["source"], item["regionCode"]) for item in events] == [
        ("203.0.113.7", "CA"), ("10.66.0.1", "")
    ]
    assert service.origins(*window)["origins"][0]["regionCode"] == "CA"
    # Only the response is enriched: historic rows retain their captured source.
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT src_ip FROM deception_events ORDER BY id").fetchall() == [
            ("10.66.0.1",), ("203.0.113.7",)
        ]
