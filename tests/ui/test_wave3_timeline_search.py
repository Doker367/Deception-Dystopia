"""Bounded source discovery on the runtime event schema."""
from datetime import datetime, timedelta, timezone
import sqlite3

from app.services.analytics_svc import AnalyticsConfig, AnalyticsService


def test_runtime_timeline_falls_back_to_days_and_caps_sample(tmp_path):
    db = tmp_path / "runtime-events.db"
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE events(sensor TEXT, event_id TEXT, device TEXT, observed_at TEXT, kind TEXT, source TEXT, payload TEXT)")
        conn.execute("CREATE INDEX idx_events_source_observed ON events(source,observed_at)")
        conn.executemany("INSERT INTO events VALUES(?,?,?,?,?,?,?)", [
            ("sensor", str(index), "device", (now - timedelta(hours=index)).isoformat(),
             "connect", "2001:db8::1", "{}") for index in range(110)
        ])
    service = AnalyticsService(AnalyticsConfig(db_path=db, max_rows=150))
    timeline = service.attacker_timeline("2001:db8::1")
    assert timeline["interval"] == "1d"
    assert timeline["total"] == 110 and timeline["scanned_limit"] == 150
    assert len(timeline["buckets"]) <= 100
    assert sum(bucket["count"] for bucket in timeline["buckets"]) == 110
    service = AnalyticsService(AnalyticsConfig(db_path=db, max_rows=100))
    assert service.attacker_timeline("2001:db8::1")["total"] == 100
    found = service.search_attackers("2001:db8:")
    assert found["items"][0]["source"] == "2001:db8::1"
    assert found["items"][0]["events"] == 100
    assert not (tmp_path / "investigations.db").exists()
