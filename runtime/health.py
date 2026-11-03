"""Read-only operator diagnostics; never create databases or alter schemas."""
from pathlib import Path
import sqlite3
import time


def snapshot(path, role):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError("existing regular database required")
    db = sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True, timeout=2)
    try:
        db.execute("PRAGMA query_only=ON")
        if role == "sensor":
            count, used, oldest = db.execute("SELECT COUNT(*),COALESCE(SUM(length(payload)),0),MIN(queued) FROM queue").fetchone()
            quarantined = db.execute("SELECT COUNT(*) FROM queue WHERE quarantined=1").fetchone()[0]
            pending = count - quarantined
            dropped = db.execute("SELECT value FROM counters WHERE name='discarded'").fetchone()
            dead_lettered = db.execute("SELECT value FROM counters WHERE name='dead_lettered'").fetchone()
            return {"queued": count, "pending": pending, "live": pending,
                    "payload_bytes": used, "quarantined": quarantined,
                    "dead_lettered_persisted": dead_lettered[0] if dead_lettered else 0,
                    "oldest_seconds": max(0,time.time()-oldest) if oldest else 0,
                    "discarded_persisted": dropped[0] if dropped else 0,
                    "connection_state": "see running sensor metrics"}
        if role != "ingest":
            raise ValueError("unknown role")
        events = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        pending, oldest = db.execute("SELECT COUNT(*),MIN(e.received_epoch) FROM outbox o JOIN events e USING(sensor,event_id) WHERE delivered=0").fetchone()
        return {"events": events, "outbox_pending": pending,
                "notification_lag_seconds": max(0,time.time()-oldest) if oldest else 0}
    finally:
        db.close()
