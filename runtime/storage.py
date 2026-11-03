"""Bounded durable queues. DELETE journal: disk bound is ~2x DB cap plus metadata.

No automatic event deletion: an operator must archive before retention is changed.
A failed transaction is never acknowledged. Metrics contain no event payloads.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import os
import grp
import shutil
import sqlite3
import stat
import time

from runtime.contracts import encode
from runtime.localfiles import open_private_parent


class CapacityError(RuntimeError):
    pass


@contextmanager
def database(path, max_bytes=256 * 1024 * 1024, read_group_gid=None):
    path = Path(path)
    # Parent must be provisioned, owned by the service/root and inaccessible to
    # decoys.  Verify it before creating the leaf; tmp_path-style 0700 parents
    # and the deployed /var/lib/dystopia tree both satisfy this invariant.
    parent_fd = open_private_parent(path)
    os.close(parent_fd)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PermissionError("database must be a regular single-link file")
        private = info.st_mode & 0o077 == 0
        # Only event storage may grant exact read-only access to the dedicated
        # query group. Spool and credential registry remain owner-only.
        query_read = (read_group_gid is not None and info.st_gid == read_group_gid
                      and stat.S_IMODE(info.st_mode) == 0o640)
        if read_group_gid is not None and info.st_uid != os.geteuid():
            raise PermissionError("event database owner must be the ingest service")
        if read_group_gid is None and info.st_uid not in {0, os.geteuid()}:
            raise PermissionError("database owner must be root or the service uid")
        if not (private or query_read):
            raise PermissionError("database permissions differ from the configured private policy")
    finally:
        os.close(fd)
    conn = sqlite3.connect(path, timeout=2, isolation_level=None)
    try:
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA temp_store=MEMORY")
        page_size = conn.execute("PRAGMA page_size").fetchone()[0]
        max_pages = max_bytes // page_size
        if max_pages < 1 or conn.execute("PRAGMA page_count").fetchone()[0] > max_pages:
            raise CapacityError("existing database exceeds configured disk cap")
        effective = conn.execute(f"PRAGMA max_page_count={max_pages}").fetchone()[0]
        if effective != max_pages:
            raise CapacityError("SQLite disk cap could not be installed")
        conn.execute("PRAGMA busy_timeout=2000")
        yield conn
    finally:
        conn.close()


class EventStore:
    def __init__(self, path, max_events=100000, per_sensor=10000, max_bytes=256*1024*1024):
        self.path = Path(path)
        group = os.getenv("DYSTOPIA_QUERY_GROUP")
        self.read_group_gid = grp.getgrnam(group).gr_gid if group else None
        self.max_events, self.per_sensor, self.max_bytes = max_events, per_sensor, max_bytes
        self.rejected = 0
        self.storage_exhausted = False
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    sensor TEXT NOT NULL, event_id TEXT NOT NULL, device TEXT NOT NULL,
                    received_at TEXT NOT NULL, received_epoch REAL NOT NULL,
                    observed_at TEXT NOT NULL, kind TEXT NOT NULL, source TEXT NOT NULL,
                    payload BLOB NOT NULL, PRIMARY KEY(sensor,event_id));
                CREATE INDEX IF NOT EXISTS brute ON events(sensor,device,source,kind,received_epoch);
                CREATE INDEX IF NOT EXISTS received_order ON events(received_epoch DESC,sensor DESC,event_id DESC);
                CREATE TABLE IF NOT EXISTS outbox (
                    sensor TEXT NOT NULL, event_id TEXT NOT NULL, rule TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0, due REAL NOT NULL DEFAULT 0,
                    delivered INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(sensor,event_id));
            """)

    def connect(self):
        return database(self.path, self.max_bytes, self.read_group_gid)

    def ingest(self, sensor, events):
        """Persistence + deterministic evaluation + outbox in one transaction.

        No AI call or notification I/O in this path. Reception time drives windows.
        """
        try:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                new = []
                for event in events:
                    prior = db.execute("SELECT payload FROM events WHERE sensor=? AND event_id=?",
                                       (sensor, event["event_id"])).fetchone()
                    if prior:
                        if prior[0] != encode(event):
                            raise ValueError("event ID reused with different content")
                    else:
                        new.append(event)
                if (db.execute("SELECT COUNT(*) FROM events").fetchone()[0] + len(new) > self.max_events
                        or db.execute("SELECT COUNT(*) FROM events WHERE sensor=?", (sensor,)).fetchone()[0] + len(new) > self.per_sensor
                        or (new and shutil.disk_usage(self.path.parent).free < self.max_bytes * 2)):
                    raise CapacityError("event capacity exhausted; archive required")
                now = time.time()
                received = datetime.fromtimestamp(now, timezone.utc).isoformat()
                for e in new:
                    db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                               (sensor, e["event_id"], e["device_id"], received, now,
                                e["observed_at"], e["type"], e["src_ip"], encode(e)))
                    rule = e["type"] if e["type"] in {"login_success", "file_download", "port_scan", "command"} else None
                    if e["type"] == "login_attempt":
                        count = db.execute("SELECT COUNT(*) FROM events WHERE sensor=? AND device=? AND source=? AND kind='login_attempt' AND received_epoch>=?",
                                           (sensor, e["device_id"], e["src_ip"], now - 60)).fetchone()[0]
                        if count >= 5:
                            rule = "brute_force"
                    if rule:
                        db.execute("INSERT INTO outbox(sensor,event_id,rule) VALUES(?,?,?)",
                                   (sensor, e["event_id"], rule))
                db.execute("COMMIT")
                self.storage_exhausted = False
                return {"accepted": len(new), "duplicates": len(events)-len(new)}
        except (sqlite3.Error, OSError) as exc:
            self.rejected += len(events)
            self.storage_exhausted = True
            raise CapacityError("storage unavailable") from exc
        except CapacityError:
            self.rejected += len(events)
            self.storage_exhausted = True
            raise

    def health(self):
        with self.connect() as db:
            count = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            pending, oldest = db.execute("SELECT COUNT(*),MIN(e.received_epoch) FROM outbox o JOIN events e USING(sensor,event_id) WHERE delivered=0").fetchone()
        return {"events": count, "capacity": self.max_events, "outbox_pending": pending,
                "notification_lag_seconds": max(0, time.time() - oldest) if oldest else 0,
                "rejected_since_start": self.rejected, "storage_exhausted": self.storage_exhausted or count >= self.max_events
                or shutil.disk_usage(self.path.parent).free < self.max_bytes * 2}

    def deliver_one(self, sender):
        """Separate worker; at least once. Receiver deduplicates by sensor/event_id.

        sender receives only metadata, never hostile captured details/credentials.
        Retry indefinitely with a bounded delay, without adding new queue entries.
        """
        with self.connect() as db:
            row = db.execute("SELECT sensor,event_id,rule,attempts FROM outbox WHERE delivered=0 AND due<=? ORDER BY due LIMIT 1", (time.time(),)).fetchone()
        if row is None:
            return False
        sensor, event_id, rule, attempts = row
        try:
            sender({"sensor_id": sensor, "event_id": event_id, "rule": rule})
        except Exception:
            with self.connect() as db:
                db.execute("UPDATE outbox SET attempts=MIN(attempts+1,1000000),due=? WHERE sensor=? AND event_id=?",
                           (time.time() + min(300, 2 ** min(attempts, 8)), sensor, event_id))
            return False
        with self.connect() as db:
            db.execute("UPDATE outbox SET delivered=1 WHERE sensor=? AND event_id=?", (sensor, event_id))
        return True
