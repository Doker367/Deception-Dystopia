"""Sensor-only spool + authenticated HTTPS transport; no app imports.

Adapters call submit(). Legacy listeners are intentionally NOT imported: they
still depend on administrative configuration and must be ported before use.
"""
import json
import logging
from pathlib import Path
import random
import sqlite3
import ssl
import time
from ipaddress import ip_address
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler, HTTPRedirectHandler

from runtime.contracts import MAX_BATCH_BYTES, MAX_BATCH_EVENTS, encode, validate_event
from runtime.storage import CapacityError, database

log = logging.getLogger(__name__)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # never send sensor credentials to another URL


class Transport:
    def __init__(self, endpoint, ca_file, token_file):
        url = urlsplit(endpoint)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path != "/v1/events":
            raise ValueError("an exact HTTPS ingestion endpoint is required")
        ip_address(url.hostname)  # explicitly provisioned address; no DNS/rebinding/proxy
        self.endpoint, self.token_file = endpoint, Path(token_file)
        context = ssl.create_default_context(cafile=str(ca_file))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())

    def send(self, events):
        from runtime.localfiles import read_private
        token = read_private(self.token_file).decode().strip()
        if not token or len(token) > 128 or "\n" in token or "\r" in token:
            raise ValueError("invalid sensor token file")
        raw = encode({"version": 1, "events": events})
        request = Request(self.endpoint, data=raw, method="POST",
                          headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        with self.opener.open(request, timeout=5) as response:
            if response.status != 200:
                raise ConnectionError("ingestion did not acknowledge")
            result = json.loads(response.read(4096))
            if result.get("version") != 1 or result.get("accepted", -1) + result.get("duplicates", -1) != len(events):
                raise ConnectionError("invalid acknowledgement")


class Spool:
    def __init__(self, path, max_events=10000, max_bytes=64*1024*1024,
                 max_quarantine_events=None, max_quarantine_bytes=None):
        self.path = Path(path)
        self.max_events, self.max_bytes = max_events, max_bytes
        # Quarantine is a separate, bounded budget: a stale assignment or a
        # revoked credential must not consume the live spool and stop the
        # sensor.  When its own bound is reached, the oldest quarantined rows
        # are dead-lettered (counted, payload no longer retained) explicitly.
        self.max_quarantine_events = max(1, min(
            int(max_events // 5 if max_quarantine_events is None else max_quarantine_events),
            max_events))
        self.max_quarantine_bytes = max(1, min(
            int(max_bytes // 8 if max_quarantine_bytes is None else max_quarantine_bytes),
            max_bytes))
        self.failures, self.discarded, self.disconnected = 0, 0, False
        self.storage_exhausted = False
        self.next_retry = 0.0
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS queue(event_id TEXT PRIMARY KEY, queued REAL NOT NULL, payload BLOB NOT NULL, quarantined INTEGER NOT NULL DEFAULT 0, quarantined_at REAL NOT NULL DEFAULT 0)")
            columns = {row[1] for row in db.execute("PRAGMA table_info(queue)")}
            if "quarantined" not in columns:
                db.execute("ALTER TABLE queue ADD COLUMN quarantined INTEGER NOT NULL DEFAULT 0")
            if "quarantined_at" not in columns:
                db.execute("ALTER TABLE queue ADD COLUMN quarantined_at REAL NOT NULL DEFAULT 0")
            db.execute("CREATE INDEX IF NOT EXISTS queue_live_order ON queue(quarantined, queued)")
            db.execute("CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL)")

    def connect(self):
        return database(self.path, self.max_bytes)

    def submit(self, event):
        event = validate_event(event)
        payload = encode(event)
        try:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                prior = db.execute("SELECT payload FROM queue WHERE event_id=?", (event["event_id"],)).fetchone()
                if prior:
                    if prior[0] != payload:
                        raise ValueError("conflicting event ID")
                    db.execute("COMMIT")
                    return
                # Only live rows count against the live budget.  Quarantined
                # rows live in the same table but have their own bound below.
                count, used = db.execute(
                    "SELECT COUNT(*),COALESCE(SUM(length(payload)),0) "
                    "FROM queue WHERE quarantined=0").fetchone()
                if count >= self.max_events or used + len(payload) > self.max_bytes // 2:
                    raise CapacityError("sensor spool full")
                db.execute("INSERT INTO queue(event_id,queued,payload) VALUES(?,?,?)", (event["event_id"], time.time(), payload))
                db.execute("COMMIT")
        except (sqlite3.Error, OSError, CapacityError) as exc:
            self.discarded += 1
            self.storage_exhausted = True
            try:
                with self.connect() as db:
                    db.execute("INSERT INTO counters VALUES('discarded',1) ON CONFLICT(name) DO UPDATE SET value=value+1")
            except (sqlite3.Error, OSError, CapacityError):
                pass
            log.error("sensor_spool_capacity_exhausted discarded_since_start=%d", self.discarded)
            # Reject-new; producer must pause or explicitly account for the lost event.
            raise CapacityError("sensor spool rejected event; producer must pause") from exc

    def _enforce_quarantine_budget(self, db):
        """Dead-letter the oldest quarantined rows until the bound is met."""
        count, used = db.execute(
            "SELECT COUNT(*),COALESCE(SUM(length(payload)),0) "
            "FROM queue WHERE quarantined=1").fetchone()
        evicted = 0
        while count > self.max_quarantine_events or used > self.max_quarantine_bytes:
            row = db.execute(
                "SELECT event_id,length(payload) FROM queue WHERE quarantined=1 "
                "ORDER BY quarantined_at,queued LIMIT 1").fetchone()
            if row is None:
                break
            db.execute("DELETE FROM queue WHERE event_id=?", (row[0],))
            count -= 1
            used -= row[1]
            evicted += 1
        if evicted:
            # The captured payload is gone; the count is retained so the
            # operator sees an explicit, auditable loss instead of a stall.
            db.execute(
                "INSERT INTO counters VALUES('dead_lettered',?) "
                "ON CONFLICT(name) DO UPDATE SET value=value+?", (evicted, evicted))
        return evicted

    def _quarantine(self, ids, status):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = time.time()
            db.executemany(
                "UPDATE queue SET quarantined=1,quarantined_at=? "
                "WHERE event_id=? AND quarantined=0",
                [(now, key) for key in ids])
            evicted = self._enforce_quarantine_budget(db)
            db.execute("COMMIT")
        log.error(
            "sensor_batch_quarantined status=%d events=%d dead_lettered=%d "
            "operator_action_required=true",
            status, len(ids), evicted)
        return evicted

    def flush_once(self, transport):
        if time.monotonic() < self.next_retry:
            return False
        with self.connect() as db:
            rows = db.execute("SELECT event_id,payload FROM queue WHERE quarantined=0 ORDER BY queued LIMIT ?", (MAX_BATCH_EVENTS,)).fetchall()
        events, ids = [], []
        for key, payload in rows:
            event = json.loads(payload)
            if len(encode({"version": 1, "events": events + [event]})) > MAX_BATCH_BYTES:
                break
            events.append(event)
            ids.append(key)
        if not events:
            return False
        try:
            transport.send(events)
        except Exception as exc:
            if isinstance(exc, HTTPError) and exc.code in {403, 409, 413, 422}:
                # Permanent rejects move to the bounded quarantine budget.
                # They never block later valid batches or the live spool.
                self._quarantine(ids, exc.code)
                return False
            self.failures = min(1000000, self.failures + 1)
            self.disconnected = True
            self.next_retry = time.monotonic() + min(300, 2 ** min(self.failures, 8)) + random.uniform(0, 1)
            log.warning("sensor_ingestion_disconnected retries=%d", self.failures)
            return False
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.executemany("DELETE FROM queue WHERE event_id=?", [(key,) for key in ids])
            db.execute("COMMIT")
        self.failures, self.disconnected, self.next_retry = 0, False, 0
        self.storage_exhausted = False
        return True

    def quarantine_records(self, limit=None):
        """Decoded quarantined events for operator review/export; never sends."""
        with self.connect() as db:
            sql = ("SELECT payload FROM queue WHERE quarantined=1 "
                   "ORDER BY quarantined_at,queued")
            params = ()
            if limit is not None:
                sql += " LIMIT ?"
                params = (max(0, int(limit)),)
            rows = db.execute(sql, params).fetchall()
        return [json.loads(payload) for payload, in rows]

    def export_quarantine(self, output, limit=None):
        """Durably export quarantined events as JSON lines without deleting them."""
        records = self.quarantine_records(limit)
        from runtime.localfiles import replace_private
        replace_private(output, b"".join(encode(event) + b"\n" for event in records))
        return len(records)

    def drain_quarantine(self, output, limit=None):
        """Export quarantined events durably, then delete only the exported rows."""
        with self.connect() as db:
            sql = ("SELECT event_id,payload FROM queue WHERE quarantined=1 "
                   "ORDER BY quarantined_at,queued")
            params = ()
            if limit is not None:
                sql += " LIMIT ?"
                params = (max(0, int(limit)),)
            rows = db.execute(sql, params).fetchall()
        records = [json.loads(payload) for _, payload in rows]
        from runtime.localfiles import replace_private
        replace_private(output, b"".join(encode(event) + b"\n" for event in records))
        ids = [event_id for event_id, _ in rows]
        if ids:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                db.executemany("DELETE FROM queue WHERE event_id=?", [(key,) for key in ids])
                db.execute("COMMIT")
        return len(ids)

    def purge_quarantine(self):
        """Explicit operator deletion; returns the number of rows removed."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            count = db.execute("SELECT COUNT(*) FROM queue WHERE quarantined=1").fetchone()[0]
            db.execute("DELETE FROM queue WHERE quarantined=1")
            if count:
                db.execute(
                    "INSERT INTO counters VALUES('purged',?) "
                    "ON CONFLICT(name) DO UPDATE SET value=value+?", (count, count))
            db.execute("COMMIT")
        return count

    def health(self):
        with self.connect() as db:
            count, used = db.execute(
                "SELECT COUNT(*),COALESCE(SUM(length(payload)),0) FROM queue").fetchone()
            pending, pending_bytes, oldest = db.execute(
                "SELECT COUNT(*),COALESCE(SUM(length(payload)),0),MIN(queued) "
                "FROM queue WHERE quarantined=0").fetchone()
            quarantined, quarantine_bytes = db.execute(
                "SELECT COUNT(*),COALESCE(SUM(length(payload)),0) "
                "FROM queue WHERE quarantined=1").fetchone()
            dropped = db.execute("SELECT value FROM counters WHERE name='discarded'").fetchone()
            dead_lettered = db.execute("SELECT value FROM counters WHERE name='dead_lettered'").fetchone()
            purged = db.execute("SELECT value FROM counters WHERE name='purged'").fetchone()
        return {"queued": count, "pending": pending, "live": pending,
                "payload_bytes": used, "pending_bytes": pending_bytes,
                "quarantined": quarantined,
                "quarantine_bytes": quarantine_bytes,
                "quarantine_capacity": self.max_quarantine_events,
                "quarantine_capacity_bytes": self.max_quarantine_bytes,
                "operator_action_required": quarantined > 0,
                "oldest_seconds": max(0, time.time() - oldest) if oldest else 0,
                "discarded_persisted": dropped[0] if dropped else 0,
                "dead_lettered_persisted": dead_lettered[0] if dead_lettered else 0,
                "purged_persisted": purged[0] if purged else 0,
                "discarded_since_start": self.discarded, "disconnected": self.disconnected,
                "storage_exhausted": self.storage_exhausted
                or pending >= self.max_events or pending_bytes >= self.max_bytes//2,
                "retry_in_seconds": max(0, self.next_retry - time.monotonic())}
