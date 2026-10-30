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
    def __init__(self, path, max_events=10000, max_bytes=64*1024*1024):
        self.path = Path(path)
        self.max_events, self.max_bytes = max_events, max_bytes
        self.failures, self.discarded, self.disconnected = 0, 0, False
        self.storage_exhausted = False
        self.next_retry = 0.0
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS queue(event_id TEXT PRIMARY KEY, queued REAL NOT NULL, payload BLOB NOT NULL, quarantined INTEGER NOT NULL DEFAULT 0)")
            if "quarantined" not in {row[1] for row in db.execute("PRAGMA table_info(queue)")}:
                db.execute("ALTER TABLE queue ADD COLUMN quarantined INTEGER NOT NULL DEFAULT 0")
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
                count, used = db.execute("SELECT COUNT(*),COALESCE(SUM(length(payload)),0) FROM queue").fetchone()
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
                # Permanent rejects are retained in the SAME bounded disk budget.
                # Do not let one stale assignment block all later valid batches.
                with self.connect() as db:
                    db.execute("BEGIN IMMEDIATE")
                    db.executemany("UPDATE queue SET quarantined=1 WHERE event_id=?", [(key,) for key in ids])
                    db.execute("COMMIT")
                log.error("sensor_batch_quarantined status=%d events=%d operator_action_required=true", exc.code, len(ids))
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

    def health(self):
        with self.connect() as db:
            count, used, oldest = db.execute("SELECT COUNT(*),COALESCE(SUM(length(payload)),0),MIN(queued) FROM queue").fetchone()
            dropped = db.execute("SELECT value FROM counters WHERE name='discarded'").fetchone()
            quarantined = db.execute("SELECT COUNT(*) FROM queue WHERE quarantined=1").fetchone()[0]
        return {"queued": count, "payload_bytes": used, "quarantined": quarantined,
                "operator_action_required": quarantined > 0,
                "oldest_seconds": max(0, time.time() - oldest) if oldest else 0,
                "discarded_persisted": dropped[0] if dropped else 0,
                "discarded_since_start": self.discarded, "disconnected": self.disconnected,
                "storage_exhausted": self.storage_exhausted or count >= self.max_events or used >= self.max_bytes//2,
                "retry_in_seconds": max(0, self.next_retry - time.monotonic())}
