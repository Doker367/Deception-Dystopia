"""Incremental, bounded exporter: runtime EventStore -> ECS -> Elasticsearch.

The standalone sensor writes v1 events to the ingest service, which persists
them in ``runtime.storage.EventStore``.  Nothing in that path is changed here:
this exporter opens the events database **read-only**, reads a bounded window
after a durable cursor, normalizes each row with ``native_svc`` and hands the
document to the existing idempotent ``ElasticPublisher``.

Delivery contract
-----------------
* The Elasticsearch publisher is opt-in and disabled by default.
* The cursor advances only after a document is durably enqueued in the
  publisher's private SQLite queue.  If Elasticsearch is down the event is
  safe in that queue and the operational ingestion path is untouched.
* A crash between enqueue and cursor commit replays the same ``event.id``;
  ``PUT /_create/<id>`` answers 409 and no duplicate document is created.
* The cursor database and the publisher queue are private SQLite files using
  ``runtime.storage.database`` (0600, single link).  Nothing is deleted from
  the events store.
* The cursor follows the ingest-assigned ``received_epoch`` (the column the
  ingest service already orders by).  A backwards wall-clock step is the one
  case that could leave older rows unread until an operator intervenes; normal
  NTP-synchronised operation is assumed, as elsewhere in the ingest service.
* One exporter per state file is expected.  Concurrent instances would only
  replay the same ``event.id`` (safe, deduplicated by ``_create``).

This module deliberately does not import the sensor runtime: only the central
exporter depends on ``app`` and on topology metadata.
"""

from contextlib import contextmanager
import grp
import json
import logging
import os
from pathlib import Path
import sqlite3
import stat
import time
from typing import Any, Mapping, Optional
from urllib.parse import quote

from runtime.storage import CapacityError, database

from . import native_svc
from .elastic_svc import DocumentConflict, PublisherDisabled
from .metadata import topology_metadata

log = logging.getLogger(__name__)

DEFAULT_BATCH = 200
MAX_BATCH = 1000
STREAM = "runtime-v1"
_STATE_BYTES = 8 * 1024 * 1024
_STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS export_cursor (
    stream TEXT PRIMARY KEY,
    received_epoch REAL NOT NULL,
    sensor TEXT NOT NULL,
    event_id TEXT NOT NULL,
    updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS export_counters (
    name TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
"""


@contextmanager
def _events_readonly(path: Path):
    """Open the ingest EventStore read-only and enforce its file policy.

    ``runtime.storage.database`` opens files read/write and applies PRAGMAs;
    an exporter must never mutate the ingest database, so this mirror checks
    the same permission boundary (0600, or 0640 for the dedicated query group)
    and then opens a ``mode=ro`` connection.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PermissionError("event database must be a regular single-link file")
        group = os.getenv("DYSTOPIA_QUERY_GROUP")
        read_gid = grp.getgrnam(group).gr_gid if group else None
        mode = stat.S_IMODE(info.st_mode)
        private = mode == 0o600
        query_read = (
            read_gid is not None and info.st_gid == read_gid and mode == 0o640
        )
        if read_gid is not None and info.st_uid != os.geteuid():
            raise PermissionError("event database owner must be the ingest service")
        if not (private or query_read):
            raise PermissionError(
                "event database permissions differ from the configured private policy"
            )
    finally:
        os.close(fd)

    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=2, isolation_level=None)
    try:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA busy_timeout=2000")
        yield conn
    finally:
        conn.close()


class NativeExporter:
    """Bounded reader/normalizer/publisher for persisted runtime v1 events."""

    def __init__(
        self,
        events_path: Any,
        state_path: Any,
        *,
        publisher: Any = None,
        resolver: Any = None,
        batch_size: int = DEFAULT_BATCH,
        stream: str = STREAM,
        clock=time.time,
    ):
        self.events_path = Path(events_path)
        self.state_path = Path(state_path)
        self.publisher = publisher
        self.resolver = resolver if resolver is not None else topology_metadata()
        self.stream = stream
        self._clock = clock
        if not isinstance(batch_size, int) or not 1 <= batch_size <= MAX_BATCH:
            raise ValueError("batch size out of range")
        self.batch_size = batch_size

        if self.events_path.resolve() == self.state_path.resolve():
            raise ValueError("export state must not be the events database")

        queue_path = getattr(getattr(publisher, "config", None), "queue_path", None)
        if queue_path is not None and Path(queue_path).resolve() in {
            self.events_path.resolve(),
            self.state_path.resolve(),
        }:
            raise ValueError("elastic queue must be a separate private database")

    @property
    def enabled(self) -> bool:
        return self.publisher is not None and bool(
            getattr(self.publisher, "enabled", False)
        )

    def _require_durable_queue(self) -> None:
        queue_path = getattr(getattr(self.publisher, "config", None), "queue_path", None)
        if queue_path is None:
            # A memory-only queue cannot survive a restart; advancing the
            # cursor would turn a transient Elasticsearch outage into loss.
            raise ValueError(
                "a persistent elastic queue is required for cursor advancement"
            )

    def _ensure_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with database(self.state_path, _STATE_BYTES) as db:
            db.executescript(_STATE_SCHEMA)

    def _cursor(self) -> tuple[float, str, str]:
        with database(self.state_path, _STATE_BYTES) as db:
            row = db.execute(
                "SELECT received_epoch,sensor,event_id FROM export_cursor WHERE stream=?",
                (self.stream,),
            ).fetchone()
        return (row[0], row[1], row[2]) if row else (-1.0, "", "")

    def _rows(self, limit: int) -> list[tuple]:
        epoch, sensor, event_id = self._cursor()
        with _events_readonly(self.events_path) as db:
            return db.execute(
                """
                SELECT received_epoch, sensor, event_id, received_at, payload
                FROM events
                WHERE received_epoch > ?
                   OR (received_epoch = ? AND sensor > ?)
                   OR (received_epoch = ? AND sensor = ? AND event_id > ?)
                ORDER BY received_epoch, sensor, event_id
                LIMIT ?
                """,
                (epoch, epoch, sensor, epoch, sensor, event_id, limit),
            ).fetchall()

    def _save(self, cursor: Optional[tuple[float, str, str]], counts: Mapping[str, int]) -> None:
        now = self._clock()
        with database(self.state_path, _STATE_BYTES) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if cursor is not None:
                    db.execute(
                        "INSERT INTO export_cursor(stream,received_epoch,sensor,event_id,updated) "
                        "VALUES(?,?,?,?,?) ON CONFLICT(stream) DO UPDATE SET "
                        "received_epoch=excluded.received_epoch, sensor=excluded.sensor, "
                        "event_id=excluded.event_id, updated=excluded.updated",
                        (self.stream, cursor[0], cursor[1], cursor[2], now),
                    )
                for name, amount in counts.items():
                    if amount:
                        db.execute(
                            "INSERT INTO export_counters(name,value) VALUES(?,?) "
                            "ON CONFLICT(name) DO UPDATE SET value=value+excluded.value",
                            (name, int(amount)),
                        )
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise

    def run_once(self, limit: Optional[int] = None) -> dict:
        """Process at most one bounded window; never raises for Elastic errors."""
        if not self.enabled:
            return {
                "enabled": False,
                "read": 0,
                "enqueued": 0,
                "duplicates": 0,
                "conflicts": 0,
                "delivered": 0,
                "skipped": 0,
                "stopped": "disabled",
            }
        self._require_durable_queue()
        self._ensure_state()

        maximum = self.batch_size if limit is None else max(0, min(int(limit), MAX_BATCH))
        if maximum == 0:
            return {
                "enabled": True, "read": 0, "enqueued": 0, "duplicates": 0,
                "conflicts": 0, "delivered": 0, "skipped": 0,
                "stopped": "empty_batch",
            }

        start = self._cursor()
        last: Optional[tuple[float, str, str]] = None
        counts = {
            "events_read": 0, "events_enqueued": 0, "event_duplicates": 0,
            "events_skipped": 0, "enqueue_failures": 0, "document_conflicts": 0,
            "delivered": 0,
        }
        stopped: Optional[str] = None

        for received_epoch, sensor, event_id, received_at, payload in self._rows(maximum):
            counts["events_read"] += 1
            try:
                raw = json.loads(payload)
                document = native_svc.normalize(
                    raw,
                    resolver=self.resolver,
                    sensor=sensor,
                    fallback_timestamp=received_at,
                    raw_reference={"source": "runtime-v1", "offset": event_id},
                )
            except (TypeError, ValueError, UnicodeError):
                document = None
            if document is None:
                # The row stays in the EventStore; only the exporter skips it.
                counts["events_skipped"] += 1
                log.error(
                    "native_export_invalid_record sensor=%s event_id=%s", sensor, event_id
                )
                last = (received_epoch, sensor, event_id)
                continue

            try:
                enqueued = self.publisher.enqueue(document)
            except DocumentConflict:
                # The queue already holds this same event.id with different
                # enrichment (e.g. topology/GeoIP changed while Elasticsearch
                # was down).  ``event.id`` is derived only from sensor +
                # persisted event_id, so the queued row is the same logical
                # event: keep the queued version, do not block the stream and
                # do not create a second document.
                counts["document_conflicts"] += 1
                log.warning(
                    "native_export_document_conflict sensor=%s event_id=%s",
                    sensor, event_id,
                )
                last = (received_epoch, sensor, event_id)
                continue
            except PublisherDisabled:
                stopped = "publisher_disabled"
                log.error("native_export_publisher_disabled")
                break
            except (CapacityError, sqlite3.Error, OSError):
                counts["enqueue_failures"] += 1
                log.error(
                    "native_export_enqueue_failed sensor=%s event_id=%s",
                    sensor, event_id,
                )
                stopped = "queue_unavailable"
                break

            counts["events_enqueued" if enqueued else "event_duplicates"] += 1
            last = (received_epoch, sensor, event_id)

        if stopped != "publisher_disabled":
            try:
                counts["delivered"] = self.publisher.flush(limit=maximum)
            except PublisherDisabled:
                stopped = "publisher_disabled"
            except Exception:  # noqa: BLE001 - delivery is best effort here
                log.error("native_export_flush_failed")

        if last is not None or counts["delivered"]:
            self._save(last, counts)

        cursor = last if last is not None else start
        return {
            "enabled": True,
            "read": counts["events_read"],
            "enqueued": counts["events_enqueued"],
            "duplicates": counts["event_duplicates"],
            "conflicts": counts["document_conflicts"],
            "delivered": counts["delivered"],
            "skipped": counts["events_skipped"],
            "stopped": stopped,
            "cursor": (
                {
                    "received_epoch": cursor[0],
                    "sensor": cursor[1],
                    "event_id": cursor[2],
                }
                if cursor[0] >= 0
                else None
            ),
            "publisher": self.publisher.health() if hasattr(self.publisher, "health") else None,
        }
