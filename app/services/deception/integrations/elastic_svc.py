"""Bounded, idempotent Elasticsearch publisher for normalised events.

Disabled by default (``DYSTOPIA_ELASTIC_ENABLED`` is false). When enabled it
uses ``PUT /<index>/_create/<event.id>`` so replaying the same log line never
creates a second document. A queue row is removed only after a 2xx response,
or a 409 from ``create`` (the document already exists, i.e. the desired state
is already reached). Any other outcome leaves the event queued and is reported
as not delivered.

The optional queue is a private, bounded SQLite file using the same
``runtime.storage`` primitives as the telemetry spool. Without a queue path the
queue is bounded in memory. Queue-full is an explicit failure, never a silent
acknowledgement. Captured payloads/credentials are never logged.

Configuration (all disabled unless ``DYSTOPIA_ELASTIC_ENABLED=true``):
``DYSTOPIA_ELASTIC_URL``, ``_INDEX`` (default ``deception-events``),
``_API_KEY_FILE``, ``_CA_FILE``, ``_TIMEOUT``, ``_RETRIES``, ``_BACKOFF``,
``_MAX_BACKOFF``, ``_QUEUE``, ``_QUEUE_MAX``, ``_QUEUE_BYTES``, ``_BATCH``.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import sqlite3
import ssl
import threading
import time
from typing import Any, Callable, Mapping, Optional
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from runtime.localfiles import read_private
from runtime.storage import CapacityError, database

log = logging.getLogger(__name__)

INDEX_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,254}$")
PERMANENT_STATUSES = {400, 401, 403, 404, 405, 413, 422}
_SCHEMA = """
CREATE TABLE IF NOT EXISTS elastic_queue (
    event_id TEXT PRIMARY KEY,
    queued REAL NOT NULL,
    payload BLOB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    permanent INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS elastic_queue_order ON elastic_queue(permanent, queued);
"""


class PublisherDisabled(RuntimeError):
    """Raised instead of pretending an event was published while disabled."""


class DocumentConflict(ValueError):
    """Same event.id was queued with different content."""


@dataclass(frozen=True)
class ElasticsearchConfig:
    enabled: bool = False
    url: str = ""
    index: str = "deception-events"
    api_key_file: Optional[Path] = None
    ca_file: Optional[Path] = None
    timeout: float = 5.0
    max_retries: int = 3
    backoff: float = 0.5
    max_backoff: float = 30.0
    queue_path: Optional[Path] = None
    max_events: int = 10000
    max_bytes: int = 64 * 1024 * 1024
    batch_size: int = 200

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "ElasticsearchConfig":
        values = os.environ if env is None else env

        def flag(name: str, default: bool = False) -> bool:
            raw = values.get(name)
            if raw is None:
                return default
            return raw.strip().lower() in {"1", "true", "yes", "on"}

        def number(name: str, default, cast):
            raw = values.get(name)
            if raw in (None, ""):
                return default
            try:
                return cast(raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid {name}") from exc

        def path(name: str) -> Optional[Path]:
            raw = values.get(name, "").strip()
            return Path(raw) if raw else None

        return cls(
            enabled=flag("DYSTOPIA_ELASTIC_ENABLED", False),
            url=values.get("DYSTOPIA_ELASTIC_URL", "").strip(),
            index=values.get("DYSTOPIA_ELASTIC_INDEX", "deception-events").strip(),
            api_key_file=path("DYSTOPIA_ELASTIC_API_KEY_FILE"),
            ca_file=path("DYSTOPIA_ELASTIC_CA_FILE"),
            timeout=number("DYSTOPIA_ELASTIC_TIMEOUT", 5.0, float),
            max_retries=number("DYSTOPIA_ELASTIC_RETRIES", 3, int),
            backoff=number("DYSTOPIA_ELASTIC_BACKOFF", 0.5, float),
            max_backoff=number("DYSTOPIA_ELASTIC_MAX_BACKOFF", 30.0, float),
            queue_path=path("DYSTOPIA_ELASTIC_QUEUE"),
            max_events=number("DYSTOPIA_ELASTIC_QUEUE_MAX", 10000, int),
            max_bytes=number("DYSTOPIA_ELASTIC_QUEUE_BYTES", 64 * 1024 * 1024, int),
            batch_size=number("DYSTOPIA_ELASTIC_BATCH", 200, int),
        )

    def validate(self) -> "ElasticsearchConfig":
        """Fail closed on unsafe/ambiguous configuration; disabled is a no-op."""
        if not self.enabled:
            return self
        if not self.url:
            raise ValueError("elasticsearch URL required when enabled")
        parsed = urlsplit(self.url)
        if parsed.scheme not in {"https", "http"}:
            raise ValueError("unsupported elasticsearch URL scheme")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("elasticsearch URL must not contain credentials or query")
        if not parsed.hostname:
            raise ValueError("elasticsearch URL requires a host")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            raise ValueError("elasticsearch host must be a literal IP address") from None
        loopback = address.is_loopback
        if parsed.scheme == "http" and not loopback:
            raise ValueError("non-loopback elasticsearch requires TLS")
        if not loopback and self.api_key_file is None:
            raise ValueError("non-loopback elasticsearch requires an API key file")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("invalid elasticsearch port")
        if not INDEX_RE.fullmatch(self.index):
            raise ValueError("invalid elasticsearch index name")
        if not 0.1 <= self.timeout <= 60:
            raise ValueError("timeout out of range")
        if not 0 <= self.max_retries <= 20:
            raise ValueError("retries out of range")
        if not 0 <= self.backoff <= 60 or not 0 <= self.max_backoff <= 600:
            raise ValueError("backoff out of range")
        if not 1 <= self.max_events <= 1_000_000:
            raise ValueError("queue max events out of range")
        if not 1024 <= self.max_bytes <= 1024 * 1024 * 1024:
            raise ValueError("queue bytes out of range")
        if not 1 <= self.batch_size <= 1000:
            raise ValueError("batch size out of range")
        for label, value in (
            ("API key", self.api_key_file), ("CA", self.ca_file),
        ):
            if value is not None and not value.is_file():
                raise FileNotFoundError(f"{label} file does not exist")
        return self


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _HttpTransport:
    """Small stdlib client; no proxy environment, redirects, or URL userinfo."""

    def __init__(self, config: ElasticsearchConfig):
        self.base = config.url.rstrip("/")
        self.index_name = config.index
        self._api_key = None
        if config.api_key_file is not None:
            data = read_private(config.api_key_file, max_bytes=1024).strip()
            if not data or b"\n" in data or b"\r" in data:
                raise ValueError("invalid elasticsearch API key file")
            key = data.decode("ascii")
            if key.lower().startswith("apikey "):
                key = key[7:].strip()
            if not key:
                raise ValueError("invalid elasticsearch API key file")
            self._api_key = key
        context = ssl.create_default_context(
            cafile=str(config.ca_file) if config.ca_file is not None else None
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = build_opener(
            ProxyHandler({}), HTTPSHandler(context=context), _NoRedirect()
        )

    def index(self, event_id: str, document: dict, timeout: float) -> int:
        # ``_create`` is the explicit-id write accepted by both data streams
        # (deception-events) and regular indices. It never overwrites an
        # existing document; a duplicate returns 409.
        url = (
            f"{self.base}/{quote(self.index_name, safe='')}/_create/"
            f"{quote(event_id, safe='')}?refresh=false"
        )
        body = json.dumps(
            document, ensure_ascii=True, separators=(",", ":"), allow_nan=False
        ).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._api_key:
            headers["Authorization"] = "ApiKey " + self._api_key
        request = Request(url, data=body, method="PUT", headers=headers)
        try:
            with self.opener.open(request, timeout=timeout) as response:
                response.read(1024)
                return response.status
        except HTTPError as exc:
            try:
                exc.read(1024)
            finally:
                exc.close()
            return exc.code


class ElasticPublisher:
    """Queue + publisher. ``publish`` returns True only for confirmed delivery."""

    def __init__(
        self,
        config: Optional[ElasticsearchConfig] = None,
        *,
        transport: Any = None,
        sleep: Callable[[float], Any] = time.sleep,
        clock: Callable[[], float] = time.time,
    ):
        self.config = (config or ElasticsearchConfig.from_env()).validate()
        self.enabled = self.config.enabled
        self._transport = transport
        if self.enabled and self._transport is None:
            self._transport = _HttpTransport(self.config)
        self._sleep, self._clock = sleep, clock
        self._lock = threading.RLock()
        self._memory: dict[str, dict[str, Any]] = {}
        self._memory_bytes = 0
        self._counters = {
            "acked": 0, "duplicates": 0, "errors": 0, "discarded": 0,
            "retries": 0, "conflicts": 0, "permanent_failures": 0,
        }
        if self.enabled and self.config.queue_path is not None:
            self.config.queue_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with self._db() as db:
                db.executescript(_SCHEMA)

    @contextmanager
    def _db(self):
        if self.config.queue_path is None:
            raise RuntimeError("in-memory queue has no database")
        cap = max(8 * 1024 * 1024, self.config.max_bytes * 2)
        with database(self.config.queue_path, cap) as db:
            yield db

    def _database(self) -> bool:
        return self.enabled and self.config.queue_path is not None

    def _count(self, name: str, amount: int = 1) -> None:
        self._counters[name] = self._counters.get(name, 0) + amount

    @staticmethod
    def _serialize(document: Any) -> tuple[str, bytes]:
        if not isinstance(document, dict):
            raise ValueError("event document must be an object")
        event = document.get("event")
        if (
            not isinstance(event, Mapping)
            or not isinstance(event.get("id"), str)
            or not event["id"]
        ):
            raise ValueError("event.id is required for idempotent indexing")
        if len(event["id"]) > 512:
            raise ValueError("event.id too long")
        try:
            payload = json.dumps(
                document, sort_keys=True, ensure_ascii=True,
                separators=(",", ":"), allow_nan=False,
            ).encode()
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("event document is not JSON-serialisable") from exc
        return event["id"], payload

    def enqueue(self, document: dict) -> bool:
        """Persist/queue an event. Returns False when it was already queued."""
        if not self.enabled:
            raise PublisherDisabled("elasticsearch publisher is disabled")
        event_id, payload = self._serialize(document)
        with self._lock:
            if self._database():
                try:
                    with self._db() as db:
                        db.execute("BEGIN IMMEDIATE")
                        prior = db.execute(
                            "SELECT payload FROM elastic_queue WHERE event_id=?", (event_id,)
                        ).fetchone()
                        if prior:
                            if prior[0] != payload:
                                self._count("conflicts")
                                raise DocumentConflict(
                                    "event.id reused with different content"
                                )
                            db.execute("COMMIT")
                            return False
                        count, used = db.execute(
                            "SELECT COUNT(*),COALESCE(SUM(length(payload)),0) "
                            "FROM elastic_queue"
                        ).fetchone()
                        if (count >= self.config.max_events
                                or used + len(payload) > self.config.max_bytes):
                            log.error(
                                "elastic_queue_full queued=%d bytes=%d", count, used
                            )
                            raise CapacityError("elastic queue full")
                        db.execute(
                            "INSERT INTO elastic_queue(event_id,queued,payload) VALUES(?,?,?)",
                            (event_id, self._clock(), payload),
                        )
                        db.execute("COMMIT")
                except DocumentConflict:
                    raise
                except CapacityError:
                    self._count("discarded")
                    log.error("elastic_queue_capacity_exhausted")
                    raise
                except (sqlite3.Error, OSError) as exc:
                    self._count("discarded")
                    log.error("elastic_queue_unavailable")
                    raise CapacityError("elastic queue unavailable") from exc
                return True
            prior = self._memory.get(event_id)
            if prior:
                if prior["payload"] != payload:
                    self._count("conflicts")
                    raise DocumentConflict("event.id reused with different content")
                return False
            used = self._memory_bytes
            if (
                len(self._memory) >= self.config.max_events
                or used + len(payload) > self.config.max_bytes
            ):
                self._count("discarded")
                log.error("elastic_queue_full queued=%d bytes=%d", len(self._memory), used)
                raise CapacityError("elastic queue full")
            self._memory[event_id] = {
                "queued": self._clock(), "payload": payload, "attempts": 0,
                "permanent": 0, "last_error": "",
            }
            self._memory_bytes += len(payload)
            return True

    def publish(self, document: dict) -> bool:
        """Queue then attempt delivery. True only after 2xx (or existing 409)."""
        if not self.enabled:
            raise PublisherDisabled("elasticsearch publisher is disabled")
        self.enqueue(document)
        return self.flush_event(document["event"]["id"])

    def publish_many(self, documents: list[dict]) -> int:
        if not self.enabled:
            raise PublisherDisabled("elasticsearch publisher is disabled")
        for document in documents:
            self.enqueue(document)
        remaining, delivered = len(documents), 0
        while remaining > 0:
            confirmed = self.flush(limit=min(remaining, self.config.batch_size))
            if confirmed == 0:
                break
            delivered += confirmed
            remaining -= confirmed
        return delivered

    def flush(self, limit: Optional[int] = None) -> int:
        """Deliver up to ``limit`` pending rows; returns confirmed count."""
        if not self.enabled:
            raise PublisherDisabled("elasticsearch publisher is disabled")
        maximum = (
            self.config.batch_size if limit is None
            else max(0, min(limit, self.config.batch_size))
        )
        delivered = 0
        try:
            pending = self._pending(maximum)
        except (sqlite3.Error, OSError, CapacityError):
            self._count("errors")
            log.error("elastic_queue_read_failed")
            return 0
        for event_id, document, attempts in pending:
            if self._deliver(event_id, document, attempts):
                delivered += 1
        return delivered

    def flush_event(self, event_id: str) -> bool:
        if not self.enabled:
            raise PublisherDisabled("elasticsearch publisher is disabled")
        row = self._get(event_id)
        if row is None:
            return False
        return self._deliver(*row)

    def _pending(self, limit: int) -> list[tuple[str, dict, int]]:
        if limit <= 0:
            return []
        if self._database():
            with self._db() as db:
                rows = db.execute(
                    "SELECT event_id,payload,attempts FROM elastic_queue "
                    "WHERE permanent=0 ORDER BY queued LIMIT ?", (limit,),
                ).fetchall()
        else:
            with self._lock:
                rows = [
                    (key, value["payload"], value["attempts"])
                    for key, value in sorted(
                        self._memory.items(), key=lambda item: item[1]["queued"]
                    )
                    if not value["permanent"]
                ][:limit]
        result = []
        for event_id, payload, attempts in rows:
            try:
                document = json.loads(payload)
                if not isinstance(document, dict):
                    raise ValueError("queued document is not an object")
            except (TypeError, ValueError, UnicodeError):
                self._quarantine(event_id, attempts + 1, "corrupt queued document")
                continue
            result.append((event_id, document, attempts))
        return result

    def _get(self, event_id: str) -> Optional[tuple[str, dict, int]]:
        if self._database():
            with self._db() as db:
                row = db.execute(
                    "SELECT payload,attempts,permanent FROM elastic_queue WHERE event_id=?",
                    (event_id,),
                ).fetchone()
            if row is None or row[2]:
                return None
            try:
                document = json.loads(row[0])
            except (TypeError, ValueError, UnicodeError):
                self._quarantine(event_id, row[1] + 1, "corrupt queued document")
                return None
            return event_id, document, row[1]
        with self._lock:
            value = self._memory.get(event_id)
            if value is None or value["permanent"]:
                return None
            try:
                document = json.loads(value["payload"])
            except (TypeError, ValueError, UnicodeError):
                self._quarantine(event_id, value["attempts"] + 1, "corrupt queued document")
                return None
            return event_id, document, value["attempts"]

    def _deliver(self, event_id: str, document: dict, attempts: int) -> bool:
        attempt = 0
        error = "unknown"
        while True:
            try:
                status = int(self._transport.index(
                    event_id, document, timeout=self.config.timeout
                ))
            except Exception as exc:  # noqa: BLE001 - transport errors are retryable
                error = type(exc).__name__
                self._count("errors")
            else:
                if 200 <= status < 300:
                    self._count("acked")
                    self._remove(event_id)
                    return True
                if status == 409:
                    # op_type=create already has this id; desired state reached.
                    self._count("duplicates")
                    self._remove(event_id)
                    return True
                if status in PERMANENT_STATUSES or (status < 500 and status not in {408, 429}):
                    self._count("errors")
                    self._count("permanent_failures")
                    self._mark_failure(event_id, attempts + attempt + 1, 1, f"HTTP {status}")
                    log.error("elastic_rejected event_id=%s status=%d", event_id, status)
                    return False
                error = f"HTTP {status}"
                self._count("errors")
            if attempt >= self.config.max_retries:
                self._mark_failure(event_id, attempts + attempt + 1, 0, error)
                log.warning(
                    "elastic_delivery_deferred event_id=%s error=%s",
                    event_id, error,
                )
                return False
            self._count("retries")
            delay = min(self.config.max_backoff, self.config.backoff * (2 ** attempt))
            if delay > 0:
                self._sleep(delay)
            attempt += 1

    def _mark_failure(self, event_id: str, attempts: int, permanent: int, error: str) -> None:
        safe_error = error[:64]
        if self._database():
            with self._db() as db:
                db.execute(
                    "UPDATE elastic_queue SET attempts=?,permanent=?,last_error=? WHERE event_id=?",
                    (attempts, permanent, safe_error, event_id),
                )
        else:
            with self._lock:
                value = self._memory.get(event_id)
                if value is not None:
                    value["attempts"] = attempts
                    value["permanent"] = permanent
                    value["last_error"] = safe_error

    def _quarantine(self, event_id: str, attempts: int, error: str) -> None:
        self._count("errors")
        self._count("permanent_failures")
        self._mark_failure(event_id, attempts, 1, error)
        log.error("elastic_queue_entry_quarantined event_id=%s", event_id)

    def _remove(self, event_id: str) -> None:
        if self._database():
            with self._db() as db:
                db.execute("DELETE FROM elastic_queue WHERE event_id=?", (event_id,))
        else:
            with self._lock:
                value = self._memory.pop(event_id, None)
                if value is not None:
                    self._memory_bytes -= len(value["payload"])

    def health(self) -> dict:
        if not self.enabled:
            return {
                "enabled": False, "queued": 0, "queued_bytes": 0, "lag_seconds": 0,
                "permanent": 0, "operator_action_required": False,
                **{f"{key}_since_start": value for key, value in self._counters.items()},
            }
        try:
            if self._database():
                with self._db() as db:
                    count, used, oldest = db.execute(
                        "SELECT COUNT(*),COALESCE(SUM(length(payload)),0),"
                        "MIN(CASE WHEN permanent=0 THEN queued END) FROM elastic_queue"
                    ).fetchone()
                    permanent = db.execute(
                        "SELECT COUNT(*) FROM elastic_queue WHERE permanent=1"
                    ).fetchone()[0]
            else:
                with self._lock:
                    count, used = len(self._memory), self._memory_bytes
                    oldest = min(
                        (v["queued"] for v in self._memory.values() if not v["permanent"]),
                        default=None,
                    )
                    permanent = sum(1 for v in self._memory.values() if v["permanent"])
        except Exception:  # noqa: BLE001 - diagnostics must not crash the caller
            log.error("elastic_queue_health_unavailable")
            return {"enabled": True, "error": "queue unavailable"}
        return {
            "enabled": True,
            "index": self.config.index,
            "queued": count,
            "queued_bytes": used,
            "lag_seconds": max(0, self._clock() - oldest) if oldest else 0,
            "permanent": permanent,
            "operator_action_required": permanent > 0,
            "queue_persistent": self._database(),
            **{f"{key}_since_start": value for key, value in self._counters.items()},
        }
