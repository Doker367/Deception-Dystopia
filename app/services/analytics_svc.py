"""Read-only analytics over Dystopia's local SQLite event stores.

The browser never receives the database path or credentials. This service
supports both local event schemas used in the laboratory:

- ``events``: the runtime v1 store written by the independent ingest service
  (sensor, device, observed_at, kind, source, payload).
- ``deception_events``: the control-plane store used by the native engine and
  the simulator.

By default both schemas are read from the control-plane SQLite file
(``DECEPTION_DB`` in ``app.core.settings``), i.e. the exact same file written
by ``app.services.deception.store_svc``. The ``DYSTOPIA_ANALYTICS_DB``
environment variable is an optional override for advanced deployments (for
example, a read replica or a pre-built analytics snapshot). Leave it unset so
the BFF always follows the live control-plane store and never ends up pointing
at a second, divergent database.

Elasticsearch is not part of this path. GeoIP is local (MaxMind/GeoLite2); no
external lookup service is used.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Mapping, Optional

from app.core.settings import DECEPTION_DB
from app.services.deception import geoip_svc

MAX_WINDOW = timedelta(days=90)
DEFAULT_MAX_ROWS = 20_000
INTERVALS = {"1m": 60, "5m": 300, "15m": 900, "30m": 1800, "1h": 3600, "3h": 10800, "6h": 21600, "12h": 43200, "1d": 86400, "7d": 604800}
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _collector_health(db_path: Path) -> dict[str, Any]:
    """Estado del colector según su heartbeat, sin abrir la BD en escritura."""
    path = Path(db_path)
    if not path.exists():
        return {"status": "missing", "reason": "db_not_found"}
    try:
        conn = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=2)
        try:
            row = conn.execute(
                """SELECT last_poll_at, polls, ingested, interval, status
                   FROM collector_heartbeat WHERE id = 1"""
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return {"status": "missing", "reason": "no_heartbeat"}
    if not row:
        return {"status": "missing", "reason": "no_heartbeat"}
    last_poll, polls, ingested, interval, status = row
    try:
        age = (datetime.now(timezone.utc)
               - datetime.fromisoformat(str(last_poll).replace("Z", "+00:00"))
               ).total_seconds()
    except ValueError:
        age = float("inf")
    stale_after = max(90.0, float(interval or 30.0) * 3)
    return {
        "status": "stale" if age > stale_after else (status or "ok"),
        "last_poll_at": last_poll,
        "age_seconds": round(age, 1),
        "polls": polls,
        "ingested": ingested,
        "interval": interval,
    }
KIND_SEVERITY = {
    "login_success": "critical",
    "file_download": "critical",
    "command": "high",
    "port_scan": "high",
    "login_attempt": "medium",
    "http_request": "medium",
    "other": "medium",
    "connect": "low",
    "disconnect": "info",
}
KIND_ACTION = {
    "connect": "Conexión",
    "disconnect": "Desconexión",
    "login_attempt": "Intento de acceso",
    "login_success": "Acceso exitoso",
    "command": "Comando ejecutado",
    "file_download": "Descarga de archivo",
    "port_scan": "Escaneo de puertos",
    "http_request": "Petición HTTP",
    "other": "Evento",
}


class AnalyticsError(RuntimeError):
    """Base class for safe analytics failures."""


class AnalyticsDisabled(AnalyticsError):
    """Compatibility error retained for the router contract."""


class AnalyticsUnavailable(AnalyticsError):
    """The local event store could not be read."""


@dataclass(frozen=True)
class AnalyticsConfig:
    db_path: Path = DECEPTION_DB
    max_rows: int = DEFAULT_MAX_ROWS
    max_window_days: int = 90

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "AnalyticsConfig":
        """Build the config from the environment.

        ``DYSTOPIA_ANALYTICS_DB`` is only an optional override; when it is
        unset (or empty) the path falls back to ``DECEPTION_DB`` from
        ``app.core.settings``, the single source of truth shared with
        ``store_svc``.
        """
        values = os.environ if env is None else env
        raw_path = values.get("DYSTOPIA_ANALYTICS_DB", "").strip()
        raw_rows = values.get("DYSTOPIA_ANALYTICS_MAX_ROWS", "").strip()
        try:
            max_rows = int(raw_rows) if raw_rows else DEFAULT_MAX_ROWS
        except ValueError as exc:
            raise ValueError("invalid DYSTOPIA_ANALYTICS_MAX_ROWS") from exc
        if not 100 <= max_rows <= 200_000:
            raise ValueError("DYSTOPIA_ANALYTICS_MAX_ROWS out of range")
        return cls(db_path=Path(raw_path) if raw_path else DECEPTION_DB, max_rows=max_rows)

    def validate(self) -> "AnalyticsConfig":
        if not self.db_path.is_absolute():
            return self
        return self

    @property
    def resolved_db_path(self) -> Path:
        """Absolute, normalised path of the SQLite store actually read."""
        return self.db_path.expanduser().resolve()

    @property
    def db_exists(self) -> bool:
        """Whether the resolved SQLite store exists on disk."""
        return self.resolved_db_path.is_file()


@dataclass
class EventRecord:
    id: str
    timestamp: str
    sensor: str
    device: str
    source: str
    country: str
    countryCode: str
    region: str
    regionCode: str
    city: str
    lat: Optional[float]
    lng: Optional[float]
    kind: str
    proto: str
    port: Optional[int]
    action: str
    severity: str
    message: str
    detail: dict[str, Any] = field(default_factory=dict)


def _parse_time(value: str | None, fallback: datetime) -> datetime:
    if not value:
        return fallback
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed.astimezone(timezone.utc)


def _window(from_time: str | None, to_time: str | None) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    end = _parse_time(to_time, now)
    start = _parse_time(from_time, end - timedelta(hours=24))
    if start > end:
        raise ValueError("from must be before to")
    if end - start > MAX_WINDOW:
        raise ValueError("window exceeds 90 days")
    return start, end


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _severity(kind: str) -> str:
    return KIND_SEVERITY.get(kind, "info")


def _action(kind: str) -> str:
    return KIND_ACTION.get(kind, kind.replace("_", " ").capitalize())


def _json_object(raw: Any) -> dict[str, Any]:
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            return {}
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _coord(value: Any, limit: float) -> Optional[float]:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if -limit <= number <= limit else None


def _lat(value: Any) -> Optional[float]:
    return _coord(value, 90)


def _lon(value: Any) -> Optional[float]:
    return _coord(value, 180)


class AnalyticsService:
    def __init__(self, config: AnalyticsConfig | None = None):
        self.config = (config or AnalyticsConfig.from_env()).validate()
        self._geo_cache: dict[str, Optional[dict]] = {}

    def _geo(self, ip: str) -> Optional[dict]:
        if ip not in self._geo_cache:
            try:
                self._geo_cache[ip] = geoip_svc.lookup(ip)
            except Exception:  # noqa: BLE001
                self._geo_cache[ip] = None
        return self._geo_cache[ip]

    def _connect(self) -> Optional[sqlite3.Connection]:
        path = self.config.resolved_db_path
        if not path.is_file():
            return None
        try:
            conn = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=2)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            conn.execute("PRAGMA temp_store=MEMORY")
            return conn
        except (OSError, sqlite3.Error) as exc:
            raise AnalyticsUnavailable("local event store unavailable") from exc

    def _schema(self, conn: sqlite3.Connection) -> str:
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        # La BD del control plane puede contener ambas tablas (runtime v1 y la
        # nativa). El colector escribe en ``deception_events``; si existe, esa
        # es la fuente de verdad para no leer una tabla ``events`` obsoleta.
        if "deception_events" in tables:
            return "control"
        if "events" in tables:
            return "runtime"
        return "none"

    def _rows(self, start: datetime, end: datetime) -> list[EventRecord]:
        conn = self._connect()
        if conn is None:
            return []
        try:
            schema = self._schema(conn)
            if schema == "runtime":
                raw_rows = conn.execute(
                    """SELECT sensor, event_id, device, observed_at, kind, source, payload
                       FROM events WHERE observed_at >= ? AND observed_at <= ?
                       ORDER BY observed_at DESC LIMIT ?""",
                    (_iso(start), _iso(end), self.config.max_rows),
                ).fetchall()
                return [record for row in raw_rows if (record := self._runtime_record(row)) is not None]
            if schema == "control":
                raw_rows = conn.execute(
                    """SELECT id, ts, device_id, src_ip, src_port, proto, event_type,
                              username, success, detail
                       FROM deception_events WHERE ts >= ? AND ts <= ?
                       ORDER BY ts DESC LIMIT ?""",
                    (_iso(start), _iso(end), self.config.max_rows),
                ).fetchall()
                return [record for row in raw_rows if (record := self._control_record(row)) is not None]
            return []
        except sqlite3.Error as exc:
            raise AnalyticsUnavailable("local event store query failed") from exc
        finally:
            conn.close()

    def _runtime_record(self, row: sqlite3.Row) -> Optional[EventRecord]:
        payload = _json_object(row["payload"])
        source = str(payload.get("src_ip") or row["source"] or "")
        kind = str(payload.get("type") or row["kind"] or "other")
        detail = _json_object(payload.get("detail"))
        geo = self._geo(source) or {}
        return EventRecord(
            id=str(payload.get("event_id") or row["event_id"] or ""),
            timestamp=str(row["observed_at"] or ""),
            sensor=str(row["sensor"] or ""),
            device=str(row["device"] or ""),
            source=source,
            country=str(geo.get("country") or ""),
            countryCode=str(geo.get("country_code") or ""),
            region=str(geo.get("subdivision") or ""),
            regionCode=str(geo.get("subdivision_code") or ""),
            city=str(geo.get("city") or ""),
            lat=_lat(geo.get("lat")),
            lng=_lon(geo.get("lon")),
            kind=kind,
            proto=str(payload.get("proto") or "tcp"),
            port=int(payload["src_port"]) if isinstance(payload.get("src_port"), int) else None,
            action=_action(kind),
            severity=_severity(kind),
            message=str(detail.get("message") or detail.get("eventid") or _action(kind)),
            detail=detail,
        )

    def _control_record(self, row: sqlite3.Row) -> Optional[EventRecord]:
        detail = _json_object(row["detail"])
        if row["username"] is not None:
            detail["username"] = str(row["username"])
        if row["success"] is not None:
            detail["success"] = bool(row["success"])
        source = str(row["src_ip"] or "")
        kind = str(row["event_type"] or "other")
        geo = self._geo(source) or {}
        sensor = str(detail.get("engine") or detail.get("sensor") or row["device_id"] or "")
        return EventRecord(
            id=f"evt_{row['id']}",
            timestamp=str(row["ts"] or ""),
            sensor=sensor,
            device=str(row["device_id"] or ""),
            source=source,
            country=str(geo.get("country") or ""),
            countryCode=str(geo.get("country_code") or ""),
            region=str(geo.get("subdivision") or ""),
            regionCode=str(geo.get("subdivision_code") or ""),
            city=str(geo.get("city") or ""),
            lat=_lat(geo.get("lat")),
            lng=_lon(geo.get("lon")),
            kind=kind,
            proto=str(row["proto"] or ""),
            port=int(row["src_port"]) if row["src_port"] is not None else None,
            action=_action(kind),
            severity=_severity(kind),
            message=str(detail.get("message") or detail.get("command") or _action(kind)),
            detail=detail,
        )

    def overview(self, from_time: str | None, to_time: str | None) -> dict[str, Any]:
        start, end = _window(from_time, to_time)
        rows = self._rows(start, end)
        sources = {row.source for row in rows if row.source}
        protocols = Counter(row.proto or "tcp" for row in rows)
        sensors = Counter(row.sensor or "unknown" for row in rows)
        max_severity = max((row.severity for row in rows), key=lambda value: SEVERITY_ORDER.get(value, 0), default="info")
        return {
            "window": {"from": _iso(start), "to": _iso(end)},
            "total_events": len(rows),
            "unique_sources": len(sources),
            "alerts": sum(1 for row in rows if row.severity == "critical"),
            "max_severity": max_severity,
            "latest_event": rows[0].timestamp if rows else None,
            "protocols": [{"name": name, "value": value} for name, value in protocols.most_common(10)],
            "datasets": [{"name": name, "value": value} for name, value in sensors.most_common(10)],
        }

    def timeline(self, from_time: str | None, to_time: str | None, interval: str = "1h") -> dict[str, Any]:
        if interval not in INTERVALS:
            raise ValueError("unsupported interval")
        start, end = _window(from_time, to_time)
        step = INTERVALS[interval]
        rows = self._rows(start, end)
        counts: Counter[int] = Counter()
        for row in rows:
            try:
                observed = datetime.fromisoformat(row.timestamp.replace("Z", "+00:00"))
            except ValueError:
                continue
            counts[int(observed.timestamp()) // step * step] += 1
        first = int(start.timestamp()) // step * step
        last = int(end.timestamp()) // step * step
        buckets = []
        for stamp in range(first, last + step, step):
            at = datetime.fromtimestamp(stamp, timezone.utc)
            buckets.append({"at": _iso(at), "count": counts.get(stamp, 0)})
        return {"interval": interval, "buckets": buckets}

    def origins(self, from_time: str | None, to_time: str | None, limit: int = 50) -> dict[str, Any]:
        start, end = _window(from_time, to_time)
        rows = self._rows(start, end)
        groups: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"events": 0, "sources": set(), "protocols": Counter(), "sensors": Counter(), "severity": "info", "last": ""}
        )
        for row in rows:
            if not row.countryCode or row.lat is None or row.lng is None:
                continue
            # Un origen es país + subdivisión (estado/provincia) cuando GeoIP la
            # conoce. En EE. UU. esto permite pintar solo el estado afectado en
            # lugar de teñir todo el país.
            key = f"{row.countryCode}|{row.regionCode or ''}"
            group = groups[key]
            group["countryCode"] = row.countryCode
            group["region"] = group.get("region") or row.region
            group["regionCode"] = group.get("regionCode") or row.regionCode
            group["country"] = row.country or row.countryCode
            group["city"] = group.get("city") or row.city
            group["ip"] = group.get("ip") or row.source
            group["lat"] = group.get("lat") if group.get("lat") is not None else row.lat
            group["lng"] = group.get("lng") if group.get("lng") is not None else row.lng
            group["events"] += 1
            group["sources"].add(row.source)
            group["protocols"][row.proto or "tcp"] += 1
            group["sensors"][row.sensor or "unknown"] += 1
            if SEVERITY_ORDER.get(row.severity, 0) > SEVERITY_ORDER.get(group["severity"], 0):
                group["severity"] = row.severity
            if row.timestamp > group["last"]:
                group["last"] = row.timestamp
        result = []
        for group in groups.values():
            result.append({
                "countryCode": group.get("countryCode") or "",
                "country": group.get("country") or group.get("countryCode") or "",
                "region": group.get("region") or "",
                "regionCode": group.get("regionCode") or "",
                "city": group.get("city") or "",
                "ip": group.get("ip") or "",
                "lat": group.get("lat"),
                "lng": group.get("lng"),
                "events": group["events"],
                "uniqueSources": len(group["sources"]),
                "severity": group["severity"],
                "protocol": group["protocols"].most_common(1)[0][0] if group["protocols"] else "",
                "sensor": group["sensors"].most_common(1)[0][0] if group["sensors"] else "",
                "lastEvent": group["last"] or None,
            })
        result.sort(key=lambda item: item["events"], reverse=True)
        return {"origins": result[: max(1, min(limit, 100))]}

    def events(
        self,
        from_time: str | None,
        to_time: str | None,
        *,
        limit: int = 25,
        offset: int = 0,
        query_text: str = "",
        severity: str = "",
        sensor: str = "",
        protocol: str = "",
    ) -> dict[str, Any]:
        start, end = _window(from_time, to_time)
        rows = self._rows(start, end)
        query = query_text.strip().lower()
        filtered = []
        for row in rows:
            if severity and row.severity != severity:
                continue
            if sensor and row.sensor != sensor:
                continue
            if protocol and row.proto != protocol:
                continue
            if query and query not in " ".join(
                [row.id, row.source, row.country, row.sensor, row.device, row.kind, row.action, row.proto, row.message]
            ).lower():
                continue
            filtered.append(row)
        page = filtered[offset: offset + max(1, min(limit, 100))]
        return {
            "total": len(filtered),
            "items": [
                {
                    "id": row.id,
                    "timestamp": row.timestamp,
                    "sensor": row.sensor,
                    "device": row.device,
                    "source": row.source,
                    "country": row.country,
                    "countryCode": row.countryCode,
                    "kind": row.kind,
                    "proto": row.proto,
                    "port": row.port,
                    "action": row.action,
                    "severity": row.severity,
                    "message": row.message,
                }
                for row in page
            ],
        }

    def _source_rows(self, source: str, start: datetime, end: datetime) -> list[EventRecord]:
        """Query the indexed source directly rather than losing older IPs to the global cap."""
        conn = self._connect()
        if conn is None:
            return []
        try:
            schema = self._schema(conn)
            if schema == "runtime":
                raw = conn.execute(
                    "SELECT sensor,event_id,device,observed_at,kind,source,payload FROM events "
                    "WHERE source=? AND observed_at>=? AND observed_at<=? ORDER BY observed_at DESC LIMIT ?",
                    (source, _iso(start), _iso(end), self.config.max_rows),
                ).fetchall()
                return [record for row in raw if (record := self._runtime_record(row)) is not None and record.source == source]
            if schema == "control":
                raw = conn.execute(
                    "SELECT id,ts,device_id,src_ip,src_port,proto,event_type,username,success,detail "
                    "FROM deception_events WHERE src_ip=? AND ts>=? AND ts<=? ORDER BY ts DESC, id DESC LIMIT ?",
                    (source, _iso(start), _iso(end), self.config.max_rows),
                ).fetchall()
                return [record for row in raw if (record := self._control_record(row)) is not None]
            return []
        except sqlite3.Error as exc:
            raise AnalyticsUnavailable("source event query failed") from exc
        finally:
            conn.close()

    def attacker_timeline(self, source: str, interval: str = "1h") -> dict[str, Any]:
        """Group at most max_rows source timestamps into nonempty UTC buckets."""
        end = datetime.now(timezone.utc)
        start = end - MAX_WINDOW
        conn = self._connect()
        stamps: list[str] = []
        if conn is not None:
            try:
                schema = self._schema(conn)
                if schema in ("runtime", "control"):
                    table, column, stamp = (("events", "source", "observed_at") if schema == "runtime"
                                            else ("deception_events", "src_ip", "ts"))
                    stamps = [row[0] for row in conn.execute(
                        f"SELECT {stamp} FROM {table} WHERE {column}=? AND {stamp}>=? AND {stamp}<=? "
                        f"ORDER BY {stamp} DESC LIMIT ?",
                        (source, _iso(start), _iso(end), self.config.max_rows),
                    )]
            except sqlite3.Error as exc:
                raise AnalyticsUnavailable("source timeline query failed") from exc
            finally:
                conn.close()
        times = []
        for stamp in stamps:
            try:
                times.append(_parse_time(stamp, end))
            except (ValueError, TypeError, AttributeError):
                continue
        def grouped(step: int) -> Counter[int]:
            return Counter(int(time.timestamp()) // step * step for time in times)

        counts = grouped(INTERVALS[interval])
        if len(counts) > 100:
            interval = "1d"
            counts = grouped(INTERVALS[interval])
        return {"source": source, "interval": interval,
                "buckets": [{"at": _iso(datetime.fromtimestamp(at, timezone.utc)), "count": count}
                            for at, count in sorted(counts.items())],
                "total": len(stamps), "scanned_limit": self.config.max_rows}

    def search_attackers(self, query: str, limit: int = 20) -> dict[str, Any]:
        """Sample at most max_rows indexed prefix matches before sorting activity."""
        end = datetime.now(timezone.utc)
        start = end - MAX_WINDOW
        conn = self._connect()
        if conn is None:
            return {"items": [], "scanned_limit": self.config.max_rows}
        try:
            schema = self._schema(conn)
            if schema not in ("runtime", "control"):
                return {"items": [], "scanned_limit": self.config.max_rows}
            table, column, stamp = (("events", "source", "observed_at") if schema == "runtime"
                                    else ("deception_events", "src_ip", "ts"))
            rows = conn.execute(
                f"SELECT origin, COUNT(*) AS events, MAX(seen) AS last_seen FROM ("
                f"SELECT {column} AS origin, {stamp} AS seen FROM {table} "
                f"WHERE {column}>=? AND {column}<? AND {stamp}>=? AND {stamp}<=? "
                "LIMIT ?) "
                "GROUP BY origin ORDER BY last_seen DESC, origin LIMIT ?",
                (query, query + ";", _iso(start), _iso(end), self.config.max_rows, limit),
            ).fetchall()
            return {"items": [{"source": row[0], "events": row[1], "last_seen": row[2]}
                              for row in rows], "scanned_limit": self.config.max_rows}
        except sqlite3.Error as exc:
            raise AnalyticsUnavailable("source search query failed") from exc
        finally:
            conn.close()

    @staticmethod
    def _evidence_item(row: EventRecord) -> dict[str, Any]:
        return {"id": row.id, "timestamp": row.timestamp, "sensor": row.sensor,
                "device": row.device, "kind": row.kind, "action": row.action,
                "proto": row.proto, "port": row.port, "severity": row.severity,
                "message": row.message, "detail": row.detail}

    def export_attacker(self, source: str, limit: int = 5000) -> dict[str, Any]:
        """Export the same bounded, normalized 90-day sample as the IP profile."""
        end = datetime.now(timezone.utc)
        start = end - MAX_WINDOW
        rows = self._source_rows(source, start, end)
        items = [self._evidence_item(row) for row in rows[:min(limit, self.config.max_rows)]]
        return {"source": source, "exported_at": _iso(end),
                "window": {"from": _iso(start), "to": _iso(end)},
                "total": len(rows), "exported": len(items),
                "truncated": len(items) < len(rows), "items": items}

    def _control_attacker(self, conn: sqlite3.Connection, source: str, start: datetime,
                          end: datetime, offset: int, limit: int,
                          include_summary: bool = True) -> dict[str, Any]:
        """Page indexed evidence in SQL; aggregate only the bounded IP sample."""
        window = (source, _iso(start), _iso(end))
        cap = self.config.max_rows
        total = conn.execute(
            "SELECT COUNT(*) FROM (SELECT 1 FROM deception_events "
            "WHERE src_ip=? AND ts>=? AND ts<=? ORDER BY ts DESC, id DESC LIMIT ?)",
            (*window, cap),
        ).fetchone()[0]
        result: dict[str, Any] = {"source": source, "total": total,
                                  "window": {"from": _iso(start), "to": _iso(end)},
                                  "scanned_limit": cap}
        if not total:
            return {**result, "items": []}
        # id breaks timestamp ties, preventing duplicates between adjacent pages.
        page_size = min(max(limit, 1), 100, max(0, cap - offset))
        raw = conn.execute(
            "SELECT id,ts,device_id,src_ip,src_port,proto,event_type,username,success,detail "
            "FROM deception_events WHERE src_ip=? AND ts>=? AND ts<=? "
            "ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
            (*window, page_size, max(0, offset)),
        ).fetchall() if page_size else []
        page = [record for row in raw if (record := self._control_record(row)) is not None]
        if not include_summary:
            return {**result, "items": [self._evidence_item(row) for row in page]}
        # Grouping runs inside SQLite; never transfer/normalize all 20k raw events
        # again when the browser asks for another 50 items.
        groups = conn.execute(
            """WITH sample AS MATERIALIZED (
                   SELECT device_id,proto,event_type,detail FROM deception_events
                   WHERE src_ip=? AND ts>=? AND ts<=?
                   ORDER BY ts DESC, id DESC LIMIT ?
               ), labels AS (
                   SELECT 'protocols' AS category, COALESCE(proto, '') AS value FROM sample
                   UNION ALL SELECT 'devices', COALESCE(device_id, '') FROM sample
                   UNION ALL SELECT 'kinds', COALESCE(NULLIF(event_type, ''), 'other') FROM sample
                   UNION ALL SELECT 'sensors', COALESCE(
                       NULLIF(CAST(json_extract(CASE WHEN json_valid(detail) THEN detail ELSE '{}' END, '$.engine') AS TEXT), ''),
                       NULLIF(CAST(json_extract(CASE WHEN json_valid(detail) THEN detail ELSE '{}' END, '$.sensor') AS TEXT), ''),
                       device_id, '') FROM sample
               ) SELECT category,value,COUNT(*) FROM labels
                 WHERE value<>'' GROUP BY category,value""",
            (*window, cap),
        ).fetchall()
        counts: dict[str, dict[str, int]] = {key: {} for key in ("protocols", "sensors", "kinds", "devices")}
        for category, value, count in groups:
            counts[category][value] = count
        last = conn.execute(
            "SELECT ts FROM deception_events WHERE src_ip=? AND ts>=? AND ts<=? "
            "ORDER BY ts DESC, id DESC LIMIT 1 OFFSET ?", (*window, total - 1),
        ).fetchone()
        first = conn.execute(
            "SELECT ts FROM deception_events WHERE src_ip=? AND ts>=? AND ts<=? "
            "ORDER BY ts DESC, id DESC LIMIT 1", window,
        ).fetchone()
        geo = self._geo(source) or {}
        return {**result, "first_seen": str(last[0] or ""), "last_seen": str(first[0] or ""),
                "country": str(geo.get("country") or ""), "countryCode": str(geo.get("country_code") or ""),
                "city": str(geo.get("city") or ""), "lat": _lat(geo.get("lat")), "lng": _lon(geo.get("lon")),
                **counts, "items": [self._evidence_item(row) for row in page]}

    def attacker(self, source: str, offset: int = 0, limit: int = 50,
                 include_summary: bool = True) -> dict[str, Any]:
        """Bounded 90-day profile from normalized evidence, not inferred identity."""
        end = datetime.now(timezone.utc)
        start = end - MAX_WINDOW
        conn = self._connect()
        if conn is not None:
            try:
                if self._schema(conn) == "control":
                    return self._control_attacker(conn, source, start, end, offset, limit, include_summary)
            except sqlite3.Error as exc:
                raise AnalyticsUnavailable("source event query failed") from exc
            finally:
                conn.close()
        rows = self._source_rows(source, start, end)
        if not rows:
            return {"source": source, "total": 0, "items": [], "window": {"from": _iso(start), "to": _iso(end)},
                    "scanned_limit": self.config.max_rows}
        protocols = Counter(row.proto for row in rows if row.proto)
        sensors = Counter(row.sensor for row in rows if row.sensor)
        kinds = Counter(row.kind for row in rows if row.kind)
        devices = Counter(row.device for row in rows if row.device)
        geo = next((row for row in rows if row.country or row.city), rows[0])
        return {
            "source": source, "total": len(rows), "first_seen": rows[-1].timestamp,
            "last_seen": rows[0].timestamp, "country": geo.country, "countryCode": geo.countryCode,
            "city": geo.city, "lat": geo.lat, "lng": geo.lng,
            "protocols": dict(protocols), "sensors": dict(sensors), "kinds": dict(kinds),
            "devices": dict(devices), "window": {"from": _iso(start), "to": _iso(end)},
            "scanned_limit": self.config.max_rows,
            "items": [self._evidence_item(row) for row in rows[offset:offset + limit]],
        }

    def health(self) -> dict[str, Any]:
        db_path = self.config.resolved_db_path
        db_exists = self.config.db_exists
        collector = _collector_health(db_path)
        conn = self._connect()
        if conn is None:
            return {
                "status": "empty",
                "store": "sqlite",
                "documents": 0,
                "schema": "none",
                "db": str(db_path),
                "db_exists": db_exists,
                "collector": collector,
            }
        try:
            schema = self._schema(conn)
            table = "events" if schema == "runtime" else "deception_events" if schema == "control" else None
            documents = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) if table else 0
            return {
                "status": "healthy" if schema != "none" else "empty",
                "store": "sqlite",
                "schema": schema,
                "documents": documents,
                "db": str(db_path),
                "db_exists": db_exists,
                "collector": collector,
                "geoip": geoip_svc.available(),
            }
        finally:
            conn.close()


_service: AnalyticsService | None = None


def service() -> AnalyticsService:
    global _service
    if _service is None:
        _service = AnalyticsService()
    return _service


def reset_service() -> None:
    """Test helper: drop the cached service after changing configuration."""
    global _service
    _service = None
