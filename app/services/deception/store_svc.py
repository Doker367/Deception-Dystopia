"""NetPulse — Deception Telemetry Store.

Almacén append-only (SQLite WAL) de los eventos que generan los
atacantes sobre la red señuelo. Sigue el mismo patrón que
``app/services/audit_svc.py``: escrituras síncronas y ligeras, lecturas
filtradas/paginadas, y agregaciones para el dashboard.

Los eventos llegan ya normalizados (``DeceptionEventIn``) desde
cualquier motor: listeners nativos, engine en Go o honeypots reales
(Cowrie/OpenCanary) mediante la capa de integración.
"""

import json
import logging
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.core.settings import DECEPTION_DB
from app.models.deception import DeceptionEventIn

logger = logging.getLogger(__name__)

# Ruta del archivo SQLite (monkeypatch-able en tests)
DB_PATH = DECEPTION_DB

# Un solo writer a la vez en el proceso
_write_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS deception_events (
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
CREATE INDEX IF NOT EXISTS idx_deception_events_ts ON deception_events(ts);
CREATE INDEX IF NOT EXISTS idx_deception_events_dev ON deception_events(device_id);
CREATE INDEX IF NOT EXISTS idx_deception_events_src ON deception_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_deception_events_src_ts_id ON deception_events(src_ip, ts DESC, id DESC);
CREATE TABLE IF NOT EXISTS collector_offsets (
    engine TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    dev INTEGER NOT NULL DEFAULT -1,
    ino INTEGER NOT NULL DEFAULT -1,
    offset INTEGER NOT NULL DEFAULT 0,
    pending BLOB NOT NULL DEFAULT X'',
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS collector_heartbeat (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    started_at TEXT NOT NULL,
    last_poll_at TEXT NOT NULL,
    polls INTEGER NOT NULL,
    ingested INTEGER NOT NULL,
    interval REAL NOT NULL,
    status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS collector_dead_letters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engine TEXT NOT NULL,
    path TEXT NOT NULL,
    byte_offset INTEGER NOT NULL,
    raw TEXT NOT NULL,
    error TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def _dedupe_existing(conn: sqlite3.Connection) -> None:
    """Colapsa duplicados históricos antes de crear el índice único.

    Solo aplica a filas que ya traen ``source_event_id`` en su detalle; el
    resto (eventos nativos sin huella) se preserva intacto.
    """
    conn.execute(
        """DELETE FROM deception_events
           WHERE json_extract(detail, '$.source_event_id') IS NOT NULL
             AND id NOT IN (
                 SELECT MIN(id) FROM deception_events
                 WHERE json_extract(detail, '$.source_event_id') IS NOT NULL
                 GROUP BY json_extract(detail, '$.engine'),
                          json_extract(detail, '$.source_event_id')
             )"""
    )


def _ensure_db() -> None:
    """Crea el directorio/BD si no existen y aplica el esquema."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.executescript(_SCHEMA)
        index_exists = conn.execute(
            """SELECT 1 FROM sqlite_master
               WHERE type = 'index' AND name = 'idx_deception_events_source'"""
        ).fetchone()
        if not index_exists:
            _dedupe_existing(conn)
            # Índice único por (motor, huella del registro): el dedupe real
            # vive aquí, no en memoria, para sobrevivir a reinicios y resets
            # de offsets.
            conn.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS idx_deception_events_source
                   ON deception_events(
                       json_extract(detail, '$.engine'),
                       json_extract(detail, '$.source_event_id')
                   )
                   WHERE json_extract(detail, '$.source_event_id') IS NOT NULL"""
            )


def _connect() -> sqlite3.Connection:
    """Conexión corta (thread-safe por check_same_thread=False)."""
    return sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=10)


# ── Escritura ────────────────────────────────────────────────


def log_event(event: DeceptionEventIn) -> dict:
    """Inserta un evento de deception normalizado (append-only).

    Returns:
        El evento tal como quedó representado (dict).
    """
    ts = event.ts or datetime.now(timezone.utc).isoformat()
    detail_json = json.dumps(event.detail or {}, ensure_ascii=False)
    etype = event.type.value if hasattr(event.type, "value") else str(event.type)

    record = {
        "timestamp": ts,
        "device_id": event.device_id,
        "src_ip": event.src_ip,
        "src_port": event.src_port,
        "proto": event.proto,
        "type": etype,
        "username": event.username,
        "success": bool(event.success),
        "detail": event.detail or {},
    }

    try:
        _ensure_db()
        with _write_lock, sqlite3.connect(str(DB_PATH), timeout=10) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute(
                """INSERT INTO deception_events
                   (ts, device_id, src_ip, src_port, proto, event_type,
                    username, success, detail)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    ts, event.device_id, event.src_ip, event.src_port,
                    event.proto, etype, event.username,
                    1 if event.success else 0, detail_json,
                ),
            )
            record["id"] = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    except sqlite3.IntegrityError:
        # La huella ya existía (índice único por motor+source_event_id):
        # no es un error, es un duplicado idempotente.
        record["duplicate"] = True
        record["id"] = _existing_id(event)
    except Exception as exc:  # noqa: BLE001
        logger.error("[deception] fallo al escribir evento (%s): %s", etype, exc)
        record.setdefault("id", 0)

    return record


def _existing_id(event: DeceptionEventIn) -> int:
    """Id de un evento ya presente con el mismo (engine, source_event_id)."""
    detail = event.detail or {}
    engine = detail.get("engine")
    source_id = detail.get("source_event_id")
    if not engine or not source_id:
        return 0
    try:
        with sqlite3.connect(str(DB_PATH), timeout=10) as conn:
            row = conn.execute(
                """SELECT id FROM deception_events
                   WHERE json_extract(detail, '$.engine') = ?
                     AND json_extract(detail, '$.source_event_id') = ?
                   LIMIT 1""",
                (engine, source_id),
            ).fetchone()
        return int(row[0]) if row else 0
    except sqlite3.Error:
        return 0


def log_events_batch(events, offset_rows=None, heartbeat=None,
                     dead_letters=None) -> list[dict]:
    """Inserta un lote y persiste offsets/corazón en la MISMA transacción.

    Es la escritura que usa el colector: o entra todo el lote (eventos,
    offsets y heartbeat) o no entra nada. Así un fallo de SQLite nunca deja
    el offset por delante de los eventos ya confirmados.

    Args:
        events: iterable de ``DeceptionEventIn``.
        offset_rows: filas de ``collector_offsets`` (dict) o ``None``.
        heartbeat: dict con el estado del colector o ``None``.
        dead_letters: muestras de líneas irrecuperables (dict) o ``None``.

    Returns:
        Lista de dicts ``{"record": ..., "inserted": bool}`` en orden.
    """
    events = list(events)
    results: list[dict] = []
    _ensure_db()
    with _write_lock, sqlite3.connect(str(DB_PATH), timeout=10) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        try:
            conn.execute("BEGIN IMMEDIATE")
            for event in events:
                ts = event.ts or datetime.now(timezone.utc).isoformat()
                detail = event.detail or {}
                detail_json = json.dumps(detail, ensure_ascii=False)
                etype = event.type.value if hasattr(event.type, "value") else str(event.type)
                record = {
                    "timestamp": ts,
                    "device_id": event.device_id,
                    "src_ip": event.src_ip,
                    "src_port": event.src_port,
                    "proto": event.proto,
                    "type": etype,
                    "username": event.username,
                    "success": bool(event.success),
                    "detail": detail,
                }
                cur = conn.execute(
                    """INSERT OR IGNORE INTO deception_events
                       (ts, device_id, src_ip, src_port, proto, event_type,
                        username, success, detail)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        ts, event.device_id, event.src_ip, event.src_port,
                        event.proto, etype, event.username,
                        1 if event.success else 0, detail_json,
                    ),
                )
                inserted = cur.rowcount > 0
                if inserted:
                    record["id"] = cur.lastrowid
                else:
                    row = conn.execute(
                        """SELECT id FROM deception_events
                           WHERE json_extract(detail, '$.engine') = ?
                             AND json_extract(detail, '$.source_event_id') = ?
                           LIMIT 1""",
                        (detail.get("engine"), detail.get("source_event_id")),
                    ).fetchone()
                    record["id"] = int(row[0]) if row else 0
                    record["duplicate"] = True
                results.append({"record": record, "inserted": inserted})

            if offset_rows:
                conn.executemany(
                    """INSERT INTO collector_offsets
                           (engine, path, dev, ino, offset, pending, updated_at)
                       VALUES (?,?,?,?,?,?,?)
                       ON CONFLICT(engine) DO UPDATE SET
                           path=excluded.path, dev=excluded.dev,
                           ino=excluded.ino, offset=excluded.offset,
                           pending=excluded.pending, updated_at=excluded.updated_at""",
                    [
                        (row["engine"], row["path"], int(row.get("dev", -1)),
                         int(row.get("ino", -1)), int(row.get("offset", 0)),
                         row.get("pending", b"") or b"", row["updated_at"])
                        for row in offset_rows
                    ],
                )
            if heartbeat:
                conn.execute(
                    """INSERT INTO collector_heartbeat
                           (id, started_at, last_poll_at, polls, ingested,
                            interval, status)
                       VALUES (1,?,?,?,?,?,?)
                       ON CONFLICT(id) DO UPDATE SET
                           last_poll_at=excluded.last_poll_at,
                           polls=excluded.polls, ingested=excluded.ingested,
                           interval=excluded.interval, status=excluded.status""",
                    (
                        heartbeat["started_at"], heartbeat["last_poll_at"],
                        int(heartbeat.get("polls", 0)),
                        int(heartbeat.get("ingested", 0)),
                        float(heartbeat.get("interval", 30.0)),
                        heartbeat.get("status", "ok"),
                    ),
                )
            if dead_letters:
                conn.executemany(
                    """INSERT INTO collector_dead_letters
                           (engine, path, byte_offset, raw, error, created_at)
                       VALUES (?,?,?,?,?,?)""",
                    [
                        (row["engine"], row["path"],
                         int(row.get("byte_offset", 0)),
                         str(row.get("raw", ""))[:4096],
                         str(row.get("error", ""))[:512],
                         row["created_at"])
                        for row in dead_letters
                    ],
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return results


def get_collector_health(max_age_seconds: float = 90.0) -> dict:
    """Estado del colector según su heartbeat en SQLite (read-only)."""
    try:
        if not DB_PATH.exists():
            return {"status": "missing", "reason": "db_not_found"}
        with sqlite3.connect(str(DB_PATH), timeout=5) as conn:
            row = conn.execute(
                """SELECT last_poll_at, polls, ingested, interval, status
                   FROM collector_heartbeat WHERE id = 1"""
            ).fetchone()
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
    stale_after = max(float(max_age_seconds), float(interval) * 3)
    if age > stale_after:
        state = "stale"
    else:
        state = status or "ok"
    return {"status": state, "last_poll_at": last_poll, "age_seconds": round(age, 1),
            "polls": polls, "ingested": ingested, "interval": interval}


# ── Lectura ──────────────────────────────────────────────────


def _build_filters(
    device_id: Optional[str],
    src_ip: Optional[str],
    event_type: Optional[str],
) -> tuple[str, list]:
    where: list[str] = []
    params: list = []
    if device_id:
        where.append("device_id = ?")
        params.append(device_id)
    if src_ip:
        where.append("src_ip = ?")
        params.append(src_ip)
    if event_type:
        where.append("event_type = ?")
        params.append(event_type)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    return clause, params


def get_events(
    limit: int = 100,
    offset: int = 0,
    device_id: Optional[str] = None,
    src_ip: Optional[str] = None,
    event_type: Optional[str] = None,
) -> list[dict]:
    """Lista eventos (más recientes primero) con filtros y paginación."""
    if not DB_PATH.exists():
        return []

    clause, params = _build_filters(device_id, src_ip, event_type)
    sql = f"SELECT * FROM deception_events{clause} ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    try:
        with _write_lock:
            conn = _connect()
            try:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(sql, params).fetchall()
            finally:
                conn.close()
    except Exception as exc:  # noqa: BLE001
        logger.error("[deception] error leyendo eventos: %s", exc)
        return []

    return [_row_to_event(r) for r in rows]


def get_sessions(limit: int = 100) -> list[dict]:
    """Agrega eventos por (dispositivo, atacante) para la vista de sesiones."""
    if not DB_PATH.exists():
        return []

    sql = """
        SELECT device_id, src_ip,
               MAX(proto) AS proto,
               MIN(ts) AS started_at,
               MAX(ts) AS last_seen,
               COUNT(*) AS event_count,
               SUM(CASE WHEN event_type = 'command' THEN 1 ELSE 0 END) AS command_count,
               MAX(success) AS success
        FROM deception_events
        GROUP BY device_id, src_ip
        ORDER BY last_seen DESC
        LIMIT ?
    """
    try:
        with _write_lock:
            conn = _connect()
            try:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(sql, [limit]).fetchall()
            finally:
                conn.close()
    except Exception as exc:  # noqa: BLE001
        logger.error("[deception] error leyendo sesiones: %s", exc)
        return []

    return [
        {
            "device_id": r["device_id"],
            "src_ip": r["src_ip"],
            "proto": r["proto"] or "",
            "started_at": r["started_at"],
            "last_seen": r["last_seen"],
            "event_count": r["event_count"],
            "command_count": r["command_count"] or 0,
            "success": bool(r["success"]),
        }
        for r in rows
    ]


def get_stats() -> dict:
    """Resumen agregado para el dashboard."""
    if not DB_PATH.exists():
        return {
            "events_total": 0,
            "attackers_unique": 0,
            "by_type": {},
            "top_devices": [],
            "top_attackers": [],
        }

    stats: dict = {
        "events_total": 0,
        "attackers_unique": 0,
        "by_type": {},
        "top_devices": [],
        "top_attackers": [],
    }
    try:
        with _write_lock:
            conn = _connect()
            try:
                conn.row_factory = sqlite3.Row
                stats["events_total"] = conn.execute(
                    "SELECT COUNT(*) FROM deception_events"
                ).fetchone()[0]
                stats["attackers_unique"] = conn.execute(
                    "SELECT COUNT(DISTINCT src_ip) FROM deception_events"
                ).fetchone()[0]
                stats["by_type"] = {
                    r["event_type"]: r["n"]
                    for r in conn.execute(
                        "SELECT event_type, COUNT(*) AS n FROM deception_events "
                        "GROUP BY event_type ORDER BY n DESC"
                    ).fetchall()
                }
                stats["top_devices"] = [
                    {"device_id": r["device_id"], "count": r["n"]}
                    for r in conn.execute(
                        "SELECT device_id, COUNT(*) AS n FROM deception_events "
                        "GROUP BY device_id ORDER BY n DESC LIMIT 10"
                    ).fetchall()
                ]
                stats["top_attackers"] = [
                    {"src_ip": r["src_ip"], "count": r["n"]}
                    for r in conn.execute(
                        "SELECT src_ip, COUNT(*) AS n FROM deception_events "
                        "GROUP BY src_ip ORDER BY n DESC LIMIT 10"
                    ).fetchall()
                ]
            finally:
                conn.close()
    except Exception as exc:  # noqa: BLE001
        logger.error("[deception] stats error: %s", exc)

    return stats


def get_timeline(minutes: int = 30) -> list[dict]:
    """Serie de eventos por minuto (para el gráfico de actividad).

    Args:
        minutes: tamaño de la ventana en minutos.

    Returns:
        Lista ordenada de ``{"bucket": ISO-minuto, "count": n}``.
    """
    if not DB_PATH.exists():
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    buckets: dict[str, int] = {}
    try:
        with _write_lock:
            conn = _connect()
            try:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT ts FROM deception_events WHERE ts >= ? ORDER BY ts",
                    (cutoff.isoformat(),),
                ).fetchall()
            finally:
                conn.close()
    except Exception as exc:  # noqa: BLE001
        logger.error("[deception] timeline error: %s", exc)
        return []

    for row in rows:
        ts = _parse_iso(row["ts"])
        if ts is None:
            continue
        key = ts.replace(second=0, microsecond=0).isoformat()
        buckets[key] = buckets.get(key, 0) + 1
    return [{"bucket": k, "count": buckets[k]} for k in sorted(buckets)]


def events_to_csv(limit: int = 1000) -> str:
    """Exporta los eventos de deception a CSV."""
    import csv
    import io

    buffer = io.StringIO()
    headers = ["timestamp", "device_id", "src_ip", "src_port", "proto",
               "type", "username", "success", "detail"]
    writer = csv.DictWriter(buffer, fieldnames=headers, lineterminator="\n")
    writer.writeheader()
    for event in get_events(limit=limit):
        row = dict(event)
        row["detail"] = json.dumps(row.get("detail") or {}, ensure_ascii=False)
        writer.writerow({h: row.get(h, "") for h in headers})
    return buffer.getvalue()


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def retain(days: int = 90) -> int:
    """Borra eventos más antiguos que N días. Retorna cuántos eliminó."""
    if days <= 0:
        return 0
    try:
        _ensure_db()
        cutoff = datetime.fromtimestamp(
            datetime.now(timezone.utc).timestamp() - days * 86400, tz=timezone.utc
        ).isoformat()
        with _write_lock, sqlite3.connect(str(DB_PATH), timeout=10) as conn:
            cur = conn.execute("DELETE FROM deception_events WHERE ts < ?", (cutoff,))
            return cur.rowcount
    except Exception as exc:  # noqa: BLE001
        logger.error("[deception] retain error: %s", exc)
        return 0


# ── Helpers ──────────────────────────────────────────────────


def _row_to_event(row: sqlite3.Row) -> dict:
    """Convierte una fila SQLite al dict de evento de la API."""
    try:
        detail = json.loads(row["detail"] or "{}")
    except json.JSONDecodeError:
        detail = {}
    return {
        "id": row["id"],
        "timestamp": row["ts"],
        "device_id": row["device_id"],
        "src_ip": row["src_ip"],
        "src_port": row["src_port"],
        "proto": row["proto"] or "",
        "type": row["event_type"],
        "username": row["username"],
        "success": bool(row["success"]),
        "detail": detail,
    }
