"""Read-only v1 metadata query service; Unix peer identity is its sole credential.

No sensor/admin secrets or raw payloads cross this boundary. Production starts
from a systemd-owned socket fd; this module never binds a network interface.
"""
import base64
import hmac
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import sqlite3
import stat
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from uuid import UUID

VERSION = 1
MAX_REQUEST = 4096
MAX_RESPONSE = 512 * 1024
MAX_ROWS = 500
MAX_WINDOW = 7 * 86400
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
TYPES = frozenset(("connect", "disconnect", "login_attempt", "login_success", "command", "file_download", "port_scan", "other"))
PROTO = frozenset(("tcp", "udp", "ssh", "telnet", "http", "ftp", "mysql", "snmp"))
FIELDS = ("sensor", "event_id", "device", "received_at", "observed_at", "kind", "source", "proto")


class QueryFailure(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _frame(sock, data):
    payload = json.dumps(data, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    if len(payload) > MAX_RESPONSE:
        raise QueryFailure("LIMIT")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def _receive(sock, limit):
    def exact(length):
        buf = bytearray()
        while len(buf) < length:
            chunk = sock.recv(length - len(buf))
            if not chunk:
                raise QueryFailure("INVALID")
            buf.extend(chunk)
        return bytes(buf)
    size = struct.unpack("!I", exact(4))[0]
    if not 0 < size <= limit:
        raise QueryFailure("LIMIT")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    def reject_constant(_):
        raise ValueError("non-finite JSON number")
    try:
        return json.loads(exact(size), object_pairs_hook=unique, parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise QueryFailure("INVALID") from None


def _utc(value):
    if not isinstance(value, str) or len(value) > 40:
        raise QueryFailure("INVALID")
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        raise QueryFailure("INVALID") from None
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise QueryFailure("INVALID")
    result = dt.timestamp()
    if not math.isfinite(result):
        raise QueryFailure("INVALID")
    return result


def _identity(value):
    return isinstance(value, str) and IDENT.fullmatch(value) is not None


def _metadata(row):
    # Positive allowlist and type checks, not regex-based secret scrubbing.
    # Anything not a canonical v1 metadata value is replaced, not reflected.
    sensor, event_id, device, received, observed, kind, source, proto = row
    try:
        parsed = UUID(event_id)
        received_dt = datetime.fromisoformat(received)
        observed_dt = datetime.fromisoformat(observed)
        if (parsed.version != 4 or str(parsed) != event_id or received_dt.tzinfo is None
                or observed_dt.tzinfo is None):
            raise ValueError
    except (ValueError, TypeError, OverflowError):
        raise QueryFailure("UNAVAILABLE") from None
    try:
        source_ok = str(ipaddress.ip_address(source)) == source
    except (ValueError, TypeError):
        source_ok = False
    return {"sensor": sensor if _identity(sensor) else "<invalid>",
            "event_id": event_id if len(event_id) == 36 else "<invalid>",
            "device": device if _identity(device) else "<invalid>",
            "received_at": received_dt.isoformat(),
            "observed_at": observed_dt.isoformat(),
            "kind": kind if kind in TYPES else "<invalid>",
            "source": source if source_ok else "<invalid>",
            "proto": proto if proto in PROTO else "<invalid>"}


class QueryStore:
    def __init__(self, path, *, owner_uid=None, reader_gid=None, budget_seconds=0.5):
        self.path = Path(path)
        self.owner_uid = owner_uid
        self.reader_gid = reader_gid
        self.budget_seconds = budget_seconds
        self._cursor_key = secrets.token_bytes(32)  # process-local; restart invalidates cursors

    def _connect(self):
        db = None
        try:
            info = self.path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_size > 256 * 1024 * 1024 or info.st_mode & 0o007
                    or (self.owner_uid is not None and info.st_uid != self.owner_uid)
                    or (self.reader_gid is not None and
                        (info.st_gid != self.reader_gid or stat.S_IMODE(info.st_mode) != 0o640))):
                raise PermissionError("untrusted events file")
            db = sqlite3.connect(self.path.absolute().as_uri() + "?mode=ro", uri=True,
                                 timeout=0.15, isolation_level=None)
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA temp_store=MEMORY")
            db.execute("PRAGMA busy_timeout=150")
            if db.execute("PRAGMA journal_mode").fetchone()[0].lower() != "delete":
                raise QueryFailure("UNAVAILABLE")
            indices = {row[1] for row in db.execute("PRAGMA index_list(events)")}
            if "received_order" not in indices:
                raise QueryFailure("UNAVAILABLE")
            start = time.monotonic()
            db.set_progress_handler(lambda: int(time.monotonic() - start > self.budget_seconds), 1000)
            return db
        except QueryFailure:
            if db is not None:
                db.close()
            raise
        except (OSError, sqlite3.Error):
            if db is not None:
                db.close()
            raise QueryFailure("UNAVAILABLE") from None

    def _cursor(self, data):
        raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        mac = hmac.digest(self._cursor_key, raw, "sha256")
        return base64.urlsafe_b64encode(raw + mac).decode().rstrip("=")

    def _decode_cursor(self, text):
        if not isinstance(text, str) or len(text) > 1024:
            raise QueryFailure("INVALID")
        try:
            blob = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
            raw, mac = blob[:-32], blob[-32:]
            if not hmac.compare_digest(hmac.digest(self._cursor_key, raw, "sha256"), mac):
                raise ValueError
            data = json.loads(raw)
            if set(data) != {"offset", "watermark", "from", "to", "filters", "expires", "limit"}:
                raise ValueError
            if (type(data["offset"]) is not int or not 0 <= data["offset"] <= 10000
                    or type(data["watermark"]) is not int or data["watermark"] < 0
                    or type(data["expires"]) is not int or data["expires"] < time.time()):
                raise ValueError
            return data
        except (ValueError, TypeError, KeyError, OverflowError):
            raise QueryFailure("INVALID") from None

    def execute(self, request):
        if not isinstance(request, dict) or type(request.get("version")) is not int or request["version"] != VERSION:
            raise QueryFailure("INVALID")
        operation = request.get("operation")
        if not isinstance(operation, str) or operation not in {"list", "detail", "activity", "export"}:
            raise QueryFailure("INVALID")
        if set(request) - {"version", "operation", "filters", "limit", "cursor", "sensor", "event_id", "minutes"}:
            raise QueryFailure("INVALID")
        if operation == "detail":
            if set(request) != {"version", "operation", "sensor", "event_id"}:
                raise QueryFailure("INVALID")
            return self._detail(request["sensor"], request["event_id"])
        if operation == "activity":
            if set(request) != {"version", "operation", "minutes"} or type(request["minutes"]) is not int or not 5 <= request["minutes"] <= 1440:
                raise QueryFailure("INVALID")
            return self._activity(request["minutes"])
        allowed = {"version", "operation", "filters", "limit"} | ({"cursor"} if operation == "list" else set())
        if not {"version", "operation", "filters", "limit"} <= set(request) or set(request) - allowed:
            raise QueryFailure("INVALID")
        limit = request["limit"]
        if type(limit) is not int or not 1 <= limit <= (100 if operation == "list" else MAX_ROWS):
            raise QueryFailure("INVALID")
        return self._listing(request["filters"], limit, request.get("cursor"), export=operation == "export")

    def _filters(self, filters):
        if not isinstance(filters, dict) or set(filters) - {"sensor", "device", "source", "kind", "proto", "from_time", "to_time"}:
            raise QueryFailure("INVALID")
        for key, value in filters.items():
            if not isinstance(value, str) or len(value) > 64 or not value:
                raise QueryFailure("INVALID")
            if key in {"sensor", "device"} and not _identity(value):
                raise QueryFailure("INVALID")
            if key == "source":
                try:
                    if str(ipaddress.ip_address(value)) != value:
                        raise ValueError
                except ValueError:
                    raise QueryFailure("INVALID") from None
            if (key == "kind" and value not in TYPES) or (key == "proto" and value not in PROTO):
                raise QueryFailure("INVALID")
        now = time.time()
        end = _utc(filters["to_time"]) if "to_time" in filters else now
        start = _utc(filters["from_time"]) if "from_time" in filters else end - 86400
        if not 0 < end - start <= MAX_WINDOW or end > now + 60 or start < 0:
            raise QueryFailure("INVALID")
        normalized = {k: filters[k] for k in ("sensor", "device", "source", "kind", "proto") if k in filters}
        return normalized, start, end

    def _where(self, filters, start, end, watermark):
        clauses = ["rowid<=?", "received_epoch>=?", "received_epoch<=?"]
        args = [watermark, start, end]
        for key, value in filters.items():
            if key == "proto":
                clauses.append("CASE WHEN length(payload)<=8192 AND json_valid(CAST(payload AS TEXT)) THEN json_extract(CAST(payload AS TEXT),'$.proto') ELSE NULL END=?")
            else:
                clauses.append(key + "=?")
            args.append(value)
        return " WHERE " + " AND ".join(clauses), args

    def _listing(self, raw_filters, limit, cursor=None, *, export=False):
        filters, start, end = self._filters(raw_filters)
        offset = 0
        if cursor is not None:
            if export:
                raise QueryFailure("INVALID")
            state = self._decode_cursor(cursor)
            if state["filters"] != filters or state["limit"] != limit:
                raise QueryFailure("INVALID")
            # Unspecified to_time would move between requests; stored range wins.
            if "from_time" in raw_filters and abs(state["from"] - start) > 1e-3 or "to_time" in raw_filters and abs(state["to"] - end) > 1e-3:
                raise QueryFailure("INVALID")
            start, end = state["from"], state["to"]
            offset, watermark = state["offset"], state["watermark"]
        db = self._connect()
        try:
            db.execute("BEGIN")  # count and rows see one read snapshot; never writes
            if cursor is None:
                watermark = db.execute("SELECT COALESCE(MAX(rowid),0) FROM events").fetchone()[0]
            where, args = self._where(filters, start, end, watermark)
            total = db.execute("SELECT COUNT(*) FROM events" + where, args).fetchone()[0]
            rows = db.execute("SELECT sensor,event_id,device,received_at,observed_at,kind,source,"
                              "CASE WHEN length(payload)<=8192 AND json_valid(payload) "
                              "THEN json_extract(payload,'$.proto') ELSE NULL END FROM events" + where +
                              " ORDER BY received_epoch DESC,sensor DESC,event_id DESC LIMIT ? OFFSET ?",
                              args + [limit, offset]).fetchall()
            db.execute("COMMIT")
            items = [_metadata(row) for row in rows]
            next_cursor = None
            if not export and offset + len(items) < total and offset + len(items) <= 10000:
                next_cursor = self._cursor({"offset": offset + len(items), "watermark": watermark,
                                            "from": start, "to": end, "filters": filters,
                                            "expires": int(time.time()) + 300, "limit": limit})
            return {"version": VERSION, "items": items, "total": total, "offset": offset,
                    "limit": limit, "next_cursor": next_cursor, "truncated": export and total > len(items),
                    "received_from": datetime.fromtimestamp(start, timezone.utc).isoformat(),
                    "received_to": datetime.fromtimestamp(end, timezone.utc).isoformat(),
                    "queried_at": datetime.now(timezone.utc).isoformat(), "redacted": True}
        except (sqlite3.Error, OverflowError):
            raise QueryFailure("UNAVAILABLE") from None
        finally:
            db.close()

    def _detail(self, sensor, event_id):
        try:
            parsed = UUID(event_id)
        except (TypeError, ValueError):
            raise QueryFailure("INVALID") from None
        if not _identity(sensor) or parsed.version != 4 or str(parsed) != event_id.lower():
            raise QueryFailure("INVALID")
        db = self._connect()
        try:
            row = db.execute("SELECT sensor,event_id,device,received_at,observed_at,kind,source,"
                             "CASE WHEN length(payload)<=8192 AND json_valid(payload) "
                             "THEN json_extract(payload,'$.proto') ELSE NULL END "
                             "FROM events WHERE sensor=? AND event_id=?", (sensor, event_id)).fetchone()
            if row is None:
                raise QueryFailure("NOT_FOUND")
            return {"version": VERSION, "event": _metadata(row), "redacted": True}
        except sqlite3.Error:
            raise QueryFailure("UNAVAILABLE") from None
        finally:
            db.close()

    def _activity(self, minutes):
        now = time.time()
        end = int(now // 60) * 60 + 60
        start = end - minutes * 60
        db = self._connect()
        try:
            rows = db.execute("SELECT CAST((received_epoch-?)/60 AS INTEGER),COUNT(*) FROM events "
                              "WHERE received_epoch>=? AND received_epoch<? GROUP BY 1", (start,start,end)).fetchall()
            counts = {int(index): int(count) for index,count in rows}
            return {"version": VERSION, "unit": "events/minute", "minutes": minutes,
                    "queried_at": datetime.now(timezone.utc).isoformat(),
                    "buckets": [{"at": datetime.fromtimestamp(start+i*60, timezone.utc).isoformat(),
                                 "count": counts.get(i, 0)} for i in range(minutes)]}
        except sqlite3.Error:
            raise QueryFailure("UNAVAILABLE") from None
        finally:
            db.close()


def _peer_uid(connection):
    if not hasattr(socket, "SO_PEERCRED"):
        raise QueryFailure("UNAVAILABLE")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)[1]


def serve_connection(conn, store, control_uid):
    """Handle exactly one framed request; never inspect or log captured payloads."""
    try:
        with conn:
            conn.settimeout(1.5)
            if _peer_uid(conn) != control_uid:
                error_id = secrets.token_hex(8)
                logging.getLogger(__name__).warning("query_error id=%s code=DENIED", error_id)
                _frame(conn, {"version": VERSION, "error": "DENIED", "id": error_id})
                return
            try:
                request = _receive(conn, MAX_REQUEST)
                response = store.execute(request)
                _frame(conn, response)
            except (QueryFailure, OSError, ValueError, TypeError, RecursionError) as exc:
                code = exc.code if isinstance(exc, QueryFailure) else "UNAVAILABLE"
                error_id = secrets.token_hex(8)
                logging.getLogger(__name__).warning("query_error id=%s code=%s", error_id, code)
                _frame(conn, {"version": VERSION, "error": code, "id": error_id})
    except (OSError, QueryFailure):
        pass  # no request bodies or paths in logs


def serve_inherited(store, *, control_uid):
    """Systemd passes one AF_UNIX listening fd at 3; no fallback bind or TCP."""
    if os.getenv("LISTEN_PID") != str(os.getpid()) or os.getenv("LISTEN_FDS") != "1":
        raise RuntimeError("exactly one systemd socket required")
    listener = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)
    if (listener.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
            or listener.getsockname() != "/run/dystopia-query/query.sock"):
        listener.close()
        raise RuntimeError("unexpected inherited query socket")
    slots = threading.BoundedSemaphore(4)
    pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="query")
    def process(conn):
        try:
            serve_connection(conn, store, control_uid)
        finally:
            slots.release()
    with listener, pool:
        while True:
            conn, _ = listener.accept()
            if slots.acquire(blocking=False):
                pool.submit(process, conn)
            else:
                try:
                    with conn:
                        conn.settimeout(0.2)
                        error_id = secrets.token_hex(8)
                        logging.getLogger(__name__).warning("query_error id=%s code=BUSY", error_id)
                        _frame(conn, {"version": VERSION, "error": "BUSY", "id": error_id})
                except OSError:
                    pass


def serve_production(path):
    ingest_uid = pwd.getpwnam("dystopia-ingest").pw_uid
    control_uid = pwd.getpwnam("dystopia-control").pw_uid
    if os.geteuid() in {ingest_uid, control_uid, 0}:
        raise RuntimeError("query daemon requires its own unprivileged Unix identity")
    serve_inherited(QueryStore(path, owner_uid=ingest_uid, reader_gid=os.getegid()), control_uid=control_uid)
