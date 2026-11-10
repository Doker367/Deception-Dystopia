"""Private analyst annotations and declarative honeypot overrides.

Captured events and the deployment inventory are deliberately never modified here.
No lifecycle operation or container runtime is available to this service.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

import yaml

from app.core.settings import STATE_DIR
from runtime.localfiles import open_private_parent
from runtime.storage import database

DB_PATH: Path = STATE_DIR / "investigations.db"
INVENTORY_PATH: Path = Path(__file__).resolve().parents[2] / "deploy" / "honeypots" / "inventory.yaml"
# Presupuesto del almacén privado. Con AUDIT_MAX_ROWS = 10 000 y notas de
# hasta 4 KB, 16 MiB podían agotarse antes de que la poda entrara en juego.
MAX_BYTES = 64 * 1024 * 1024
# Retain the newest audit rows by insertion order, not by elapsed time.
AUDIT_MAX_ROWS = 10_000
SENSORS = frozenset({"cowrie", "opencanary", "dionaea", "heralding", "redishoneypot", "endlessh"})
DRAFT_FIELDS = ("display_name", "description", "memory_mib", "cpus", "pids_limit")
PROFILE_FIELDS = ("alias", "classification", "handling", "handling_target", "tags", "notes")
# Nombres visibles de la interfaz. El inventario estricto no admite campos extra,
# así que esta etiqueta vive con el servicio y no altera su contrato.
DISPLAY_NAMES = {"cowrie": "Cowrie", "opencanary": "OpenCanary", "dionaea": "Dionaea",
                 "heralding": "Heralding", "redishoneypot": "RedisHoneyPot", "endlessh": "Endlessh"}
SCHEMA = """
CREATE TABLE IF NOT EXISTS profiles (
    source TEXT PRIMARY KEY, revision INTEGER NOT NULL, body TEXT NOT NULL,
    updated_at TEXT NOT NULL, updated_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sensor_drafts (
    sensor TEXT PRIMARY KEY, revision INTEGER NOT NULL, body TEXT NOT NULL,
    updated_at TEXT NOT NULL, updated_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL,
    kind TEXT NOT NULL, subject TEXT NOT NULL, revision INTEGER NOT NULL,
    before TEXT, after TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_subject ON audit(kind, subject, id DESC);
"""


class Conflict(Exception):
    pass


def _read_only() -> sqlite3.Connection | None:
    """Open an existing private store without creating files, tables or journal state."""
    if not DB_PATH.parent.is_dir():
        raise FileNotFoundError("private state directory not provisioned")
    parent_fd = open_private_parent(DB_PATH)
    try:
        try:
            fd = os.open(DB_PATH.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077
                    or info.st_uid not in {0, os.geteuid()} or info.st_size > MAX_BYTES):
                raise PermissionError("investigation store must be a private regular file")
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    db = sqlite3.connect(f"{DB_PATH.absolute().as_uri()}?mode=ro", uri=True, timeout=2)
    db.execute("PRAGMA query_only=ON")
    return db


def _read(table: str, key: str, value: str):
    db = _read_only()
    if db is None:
        return None
    try:
        # Table names are fixed here, never sourced from request parameters.
        row = db.execute(
            f"SELECT revision,body,updated_at,updated_by FROM {table} WHERE {key}=?", (value,)
        ).fetchone()
    except sqlite3.OperationalError as exc:
        if "no such table" not in str(exc):
            raise
        row = None
    finally:
        db.close()
    if row is None:
        return None
    return {"revision": row[0], **json.loads(row[1]), "updated_at": row[2], "updated_by": row[3]}


def profile(source: str):
    return _read("profiles", "source", source)


def sensor_draft(sensor: str):
    return _read("sensor_drafts", "sensor", sensor)


def _save(table: str, key: str, value: str, body: dict, actor: str, expected: int):
    kind = "profile" if table == "profiles" else "sensor_draft"
    # Parent directory is provisioned separately; reads never create files.
    with database(DB_PATH, MAX_BYTES) as db:
        db.executescript(SCHEMA)
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(f"SELECT revision,body FROM {table} WHERE {key}=?", (value,)).fetchone()
        current = row[0] if row else 0
        before = json.loads(row[1]) if row else None
        if current != expected:
            raise Conflict("revision changed; reload before saving")
        revision = current + 1
        now = datetime.now(timezone.utc).isoformat()
        after = json.dumps(body, ensure_ascii=False)
        db.execute(
            f"INSERT INTO {table}({key},revision,body,updated_at,updated_by) VALUES(?,?,?,?,?) "
            f"ON CONFLICT({key}) DO UPDATE SET revision=excluded.revision,body=excluded.body,"
            "updated_at=excluded.updated_at,updated_by=excluded.updated_by",
            (value, revision, after, now, actor),
        )
        # Append new history and prune only the oldest audit rows in this transaction.
        db.execute(
            "INSERT INTO audit(at,actor,kind,subject,revision,before,after) VALUES(?,?,?,?,?,?,?)",
            (now, actor, kind, value, revision,
             json.dumps(before, ensure_ascii=False) if before is not None else None, after),
        )
        db.execute(
            "DELETE FROM audit WHERE id <= COALESCE("
            "(SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET ?), 0)",
            (AUDIT_MAX_ROWS,),
        )
        db.execute("COMMIT")
    return _read(table, key, value)


def _changes(kind: str, before: dict | None, after: dict) -> list[dict]:
    fields = PROFILE_FIELDS if kind == "profile" else DRAFT_FIELDS
    old = before or {}
    return [{"field": field, "from": old.get(field), "to": after.get(field)}
            for field in fields if old.get(field) != after.get(field)]


def history(kind: str, subject: str, limit: int = 20) -> list[dict]:
    """Read-only audit trail; never creates the database or its tables."""
    db = _read_only()
    if db is None:
        return []
    try:
        table = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit'"
        ).fetchone()
        if table is None:
            return []
        rows = db.execute(
            "SELECT id,at,actor,revision,before,after FROM audit "
            "WHERE kind=? AND subject=? ORDER BY id DESC LIMIT ?",
            (kind, subject, min(max(limit, 1), 100)),
        ).fetchall()
    finally:
        db.close()
    return [{"id": row[0], "at": row[1], "actor": row[2], "revision": row[3],
             "changes": _changes(kind, json.loads(row[4]) if row[4] else None,
                                 json.loads(row[5]))}
            for row in rows]


def _memory_mib(value: object) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([mMgG]?)\s*", str(value))
    if match is None:
        return 0
    amount = int(match.group(1))
    return amount * 1024 if match.group(2).lower() == "g" else amount


def baseline(sensor: str) -> dict:
    """Declared reference from the static inventory, not observed runtime state."""
    document = yaml.safe_load(INVENTORY_PATH.read_text(encoding="utf-8"))
    engine = next((item for item in document.get("engines", []) if item.get("id") == sensor), None)
    if engine is None:
        raise FileNotFoundError("sensor missing from static inventory")
    resources = engine.get("resources") or {}
    return {
        "display_name": DISPLAY_NAMES.get(sensor, sensor),
        "description": engine.get("description") or "",
        "memory_mib": _memory_mib(resources.get("mem_limit", 0)),
        "cpus": float(resources.get("cpus") or 0),
        "pids_limit": int(resources.get("pids_limit") or 0),
    }


def plan(sensor: str) -> dict:
    """Deterministic declarative diff. It is never an execution authorization."""
    reference = baseline(sensor)
    draft = sensor_draft(sensor)
    candidate = {field: (draft or reference)[field] for field in DRAFT_FIELDS}
    changes = [{"field": field, "from": reference[field], "to": candidate[field]}
               for field in DRAFT_FIELDS if reference[field] != candidate[field]]
    canonical = json.dumps({"sensor": sensor, "baseline": reference, "draft": draft},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {
        "sensor": sensor,
        "baseline": reference,
        "draft": draft,
        "changes": changes,
        "changed": bool(changes),
        "plan_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "activation": "blocked",
        "blocking_reasons": [
            "No hay una clave pública de verificador Linux revisada e independiente fijada (v1 fail-closed)",
            "El ciclo de vida y la aplicación de sensores no están implementados; el plan es declarativo",
            "Los límites declarados no están verificados contra el estado efectivo de cgroup/kernel",
        ],
    }


def save_profile(source: str, body: dict, actor: str, expected: int):
    return _save("profiles", "source", source, body, actor, expected)


def save_sensor(sensor: str, body: dict, actor: str, expected: int):
    return _save("sensor_drafts", "sensor", sensor, body, actor, expected)
