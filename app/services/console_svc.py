"""Private declarative cell drafts. This module never provisions a sensor or host resource.

A validation here is only a schema/configuration check, never containment evidence.
Every edit invalidates the previous result in the same SQLite transaction.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from app.core.settings import STATE_DIR
from runtime.storage import database

DB_PATH = STATE_DIR / "cells.db"
MAX_BYTES = 16 * 1024 * 1024
SCHEMA = """
CREATE TABLE IF NOT EXISTS cells (
 id TEXT PRIMARY KEY, revision INTEGER NOT NULL, body TEXT NOT NULL,
 updated_at TEXT NOT NULL, validation TEXT
);
CREATE TABLE IF NOT EXISTS operations (
 id INTEGER PRIMARY KEY, cell_id TEXT NOT NULL, actor TEXT NOT NULL,
 action TEXT NOT NULL, revision INTEGER NOT NULL, outcome TEXT NOT NULL,
 timestamp TEXT NOT NULL
);
"""


class Conflict(Exception):
    pass


def _now():
    return datetime.now(timezone.utc).isoformat()


def _unpack(row):
    if row is None:
        return None
    body = json.loads(row[2])
    return {"id": row[0], "revision": row[1], **body,
            "updated_at": row[3], "validation": json.loads(row[4]) if row[4] else None,
            "operational_state": "draft", "verification": {"state": "unavailable", "last_verified_at": None,
            "reason": "No independent Linux containment verifier"}}


def list_cells():
    if not DB_PATH.parent.is_dir():
        raise FileNotFoundError("cell state directory not provisioned")
    if not DB_PATH.exists():
        return []
    with database(DB_PATH, MAX_BYTES) as db:
        return [_unpack(row) for row in db.execute(
            "SELECT id,revision,body,updated_at,validation FROM cells ORDER BY id LIMIT 500")]


def get_cell(cell_id):
    if not DB_PATH.parent.is_dir():
        raise FileNotFoundError("cell state directory not provisioned")
    if not DB_PATH.exists():
        return None
    with database(DB_PATH, MAX_BYTES) as db:
        return _unpack(db.execute(
            "SELECT id,revision,body,updated_at,validation FROM cells WHERE id=?", (cell_id,)).fetchone())


def save(cell_id, body, actor, expected=None):
    # DB_PATH parent must already exist; no import-time or GET side effects.
    with database(DB_PATH, MAX_BYTES) as db:
        db.executescript(SCHEMA)
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT revision FROM cells WHERE id=?", (cell_id,)).fetchone()
        if expected is None and row or expected is not None and (not row or row[0] != expected):
            raise Conflict("cell already exists or revision changed; reload before saving")
        revision = 1 if row is None else row[0] + 1
        ts = _now()
        db.execute("INSERT INTO cells(id,revision,body,updated_at,validation) VALUES(?,?,?,?,NULL) "
                   "ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,body=excluded.body,"
                   "updated_at=excluded.updated_at,validation=NULL",
                   (cell_id, revision, json.dumps(body, sort_keys=True), ts))
        db.execute("INSERT INTO operations(cell_id,actor,action,revision,outcome,timestamp) "
                   "VALUES(?,?,?,?,?,?)", (cell_id, actor, "create" if row is None else "update", revision, "saved_draft", ts))
        db.execute("COMMIT")
    return get_cell(cell_id)


def validate(cell_id, expected, actor):
    with database(DB_PATH, MAX_BYTES) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT revision,body FROM cells WHERE id=?", (cell_id,)).fetchone()
        if not row:
            return None
        if row[0] != expected:
            raise Conflict("revision changed; reload before validating")
        body = json.loads(row[1]); missing = []
        for key in ("name", "purpose", "profile", "segment", "address", "sensor_id", "device_id"):
            if not body.get(key):
                missing.append(key)
        result = {"state": "complete" if not missing else "incomplete", "scope": "declarative_only",
                  "config_version": expected, "checked_at": _now(), "missing": missing,
                  "activation_allowed": False,
                  "blocking_reasons": ["Independent containment verification and libvirt lifecycle not implemented"]}
        db.execute("UPDATE cells SET validation=? WHERE id=? AND revision=?",
                   (json.dumps(result), cell_id, expected))
        db.execute("INSERT INTO operations(cell_id,actor,action,revision,outcome,timestamp) "
                   "VALUES(?,?,?,?,?,?)", (cell_id, actor, "validate_config", expected, result["state"], result["checked_at"]))
        db.execute("COMMIT")
        return result


def history(cell_id):
    if not DB_PATH.parent.is_dir():
        raise FileNotFoundError("cell state directory not provisioned")
    if not DB_PATH.exists():
        return []
    with database(DB_PATH, MAX_BYTES) as db:
        return [{"id": row[0], "actor": row[1], "action": row[2], "revision": row[3],
                 "outcome": row[4], "timestamp": row[5]} for row in db.execute(
            "SELECT id,actor,action,revision,outcome,timestamp FROM operations WHERE cell_id=? ORDER BY id DESC LIMIT 100", (cell_id,))]
