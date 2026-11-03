"""Shared synthetic fixtures for the offline operations-integration tests.

Everything here is synthetic and bounded: a fake state root, a fake control
environment directory and small SQLite stores that use the *real* runtime
schemas (ingest event store, sensor spool, sensor credential registry) so the
integrated report can reuse ``runtime.health`` without any service, socket,
container or privileged operation.
"""
import json
import os
import sqlite3

import pytest

# Synthetic, never-real secret material used only to prove it stays excluded.
PLANTED_SECRETS = (
    "CHANGEME_UNIQUE_ADMIN_PASSWORD_PER_INSTANCE",
    "CHANGEME_KIBANA_SERVICE_TOKEN",
    "synthetic-ingest-api-key-never-in-report",
)
CONTROL_ENV = ("DYSTOPIA_CONTROL_STATE=/var/lib/dystopia/control\n"
               "DYSTOPIA_CONTROL_CONFIG=/var/lib/dystopia/control/config\n"
               "NETPULSE_ENV=production\n"
               f"NETPULSE_JWT_SECRET={'b' * 64}\n"
               f"ELASTIC_PASSWORD={PLANTED_SECRETS[0]}\n")
ANALYTICS_ENV = ("ELASTIC_VERSION=9.3.5\n"
                 "ELASTIC_MEMORY_LIMIT=3g\n"
                 f"ELASTIC_PASSWORD={PLANTED_SECRETS[0]}\n"
                 f"KIBANA_SYSTEM_PASSWORD={PLANTED_SECRETS[1]}\n"
                 f"DYSTOPIA_ELASTIC_API_KEY={PLANTED_SECRETS[2]}\n")

INGEST_SCHEMA = """
    CREATE TABLE events (
        sensor TEXT NOT NULL, event_id TEXT NOT NULL, device TEXT NOT NULL,
        received_at TEXT NOT NULL, received_epoch REAL NOT NULL,
        observed_at TEXT NOT NULL, kind TEXT NOT NULL, source TEXT NOT NULL,
        payload BLOB NOT NULL, PRIMARY KEY(sensor,event_id));
    CREATE TABLE outbox (
        sensor TEXT NOT NULL, event_id TEXT NOT NULL, rule TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0, due REAL NOT NULL DEFAULT 0,
        delivered INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(sensor,event_id));
    INSERT INTO events VALUES('sensor-a','event-1','device-1',
        '2026-11-02T10:00:00+00:00',1762087200.0,'2026-11-02T10:00:00+00:00',
        'login_attempt','198.51.100.7',X'7b7d');
    INSERT INTO outbox VALUES('sensor-a','event-1','brute_force',0,0,0);
"""

REGISTRY_SCHEMA = """
    CREATE TABLE sensors(sensor TEXT PRIMARY KEY, devices TEXT NOT NULL);
    CREATE TABLE credentials(key_id TEXT PRIMARY KEY, sensor TEXT NOT NULL,
        digest TEXT NOT NULL UNIQUE, expires REAL NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0);
    INSERT INTO sensors VALUES('sensor-a','["device-1"]');
    INSERT INTO credentials VALUES('key-1','sensor-a','digest-only',4102444800,0);
"""

SPOOL_SCHEMA = """
    CREATE TABLE queue(event_id TEXT PRIMARY KEY, queued REAL NOT NULL,
        payload BLOB NOT NULL, quarantined INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL);
    INSERT INTO queue VALUES('event-2',1762087200.0,X'7b7d',0);
    INSERT INTO counters VALUES('discarded',0);
"""


def _database(path, script):
    db = sqlite3.connect(path)
    db.executescript(script)
    db.commit()
    db.close()


def _private(path, text=None):
    if text is not None:
        path.write_text(text)
    os.chmod(path, 0o600)
    return path


@pytest.fixture()
def state(tmp_path):
    """A synthetic, fully populated Dystopia state root."""
    state_root = tmp_path / "state"
    etc = tmp_path / "etc"
    (state_root / "control/config").mkdir(parents=True)
    (state_root / "ingest").mkdir()
    (state_root / "sensor").mkdir()
    etc.mkdir()

    _private(state_root / "control/config/users.yaml",
             "users:\n- username: synthetic\n  password_hash: never-a-real-bcrypt-value\n")
    _private(state_root / "ingest/server.crt",
             "-----BEGIN SYNTHETIC CERTIFICATE-----\n" + "ab" * 16 + "\n")
    _private(state_root / "ingest/server.key",
             "-----BEGIN SYNTHETIC KEY-----\n" + "cd" * 16 + "\n")
    _database(state_root / "ingest/events.db", INGEST_SCHEMA)
    _database(state_root / "ingest/sensors.db", REGISTRY_SCHEMA)
    _database(state_root / "sensor/spool.db", SPOOL_SCHEMA)
    for path in (state_root / "ingest/events.db", state_root / "ingest/sensors.db",
                 state_root / "sensor/spool.db"):
        _private(path)
    _private(etc / "install.json", json.dumps({"version": 1}))
    _private(etc / "control.env", CONTROL_ENV)
    elastic = tmp_path / "deploy/elastic/.env"
    elastic.parent.mkdir(parents=True)
    elastic.write_text(ANALYTICS_ENV)

    return {
        "state_root": state_root,
        "control_env_dir": etc,
        "elastic_env": elastic,
        "spool": state_root / "sensor/spool.db",
        "users": state_root / "control/config/users.yaml",
        "events": state_root / "ingest/events.db",
    }
