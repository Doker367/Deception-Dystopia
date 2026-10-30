"""Individual, revocable sensor credentials; no administrative tokens accepted."""
from contextlib import contextmanager
import hashlib
import hmac
import json
import secrets
import time

from runtime.contracts import identifier
from runtime.storage import database


class Registry:
    def __init__(self, path):
        self.path = path
        with database(path, 8*1024*1024) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS sensors(sensor TEXT PRIMARY KEY, devices TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS credentials(key_id TEXT PRIMARY KEY, sensor TEXT NOT NULL,
                    digest TEXT NOT NULL UNIQUE, expires REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
            """)

    def rotate(self, sensor, devices, lifetime=86400*30, output=None):
        """Operator-local operation; immediately revokes all older keys for this sensor."""
        identifier(sensor)
        if not devices or len(devices) > 64 or not 60 <= lifetime <= 86400*90:
            raise ValueError("invalid assignment or lifetime")
        for device in devices:
            identifier(device)
        key_id, secret = secrets.token_hex(16), secrets.token_urlsafe(32)
        token = key_id + "." + secret
        with database(self.path, 8*1024*1024) as db:
            db.execute("BEGIN IMMEDIATE")
            # Devices cannot be assigned to two different sensor identities.
            for other, assigned in db.execute("SELECT sensor,devices FROM sensors"):
                if other != sensor and set(devices) & set(json.loads(assigned)):
                    raise ValueError("device already assigned to another sensor")
            if output is not None:
                from runtime.localfiles import create_private
                if not create_private(output, (token + "\n").encode()):
                    raise FileExistsError("rotation output exists; no credential was changed")
                # File is durable before old credentials are revoked. On DB failure
                # this file is INACTIVE; keep old credential and repeat to a new path.
            db.execute("INSERT INTO sensors VALUES(?,?) ON CONFLICT(sensor) DO UPDATE SET devices=excluded.devices",
                       (sensor, json.dumps(sorted(set(devices)))))
            db.execute("UPDATE credentials SET revoked=1 WHERE sensor=?", (sensor,))
            # Retain only current key: revoked/rotated tokens always fail lookup.
            db.execute("DELETE FROM credentials WHERE sensor=?", (sensor,))
            db.execute("INSERT INTO credentials VALUES(?,?,?,?,0)",
                       (key_id, sensor, hashlib.sha256(token.encode()).hexdigest(), time.time()+lifetime))
            db.execute("COMMIT")
        return token

    def revoke(self, sensor):
        identifier(sensor)
        with database(self.path, 8*1024*1024) as db:
            db.execute("UPDATE credentials SET revoked=1 WHERE sensor=?", (sensor,))

    @staticmethod
    def _authenticate(db, token):
        if not isinstance(token, str) or len(token) > 128 or token.count(".") != 1:
            raise PermissionError("invalid sensor credential")
        row = db.execute("SELECT c.sensor,c.digest,c.expires,c.revoked,s.devices FROM credentials c JOIN sensors s ON s.sensor=c.sensor WHERE key_id=?",
                         (token.split(".")[0],)).fetchone()
        digest = hashlib.sha256(token.encode()).hexdigest()
        if not row or not hmac.compare_digest(digest, row[1]) or row[2] <= time.time() or row[3]:
            raise PermissionError("invalid sensor credential")
        return row[0], frozenset(json.loads(row[4]))

    def authenticate(self, token):
        with database(self.path, 8*1024*1024) as db:
            return self._authenticate(db, token)

    @contextmanager
    def authorized(self, token):
        """Serialize final authorization+event commit against rotation/revocation.

        Revocation may wait for an already authorized transaction, but once it
        returns no transaction authorized with that credential can still commit.
        Lock ordering is registry then event store in every ingress operation.
        """
        with database(self.path, 8*1024*1024) as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._authenticate(db, token)
            yield identity
            db.execute("COMMIT")
