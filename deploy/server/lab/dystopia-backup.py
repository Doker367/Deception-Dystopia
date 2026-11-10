"""Consistent SQLite backup inside the Dystopia control image.

Mounted at /backup.py by the lab backup script. Reads the private state
volumes read-only and writes 0600 copies with SQLite's online backup API.
"""

import os
import shutil
import sqlite3

ITEMS = (
    ("deception.db", "/srv/deception/deception.db"),
    ("audit.db", "/srv/state/audit/audit.db"),
    ("investigations.db", "/srv/state/investigations.db"),
)

for name, path in ITEMS:
    if not os.path.exists(path):
        continue
    source = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    target = sqlite3.connect(f"/backup/{name}")
    source.backup(target)
    target.close()
    source.close()
    os.chmod(f"/backup/{name}", 0o600)
    print("backup", name)

users = "/srv/local-config/users.yaml"
if os.path.exists(users):
    shutil.copy2(users, "/backup/users.yaml")
    os.chmod("/backup/users.yaml", 0o600)
    print("backup users.yaml")
