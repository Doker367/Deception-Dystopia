#!/bin/bash
# Lab backup: private SQLite state + local configuration, 14-day retention.
# Root-only. Backups stay on this host until copied to the CPD backup target.
set -euo pipefail
umask 077

BASE=/var/backups/dystopia
TS=$(date -u +%Y%m%dT%H%M%SZ)
DEST="$BASE/$TS"
LOG=/var/log/dystopia-backup.log

mkdir -p "$BASE"
chmod 700 "$BASE"
exec >>"$LOG" 2>&1
echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) backup $TS"
mkdir -p "$DEST"
chmod 700 "$DEST"

docker run --rm --user 0:0 \
  -v dystopia-local_deception_db:/srv/deception:ro \
  -v dystopia-local_control_state:/srv/state:ro \
  -v dystopia-local_control_config:/srv/local-config:ro \
  -v "$DEST":/backup \
  -v /usr/local/lib/dystopia/backup.py:/backup.py:ro \
  --entrypoint python3 dystopia/local-control:lab /backup.py

install -m 600 /home/doker/Dystopia/deploy/local/.env "$DEST/env"
cp -a /home/doker/Dystopia/deploy/local/docker-compose.yml "$DEST/docker-compose.yml"
cp -a /home/doker/Dystopia/deploy/local/docker-compose.remote.yml "$DEST/docker-compose.remote.yml" 2>/dev/null || true
cp -a /home/doker/Dystopia/deploy/local/SERVER-NOTES.md "$DEST/SERVER-NOTES.md" 2>/dev/null || true
( cd "$DEST" && sha256sum * > MANIFEST.sha256 && chmod 600 MANIFEST.sha256 )

find "$BASE" -mindepth 1 -maxdepth 1 -type d -mtime +14 -exec rm -rf {} +
echo "=== done $(du -sh "$DEST" | cut -f1)"
