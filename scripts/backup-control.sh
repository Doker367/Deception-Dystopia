#!/usr/bin/env bash
# Offline export of Dystopia control-plane state and analytics configuration.
# Deterministic and conservative: python contract in runtime/backup.py, CLI in
# runtime.cli. This script never copies service data itself, never prints any
# secret and never writes inside the repository (real state stays unversioned).
#
# Usage: scripts/backup-control.sh <output-dir> [--created-at UTC_STAMP]
#
# Environment overrides (all optional):
#   DYSTOPIA_STATE_ROOT       state root (default /var/lib/dystopia)
#   DYSTOPIA_CONTROL_ENV_DIR  control environment dir (default /etc/dystopia)
#   PYTHON                    interpreter (default python3)
#
# Artifacts come from the fixed table in runtime.backup.default_artifact_specs:
#   /var/lib/dystopia/control/config/users.yaml   (control identity store)
#   /var/lib/dystopia/ingest/{events.db,sensors.db,server.crt,server.key}
#   /etc/dystopia/install.json                    (deployment plan)
#   /etc/dystopia/control.env                     (non-secret settings only)
#   deploy/elastic/.env                           (analytics settings, filtered)
#
# Output layout (created with mode 0700/0600):
#   <output-dir>/manifest.json
#   <output-dir>/artifacts/...
#
# Classification: secret-bearing. The table includes sensors.db and server.key,
# so the complete backup must be stored root-only and encrypted at rest. It is
# never a "secrets excluded" copy.
set -euo pipefail

umask 077

usage() {
    echo "usage: $0 <output-dir> [--created-at YYYY-MM-DDTHH:MM:SSZ]" >&2
    echo "environment: PYTHON (default python3)" >&2
}

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
    usage
    exit 2
fi

OUT=$1
shift
CREATED_AT=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --created-at)
            [ "$#" -ge 2 ] || { echo "error: --created-at needs a value" >&2; exit 2; }
            CREATED_AT=$2
            shift 2
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}

if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "error: $PYTHON interpreter not found" >&2
    exit 1
fi
case "$OUT" in
    /*|~*) ;;
    *) OUT="$PWD/$OUT" ;;
esac
case "$OUT" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
        echo "error: backup output must live outside the repository" >&2
        exit 1
        ;;
esac
case "$CREATED_AT" in
    "") CREATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ) ;;
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z) ;;
    *) echo "error: --created-at must be UTC YYYY-MM-DDTHH:MM:SSZ" >&2; exit 2 ;;
esac

# Read-only preflight: fails with exit 2 when required state artifacts are
# missing, before any output directory is touched.
PLAN_ARGS=()
if [ -n "${DYSTOPIA_STATE_ROOT:-}" ]; then
    PLAN_ARGS+=(--state-root "$DYSTOPIA_STATE_ROOT")
fi
if [ -n "${DYSTOPIA_CONTROL_ENV_DIR:-}" ]; then
    PLAN_ARGS+=(--control-env-dir "$DYSTOPIA_CONTROL_ENV_DIR")
fi
"$PYTHON" -m runtime.cli backup-plan "${PLAN_ARGS[@]}"

mkdir -p "$OUT"
"$PYTHON" -m runtime.cli backup-export "${PLAN_ARGS[@]}" --output "$OUT" --created-at "$CREATED_AT"

MANIFEST="$OUT/manifest.json"
if [ ! -f "$MANIFEST" ]; then
    echo "error: export did not produce a manifest" >&2
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    DIGEST=$(sha256sum "$MANIFEST" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    DIGEST=$(shasum -a 256 "$MANIFEST" | awk '{print $1}')
else
    echo "error: no sha256 tool available to seal the manifest" >&2
    exit 1
fi
BACKUP_ID=$("$PYTHON" -c 'import json,sys;import hashlib;data=open(sys.argv[1],"rb").read();print(hashlib.sha256(data).hexdigest()[:16])' "$MANIFEST")
CLASSIFICATION=$("$PYTHON" -c 'import json,sys;print(json.load(open(sys.argv[1]))["policy"]["classification"])' "$MANIFEST")
echo "backup_complete: $OUT"
echo "created_at: $CREATED_AT"
echo "backup_id: $BACKUP_ID"
echo "manifest_sha256: $DIGEST"
echo "classification: $CLASSIFICATION"
echo "next: store offline, verify the digest at the storage site and schedule a restore drill"
