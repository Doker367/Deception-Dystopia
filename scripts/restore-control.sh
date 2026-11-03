#!/usr/bin/env bash
# Safe restore of Dystopia control-plane state from a verifiable backup dir.
# Delegates every read, digest check and write to the python contract
# (runtime.backup + runtime.cli backup-restore): verification happens before
# any write, existing target state is never overwritten and destinations are
# re-derived from the fixed artifact table, never from manifest paths.
#
# Usage: scripts/restore-control.sh --backup <backup-dir> \
#            --state-root /var/lib/dystopia [--control-env-dir /etc/dystopia]
#
# Required confirmation guard (non-interactive, deterministic):
#   DYSTOPIA_RESTORE_CONFIRM=restore
#
# Refuses to run when: the guard is not set, the backup manifest is absent,
# a restored artifact is missing/corrupted, or any target state file exists.
set -euo pipefail

umask 077

usage() {
    echo "usage: $0 --backup <backup-dir> --state-root <dir> [--control-env-dir <dir>]" >&2
    echo "required: DYSTOPIA_RESTORE_CONFIRM=restore" >&2
}

if [ "$#" -lt 1 ] || [ "$#" -gt 6 ]; then
    usage
    exit 2
fi

BACKUP_DIR=""
STATE_ROOT="/var/lib/dystopia"
CONTROL_ENV_DIR="/etc/dystopia"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --backup)
            [ "$#" -ge 2 ] || { echo "error: --backup needs a value" >&2; exit 2; }
            BACKUP_DIR=$2
            shift 2
            ;;
        --state-root)
            [ "$#" -ge 2 ] || { echo "error: --state-root needs a value" >&2; exit 2; }
            STATE_ROOT=$2
            shift 2
            ;;
        --control-env-dir)
            [ "$#" -ge 2 ] || { echo "error: --control-env-dir needs a value" >&2; exit 2; }
            CONTROL_ENV_DIR=$2
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
if [ "${DYSTOPIA_RESTORE_CONFIRM:-}" != "restore" ]; then
    echo "error: refusing to restore without DYSTOPIA_RESTORE_CONFIRM=restore" >&2
    usage
    exit 2
fi
if [ -z "$BACKUP_DIR" ]; then
    echo "error: --backup is required" >&2
    exit 2
fi
if [ ! -d "$BACKUP_DIR" ] || [ ! -f "$BACKUP_DIR/manifest.json" ]; then
    echo "error: not a backup directory (manifest.json missing): $BACKUP_DIR" >&2
    exit 1
fi
# Hard-path guards: restore targets must be canonical state roots, never
# arbitrary paths, and never inside the repository.
case "$STATE_ROOT" in
    /*) ;;
    *) echo "error: --state-root must be an absolute path" >&2; exit 1 ;;
esac
case "$CONTROL_ENV_DIR" in
    /*) ;;
    *) echo "error: --control-env-dir must be an absolute path" >&2; exit 1 ;;
esac
for ROOT in "$STATE_ROOT" "$CONTROL_ENV_DIR"; do
    case "$ROOT" in
        "$REPO_ROOT"|"$REPO_ROOT"/*)
            echo "error: state roots must stay outside the repository" >&2
            exit 1
            ;;
    esac
done
if [ ! -d "$STATE_ROOT" ] && [ ! -d "$(dirname "$STATE_ROOT")" ]; then
    echo "error: state root cannot be created: $STATE_ROOT" >&2
    exit 1
fi

# All parsing, digest and size verification, and the write itself, live in the
# python contract. Exit code 0 means every verified artifact is restored and
# nothing was overwritten.
exec "$PYTHON" -m runtime.cli backup-restore \
    --backup "$BACKUP_DIR" \
    --state-root "$STATE_ROOT" \
    --control-env-dir "$CONTROL_ENV_DIR"
