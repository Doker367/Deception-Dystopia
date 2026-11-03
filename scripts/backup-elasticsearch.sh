#!/usr/bin/env bash
# Elasticsearch snapshot/restore contract for the Dystopia analytics plane.
#
# THIS SCRIPT IS CONSERVATIVE AND NOT EXECUTABLE IN THIS ENVIRONMENT. It exits
# before touching anything unless Linux is confirmed at runtime. It only talks
# to an already-running container via `docker exec`; it never starts, stops,
# creates or removes containers, never runs compose and never changes the host
# or the cell environment. Secrets never traverse an argv or an inherited
# environment: curl reads its configuration (user, password, request body)
# from stdin.
#
# Usage:
#   scripts/backup-elasticsearch.sh register
#   scripts/backup-elasticsearch.sh verify
#   scripts/backup-elasticsearch.sh snapshot [NAME_SUFFIX]
#   scripts/backup-elasticsearch.sh list
#   scripts/backup-elasticsearch.sh restore SNAPSHOT_NAME
#
# Environment (defaults in parentheses):
#   DYSTOPIA_ELASTIC_CONTAINER  container name (dystopia-elasticsearch)
#   DYSTOPIA_SNAPSHOT_REPO_NAME repository name (dystopia-offline)
#   DYSTOPIA_SNAPSHOT_REPO_PATH REQUIRED absolute path inside the container; it
#                               must be a mounted, operator-owned volume kept
#                               offline-safe and outside this repository
#   DYSTOPIA_ES_USER            REST API user (elastic)
#   DYSTOPIA_ES_PASSWORD_FILE   REQUIRED file, mode 0600, holding the password
#   DYSTOPIA_ES_LOCAL_URL       URL inside the container (https://127.0.0.1:9200)
#   DYSTOPIA_ES_CACERT          CA bundle inside the container for https
#                               (/usr/share/elasticsearch/config/certs/ca.crt);
#                               ignored for http:// URLs
#   DYSTOPIA_SNAPSHOT_INDEX     index expression (deception-*)
#   DYSTOPIA_ES_RESTORE_CONFIRM must be the literal `restore` to restore
#
# Restore only writes renamed indices (restored-*) so nothing live is
# deleted or replaced implicitly; cutover is a separate reviewed step
# documented in docs/BACKUP-RESTORE.md.
set -euo pipefail

PLATFORM=$(uname -s)
if [ "$PLATFORM" != "Linux" ]; then
    echo "error: this contract only executes on Linux; refusing here ($PLATFORM)" >&2
    exit 3
fi

CONTAINER=${DYSTOPIA_ELASTIC_CONTAINER:-dystopia-elasticsearch}
REPO=${DYSTOPIA_SNAPSHOT_REPO_NAME:-dystopia-offline}
REPO_PATH=${DYSTOPIA_SNAPSHOT_REPO_PATH:-}
ES_USER=${DYSTOPIA_ES_USER:-elastic}
PASSWORD_FILE=${DYSTOPIA_ES_PASSWORD_FILE:-}
LOCAL_URL=${DYSTOPIA_ES_LOCAL_URL:-https://127.0.0.1:9200}
CACERT=${DYSTOPIA_ES_CACERT:-/usr/share/elasticsearch/config/certs/ca.crt}
INDEX_PATTERN=${DYSTOPIA_SNAPSHOT_INDEX:-deception-*}
RENAME_PATTERN=${DYSTOPIA_ES_RENAME_PATTERN:-deception-(.*)}
RENAME_REPLACEMENT=${DYSTOPIA_ES_RENAME_REPLACEMENT:-restored-deception-$1}

usage() { echo "usage: $0 register|verify|snapshot|list|restore [SNAPSHOT_NAME]" >&2; }

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    usage
    exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker CLI not found" >&2
    exit 1
fi
if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
    echo "error: container not present: $CONTAINER" >&2
    exit 1
fi
if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" != "true" ]; then
    echo "error: container is not running: $CONTAINER" >&2
    exit 1
fi
if [ -z "$REPO_PATH" ]; then
    echo "error: DYSTOPIA_SNAPSHOT_REPO_PATH is required" >&2
    exit 2
fi
if [ ! -f "$PASSWORD_FILE" ] || [ ! -r "$PASSWORD_FILE" ]; then
    echo "error: DYSTOPIA_ES_PASSWORD_FILE must name a readable file" >&2
    exit 2
fi

# All HTTP goes through curl reading its whole configuration from stdin, so no
# argv and no environment of any process ever carries the credentials.
es_api() {
    METHOD=$1
    PATHPART=$2
    BODY=${3:-}
    {
        printf 'user = "%s:%s"\n' "$ES_USER" "$(cat "$PASSWORD_FILE")"
        printf 'request = "%s"\n' "$METHOD"
        printf 'url = "%s%s"\n' "$LOCAL_URL" "$PATHPART"
        printf 'header = "Content-Type: application/json"\n'
        [ "${LOCAL_URL#https:}" = "$LOCAL_URL" ] || printf 'cacert = "%s"\n' "$CACERT"
        [ -z "$BODY" ] || printf 'data = %s\n' "$BODY"
    } | docker exec -i "$CONTAINER" curl --silent --show-error --fail --config -
    echo
}

ACTION=$1
SNAPSHOT_SUFFIX=${2:-}

case "$ACTION" in
    register)
        case "$REPO_PATH" in
            /*) ;;
            *) echo "error: DYSTOPIA_SNAPSHOT_REPO_PATH must be an absolute container path" >&2; exit 2 ;;
        esac
        es_api PUT "/_snapshot/$REPO" \
            "{\"type\":\"fs\",\"settings\":{\"location\":\"$REPO_PATH\",\"compress\":true}}"
        echo "repository registered: $REPO at $REPO_PATH; verify with the verify action"
        ;;
    verify)
        es_api GET "/_snapshot/$REPO"
        echo "operator check: the location above must equal $REPO_PATH"
        ;;
    list)
        es_api GET "/_snapshot/$REPO/_all"
        ;;
    snapshot)
        STAMP=${SNAPSHOT_SUFFIX:-$(date -u +%Y%m%dT%H%M%SZ)}
        case "$STAMP" in
            [a-z0-9._-]*) ;;
            *) echo "error: snapshot name must use [a-z0-9._-]*" >&2; exit 2 ;;
        esac
        es_api PUT "/_snapshot/$REPO/deception-$STAMP?wait_for_completion=true" \
            "{\"indices\":\"$INDEX_PATTERN\",\"ignore_unavailable\":true,\"include_global_state\":false}"
        echo "snapshot requested: deception-$STAMP; confirm with the list action and an offline copy"
        ;;
    restore)
        NAME=${SNAPSHOT_SUFFIX:-}
        case "$NAME" in
            [a-z0-9._-]*) ;;
            *) echo "error: restore requires an explicit SNAPSHOT_NAME" >&2; exit 2 ;;
        esac
        if [ "${DYSTOPIA_ES_RESTORE_CONFIRM:-}" != "restore" ]; then
            echo "error: refusing to restore without DYSTOPIA_ES_RESTORE_CONFIRM=restore" >&2
            usage
            exit 2
        fi
        es_api POST "/_snapshot/$REPO/$NAME/_restore?wait_for_completion=true" \
            "{\"indices\":\"$INDEX_PATTERN\",\"ignore_unavailable\":true,\"include_global_state\":false,\"rename_pattern\":\"$RENAME_PATTERN\",\"rename_replacement\":\"$RENAME_REPLACEMENT\"}"
        echo "restore requested for $NAME into restored-* indices; verify in Kibana before any cutover"
        ;;
    *)
        usage
        exit 2
        ;;
esac
