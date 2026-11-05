#!/usr/bin/env bash
# ============================================================================
# Dystopia - provision the read-only API key used by the analytics BFF.
#
# Prerequisite: the `deception-analyst` role exists (bootstrap-security.sh
# --install-roles) and deploy/elastic/.env contains ELASTIC_PASSWORD and the
# CA/key paths. This script never prints the encoded key.
#
# Usage:
#   ENV_FILE=deploy/elastic/.env ./deploy/elastic/scripts/create-analytics-key.sh
#
# The output file is 0600 and must stay outside the repository. The web
# frontend never receives this value; only FastAPI reads it.
# ============================================================================
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/../.env}"
ES_URL="${ES_URL:-https://127.0.0.1:9200}"
CA_FILE="${CA_FILE:-${ROOT_DIR}/deploy/elastic/certs/ca.crt}"
KEY_DIR="${KEY_DIR:-${ROOT_DIR}/deploy/elastic/api-keys}"
KEY_FILE="${KEY_FILE:-${KEY_DIR}/dystopia-analytics-reader.api-key}"
ROLE_FILE="${ROLE_FILE:-${ROOT_DIR}/deploy/elastic/roles/deception-analyst.json}"
KEY_NAME="dystopia-analytics-reader"

[ -f "${ENV_FILE}" ] || { echo "[FATAL] falta ${ENV_FILE}" >&2; exit 2; }
[ -f "${CA_FILE}" ] || { echo "[FATAL] falta ${CA_FILE}" >&2; exit 2; }
[ -f "${ROLE_FILE}" ] || { echo "[FATAL] falta ${ROLE_FILE}" >&2; exit 2; }
set -a; . "${ENV_FILE}"; set +a
: "${ELASTIC_PASSWORD:?ELASTIC_PASSWORD requerido}"

mkdir -p "${KEY_DIR}"
chmod 0700 "${KEY_DIR}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

python3 - "${ROLE_FILE}" "${KEY_NAME}" > "${WORK}/key.json" <<'PY'
import json, sys
role = json.load(open(sys.argv[1]))
for key in ("_doc", "_doc_2", "metadata", "run_as"):
    role.pop(key, None)
payload = {"name": sys.argv[2], "role_descriptors": {"deception-analyst": role}}
print(json.dumps(payload, separators=(",", ":")))
PY
chmod 0600 "${WORK}/key.json"

existing="$(curl -fsS --cacert "${CA_FILE}" -u "elastic:${ELASTIC_PASSWORD}" \
  "${ES_URL}/_security/api_key?name=${KEY_NAME}&active_only=true")"
ids="$(printf '%s' "${existing}" | python3 -c 'import json,sys; print(json.dumps([k["id"] for k in json.load(sys.stdin).get("api_keys", []) if k.get("name") == "dystopia-analytics-reader"]))')"
if [ "${ids}" != "[]" ]; then
  printf '{"ids": %s}' "${ids}" > "${WORK}/invalidate.json"
  curl -fsS --cacert "${CA_FILE}" -u "elastic:${ELASTIC_PASSWORD}" -X DELETE \
    "${ES_URL}/_security/api_key" -H 'Content-Type: application/json' \
    --data-binary "@${WORK}/invalidate.json" >/dev/null
  rm -f "${WORK}/invalidate.json"
  echo "[OK] key anterior ${KEY_NAME} invalidada"
fi

curl -fsS --cacert "${CA_FILE}" -u "elastic:${ELASTIC_PASSWORD}" -X POST \
  "${ES_URL}/_security/api_key" -H 'Content-Type: application/json' \
  --data-binary "@${WORK}/key.json" > "${WORK}/out.json"
python3 - "${WORK}/out.json" "${KEY_FILE}" <<'PY'
import json, os, sys
payload = json.load(open(sys.argv[1]))
encoded = payload.get("encoded")
if not encoded:
    raise SystemExit("la respuesta de Elasticsearch no contiene encoded")
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    fh.write(encoded + "\n")
os.chmod(sys.argv[2], 0o600)
PY

key="$(cat "${KEY_FILE}")"
curl -fsS --cacert "${CA_FILE}" -H "Authorization: ApiKey ${key}" \
  "${ES_URL}/_security/_authenticate" >/dev/null
echo "[OK] key ${KEY_NAME} escrita en ${KEY_FILE} (0600, no mostrada)"
