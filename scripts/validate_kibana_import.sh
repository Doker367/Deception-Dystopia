#!/usr/bin/env bash
# ============================================================================
# Dystopia - validación reproducible del bundle canónico de Kibana.
#
# Levanta un stack EFÍMERO de Elasticsearch + Kibana 9.3.5 con secretos
# aleatorios en un directorio temporal, ejecuta el bootstrap de seguridad,
# importa deploy/kibana-dashboards/artifacts/deception-kibana-bundle.ndjson
# y comprueba que se importan 53/53 objetos sin errores.
#
# USO:
#   ./scripts/validate_kibana_import.sh
#
# Variables opcionales (sin secretos):
#   ELASTIC_HTTP_PORT       puerto host de Elasticsearch (def. 19201)
#   KIBANA_HTTP_PORT        puerto host de Kibana        (def. 15602)
#   KIBANA_CI_SUMMARY_FILE  resumen de resultado (def. <repo>/ci-artifacts/
#                           kibana-import-summary.txt)
#   KIBANA_CI_KEEP_TMP=1    conserva el temporal (solo para depurar; NUNCA en CI)
#
# Requisitos: docker + docker compose v2, curl, openssl, python3.
# Funciona en macOS con Docker Desktop/Colima y en Linux (runner Ubuntu).
#
# SEGURIDAD: los secretos se generan con openssl, viven SOLO en el .env del
# directorio temporal (0600) y nunca se imprimen. El trap apaga el stack y
# borra el temporal. No toca volúmenes de otros proyectos: usa un nombre de
# proyecto Compose único y `down` sin `-v`.
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_EXAMPLE="${REPO_ROOT}/deploy/elastic/.env.example"
COMPOSE_FILE="${REPO_ROOT}/deploy/elastic/docker-compose.elastic.yml"
CERTS_GEN="${REPO_ROOT}/deploy/elastic/scripts/generate-certs.sh"
BOOTSTRAP="${REPO_ROOT}/deploy/elastic/scripts/bootstrap-security.sh"
BUNDLE="${REPO_ROOT}/deploy/kibana-dashboards/artifacts/deception-kibana-bundle.ndjson"

ELASTIC_VERSION="${KIBANA_CI_ELASTIC_VERSION:-9.3.5}"
ELASTIC_HTTP_PORT="${ELASTIC_HTTP_PORT:-19201}"
KIBANA_HTTP_PORT="${KIBANA_HTTP_PORT:-15602}"
ES_URL="https://127.0.0.1:${ELASTIC_HTTP_PORT}"
KIBANA_URL="http://127.0.0.1:${KIBANA_HTTP_PORT}"
WAIT_TIMEOUT="${KIBANA_CI_WAIT_TIMEOUT:-240}"
EXPECTED_OBJECTS=53
SUMMARY_FILE="${KIBANA_CI_SUMMARY_FILE:-${REPO_ROOT}/ci-artifacts/kibana-import-summary.txt}"

log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- preflight
need() {
  command -v "$1" >/dev/null 2>&1 || die "falta '$1' en PATH"
}

need docker
need curl
need openssl
need python3

for f in "${ENV_EXAMPLE}" "${COMPOSE_FILE}" "${CERTS_GEN}" "${BOOTSTRAP}" "${BUNDLE}"; do
  [ -f "${f}" ] || die "falta el fichero requerido: ${f}"
done

docker info >/dev/null 2>&1 || die "el demonio Docker no responde (¿Docker Desktop/Colima arrancado?)"
docker compose version >/dev/null 2>&1 || die "falta 'docker compose' v2"

# Puertos libres en 127.0.0.1 (un laboratorio local puede estar usando 9200/5601).
python3 - "${ELASTIC_HTTP_PORT}" "${KIBANA_HTTP_PORT}" <<'PY' || die "puerto ocupado: exporta ELASTIC_HTTP_PORT/KIBANA_HTTP_PORT libres"
import socket, sys
for raw in sys.argv[1:]:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", int(raw)))
    except OSError as exc:
        print(f"[FAIL] 127.0.0.1:{raw} no disponible: {exc}", file=sys.stderr)
        raise SystemExit(1)
    finally:
        s.close()
PY

# vm.max_map_count: obligatorio en Linux; en macOS lo aplica la VM de Docker.
if [ "$(uname -s)" = "Linux" ]; then
  current="$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)"
  if [ "${current}" -lt 262144 ]; then
    warn "vm.max_map_count=${current} (<262144). Ejecuta: sudo sysctl -w vm.max_map_count=262144"
  fi
fi

# ---------------------------------------------------------------- proyecto
# Base del temporal: en macOS Docker Desktop/Colima solo comparte rutas del
# HOME por defecto (/tmp queda fuera del file sharing y el bind mount aparece
# root:root sin permisos para el uid 1000 de Elasticsearch). En Linux /tmp
# funciona y es lo esperado en CI.
if [ "$(uname -s)" = "Darwin" ]; then
  TMP_BASE="${KIBANA_CI_TMP_BASE:-${HOME}/.cache}"
else
  TMP_BASE="${KIBANA_CI_TMP_BASE:-${TMPDIR:-/tmp}}"
fi
mkdir -p "${TMP_BASE}"
TMP_DIR="$(mktemp -d "${TMP_BASE%/}/dystopia-kibana-ci.XXXXXX")"
chmod 700 "${TMP_DIR}"
PROJECT_NAME="dystopia-kibana-ci-$(basename "${TMP_DIR}" | tr -cd 'a-zA-Z0-9' | tr 'A-Z' 'a-z')"
ENV_FILE="${TMP_DIR}/.env"
CERTS_DIR="${TMP_DIR}/certs"
DATA_DIR="${TMP_DIR}/data"
KIBANA_DATA_DIR="${DATA_DIR}/kibana"
ES_DATA_DIR="${DATA_DIR}/elastic"
API_KEY_DIR="${TMP_DIR}/api-keys"
OVERRIDE_FILE="${TMP_DIR}/compose.override.yml"
COMPOSE_LOG="${TMP_DIR}/compose.log"
IMPORT_JSON="${TMP_DIR}/import-response.json"
COMPOSE_STARTED=0

mkdir -p "${DATA_DIR}" "${KIBANA_DATA_DIR}" "${ES_DATA_DIR}" "${API_KEY_DIR}" "${CERTS_DIR}"
chmod 700 "${API_KEY_DIR}" "${CERTS_DIR}"

write_summary() {
  # $1 = resultado, $2 = detalle. Nunca incluye secretos.
  mkdir -p "$(dirname "${SUMMARY_FILE}")"
  {
    echo "dystopia-kibana-import"
    echo "result: $1"
    echo "detail: $2"
    echo "target: elasticsearch/kibana ${ELASTIC_VERSION}"
    echo "ports: elastic=${ELASTIC_HTTP_PORT} kibana=${KIBANA_HTTP_PORT}"
    echo "bundle: deploy/kibana-dashboards/artifacts/deception-kibana-bundle.ndjson"
    echo "expected_objects: ${EXPECTED_OBJECTS}"
    echo "runner: $(uname -s)/$(uname -m)"
    echo "finished_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "${SUMMARY_FILE}"
}

redact() {
  # Sustituye los secretos conocidos por *** en un fichero de log.
  local f="$1"
  [ -f "${f}" ] || return 0
  local secret
  for secret in "${ELASTIC_PASSWORD}" "${KIBANA_SYSTEM_PASSWORD}" \
                "${DECEPTION_WRITER_PASSWORD}" "${DECEPTION_ANALYST_PASSWORD}" \
                "${DECEPTION_ADMIN_PASSWORD}" "${ELASTIC_CA_PASSPHRASE}" \
                "${KIBANA_SAVED_OBJECTS_ENCRYPTION_KEY}" \
                "${KIBANA_SECURE_SAVED_OBJECTS_ENCRYPTION_KEY}"; do
    [ -n "${secret}" ] && sed -i.bak "s|${secret}|***|g" "${f}" 2>/dev/null || true
  done
  rm -f "${f}.bak"
}

append_diagnostics() {
  # Añade al resumen un diagnóstico sin secretos.
  {
    echo "--- diagnostics ---"
    docker compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}" -f "${OVERRIDE_FILE}" \
      --profile deception-elastic --env-file "${ENV_FILE}" ps 2>&1 || true
    redact "${COMPOSE_LOG}"
    tail -n 40 "${COMPOSE_LOG}" 2>/dev/null || true
    docker compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}" -f "${OVERRIDE_FILE}" \
      --profile deception-elastic --env-file "${ENV_FILE}" logs --no-color --tail 60 2>&1 || true
  } 2>&1 | python3 -c '
import sys
for line in sys.stdin:
    for secret in sys.argv[1:]:
        if secret:
            line = line.replace(secret, "***")
    sys.stdout.write(line)
' "${ELASTIC_PASSWORD}" "${KIBANA_SYSTEM_PASSWORD}" "${DECEPTION_WRITER_PASSWORD}" \
  "${DECEPTION_ANALYST_PASSWORD}" "${DECEPTION_ADMIN_PASSWORD}" "${ELASTIC_CA_PASSPHRASE}" \
  "${KIBANA_SAVED_OBJECTS_ENCRYPTION_KEY}" "${KIBANA_SECURE_SAVED_OBJECTS_ENCRYPTION_KEY}" \
    >> "${SUMMARY_FILE}" 2>/dev/null || true
}

cleanup() {
  local status=$?
  set +e
  set +u
  # Diagnóstico ANTES de apagar: si no, los contenedores ya no existen.
  if [ "${status}" -ne 0 ] && [ -n "${TMP_DIR:-}" ]; then
    write_summary "FAIL" "ver diagnóstico adjunto y la salida del job"
    append_diagnostics
  fi
  if [ "${COMPOSE_STARTED}" = "1" ]; then
    log "apagando stack efímero (proyecto ${PROJECT_NAME})..."
    docker compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}" -f "${OVERRIDE_FILE}" \
      --profile deception-elastic --env-file "${ENV_FILE}" down --remove-orphans --timeout 60 >>"${COMPOSE_LOG}" 2>&1
  fi
  if [ "${status}" -eq 0 ]; then
    write_summary "PASS" "import ${EXPECTED_OBJECTS}/${EXPECTED_OBJECTS}; data stream y Kibana OK"
  fi
  if [ "${KIBANA_CI_KEEP_TMP:-0}" = "1" ]; then
    warn "KIBANA_CI_KEEP_TMP=1: se conserva ${TMP_DIR} (contiene secretos de prueba; bórralo tú)"
  else
    if ! rm -rf "${TMP_DIR}" 2>/dev/null; then
      # Directorios creados por el contenedor (uid 1000): limpiar con sudo si es passwordless.
      if sudo -n rm -rf "${TMP_DIR}" 2>/dev/null; then
        :
      else
        warn "no se pudo borrar ${TMP_DIR} (permisos de uid 1000); bórralo manualmente"
      fi
    fi
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---------------------------------------------------------------- secretos
# Solo hex + un sufijo alfanumérico: seguro para .env sin comillas ni escapes.
rand_secret() { printf '%s-Ci9x' "$(openssl rand -hex "${1:-24}")"; }
ELASTIC_PASSWORD="$(rand_secret 24)"
KIBANA_SYSTEM_PASSWORD="$(rand_secret 24)"
DECEPTION_WRITER_PASSWORD="$(rand_secret 20)"
DECEPTION_ANALYST_PASSWORD="$(rand_secret 20)"
DECEPTION_ADMIN_PASSWORD="$(rand_secret 20)"
ELASTIC_CA_PASSPHRASE="$(rand_secret 24)"
KIBANA_SAVED_OBJECTS_ENCRYPTION_KEY="$(openssl rand -hex 32)"
KIBANA_SECURE_SAVED_OBJECTS_ENCRYPTION_KEY="$(openssl rand -hex 32)"

# ---------------------------------------------------------------- .env
CI_ELASTIC_VERSION="${ELASTIC_VERSION}" \
CI_JAVA_OPTS="-Xms2048m -Xmx2048m" \
CI_ELASTIC_PASSWORD="${ELASTIC_PASSWORD}" \
CI_KIBANA_SYSTEM_PASSWORD="${KIBANA_SYSTEM_PASSWORD}" \
CI_DECEPTION_WRITER_PASSWORD="${DECEPTION_WRITER_PASSWORD}" \
CI_DECEPTION_ANALYST_PASSWORD="${DECEPTION_ANALYST_PASSWORD}" \
CI_DECEPTION_ADMIN_PASSWORD="${DECEPTION_ADMIN_PASSWORD}" \
CI_CA_PASSPHRASE="${ELASTIC_CA_PASSPHRASE}" \
CI_KIBANA_SO_KEY="${KIBANA_SAVED_OBJECTS_ENCRYPTION_KEY}" \
CI_KIBANA_SECURE_KEY="${KIBANA_SECURE_SAVED_OBJECTS_ENCRYPTION_KEY}" \
CI_ES_DATA_DIR="${ES_DATA_DIR}" \
CI_KIBANA_DATA_DIR="${KIBANA_DATA_DIR}" \
CI_CERTS_DIR="${CERTS_DIR}" \
CI_API_KEY_DIR="${API_KEY_DIR}" \
CI_API_KEY_FILE="${API_KEY_DIR}/deception-ingest-writer.api-key" \
CI_ELASTIC_PORT="${ELASTIC_HTTP_PORT}" \
CI_KIBANA_PORT="${KIBANA_HTTP_PORT}" \
CI_KIBANA_PUBLIC_URL="${KIBANA_URL}" \
python3 - "${ENV_EXAMPLE}" "${ENV_FILE}" <<'PY'
import os, sys

src, dst = sys.argv[1], sys.argv[2]
overrides = {
    "ELASTIC_VERSION": os.environ["CI_ELASTIC_VERSION"],
    "ELASTIC_JAVA_OPTS": os.environ["CI_JAVA_OPTS"],
    "ELASTIC_PASSWORD": os.environ["CI_ELASTIC_PASSWORD"],
    "KIBANA_SYSTEM_PASSWORD": os.environ["CI_KIBANA_SYSTEM_PASSWORD"],
    "KIBANA_SAVED_OBJECTS_ENCRYPTION_KEY": os.environ["CI_KIBANA_SO_KEY"],
    "KIBANA_SECURE_SAVED_OBJECTS_ENCRYPTION_KEY": os.environ["CI_KIBANA_SECURE_KEY"],
    "ELASTIC_DATA_DIR": os.environ["CI_ES_DATA_DIR"],
    "KIBANA_DATA_DIR": os.environ["CI_KIBANA_DATA_DIR"],
    "ELASTIC_CERTS_DIR": os.environ["CI_CERTS_DIR"],
    "ELASTIC_HTTP_PORT": os.environ["CI_ELASTIC_PORT"],
    "KIBANA_HTTP_PORT": os.environ["CI_KIBANA_PORT"],
    "KIBANA_PUBLIC_BASE_URL": os.environ["CI_KIBANA_PUBLIC_URL"],
    "DECEPTION_WRITER_PASSWORD": os.environ["CI_DECEPTION_WRITER_PASSWORD"],
    "DECEPTION_ANALYST_PASSWORD": os.environ["CI_DECEPTION_ANALYST_PASSWORD"],
    "DECEPTION_ADMIN_PASSWORD": os.environ["CI_DECEPTION_ADMIN_PASSWORD"],
    "ELASTIC_CA_PASSPHRASE": os.environ["CI_CA_PASSPHRASE"],
    "ELASTIC_API_KEY_DIR": os.environ["CI_API_KEY_DIR"],
    "DYSTOPIA_ELASTIC_API_KEY_FILE": os.environ["CI_API_KEY_FILE"],
}
lines = []
with open(src, encoding="utf-8") as fh:
    for line in fh:
        key, sep, _ = line.partition("=")
        if sep and not line.lstrip().startswith("#"):
            key = key.strip()
            if key in overrides:
                value = overrides[key]
                # ELASTIC_JAVA_OPTS contiene espacios: el .env se hace `source`
                # en generate-certs/bootstrap, así que debe ir entre comillas.
                if key == "ELASTIC_JAVA_OPTS":
                    lines.append(f"{key}=\"{value}\"\n")
                else:
                    lines.append(f"{key}={value}\n")
                continue
        lines.append(line)
fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    fh.writelines(lines)
PY

log "entorno temporal preparado en ${TMP_DIR} (.env 0600, secretos aleatorios)"

# Override del compose SOLO en el temporal: nombres de contenedor únicos para
# no colisionar con un laboratorio local que use el mismo compose versionado.
cat > "${OVERRIDE_FILE}" <<EOF
services:
  elasticsearch:
    container_name: ${PROJECT_NAME}-elasticsearch
  kibana:
    container_name: ${PROJECT_NAME}-kibana
EOF

compose() {
  docker compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}" -f "${OVERRIDE_FILE}" \
    --profile deception-elastic --env-file "${ENV_FILE}" "$@"
}

# ---------------------------------------------------------------- certificados
log "generando certificados TLS efímeros..."
ENV_FILE="${ENV_FILE}" ELASTIC_CERTS_DIR="${CERTS_DIR}" \
  bash "${CERTS_GEN}" >>"${COMPOSE_LOG}" 2>&1 || die "generate-certs.sh falló (ver ${SUMMARY_FILE})"

# Permisos: el contenedor corre como uid 1000. En Linux el bind mount exige
# ownership real; en macOS Docker Desktop/Colima lo abstrae.
chmod 755 "${CERTS_DIR}" "${DATA_DIR}" "${ES_DATA_DIR}" "${KIBANA_DATA_DIR}"
chmod 644 "${CERTS_DIR}"/*.crt "${CERTS_DIR}"/*.pem 2>/dev/null || true
chmod 640 "${CERTS_DIR}"/*.key 2>/dev/null || true
if [ "$(uname -s)" = "Linux" ]; then
  if sudo -n true 2>/dev/null; then
    sudo -n chown -R 1000:1000 "${CERTS_DIR}" "${DATA_DIR}" \
      || die "no se pudo asignar uid 1000 a certs/data (requerido por los contenedores)"
  else
    # Sin sudo no se puede chown: permisos de PRUEBA para que el uid 1000
    # pueda leer la key y escribir en el data dir. Todo vive en un temporal 0700.
    warn "sin sudo passwordless: aplicando permisos de prueba (keys 0644, data 0777)"
    chmod 644 "${CERTS_DIR}"/*.key 2>/dev/null || true
    chmod 777 "${DATA_DIR}" "${ES_DATA_DIR}" "${KIBANA_DATA_DIR}"
  fi
fi

# ---------------------------------------------------------------- arranque
log "arrancando Elasticsearch ${ELASTIC_VERSION} (puerto ${ELASTIC_HTTP_PORT})..."
COMPOSE_STARTED=1
compose up -d elasticsearch >>"${COMPOSE_LOG}" 2>&1 || die "docker compose up (elasticsearch) falló"

curl_es() {
  # $1 = method, $2 = path, $3 = fichero salida. Credenciales por stdin (-K -)
  # para no exponerlas en argv.
  printf 'user = "%s:%s"\n' "elastic" "${ELASTIC_PASSWORD}" \
    | curl -sS --max-time 15 --cacert "${CERTS_DIR}/ca.crt" -K - \
        -X "$1" -o "$3" -w '%{http_code}' "${ES_URL}$2" 2>/dev/null || true
}

wait_es() {
  local deadline=$((SECONDS + WAIT_TIMEOUT))
  local code
  log "esperando Elasticsearch en ${ES_URL} (máx ${WAIT_TIMEOUT}s)..."
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    code="$(curl_es GET /_cluster/health "${TMP_DIR}/es-health.json")"
    case "${code}" in
      200) log "Elasticsearch disponible (HTTP 200)"; return 0 ;;
      401) die "Elasticsearch rechaza la autenticación (HTTP 401): .env temporal inconsistente" ;;
    esac
    sleep 5
  done
  return 1
}

KIBANA_STATUS_JSON="${TMP_DIR}/kibana-status.json"
wait_kibana() {
  local deadline=$((SECONDS + WAIT_TIMEOUT))
  local code
  log "esperando Kibana en ${KIBANA_URL} (máx ${WAIT_TIMEOUT}s)..."
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    code="$(curl -sS -o "${KIBANA_STATUS_JSON}" -w '%{http_code}' --max-time 10 \
      "${KIBANA_URL}/api/status" 2>/dev/null || true)"
    if [ "${code}" = "200" ]; then
      log "Kibana disponible (HTTP 200)"
      return 0
    fi
    sleep 5
  done
  return 1
}

if ! wait_es; then
  die "Elasticsearch no respondió en ${WAIT_TIMEOUT}s"
fi

log "arrancando Kibana ${ELASTIC_VERSION} (puerto ${KIBANA_HTTP_PORT})..."
compose up -d --no-deps kibana >>"${COMPOSE_LOG}" 2>&1 || die "docker compose up (kibana) falló"

# Kibana no puede quedar 'available' hasta que kibana_system tenga la password
# del .env: el bootstrap debe correr antes de esperar /api/status.
log "ejecutando bootstrap-security.sh --all..."
ENV_FILE="${ENV_FILE}" ELASTIC_CERTS_DIR="${CERTS_DIR}" ES_URL="${ES_URL}" \
  ES_CA_CERT="${CERTS_DIR}/ca.crt" ELASTIC_API_KEY_DIR="${API_KEY_DIR}" \
  bash "${BOOTSTRAP}" --all >>"${COMPOSE_LOG}" 2>&1 \
  || die "bootstrap-security.sh --all falló (ver ${SUMMARY_FILE})"

if ! wait_kibana; then
  die "Kibana no respondió en ${WAIT_TIMEOUT}s"
fi

python3 - "${KIBANA_STATUS_JSON}" <<'PY' || die "Kibana /api/status no está 'available'"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
level = d.get("status", {}).get("overall", {}).get("level")
if level != "available":
    raise SystemExit(f"Kibana status={level!r}")
PY

# ---------------------------------------------------------------- import
log "importando el bundle canónico con deception_admin (overwrite=true)..."
IMPORT_CODE=""
attempt=1
while [ "${attempt}" -le 10 ]; do
  IMPORT_CODE="$(printf 'user = "%s:%s"\n' "deception_admin" "${DECEPTION_ADMIN_PASSWORD}" \
    | curl -sS --max-time 180 -K - \
        -o "${IMPORT_JSON}" -w '%{http_code}' \
        -X POST "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
        -H 'kbn-xsrf: true' \
        -F "file=@${BUNDLE};type=application/ndjson" 2>/dev/null || true)"
  if [ "${IMPORT_CODE}" = "200" ]; then
    break
  fi
  # 401/503 transitorios: Kibana puede reportar 'available' antes de que su
  # caché de autenticación contra Elasticsearch esté caliente.
  log "intento ${attempt}/10: import HTTP ${IMPORT_CODE}"
  attempt=$((attempt + 1))
  if [ "${attempt}" -le 10 ]; then
    log "reintentando en 5s..."
    sleep 5
  fi
done

if [ "${IMPORT_CODE}" != "200" ]; then
  {
    echo "[DIAG] respuesta del import (HTTP ${IMPORT_CODE}):"
    head -c 1500 "${IMPORT_JSON}" 2>/dev/null || true
    echo
  } >>"${COMPOSE_LOG}"
  # Distinguir credenciales inválidas de un fallo de la API de Kibana.
  AUTH_CODE="$(printf 'user = "%s:%s"\n' "deception_admin" "${DECEPTION_ADMIN_PASSWORD}" \
    | curl -sS --max-time 15 --cacert "${CERTS_DIR}/ca.crt" -K - \
        -o "${TMP_DIR}/es-auth.json" -w '%{http_code}' \
        "${ES_URL}/_security/_authenticate" 2>/dev/null || true)"
  die "import HTTP ${IMPORT_CODE} tras 10 intentos; ES _security/_authenticate (deception_admin) -> HTTP ${AUTH_CODE}"
fi

if ! python3 - "${IMPORT_JSON}" "${EXPECTED_OBJECTS}" <<'PY'
import json, sys
path, expected = sys.argv[1], int(sys.argv[2])
with open(path, encoding="utf-8") as fh:
    data = json.load(fh)
errors = data.get("errors") or []
ok = (
    data.get("success") is True
    and data.get("successCount") == expected
    and not errors
)
print(f"[INFO] import: success={data.get('success')} "
      f"successCount={data.get('successCount')}/{expected} errors={len(errors)}")
if not ok:
    for err in errors[:5]:
        print(f"[FAIL] {err.get('id')}: {err.get('error', {}).get('message', err)}",
              file=sys.stderr)
    raise SystemExit(1)
PY
then
  {
    echo "[DIAG] respuesta del import no válida:"
    head -c 1500 "${IMPORT_JSON}" 2>/dev/null || true
    echo
  } >>"${COMPOSE_LOG}"
  die "el import no devolvió ${EXPECTED_OBJECTS}/${EXPECTED_OBJECTS} objetos sin errores"
fi

# ---------------------------------------------------------------- postchecks
DS_JSON="${TMP_DIR}/data-stream.json"
DS_CODE="$(curl_es GET "/_data_stream/deception-events" "${DS_JSON}")"
[ "${DS_CODE}" = "200" ] || die "GET /_data_stream/deception-events -> HTTP ${DS_CODE}"
python3 - "${DS_JSON}" <<'PY' || die "el data stream deception-events no existe o está mal formado"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
names = [ds.get("name") for ds in d.get("data_streams", [])]
if "deception-events" not in names:
    raise SystemExit(f"data_streams={names!r}")
print(f"[INFO] data stream OK: {names}")
PY

log "validación completa: ${EXPECTED_OBJECTS}/${EXPECTED_OBJECTS} objetos, data stream y Kibana OK"
exit 0
