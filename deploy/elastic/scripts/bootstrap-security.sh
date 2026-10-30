#!/usr/bin/env bash
# ============================================================================
# Dystopia - bootstrap de seguridad y contratos de índices para Elasticsearch.
#
# NO autoejecutable. Fat:  chmod +x bootstrap-security.sh
# Requisitos: deploy/elastic/.env relleno (plantilla .env.example),
#             generate-certs.sh YA ejecutado, Elasticsearch (y Kibana) ya
#             arrancados TLS por el operador vía docker-compose.elastic.yml,
#             curl, python3 en el host (SOLO stdlib).
#
# Qué hace (idempotente, sin secretos por stdout):
#   --install-roles    crea roles deception-ingest-writer / deception-analyst
#                      / deception-admin desde deploy/elastic/roles/*.json
#   --create-users     password-reset de kibana_system + usuarios funcionales
#                      deception_writer / deception_analyst / deception_admin
#   --create-api-key   (re)crea la API key least-privilege del publicador y
#                      la escribe en ELASTIC_API_KEY_DIR (nunca por stdout)
#   --install-templates ILM policies + index templates (data streams)
#   --all              (por defecto) los cuatro pasos
#
# Respeta la separación de roles:
#   * elastic (superusuario) SOLO ejecuta este bootstrap.
#   * El operador diario usa deception_admin (sin manage_security).
#   * El writer de ingesta NO tiene acceso a Kibana de ninguna manera.
# ============================================================================

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/.env}"
CERTS_DIR="${ELASTIC_CERTS_DIR:-${SCRIPT_DIR}/certs}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
ROLES_DIR="${SCRIPT_DIR}/../roles"
TEMPLATES_DIR="${ROOT_DIR}/config/elasticsearch/templates"
ILM_DIR="${ROOT_DIR}/config/elasticsearch/ilm"

[ -f "${ENV_FILE}" ] || { echo "[FATAL] falta ${ENV_FILE} (copio .env.example y relleno)" >&2; exit 2; }
set -a; . "${ENV_FILE}"; set +a

: "${ELASTIC_VERSION:?ELASTIC_VERSION requerido}"
: "${ELASTIC_PASSWORD:?ELASTIC_PASSWORD requerido}"
: "${KIBANA_SYSTEM_PASSWORD:?KIBANA_SYSTEM_PASSWORD requerido (mín 6, recomendado 16+)}"
: "${DECEPTION_WRITER_PASSWORD:?DECEPTION_WRITER_PASSWORD requerido}"
: "${DECEPTION_ANALYST_PASSWORD:?DECEPTION_ANALYST_PASSWORD requerido}"
: "${DECEPTION_ADMIN_PASSWORD:?DECEPTION_ADMIN_PASSWORD requerido}"
: "${ILM_DECEPTION_EVENTS_DAYS:=30}"
: "${ILM_DECEPTION_ALERTS_DAYS:=90}"
: "${ES_URL:=https://127.0.0.1:${ELASTIC_HTTP_PORT:-9200}}"
: "${ES_CA_CERT:=${CERTS_DIR}/ca.crt}"
: "${ELASTIC_API_KEY_DIR:=${SCRIPT_DIR}/api-keys}"

MODE="${1:---all}"
ES_AUTH="elastic:${ELASTIC_PASSWORD}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

es() {
  # es METHOD PATH [BODY] -> JSON; falla si HTTP>=400.
  # Evita expandir un array vacío: Bash 3.2/macOS lo rechaza con set -u.
  local method="$1" path="$2"; shift 2
  if [ "$#" -gt 0 ]; then
    curl -fsS -X "${method}" "${ES_URL}${path}" \
      --cacert "${ES_CA_CERT}" \
      -u "${ES_AUTH}" \
      -H 'Content-Type: application/json' \
      --data-binary "@$1" 2>&1
  else
    curl -fsS -X "${method}" "${ES_URL}${path}" \
      --cacert "${ES_CA_CERT}" \
      -u "${ES_AUTH}" \
      -H 'Content-Type: application/json' 2>&1
  fi
}

wait_for_es() {
  echo "[INFO] esperando clúster en ${ES_URL}..."
  local i
  for i in $(seq 1 30); do
    if es GET /_cluster/health >/dev/null 2>&1; then
      echo "[OK] clúster up"; return 0
    fi
    sleep 5
  done
  echo "[FATAL] clúster no respondió en 150s" >&2
  exit 3
}

# ---------------------------------------------------------------- roles/json
install_roles() {
  local json_strip='import json,sys; d=json.load(sys.stdin); d.pop("_doc",None); d.pop("_doc_2",None); [d.get("indices",[[]])[i].pop(k,None) for i,_ in enumerate(d.get("indices",[[]])) for k in ("_doc","_doc_2") if d.get("indices")]; print(json.dumps(d,separators=(",",":")))'
  local role
  for role in deception-ingest-writer deception-analyst deception-admin; do
    python3 -c "${json_strip}" < "${ROLES_DIR}/${role}.json" > "${WORK_DIR}/${role}.json"
    es PUT "/_security/role/${role}" "${WORK_DIR}/${role}.json" >/dev/null
    echo "[OK] rol ${role} creado/actualizado"
  done
}

# ---------------------------------------------------------------- users
set_password() {
  local user="$1" pass="$2"
  printf '{"password": %s}' "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${pass}")" > "${WORK_DIR}/pw.json"
  es PUT "/_security/user/${user}/_password" "${WORK_DIR}/pw.json" >/dev/null
  rm -f "${WORK_DIR}/pw.json"
}

create_user() {
  # args: <user> <roles_json_array> <full_name> <password>
  local user="$1" roles_json="$2" full_name="$3" password="$4"
  # Incluir password: Elasticsearch exige password al crear un usuario nuevo.
  # Al actualizar, el mismo PUT también rota la clave desde ENV_FILE.
  python3 -c "import json,sys; print(json.dumps({'enabled':True,'roles':json.loads(sys.argv[1]),'full_name':sys.argv[2],'password':sys.argv[3]}))" \
    "${roles_json}" "${full_name:-$user}" "${password}" > "${WORK_DIR}/user.json"
  chmod 0600 "${WORK_DIR}/user.json"
  es PUT "/_security/user/${user}" "${WORK_DIR}/user.json" >/dev/null
  rm -f "${WORK_DIR}/user.json"
  echo "[OK] usuario ${user} (password por ${ENV_FILE}, no mostrada)"
}

create_users() {
  set_password "kibana_system" "${KIBANA_SYSTEM_PASSWORD}"
  echo "[OK] password de kibana_system reseteada"
  create_user "deception_writer" '["deception-ingest-writer"]' "Ingesta normalizada Dystopia" "${DECEPTION_WRITER_PASSWORD}"
  create_user "deception_analyst" '["deception-analyst"]' "Analista SOC solo-lectura" "${DECEPTION_ANALYST_PASSWORD}"
  create_user "deception_admin" '["deception-admin"]' "Admin día-a-día panel" "${DECEPTION_ADMIN_PASSWORD}"
  cat <<PDONE

[REGISTRO] (NO mostrar aquí los valores):
 - kibana_system -> KIBANA_SYSTEM_PASSWORD (.env) para config/kibana/kibana.yml
 - deception_writer -> DECEPTION_WRITER_PASSWORD: SOLO pipeline/ingesta
 - deception_analyst -> DECEPTION_ANALYST_PASSWORD: personas analista, browser
 - deception_admin -> DECEPTION_ADMIN_PASSWORD: operador del panel
 Verificación manual posterior sugerida: curl --cacert ca.crt -u deception_analyst
 'https://127.0.0.1:9200/_security/user/_xpack/privilege/_has_privileges' -d '{"index":[{"name":"logs-*","privileges":["read"]}]}' -> expected unauthorized
PDONE
}

# ---------------------------------------------------------------- api key
create_api_key() {
  local name="dystopia-ingest-writer" key_file existing ids key_json
  key_file="${ELASTIC_API_KEY_DIR}/${name}.api-key"
  mkdir -p "${ELASTIC_API_KEY_DIR}"
  chmod 0700 "${ELASTIC_API_KEY_DIR}"

  # Rotación idempotente: desactivar keys previas con el mismo nombre.
  existing="$(es GET "/_security/api_key?name=${name}&active_only=true")"
  ids="$(printf '%s' "${existing}" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps([k["id"] for k in d.get("api_keys",[]) if k.get("name")=="dystopia-ingest-writer"]))')"
  if [ "${ids}" != "[]" ]; then
    printf '{"ids": %s}' "${ids}" > "${WORK_DIR}/invalidate.json"
    es DELETE "/_security/api_key" "${WORK_DIR}/invalidate.json" >/dev/null
    rm -f "${WORK_DIR}/invalidate.json"
    echo "[OK] API key previa ${name} invalidada"
  fi

  # Elasticsearch 9 no acepta "roles" en _security/api_key: la key incorpora
  # sus privilegios como role_descriptors. Se copia el rol mínimo del writer.
  python3 -c '
import json, sys
role = json.load(open(sys.argv[1]))
for key in ("_doc", "_doc_2", "metadata", "run_as"):
    role.pop(key, None)
payload = {"name": sys.argv[2], "role_descriptors": {"deception-ingest-writer": role}}
print(json.dumps(payload, separators=(",", ":")))
' "${ROLES_DIR}/deception-ingest-writer.json" "${name}" > "${WORK_DIR}/api-key.json"
  chmod 0600 "${WORK_DIR}/api-key.json"
  key_json="$(es POST "/_security/api_key" "${WORK_DIR}/api-key.json")"
  rm -f "${WORK_DIR}/api-key.json"
  printf '%s' "${key_json}" | python3 -c '
import json, os, sys
d = json.load(sys.stdin)
encoded = d.get("encoded")
if not encoded:
    raise SystemExit("API key response lacks encoded value")
path = sys.argv[1]
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    fh.write(encoded + "\n")
os.chmod(path, 0o600)
' "${key_file}"
  echo "[OK] API key ${name} escrita en ${key_file} (0600, no mostrada)"
  echo "[INFO] publicador: DYSTOPIA_ELASTIC_API_KEY_FILE=${key_file}"
}

# ---------------------------------------------------------------- templates + ILM
install_templates() {
  local f name
  name="deception-events-policy"
  python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
for k in ('_doc','_comment','_note'): d.pop(k,None)
d['policy']['phases']['delete']['min_age']=sys.argv[2]+'d'
print(json.dumps(d))" "${ILM_DIR}/${name}.json" "${ILM_DECEPTION_EVENTS_DAYS}" > "${WORK_DIR}/${name}.json"
  es PUT "/_ilm/policy/${name}" "${WORK_DIR}/${name}.json" >/dev/null
  echo "[OK] ILM ${name} (retención ${ILM_DECEPTION_EVENTS_DAYS}d)"

  name="deception-alerts-policy"
  python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
for k in ('_doc','_comment','_note'): d.pop(k,None)
d['policy']['phases']['delete']['min_age']=sys.argv[2]+'d'
print(json.dumps(d))" "${ILM_DIR}/${name}.json" "${ILM_DECEPTION_ALERTS_DAYS}" > "${WORK_DIR}/${name}.json"
  es PUT "/_ilm/policy/${name}" "${WORK_DIR}/${name}.json" >/dev/null
  echo "[OK] ILM ${name} (retención ${ILM_DECEPTION_ALERTS_DAYS}d)"

  for f in "${TEMPLATES_DIR}"/*.json; do
    name="$(python3 -c 'import json,sys; print(sys.argv[1].rsplit("/",1)[1].removesuffix("-template.json"))' "${f}")"
    python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
for k in ('_doc','_comment','_note'): d.pop(k,None)
def scrub(o):
  if isinstance(o,dict): return {k:scrub(v) for k,v in o.items() if not k.startswith(('_doc','_comment','_note'))}
  return o
d=scrub(d)
print(json.dumps(d))" "${f}" > "${WORK_DIR}/tmp-template.json"
    es PUT "/_index_template/${name}-template" "${WORK_DIR}/tmp-template.json" >/dev/null
    echo "[OK] index template ${name}-template instalado"
  done

  # Crear los data streams de forma explícita. Indexar en /<nombre>/_doc
  # cuando aún no existe crea un ÍNDICE PLANO, no un data stream, y deja el
  # patrón deception-events-* sin casar con el nombre deception-events.
  local ds
  for ds in deception-events deception-alerts; do
    if es GET "/_data_stream/${ds}" >/dev/null 2>&1; then
      echo "[OK] data stream ${ds} ya existía"
    else
      if es PUT "/_data_stream/${ds}" >/dev/null; then
        echo "[OK] data stream ${ds} creado"
      else
        echo "[WARN] data stream ${ds} no se pudo crear; revisar plantilla y dry-run" >&2
      fi
    fi
  done
}

wait_for_es

case "${MODE}" in
  --install-roles)      install_roles ;;
  --create-users)       create_users ;;
  --create-api-key)     create_api_key ;;
  --install-templates)  install_templates ;;
  --all)                install_roles; create_users; create_api_key; install_templates ;;
  *) echo "[FATAL] modo desconocido: ${MODE} (usar --install-roles | --create-users | --create-api-key | --install-templates | --all)" >&2; exit 2 ;;
esac

echo "[DONE] bootstrap terminado (modo=${MODE}). Validación recomendada: README.md"
