#!/usr/bin/env bash
# ============================================================================
# Dystopia - generación de certificados TLS para Elasticsearch (HTTP+transport)
# y material de confianza para Kibana.
#
# NO autoejecutable. Fat:  chmod +x generate-certs.sh && ./generate-certs.sh
# Requisitos: openssl en el host (macOS lo trae), fichero .env (copied
#            de .env.example con ELASTIC_CERTS_DIR/ELASTIC_VERSION).
#
# NO utiliza `latest` ni dependencias de imagen: certificados PKI con openssl
# servidor-side. Incluye SAN para:
#   * elasticsearch (hostname del servicio interno en Compose),
#   * 127.0.0.1 / ::1 / 0.0.0.0 (healthcheck y curl localhost en el nodo),
#   * DystopiaBool.Dystopia.Dystopia (placeholder DNS de gestión).
# El CA private key puede quedarse para rotar/reemitir; debe quedar en
# secretos operativos fuera del repo, NO en ELASTIC_CERTS_DIR del repo.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/.env}"
CERTS_DIR="${ELASTIC_CERTS_DIR:-${SCRIPT_DIR}/certs}"

# shellcheck source=./.env.example
[ -f "${ENV_FILE}" ] && set -a && . "${ENV_FILE}" && set +a

if [ -z "${ELASTIC_VERSION:-}" ]; then
  echo "[FATAL] ELASTIC_VERSION no está definido en ${ENV_FILE} (copiar .env.example a .env)" >&2
  exit 2
fi

FORCE="${1:-}"
if [ -d "${CERTS_DIR}" ] && ls "${CERTS_DIR}"/*.crt >/dev/null 2>&1; then
  if [ "${FORCE}" = "--force" ]; then
    echo "[WARN] sobrescribiendo certs existentes en ${CERTS_DIR} (--force)"
  else
    echo "[SKIP] ${CERTS_DIR} ya contiene certificados. Use: ./generate-certs.sh --force" >&2
    exit 1
  fi
fi

DAYS="${ELASTIC_CA_DAYS:-1825}"
CA_PASSPHRASE="${ELASTIC_CA_PASSPHRASE:-}"
if [ -z "${CA_PASSPHRASE}" ]; then
  echo "[FATAL] Definir ELASTIC_CA_PASSPHRASE en ${ENV_FILE} (frase única >= 20 chars; NO commit)." >&2
  exit 2
fi

mkdir -p "${CERTS_DIR}"
umask 077

# ----------------------------------------------------------------------
# 1) CA auto-firmada Dystopia Elastic (PKI de gestión, única por clúster).
# ----------------------------------------------------------------------
if [ ! -f "${CERTS_DIR}/ca.key" ]; then
  echo "[INFO] generando CA..."
  openssl genrsa -aes256 -passout "pass:${CA_PASSPHRASE}" -out "${CERTS_DIR}/ca.key" 4096
  openssl req -x509 -new -nodes -sha256 \
    -key "${CERTS_DIR}/ca.key" -passin "pass:${CA_PASSPHRASE}" \
    -days "${DAYS}" \
    -out "${CERTS_DIR}/ca.crt" \
    -subj "/C=ES/O=Dystopia/OU=Deception/CN=dystopia-elastic-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -addext "authorityKeyIdentifier=keyid:always"
fi

# ----------------------------------------------------------------------
# 2) Certificado de nodo para ELASTIC (HTTP + transport).
#    Claves PRIVADAS SIN passphrase: así elasticsearch no exige bootstrap de
#    keystore para xpack.security.*.key_passphrase; la protección es el
#    chmod 0600 que imponen umask 077 y el chmod -R 600 del final del
#    script, más el acceso local al host requerido para leer la clave.
#    La passphrase queda SOLO en la CA (cifrada), para rotación futura.
#    En producción: LUKS/Bitlocker/ACLs sobre ELASTIC_CERTS_DIR.
# ----------------------------------------------------------------------
echo "[INFO] generando certificado de nodo elasticsearch..."
openssl genrsa -out "${CERTS_DIR}/elasticsearch.key.new" 4096
openssl req -new -sha256 \
  -key "${CERTS_DIR}/elasticsearch.key.new" \
  -out "${CERTS_DIR}/elasticsearch.csr" \
  -subj "/C=ES/O=Dystopia/OU=Deception/CN=dystopia-elasticsearch"
# SANs combinados (SO indispensable en ES >=8 con verificación hostname).
cat > "${CERTS_DIR}/elasticsearch.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=DNS:elasticsearch,DNS:dystopia-elasticsearch,DNS:localhost,IP:127.0.0.1,IP:0.0.0.0
EOF
openssl x509 -req -sha256 \
  -in "${CERTS_DIR}/elasticsearch.csr" \
  -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" -passin "pass:${CA_PASSPHRASE}" \
  -CAcreateserial \
  -days 1095 \
  -extfile "${CERTS_DIR}/elasticsearch.ext" \
  -out "${CERTS_DIR}/elasticsearch.crt" && mv "${CERTS_DIR}/elasticsearch.key.new" "${CERTS_DIR}/elasticsearch.key"

echo "[INFO] generando certificado de nodo kibana..."
openssl genrsa -out "${CERTS_DIR}/kibana.key.new" 4096
openssl req -new -sha256 \
  -key "${CERTS_DIR}/kibana.key.new" \
  -out "${CERTS_DIR}/kibana.csr" \
  -subj "/C=ES/O=Dystopia/OU=Deception/CN=dystopia-kibana"
cat > "${CERTS_DIR}/kibana.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=DNS:kibana,DNS:dystopia-kibana,DNS:localhost,IP:127.0.0.1,IP:0.0.0.0
EOF
openssl x509 -req -sha256 \
  -in "${CERTS_DIR}/kibana.csr" \
  -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" -passin "pass:${CA_PASSPHRASE}" \
  -days 1095 \
  -extfile "${CERTS_DIR}/kibana.ext" \
  -out "${CERTS_DIR}/kibana.crt" && mv "${CERTS_DIR}/kibana.key.new" "${CERTS_DIR}/kibana.key"

# ----------------------------------------------------------------------
# 4) Copia legible del CA para Kibana (pem de confianza) y limpieza de CSR/ext
# ----------------------------------------------------------------------
cp "${CERTS_DIR}/ca.crt" "${CERTS_DIR}/kibana-ca-trust.pem"

rm -f "${CERTS_DIR}"/*.csr "${CERTS_DIR}"/*.ext "${CERTS_DIR}"/*.srl
chmod 600 "${CERTS_DIR}"/*.key 2>/dev/null || true
echo "[OK] certificados en: ${CERTS_DIR}"
ls -l "${CERTS_DIR}"/*.key "${CERTS_DIR}"/*.crt 2>&1

# Nota de ownership para el despliegue real (los contenedores corrren como
# UID 1000 elasticsearch y UID 1000 kibana):
#     chown -R 1000:1000 "${CERTS_DIR}"  (sudo necesario en el host)
cat <<'NEXT'

[SIGUIENTE] Pasos pendientes del operador (NO automatizados aquí):
 1. sudo chown -R 1000:1000 <ELASTIC_CERTS_DIR>
 2. exportar los PEM al ES keystore si se usan contraseñas en la private key:
    docker compose --env-file deploy/elastic/.env --profile deception-elastic \
      run --rm elasticsearch bin/elasticsearch-keystore create
    (xpack.security.http.ssl.key_passphrase y
        xpack.security.transport.ssl.key_passphrase)
 3. Revisar deploy/elastic/README.md
NEXT
