#!/usr/bin/env bash
# Generate a local private CA and a TLS server certificate for the reverse
# proxy. This is for managed/lab clients; production may use an organization
# CA. Files are generated outside tracked paths and have restrictive modes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${PROXY_CERT_DIR:-${SCRIPT_DIR}/certs}"
CA_DAYS="${PROXY_CA_DAYS:-3650}"
CERT_DAYS="${PROXY_CERT_DAYS:-397}"

if [[ ! "${CA_DAYS}" =~ ^[1-9][0-9]{0,4}$ || ! "${CERT_DAYS}" =~ ^[1-9][0-9]{0,3}$ ]]; then
	echo "[FATAL] certificate validity must be a positive number of days" >&2
	exit 2
fi

if [[ "$#" -lt 1 ]]; then
	cat >&2 <<'USAGE'
Usage: generate-certs.sh <DNS-name-or-IP> [additional-DNS-names-or-IPs...]
Example: generate-certs.sh kibana.mgmt.example.invalid control.mgmt.example.invalid 192.0.2.40
Set PROXY_CERT_DIR to an absolute, private output directory if desired.
USAGE
	exit 2
fi

if ! command -v openssl >/dev/null 2>&1; then
	echo "[FATAL] openssl is required" >&2
	exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
	echo "[FATAL] python3 is required to validate certificate SANs" >&2
	exit 2
fi

names=()
sans=()
for name in "$@"; do
	type="$(python3 - "$name" <<'PY'
import ipaddress
import re
import sys

value = sys.argv[1]
try:
    ipaddress.ip_address(value)
except ValueError:
    if len(value) > 253 or not re.fullmatch(
        r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*",
        value,
    ):
        raise SystemExit(1)
    print("DNS")
else:
    print("IP")
PY
	)" || {
		echo "[FATAL] invalid DNS name or IP address: ${name}" >&2
		exit 2
	}
	names+=("$name")
	sans+=("${type}:${name}")
done

for generated_file in proxy-ca.key proxy-ca.crt proxy-ca.srl reverse-proxy.key reverse-proxy.crt reverse-proxy.csr reverse-proxy.ext; do
	if [[ -e "${CERT_DIR}/${generated_file}" ]]; then
		echo "[FATAL] ${CERT_DIR}/${generated_file} already exists; choose a new directory or remove it securely after review" >&2
		exit 1
	fi
done

mkdir -p "${CERT_DIR}"
chmod 0700 "${CERT_DIR}"
umask 077

echo "[INFO] creating local proxy CA and leaf certificate in ${CERT_DIR}"
openssl genrsa -out "${CERT_DIR}/proxy-ca.key" 4096
openssl req -x509 -new -sha256 -days "${CA_DAYS}" \
	-key "${CERT_DIR}/proxy-ca.key" \
	-out "${CERT_DIR}/proxy-ca.crt" \
	-subj "/O=Dystopia/OU=TLS Proxy/CN=Dystopia TLS Proxy Local CA" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign,cRLSign" \
	-addext "subjectKeyIdentifier=hash"

openssl genrsa -out "${CERT_DIR}/reverse-proxy.key" 3072
openssl req -new -sha256 -key "${CERT_DIR}/reverse-proxy.key" \
	-out "${CERT_DIR}/reverse-proxy.csr" \
	-subj "/O=Dystopia/OU=TLS Proxy/CN=${names[0]}"

san_list="$(IFS=,; printf '%s' "${sans[*]}")"
cat > "${CERT_DIR}/reverse-proxy.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=${san_list}
EOF

openssl x509 -req -sha256 -days "${CERT_DAYS}" \
	-in "${CERT_DIR}/reverse-proxy.csr" \
	-CA "${CERT_DIR}/proxy-ca.crt" \
	-CAkey "${CERT_DIR}/proxy-ca.key" \
	-CAcreateserial \
	-extfile "${CERT_DIR}/reverse-proxy.ext" \
	-out "${CERT_DIR}/reverse-proxy.crt"

rm -f "${CERT_DIR}/reverse-proxy.csr" "${CERT_DIR}/reverse-proxy.ext" "${CERT_DIR}/proxy-ca.srl"
chmod 0600 "${CERT_DIR}/proxy-ca.key" "${CERT_DIR}/reverse-proxy.key"
chmod 0644 "${CERT_DIR}/proxy-ca.crt" "${CERT_DIR}/reverse-proxy.crt"

echo "[OK] certificate SANs: ${names[*]}"
echo "[OK] import ${CERT_DIR}/proxy-ca.crt into approved client trust stores; never distribute proxy-ca.key"
