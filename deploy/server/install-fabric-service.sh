#!/usr/bin/env bash
# NetPulse — instalación del servicio de fabric del host (Fase 4c).
#
# Crea directorios de estado, tokens bearer (0600), clave Fernet, certificado
# TLS autofirmado, logrotate e instala la unit endurecida; verifica /health.
# Idempotente: reejecutarlo conserva tokens, clave y certificado existentes.
#
#   sudo deploy/server/install-fabric-service.sh
#
# Requisitos: Debian trixie / Ubuntu 24.04, root, systemd, Docker,
# Open vSwitch, curl y el venv del control en /opt/dystopia/venv.
# NUNCA imprime el token.
set -euo pipefail

SERVICE="dystopia-fabric"
UNIT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/deploy/systemd/${SERVICE}.service"
UNIT_DST="/etc/systemd/system/${SERVICE}.service"
ENV_DIR="/etc/dystopia"
ENV_FILE="${ENV_DIR}/fabric.env"
STATE_DIR="/var/lib/dystopia/fabric"
KEY_FILE="/etc/dystopia/fabric.key"
CREDENTIALS_DIR="/var/lib/dystopia/fabric/credentials"
TLS_DIR="/etc/dystopia/fabric-tls"
TLS_CERT="${TLS_DIR}/server.crt"
TLS_KEY="${TLS_DIR}/server.key"
LOGROTATE_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/deploy/logrotate/dystopia-fabric"
LOGROTATE_DST="/etc/logrotate.d/dystopia-fabric"
PYTHON="/opt/dystopia/venv/bin/python"
MANIFEST_DEFAULT="/opt/dystopia/current/config/deception/network.yaml"

fail() { printf 'install-fabric-service: %s\n' "$*" >&2; exit 1; }
log() { printf 'install-fabric-service: %s\n' "$*"; }

[[ ${EUID:-$(id -u)} -eq 0 ]] || fail "se requiere root"

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
        debian|ubuntu) ;;
        *) fail "sistema no soportado (${ID:-desconocido}); usa Debian trixie o Ubuntu 24.04" ;;
    esac
fi

for tool in systemctl curl getent install sed grep openssl logrotate; do
    command -v "$tool" >/dev/null 2>&1 || fail "falta el comando '$tool'"
done
[[ -x "$PYTHON" ]] || fail "no existe el venv del control en $PYTHON"
[[ -f "$UNIT_SRC" ]] || fail "no se encuentra la unit en $UNIT_SRC"
getent group docker >/dev/null || fail "no existe el grupo 'docker' (instala Docker primero)"

# ── Directorios de estado y configuración ───────────────────
# El servicio corre como root (ver la unit: el socket de OVSDB es root:root),
# así que el estado también es root:root 0700.
install -d -m 0755 "$ENV_DIR"
install -d -m 0700 -o root -g root "$STATE_DIR"

# ── Token bearer (solo en el host; nunca en el repo) ────────
generate_token() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        "$PYTHON" -c 'import secrets; print(secrets.token_hex(32))'
    fi
}

umask 077
if [[ ! -f "$ENV_FILE" ]]; then
    install -m 0600 -o root -g root /dev/null "$ENV_FILE"
fi
if grep -qE '^DYSTOPIA_FABRIC_TOKEN=.{32,}$' "$ENV_FILE"; then
    log "token existente conservado en $ENV_FILE"
else
    token="$(generate_token)"
    [[ ${#token} -ge 32 ]] || fail "no se pudo generar un token válido"
    if grep -q '^DYSTOPIA_FABRIC_TOKEN=' "$ENV_FILE"; then
        sed -i "s|^DYSTOPIA_FABRIC_TOKEN=.*|DYSTOPIA_FABRIC_TOKEN=${token}|" "$ENV_FILE"
    else
        printf 'DYSTOPIA_FABRIC_TOKEN=%s\n' "$token" >> "$ENV_FILE"
    fi
    log "token nuevo generado en $ENV_FILE"
fi
if grep -qE '^DYSTOPIA_FABRIC_EVENTS_TOKEN=.{32,}$' "$ENV_FILE"; then
    log "token de eventos existente conservado en $ENV_FILE"
else
    events_token="$(generate_token)"
    [[ ${#events_token} -ge 32 ]] || fail "no se pudo generar el token de eventos"
    if grep -q '^DYSTOPIA_FABRIC_EVENTS_TOKEN=' "$ENV_FILE"; then
        sed -i "s|^DYSTOPIA_FABRIC_EVENTS_TOKEN=.*|DYSTOPIA_FABRIC_EVENTS_TOKEN=${events_token}|" "$ENV_FILE"
    else
        printf 'DYSTOPIA_FABRIC_EVENTS_TOKEN=%s\n' "$events_token" >> "$ENV_FILE"
    fi
    log "token de eventos nuevo generado en $ENV_FILE"
fi
grep -q '^DYSTOPIA_FABRIC_MANIFEST=' "$ENV_FILE" \
    || printf 'DYSTOPIA_FABRIC_MANIFEST=%s\n' "$MANIFEST_DEFAULT" >> "$ENV_FILE"
# BIND recomendado con control en contenedor: 172.17.0.1 (gateway de docker0,
# estable; host.docker.internal resuelve ahí). NO usar la IP de la red compose:
# cambia al recrear la red y el control se queda sin servicio (~120 s de timeout).
# Firewall (INPUT DROP por defecto):
#   ufw allow from 172.16.0.0/12 to 172.17.0.1 port <DYSTOPIA_FABRIC_PORT> proto tcp
grep -q '^DYSTOPIA_FABRIC_BIND=' "$ENV_FILE" \
    || printf 'DYSTOPIA_FABRIC_BIND=127.0.0.1\n' >> "$ENV_FILE"
grep -q '^DYSTOPIA_FABRIC_PORT=' "$ENV_FILE" \
    || printf 'DYSTOPIA_FABRIC_PORT=8090\n' >> "$ENV_FILE"
# Forwarder de eventos del agente → control (Fase 5b).
grep -q '^DYSTOPIA_FABRIC_EVENTS_URL=' "$ENV_FILE" \
    || printf 'DYSTOPIA_FABRIC_EVENTS_URL=http://127.0.0.1:8082/api/fabric/events\n' >> "$ENV_FILE"
grep -q '^DYSTOPIA_FABRIC_EVENTS_INTERVAL=' "$ENV_FILE" \
    || printf 'DYSTOPIA_FABRIC_EVENTS_INTERVAL=5\n' >> "$ENV_FILE"
grep -q '^DYSTOPIA_FABRIC_EVENTS_ENABLED=' "$ENV_FILE" \
    || printf 'DYSTOPIA_FABRIC_EVENTS_ENABLED=true\n' >> "$ENV_FILE"
chown root:root "$ENV_FILE"
chmod 0600 "$ENV_FILE"

# ── Clave Fernet del fabric (credenciales cifradas en reposo) ──
if [[ -s "$KEY_FILE" ]]; then
    log "clave del fabric existente conservada en $KEY_FILE"
else
    "$PYTHON" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' \
        > "$KEY_FILE" || fail "no se pudo generar la clave Fernet (¿cryptography en el venv?)"
    log "clave Fernet nueva generada en $KEY_FILE"
fi
chown root:root "$KEY_FILE"
chmod 0600 "$KEY_FILE"
install -d -m 0700 -o root -g root "$CREDENTIALS_DIR"

# ── TLS opcional del servicio (control ↔ host) ──────────────
# Certificado autofirmado con SANs para el gateway de docker0 y
# host.docker.internal. El control lo usa como CA (DYSTOPIA_FABRIC_REMOTE_CA).
# Se conserva si ya existe: rotarlo es una decisión explícita del operador.
# 0755: el control (uid 2000) monta el directorio y debe poder leer el
# certificado público; la clave privada queda 0600 root y no es accesible.
install -d -m 0755 -o root -g root "$TLS_DIR"
if [[ -s "$TLS_CERT" && -s "$TLS_KEY" ]]; then
    log "certificado TLS existente conservado en $TLS_DIR"
else
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout "$TLS_KEY" -out "$TLS_CERT" \
        -subj "/CN=dystopia-fabric" \
        -addext "subjectAltName=IP:172.17.0.1,IP:127.0.0.1,DNS:host.docker.internal,DNS:localhost" \
        >/dev/null 2>&1 || fail "no se pudo generar el certificado TLS"
    log "certificado TLS nuevo generado en $TLS_DIR"
fi
chown root:root "$TLS_CERT" "$TLS_KEY"
chmod 0644 "$TLS_CERT"
chmod 0600 "$TLS_KEY"
# TLS desactivado por defecto: activarlo es una decisión del operador
# (definir DYSTOPIA_FABRIC_TLS_CERT/KEY en fabric.env y usar https en el control).
grep -q '^DYSTOPIA_FABRIC_TLS_CERT=' "$ENV_FILE" \
    || printf '# DYSTOPIA_FABRIC_TLS_CERT=%s\n' "$TLS_CERT" >> "$ENV_FILE"
grep -q '^DYSTOPIA_FABRIC_TLS_KEY=' "$ENV_FILE" \
    || printf '# DYSTOPIA_FABRIC_TLS_KEY=%s\n' "$TLS_KEY" >> "$ENV_FILE"

# ── Rotación de los JSONL del agente ────────────────────────
if [[ -f "$LOGROTATE_SRC" ]]; then
    install -m 0644 "$LOGROTATE_SRC" "$LOGROTATE_DST"
    log "logrotate instalado en $LOGROTATE_DST"
fi

# ── Unit + arranque ─────────────────────────────────────────
install -m 0644 "$UNIT_SRC" "$UNIT_DST"
systemctl daemon-reload
systemctl enable "$SERVICE.service" >/dev/null
systemctl restart "$SERVICE.service"
log "servicio $SERVICE instalado y reiniciado"

# ── Verificación de /health (sin exponer el token en argv) ──
bind="$(sed -n 's/^DYSTOPIA_FABRIC_BIND=//p' "$ENV_FILE" | tail -n1)"
port="$(sed -n 's/^DYSTOPIA_FABRIC_PORT=//p' "$ENV_FILE" | tail -n1)"
token="$(sed -n 's/^DYSTOPIA_FABRIC_TOKEN=//p' "$ENV_FILE" | tail -n1)"
bind="${bind:-127.0.0.1}"
port="${port:-8090}"
case "$bind" in
    0.0.0.0|::|"[::]") url_host="127.0.0.1" ;;
    *) url_host="$bind" ;;
esac

healthy=0
scheme="http"
curl_tls=()
if grep -qE '^DYSTOPIA_FABRIC_TLS_CERT=.+' "$ENV_FILE"; then
    scheme="https"
    curl_tls=(--cacert "$TLS_CERT")
fi
for _ in $(seq 1 15); do
    if printf 'header = "Authorization: Bearer %s"\n' "$token" \
        | curl -fsS --max-time 3 --config - "${curl_tls[@]}" \
            "${scheme}://${url_host}:${port}/health" \
        | "$PYTHON" -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("service")=="dystopia-fabric" else 1)' 2>/dev/null; then
        healthy=1
        break
    fi
    sleep 1
done

if [[ "$healthy" -ne 1 ]]; then
    systemctl status "$SERVICE.service" --no-pager -l >&2 || true
    journalctl -u "$SERVICE.service" -n 40 --no-pager >&2 || true
    fail "el servicio no respondió a /health en ${scheme}://${url_host}:${port}"
fi

log "OK: $SERVICE escucha en ${scheme}://${url_host}:${port} (token en $ENV_FILE, 0600)"
