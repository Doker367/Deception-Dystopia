#!/usr/bin/env python3
"""NetPulse — redeploy del fabric tras un reinicio del host.

OVS y los veths no sobreviven a un reboot: los bridges desaparecen y los
contenedores de dispositivo se recrean sin red. El estado del control sigue
diciendo ``deployed`` (lo restauró de ``fabric_state``), así que sin esto el
fabric queda "desplegado pero vacío" hasta que un operador pulse Rebuild.

Esta unidad (``dystopia-fabric-boot.service``) espera a que el servicio del
host responda ``/health`` y lanza ``POST /deploy`` (idempotente). No hace
nada si el fabric está deshabilitado en el manifiesto.
"""

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

ENV_FILE = "/etc/dystopia/fabric.env"
HEALTH_TIMEOUT = 60
RETRY_INTERVAL = 2


def _read_env(path=ENV_FILE):
    values = {}
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
    except OSError as exc:
        print(f"[fabric-boot] no se pudo leer {path}: {exc}", file=sys.stderr)
    return values


def _url(env):
    bind = env.get("DYSTOPIA_FABRIC_BIND", "127.0.0.1")
    port = env.get("DYSTOPIA_FABRIC_PORT", "8090")
    host = "127.0.0.1" if bind in {"0.0.0.0", "::", "[::]"} else bind
    scheme = "https" if env.get("DYSTOPIA_FABRIC_TLS_CERT") else "http"
    return f"{scheme}://{host}:{port}"


def _ssl_context(env):
    cert = env.get("DYSTOPIA_FABRIC_TLS_CERT")
    if not cert:
        return None
    return ssl.create_default_context(cafile=cert)


def _request(base, path, token, context, method="GET"):
    request = urllib.request.Request(
        f"{base}{path}",
        headers={"Authorization": f"Bearer {token}"},
        method=method,
    )
    with urllib.request.urlopen(request, timeout=30, context=context) as response:
        return response.status, json.loads(response.read().decode("utf-8") or "{}")


def main() -> int:
    env = _read_env()
    token = env.get("DYSTOPIA_FABRIC_TOKEN", "")
    if len(token) < 32:
        print("[fabric-boot] token ausente; nada que desplegar", file=sys.stderr)
        return 0
    base = _url(env)
    context = _ssl_context(env)

    deadline = time.monotonic() + HEALTH_TIMEOUT
    last_error = None
    while time.monotonic() < deadline:
        try:
            status, payload = _request(base, "/health", token, context)
            if status == 200 and payload.get("service") == "dystopia-fabric":
                break
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last_error = exc
        time.sleep(RETRY_INTERVAL)
    else:
        print(f"[fabric-boot] el servicio no respondió: {last_error}", file=sys.stderr)
        return 1

    try:
        status, payload = _request(base, "/deploy", token, context, method="POST")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        print(f"[fabric-boot] deploy falló ({exc.code}): {detail}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"[fabric-boot] deploy falló: {exc}", file=sys.stderr)
        return 1

    print(
        "[fabric-boot] deploy "
        f"state={payload.get('state')} "
        f"bridges={len(payload.get('bridges_created') or [])} "
        f"containers={len(payload.get('containers_created') or [])} "
        f"warnings={len(payload.get('warnings') or [])}"
    )
    return 0 if payload.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
