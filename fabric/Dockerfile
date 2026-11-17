# NetPulse — imagen de dispositivo del fabric (Fase 5a).
#
# Contenedor señuelo endurecido: sin secretos embebidos, sin socket de
# Docker y con usuario no root. El Device Runtime monta:
#   - /etc/fabric/device.json  (read-only, 0600): configuración del agente
#   - /var/log/fabric          (rw): events.jsonl + host key SSH persistente
# La red (veth/IP/rutas/ARP) la configura el host con nsenter.
#
# El contexto de build es la RAÍZ del repo (se copia app/):
#
#   docker build -t dystopia/fabric-device:v1 -f fabric/Dockerfile .
#
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/dystopia

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-venv \
        iproute2 \
        iputils-ping \
        procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Solo las dependencias de los listeners (telemetry/store) y del agente.
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --no-compile \
        pydantic==2.11.7 \
        PyYAML==6.0.2 \
        paramiko==5.1.0 \
        prometheus-client==0.22.1

# UID/GID fijos y no root (mismo criterio que las celdas de honeypots).
RUN groupadd --gid 2000 fabric \
    && useradd --uid 2000 --gid 2000 --no-create-home \
        --shell /usr/sbin/nologin fabric

COPY app/ /opt/dystopia/app/
COPY fabric/agent.py /opt/dystopia/fabric/agent.py
# Fase 11: binding de motores reales. Sin los motores instalados (imagen
# base) el agente cae al listener nativo; Dockerfile.engines los añade.
COPY fabric/engines.py /opt/dystopia/fabric/engines.py
COPY runtime/ /opt/dystopia/runtime/

# Directorios de montaje con owner 2000 (el bind mount conserva el dueño
# del host; el Device Runtime hace chown 2000:2000).
RUN mkdir -p /etc/fabric /var/log/fabric/keys \
    && chown -R 2000:2000 /opt/dystopia /etc/fabric /var/log/fabric

USER 2000:2000

ENTRYPOINT ["/opt/venv/bin/python", "/opt/dystopia/fabric/agent.py"]
