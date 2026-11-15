# NetPulse — imagen base de dispositivo del fabric (Fase 4).
#
# Contenedor señuelo mínimo y endurecido: sin secretos embebidos, sin
# socket de Docker y con usuario no root. La configuración de red (veth,
# IP, rutas, ARP) la aplica el Device Runtime desde el host con nsenter;
# el contenedor solo aporta el netns y el sistema base.
#
#   docker build -t dystopia/fabric-device:v1 fabric/
#
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 \
        iputils-ping \
        procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# UID/GID fijos y no root (mismo criterio que las celdas de honeypots).
RUN groupadd --gid 2000 fabric \
    && useradd --uid 2000 --gid 2000 --no-create-home \
        --shell /usr/sbin/nologin fabric

COPY device-entry.sh /usr/local/bin/device-entry.sh
RUN chmod 0755 /usr/local/bin/device-entry.sh

USER 2000:2000

# Mantiene el contenedor vivo hasta que la Fase 5 arranque los servicios.
ENTRYPOINT ["/usr/local/bin/device-entry.sh"]
