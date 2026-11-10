# OpenCanary — Dystopia sensor artifact.
#
# Base image and Python package are pinned (no `latest`). The daemon runs as
# uid/gid 2000; only CAP_NET_BIND_SERVICE is expected at runtime so it can
# bind the low ports used by the decoy personas.
#
# Upstream: https://github.com/thinkst/opencanary (BSD-3-Clause)
# License of this file: follows the Dystopia repository.

FROM python:3.12.8-slim-bookworm@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Direct dependencies of opencanary==0.9.10 are pinned by the package
# metadata; the full transitive set is not hash-locked in this artifact.
RUN pip install --no-cache-dir --no-compile "opencanary==0.9.10"

RUN groupadd --gid 2000 opencanary \
    && useradd --uid 2000 --gid 2000 --no-create-home --shell /usr/sbin/nologin opencanary \
    && mkdir -p /etc/opencanaryd /var/log/opencanary \
    && chown -R 2000:2000 /var/log/opencanary \
    && setcap cap_net_bind_service=+ep "$(readlink -f "$(command -v python3)")"

COPY --chown=2000:2000 opencanary.conf /etc/opencanaryd/opencanary.conf
COPY --chown=2000:2000 access_shim.py /usr/local/bin/access_shim.py
COPY fingerprint.js patch_fp.py /tmp/
RUN python3 /tmp/patch_fp.py && rm -f /tmp/patch_fp.py /tmp/fingerprint.js

# El wrapper opencanaryd usa `sudo -E` incluso cuando ya corre como usuario
# sin privilegios. Un shim que solo elimina -E y executa el comando evita
# instalar sudo real (y no eleva privilegios: USER 2000 no puede).
RUN printf '#!/bin/sh\n[ "$1" = "-E" ] && shift\nexec "$@"\n' \
      > /usr/local/bin/sudo \
    && chmod 0755 /usr/local/bin/sudo

USER 2000:2000

# Process-level liveness check. Avoids self-connections that would create
# synthetic events in opencanary.log.
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python3", "-c", "import sys; sys.exit(0 if b'opencanaryd' in open('/proc/1/cmdline','rb').read() else 1)"]

EXPOSE 21 22 23 80 3306

# --dev keeps the process in the foreground for Docker. The shim forwards
# stdout and mirrors Twisted HTTP access lines into the JSON log tailed by the
# collector, so arbitrary paths and user agents reach the analytics plane.
CMD ["sh", "-c", "opencanaryd --dev 2>&1 | python3 /usr/local/bin/access_shim.py"]
