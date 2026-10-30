# Heralding — Dystopia sensor artifact.
#
# Built from a pinned upstream commit. The upstream project has no LICENSE
# file; setup.py declares GPL-3.0 and source headers carry GPLv3 notices.
# The resulting image is therefore GPL-3.0.
#
# Upstream: https://github.com/johnnykv/heralding
# See PROVENANCE.md for the T-Pot build-pattern and licensing provenance.
# The combined image is subject to the upstream GPL-3.0 terms.

FROM alpine:3.23.7@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63

ARG HERALDING_COMMIT=ac12724ab38c4e2fe78f07d1bc35e6e586ba69c0
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apk add --no-cache \
        build-base \
        git \
        libcap \
        libffi-dev \
        libpq \
        openssl-dev \
        postgresql-dev \
        py3-pip \
        py3-setuptools \
        py3-wheel \
        python3 \
        python3-dev \
        zeromq \
        zeromq-dev \
    && git clone https://github.com/johnnykv/heralding.git /opt/heralding-src \
    && cd /opt/heralding-src \
    && git checkout "${HERALDING_COMMIT}" \
    && test "$(git rev-parse HEAD)" = "${HERALDING_COMMIT}" \
    && sed -i '/^from ez_setup import use_setuptools$/d;/^use_setuptools()/d' setup.py \
    && pip3 install --break-system-packages --no-cache-dir -r requirements.txt \
    && pip3 install --break-system-packages --no-cache-dir . \
    && addgroup -g 2000 heralding \
    && adduser -S -H -s /bin/ash -u 2000 -D -g 2000 heralding \
    && mkdir -p /var/log/heralding /etc/heralding /tmp/heralding \
    && cp /opt/heralding-src/heralding/heralding.yml /etc/heralding/heralding.yml \
    && chown -R heralding:heralding /var/log/heralding /tmp/heralding \
    && setcap cap_net_bind_service=+ep "$(readlink -f "$(command -v python3)")" \
    && apk del --purge \
        build-base \
        git \
        libffi-dev \
        openssl-dev \
        postgresql-dev \
        python3-dev \
        zeromq-dev \
    && rm -rf /root/.cache /tmp/* /opt/heralding-src

COPY --chown=2000:2000 heralding.yml /etc/heralding/heralding.yml

STOPSIGNAL SIGINT
WORKDIR /tmp/heralding
USER 2000:2000

# Process-level liveness check; avoids a probe connection being logged.
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python3", "-c", "import sys; sys.exit(0 if b'heralding' in open('/proc/1/cmdline','rb').read() else 1)"]

EXPOSE 21 22 23 25 80 110 143 443 3306 3389 5432 5900

CMD ["heralding", "-c", "/etc/heralding/heralding.yml", "-l", "/var/log/heralding/heralding.log"]
