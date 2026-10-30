# Dionaea — Dystopia sensor artifact.
#
# Built from a pinned upstream commit (no `latest`). Upstream 0.12.5 vendors
# libemu, so the build no longer depends on archived Debian packages.
#
# Upstream: https://github.com/telekom-security/dionaea
# Upstream license: GPL-2.0-or-later (see the upstream LICENSES directory).
# The configuration files under dionaea/, services/ and ihandlers/ are
# adapted from upstream dionaea conf/ (CC0-1.0).
# License of this Dockerfile: follows the Dystopia repository; the resulting
# combined image is subject to the upstream GPL-2.0-or-later terms.

FROM ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c AS builder

ARG DEBIAN_FRONTEND=noninteractive
ARG DIONAEA_COMMIT=78af2ff2a0f1b62ac7cc5858bac2ab46898c9cc0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        cython3 \
        git \
        libcurl4-openssl-dev \
        libev-dev \
        libglib2.0-dev \
        libnetfilter-queue-dev \
        libpcap-dev \
        libssl-dev \
        libudns-dev \
        pkg-config \
        python3 \
        python3-dev \
        python3-setuptools \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/telekom-security/dionaea.git /src \
    && cd /src \
    && git checkout "${DIONAEA_COMMIT}" \
    && test "$(git rev-parse HEAD)" = "${DIONAEA_COMMIT}"

RUN mkdir -p /src/build \
    && cd /src/build \
    && cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea -DCMAKE_BUILD_TYPE=RelWithDebInfo .. \
    && make -j"$(nproc)" \
    && make install


FROM ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c

ARG DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libcap2-bin \
        libcurl4t64 \
        libev4t64 \
        libglib2.0-0t64 \
        libnetfilter-queue1 \
        libpcap0.8t64 \
        libpython3.14 \
        libudns0t64 \
        python3 \
        python3-boto3 \
        python3-bson \
        python3-yaml \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/*

COPY --from=builder /opt/dionaea /opt/dionaea

# Replace upstream sample handlers/services with the reviewed Dystopia set.
RUN rm -rf \
        /opt/dionaea/etc/dionaea/services-enabled \
        /opt/dionaea/etc/dionaea/ihandlers-enabled
COPY dionaea.cfg /opt/dionaea/etc/dionaea/dionaea.cfg
COPY ihandlers/ /opt/dionaea/etc/dionaea/ihandlers-enabled/
COPY services/ /opt/dionaea/etc/dionaea/services-enabled/

RUN rm -rf /opt/dionaea/etc/dionaea/ihandlers /opt/dionaea/etc/dionaea/services \
    && mkdir -p \
        /opt/dionaea/var/log \
        /opt/dionaea/var/dionaea/binaries \
        /opt/dionaea/var/dionaea/bistreams \
        /opt/dionaea/var/dionaea/roots/ftp \
        /opt/dionaea/var/dionaea/roots/tftp \
        /opt/dionaea/var/dionaea/roots/www \
    && addgroup --gid 2000 dionaea \
    && adduser --system --no-create-home --shell /bin/bash --uid 2000 \
        --disabled-password --disabled-login --gid 2000 dionaea \
    && setcap cap_net_bind_service=+ep /opt/dionaea/sbin/dionaea \
    && chown -R dionaea:dionaea /opt/dionaea/var

STOPSIGNAL SIGINT

USER dionaea:dionaea

# Process-level liveness check; does not open a decoy connection.
HEALTHCHECK --interval=60s --timeout=5s --start-period=45s --retries=3 \
  CMD ["python3", "-c", "import sys; sys.exit(0 if b'dionaea' in open('/proc/1/cmdline','rb').read() else 1)"]

EXPOSE 21 69/udp 81 135 443 445 1433 1723 1883 3306 27017

CMD ["/opt/dionaea/sbin/dionaea", "-u", "dionaea", "-g", "dionaea", "-c", "/opt/dionaea/etc/dionaea/dionaea.cfg"]
