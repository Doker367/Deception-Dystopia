# RedisHoneyPot — Dystopia sensor artifact.
#
# Built from a pinned upstream commit. The upstream project is GPL-3.0.
# The binary is static (CGO disabled) and runs as uid/gid 2000.
#
# Upstream: https://github.com/cypwnpwnsocute/RedisHoneyPot
# License of this Dockerfile: follows the Dystopia repository; the combined
# image is subject to the upstream GPL-3.0 terms.

FROM golang:1.26.10-alpine3.23@sha256:34414731924cf2263160f0021f5cf6e1807382d85248f7cb419d4187b96d5e43 AS builder

ARG REDIS_HONEYPOT_COMMIT=45adc622a423d12d76392c3a54274f6cff111d58

RUN apk add --no-cache build-base git \
    && git clone https://github.com/cypwnpwnsocute/RedisHoneyPot.git /src \
    && cd /src \
    && git checkout "${REDIS_HONEYPOT_COMMIT}" \
    && test "$(git rev-parse HEAD)" = "${REDIS_HONEYPOT_COMMIT}" \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/RedisHoneyPot .


FROM alpine:3.23.7@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63

RUN addgroup -g 2000 redishoneypot \
    && adduser -S -H -s /sbin/nologin -u 2000 -D -g 2000 redishoneypot \
    && mkdir -p /opt/redishoneypot /var/log/redishoneypot \
    && chown -R redishoneypot:redishoneypot /var/log/redishoneypot

COPY --from=builder --chown=2000:2000 /out/RedisHoneyPot /opt/redishoneypot/RedisHoneyPot
COPY --chown=2000:2000 redis.conf /opt/redishoneypot/redis.conf

WORKDIR /opt/redishoneypot
USER 2000:2000

# Process-level liveness check; does not issue a Redis command.
HEALTHCHECK --interval=60s --timeout=5s --start-period=15s --retries=3 \
  CMD ["sh", "-c", "grep -q RedisHoneyPot /proc/1/cmdline"]

EXPOSE 6379

# logrus writes one JSON object per line; keep a file copy for the adapter.
CMD ["sh", "-c", "exec ./RedisHoneyPot -addr 0.0.0.0:6379 -proto tcp -num 1 >> /var/log/redishoneypot/redishoneypot.log 2>&1"]
