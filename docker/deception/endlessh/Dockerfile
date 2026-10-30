# Endlessh — Dystopia sensor artifact.
#
# Built from a pinned upstream commit. Endlessh is released under the
# Unlicense (public domain). The runtime user is uid/gid 2000 and the
# listener uses an unprivileged port (2222).
#
# Upstream: https://github.com/skeeto/endlessh
# Build recipe rewritten from the upstream Makefile and the T-Pot build
# pattern; see PROVENANCE.md for licensing provenance.

FROM alpine:3.23.7@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63 AS builder

ARG ENDLESSH_COMMIT=dfe44eb2c5b6fc3c48a39ed826fe0e4459cdf6ef

RUN apk add --no-cache build-base git \
    && git clone https://github.com/skeeto/endlessh.git /src \
    && cd /src \
    && git checkout "${ENDLESSH_COMMIT}" \
    && test "$(git rev-parse HEAD)" = "${ENDLESSH_COMMIT}" \
    && make


FROM alpine:3.23.7@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63

# coreutils provides stdbuf, used to line-buffer endlessh's stdout into the
# log file so the adapter sees open/close events promptly.
RUN apk add --no-cache coreutils \
    && addgroup -g 2000 endlessh \
    && adduser -S -H -s /sbin/nologin -u 2000 -D -g 2000 endlessh \
    && mkdir -p /opt/endlessh /var/log/endlessh \
    && chown -R endlessh:endlessh /var/log/endlessh

COPY --from=builder --chown=2000:2000 /src/endlessh /opt/endlessh/endlessh
COPY --chown=2000:2000 endlessh.conf /opt/endlessh/endlessh.conf

WORKDIR /opt/endlessh
USER 2000:2000

# Process-level liveness check; avoids opening a tarpit connection.
HEALTHCHECK --interval=60s --timeout=5s --start-period=15s --retries=3 \
  CMD ["sh", "-c", "grep -q endlessh /proc/1/cmdline"]

EXPOSE 2222

CMD ["sh", "-c", "exec stdbuf -oL -eL ./endlessh -f endlessh.conf >> /var/log/endlessh/endlessh.log 2>&1"]
