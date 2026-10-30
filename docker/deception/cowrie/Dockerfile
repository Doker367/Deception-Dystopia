# Cowrie SSH/Telnet honeypot — Dystopia sensor artifact.
#
# Upstream image is pinned by tag and registry digest (no `latest`).
# The image already runs as uid/gid 999 and uses /cowrie/cowrie-git as
# WORKDIR. Only the operator config is overlaid; logs and state live under
# the image's declared /cowrie/cowrie-git/var volume.
#
# Upstream: https://github.com/cowrie/cowrie (BSD-3-Clause)
# License of this file: follows the Dystopia repository.

# The upstream runtime is distroless: create the writable log/state
# directories in a tiny build stage and copy them with the right owner.
FROM alpine:3.23.7@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63 AS dirs
RUN mkdir -p \
        /cowrie-var/log/cowrie \
        /cowrie-var/lib/cowrie/downloads \
        /cowrie-var/lib/cowrie/tty

FROM cowrie/cowrie:3.1.4@sha256:4e2d40671691ab7a4af19840918556c62316939e905bfc9ab3fc1f9e1db54e55

# Config is read from /etc/cowrie/cowrie.cfg (first entry in Cowrie's
# documented search order). Keep it read-only at runtime.
COPY --chown=999:999 cowrie.cfg /etc/cowrie/cowrie.cfg
COPY --from=dirs --chown=999:999 /cowrie-var /cowrie/cowrie-git/var

USER 999:999

# Process-level liveness check. Deliberately does not open a TCP session,
# because a probe would create synthetic connect events in cowrie.json.
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python3", "-c", "import sys; sys.exit(0 if b'twistd' in open('/proc/1/cmdline','rb').read() else 1)"]

EXPOSE 2222 2223
