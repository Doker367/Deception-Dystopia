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

# Real, benign Debian binaries used only as file content by the emulated
# filesystem.  They are never executed from honeyfs; Cowrie serves their bytes
# for /proc/self/exe and for the matching fake-fs paths.  The versions match
# the sizes recorded in Cowrie's Debian fs.pickle.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS realbin
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        busybox-static \
        coreutils \
        mawk \
        python3.11-minimal \
        sed \
        tar \
    && rm -rf /var/lib/apt/lists/*

FROM cowrie/cowrie:3.1.4@sha256:4e2d40671691ab7a4af19840918556c62316939e905bfc9ab3fc1f9e1db54e55

# Config is read from /etc/cowrie/cowrie.cfg (first entry in Cowrie's
# documented search order). Keep it read-only at runtime.
COPY --chown=999:999 cowrie.cfg /etc/cowrie/cowrie.cfg
COPY --from=dirs --chown=999:999 /cowrie-var /cowrie/cowrie-git/var

# Honeyfs contains only data.  These paths already exist in Cowrie's
# fs.pickle, so init_honeyfs() binds real bytes to them at session start.
COPY --from=realbin --chown=999:999 /bin/busybox /cowrie/cowrie-git/share/cowrie/honeyfs/usr/bin/busybox
COPY --from=realbin --chown=999:999 /usr/bin/base64 /cowrie/cowrie-git/share/cowrie/honeyfs/usr/bin/base64
COPY --from=realbin --chown=999:999 /usr/bin/cat /cowrie/cowrie-git/share/cowrie/honeyfs/usr/bin/cat
COPY --from=realbin --chown=999:999 /usr/bin/cut /cowrie/cowrie-git/share/cowrie/honeyfs/usr/bin/cut
COPY --from=realbin --chown=999:999 /usr/bin/dd /cowrie/cowrie-git/share/cowrie/honeyfs/usr/bin/dd
COPY --from=realbin --chown=999:999 /usr/bin/mawk /cowrie/cowrie-git/share/cowrie/honeyfs/usr/bin/mawk
COPY --from=realbin --chown=999:999 /usr/bin/python3.11 /cowrie/cowrie-git/share/cowrie/honeyfs/usr/bin/python3.11
COPY --from=realbin --chown=999:999 /usr/bin/sed /cowrie/cowrie-git/share/cowrie/honeyfs/usr/bin/sed
COPY --from=realbin --chown=999:999 /bin/tar /cowrie/cowrie-git/share/cowrie/honeyfs/usr/bin/tar
COPY --from=realbin --chown=999:999 /usr/bin/wc /cowrie/cowrie-git/share/cowrie/honeyfs/usr/bin/wc

# Build-time patch: add /usr/bin/busybox to fs.pickle and make /proc/self/exe,
# cmdline, comm, status and maps resolve against the current command.  The
# script fails the build if an upstream anchor changed.
COPY --chown=999:999 patch_process.py /tmp/patch_process.py
# Distroless has no /bin/sh, so use the Python interpreter directly.
RUN ["/cowrie/cowrie-env/bin/python3", "-c", "import os, runpy; runpy.run_path('/tmp/patch_process.py', run_name='__main__'); os.unlink('/tmp/patch_process.py')"]

USER 999:999

# Process-level liveness check. Deliberately does not open a TCP session,
# because a probe would create synthetic connect events in cowrie.json.
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python3", "-c", "import sys; sys.exit(0 if b'twistd' in open('/proc/1/cmdline','rb').read() else 1)"]

EXPOSE 2222 2223
