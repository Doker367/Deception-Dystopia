#!/usr/bin/env python3
"""Forward OpenCanary's Twisted stdout and persist HTTP access lines as JSONL.

OpenCanary logs arbitrary HTTP paths (including 404 probes) through Twisted's
access logger on stdout, not through its JSON logger. The collector tails the
JSON file, so without this shim those requests never reach the panel.

The shim is intentionally small and read-only with respect to the request:
it copies stdout unchanged for ``docker logs`` and appends one bounded JSON
line per matching access record to ``opencanary.log``. Captured passwords are
not present in the access log; POST bodies are not read.

Captured fields per request (Twisted combined format): source IP, method,
path, protocol, status, ``Referer`` and ``User-Agent``. The NCSA format carries
neither the source port nor the request headers: those only exist in the JSON
events the OpenCanary HTTP module itself emits per request (logtype
3000/3001, with ``src_port`` and — since the ``patch_http_capture.py`` patch —
``AUTH``/``REFERER`` and Basic credentials). That is why this synthetic record
marks ``src_port: -1`` and the normalizer drops it.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import re
import sys

LOG_PATH = os.environ.get("OPENCANARY_ACCESS_LOG", "/var/log/opencanary/opencanary.log")
# Con el parche del módulo HTTP (patch_http_capture.py) las peticiones —incluidos
# los 404— se registran por el logger JSON con datos completos (método, headers,
# credenciales, SRC_IP del proxy). En ese modo el shim solo reenvía stdout para
# ``docker logs`` y no duplica el evento sin IP: OPENCANARY_ACCESS_JSON=0.
PERSIST_ACCESS = os.environ.get("OPENCANARY_ACCESS_JSON", "1") != "0"
# El campo de IP llega entrecomillado en algunas versiones de Twisted y sin
# comillas en otras; ambos formatos son línea de acceso NCSA/combined.
ACCESS = re.compile(
    r'"?(?P<ip>[^"\s]+)"? - \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) \S+ "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)


def access_record(line: str) -> dict | None:
    """Parse one Twisted access line into an OpenCanary-shaped JSON record."""
    if not PERSIST_ACCESS:
        return None
    # /__fp is already logged with its full fingerprint by the HTTP handler.
    if " /__fp " in line:
        return None
    match = ACCESS.search(line.strip())
    if match is None:
        return None
    try:
        stamp = datetime.strptime(match["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        stamp = datetime.now(timezone.utc)
    logdata = {
        "PATH": match["path"],
        "USERAGENT": match["ua"],
        "METHOD": match["method"],
        "STATUS": match["status"],
        "PROTO": match["proto"],
    }
    # Referer del formato combined; "-" significa ausente.
    referer = match["ref"]
    if referer and referer != "-":
        logdata["REFERER"] = referer[:512]
    return {
        "src_host": match["ip"],
        "src_port": -1,
        "dst_host": "",
        "dst_port": 80,
        "logtype": 3000,
        "logdata": logdata,
        "utc_time": stamp.isoformat(),
        "message": line.rstrip("\n"),
    }


def main() -> int:
    fd = os.open(LOG_PATH, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        for line in sys.stdin:
            sys.stdout.write(line)
            sys.stdout.flush()
            record = access_record(line)
            if record is not None:
                payload = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
                os.write(fd, (payload + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
