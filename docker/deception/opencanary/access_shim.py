#!/usr/bin/env python3
"""Forward OpenCanary's Twisted stdout and persist HTTP access lines as JSONL.

OpenCanary logs arbitrary HTTP paths (including 404 probes) through Twisted's
access logger on stdout, not through its JSON logger. The collector tails the
JSON file, so without this shim those requests never reach the panel.

The shim is intentionally small and read-only with respect to the request:
it copies stdout unchanged for ``docker logs`` and appends one bounded JSON
line per matching access record to ``opencanary.log``. Captured passwords are
not present in the access log; POST bodies are not read.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import re
import sys

LOG_PATH = os.environ.get("OPENCANARY_ACCESS_LOG", "/var/log/opencanary/opencanary.log")
ACCESS = re.compile(
    r'^"(?P<ip>[^"]+)" \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) \S+ "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)


def access_record(line: str) -> dict | None:
    match = ACCESS.match(line.strip())
    if match is None:
        return None
    try:
        stamp = datetime.strptime(match["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        stamp = datetime.now(timezone.utc)
    return {
        "src_host": match["ip"],
        "src_port": -1,
        "dst_host": "",
        "dst_port": 80,
        "logtype": 3000,
        "logdata": {
            "PATH": match["path"],
            "USERAGENT": match["ua"],
            "METHOD": match["method"],
            "STATUS": match["status"],
            "PROTO": match["proto"],
        },
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
