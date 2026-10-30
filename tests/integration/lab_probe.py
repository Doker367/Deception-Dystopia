"""Manual-only synthetic connectivity probe. NEVER authorizes cell activation.

Run as root only inside the authorized disposable Linux lab guest/client.
No listener, firewall or route changes. A successful denied connection fails.
Timeouts alone are observations, NOT evidence that the isolation policy worked.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import platform
import socket
import stat
import time

SYNTHETIC = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "fd42:d570::/32"))


def validate_targets(data):
    if not isinstance(data, list) or not 1 <= len(data) <= 16:
        raise ValueError("one to sixteen explicitly synthetic targets required")
    for target in data:
        if set(target) != {"name", "ip", "port", "expect"}:
            raise ValueError("invalid target fields")
        ip = ipaddress.ip_address(target["ip"])
        if not any(ip.version == net.version and ip in net for net in SYNTHETIC):
            raise ValueError("non-synthetic destination forbidden")
        if target["expect"] not in {"allow", "deny"} or type(target["port"]) is not int or not 1024 <= target["port"] <= 65535:
            raise ValueError("invalid port or expectation")
        if not isinstance(target["name"], str) or len(target["name"]) > 64:
            raise ValueError("invalid label")
    return data


def probe(target):
    ip = ipaddress.ip_address(target["ip"])
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    connected, banner = False, False
    start = time.monotonic()
    outcome = "unknown"
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        try:
            sock.connect((str(ip), target["port"]))
            connected = True
            outcome = "connected"
            sock.sendall(b"DYSTOPIA-LAB-v1\n")
            banner = sock.recv(64) == b"DYSTOPIA-LAB-v1\n"
        except socket.timeout:
            outcome = "timeout_after_connect" if connected else "timeout"
        except OSError as exc:
            outcome = "os_error_" + str(exc.errno)
    passed = (connected and banner) if target["expect"] == "allow" else not connected
    return {**target, "connected": connected, "synthetic_banner": banner,
            "observation_matches_expectation": passed, "outcome": outcome,
            "elapsed_seconds": round(time.monotonic()-start, 3)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--targets", type=Path, required=True)
    p.add_argument("--confirm", required=True)
    args = p.parse_args()
    if args.confirm != "DISPOSABLE-LAB-ONLY" or platform.system() != "Linux" or os.geteuid() != 0:
        p.error("explicit authorization and root inside disposable Linux guest/client required")
    marker = Path("/etc/dystopia-disposable-lab.json")
    fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 4096:
            p.error("root-owned bounded lab authorization marker required")
        authorization = json.loads(stream.read(4097))
    if authorization.get("purpose") != "dystopia-disposable-lab" or not authorization.get("authorization_id"):
        p.error("invalid lab authorization marker")
    targets = validate_targets(json.loads(args.targets.read_text()))
    results = [probe(t) for t in targets]
    print(json.dumps({"authorization_id": authorization["authorization_id"],
                      "containment_verified": False, "results": results,
                      "requires": "baseline reachable services, captures, host counters, topology review, L2 tests"}, indent=2))
    return 0 if all(r["observation_matches_expectation"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
