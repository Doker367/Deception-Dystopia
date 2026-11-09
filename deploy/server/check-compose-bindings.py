#!/usr/bin/env python3
"""Fail-closed Linux preflight for effective Compose publishes; never print secrets.

Feed `docker compose ... config --format json` on stdin. Do not store that
JSON: it contains interpolated application secrets. The only successful output
is a short PASS message with no addresses.
"""

import ipaddress
import json
import os
import re
import subprocess
import sys

WG_IP = "10.66.0.3"
PORTS = {
    "cowrie": {12222: 2222, 12223: 2223},
    "opencanary": {13022: 22, 13080: 80},
    "dionaea": {14021: 21},
    "heralding": {15021: 21},
    "redishoneypot": {16379: 6379},
    "endlessh": {17222: 2222},
}


def _bindings(service: dict) -> set[tuple[str, int, int, str]]:
    ports = service.get("ports", [])
    if not isinstance(ports, list):
        raise ValueError("invalid Compose ports")
    result = set()
    for port in ports:
        if not isinstance(port, dict):
            raise ValueError("unresolved Compose port")
        item = (str(port.get("host_ip", "")), int(port["published"]),
                int(port["target"]), str(port.get("protocol", "tcp")))
        if item in result:
            raise ValueError("duplicate Compose port")
        result.add(item)
    return result


def valid(config: dict, tailscale_ip: str, assigned_tail_ips: set[str]) -> bool:
    """Check the entire effective publish set, not only the source override."""
    try:
        address = ipaddress.ip_address(tailscale_ip)
        if address.version != 4 or address not in ipaddress.ip_network("100.64.0.0/10"):
            return False
        if tailscale_ip not in assigned_tail_ips or tailscale_ip == WG_IP:
            return False
        services = config["services"]
        if _bindings(services["control"]) != {
            ("127.0.0.1", 8082, 8082, "tcp"), (tailscale_ip, 8082, 8082, "tcp")
        }:
            return False
        for name, ports in PORTS.items():
            expected = {
                (host, published, target, "tcp")
                for host in ("127.0.0.1", WG_IP)
                for published, target in ports.items()
            }
            if _bindings(services[name]) != expected:
                return False
        return all(not _bindings(service) for name, service in services.items()
                   if name not in PORTS and name != "control")
    except (KeyError, ValueError, TypeError, AttributeError):
        return False


def main() -> int:
    try:
        tail_ip = os.environ.get("DYSTOPIA_TAILSCALE_IP", "")
        proc = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "dev", "tailscale0"],
            check=True, capture_output=True, text=True, timeout=5,
        )
        assigned = set(re.findall(r"\binet (\d+\.\d+\.\d+\.\d+)/", proc.stdout))
        config = json.load(sys.stdin)
        if valid(config, tail_ip, assigned):
            print("PASS: eight WG/loopback decoys; panel on loopback and tailscale0 only")
            return 0
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        pass
    print("FAIL: invalid Tailscale interface or effective Compose port bindings", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
