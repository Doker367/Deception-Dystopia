#!/usr/bin/env python3
"""Operator-side verification: local authenticated API only, no IP/token output.

Run on the Linux server after one approved external honeypot connection.
Expected public egress IP and JWT are supplied via environment, never via Git.
"""

import ipaddress
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta


BASE = "http://127.0.0.1:8082/api/analytics"


def fetch(path: str, token: str, **params: object) -> dict:
    query = urllib.parse.urlencode(params)
    request = urllib.request.Request(
        f"{BASE}/{path}?{query}", headers={"Authorization": f"Bearer {token}"}
    )
    # Ignore inherited HTTP(S)_PROXY so the JWT never leaves loopback.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=8) as response:
        return json.load(response)


def check(events: list[dict], origins: list[dict], expected_ip: str,
          country: str, region: str) -> bool:
    """A matching event AND its geolocated origin must both exist."""
    observed = any(
        item.get("source") == expected_ip
        and item.get("countryCode") == country
        and item.get("regionCode") == region
        for item in events
    )
    # Origins group by country+region; its 'ip' is only a representative when
    # several sources are in the same state. Never match that field to source.
    located = any(
        item.get("countryCode") == country
        and item.get("regionCode") == region
        and item.get("lat") is not None
        and item.get("lng") is not None
        and item.get("events", 0) >= 1
        for item in origins
    )
    return observed and located


def main() -> int:
    token = os.environ.get("DYSTOPIA_API_TOKEN", "")
    expected_ip = os.environ.get("EXPECTED_SOURCE_IP", "")
    country = os.environ.get("EXPECTED_COUNTRY_CODE", "")
    region = os.environ.get("EXPECTED_REGION_CODE", "")
    from_time = os.environ.get("PROBE_FROM_UTC", "")
    to_time = os.environ.get("PROBE_TO_UTC", "")
    if not all((token, expected_ip, country, region, from_time, to_time)):
        print("FAIL: supply token, expected source/country/region and UTC time window", file=sys.stderr)
        return 2
    try:
        address = ipaddress.ip_address(expected_ip)
        if address.version != 4 or not address.is_global:
            raise ValueError("expected source must be a public IPv4 address")
        start = datetime.fromisoformat(from_time.replace("Z", "+00:00"))
        end = datetime.fromisoformat(to_time.replace("Z", "+00:00"))
        if start.tzinfo is None or end.tzinfo is None or not timedelta(0) < end - start <= timedelta(minutes=10):
            raise ValueError("use a timezone-aware UTC window of at most 10 minutes")
        events = []
        for offset in range(0, 10_001, 100):
            page = fetch("events", token, **{"from": from_time, "to": to_time,
                                              "limit": 100, "offset": offset})
            events.extend(page.get("items", []))
            if offset + len(page.get("items", [])) >= page.get("total", 0):
                break
        origins = fetch("origins", token, **{"from": from_time, "to": to_time, "limit": 100})
        if check(events, origins.get("origins", []), expected_ip, country, region):
            print(f"PASS: real public source and regionCode={region} present in events and origins")
            return 0
        print("FAIL: expected public source and region not found in both analytics endpoints", file=sys.stderr)
        return 1
    except (ValueError, KeyError, TypeError, urllib.error.URLError, TimeoutError) as exc:
        # Do not echo request URLs, source IPs, tokens or response bodies.
        print(f"FAIL: verification unavailable ({type(exc).__name__})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
