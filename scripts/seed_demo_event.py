#!/usr/bin/env python3
"""Send one synthetic ECS/Dystopia event to a local Elasticsearch data stream.

This is a local-demo helper. It never reads or prints captured credentials.
The API key is read from a file; the event contains only synthetic values.

Example:
    DYSTOPIA_ELASTIC_CA_CERT="$LAB/certs/ca.crt" \
    DYSTOPIA_ELASTIC_API_KEY_FILE="$LAB/api-keys/deception-ingest-writer.api-key" \
    python3 scripts/seed_demo_event.py --url https://127.0.0.1:9200
"""
import argparse
import json
import ssl
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_event(event_id: str) -> dict:
    now = _now()
    return {
        "@timestamp": now,
        "event": {
            "id": event_id,
            "kind": "event",
            "category": ["authentication"],
            "type": ["start"],
            "action": "login",
            "severity": 5,
            "outcome": "failure",
            "dataset": "deception.cowrie",
            "ingested": now,
        },
        "source": {
            "ip": "203.0.113.50",
            "port": 55555,
            "geo": {
                "country_name": "Testland",
                "country_iso_code": "TL",
                "location": {"lat": 40.0, "lon": -3.0},
            },
        },
        "destination": {"ip": "192.0.2.10", "port": 22},
        "network": {"transport": "tcp", "protocol": "ssh"},
        "observer": {
            "type": "honeypot",
            "name": "cowrie",
            "product": "Cowrie",
            "vendor": "Dystopia",
        },
        "session": {"id": f"demo-{uuid.uuid4().hex[:12]}"},
        "dystopia": {
            "schema_version": "1.0",
            "device_id": "demo-srv-01",
            "segment_id": "demo-segment",
            "instance_id": "demo-cell",
            "persona": "linux",
            "raw_reference": f"synthetic:{event_id}",
            "ingest_source": "native",
            "control_version": "1",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="https://127.0.0.1:9200")
    parser.add_argument(
        "--api-key-file",
        default="deploy/elastic/api-keys/deception-ingest-writer.api-key",
    )
    parser.add_argument("--ca-cert", default="deploy/elastic/certs/ca.crt")
    parser.add_argument("--event-id", default=f"demo-{uuid.uuid4().hex[:12]}")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    event = build_event(args.event_id)
    if args.dry_run:
        print(json.dumps(event, indent=2, ensure_ascii=False))
        return 0

    key_path = Path(args.api_key_file)
    if not key_path.is_file():
        print(f"missing API key file: {key_path}", file=sys.stderr)
        return 2
    api_key = key_path.read_text(encoding="utf-8").strip()
    if not api_key:
        print(f"empty API key file: {key_path}", file=sys.stderr)
        return 2

    context = ssl.create_default_context(cafile=args.ca_cert)
    url = f"{args.url.rstrip('/')}/deception-events/_create/{args.event_id}"
    request = Request(
        url,
        data=json.dumps(event).encode("utf-8"),
        method="PUT",
        headers={
            "Authorization": f"ApiKey {api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urlopen(request, context=context, timeout=10) as response:
            body = json.loads(response.read().decode("utf-8"))
            print(f"created {body.get('_id')} in {body.get('_index')} (HTTP {response.status})")
    except HTTPError as exc:
        print(f"Elasticsearch rejected the event: HTTP {exc.code} {exc.reason}", file=sys.stderr)
        return 1
    except URLError as exc:
        print(f"cannot reach Elasticsearch: {exc.reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
