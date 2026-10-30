#!/usr/bin/env python3
"""Explicit, opt-in runner for the runtime -> Elasticsearch export bridge.

Disabled by default: without ``--enable-elastic`` it prints a disabled summary
and touches neither the events database nor a cursor.  The sensor and ingest
services are never started or modified by this process.

Configuration and secrets
-------------------------
Non-secret Elasticsearch settings come from the environment, exactly like the
existing publisher (``DYSTOPIA_ELASTIC_URL``, ``_INDEX``, ``_CA_FILE``,
``_TIMEOUT``, ``_RETRIES``, ``_BACKOFF``, ``_MAX_BACKOFF``, ``_BATCH``,
``_QUEUE_MAX``, ``_QUEUE_BYTES``).  The API key is read only from the private
file named by ``DYSTOPIA_ELASTIC_API_KEY_FILE``; it is never accepted as an
argument and never printed.

The publisher queue is mandatory: the cursor advances after a document is
durably handed to that queue, so an Elasticsearch outage cannot lose events.

Examples
--------
    # Disabled by default: no state, no network.
    .venv/bin/python scripts/run_elastic_export.py \\
        --events /var/lib/dystopia/ingest/events.db \\
        --state /var/lib/dystopia/control/export-cursor.db

    # One bounded pass, explicitly enabled.
    DYSTOPIA_ELASTIC_URL=https://127.0.0.1:9200 \\
    DYSTOPIA_ELASTIC_API_KEY_FILE=/etc/dystopia/elastic/api-key \\
    DYSTOPIA_ELASTIC_QUEUE=/var/lib/dystopia/control/elastic-queue.db \\
    .venv/bin/python scripts/run_elastic_export.py \\
        --events /var/lib/dystopia/ingest/events.db \\
        --state /var/lib/dystopia/control/export-cursor.db \\
        --enable-elastic --once
"""

import argparse
from dataclasses import replace
import json
import logging
from pathlib import Path
import sqlite3
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.services.deception.integrations.elastic_svc import (  # noqa: E402
    ElasticsearchConfig,
    ElasticPublisher,
)
from app.services.deception.integrations.exporter_svc import (  # noqa: E402
    DEFAULT_BATCH,
    NativeExporter,
)
from runtime.storage import CapacityError  # noqa: E402

log = logging.getLogger("dystopia.elastic_export")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export persisted runtime v1 events to Elasticsearch (opt-in)."
    )
    parser.add_argument("--events", type=Path, required=True,
                        help="existing ingest EventStore SQLite file (read-only)")
    parser.add_argument("--state", type=Path, required=True,
                        help="private cursor SQLite file owned by the exporter")
    parser.add_argument("--enable-elastic", action="store_true",
                        help="explicit opt-in; without it nothing is read or written")
    parser.add_argument("--elastic-queue", type=Path, default=None,
                        help="override DYSTOPIA_ELASTIC_QUEUE (persistent queue required)")
    parser.add_argument("--batch", type=int, default=DEFAULT_BATCH,
                        help=f"maximum events per pass (1-1000, default {DEFAULT_BATCH})")
    parser.add_argument("--once", action="store_true",
                        help="process one bounded pass and exit (default)")
    parser.add_argument("--follow", action="store_true",
                        help="keep processing bounded passes until interrupted")
    parser.add_argument("--interval", type=float, default=30.0,
                        help="seconds between passes with --follow (minimum 1)")
    parser.add_argument("--log-level", default="WARNING",
                        choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    return parser


def build_exporter(args: argparse.Namespace) -> NativeExporter:
    base = ElasticsearchConfig.from_env()
    queue = args.elastic_queue if args.elastic_queue is not None else base.queue_path
    if queue is None:
        raise ValueError(
            "a persistent elastic queue is required: use --elastic-queue "
            "or DYSTOPIA_ELASTIC_QUEUE"
        )
    config = replace(base, enabled=True, queue_path=Path(queue)).validate()
    publisher = ElasticPublisher(config)
    return NativeExporter(
        args.events,
        args.state,
        publisher=publisher,
        batch_size=args.batch,
    )


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if args.follow and args.once:
        parser.error("--once and --follow are mutually exclusive")

    if not args.enable_elastic:
        print(json.dumps({
            "enabled": False,
            "reason": "elasticsearch export disabled; pass --enable-elastic",
        }, sort_keys=True), flush=True)
        return 0

    try:
        exporter = build_exporter(args)
        while True:
            summary = exporter.run_once()
            print(json.dumps(summary, sort_keys=True), flush=True)
            if not args.follow:
                return 0
            time.sleep(max(1.0, args.interval))
    except KeyboardInterrupt:
        return 0
    except (ValueError, OSError, CapacityError, sqlite3.Error) as exc:
        log.error("elastic_export_configuration_error type=%s", type(exc).__name__)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
