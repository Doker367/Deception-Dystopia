"""Explicit entry points. No daemon starts on import; sensors are never implicit."""
import argparse
import getpass
import ipaddress
import json
import os
from pathlib import Path
import time

from runtime.localfiles import create_private, read_private


def bootstrap(users_file, username, password):
    from runtime.contracts import identifier
    identifier(username)
    if len(password) < 16 or len(password.encode()) > 72:
        raise ValueError("password must contain 16+ characters and at most 72 UTF-8 bytes")
    import bcrypt
    # JSON is also valid YAML for the retained control authentication store.
    data = {"users": [{"username": username, "role": "admin", "name": username,
                       "password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()}]}
    if not create_private(users_file, json.dumps(data).encode()):
        raise FileExistsError("users already provisioned; bootstrap never overwrites")


def main(argv=None):
    p = argparse.ArgumentParser(description="Dystopia explicit service entry points")
    sub = p.add_subparsers(dest="command", required=True)
    control = sub.add_parser("control")
    control.add_argument("--host", default="127.0.0.1")
    control.add_argument("--port", type=int, default=8082)
    control.add_argument("--cert")
    control.add_argument("--key")
    ingest = sub.add_parser("ingest")
    ingest.add_argument("--host", required=True)
    ingest.add_argument("--port", type=int, default=8443)
    ingest.add_argument("--cert", required=True)
    ingest.add_argument("--key", required=True)
    ingest.add_argument("--registry", type=Path, required=True)
    ingest.add_argument("--events", type=Path, required=True)
    query = sub.add_parser("query", help="systemd Unix-socket read-only event query daemon")
    query.add_argument("--events", type=Path, required=True)
    admin = sub.add_parser("bootstrap-admin")
    admin.add_argument("--users", type=Path, required=True)
    admin.add_argument("--username", required=True)
    rotate = sub.add_parser("rotate-sensor")
    rotate.add_argument("--registry", type=Path, required=True)
    rotate.add_argument("--sensor", required=True)
    rotate.add_argument("--device", action="append", required=True)
    rotate.add_argument("--output", type=Path, required=True)
    revoke = sub.add_parser("revoke-sensor")
    revoke.add_argument("--registry", type=Path, required=True)
    revoke.add_argument("--sensor", required=True)
    sensor = sub.add_parser("sensor-drain")
    sensor.add_argument("--spool", type=Path, required=True)
    sensor.add_argument("--endpoint", required=True)
    sensor.add_argument("--ca", type=Path, required=True)
    sensor.add_argument("--token", type=Path, required=True)
    status = sub.add_parser("status")
    status.add_argument("--events", type=Path)
    status.add_argument("--spool", type=Path)
    args = p.parse_args(argv)
    os.umask(0o077)
    if args.command == "bootstrap-admin":
        first = getpass.getpass("Contraseña única del primer administrador: ")
        if first != getpass.getpass("Repetir contraseña: "):
            p.error("las contraseñas no coinciden")
        bootstrap(args.users, args.username, first)
    elif args.command in {"rotate-sensor", "revoke-sensor"}:
        from runtime.identity import Registry
        registry = Registry(args.registry)
        if args.command == "revoke-sensor":
            registry.revoke(args.sensor)
        else:
            registry.rotate(args.sensor, args.device, output=args.output)
    elif args.command in {"control", "ingest"}:
        import uvicorn
        address = ipaddress.ip_address(args.host)
        if address.is_unspecified or address.is_multicast:
            p.error("explicit unicast bind address required")
        if bool(args.cert) != bool(args.key):
            p.error("both TLS certificate and key required")
        if not address.is_loopback and not (args.cert and args.key):
            p.error("non-loopback control requires direct TLS")
        if args.key:
            read_private(args.key)
        if args.command == "control":
            from app.main import app
        else:
            from runtime.identity import Registry
            from runtime.ingest import create_app
            from runtime.storage import EventStore
            app = create_app(Registry(args.registry), EventStore(args.events))
        uvicorn.run(app, host=str(address), port=args.port, ssl_certfile=args.cert,
                    ssl_keyfile=args.key, proxy_headers=False, access_log=False,
                    workers=1, limit_concurrency=32, timeout_keep_alive=5,
                    h11_max_incomplete_event_size=16384)
    elif args.command == "query":
        from runtime.query import serve_production
        serve_production(args.events)
    elif args.command == "sensor-drain":
        from runtime.sensor import Spool, Transport
        spool = Spool(args.spool)
        transport = Transport(args.endpoint, args.ca, args.token)
        while True:
            spool.flush_once(transport)
            # Metrics are numeric/boolean only; no captured payload or credentials.
            print(json.dumps(spool.health()), flush=True)
            time.sleep(5)
    elif args.command == "status":
        if bool(args.events) == bool(args.spool):
            p.error("select exactly one store")
        from runtime.health import snapshot
        data = snapshot(args.events or args.spool, "ingest" if args.events else "sensor")
        print(json.dumps(data, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
