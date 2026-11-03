"""Explicit entry points. No daemon starts on import; sensors are never implicit."""
import argparse
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time

from runtime.localfiles import create_private, read_private

REPO_ROOT = Path(__file__).resolve().parent.parent
HONEYPOT_INVENTORY = REPO_ROOT / "deploy/honeypots/inventory.yaml"
HONEYPOT_PROFILE = REPO_ROOT / "deploy/honeypots/profiles/cell-mvp.example.yaml"
_CREATE_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


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


def _backup_common(parser):
    # Lazy import: no hygiene change, no side effects, keeps CLI startup lean.
    from runtime import backup
    parser.add_argument("--state-root", type=Path, default=backup.STATE_ROOT)
    parser.add_argument("--control-env-dir", type=Path, default=backup.CONTROL_ENV_DIR)
    return parser


def _backup_report(payload, file=None):
    print(json.dumps(payload, sort_keys=True), file=file or sys.stdout, flush=True)


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
    honeypots = sub.add_parser("honeypots", help="read-only per-cell honeypot compose planning")
    honeypots.add_argument("action", choices=("plan", "render", "validate") +
                           ("apply", "up", "down"))
    honeypots.add_argument("--inventory", type=Path, default=HONEYPOT_INVENTORY)
    honeypots.add_argument("--profile", type=Path, default=HONEYPOT_PROFILE)
    honeypots.add_argument("--output", type=Path)
    cells = sub.add_parser("cells", help="offline cell admission contracts")
    cell_sub = cells.add_subparsers(dest="cell_action", required=True)
    gate = cell_sub.add_parser("gate", help="evaluate cell verification evidence without effects")
    gate.add_argument("--cell", type=int, required=True)
    gate.add_argument("--policy", type=Path, required=True)
    gate.add_argument("--artifacts", type=Path)
    _backup_common(sub.add_parser(
        "backup-plan", help="read-only backup plan; fails if state artifacts are missing"))
    bexport = _backup_common(sub.add_parser(
        "backup-export", help="export control state and analytics config offline"))
    bexport.add_argument("--output", type=Path, required=True)
    bexport.add_argument("--label", default="backup")
    bexport.add_argument("--created-at",
                         help="deterministic UTC timestamp (YYYY-MM-DDTHH:MM:SSZ)")
    brestore = _backup_common(sub.add_parser(
        "backup-restore", help="verify a backup completely, then restore; never overwrites"))
    brestore.add_argument("--backup", type=Path, required=True)

    args = p.parse_args(argv)
    # The offline gate is read-only; do not even change process umask on that path.
    if args.command != "cells":
        os.umask(0o077)
    if args.command == "cells":
        from runtime.cell_gate import (
            REQUIRED_ARTIFACTS, CellGateContext, evaluate_cell_gate,
        )
        from runtime.isolation.containers import ContainerCellPolicy
        from runtime.isolation.policy import CellPolicy

        def unique_object(pairs):
            document = {}
            for key, value in pairs:
                if key in document:
                    raise ValueError("duplicate JSON key")
                document[key] = value
            return document

        try:
            raw = args.policy.read_bytes()
            if len(raw) > 16384:
                raise ValueError("policy exceeds 16 KiB")
            document = json.loads(raw, object_pairs_hook=unique_object)
            if type(document) is not dict:
                raise ValueError("policy object required")
            policy = (ContainerCellPolicy.from_mapping(document)
                      if document.get("workload") == "container"
                      else CellPolicy.from_mapping(document))
            result = evaluate_cell_gate(
                policy, CellGateContext(cell=args.cell), artifacts_path=args.artifacts,
            )
            payload = result.as_dict()
        except (OSError, ValueError, TypeError) as exc:
            payload = {
                "activation_allowed": False,
                "blocking_reasons": [f"policy unavailable or invalid: {exc}"],
                "containment_verified": False,
                "detail": "activation blocked; validated cell policy is required",
                "required_artifacts": list(REQUIRED_ARTIFACTS),
            }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if payload["activation_allowed"] else 2
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
    elif args.command == "honeypots":
        from runtime import honeypots
        if args.action in honeypots.BLOCKED_ACTIONS:
            # No containment verification exists; activation is unreachable.
            try:
                honeypots.blocked(args.action)
            except honeypots.HoneypotBlocked as exc:
                print(json.dumps({"action": args.action, "state": "blocked",
                                  "containment_verified": False, "detail": str(exc)}),
                      file=sys.stderr)
                return 2
        try:
            if args.action == "render":
                inventory = honeypots.load_inventory(args.inventory)
                cell = honeypots.load_cell(args.profile, inventory)
                text = honeypots.dump_cell(inventory, cell)
                if args.output:
                    try:
                        args.output.write_text(text, encoding="utf-8")
                    except OSError as exc:
                        p.error(f"cannot write compose file: {exc.strerror or exc}")
                    print(json.dumps({"action": "render", "output": str(args.output),
                                      "containment_verified": False,
                                      "activation_allowed": False}, sort_keys=True))
                else:
                    print(text, end="")
            elif args.output is not None:
                p.error("--output is only valid with render")
            elif args.action == "plan":
                print(json.dumps(honeypots.plan(args.inventory, args.profile),
                                 indent=2, sort_keys=True))
            else:
                print(json.dumps(honeypots.validate(args.inventory, args.profile),
                                 indent=2, sort_keys=True))
        except honeypots.HoneypotError as exc:
            p.error(str(exc))
    elif args.command in {"backup-plan", "backup-export", "backup-restore"}:
        from runtime import backup as contract
        try:
            if args.command == "backup-plan":
                report = contract.plan(state_root=args.state_root,
                                       control_env_dir=args.control_env_dir)
                _backup_report({"schema": report["schema"], "action": report["action"],
                                "dry_run": report["dry_run"],
                                "artifact_count": len(report["artifacts"]),
                                "required_count": report["required_count"],
                                "optional_count": report["optional_count"],
                                "artifacts": report["artifacts"]})
            elif args.command == "backup-export":
                if args.created_at is not None \
                        and not _CREATE_AT.fullmatch(args.created_at):
                    p.error("--created-at must use YYYY-MM-DDTHH:MM:SSZ (UTC)")
                manifest, data = contract.create_backup(
                    contract.default_artifact_specs(args.state_root,
                                                    args.control_env_dir),
                    args.output, created_at=args.created_at, label=args.label)
                _backup_report({"schema": manifest["schema"], "backup_dir": str(args.output),
                                "backup_id": contract.backup_id(manifest),
                                "created_at": manifest["created_at"],
                                "artifact_count": manifest["artifact_count"],
                                "manifest_bytes": len(data)})
            else:
                report = contract.restore(args.backup, state_root=args.state_root,
                                          control_env_dir=args.control_env_dir)
                _backup_report({"schema": report["schema"], "action": report["action"],
                                "backup_dir": report["backup_dir"],
                                "created_at": report["created_at"],
                                "restored": sorted(report["restored"]),
                                "overwrites": report["overwrites"]})
        except (contract.BackupError, FileExistsError, FileNotFoundError,
                PermissionError, sqlite3.Error) as exc:
            _backup_report({"error": type(exc).__name__, "detail": str(exc)}, sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
