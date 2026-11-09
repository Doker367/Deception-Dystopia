"""Strict v1 telemetry wire contract, independent of administrative settings."""
from datetime import datetime, timezone
from ipaddress import ip_address
import json
import re
from uuid import UUID

MAX_EVENT_BYTES = 8192
MAX_BATCH_BYTES = 262144
MAX_BATCH_EVENTS = 64
ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}\Z")
TYPES = {"connect", "disconnect", "login_attempt", "login_success", "command",
         "file_download", "port_scan", "other"}


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError("invalid identifier")
    return value


def timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("invalid timestamp")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError("timezone required")
        return dt.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError):
        raise ValueError("invalid timestamp or UTC range") from None


def encode(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()


def validate_event(event):
    required = {"event_id", "device_id", "observed_at", "src_ip", "type", "proto"}
    optional = {"src_port", "dst_ip", "dst_port", "detail"}
    if not isinstance(event, dict) or not required <= event.keys() or event.keys() - required - optional:
        raise ValueError("invalid event fields (identity and simulation flags are not accepted)")
    if len(encode(event)) > MAX_EVENT_BYTES:
        raise ValueError("event too large")
    identifier(event["device_id"])
    if not isinstance(event["event_id"], str):
        raise ValueError("invalid event ID")
    try:
        uid = UUID(event["event_id"])
    except (ValueError, AttributeError):
        raise ValueError("invalid event ID") from None
    if uid.version != 4 or str(uid) != event["event_id"]:
        raise ValueError("canonical UUID4 required")
    timestamp(event["observed_at"])
    if not isinstance(event["src_ip"], str) or "%" in event["src_ip"]:
        raise ValueError("invalid source address")
    try:
        canonical_ip = str(ip_address(event["src_ip"]))
    except ValueError:
        raise ValueError("invalid source address") from None
    if event["src_ip"] != canonical_ip:
        raise ValueError("canonical source address required")
    if event["type"] not in TYPES or event["proto"] not in {"tcp", "udp", "ssh", "telnet", "http", "ftp", "mysql", "snmp"}:
        raise ValueError("invalid event kind")
    port = event.get("src_port")
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError("invalid source port")
    dst_ip = event.get("dst_ip")
    if dst_ip is not None:
        if not isinstance(dst_ip, str) or "%" in dst_ip:
            raise ValueError("invalid destination address")
        try:
            canonical_dst = str(ip_address(dst_ip))
        except ValueError:
            raise ValueError("invalid destination address") from None
        if dst_ip != canonical_dst:
            raise ValueError("canonical destination address required")
    dst_port = event.get("dst_port")
    if dst_port is not None and (type(dst_port) is not int or not 1 <= dst_port <= 65535):
        raise ValueError("invalid destination port")
    detail = event.get("detail", {})
    # Opaque hostile strings only, no nested objects or execution semantics.
    if not isinstance(detail, dict) or len(detail) > 16:
        raise ValueError("invalid detail")
    for key, value in detail.items():
        identifier(key)
        if key in {"simulated", "sensor_id", "trusted", "suppress"}:
            raise ValueError("reserved detail field")
        if not isinstance(value, str) or len(value.encode()) > 2048:
            raise ValueError("detail value too large or not a string")
    return dict(event)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def decode_batch(raw):
    if len(raw) > MAX_BATCH_BYTES:
        raise ValueError("batch too large")
    try:
        body = json.loads(raw, object_pairs_hook=_unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
        if not isinstance(body, dict) or set(body) != {"version", "events"} or type(body["version"]) is not int or body["version"] != 1:
            raise ValueError("unsupported contract")
        events = body["events"]
        if not isinstance(events, list) or not 1 <= len(events) <= MAX_BATCH_EVENTS:
            raise ValueError("invalid batch count")
        events = [validate_event(e) for e in events]
        if len({e["event_id"] for e in events}) != len(events):
            raise ValueError("duplicate ID within batch")
        return events
    except (TypeError, RecursionError, UnicodeError, KeyError) as exc:
        raise ValueError("invalid batch") from exc
