"""Adapter for Heralding (multi-protocol credential catcher).

Heralding writes one JSON object per authentication attempt with protocol,
source/destination tuple and captured credentials. Records without credentials
are treated as connection events instead of being discarded.
"""

from typing import Any, Optional

from .ecs import build_event, protocol_for_port

OBSERVER = "heralding"
PRODUCT = "Heralding"

_PROTOCOLS = {
    "ssh": "ssh", "telnet": "telnet", "ftp": "ftp", "http": "http",
    "https": "https", "smtp": "smtp", "pop3": "pop3", "imap": "imap",
    "mysql": "mysql", "mssql": "mssql", "rdp": "rdp", "vnc": "vnc",
    "redis": "redis", "postgresql": "postgresql", "sip": "sip",
}


def _text(raw: dict, *keys: str) -> Optional[str]:
    for key in keys:
        value = raw.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _first_mapping(value: Any) -> dict:
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    if isinstance(value, dict):
        return value
    return {}


def normalize(
    raw: Any,
    *,
    resolver=None,
    instance_id: str = "unassigned",
    default_device: str = "",
    fallback_timestamp: Any = None,
    raw_reference: Any = None,
) -> Optional[dict]:
    if not isinstance(raw, dict):
        return None
    try:
        dst_port = int(raw.get("dst_port") or raw.get("destination_port") or 0)
    except (TypeError, ValueError):
        dst_port = None
    dst_port = dst_port if dst_port is not None and 0 <= dst_port <= 65535 else None
    explicit = _text(raw, "protocol", "proto", "service")
    protocol = _PROTOCOLS.get((explicit or "").lower()) or protocol_for_port(dst_port, "tcp")
    attempt = _first_mapping(raw.get("auth_attempts"))
    username = _text(raw, "username", "user") or _text(attempt, "username", "user")
    password = _text(raw, "password", "pass") or _text(attempt, "password", "pass")
    if username or password:
        etype, outcome = "login_attempt", "failure"
    else:
        etype, outcome = "connect", None
    captured: dict[str, Any] = {}
    message = _text(raw, "message", "msg")
    if message:
        captured["message"] = message
    return build_event(
        observer_name=OBSERVER,
        observer_product=PRODUCT,
        event_type=etype,
        timestamp=_text(raw, "timestamp", "time", "@timestamp", "date"),
        src_ip=_text(raw, "src_ip", "source_ip", "remote_host", "src"),
        src_port=(
            raw.get("src_port") or raw.get("source_port")
            or raw.get("remote_port")
        ),
        dst_ip=_text(raw, "dst_ip", "destination_ip", "local_host", "dst"),
        dst_port=dst_port,
        protocol=protocol,
        session_id=_text(raw, "session", "session_id"),
        username=username,
        password=password,
        payload=captured,
        outcome=outcome,
        native_id=_text(raw, "id", "uuid", "session_id", "session"),
        raw=raw,
        raw_reference=raw_reference,
        resolver=resolver,
        device_id=default_device or _text(raw, "device_id", "sensor", "node_id") or "",
        instance_id=instance_id,
        fallback_timestamp=fallback_timestamp,
    )
