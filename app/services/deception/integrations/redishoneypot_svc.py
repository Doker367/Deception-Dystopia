"""Adapter for RedisHoneypot-style logs.

Accepted records are JSON objects with a source socket, optional session and
one of ``command``/``args``/``payload``. Redis commands are hostile input and
therefore live only in the non-indexed ``dystopia_restricted`` container;
authentication attempts are marked as such even when the honeypot never
accepts the credential.
"""

from typing import Any, Optional

from .ecs import build_event

OBSERVER = "redishoneypot"
PRODUCT = "RedisHoneypot"


def _text(raw: dict, *keys: str) -> Optional[str]:
    for key in keys:
        value = raw.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _command(raw: dict) -> Optional[str]:
    value = raw.get("command") or raw.get("payload")
    args = raw.get("args")
    suffix = ""
    if isinstance(args, (list, tuple)):
        suffix = " ".join(str(part) for part in args)
    elif args not in (None, ""):
        suffix = str(args)
    if value in (None, ""):
        return suffix or None
    prefix = (
        " ".join(str(part) for part in value)
        if isinstance(value, (list, tuple)) else str(value)
    )
    return f"{prefix} {suffix}".strip() if suffix else prefix


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
    command = _command(raw)
    username = _text(raw, "username", "user")
    password = _text(raw, "password", "pass")
    action = (_text(raw, "event", "action") or "").lower()
    if username or password:
        etype, outcome = "login_attempt", "failure"
    elif command:
        etype, outcome = "command", None
    elif any(token in action for token in ("disconnect", "closed", "close")):
        etype, outcome = "disconnect", None
    elif any(token in action for token in ("connect", "accept")):
        etype, outcome = "connect", None
    else:
        etype, outcome = "connect", None
    captured: dict[str, Any] = {}
    if command:
        captured["command"] = command
    message = _text(raw, "message", "msg")
    if message:
        captured["message"] = message
    try:
        dst_port = int(raw.get("dst_port") or 6379)
    except (TypeError, ValueError):
        dst_port = 6379
    return build_event(
        observer_name=OBSERVER,
        observer_product=PRODUCT,
        event_type=etype,
        timestamp=_text(raw, "timestamp", "time", "@timestamp", "date"),
        src_ip=_text(raw, "src_ip", "remote_host", "src"),
        src_port=raw.get("src_port") or raw.get("remote_port"),
        dst_ip=_text(raw, "dst_ip", "local_host", "dst"),
        dst_port=dst_port,
        protocol="redis",
        transport="tcp",
        session_id=_text(raw, "session", "session_id"),
        username=username,
        password=password,
        payload=captured,
        outcome=outcome,
        native_id=_text(raw, "id", "uuid", "session", "session_id"),
        raw=raw,
        raw_reference=raw_reference,
        resolver=resolver,
        device_id=default_device or _text(raw, "device_id", "sensor", "node_id") or "",
        instance_id=instance_id,
        fallback_timestamp=fallback_timestamp,
    )
