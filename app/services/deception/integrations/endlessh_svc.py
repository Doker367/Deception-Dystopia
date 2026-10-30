"""Adapter for Endlessh (SSH tarpit).

Endlessh typically logs plain text such as::

    2026/09/24 10:00:00 203.0.113.9:41234 connected
    2026-09-24T10:00:05Z 203.0.113.9:41234 closed

JSON records are accepted too. Lines without a recognisable socket are kept
as ``other`` so an operator can still see the sensor is alive; the raw text is
confined to ``dystopia.payload.message``.
"""

from datetime import datetime
import re
from typing import Any, Optional

from .ecs import build_event

OBSERVER = "endlessh"
PRODUCT = "Endlessh"

_SOCKET = re.compile(
    r"(?P<ip>(?:\d{1,3}(?:\.\d{1,3}){3})|(?:\[[0-9a-fA-F:]+\])|"
    r"(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*)"
    r":(?P<port>\d{1,5})"
)
_GO_STAMP = re.compile(r"^(\d{4})/(\d{2})/(\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)")
_ISO_STAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))"
)


def _event_name(text: str) -> tuple[str, Optional[str]]:
    low = text.lower()
    if any(token in low for token in ("disconnect", "closed", "close", "timeout", "drop")):
        return "disconnect", None
    if any(token in low for token in ("connect", "accepted", "accept")):
        return "connect", None
    return "other", None


def _text(raw: dict, *keys: str) -> Optional[str]:
    for key in keys:
        value = raw.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _parse_string(line: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    iso = _ISO_STAMP.match(line)
    if iso:
        parsed["timestamp"] = iso.group(1)
    else:
        stamp = _GO_STAMP.match(line)
        if stamp:
            try:
                parsed["timestamp"] = datetime.fromisoformat(
                    "-".join(stamp.groups()[:3]) + "T" + stamp.group(4)
                ).isoformat()
            except ValueError:
                pass
    socket = _SOCKET.search(line)
    if socket:
        parsed["src_ip"] = socket.group("ip").strip("[]")
        parsed["src_port"] = int(socket.group("port"))
    etype, _ = _event_name(line)
    parsed["event"] = etype
    parsed["message"] = line
    return parsed


def normalize(
    raw: Any,
    *,
    resolver=None,
    instance_id: str = "unassigned",
    default_device: str = "",
    fallback_timestamp: Any = None,
    raw_reference: Any = None,
) -> Optional[dict]:
    if isinstance(raw, str):
        original = raw
        data = _parse_string(raw)
    elif isinstance(raw, dict):
        original = raw
        data = raw
    else:
        return None
    etype = data.get("event") or data.get("event_type") or "connect"
    if etype not in {"connect", "disconnect", "other"}:
        etype, _ = _event_name(str(etype))
    try:
        dst_port = int(data.get("dst_port") or 2222)
    except (TypeError, ValueError):
        dst_port = 2222
    captured: dict[str, Any] = {}
    message = _text(data, "message", "msg")
    if message:
        captured["message"] = message
    return build_event(
        observer_name=OBSERVER,
        observer_product=PRODUCT,
        event_type=etype,
        timestamp=_text(data, "timestamp", "time", "@timestamp", "date"),
        src_ip=_text(data, "src_ip", "remote_host", "src"),
        src_port=data.get("src_port") or data.get("remote_port"),
        dst_ip=_text(data, "dst_ip", "local_host", "dst"),
        dst_port=dst_port,
        protocol="ssh",
        transport="tcp",
        session_id=_text(data, "session", "session_id"),
        payload=captured,
        native_id=_text(data, "id", "uuid"),
        raw=original,
        raw_reference=raw_reference,
        resolver=resolver,
        device_id=default_device or _text(data, "device_id", "sensor", "node_id") or "",
        instance_id=instance_id,
        fallback_timestamp=fallback_timestamp,
    )
