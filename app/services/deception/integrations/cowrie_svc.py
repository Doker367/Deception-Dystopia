"""Parser de eventos de Cowrie (SSH/Telnet medium-interaction).

Cowrie emite un JSON por línea con un campo ``eventid``. El parser heredado
``parse`` se conserva para el tailer/telemetría existente; ``normalize``
produce el contrato ECS/Dystopia común sin perder eventos desconocidos.
"""

from typing import Any, Optional
from uuid import UUID

from .ecs import build_event

# eventid de Cowrie → tipo de evento NetPulse
_EVENT_MAP = {
    "cowrie.session.connect": "connect",
    "cowrie.login.failed": "login_attempt",
    "cowrie.login.success": "login_success",
    "cowrie.command.input": "command",
    "cowrie.session.file_download": "file_download",
}

# eventid de Cowrie → (tipo normalizado, outcome opcional)
_ECS_EVENT_MAP = {
    "cowrie.session.connect": ("connect", None),
    "cowrie.session.closed": ("disconnect", None),
    "cowrie.login.failed": ("login_attempt", "failure"),
    "cowrie.login.success": ("login_success", "success"),
    "cowrie.command.input": ("command", None),
    "cowrie.session.file_download": ("file_download", "success"),
    "cowrie.session.file_upload": ("file_upload", "success"),
}

OBSERVER = "cowrie"
PRODUCT = "Cowrie"


def parse(raw: dict, default_device: str = "") -> Optional[dict]:
    """Traduce un evento Cowrie a kwargs de ``telemetry_svc.emit``.

    Args:
        raw: Diccionario JSON de una línea de ``cowrie.json``.
        default_device: device_id a usar (Cowrie no conoce nuestros ids).

    Returns:
        Dict de kwargs, o None si el evento no es relevante.
    """
    eventid = raw.get("eventid", "")
    etype = _EVENT_MAP.get(eventid)
    if etype is None:
        return None

    detail: dict = {"sensor": "cowrie", "eventid": eventid}
    if raw.get("input"):
        detail["command"] = raw["input"]
    if raw.get("password"):
        detail["password"] = raw["password"]
    if raw.get("url"):
        detail["url"] = raw["url"]
    if raw.get("session"):
        detail["session"] = raw["session"]

    return {
        "device_id": default_device or raw.get("sensor") or "cowrie",
        "src_ip": raw.get("src_ip", "0.0.0.0"),
        "src_port": raw.get("src_port"),
        "proto": "ssh",
        "event_type": etype,
        "detail": detail,
        "username": raw.get("username"),
        "success": eventid == "cowrie.login.success",
        "ts": raw.get("timestamp"),
    }


def payload(raw: dict) -> dict[str, Any]:
    """Captured hostile content, published only in the restricted container."""
    captured: dict[str, Any] = {}
    if raw.get("input"):
        captured["command"] = raw["input"]
    if raw.get("url"):
        captured["url"] = raw["url"]
    if raw.get("filename"):
        captured["file"] = raw["filename"]
    elif raw.get("outfile"):
        captured["file"] = raw["outfile"]
    if raw.get("shasum"):
        captured["hash"] = raw["shasum"]
    if raw.get("message") and not raw.get("input"):
        captured["message"] = raw["message"]
    return captured


def _native_uuid(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        return None
    return value if parsed.version == 4 and str(parsed) == value else None


def normalize(
    raw: Any,
    *,
    resolver=None,
    instance_id: str = "unassigned",
    default_device: str = "",
    fallback_timestamp: Any = None,
    raw_reference: Any = None,
) -> Optional[dict]:
    """Normalize one Cowrie JSON record; unknown eventids become ``other``."""
    if not isinstance(raw, dict):
        return None
    eventid = str(raw.get("eventid") or "")
    # Cowrie normally puts the event name in ``eventid``. Some collectors use a
    # UUID there and mirror the event name in ``message``; accept both.
    event_name = eventid if eventid in _ECS_EVENT_MAP else str(raw.get("message") or "")
    etype, outcome = _ECS_EVENT_MAP.get(event_name, ("other", None))
    device = (
        default_device
        or raw.get("device_id")
        or raw.get("sensor")
        or raw.get("node_id")
        or ""
    )
    protocol = raw.get("protocol") or ("telnet" if "telnet" in event_name.lower() else "ssh")
    native_id = raw.get("uuid") or raw.get("id") or _native_uuid(eventid)
    return build_event(
        observer_name=OBSERVER,
        observer_product=PRODUCT,
        event_type=etype,
        timestamp=raw.get("timestamp") or raw.get("time"),
        src_ip=raw.get("src_ip"),
        src_port=raw.get("src_port"),
        dst_ip=raw.get("dst_ip"),
        dst_port=raw.get("dst_port"),
        protocol=protocol,
        transport="tcp",
        session_id=raw.get("session"),
        username=raw.get("username"),
        password=raw.get("password"),
        payload=payload(raw),
        outcome=outcome,
        native_id=native_id,
        raw=raw,
        raw_reference=raw_reference,
        resolver=resolver,
        device_id=device,
        instance_id=instance_id or raw.get("sensor"),
        fallback_timestamp=fallback_timestamp,
    )
