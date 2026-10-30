"""Parser de eventos de OpenCanary (honeypot multi-protocolo ligero).

OpenCanary emite líneas JSON con ``dst_port``, ``src_host``, ``msg`` y
``logtype``. El parser heredado ``parse`` se mantiene; ``normalize`` añade el
contrato ECS/Dystopia y conserva eventos cuyo dispositivo no está en la
topología.
"""

from typing import Any, Optional

from .ecs import build_event, protocol_for_port

# Puerto destino → protocolo
_PORT_PROTO = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http",
    110: "pop3", 143: "imap", 161: "snmp", 443: "https", 445: "smb",
    1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http",
}

# OpenCanary logtype (miles) → protocolo.
_LOGTYPE_PROTO = {
    1: "ftp", 2: "ssh", 3: "http", 4: "telnet", 5: "http", 6: "mysql",
    7: "mssql", 8: "snmp", 9: "redis", 10: "tcp", 11: "smb", 12: "rdp",
}

OBSERVER = "opencanary"
PRODUCT = "OpenCanary"


def parse(raw: dict, default_device: str = "") -> Optional[dict]:
    """Traduce un evento OpenCanary a kwargs de ``telemetry_svc.emit``.

    Returns:
        Dict de kwargs, o None si la línea no es un evento válido.
    """
    src_ip = raw.get("src_host") or raw.get("src_ip")
    if not src_ip:
        return None

    try:
        dst_port = int(raw.get("dst_port", 0) or 0)
    except (TypeError, ValueError):
        dst_port = 0
    proto = _PORT_PROTO.get(dst_port, "tcp")
    if dst_port == 161:
        proto = "snmp"

    msg = str(raw.get("msg", ""))
    low = msg.lower()
    if "login" in low or "password" in low or "credential" in low:
        etype = "login_attempt"
    elif dst_port in (161,):
        etype = "snmp_query"
    else:
        etype = "connect"

    return {
        "device_id": default_device or raw.get("node_id") or "opencanary",
        "src_ip": src_ip,
        "src_port": raw.get("src_port"),
        "proto": proto,
        "event_type": etype,
        "detail": {"sensor": "opencanary", "logtype": raw.get("logtype"),
                   "dst_port": dst_port, "msg": msg},
        "username": raw.get("username"),
        "success": False,
        "ts": raw.get("utc_time") or raw.get("local_time"),
    }


def _protocol(raw: dict, dst_port: Optional[int]) -> str:
    explicit = raw.get("protocol") or raw.get("proto")
    if explicit:
        return str(explicit).lower()
    try:
        logtype = int(raw.get("logtype", 0) or 0)
    except (TypeError, ValueError):
        logtype = 0
    if logtype:
        mapped = _LOGTYPE_PROTO.get(logtype // 1000)
        if mapped:
            return mapped
    return protocol_for_port(dst_port, "tcp")


def _event_type(raw: dict, protocol: str) -> tuple[str, Optional[str]]:
    msg = str(raw.get("msg", "")).lower()
    if any(token in msg for token in ("login", "password", "credential", "auth")):
        return "login_attempt", "failure"
    if protocol == "snmp":
        return "snmp_query", None
    if protocol in {"http", "https"}:
        return "http_request", None
    if protocol == "redis" and any(
        token in msg for token in ("command", "config", "get ", "set ", "keys")
    ):
        return "command", None
    return "connect", None


def normalize(
    raw: Any,
    *,
    resolver=None,
    instance_id: str = "unassigned",
    default_device: str = "",
    fallback_timestamp: Any = None,
    raw_reference: Any = None,
) -> Optional[dict]:
    """Normalize one OpenCanary JSON record; missing source is not fatal."""
    if not isinstance(raw, dict):
        return None
    try:
        dst_port = int(raw.get("dst_port", 0) or 0)
    except (TypeError, ValueError):
        dst_port = 0
    dst_port = dst_port if 0 <= dst_port <= 65535 else None
    protocol = _protocol(raw, dst_port)
    etype, outcome = _event_type(raw, protocol)
    device = default_device or raw.get("device_id") or raw.get("node_id") or ""
    raw_logdata = raw.get("logdata")
    logdata: dict = raw_logdata if isinstance(raw_logdata, dict) else {}
    username = raw.get("username") or raw.get("user") or logdata.get("USERNAME")
    password = raw.get("password") or logdata.get("PASSWORD")
    captured: dict[str, Any] = {}
    if raw.get("msg"):
        captured["message"] = raw["msg"]
    if raw.get("url"):
        captured["url"] = raw["url"]
    return build_event(
        observer_name=OBSERVER,
        observer_product=PRODUCT,
        event_type=etype,
        timestamp=raw.get("utc_time") or raw.get("local_time") or raw.get("timestamp"),
        src_ip=raw.get("src_host") or raw.get("src_ip"),
        src_port=raw.get("src_port"),
        dst_ip=raw.get("dst_host") or raw.get("dst_ip"),
        dst_port=dst_port,
        protocol=protocol,
        username=username,
        password=password,
        payload=captured,
        outcome=outcome,
        native_id=raw.get("id"),
        raw=raw,
        raw_reference=raw_reference,
        resolver=resolver,
        device_id=device,
        instance_id=instance_id,
        fallback_timestamp=fallback_timestamp,
    )
