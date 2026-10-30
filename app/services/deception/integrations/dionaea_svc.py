"""Adapter for Dionaea (malware capture honeypot).

Dionaea emits JSON records (``dionaea.log``/``-l``) with source/destination
sockets, protocol/module, optional URLs and file hashes. Field names vary
between builds, so aliases are accepted conservatively. Unknown records are
kept as ``other``; no event is discarded because topology or GeoIP is absent.
"""

from typing import Any, Optional

from .ecs import build_event, protocol_for_port

OBSERVER = "dionaea"
PRODUCT = "Dionaea"

_PROTOCOLS = {
    "smbd": "smb", "smb": "smb", "httpd": "http", "http": "http",
    "ftpd": "ftp", "ftp": "ftp", "mysqld": "mysql", "mysql": "mysql",
    "mssqld": "mssql", "mssql": "mssql", "capture": "tcp",
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


def _connection(raw: dict) -> dict:
    return _first_mapping(raw.get("connection"))


def _protocol(raw: dict, dst_port: Optional[int]) -> str:
    explicit = _text(raw, "protocol", "proto", "module") or _text(_connection(raw), "protocol")
    if explicit:
        return _PROTOCOLS.get(explicit.lower(), explicit.lower())
    return protocol_for_port(dst_port, "tcp")


def _event_type(raw: dict, protocol: str) -> tuple[str, Optional[str]]:
    credential = _first_mapping(raw.get("credentials"))
    if (_text(raw, "username", "password", "user", "pwd")
            or _text(credential, "username", "password", "user", "pwd")):
        return "login_attempt", "failure"
    download = _first_mapping(raw.get("downloads"))
    if (_text(raw, "url", "md5_hash", "sha256_hash", "filename")
            or _text(download, "url", "filename")):
        return "file_download", "success"
    connection = (
        _text(_connection(raw), "type")
        or _text(raw, "event", "connection")
        or ""
    ).lower()
    if connection in {"close", "closed", "disconnect"}:
        return "disconnect", None
    if connection in {"accept", "connect", "connected"}:
        return "connect", None
    if protocol in {"http", "https"}:
        return "http_request", None
    return "other", None


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
        dst_port = int(raw.get("dst_port") or 0)
    except (TypeError, ValueError):
        dst_port = None
    dst_port = dst_port if dst_port is not None and 0 <= dst_port <= 65535 else None
    protocol = _protocol(raw, dst_port)
    etype, outcome = _event_type(raw, protocol)
    credential = _first_mapping(raw.get("credentials"))
    download = _first_mapping(raw.get("downloads"))
    username = _text(raw, "username", "user") or _text(credential, "username", "user")
    password = _text(raw, "password", "pwd") or _text(credential, "password", "pwd")
    captured: dict[str, Any] = {}
    for key, mapped in (
        ("url", "url"), ("filename", "file"), ("md5_hash", "md5"),
        ("sha256_hash", "sha256"), ("data", "data"),
    ):
        value = _text(raw, key) or _text(download, key)
        if value:
            captured[mapped] = value
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
        session_id=_text(raw, "session", "connection_id", "id"),
        username=username,
        password=password,
        payload=captured,
        outcome=outcome,
        native_id=_text(raw, "id", "uuid", "connection_id"),
        raw=raw,
        raw_reference=raw_reference,
        resolver=resolver,
        device_id=default_device or _text(raw, "device_id", "sensor", "node_id") or "",
        instance_id=instance_id,
        fallback_timestamp=fallback_timestamp,
    )
