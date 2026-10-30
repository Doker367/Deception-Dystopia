"""Common ECS/Dystopia event contract for external honeypot adapters.

This module is intentionally standard-library only. Device/segment/GeoIP
metadata is supplied by an injected provider (see ``metadata.py``): a missing
topology file, NetBox, GeoIP database or unknown device must never drop an
event. Unknown identities are retained and identified by ``observer.name``.

Captured secrets and hostile payloads are kept out of indexable fields. The
Elasticsearch template maps ``dystopia.decoy_credentials`` as a keyword and
forbids credential values there, so ``CredentialReference`` exposes captured
values only to trusted in-process callers while JSON serialisation (and every
log line) contains a non-secret identifier. Hostile payloads live in the
top-level, non-indexed ``dystopia_restricted`` object.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import re
from typing import Any, Callable, Mapping, Optional, Protocol
from uuid import NAMESPACE_URL, uuid5

SCHEMA_VERSION = 1
UNKNOWN_SEGMENT = "unknown"
UNASSIGNED_INSTANCE = "unassigned"
MAX_TEXT = 2048
MAX_CREDENTIAL = 512

# ECS event.severity is numeric (0-100). Dystopia uses a small deterministic
# scale so detections and Kibana visualisations agree across adapters.
SEVERITY_INFO = 1
SEVERITY_LOW = 2
SEVERITY_MEDIUM = 3
SEVERITY_HIGH = 4
SEVERITY_CRITICAL = 5
SEVERITY_LABELS = {
    SEVERITY_INFO: "info",
    SEVERITY_LOW: "low",
    SEVERITY_MEDIUM: "medium",
    SEVERITY_HIGH: "high",
    SEVERITY_CRITICAL: "critical",
}

# Normalized event type -> ECS fields. Additional honeypot-native actions are
# mapped by the adapters but keep the same shape.
EVENT_MAPPING: dict[str, dict[str, Any]] = {
    "connect": {
        "kind": "event", "category": ["network"], "type": ["connection"],
        "action": "network_connection", "severity": SEVERITY_INFO,
    },
    "disconnect": {
        "kind": "event", "category": ["network"], "type": ["end"],
        "action": "network_disconnect", "severity": SEVERITY_INFO,
    },
    "login_attempt": {
        "kind": "event", "category": ["authentication"], "type": ["start"],
        "action": "login", "severity": SEVERITY_MEDIUM,
    },
    "login_success": {
        "kind": "event", "category": ["authentication"], "type": ["start"],
        "action": "login", "severity": SEVERITY_HIGH, "outcome": "success",
    },
    "command": {
        "kind": "event", "category": ["process"], "type": ["start"],
        "action": "command", "severity": SEVERITY_MEDIUM,
    },
    "file_download": {
        "kind": "event", "category": ["file"], "type": ["access"],
        "action": "file_download", "severity": SEVERITY_CRITICAL,
    },
    "file_upload": {
        "kind": "event", "category": ["file"], "type": ["change"],
        "action": "file_upload", "severity": SEVERITY_HIGH,
    },
    "port_scan": {
        "kind": "event", "category": ["network"], "type": ["info"],
        "action": "port_scan", "severity": SEVERITY_MEDIUM,
    },
    "snmp_query": {
        "kind": "event", "category": ["network"], "type": ["info"],
        "action": "snmp_query", "severity": SEVERITY_INFO,
    },
    "http_request": {
        "kind": "event", "category": ["web"], "type": ["access"],
        "action": "http_request", "severity": SEVERITY_INFO,
    },
    "rtsp_request": {
        "kind": "event", "category": ["network"], "type": ["info"],
        "action": "rtsp_request", "severity": SEVERITY_INFO,
    },
    "other": {
        "kind": "event", "category": ["host"], "type": ["info"],
        "action": "other", "severity": SEVERITY_INFO,
    },
}

UDP_PROTOCOLS = {"dns", "snmp", "ntp", "dhcp", "tftp", "radius", "syslog", "udp"}
TCP_PROTOCOLS = {
    "ftp", "ssh", "telnet", "smtp", "http", "https", "pop3", "imap", "smb",
    "mssql", "mysql", "rdp", "vnc", "rtsp", "redis", "tcp", "postgresql",
    "sip", "ldap", "kerberos",
}

PROTOCOL_ALIASES = {
    "smbd": "smb", "httpd": "http", "ftpd": "ftp", "mysqld": "mysql",
    "mssqld": "mssql", "sshd": "ssh", "telnetd": "telnet", "redis-server": "redis",
}

PROTOCOLS_BY_PORT = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 161: "snmp", 443: "https", 445: "smb",
    1433: "mssql", 2222: "ssh", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http", 8443: "https",
}

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ISO_SPACE = re.compile(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)$")
_GO_TIME = re.compile(r"^(\d{4})/(\d{2})/(\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)$")


class MetadataProvider(Protocol):
    """Injected read-only metadata sources; implementations must not raise."""

    def device(self, device_id: str) -> Optional[Mapping[str, Any]]:
        ...

    def segment(self, segment_id: str) -> Optional[Mapping[str, Any]]:
        ...

    def geo(self, ip: str) -> Optional[Mapping[str, Any]]:
        ...


@dataclass
class StaticMetadata:
    """Small in-memory provider for tests and offline normalisation.

    The shapes mirror ``topology_svc``/``geoip_svc`` so the same provider can
    be swapped for the lazy topology implementation without changing adapters.
    """

    devices: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    segments: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    geo_map: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    geo_lookup: Optional[Callable[[str], Optional[Mapping[str, Any]]]] = None

    def device(self, device_id: str) -> Optional[Mapping[str, Any]]:
        return self.devices.get(device_id)

    def segment(self, segment_id: str) -> Optional[Mapping[str, Any]]:
        return self.segments.get(segment_id)

    def geo(self, ip: str) -> Optional[Mapping[str, Any]]:
        if self.geo_lookup is not None:
            return self.geo_lookup(ip)
        return self.geo_map.get(ip)


def _safe(call: Optional[Callable[..., Any]], *args: Any) -> Any:
    if call is None:
        return None
    try:
        return call(*args)
    except Exception:  # noqa: BLE001 - metadata must never drop an event
        return None


def canonical_ip(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > 64 or "%" in text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def valid_port(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 1 <= number <= 65535 else None


def bounded_text(value: Any, limit: int = MAX_TEXT) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        text = value.decode("utf-8", "replace")
    elif isinstance(value, str):
        text = value
    else:
        text = str(value)
    text = _CONTROL_CHARS.sub("?", text)
    return text[:limit]


def normalize_timestamp(value: Any, fallback: Any = None) -> datetime:
    """Parse common honeypot timestamps; default to observation time."""
    for candidate in (value, fallback):
        parsed = _parse_timestamp(candidate)
        if parsed is not None:
            return parsed
    return datetime.now(timezone.utc)


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        parsed = value
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        try:
            return parsed.astimezone(timezone.utc)
        except (OverflowError, ValueError):
            return None
    if isinstance(value, (int, float)):
        try:
            seconds = float(value)
            if seconds > 1e12:
                seconds /= 1000.0
            if not math.isfinite(seconds) or seconds < 0 or seconds > 253402300799:
                return None
            return datetime.fromtimestamp(seconds, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > 64:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        parsed = None
    if parsed is None:
        match = _ISO_SPACE.match(text)
        if match:
            candidate = match.group(1) + "T" + match.group(2)
        else:
            match = _GO_TIME.match(text)
            candidate = (
                "-".join(match.groups()[:3]) + "T" + match.group(4) if match else None
            )
        if candidate:
            try:
                parsed = datetime.fromisoformat(candidate)
            except ValueError:
                parsed = None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    try:
        return parsed.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        return None


def iso_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def fingerprint(raw: Any) -> str:
    """Stable digest of a raw log record; digest, never the content, is stored."""
    try:
        canonical = json.dumps(
            raw, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
            default=str, allow_nan=False,
        )
    except (TypeError, ValueError):
        canonical = repr(raw)
    return hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()


def stable_event_id(
    *,
    observer: str,
    instance_id: str,
    device_id: str,
    native_id: Optional[str],
    session_id: Optional[str],
    src_ip: Optional[str],
    src_port: Optional[int],
    dst_ip: Optional[str],
    dst_port: Optional[int],
    action: str,
    raw_fingerprint: str,
    sequence: Any = None,
) -> str:
    """Deterministic UUID5 used as Elasticsearch document id (``event.id``).

    Re-reading the same log line yields the same id; no random or wall-clock
    value is involved, so ``create`` is idempotent across retries/restarts.
    """
    identity = {
        "observer": observer,
        "instance": instance_id,
        "device": device_id,
        "native": native_id or "",
        "session": session_id or "",
        "src": src_ip or "",
        "src_port": src_port,
        "dst": dst_ip or "",
        "dst_port": dst_port,
        "action": action,
        "raw": raw_fingerprint,
        "sequence": "" if sequence is None else str(sequence),
    }
    canonical = json.dumps(
        identity, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    )
    return str(uuid5(NAMESPACE_URL, "dystopia/" + canonical))


def normalize_protocol(value: Any) -> str:
    text = bounded_text(value, 64) or ""
    text = text.strip().lower()
    return PROTOCOL_ALIASES.get(text, text) or "unknown"


def transport_for(protocol: str, explicit: Any = None) -> str:
    candidate = bounded_text(explicit, 16)
    if candidate:
        candidate = candidate.lower()
        if candidate in {"tcp", "udp"}:
            return candidate
    if protocol in UDP_PROTOCOLS:
        return "udp"
    if protocol in TCP_PROTOCOLS:
        return "tcp"
    return "tcp"


def protocol_for_port(port: Optional[int], default: str = "unknown") -> str:
    if port is None:
        return default
    return PROTOCOLS_BY_PORT.get(port, default)


def _persona(value: Any) -> Optional[str]:
    """Persona provenance as a keyword (the ES template maps it as keyword)."""
    if isinstance(value, str):
        return bounded_text(value, 128) or None
    if not isinstance(value, Mapping):
        return None
    parts = []
    for key in ("vendor", "os", "hostname", "mac"):
        item = bounded_text(value.get(key), 128)
        if item:
            parts.append(f"{key}={item}")
    return ";".join(parts)[:128] or None


class CredentialReference(str):
    """Keyword-safe credential identifier with in-process captured values.

    The Elasticsearch template maps ``dystopia.decoy_credentials`` as a keyword
    and explicitly forbids credential values there. This string subclass keeps
    the captured user/password available to trusted in-process handlers via
    ``get``/item access, while JSON serialisation (and therefore the published
    document and every log line) contains only a non-secret identifier.
    """

    _values: dict[str, str]

    def __new__(cls, identifier: str, values: Optional[Mapping[str, str]] = None):
        instance = super().__new__(cls, identifier)
        instance._values = dict(values or {})
        return instance

    def get(self, key: str, default: Any = None) -> Any:
        return self._values.get(key, default)

    def __getitem__(self, key):
        if isinstance(key, str):
            return self._values[key]
        return super().__getitem__(key)

    def __contains__(self, key) -> bool:
        if isinstance(key, str) and key in self._values:
            return True
        return super().__contains__(key)

    def items(self):
        return self._values.items()


def _payload(value: Any) -> Optional[dict[str, str]]:
    """Restricted container for hostile payloads; never copied from metadata."""
    if not isinstance(value, Mapping):
        return None
    payload: dict[str, str] = {}
    for key in ("command", "url", "message", "file", "data", "hash", "md5", "sha256"):
        text = bounded_text(value.get(key))
        if text:
            payload[key] = text
    return payload or None


def _credentials(username: Any, password: Any) -> Optional[dict[str, str]]:
    credentials: dict[str, str] = {}
    user = bounded_text(username, MAX_CREDENTIAL)
    secret = bounded_text(password, MAX_CREDENTIAL)
    if user:
        credentials["username"] = user
    if secret:
        credentials["password"] = secret
    return credentials or None


def _credential_reference(
    username: Any, credentials: Optional[Mapping[str, str]]
) -> CredentialReference:
    if not credentials:
        return CredentialReference("none")
    identifier = bounded_text(username, 256) or "password-present"
    return CredentialReference(identifier, credentials)


def _geo(provider: Optional[MetadataProvider], ip: Optional[str]) -> Optional[dict[str, Any]]:
    if provider is None or not ip:
        return None
    data = _safe(getattr(provider, "geo", None), ip)
    if not isinstance(data, Mapping):
        return None
    geo: dict[str, Any] = {}
    country = bounded_text(data.get("country_code"), 8)
    if country:
        geo["country_iso_code"] = country.upper()
    name = bounded_text(data.get("country"), 128)
    if name:
        geo["country_name"] = name
    city = bounded_text(data.get("city"), 128)
    if city:
        geo["city_name"] = city
    region = bounded_text(data.get("subdivision"), 128)
    if region:
        geo["region_name"] = region
    lat, lon = data.get("lat"), data.get("lon")
    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
        if math.isfinite(lat) and math.isfinite(lon) and -90 <= lat <= 90 and -180 <= lon <= 180:
            geo["location"] = {"lat": float(lat), "lon": float(lon)}
    return geo or None


def _raw_reference(
    *,
    observer: str,
    native_id: Optional[str],
    raw_fingerprint: str,
    extra: Any,
) -> str:
    """Keyword-safe provenance string; never contains the raw record."""
    parts = [f"sensor={observer}", f"sha256={raw_fingerprint}"]
    if native_id:
        parts.append(f"native_id={bounded_text(native_id, 256)}")
    if isinstance(extra, Mapping):
        for key in ("source", "path", "offset", "line", "sequence"):
            if extra.get(key) not in (None, ""):
                parts.append(f"{key}={bounded_text(extra[key], 256)}")
    return ";".join(parts)[:512]


def build_event(
    *,
    observer_name: str,
    observer_product: str,
    event_type: str,
    timestamp: Any = None,
    src_ip: Any = None,
    src_port: Any = None,
    dst_ip: Any = None,
    dst_port: Any = None,
    protocol: Any = None,
    transport: Any = None,
    session_id: Any = None,
    username: Any = None,
    password: Any = None,
    payload: Any = None,
    outcome: Optional[str] = None,
    severity: Optional[int] = None,
    native_id: Any = None,
    raw: Any = None,
    raw_fingerprint: Optional[str] = None,
    raw_reference: Any = None,
    resolver: Optional[MetadataProvider] = None,
    device_id: Any = None,
    segment_id: Any = None,
    instance_id: Any = None,
    persona: Any = None,
    sequence: Any = None,
    fallback_timestamp: Any = None,
) -> dict[str, Any]:
    """Build one ECS/Dystopia document. Missing metadata never removes input."""
    observer = bounded_text(observer_name, 64) or "unknown"
    product = bounded_text(observer_product, 128) or observer
    normalized_type = event_type if event_type in EVENT_MAPPING else "other"
    mapping = EVENT_MAPPING[normalized_type]

    chosen_device = bounded_text(device_id, 128)
    resolved = _safe(getattr(resolver, "device", None), chosen_device) if chosen_device else None
    if not isinstance(resolved, Mapping):
        resolved = {}
    chosen_device = (
        bounded_text(device_id, 128)
        or bounded_text(resolved.get("id"), 128)
        or "unknown-" + observer
    )

    chosen_segment = bounded_text(segment_id, 128) or bounded_text(
        resolved.get("segment") or resolved.get("segment_id"), 128
    )
    if chosen_segment and resolver is not None:
        segment = _safe(getattr(resolver, "segment", None), chosen_segment)
        if isinstance(segment, Mapping) and segment.get("id"):
            chosen_segment = bounded_text(segment.get("id"), 128) or chosen_segment
    chosen_segment = chosen_segment or UNKNOWN_SEGMENT

    source_ip = canonical_ip(src_ip)
    dest_ip = canonical_ip(dst_ip) or canonical_ip(resolved.get("ip"))
    source_port = valid_port(src_port)
    dest_port = valid_port(dst_port)
    net_protocol = normalize_protocol(protocol)
    if net_protocol == "unknown" and dest_port is not None:
        net_protocol = protocol_for_port(dest_port)
    net_transport = transport_for(net_protocol, transport)

    observed = normalize_timestamp(timestamp, fallback_timestamp)
    chosen_instance = bounded_text(instance_id, 128)
    if not chosen_instance or chosen_instance == UNASSIGNED_INSTANCE:
        chosen_instance = (
            bounded_text(resolved.get("instance_id"), 128)
            or chosen_instance
            or UNASSIGNED_INSTANCE
        )
    inferred_persona = _persona(persona) or _persona(resolved.get("persona"))
    session = bounded_text(session_id, 256)
    native = bounded_text(native_id, 256)
    raw_hash = raw_fingerprint or fingerprint(raw)
    action = bounded_text(mapping["action"], 128) or normalized_type
    id_suffix = stable_event_id(
        observer=observer,
        instance_id=chosen_instance,
        device_id=chosen_device,
        native_id=native,
        session_id=session,
        src_ip=source_ip,
        src_port=source_port,
        dst_ip=dest_ip,
        dst_port=dest_port,
        action=action,
        raw_fingerprint=raw_hash,
        sequence=sequence,
    )

    chosen_severity = severity if severity in SEVERITY_LABELS else mapping["severity"]
    event: dict[str, Any] = {
        "@timestamp": iso_timestamp(observed),
        "event": {
            "id": id_suffix,
            "kind": mapping["kind"],
            "category": list(mapping["category"]),
            "type": list(mapping["type"]),
            "action": action,
            "severity": chosen_severity,
            "module": observer,
            "dataset": "dystopia.honeypot",
        },
        "observer": {
            "type": "honeypot",
            "name": observer,
            "product": product,
            "vendor": "Dystopia",
        },
        "network": {"transport": net_transport, "protocol": net_protocol},
        "dystopia": {
            "schema_version": SCHEMA_VERSION,
            "device_id": chosen_device,
            "segment_id": chosen_segment,
            "instance_id": chosen_instance,
            "ingest_source": observer,
            "raw_reference": _raw_reference(
                observer=observer, native_id=native,
                raw_fingerprint=raw_hash, extra=raw_reference,
            ),
        },
    }

    if source_ip:
        source: dict[str, Any] = {"ip": source_ip}
        if source_port is not None:
            source["port"] = source_port
        geo = _geo(resolver, source_ip)
        if geo:
            source["geo"] = geo
        event["source"] = source
    elif source_port is not None:
        event["source"] = {"port": source_port}

    if dest_ip or dest_port is not None:
        destination: dict[str, Any] = {}
        if dest_ip:
            destination["ip"] = dest_ip
        if dest_port is not None:
            destination["port"] = dest_port
        event["destination"] = destination

    if session:
        event["session"] = {"id": session}
    user = bounded_text(username, MAX_CREDENTIAL)
    if user:
        event["user"] = {"name": user}

    event_outcome = outcome or mapping.get("outcome")
    if event_outcome:
        event["event"]["outcome"] = event_outcome

    credentials = _credentials(username, password)
    event["dystopia"]["decoy_credentials"] = _credential_reference(username, credentials)
    restricted_payload = _payload(payload)
    if restricted_payload:
        # Top-level, non-indexed (template dynamic=false): hostile payload only.
        event["dystopia_restricted"] = {"payload": restricted_payload}
    if inferred_persona:
        event["dystopia"]["persona"] = inferred_persona

    related = [value for value in (source_ip, dest_ip) if value]
    if related:
        event["related"] = {"ip": related}
    return event
