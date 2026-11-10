"""Normalize raw honeypot log records into strict v1 transport events.

This is the missing "colector" half of the sensor: it turns one native record
from any of the six declared engines (Cowrie, OpenCanary, Dionaea, Heralding,
RedisHoneyPot, Endlessh) into a ``runtime.contracts`` v1 event that
``runtime.sensor.Spool.submit`` accepts. It depends only on the standard library
and ``runtime.contracts``: no ``app.*``, no administrative settings, no yaml.

Design invariants (mirroring ``deploy/honeypots/adapters.md``):

* **Deterministic identity.** ``event_id`` is derived from the raw record
  fingerprint (SHA-256 of the canonical JSON) folded into a UUID, so re-reading
  the same log line yields the same id. The spool deduplicates on
  ``(sensor, event_id)``; a replay is therefore idempotent, never a conflict.
  No random or wall-clock value is used when the native timestamp is present.
* **Redaction.** Captured passwords/tokens are *never* copied into ``detail``.
  Hostile payload (commands, URLs, hashes) is bounded and kept as plain strings
  only; no nested objects, no execution semantics.
* **No discard-by-metadata.** A record with a missing device/timestamp/protocol
  is degraded to a safe default, not dropped; the operator still sees the event.
* **Bounded.** ``detail`` is limited to 16 keys of strings <= 2048 bytes, and
  the whole event stays under the ``MAX_EVENT_BYTES`` contract limit.
"""

from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_address
import hashlib
import json
import re
from uuid import UUID, NAMESPACE_URL, uuid5

from runtime.contracts import identifier, validate_event

# proto allowed by the v1 contract.
_PROTOCOL_SET = {"tcp", "udp", "ssh", "telnet", "http", "ftp", "mysql", "snmp"}

# Native protocol/service names -> the nearest contract enum. Everything not in
# the enum (smb, smtp, imap, pop3, redis, rdp, vnc, postgresql, mssql, ...) is
# normalized to ``tcp``, exactly as adapters.md requires.
_PROTOCOL_ALIASES = {
    "ssh": "ssh", "telnet": "telnet", "http": "http", "https": "http",
    "ftp": "ftp", "ftpd": "ftp", "mysql": "mysql", "mysqld": "mysql",
    "snmp": "snmp", "udp": "udp", "tcp": "tcp",
    "smb": "tcp", "smbd": "tcp", "smtp": "tcp", "imap": "tcp", "pop3": "tcp",
    "redis": "tcp", "rdp": "tcp", "vnc": "tcp", "postgresql": "tcp",
    "mssql": "tcp", "mssqld": "tcp", "sip": "tcp", "samba": "tcp",
    "capture": "tcp", "httpd": "http", "mqtt": "tcp", "epmap": "tcp",
    "pptp": "tcp", "mongodb": "tcp",
}

_PORT_PROTOCOL = {
    21: "ftp", 22: "ssh", 23: "telnet", 80: "http", 443: "http",
    3306: "mysql", 161: "snmp", 53: "udp", 69: "udp",
}

# Cowrie eventid -> v1 type (telnet listener still normalizes to ``telnet``).
_COWRIE_TYPES = {
    "cowrie.session.connect": "connect",
    "cowrie.session.closed": "disconnect",
    "cowrie.login.failed": "login_attempt",
    "cowrie.login.success": "login_success",
    "cowrie.command.input": "command",
    "cowrie.session.file_download": "file_download",
    "cowrie.session.file_upload": "file_download",
}

_ENGINES = ("cowrie", "opencanary", "dionaea", "heralding", "redishoneypot", "endlessh")


class NormalizeError(ValueError):
    """A raw record cannot be turned into a v1 event without guessing."""


def _text(raw: dict, *keys: str):
    for key in keys:
        value = raw.get(key)
        if isinstance(value, str) and value:
            return value
        if value is not None and not isinstance(value, (dict, list)):
            return str(value)
    return None


def _int(value):
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 1 <= number <= 65535 else None


def _first_mapping(value):
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    if isinstance(value, dict):
        return value
    return {}


def canonical_ip(value):
    """Canonical literal IP, or ``None`` when the record has no usable source."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or "%" in text:
        return None
    try:
        parsed = ip_address(text)
    except ValueError:
        return None
    if parsed.is_multicast or parsed.is_unspecified:
        return None
    return str(parsed)


def normalize_timestamp(value):
    """Best-effort UTC timestamp; always returns a tz-aware ISO-8601 string.

    A missing/invalid timestamp falls back to *now*, which is deliberately the
    only non-deterministic path. Records read from the fixtures always carry a
    native timestamp, so replay stays idempotent there.
    """
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = float(value)
        if seconds > 1e12:
            seconds /= 1000.0
        try:
            return datetime.fromtimestamp(seconds, timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return datetime.now(timezone.utc).isoformat()
    if not isinstance(value, str) or not value.strip():
        return datetime.now(timezone.utc).isoformat()
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        parsed = None
    if parsed is None:
        # ``YYYY-MM-DD HH:MM:SS(.ffffff)`` (OpenCanary/RedisHoneyPot native).
        bare = text.split(".")[0]
        if len(bare) >= 19 and bare[4] == "-" and bare[7] == "-" and bare[10] == " ":
            try:
                parsed = datetime.fromisoformat(bare.replace(" ", "T"))
            except ValueError:
                parsed = None
    if parsed is None:
        return datetime.now(timezone.utc).isoformat()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    try:
        return parsed.astimezone(timezone.utc).isoformat()
    except (OverflowError, ValueError):
        return datetime.now(timezone.utc).isoformat()


def resolve_protocol(raw: dict, engine: str) -> str:
    explicit = _text(raw, "protocol", "proto", "service", "module")
    if explicit:
        alias = _PROTOCOL_ALIASES.get(explicit.strip().lower())
        if alias:
            return alias
    connection = _first_mapping(raw.get("connection"))
    nested = _text(connection, "protocol")
    if nested and _PROTOCOL_ALIASES.get(nested.strip().lower()):
        return _PROTOCOL_ALIASES[nested.strip().lower()]
    dst_port = _int(raw.get("dst_port") or raw.get("destination_port"))
    if dst_port and dst_port in _PORT_PROTOCOL:
        return _PORT_PROTOCOL[dst_port]
    # Per-engine default; Cowrie/Endlessh are SSH listeners.
    if engine in ("cowrie", "endlessh"):
        return "ssh"
    return "tcp"


def _cowrie_type(raw: dict) -> str:
    eventid = raw.get("eventid")
    if eventid in _COWRIE_TYPES:
        return _COWRIE_TYPES[eventid]
    message = raw.get("message")
    if isinstance(message, str) and message in _COWRIE_TYPES:
        return _COWRIE_TYPES[message]
    return "other"


def _opencanary_type(raw: dict) -> str:
    msg = str(raw.get("msg") or "").lower()
    logdata = raw.get("logdata")
    username = raw.get("username") or (logdata.get("USERNAME") if isinstance(logdata, dict) else None)
    if any(token in msg for token in ("login", "password", "credential", "auth")) or username:
        return "login_attempt"
    if isinstance(logdata, dict) and (logdata.get("PATH") or logdata.get("path")):
        return "http_request"
    if resolve_protocol(raw, "opencanary") == "snmp":
        return "other"
    return "connect"


def _dionaea_type(raw: dict) -> str:
    credential = _first_mapping(raw.get("credentials"))
    if _text(raw, "username", "password") or _text(credential, "username", "password"):
        return "login_attempt"
    download = _first_mapping(raw.get("downloads"))
    if _text(raw, "url", "md5_hash", "sha256_hash", "filename") or _text(download, "url", "filename"):
        return "file_download"
    connection = (_text(_first_mapping(raw.get("connection")), "type") or _text(raw, "event") or "").lower()
    if connection in {"close", "closed", "disconnect"}:
        return "disconnect"
    if connection in {"accept", "connect", "connected"}:
        return "connect"
    return "other"


def _heralding_type(raw: dict) -> str:
    attempt = _first_mapping(raw.get("auth_attempts"))
    if _text(raw, "username", "password") or _text(attempt, "username", "password"):
        return "login_attempt"
    return "connect"


def _redis_type(raw: dict) -> str:
    if _text(raw, "username", "password"):
        return "login_attempt"
    command = raw.get("command") or raw.get("payload")
    if command not in (None, ""):
        return "command"
    action = (_text(raw, "event", "action") or "").lower()
    if any(token in action for token in ("disconnect", "closed", "close")):
        return "disconnect"
    return "connect"


def _endlessh_type(raw: dict) -> str:
    event = _text(raw, "event", "event_type")
    if event in {"connect", "disconnect", "other"}:
        return event
    line = str(raw.get("message") or "").lower()
    if any(token in line for token in ("disconnect", "closed", "close", "timeout", "drop")):
        return "disconnect"
    if any(token in line for token in ("connect", "accepted", "accept")):
        return "connect"
    return "other"


# HTTP request line sent to a non-HTTP listener (nmap, curl, bots). Cowrie may
# log this as ``login.success`` after accepting an empty Telnet credential; it
# is a protocol probe, not a credential compromise.
_HTTP_PROBE = re.compile(r"^(?:GET|POST|HEAD|PUT|OPTIONS|DELETE|TRACE|CONNECT|PATCH)\s+\S+", re.IGNORECASE)

_MITRE = {
    "login_attempt": "T1110",
    "login_success": "T1110",
    "command": "T1059",
    "file_download": "T1105",
    "port_scan": "T1046",
    "http_request": "T1190",
}

_SOCKET = re.compile(
    r"(?:host=)?(?P<ip>(?:\d{1,3}(?:\.\d{1,3}){3})|(?:\[[0-9a-fA-F:]+\])|"
    r"(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*)"
    r"(?::(?P<port>\d{1,5})|\s+port=(?P<port2>\d{1,5}))"
)
_ISO_STAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))"
)
_GO_STAMP = re.compile(r"^(\d{4})/(\d{2})/(\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)")


def parse_endlessh_line(line: str) -> dict:
    """Parse one Endlessh text line into a record mapping.

    Endlessh native lines look like ``ACCEPT host=… port=… fd=… n=…`` or
    ``CLOSE host=… port=… fd=… time=… bytes=…`` (per adapters.md). The fixture
    format uses ``ip:port`` plus an explicit ``event`` token. ``TOTALS`` lines
    are aggregate metrics, not attacker events.
    """
    parsed: dict = {}
    text = line.strip()
    iso = _ISO_STAMP.match(text)
    if iso:
        parsed["timestamp"] = iso.group(1)
    else:
        stamp = _GO_STAMP.match(text)
        if stamp:
            try:
                parsed["timestamp"] = datetime.fromisoformat(
                    "-".join(stamp.groups()[:3]) + "T" + stamp.group(4)
                ).isoformat()
            except ValueError:
                pass
    socket = _SOCKET.search(text)
    if socket:
        parsed["src_ip"] = socket.group("ip").strip("[]")
        port = socket.group("port") or socket.group("port2")
        parsed["src_port"] = _int(port)
    low = text.lower()
    if "totals" in low:
        parsed["event"] = "other"
    elif any(token in low for token in ("disconnect", "closed", "close", "timeout", "drop")):
        parsed["event"] = "disconnect"
    elif any(token in low for token in ("connect", "accepted", "accept")):
        parsed["event"] = "connect"
    else:
        parsed["event"] = "other"
    parsed["message"] = text
    return parsed


def _resolve_type(raw: dict, engine: str) -> str:
    if engine == "cowrie":
        return _cowrie_type(raw)
    if engine == "opencanary":
        return _opencanary_type(raw)
    if engine == "dionaea":
        return _dionaea_type(raw)
    if engine == "heralding":
        return _heralding_type(raw)
    if engine == "redishoneypot":
        return _redis_type(raw)
    if engine == "endlessh":
        return _endlessh_type(raw)
    raise NormalizeError(f"unknown engine {engine!r}")


def _src_ip(raw: dict) -> str:
    value = _text(raw, "src_ip", "src_host", "source_ip", "remote_host", "src")
    ip = canonical_ip(value)
    if ip:
        return ip
    # RedisHoneyPot escribe ``addr: "ip:puerto"`` en vez de un campo src_ip.
    addr = _text(raw, "addr")
    if addr:
        host = addr.rsplit(":", 1)[0] if ":" in addr else addr
        ip = canonical_ip(host)
        if ip:
            return ip
    # OpenCanary ``src_host`` is a hostname in the fixture; fall back to its
    # nested logdata when present, otherwise fail closed.
    logdata = raw.get("logdata")
    if isinstance(logdata, dict):
        nested = canonical_ip(logdata.get("HOST"))
        if nested:
            return nested
    raise NormalizeError("no canonical source IP")


def _src_port(raw: dict):
    port = _int(raw.get("src_port") or raw.get("source_port") or raw.get("remote_port"))
    if port is not None:
        return port
    addr = _text(raw, "addr")
    if addr and ":" in addr:
        return _int(addr.rsplit(":", 1)[1])
    return None


def _dst_ip(raw: dict):
    """Destination address as reported by the sensor, canonical or None."""
    value = _text(raw, "dst_ip", "dst_host", "destination_ip", "destination_host")
    connection = _first_mapping(raw.get("connection"))
    value = value or _text(connection, "dst_ip", "dst_host", "destination_ip")
    return canonical_ip(value)


def _dst_port(raw: dict):
    value = raw.get("dst_port") or raw.get("destination_port")
    connection = _first_mapping(raw.get("connection"))
    value = value or connection.get("dst_port") or connection.get("destination_port")
    return _int(value)


def _protocol_probe(raw: dict, etype: str) -> bool:
    """True when credential-like events actually carry an HTTP request line."""
    if etype not in ("login_attempt", "login_success"):
        return False
    candidates = [
        _text(raw, "username", "user"),
        raw.get("input"),
        raw.get("command"),
        raw.get("payload"),
    ]
    return any(isinstance(value, str) and _HTTP_PROBE.match(value.strip()) for value in candidates)


def _detail(raw: dict, engine: str, etype: str) -> dict:
    """Bounded, redacted detail. Passwords and tokens never leave the sensor."""
    detail: dict = {}
    session = _text(raw, "session", "session_id")
    if session:
        detail["session"] = session
    username = _text(raw, "username", "user") or _text(_first_mapping(raw.get("credentials")), "username")
    if username:
        detail["username"] = username
    if etype == "command":
        command = raw.get("command") or raw.get("input") or raw.get("payload")
        args = raw.get("args")
        if isinstance(args, (list, tuple)):
            command = (command + " " + " ".join(str(a) for a in args)) if command else " ".join(str(a) for a in args)
        if command not in (None, ""):
            detail["command"] = str(command)
    if etype == "file_download":
        url = _text(raw, "url") or _text(_first_mapping(raw.get("downloads")), "url")
        filename = _text(raw, "filename", "outfile") or _text(_first_mapping(raw.get("downloads")), "filename")
        if url:
            detail["url"] = url
        if filename:
            detail["file"] = filename
        for key in ("md5_hash", "sha256_hash", "shasum"):
            value = _text(raw, key)
            if value:
                detail[key] = value
    eventid = _text(raw, "eventid", "event", "logtype")
    if eventid:
        detail["eventid"] = eventid
    message = _redact_message(_text(raw, "message", "msg"), raw)
    if message:
        detail["message"] = message
    mitre = _MITRE.get(etype)
    if mitre:
        detail.setdefault("mitre", mitre)
    # OpenCanary keeps the useful HTTP/credential fields inside ``logdata``.
    logdata = raw.get("logdata")
    if isinstance(logdata, dict):
        for key, target in (("path", "path"), ("PATH", "path"),
                            ("useragent", "useragent"), ("USERAGENT", "useragent"),
                            ("method", "method"), ("METHOD", "method"),
                            ("host", "host"), ("HOSTNAME", "host"),
                            ("USERNAME", "username"), ("SESSION", "session")):
            value = logdata.get(key)
            if value not in (None, "") and target not in detail:
                detail[target] = str(value)
    bounded = {}
    for key, value in detail.items():
        if value is None:
            continue
        text = str(value)[:2048]
        if text:
            bounded[key] = text
        if len(bounded) >= 16:
            break
    return bounded


def _redact_message(message, raw: dict):
    """Strip credential material from a native log message before it is indexed.

    The message field is hostile input: it can embed the captured password
    (e.g. Cowrie ``login attempt [root/demo-password] failed``). Any known
    password value and any ``password[=: ]value`` assignment is replaced with
    a placeholder so the event stays useful without leaking the secret.
    """
    if not message:
        return None
    text = str(message)
    for key in ("password", "pass", "pwd"):
        value = raw.get(key)
        if isinstance(value, str) and value:
            text = text.replace(value, "[REDACTED]")
    text = _CREDENTIAL_ASSIGNMENT.sub(
        lambda m: f"{m.group(1)}[REDACTED]", text
    )
    return text


# ``password[/passwd/pwd/token/secret][=: ]value`` without trailing word chars.
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)(password|passwd|pwd|token|secret)\s*[=:]\s*"
    r"[\"']?[^\s\"',;]+"
)


def fingerprint(raw) -> str:
    if isinstance(raw, str):
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()
    try:
        canonical = json.dumps(raw, sort_keys=True, ensure_ascii=True, separators=(",", ":"), default=str, allow_nan=False)
    except (TypeError, ValueError):
        canonical = repr(raw)
    return hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()


def stable_event_id(engine: str, device_id: str, raw) -> str:
    """Deterministic UUID4 derived from the raw fingerprint.

    Re-reading the same line yields the same id (idempotent spool replay). The
    UUID is version 4 and canonical so ``validate_event`` accepts it.
    """
    material = f"dystopia/{engine}/{device_id}/{fingerprint(raw)}"
    derived = uuid5(NAMESPACE_URL, material)
    # Keep version 4 (uuid5 sets version 5); preserve the variant bits.
    return str(UUID(bytes=derived.bytes, version=4))


def normalize_raw(engine: str, device_id: str, raw, observed_at=None) -> dict | None:
    """Normalize one raw record into a validated v1 event.

    ``raw`` is a JSON object (jsonl engines) or a text line (endlessh). ``None``
    is returned only for empty/whitespace lines; anything malformed raises
    ``NormalizeError`` so the collector can count and continue without guessing.
    """
    engine = str(engine).strip().lower()
    if engine not in _ENGINES:
        raise NormalizeError(f"unknown engine {engine!r}")
    identifier(device_id)

    if isinstance(raw, str):
        line = raw
        if not line.strip():
            return None
        record = parse_endlessh_line(line) if engine == "endlessh" else json.loads(line)
    elif isinstance(raw, dict):
        record = raw
    else:
        raise NormalizeError("raw record must be a JSON object or text line")

    if not isinstance(record, dict):
        raise NormalizeError("raw record must map to an object")

    # Endlessh ``TOTALS`` is an aggregate metric, not an attacker event; the
    # parsed record carries no source socket, so skip it instead of guessing.
    if engine == "endlessh" and _text(record, "event") == "other" and canonical_ip(record.get("src_ip")) is None:
        return None

    src_ip = _src_ip(record)
    original_type = _resolve_type(record, engine)
    probe = _protocol_probe(record, original_type)
    # A bare HTTP request line accepted by a Telnet listener is a protocol
    # probe, not a successful credential login. Keep the captured bytes but
    # correct the classification before it reaches the panel.
    etype = "connect" if probe else original_type
    proto = resolve_protocol(record, engine)
    observed = observed_at or normalize_timestamp(
        record.get("timestamp") or record.get("utc_time") or record.get("local_time") or record.get("time")
    )

    event = {
        "event_id": stable_event_id(engine, device_id, raw),
        "device_id": device_id,
        "observed_at": observed,
        "src_ip": src_ip,
        "type": etype,
        "proto": proto,
    }
    src_port = _src_port(record)
    if src_port is not None:
        event["src_port"] = src_port
    dst_ip = _dst_ip(record)
    if dst_ip:
        event["dst_ip"] = dst_ip
    dst_port = _dst_port(record)
    if dst_port:
        event["dst_port"] = dst_port
    detail = _detail(record, engine, etype)
    if probe:
        detail["classification"] = "protocol_probe"
        detail["probe_protocol"] = "http"
        detail["original_type"] = original_type
        detail["mitre"] = "T1046"
        detail["message"] = "Protocol probe: HTTP request on a non-HTTP listener"
    if detail:
        event["detail"] = detail
    # validate_event raises ValueError on any contract violation.
    return validate_event(event)


__all__ = [
    "NormalizeError",
    "canonical_ip",
    "fingerprint",
    "normalize_raw",
    "normalize_timestamp",
    "resolve_protocol",
    "stable_event_id",
]
