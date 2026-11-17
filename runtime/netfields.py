"""Robust source/destination attribution for heterogeneous honeypot logs.

Every engine names the peer differently and some of them nest it: Cowrie writes
``src_ip``, OpenCanary ``src_host``, Heralding ``source_ip``, RedisHoneyPot
``addr`` (``ip:port``), Endlessh ``host=... port=...`` and Dionaea may only
expose ``connection.remote_ip``. When the normalizer understands just one
spelling, an event that does carry an origin is either dropped (no source IP)
or, worse, attributed to the decoy's own address.

This module is standard-library only and deliberately conservative:

* Structured, source-specific fields win over free text.
* Nested ``source``/``client``/``remote``/``connection`` mappings are searched.
* ``ip:port``, ``[ipv6]:port`` and ``host=IP port=N`` spellings are accepted.
* Free text is only a last resort and never looked up in URLs or payloads.
* Generic ``host``/``hostname`` fields are *not* treated as an origin unless
  they appear inside an explicit source container: OpenCanary stores the decoy
  address in ``logdata.HOST`` and using it would invert the attribution.

Both the sensor collector (``runtime.normalize``) and the ECS adapters
(``app.services.deception.integrations.ecs``) use the same helpers, so the
rules cannot drift between the telemetry and the analytics path.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
import re
from typing import Any, Mapping, Optional

MAX_DEPTH = 4
MAX_ITEMS = 32
MAX_NODES = 128
MAX_TEXT = 512

# Ordered by specificity. Nested containers are represented by their name and
# are coerced through ``_metadata_ip`` below.
_SOURCE_KEYS = (
    "src_ip", "srcip", "src_addr", "src_address", "src_host", "src_hostname",
    "source_ip", "sourceip", "source_addr", "source_address", "source_host",
    "source_hostname", "sourceipaddress",
    "remote_ip", "remoteip", "remote_addr", "remote_address", "remote_host",
    "remote_hostname", "remotehost",
    "peer_ip", "peerip", "peer_addr", "peer_address", "peer_host",
    "client_ip", "clientip", "client_addr", "client_address", "client_host",
    "origin_ip", "origin_addr", "origin_address", "attacker_ip",
    "attacker_addr", "attacker_address", "sender_ip", "sender_addr",
    "saddr", "srcaddr", "sourceaddress",
    # A mapping/string under one of these names is handled as an address.
    "source", "client", "remote", "peer", "origin", "src",
    # RedisHoneyPot/common sockets. ``addr`` outranks the generic keys because
    # it is the only origin field in the native RedisHoneyPot record.
    "addr", "sock", "socket", "address", "ip", "ip_address", "ipaddress",
)
_GENERIC_SOURCE_KEYS = {"address", "ip", "ip_address", "ipaddress"}

_DESTINATION_KEYS = (
    "dst_ip", "dstip", "dst_addr", "dst_address", "dst_host", "dst_hostname",
    "dest_ip", "destip", "dest_addr", "dest_address", "dest_host",
    "destination_ip", "destinationip", "destination_addr",
    "destination_address", "destination_host", "destination_hostname",
    "local_ip", "localip", "local_addr", "local_address", "local_host",
    "server_ip", "server_addr", "server_host", "target_ip", "target_addr",
    "sink_ip", "daddr", "destinationaddress",
    "destination", "local", "server", "target", "dst", "dest",
    "address", "ip", "ip_address", "ipaddress",
)
_GENERIC_DESTINATION_KEYS = {"address", "ip", "ip_address", "ipaddress"}

# Containers commonly used by the engines. We only recurse into names we know,
# never into arbitrary payloads, and we bound depth/count.
_NESTED_CONTAINERS = (
    "connection", "connections", "conn", "socket", "sockets", "network",
    "source", "client", "remote", "peer", "origin", "src", "request", "http",
    "tls", "smtp", "ssh", "ftp", "smb", "session", "auth_attempts", "data",
    "logdata", "event", "metadata", "flow", "transport",
)
_SOURCE_CONTAINERS = {"source", "client", "remote", "peer", "origin", "src"}
_DESTINATION_CONTAINERS = {"destination", "local", "server", "target", "dst", "dest"}

_SOURCE_PORT_KEYS = (
    "src_port", "srcport", "source_port", "sourceport", "remote_port",
    "remoteport", "client_port", "clientport", "sport", "sp", "sportnum",
)
_DESTINATION_PORT_KEYS = (
    "dst_port", "dstport", "destination_port", "destinationport", "dest_port",
    "local_port", "localport", "server_port", "target_port", "dport", "dp",
)

# Text fallbacks. They are intentionally narrower than the structured search:
# no URLs, no payload fields, only lines/messages that can describe a socket.
_TEXT_KEYS = ("message", "msg", "action", "line", "raw", "text")

_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
_IPV6 = r"(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*"
_IP_TOKEN = rf"(?:\[{_IPV6}\]|\[{_IPV4}\]|{_IPV4}|{_IPV6})"
_SOCKET_RE = re.compile(
    rf"(?<![\w.])(?P<ip>{_IP_TOKEN})(?::(?P<port>\d{{1,5}}))?(?![\w.])"
)
_NAMED_SOURCE_RE = re.compile(
    rf"(?i)\b(?:from|src|source|client|remote|orig(?:in)?)\s*[=: ]\s*[\"']?"
    rf"(?P<ip>{_IP_TOKEN})(?::(?P<port>\d{{1,5}}))?"
)
_HOST_PORT_RE = re.compile(
    rf"(?i)\bhost\s*=\s*[\"']?(?P<ip>{_IP_TOKEN})[\"']?"
    rf"(?:\s+port\s*=\s*(?P<port>\d{{1,5}}))?"
)
_NAMED_DESTINATION_RE = re.compile(
    rf"(?i)\b(?:to|dst|dest|destination|local|server|target)\s*[=: ]\s*[\"']?"
    rf"(?P<ip>{_IP_TOKEN})(?::(?P<port>\d{{1,5}}))?"
)
_PAREN_SOCKET_RE = re.compile(
    rf"\([^)]*?(?P<ip>{_IP_TOKEN})(?::(?P<port>\d{{1,5}}))?[^)]*?\)"
)
# Only scan a free-text message for a bare socket when the line describes a
# connection. This avoids attributing a file-download URL to the attacker.
_TEXT_ORIGIN_HINT = re.compile(
    r"(?i)\b(?:connection|connect|accepted|accept|session|login|auth|from|"
    r"client|remote|host|source|src)\b"
)


@dataclass(frozen=True)
class Address:
    """A canonical IP plus an optional port and the field it came from."""

    ip: str
    port: Optional[int] = None
    origin: str = ""


def _int_port(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _make_address(host: Any, port: Any) -> Optional[Address]:
    if not isinstance(host, str):
        return None
    text = host.strip().strip("\"'").strip().strip("[]").rstrip(".,;")
    if not text or len(text) > MAX_TEXT:
        return None
    try:
        parsed = ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    if parsed.is_multicast or parsed.is_unspecified:
        return None
    return Address(str(parsed), _int_port(port))


def parse_address(value: Any) -> Optional[Address]:
    """Parse a value or nested mapping into an :class:`Address`."""
    if isinstance(value, Mapping):
        return _metadata_ip(value, "")
    if isinstance(value, (list, tuple)):
        for item in value[:MAX_ITEMS]:
            found = parse_address(item)
            if found:
                return found
        return None
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > MAX_TEXT:
        return None

    # ``host=1.2.3.4 port=443`` is common in Endlessh/other text logs.
    match = _HOST_PORT_RE.search(text)
    if match:
        return _make_address(match.group("ip"), match.group("port"))

    # ``1.2.3.4:443`` / ``[2001:db8::1]:443`` / plain literal.
    token = text.split()[0].strip().strip("\"'").rstrip(",;")
    if token.startswith("["):
        end = token.find("]")
        if end != -1:
            return _make_address(token[1:end], token[end + 1:].lstrip(":") or None)
    # A bare IPv6 literal can legitimately end in a numeric group (for example
    # ``2001:db8::1:443``). Parse the whole token first; only split a trailing
    # numeric component when the full token is not a valid address.
    whole = _make_address(token, None)
    if whole:
        return whole
    if ":" in token:
        head, tail = token.rsplit(":", 1)
        if tail.isdigit():
            found = _make_address(head, tail)
            if found:
                return found
    return None


def canonical_ip(value: Any) -> Optional[str]:
    """Return the canonical IP literal or ``None``.

    Accepts raw literals, bracketed IPv6, ``ip:port`` and ``host=IP port=N``.
    Unspecified and multicast addresses are rejected because they cannot
    identify a sender.
    """
    address = parse_address(value)
    return address.ip if address else None


def _metadata_ip(value: Mapping[str, Any], origin: str) -> Optional[Address]:
    """Extract an address from a mapping such as ``{"ip": ..., "port": ...}``."""
    for key in (
        "ip", "source_ip", "src_ip", "address", "addr", "remote_ip",
        "source", "client", "ip_address",
    ):
        if key not in value:
            continue
        found = parse_address(value[key])
        if found:
            port = found.port
            if port is None:
                for port_key in ("port", *_SOURCE_PORT_KEYS):
                    port = _int_port(value.get(port_key))
                    if port is not None:
                        break
            return Address(found.ip, port, f"{origin}{key}")
    return None


def _iter_mappings(value: Mapping[str, Any], origin: str, depth: int):
    """Yield bounded ``(mapping, path)`` pairs from known containers."""
    if depth >= MAX_DEPTH:
        return
    for container in _NESTED_CONTAINERS:
        child = value.get(container)
        if isinstance(child, Mapping):
            yield child, f"{origin}{container}."
        elif isinstance(child, (list, tuple)):
            for item in child[:MAX_ITEMS]:
                if isinstance(item, Mapping):
                    yield item, f"{origin}{container}."
                    break


def _search(
    record: Mapping[str, Any],
    keys: tuple[str, ...],
    generic_keys: set[str],
    containers: set[str],
    origin: str,
    depth: int,
    budget: list[int],
) -> Optional[Address]:
    if depth > MAX_DEPTH or budget[0] <= 0:
        return None
    budget[0] -= 1
    for key in keys:
        if key not in record:
            continue
        value = record[key]
        # Generic "address"/"ip" fields are only trusted inside a source or
        # destination container, where the meaning is explicit.
        if key in generic_keys:
            parent = origin.rsplit(".", 1)[0].split(".")[-1]
            if parent not in containers:
                continue
        found = parse_address(value)
        if found:
            return Address(found.ip, found.port, f"{origin}{key}")

    for child, path in _iter_mappings(record, origin, depth):
        found = _search(child, keys, generic_keys, containers, path, depth + 1, budget)
        if found:
            return found
    return None


def _source_port_from_mapping(record: Mapping[str, Any], depth: int = 0) -> Optional[int]:
    if depth > MAX_DEPTH:
        return None
    for key in (*_SOURCE_PORT_KEYS, "source.port", "src.port", "remote.port",
                "client.port"):
        port = _int_port(record.get(key))
        if port is not None:
            return port
    for container in (*_SOURCE_CONTAINERS, "connection"):
        child = record.get(container)
        if isinstance(child, Mapping):
            port = _source_port_from_mapping(child, depth + 1)
            if port is not None:
                return port
    return None


def _destination_port_from_mapping(
    record: Mapping[str, Any], depth: int = 0,
) -> Optional[int]:
    if depth > MAX_DEPTH:
        return None
    for key in (*_DESTINATION_PORT_KEYS, "destination.port", "dst.port",
                "local.port", "server.port"):
        port = _int_port(record.get(key))
        if port is not None:
            return port
    for container in (*_DESTINATION_CONTAINERS, "connection"):
        child = record.get(container)
        if isinstance(child, Mapping):
            port = _destination_port_from_mapping(child, depth + 1)
            if port is not None:
                return port
    return None


def _text_candidates(record: Mapping[str, Any]) -> list[str]:
    candidates: list[str] = []
    for key in _TEXT_KEYS:
        value = record.get(key)
        if isinstance(value, str) and value:
            candidates.append(value[:MAX_TEXT])
    return candidates


def _from_text(text: str, pattern: re.Pattern[str]) -> Optional[Address]:
    match = pattern.search(text)
    if not match:
        return None
    return _make_address(match.group("ip"), match.group("port"))


def _socket_matches(text: str) -> list[Address]:
    found: list[Address] = []
    for match in _SOCKET_RE.finditer(text):
        address = _make_address(match.group("ip"), match.group("port"))
        if address:
            found.append(address)
    return found


def find_source(record: Any, *, allow_text: bool = True) -> Optional[Address]:
    """Find the sender address using structured fields, then text fallback."""
    if isinstance(record, str):
        if not allow_text:
            return None
        return (_from_text(record, _NAMED_SOURCE_RE)
                or _from_text(record, _HOST_PORT_RE)
                or next((item for item in _socket_matches(record) if item.port is not None), None))
    if not isinstance(record, Mapping):
        return None

    found = _search(
        record, _SOURCE_KEYS, _GENERIC_SOURCE_KEYS, _SOURCE_CONTAINERS, "", 0,
        [MAX_NODES],
    )
    if found:
        port = found.port or _source_port_from_mapping(record)
        return Address(found.ip, port, found.origin)

    # ECS dotted keys are valid top-level JSON keys in flattened exports.
    for key in ("source.ip", "source.address", "client.ip", "client.address",
                "related.ip", "observer.ip"):
        if key in record:
            found = parse_address(record[key])
            if found:
                return Address(
                    found.ip, found.port or _source_port_from_mapping(record), key,
                )

    if allow_text:
        for text in _text_candidates(record):
            found = _from_text(text, _NAMED_SOURCE_RE) or _from_text(text, _HOST_PORT_RE)
            if found:
                return Address(found.ip, found.port, "message")
            if _TEXT_ORIGIN_HINT.search(text):
                sockets = [item for item in _socket_matches(text) if item.port is not None]
                if sockets:
                    return Address(sockets[0].ip, sockets[0].port, "message")
    return None


def find_destination(record: Any, *, allow_text: bool = True) -> Optional[Address]:
    """Find the decoy/destination address; never guesses from URLs."""
    if not isinstance(record, Mapping):
        return None

    found = _search(
        record, _DESTINATION_KEYS, _GENERIC_DESTINATION_KEYS,
        _DESTINATION_CONTAINERS, "", 0, [MAX_NODES],
    )
    if found:
        port = found.port or _destination_port_from_mapping(record)
        return Address(found.ip, port, found.origin)

    for key in ("destination.ip", "destination.address", "server.ip",
                "server.address", "host.ip"):
        if key in record:
            found = parse_address(record[key])
            if found:
                return Address(
                    found.ip, found.port or _destination_port_from_mapping(record), key,
                )

    # OpenCanary keeps the decoy address in ``logdata.HOST``/``HOSTNAME``. It is
    # a destination, never an origin, so it is only consulted here.
    logdata = record.get("logdata")
    if isinstance(logdata, Mapping):
        for key in ("HOST", "host", "HOSTNAME", "hostname"):
            found = parse_address(logdata.get(key))
            if found:
                return Address(
                    found.ip, found.port or _destination_port_from_mapping(record),
                    f"logdata.{key}",
                )

    if allow_text:
        for text in _text_candidates(record):
            found = _from_text(text, _NAMED_DESTINATION_RE)
            if found:
                return Address(found.ip, found.port, "message")
            # Cowrie writes "src (dst)" in connection messages. Only an
            # explicitly parenthesized socket is used; a bare second socket
            # would misread Endlessh ``host=... port=...`` as a destination.
            if _TEXT_ORIGIN_HINT.search(text):
                found = _from_text(text, _PAREN_SOCKET_RE)
                if found:
                    return Address(found.ip, found.port, "message")
    return None


__all__ = [
    "Address",
    "canonical_ip",
    "find_destination",
    "find_source",
    "parse_address",
]
