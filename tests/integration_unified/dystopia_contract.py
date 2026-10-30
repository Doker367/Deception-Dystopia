"""Test-only reference implementation of the unified Dystopia/T-Pot/Elastic contract.

This module is deliberately dependency-free (standard library only). It does NOT
replace production normalizers, publishers or mappings: it encodes the contract
that those artifacts are expected to satisfy, so the integration suite is
executable with mocks while production code is still being built.

Contract summary
----------------
* Wire input: Dystopia ``runtime.contracts`` v1 events and T-Pot/Cowrie JSON lines.
* Document: ECS-shaped with ``@timestamp``, stable ``event.id``, source/destination/
  network/observer/session and ``dystopia.*`` topology provenance.
* Identity: ``event.id`` is globally unique and stable, so it is the
  Elasticsearch document id (``PUT _doc/{event.id}``). Producers fold the
  observer into the derivation when the honeypot ID is not globally unique.
  Replays are idempotent; the same ID with different content is a conflict,
  never an overwrite.
* Hygiene: captured passwords, tokens and commands are dropped before a
  document or a log line is produced.
"""
from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_address
import json
from pathlib import Path
import re
from uuid import UUID

FIXTURES = Path(__file__).resolve().with_name("fixtures")

SCHEMA_VERSION = "1.0"

# path -> accepted Elasticsearch mapping types
REQUIRED_FIELDS = {
    "@timestamp": {"date"},
    "event.id": {"keyword"},
    "event.action": {"keyword"},
    "event.dataset": {"keyword"},
    "source.ip": {"ip"},
    "destination.ip": {"ip"},
    "destination.port": {"long", "integer"},
    "network.transport": {"keyword"},
    "network.protocol": {"keyword"},
    "observer.name": {"keyword"},
    "session.id": {"keyword"},
    "dystopia.schema_version": {"keyword"},
    "dystopia.device_id": {"keyword"},
    "dystopia.segment_id": {"keyword"},
    "dystopia.instance_id": {"keyword"},
    "dystopia.persona": {"keyword"},
}
# Fields that must be present with the listed mapping type. Keeping the nested
# set explicit makes the contract readable in one place.

OPTIONAL_FIELDS = {
    "source.port": {"long", "integer"},
    "event.outcome": {"keyword"},
    "event.category": {"keyword"},
    "observer.product": {"keyword"},
}

EVENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
SCHEMA_VERSION_RE = re.compile(r"^\d+\.\d+$")
SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|"
    r"private[_-]?key|credential|client[_-]?secret)"
)


class ContractError(ValueError):
    """A document or fixture violates the unified contract."""


# --------------------------------------------------------------------------- #
# Loading and timestamps
# --------------------------------------------------------------------------- #
def load_json(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def load_jsonl(name):
    rows = []
    for line_no, line in enumerate((FIXTURES / name).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ContractError(f"{name}:{line_no}: invalid JSON: {exc.msg}") from None
    return rows


def parse_timestamp(value):
    if not isinstance(value, str) or not value or len(value) > 40:
        raise ContractError("timestamp must be a non-empty ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ContractError("timestamp is not ISO-8601") from None
    if parsed.tzinfo is None:
        raise ContractError("timestamp requires an explicit timezone")
    return parsed.astimezone(timezone.utc)


def format_timestamp(value):
    parsed = parse_timestamp(value)
    return parsed.strftime("%Y-%m-%dT%H:%M:%S.") + f"{parsed.microsecond // 1000:03d}Z"


# --------------------------------------------------------------------------- #
# Nested access and mapping flattening
# --------------------------------------------------------------------------- #
def get_path(document, path, default=None):
    current = document
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def set_path(document, path, value):
    parts = path.split(".")
    current = document
    for part in parts[:-1]:
        current = current.setdefault(part, {})
    current[parts[-1]] = value


def extract_mapping_properties(mapping, _depth=0):
    """Accept a raw mapping, an index template or a component template."""
    if not isinstance(mapping, dict) or _depth > 4:
        raise ContractError("mapping must be a JSON object")
    if "mappings" in mapping and isinstance(mapping["mappings"], dict):
        return extract_mapping_properties(mapping["mappings"], _depth + 1)
    if "template" in mapping and isinstance(mapping["template"], dict):
        return extract_mapping_properties(mapping["template"], _depth + 1)
    if "properties" in mapping and isinstance(mapping["properties"], dict):
        return mapping["properties"]
    raise ContractError("mapping has no properties/mappings/template object")


def flatten_mapping(properties, prefix=""):
    """Map dotted path -> leaf type. Multi-fields are ignored on purpose."""
    flat = {}
    for name, definition in properties.items():
        path = f"{prefix}.{name}" if prefix else name
        if not isinstance(definition, dict):
            raise ContractError(f"mapping field {path} is not an object")
        if "properties" in definition:
            flat.update(flatten_mapping(definition["properties"], path))
        else:
            leaf_type = definition.get("type")
            if not isinstance(leaf_type, str):
                raise ContractError(f"mapping field {path} has no type")
            flat[path] = leaf_type
    return flat


# --------------------------------------------------------------------------- #
# Topology (Dystopia is the topology source of truth)
# --------------------------------------------------------------------------- #
def load_topology():
    topology = load_json("topology.json")
    devices = topology.get("devices")
    if not isinstance(devices, dict) or not devices:
        raise ContractError("topology fixture has no devices")
    return topology


def topology_device(topology, device_id):
    try:
        device = topology["devices"][device_id]
    except KeyError:
        raise ContractError(f"device {device_id!r} is absent from Dystopia topology") from None
    for field in ("segment_id", "instance_id", "persona", "destination_ip"):
        if not isinstance(device.get(field), str) or not device[field]:
            raise ContractError(f"topology device {device_id!r} lacks {field}")
    ip_address(device["destination_ip"])
    return device


def _canonical_address(value):
    try:
        address = ip_address(value)
    except (ValueError, TypeError):
        raise ContractError("event has a non-literal source address") from None
    if str(address) != value:
        raise ContractError("event source address must be canonical")
    return str(address)


def _service_port(device, protocol):
    for service in device.get("services", []):
        if service.get("protocol") == protocol:
            return int(service["port"])
    services = device.get("services") or []
    if not services:
        raise ContractError(f"device {device.get('hostname')!r} has no services")
    return int(services[0]["port"])


# --------------------------------------------------------------------------- #
# Normalization (reference behaviour, not production code)
# --------------------------------------------------------------------------- #
NATIVE_CATEGORY = {
    "connect": ["network"],
    "disconnect": ["session"],
    "login_attempt": ["authentication"],
    "login_success": ["authentication"],
    "command": ["process"],
    "file_download": ["file"],
    "port_scan": ["network", "intrusion_detection"],
    "other": ["event"],
}
COWRIE_CATEGORY = {
    "connect": ["session"],
    "login": ["authentication"],
    "command": ["process"],
    "client": ["network"],
    "session": ["session"],
}


def _native_outcome(event):
    detail = event.get("detail") or {}
    explicit = detail.get("outcome")
    if explicit in {"success", "failure", "unknown"}:
        return explicit
    if event["type"] == "login_success":
        return "success"
    if event["type"] == "login_attempt":
        return "failure"
    if event["type"] == "port_scan":
        return "unknown"
    return "success"


def normalize_native(event, topology, observer_name="dystopia-native-lab"):
    """Map a strict v1 Dystopia event to the unified ECS document."""
    device = topology_device(topology, event["device_id"])
    proto = event["proto"]
    transport = "udp" if proto in {"snmp", "udp"} else "tcp"
    detail = event.get("detail") or {}
    document = {
        "@timestamp": format_timestamp(event["observed_at"]),
        "event": {
            "id": event["event_id"],
            "action": event["type"],
            "dataset": "dystopia",
            "outcome": _native_outcome(event),
            "category": list(NATIVE_CATEGORY.get(event["type"], ["event"])),
        },
        "source": {"ip": _canonical_address(event["src_ip"])},
        "destination": {
            "ip": device["destination_ip"],
            "port": _service_port(device, proto),
        },
        "network": {"transport": transport, "protocol": proto},
        "observer": {"name": observer_name, "product": "Dystopia"},
        "session": {
            "id": detail.get("session")
            or f"{event['device_id']}:{event['src_ip']}",
        },
        "dystopia": {
            "schema_version": SCHEMA_VERSION,
            "device_id": event["device_id"],
            "segment_id": device["segment_id"],
            "instance_id": device["instance_id"],
            "persona": device["persona"],
        },
    }
    if "src_port" in event:
        document["source"]["port"] = event["src_port"]
    return document


def normalize_cowrie(raw, topology, device_id, observer_name="cowrie-lab-01"):
    """Map a raw Cowrie JSON line to the unified ECS document.

    Passwords and raw input are intentionally not copied. ``eventid`` must be a
    canonical UUID4: a missing or malformed ID is rejected instead of being
    replaced by a random value, because a random value would break idempotency.
    """
    event_id = raw.get("eventid")
    if not isinstance(event_id, str):
        raise ContractError("Cowrie event lacks eventid")
    try:
        parsed = UUID(event_id)
    except (ValueError, AttributeError):
        raise ContractError("Cowrie eventid is not a UUID") from None
    if parsed.version != 4 or str(parsed) != event_id:
        raise ContractError("Cowrie eventid must be a canonical UUID4")

    message = raw.get("message")
    if not isinstance(message, str) or not message:
        raise ContractError("Cowrie event lacks message")
    session = raw.get("session")
    if not isinstance(session, str) or not session:
        raise ContractError("Cowrie event lacks session")
    device = topology_device(topology, device_id)

    try:
        source_ip = str(ip_address(raw.get("src_ip", "")))
        destination_ip = str(ip_address(raw.get("dst_ip", "")))
    except (ValueError, TypeError):
        raise ContractError("Cowrie event has a non-literal source/destination address") from None
    if source_ip != raw.get("src_ip") or destination_ip != raw.get("dst_ip"):
        raise ContractError("Cowrie addresses must be canonical")
    if destination_ip != device["destination_ip"]:
        raise ContractError(
            "Cowrie destination does not match the device's Dystopia address"
        )
    protocol = raw.get("protocol") or "ssh"
    category_key = message.split(".")[1] if "." in message else "session"
    document = {
        "@timestamp": format_timestamp(raw["timestamp"]),
        "event": {
            "id": event_id,
            "action": message,
            "dataset": "cowrie",
            "category": list(COWRIE_CATEGORY.get(category_key, ["event"])),
        },
        "source": {"ip": source_ip},
        "destination": {
            "ip": destination_ip,
            "port": int(raw.get("dst_port") or _service_port(device, protocol)),
        },
        "network": {
            "transport": "udp" if protocol in {"snmp", "udp"} else "tcp",
            "protocol": protocol,
        },
        "observer": {"name": observer_name, "product": "Cowrie"},
        "session": {"id": session},
        "dystopia": {
            "schema_version": SCHEMA_VERSION,
            "device_id": device_id,
            "segment_id": device["segment_id"],
            "instance_id": device["instance_id"],
            "persona": device["persona"],
        },
    }
    if raw.get("src_port") is not None:
        document["source"]["port"] = int(raw["src_port"])

    if message == "cowrie.login.failed":
        document["event"]["outcome"] = "failure"
    elif message == "cowrie.login.success":
        document["event"]["outcome"] = "success"
    elif message in {"cowrie.command.input", "cowrie.session.connect", "cowrie.session.closed"}:
        document["event"]["outcome"] = "success"
    else:
        document["event"]["outcome"] = "unknown"
    return document


def normalize_fixture_documents():
    """Return (native, cowrie) reference documents for the shipped fixtures."""
    topology = load_topology()
    native = [normalize_native(event, topology) for event in load_jsonl("events_native.jsonl")]
    cowrie = [
        normalize_cowrie(raw, topology, "srv-files-01")
        for raw in load_jsonl("events_cowrie.jsonl")
    ]
    return native, cowrie


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def _check_type(path, value, accepted, errors):
    if isinstance(value, list):
        if path == "event.category" and all(isinstance(item, str) for item in value):
            return
        errors.append(f"{path}: arrays are not allowed for this field")
        return
    if path == "dystopia.schema_version" and type(value) is int:
        # Elasticsearch coerces an integer into a keyword. Producers should
        # emit the string form, but a numeric schema version is not a defect.
        return
    if "keyword" in accepted or "text" in accepted:
        if not isinstance(value, str) or not value:
            errors.append(f"{path}: expected a non-empty keyword string")
        return
    if "ip" in accepted:
        try:
            parsed = str(ip_address(value))
        except (ValueError, TypeError):
            errors.append(f"{path}: expected a literal IP address")
            return
        if parsed != value:
            errors.append(f"{path}: IP address must be canonical")
        return
    if "date" in accepted:
        try:
            parse_timestamp(value)
        except ContractError as exc:
            errors.append(f"{path}: {exc}")
        return
    if accepted & {"long", "integer"}:
        if type(value) is not int:
            errors.append(f"{path}: expected an integer")
        return
    if "boolean" in accepted and type(value) is not bool:
        errors.append(f"{path}: expected a boolean")


def validate_document(document, require_optional=False):
    errors = []
    if not isinstance(document, dict):
        raise ContractError("document must be an object")
    for path, accepted in REQUIRED_FIELDS.items():
        if get_path(document, path) is None:
            errors.append(f"{path}: required field missing")
        else:
            _check_type(path, get_path(document, path), accepted, errors)
    if require_optional:
        for path, accepted in OPTIONAL_FIELDS.items():
            if get_path(document, path) is not None:
                _check_type(path, get_path(document, path), accepted, errors)

    event_id = get_path(document, "event.id")
    if isinstance(event_id, str) and not EVENT_ID_RE.fullmatch(event_id):
        errors.append("event.id: must be stable, whitespace-free and <=128 chars")
    schema_version = get_path(document, "dystopia.schema_version")
    if isinstance(schema_version, str) and not SCHEMA_VERSION_RE.fullmatch(schema_version):
        errors.append("dystopia.schema_version: expected MAJOR.MINOR")
    elif type(schema_version) is int and not 1 <= schema_version <= 999:
        errors.append("dystopia.schema_version: integer version out of range")
    for path in ("source.port", "destination.port"):
        port = get_path(document, path)
        if port is not None and (type(port) is not int or not 1 <= port <= 65535):
            errors.append(f"{path}: port must be 1..65535")
    transport = get_path(document, "network.transport")
    if isinstance(transport, str) and transport not in {"tcp", "udp"}:
        errors.append("network.transport: expected tcp or udp")
    for path in ("source.ip", "destination.ip"):
        value = get_path(document, path)
        try:
            if ip_address(value).is_multicast or ip_address(value).is_unspecified:
                errors.append(f"{path}: multicast/unspecified addresses are not valid peers")
        except (ValueError, TypeError):
            pass
    if errors:
        raise ContractError("; ".join(errors))
    return True


def mapping_contract_errors(properties):
    flat = flatten_mapping(properties)
    errors = []
    for path, accepted in REQUIRED_FIELDS.items():
        actual = flat.get(path)
        if actual is None:
            errors.append(f"{path}: missing from mapping")
        elif actual not in accepted:
            errors.append(f"{path}: mapping type {actual!r} is not one of {sorted(accepted)}")
    return errors


def validate_expected_mapping(mapping):
    properties = extract_mapping_properties(mapping)
    errors = mapping_contract_errors(properties)
    if errors:
        raise ContractError("; ".join(errors))
    return True


# --------------------------------------------------------------------------- #
# Identity, deduplication and idempotent indexing
# --------------------------------------------------------------------------- #
def document_key(document):
    """Elasticsearch ``_id`` is the stable, globally unique ``event.id``.

    Producers MUST include the observer/sensor in the derivation when an ID is
    not already globally unique (the production normalizer folds observer,
    device, session and a raw fingerprint into a UUID5). The publisher key is
    therefore the event ID alone, matching ``PUT _doc/{event.id}``.
    """
    event_id = get_path(document, "event.id")
    if not event_id:
        raise ContractError("document needs event.id before indexing")
    return event_id


def canonical_payload(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class ConflictError(ContractError):
    pass


class Deduper:
    """In-memory equivalent of the durable identity rule."""

    def __init__(self):
        self._seen = {}
        self.new = 0
        self.duplicates = 0

    def add(self, document):
        key = document_key(document)
        payload = canonical_payload(document)
        prior = self._seen.get(key)
        if prior is None:
            self._seen[key] = payload
            self.new += 1
            return "new"
        if prior != payload:
            raise ConflictError(f"{key}: event ID reused with different content")
        self.duplicates += 1
        return "duplicate"

    @property
    def keys(self):
        return sorted(self._seen)


def dedupe_documents(documents):
    deduper = Deduper()
    unique = []
    for document in documents:
        if deduper.add(document) == "new":
            unique.append(document)
    return unique, deduper.duplicates


class InMemoryIndex:
    """Models Elasticsearch ``PUT _doc/{_id}`` semantics used by the publisher.

    Returns ``created``/``updated``/``duplicate``; a conflicting payload for an
    existing ``_id`` is rejected rather than silently overwritten.
    """

    def __init__(self):
        self._documents = {}

    def index(self, document):
        key = document_key(document)
        payload = canonical_payload(document)
        prior = self._documents.get(key)
        if prior is None:
            self._documents[key] = payload
            return "created"
        if prior != payload:
            raise ConflictError(f"{key}: refusing to overwrite with different content")
        return "duplicate"

    def count(self, field=None, value=None):
        if field is None:
            return len(self._documents)
        return sum(
            1
            for raw in self._documents.values()
            if get_path(json.loads(raw), field) == value
        )

    def search(self, field, op, value, upper=None):
        matches = []
        for raw in self._documents.values():
            document = json.loads(raw)
            if apply_filter(document, {"field": field, "op": op, "value": value, "upper": upper}):
                matches.append(document)
        return matches


# --------------------------------------------------------------------------- #
# Kibana-style filters (offline evaluator)
# --------------------------------------------------------------------------- #
def _comparable(value):
    if isinstance(value, str):
        try:
            return parse_timestamp(value)
        except ContractError:
            return value
    return value


def apply_filter(document, filter_spec):
    field = filter_spec["field"]
    op = filter_spec["op"]
    value = filter_spec.get("value")
    actual = get_path(document, field)
    if op == "exists":
        return actual is not None
    if actual is None:
        return False
    if op == "eq":
        return actual == value
    if op == "ne":
        return actual != value
    if op == "in":
        return actual in value
    if op == "prefix":
        return isinstance(actual, str) and actual.startswith(str(value))
    if op == "contains":
        return value in actual if isinstance(actual, (str, list)) else False
    if op in {"gte", "lte", "gte_lte"}:
        left, right = _comparable(actual), _comparable(value)
        try:
            if op == "gte":
                return left >= right
            if op == "lte":
                return left <= right
            upper = _comparable(filter_spec.get("upper"))
            return left >= right and left <= upper
        except TypeError:
            return False
    raise ContractError(f"unsupported filter op {op!r}")


def filter_documents(documents, filter_spec):
    return [document for document in documents if apply_filter(document, filter_spec)]


# --------------------------------------------------------------------------- #
# Secret hygiene
# --------------------------------------------------------------------------- #
PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}")
APIKEY_RE = re.compile(r"(?i)\b(?:ApiKey|apikey)\s+[A-Za-z0-9._~+/-]{8,}")
USERINFO_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@")
ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|authorization)\s*[=:]\s*"
    r"(?!<\s*redacted|<redacted>|\*\*\*|\[redacted\])[\"']?[^\s\"',;]{4,}"
)
CLOUD_KEY_RE = re.compile(r"\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,})\b")


def _scan_value(path, value, canaries, findings):
    if isinstance(value, dict):
        for key, nested in value.items():
            child = f"{path}.{key}" if path else str(key)
            if SECRET_KEY_RE.search(str(key)):
                findings.append(f"{child}: secret-bearing field present")
            _scan_value(child, nested, canaries, findings)
        return
    if isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _scan_value(f"{path}[{index}]", nested, canaries, findings)
        return
    if not isinstance(value, str):
        return
    for canary in canaries:
        if canary and canary in value:
            findings.append(f"{path}: synthetic canary value leaked")
    if PEM_RE.search(value):
        findings.append(f"{path}: private key material")
    if BEARER_RE.search(value):
        findings.append(f"{path}: bearer credential")
    if APIKEY_RE.search(value):
        findings.append(f"{path}: API key credential")
    if USERINFO_RE.search(value):
        findings.append(f"{path}: URL with embedded credentials")
    if ASSIGNMENT_RE.search(value):
        findings.append(f"{path}: credential-like assignment")
    if CLOUD_KEY_RE.search(value):
        findings.append(f"{path}: cloud access-key pattern")


def scan_for_secrets(value, canaries=()):
    """Return path/pattern findings only; secret values are never echoed."""
    findings = []
    _scan_value("$", value, tuple(canaries), findings)
    return findings


def scan_log_lines(lines, canaries=()):
    findings = []
    for line_no, line in enumerate(lines, 1):
        for finding in scan_for_secrets(line, canaries):
            findings.append(f"line {line_no}: {finding.removeprefix('$: ')}")
    return findings
