"""Adapter from the runtime v1 event contract to the ECS/Dystopia contract.

The standalone sensor (``runtime/``) never imports ``app`` and persists only
the strict v1 fields (``event_id``, ``device_id``, ``observed_at``, ``src_ip``,
``type``, ``proto``, ``src_port``, ``detail``).  The central exporter reads
those already-persisted rows and rebuilds one ECS document with the same
``build_event`` helper used by the native-log adapters.

Two properties are intentional:

* **Stable document id.**  ``event.id`` is derived only from the ingest sensor
  name and the persisted runtime ``event_id`` (a canonical UUID4).  Topology
  metadata is used for enrichment, never for identity, so a topology edit
  cannot create a second Elasticsearch document for the same stored event.
* **No silent drops.**  An unknown runtime ``type`` becomes ECS ``other`` and
  a missing/unknown device is retained under ``unknown-<observer>`` by
  ``build_event``.  Missing topology metadata never removes the event.

Captured values in ``detail`` (password, command, URL, ...) are handled exactly
like the other adapters: credentials become a non-secret reference and hostile
payloads go to the non-indexed ``dystopia_restricted`` container.
"""

from typing import Any, Mapping, Optional
from uuid import NAMESPACE_URL, uuid5

from .ecs import build_event

OBSERVER = "dystopia-runtime"
PRODUCT = "Dystopia runtime sensor"
DOCUMENT_NAMESPACE = "dystopia/runtime/"

# ``detail`` keys that are hostile payload, never indexable content.  The
# container in ``ecs._payload`` accepts only these names.
_PAYLOAD_KEYS = ("command", "url", "message", "file", "data", "hash", "md5", "sha256")


def runtime_document_id(sensor: str, event_id: str) -> str:
    """Deterministic Elasticsearch ``_id`` for a persisted runtime event.

    Both inputs are server-assigned and stable; no wall clock, topology or
    GeoIP data is part of the identity.  Replays therefore hit the existing
    ``_create`` document (409) instead of creating a logical duplicate.
    """
    return str(uuid5(NAMESPACE_URL, DOCUMENT_NAMESPACE + sensor + "/" + event_id))


def _text(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _device_destination(resolver: Any, device_id: Optional[str]) -> Optional[str]:
    """Best-effort destination address from topology; never raises."""
    if not device_id or resolver is None:
        return None
    try:
        device = resolver.device(device_id)
    except Exception:  # noqa: BLE001 - metadata must never drop an event
        return None
    if not isinstance(device, Mapping):
        return None
    return _text(device.get("destination_ip")) or _text(device.get("ip"))


def normalize(
    raw: Any,
    *,
    resolver: Any = None,
    instance_id: str = "unassigned",
    default_device: str = "",
    sensor: str = "",
    fallback_timestamp: Any = None,
    raw_reference: Any = None,
) -> Optional[dict]:
    """Normalize one stored runtime v1 event.

    Returns ``None`` only when the stored payload is not a mapping or lacks a
    usable ``event_id`` (repository corruption); the caller decides how to
    account for it.  A valid event with an unknown ``type`` is still returned
    as an ECS ``other`` event.
    """
    if not isinstance(raw, Mapping):
        return None
    event_id = _text(raw.get("event_id"))
    if not event_id:
        return None

    detail = raw.get("detail")
    if not isinstance(detail, Mapping):
        detail = {}

    payload = {
        key: detail[key]
        for key in _PAYLOAD_KEYS
        if isinstance(detail.get(key), str) and detail[key]
    }
    username = _text(detail.get("username")) or _text(detail.get("user"))
    password = _text(detail.get("password"))
    session = _text(detail.get("session")) or _text(detail.get("session_id"))
    device = _text(raw.get("device_id")) or default_device or ""
    observer = _text(sensor) or OBSERVER

    document = build_event(
        observer_name=observer,
        observer_product=PRODUCT,
        event_type=_text(raw.get("type")) or "other",
        timestamp=raw.get("observed_at"),
        fallback_timestamp=fallback_timestamp,
        src_ip=raw.get("src_ip"),
        src_port=raw.get("src_port"),
        dst_ip=_device_destination(resolver, device),
        dst_port=detail.get("dst_port"),
        protocol=raw.get("proto"),
        session_id=session,
        username=username,
        password=password,
        payload=payload or None,
        native_id=event_id,
        raw=dict(raw),
        raw_reference=raw_reference or {"source": "runtime-v1", "offset": event_id},
        resolver=resolver,
        device_id=device,
        instance_id=instance_id,
    )
    document["event"]["id"] = runtime_document_id(observer, event_id)
    return document
