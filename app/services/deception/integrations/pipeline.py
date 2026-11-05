"""Small pipeline that normalizes a native log record and optionally publishes.

Publication is opt-in: with no publisher the caller still receives the
normalized document. A publisher is any object exposing ``publish(document)``;
Dystopia no longer ships an Elasticsearch publisher.
"""

from typing import Any, Optional

from . import adapters


class HoneypotPipeline:
    def __init__(
        self,
        *,
        publisher: Optional[Any] = None,
        resolver=None,
        instance_id: str = "unassigned",
        default_device: str = "",
    ):
        self.publisher = publisher
        if resolver is None:
            # Dystopia topology/GeoIP remain the source of truth; the lazy
            # provider imports them inside its methods to avoid cycles.
            from .metadata import topology_metadata

            resolver = topology_metadata()
        self.resolver = resolver
        self.instance_id = instance_id
        self.default_device = default_device

    def ingest(self, sensor: str, raw: Any, *, raw_reference: Any = None) -> tuple[dict, bool]:
        """Normalize, then publish if configured. Never logs captured content."""
        document = adapters.normalize(
            sensor,
            raw,
            resolver=self.resolver,
            instance_id=self.instance_id,
            default_device=self.default_device,
            raw_reference=raw_reference,
        )
        if document is None:
            raise ValueError("record could not be normalized")
        delivered = False
        if self.publisher is not None:
            delivered = self.publisher.publish(document)
        return document, delivered
