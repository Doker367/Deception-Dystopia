"""Lazy metadata bridge for external honeypot adapters.

Dystopia topology/GeoIP remain the source of truth. Imports happen inside the
methods, so importing adapters can never create a topology <-> integrations
cycle, and a missing configuration cannot reject an event.
"""


class TopologyMetadata:
    """Read-only provider backed by the existing topology and GeoIP services."""

    def device(self, device_id: str):
        from app.services.deception import topology_svc

        return topology_svc.get_device(device_id)

    def segment(self, segment_id: str):
        from app.services.deception import topology_svc

        return topology_svc.get_segment(segment_id)

    def geo(self, ip: str):
        from app.services.deception import geoip_svc

        return geoip_svc.lookup(ip)


def topology_metadata() -> TopologyMetadata:
    """Factory used by callers that opt into Dystopia topology enrichment."""
    return TopologyMetadata()
