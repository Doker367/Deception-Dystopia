"""Read-only Elasticsearch query service for the Dystopia analytics UI.

The browser never receives Elasticsearch credentials. This service is the only
component that talks to the analytics cluster and it is intentionally limited
to a small set of aggregate/search operations over the deception data streams.

Configuration (disabled unless ``DYSTOPIA_ANALYTICS_ENABLED=true``):

- ``DYSTOPIA_ANALYTICS_URL``: Elasticsearch base URL (literal IP).
- ``DYSTOPIA_ANALYTICS_INDEX``: default ``deception-events*``.
- ``DYSTOPIA_ANALYTICS_ALERTS_INDEX``: default ``deception-alerts*``.
- ``DYSTOPIA_ANALYTICS_API_KEY_FILE``: private file containing the API key.
- ``DYSTOPIA_ANALYTICS_CA_FILE``: optional CA bundle for TLS.
- ``DYSTOPIA_ANALYTICS_TIMEOUT``: request timeout in seconds.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.parse import urlsplit

import httpx

from runtime.localfiles import read_private

INDEX_RE = re.compile(r"^[a-z0-9][a-z0-9._*-]{0,254}$")
MAX_WINDOW = timedelta(days=90)
DEFAULT_INDEX = "deception-events*"
DEFAULT_ALERTS = "deception-alerts*"
INTERVALS = {"1m", "5m", "15m", "30m", "1h", "3h", "6h", "12h", "1d", "7d"}


class AnalyticsError(RuntimeError):
    """Base class for safe, non-leaking analytics failures."""


class AnalyticsDisabled(AnalyticsError):
    """The analytics plane is not configured."""


class AnalyticsUnavailable(AnalyticsError):
    """Elasticsearch is unreachable or returned an unexpected response."""


@dataclass(frozen=True)
class AnalyticsConfig:
    enabled: bool = False
    url: str = ""
    index: str = DEFAULT_INDEX
    alerts_index: str = DEFAULT_ALERTS
    api_key_file: Path | None = None
    ca_file: Path | None = None
    timeout: float = 5.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "AnalyticsConfig":
        values = os.environ if env is None else env

        def flag(name: str, default: bool = False) -> bool:
            raw = values.get(name)
            if raw is None:
                return default
            return raw.strip().lower() in {"1", "true", "yes", "on"}

        def path(name: str) -> Path | None:
            raw = values.get(name, "").strip()
            return Path(raw) if raw else None

        def number(name: str, default: float) -> float:
            raw = values.get(name, "").strip()
            if not raw:
                return default
            try:
                return float(raw)
            except ValueError as exc:
                raise ValueError(f"invalid {name}") from exc

        return cls(
            enabled=flag("DYSTOPIA_ANALYTICS_ENABLED", False),
            url=values.get("DYSTOPIA_ANALYTICS_URL", "").strip(),
            index=values.get("DYSTOPIA_ANALYTICS_INDEX", DEFAULT_INDEX).strip(),
            alerts_index=values.get("DYSTOPIA_ANALYTICS_ALERTS_INDEX", DEFAULT_ALERTS).strip(),
            api_key_file=path("DYSTOPIA_ANALYTICS_API_KEY_FILE"),
            ca_file=path("DYSTOPIA_ANALYTICS_CA_FILE"),
            timeout=number("DYSTOPIA_ANALYTICS_TIMEOUT", 5.0),
        )

    def validate(self) -> "AnalyticsConfig":
        if not self.enabled:
            return self
        if not self.url:
            raise ValueError("analytics URL required when enabled")
        parsed = urlsplit(self.url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("unsupported analytics URL scheme")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("analytics URL must not contain credentials or query")
        if not parsed.hostname:
            raise ValueError("analytics URL requires a host")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            raise ValueError("analytics host must be a literal IP address") from None
        if parsed.scheme == "http" and not address.is_loopback:
            raise ValueError("non-loopback analytics requires TLS")
        if not address.is_loopback and self.api_key_file is None:
            raise ValueError("non-loopback analytics requires an API key file")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("invalid analytics port")
        if not INDEX_RE.fullmatch(self.index) or not INDEX_RE.fullmatch(self.alerts_index):
            raise ValueError("invalid analytics index name")
        if not 0.1 <= self.timeout <= 30:
            raise ValueError("analytics timeout out of range")
        return self


def _parse_time(value: str | None, fallback: datetime) -> datetime:
    if not value:
        return fallback
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed.astimezone(timezone.utc)


def _window(from_time: str | None, to_time: str | None) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    end = _parse_time(to_time, now)
    start = _parse_time(from_time, end - timedelta(hours=24))
    if start > end:
        raise ValueError("from must be before to")
    if end - start > MAX_WINDOW:
        raise ValueError("window exceeds 90 days")
    return start, end


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _severity(value: Any) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return "info"
    if number >= 9:
        return "critical"
    if number >= 7:
        return "high"
    if number >= 4:
        return "medium"
    if number >= 1:
        return "low"
    return "info"


def _bucket_count(bucket: Mapping[str, Any]) -> int:
    return int(bucket.get("doc_count", 0) or 0)


def _first_term(aggregation: Mapping[str, Any] | None) -> Any:
    buckets = (aggregation or {}).get("buckets") or []
    return buckets[0].get("key") if buckets else None


class AnalyticsService:
    def __init__(self, config: AnalyticsConfig | None = None):
        self.config = (config or AnalyticsConfig.from_env()).validate()

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.config.api_key_file is not None:
            key = read_private(self.config.api_key_file, max_bytes=8192).decode("utf-8").strip()
            if not key:
                raise AnalyticsDisabled("empty analytics API key")
            headers["Authorization"] = f"ApiKey {key}"
        return headers

    def _request(self, method: str, path: str, *, json: Any = None) -> dict[str, Any]:
        if not self.config.enabled:
            raise AnalyticsDisabled("analytics plane disabled")
        verify: bool | str = True
        if self.config.ca_file is not None:
            if not self.config.ca_file.is_file():
                raise AnalyticsUnavailable("analytics CA bundle unavailable")
            verify = str(self.config.ca_file)
        try:
            with httpx.Client(
                base_url=self.config.url.rstrip("/"),
                headers=self._headers(),
                timeout=httpx.Timeout(self.config.timeout, connect=min(self.config.timeout, 3.0)),
                verify=verify,
                follow_redirects=False,
            ) as client:
                response = client.request(method, path, json=json)
        except (httpx.HTTPError, OSError, ValueError) as exc:
            raise AnalyticsUnavailable("analytics backend unavailable") from exc
        if response.status_code >= 400:
            raise AnalyticsUnavailable(f"analytics backend returned HTTP {response.status_code}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise AnalyticsUnavailable("analytics backend returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise AnalyticsUnavailable("analytics backend returned an unexpected payload")
        return payload

    def _search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", f"/{index}/_search?ignore_unavailable=true", json=body)

    def overview(self, from_time: str | None, to_time: str | None) -> dict[str, Any]:
        start, end = _window(from_time, to_time)
        range_query = {"range": {"@timestamp": {"gte": _iso(start), "lte": _iso(end)}}}
        body = {
            "size": 0,
            "track_total_hits": True,
            "query": range_query,
            "aggs": {
                "unique_sources": {"cardinality": {"field": "source.ip"}},
                "protocols": {"terms": {"field": "network.protocol", "size": 10}},
                "datasets": {"terms": {"field": "event.dataset", "size": 10}},
                "severity": {"max": {"field": "event.severity"}},
                "last_event": {"max": {"field": "@timestamp"}},
            },
        }
        result = self._search(self.config.index, body)
        total = int(result.get("hits", {}).get("total", {}).get("value", 0) or 0)
        aggregations = result.get("aggregations", {})
        alerts = 0
        try:
            alert_result = self._search(
                self.config.alerts_index,
                {"size": 0, "track_total_hits": True, "query": range_query},
            )
            alerts = int(alert_result.get("hits", {}).get("total", {}).get("value", 0) or 0)
        except AnalyticsUnavailable:
            # An absent alerts stream is not a fatal condition for the overview.
            alerts = 0
        return {
            "window": {"from": _iso(start), "to": _iso(end)},
            "total_events": total,
            "unique_sources": int(aggregations.get("unique_sources", {}).get("value", 0) or 0),
            "alerts": alerts,
            "max_severity": _severity(aggregations.get("severity", {}).get("value")),
            "latest_event": aggregations.get("last_event", {}).get("value_as_string"),
            "protocols": [
                {"name": bucket.get("key"), "value": _bucket_count(bucket)}
                for bucket in aggregations.get("protocols", {}).get("buckets", [])
            ],
            "datasets": [
                {"name": bucket.get("key"), "value": _bucket_count(bucket)}
                for bucket in aggregations.get("datasets", {}).get("buckets", [])
            ],
        }

    def timeline(self, from_time: str | None, to_time: str | None, interval: str = "1h") -> dict[str, Any]:
        if interval not in INTERVALS:
            raise ValueError("unsupported interval")
        start, end = _window(from_time, to_time)
        body = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": _iso(start), "lte": _iso(end)}}},
            "aggs": {
                "events": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": interval,
                        "min_doc_count": 0,
                        "extended_bounds": {"min": _iso(start), "max": _iso(end)},
                    }
                }
            },
        }
        result = self._search(self.config.index, body)
        buckets = result.get("aggregations", {}).get("events", {}).get("buckets", [])
        return {
            "interval": interval,
            "buckets": [
                {"at": bucket.get("key_as_string"), "count": _bucket_count(bucket)}
                for bucket in buckets
            ],
        }

    def origins(self, from_time: str | None, to_time: str | None, limit: int = 50) -> dict[str, Any]:
        start, end = _window(from_time, to_time)
        body = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": _iso(start), "lte": _iso(end)}}},
            "aggs": {
                "countries": {
                    "terms": {"field": "source.geo.country_iso_code", "size": max(1, min(limit, 100))},
                    "aggs": {
                        "country_name": {"terms": {"field": "source.geo.country_name", "size": 1}},
                        "city": {"terms": {"field": "source.geo.city_name", "size": 1}},
                        "location": {
                            "top_hits": {
                                "size": 1,
                                "_source": [
                                    "source.geo.location",
                                    "source.geo.city_name",
                                    "source.geo.country_name",
                                ],
                            }
                        },
                        "top_ip": {"terms": {"field": "source.ip", "size": 1}},
                        "protocol": {"terms": {"field": "network.protocol", "size": 1}},
                        "dataset": {"terms": {"field": "event.dataset", "size": 1}},
                        "sources": {"cardinality": {"field": "source.ip"}},
                        "severity": {"max": {"field": "event.severity"}},
                        "last_event": {"max": {"field": "@timestamp"}},
                    },
                }
            },
        }
        result = self._search(self.config.index, body)
        origins = []
        for bucket in result.get("aggregations", {}).get("countries", {}).get("buckets", []):
            hit_source = (
                bucket.get("location", {})
                .get("hits", {})
                .get("hits", [{}])[0]
                .get("_source", {})
            )
            geo = hit_source.get("source", {}).get("geo", {}) if isinstance(hit_source, dict) else {}
            location = geo.get("location") if isinstance(geo, dict) else None
            lat = location.get("lat") if isinstance(location, dict) else None
            lng = location.get("lon") if isinstance(location, dict) else None
            origins.append(
                {
                    "countryCode": bucket.get("key"),
                    "country": _first_term(bucket.get("country_name")) or geo.get("country_name") or bucket.get("key"),
                    "city": _first_term(bucket.get("city")) or geo.get("city_name") or "",
                    "ip": _first_term(bucket.get("top_ip")) or "",
                    "lat": lat,
                    "lng": lng,
                    "events": _bucket_count(bucket),
                    "uniqueSources": int(bucket.get("sources", {}).get("value", 0) or 0),
                    "severity": _severity(bucket.get("severity", {}).get("value")),
                    "protocol": _first_term(bucket.get("protocol")) or "",
                    "sensor": _first_term(bucket.get("dataset")) or "",
                    "lastEvent": bucket.get("last_event", {}).get("value_as_string"),
                }
            )
        return {"origins": origins}

    def events(
        self,
        from_time: str | None,
        to_time: str | None,
        *,
        limit: int = 25,
        offset: int = 0,
        query_text: str = "",
        severity: str = "",
        sensor: str = "",
        protocol: str = "",
    ) -> dict[str, Any]:
        start, end = _window(from_time, to_time)
        must: list[dict[str, Any]] = [{"range": {"@timestamp": {"gte": _iso(start), "lte": _iso(end)}}}]
        filters: list[dict[str, Any]] = []
        if sensor:
            filters.append({"term": {"event.dataset": sensor}})
        if protocol:
            filters.append({"term": {"network.protocol": protocol}})
        severity_ranges = {
            "critical": {"gte": 9},
            "high": {"gte": 7, "lt": 9},
            "medium": {"gte": 4, "lt": 7},
            "low": {"gte": 1, "lt": 4},
        }
        if severity in severity_ranges:
            filters.append({"range": {"event.severity": severity_ranges[severity]}})
        if query_text:
            must.append(
                {
                    "multi_match": {
                        "query": query_text,
                        "fields": [
                            "source.ip",
                            "source.geo.country_name",
                            "event.dataset",
                            "event.kind",
                            "event.action",
                            "dystopia.device_id",
                            "network.protocol",
                        ],
                        "type": "best_fields",
                    }
                }
            )
        body = {
            "from": max(0, offset),
            "size": max(1, min(limit, 100)),
            "track_total_hits": True,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": must, "filter": filters}},
            "_source": [
                "@timestamp",
                "event.id",
                "event.kind",
                "event.action",
                "event.severity",
                "event.dataset",
                "source.ip",
                "source.geo.country_name",
                "source.geo.country_iso_code",
                "destination.port",
                "network.protocol",
                "dystopia.device_id",
                "dystopia.segment_id",
            ],
        }
        result = self._search(self.config.index, body)
        hits = result.get("hits", {})
        items = []
        for hit in hits.get("hits", []):
            source = hit.get("_source", {})
            event = source.get("event", {}) if isinstance(source, dict) else {}
            src = source.get("source", {}) if isinstance(source, dict) else {}
            geo = src.get("geo", {}) if isinstance(src, dict) else {}
            network = source.get("network", {}) if isinstance(source, dict) else {}
            dystopia = source.get("dystopia", {}) if isinstance(source, dict) else {}
            items.append(
                {
                    "id": event.get("id") or hit.get("_id", ""),
                    "timestamp": source.get("@timestamp"),
                    "sensor": str(event.get("dataset") or "").removeprefix("deception."),
                    "device": dystopia.get("device_id") or "",
                    "source": src.get("ip") or "",
                    "country": geo.get("country_name") or "",
                    "countryCode": geo.get("country_iso_code") or "",
                    "kind": event.get("kind") or "",
                    "proto": network.get("protocol") or "",
                    "port": source.get("destination", {}).get("port") if isinstance(source.get("destination"), dict) else None,
                    "action": event.get("action") or "",
                    "severity": _severity(event.get("severity")),
                    "message": "Evento normalizado de deception-events",
                }
            )
        total = hits.get("total", {})
        return {"total": int(total.get("value", 0) or 0) if isinstance(total, dict) else int(total or 0), "items": items}

    def health(self) -> dict[str, Any]:
        # The analyst role has read + view_index_metadata, not cluster monitor.
        # A bounded search is the least-privilege health signal.
        result = self._search(
            self.config.index,
            {"size": 0, "track_total_hits": True, "query": {"match_all": {}}},
        )
        total = int(result.get("hits", {}).get("total", {}).get("value", 0) or 0)
        shards = result.get("_shards", {}) if isinstance(result.get("_shards"), dict) else {}
        failed = int(shards.get("failed", 0) or 0)
        return {
            "status": "healthy" if failed == 0 else "degraded",
            "index": self.config.index,
            "documents": total,
            "failed_shards": failed,
        }


_service: AnalyticsService | None = None


def service() -> AnalyticsService:
    global _service
    if _service is None:
        _service = AnalyticsService()
    return _service
