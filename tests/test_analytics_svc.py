"""Offline contract tests for the read-only analytics service."""

import pytest

from app.services import analytics_svc


def test_analytics_disabled_fails_closed():
    service = analytics_svc.AnalyticsService(analytics_svc.AnalyticsConfig())
    with pytest.raises(analytics_svc.AnalyticsDisabled):
        service.overview(None, None)


def test_analytics_config_rejects_credentials_in_url():
    config = analytics_svc.AnalyticsConfig(
        enabled=True,
        url="https://user:pass@127.0.0.1:9200",
    )
    with pytest.raises(ValueError):
        config.validate()


def test_analytics_config_rejects_plaintext_non_loopback():
    config = analytics_svc.AnalyticsConfig(
        enabled=True,
        url="http://192.0.2.10:9200",
        api_key_file=None,
    )
    with pytest.raises(ValueError):
        config.validate()


def test_origins_maps_geo_and_severity(monkeypatch):
    service = analytics_svc.AnalyticsService(
        analytics_svc.AnalyticsConfig(enabled=True, url="https://127.0.0.1:9200")
    )
    payload = {
        "aggregations": {
            "countries": {
                "buckets": [
                    {
                        "key": "CN",
                        "doc_count": 12,
                        "country_name": {"buckets": [{"key": "China"}]},
                        "city": {"buckets": [{"key": "Shanghai"}]},
                        "location": {
                            "hits": {
                                "hits": [
                                    {
                                        "_source": {
                                            "source": {
                                                "geo": {
                                                    "country_name": "China",
                                                    "city_name": "Shanghai",
                                                    "location": {"lat": 31.2, "lon": 121.4},
                                                }
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        "top_ip": {"buckets": [{"key": "203.0.113.7"}]},
                        "protocol": {"buckets": [{"key": "ssh"}]},
                        "dataset": {"buckets": [{"key": "deception.cowrie"}]},
                        "sources": {"value": 3},
                        "severity": {"value": 9},
                        "last_event": {"value_as_string": "2026-11-05T12:00:00.000Z"},
                    }
                ]
            }
        }
    }
    monkeypatch.setattr(service, "_search", lambda index, body: payload)
    result = service.origins("2026-11-05T00:00:00Z", "2026-11-05T23:59:59Z")
    origin = result["origins"][0]
    assert origin["country"] == "China"
    assert origin["city"] == "Shanghai"
    assert origin["lat"] == 31.2
    assert origin["lng"] == 121.4
    assert origin["severity"] == "critical"
    assert origin["uniqueSources"] == 3


def test_events_maps_ecs_document(monkeypatch):
    service = analytics_svc.AnalyticsService(
        analytics_svc.AnalyticsConfig(enabled=True, url="https://127.0.0.1:9200")
    )
    payload = {
        "hits": {
            "total": {"value": 1},
            "hits": [
                {
                    "_id": "abc",
                    "_source": {
                        "@timestamp": "2026-11-05T12:00:00.000Z",
                        "event": {
                            "id": "evt-1",
                            "kind": "event",
                            "action": "login",
                            "severity": 7,
                            "dataset": "deception.cowrie",
                        },
                        "source": {
                            "ip": "203.0.113.7",
                            "geo": {"country_name": "China", "country_iso_code": "CN"},
                        },
                        "destination": {"port": 22},
                        "network": {"protocol": "ssh"},
                        "dystopia": {"device_id": "srv-files-01"},
                    },
                }
            ],
        }
    }
    monkeypatch.setattr(service, "_search", lambda index, body: payload)
    result = service.events("2026-11-05T00:00:00Z", "2026-11-05T23:59:59Z")
    assert result["total"] == 1
    assert result["items"][0]["sensor"] == "cowrie"
    assert result["items"][0]["severity"] == "high"
    assert result["items"][0]["port"] == 22
    assert result["items"][0]["device"] == "srv-files-01"
