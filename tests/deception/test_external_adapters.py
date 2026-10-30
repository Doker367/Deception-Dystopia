"""Contract tests for external honeypot adapters (Cowrie, OpenCanary, ...).

All fixtures are inline and synthetic. No service, honeypot, network or
Elasticsearch instance is contacted.
"""

import json
import logging
import sys
from pathlib import Path
from uuid import UUID

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.services.deception.integrations import adapters
from app.services.deception.integrations import cowrie_svc, opencanary_svc
from app.services.deception.integrations.ecs import StaticMetadata
from app.services.deception.integrations.pipeline import HoneypotPipeline


def assert_contract(document):
    assert isinstance(document, dict)
    assert set(document) >= {
        "@timestamp", "event", "observer", "network", "dystopia",
    }
    assert document["@timestamp"].endswith("Z")
    assert UUID(document["event"]["id"])
    assert document["event"]["kind"] in {"event", "alert", "signal"}
    assert isinstance(document["event"]["category"], list) and document["event"]["category"]
    assert isinstance(document["event"]["type"], list) and document["event"]["type"]
    assert isinstance(document["event"]["action"], str) and document["event"]["action"]
    assert isinstance(document["event"]["severity"], int)
    assert document["observer"]["type"] == "honeypot"
    assert document["observer"]["name"]
    assert document["observer"]["product"]
    assert document["network"]["transport"] in {"tcp", "udp"}
    assert document["network"]["protocol"]
    assert document["dystopia"]["schema_version"] == 1
    assert document["dystopia"]["device_id"]
    assert document["dystopia"]["segment_id"]
    assert document["dystopia"]["instance_id"]
    assert isinstance(document["dystopia"]["decoy_credentials"], str)
    assert isinstance(document["dystopia"]["raw_reference"], str)
    assert "sha256=" in document["dystopia"]["raw_reference"]
    allowed = {
        "schema_version", "device_id", "segment_id", "instance_id",
        "ingest_source", "persona", "decoy_credentials", "raw_reference",
    }
    assert set(document["dystopia"]) <= allowed


SAMPLES = {
    "cowrie": {
        "eventid": "cowrie.login.failed", "timestamp": "2026-09-24T10:00:00Z",
        "src_ip": "203.0.113.9", "src_port": 41234,
        "dst_ip": "10.40.0.11", "dst_port": 22,
        "username": "root", "password": "SENSITIVE-PASSWORD-FIXTURE",
        "session": "cowrie-s1",
    },
    "opencanary": {
        "src_host": "198.51.100.7", "src_port": 55000, "dst_host": "10.40.0.11",
        "dst_port": 80, "logtype": 3000, "msg": "GET /admin HTTP/1.1",
        "utc_time": "2026-09-24 10:00:00",
    },
    "dionaea": {
        "timestamp": "2026-09-24T10:00:00Z", "src_ip": "203.0.113.9",
        "src_port": 50000, "dst_ip": "10.40.0.11", "dst_port": 445,
        "protocol": "smbd", "connection": "accept",
        "url": "http://203.0.113.9/payload.exe", "md5_hash": "d41d8cd98f00b204",
    },
    "heralding": {
        "timestamp": "2026-09-24T10:00:00Z", "src_ip": "203.0.113.9",
        "src_port": 50000, "dst_ip": "10.40.0.11", "dst_port": 21,
        "protocol": "ftp", "username": "anonymous", "password": "guest@example",
    },
    "redishoneypot": {
        "timestamp": "2026-09-24T10:00:00Z", "src_ip": "203.0.113.9",
        "src_port": 50000, "dst_ip": "10.40.0.11",
        "command": "CONFIG", "args": ["GET", "*"], "session": "redis-s1",
    },
    "endlessh": "2026/09/24 10:00:00 203.0.113.9:41234 connected",
}


@pytest.mark.parametrize("sensor", list(SAMPLES))
def test_every_adapter_emits_the_common_contract(sensor):
    document = adapters.normalize(sensor, SAMPLES[sensor], default_device="decoy-a")
    assert_contract(document)
    assert document["observer"]["name"] == sensor
    assert document["dystopia"]["device_id"] == "decoy-a"


def test_registry_covers_all_required_sensors():
    assert {
        "cowrie", "opencanary", "dionaea", "heralding", "redishoneypot", "endlessh",
    } <= set(adapters.supported())
    with pytest.raises(ValueError):
        adapters.normalize("not-a-honeypot", {})


def test_unknown_device_and_absent_geoip_are_not_dropped():
    resolver = StaticMetadata(devices={"known-device": {"id": "known-device", "segment": "vlan-1"}})
    document = adapters.normalize(
        "cowrie", SAMPLES["cowrie"], default_device="ghost-device", resolver=resolver,
    )
    assert document["dystopia"]["device_id"] == "ghost-device"
    assert document["dystopia"]["segment_id"] == "unknown"
    assert document["observer"]["name"] == "cowrie"
    assert "geo" not in document["source"]

    no_source = adapters.normalize("endlessh", "unparseable sensor line", default_device="x")
    assert_contract(no_source)
    assert no_source["event"]["action"] == "other"
    assert no_source["dystopia_restricted"]["payload"]["message"] == "unparseable sensor line"


def test_injected_topology_and_geoip_enrich_without_importing_topology():
    resolver = StaticMetadata(
        devices={
            "cam-entrada-01": {
                "id": "cam-entrada-01", "segment": "vlan-camaras",
                "ip": "10.30.0.11",
                "persona": {
                    "vendor": "hikvision", "os": "linux",
                    "hostname": "cam-entrada", "mac": "00:12:5a:00:00:11",
                },
            },
        },
        segments={"vlan-camaras": {"id": "vlan-camaras", "cidr": "10.30.0.0/24"}},
        geo_map={
            "198.51.100.7": {
                "country_code": "US", "country": "United States",
                "city": "Ashburn", "subdivision": "Virginia",
                "lat": 39.0438, "lon": -77.4874,
            },
        },
    )
    raw = dict(SAMPLES["opencanary"])
    raw.pop("dst_host")
    document = adapters.normalize(
        "opencanary", raw, default_device="cam-entrada-01", resolver=resolver,
    )
    assert document["dystopia"]["device_id"] == "cam-entrada-01"
    assert document["dystopia"]["segment_id"] == "vlan-camaras"
    assert "vendor=hikvision" in document["dystopia"]["persona"]
    assert document["destination"]["ip"] == "10.30.0.11"
    assert document["source"]["geo"]["country_iso_code"] == "US"
    assert document["source"]["geo"]["location"] == {"lat": 39.0438, "lon": -77.4874}


def test_event_id_is_stable_and_content_sensitive():
    first = adapters.normalize("cowrie", SAMPLES["cowrie"], default_device="srv-1")
    reordered = dict(reversed(list(SAMPLES["cowrie"].items())))
    second = adapters.normalize("cowrie", reordered, default_device="srv-1")
    changed = dict(SAMPLES["cowrie"], src_port=41235)
    third = adapters.normalize("cowrie", changed, default_device="srv-1")
    assert first["event"]["id"] == second["event"]["id"]
    assert first["event"]["id"] != third["event"]["id"]


def test_captured_secrets_and_payloads_stay_in_restricted_fields(caplog):
    caplog.set_level(logging.DEBUG)
    document = adapters.normalize(
        "cowrie", SAMPLES["cowrie"], default_device="srv-1",
    )
    serialized = json.dumps(document)
    # The live credential reference exposes captured values in-process; JSON
    # (and therefore Elasticsearch/logs) contains only a non-secret identifier.
    assert document["dystopia"]["decoy_credentials"].get("password") == "SENSITIVE-PASSWORD-FIXTURE"
    assert "SENSITIVE-PASSWORD-FIXTURE" not in serialized
    assert "password" not in document["event"]
    assert "password" not in document["observer"]
    assert "SENSITIVE-PASSWORD-FIXTURE" not in document["dystopia"]["raw_reference"]
    assert "SENSITIVE-PASSWORD-FIXTURE" not in caplog.text

    command = adapters.normalize(
        "redishoneypot", SAMPLES["redishoneypot"], default_device="redis-1",
    )
    assert command["dystopia_restricted"]["payload"]["command"] == "CONFIG GET *"
    assert "payload" not in command["dystopia"]


def test_protocol_aliases_and_actions_are_normalised():
    dionaea = adapters.normalize("dionaea", SAMPLES["dionaea"], default_device="fs-1")
    assert dionaea["network"]["protocol"] == "smb"
    assert dionaea["event"]["action"] == "file_download"
    assert dionaea["event"]["severity"] == 5
    assert dionaea["dystopia_restricted"]["payload"]["md5"]

    redis = adapters.normalize("redishoneypot", SAMPLES["redishoneypot"], default_device="r-1")
    assert redis["event"]["action"] == "command"
    assert redis["network"]["protocol"] == "redis"

    endlessh = adapters.normalize("endlessh", SAMPLES["endlessh"], default_device="tarpit-1")
    assert endlessh["event"]["action"] == "network_connection"
    assert endlessh["network"]["protocol"] == "ssh"
    assert endlessh["source"]["ip"] == "203.0.113.9"
    assert endlessh["source"]["port"] == 41234


def test_legacy_parsers_remain_compatible():
    parsed = cowrie_svc.parse(SAMPLES["cowrie"], "srv-files-01")
    assert parsed["event_type"] == "login_attempt"
    assert parsed["detail"]["password"] == "SENSITIVE-PASSWORD-FIXTURE"
    assert opencanary_svc.parse(SAMPLES["opencanary"], "sw-1")["proto"] == "http"


def test_cowrie_uuid_eventid_uses_message_and_topology():
    from uuid import uuid4

    resolver = StaticMetadata(
        devices={
            "srv-files-01": {
                "id": "srv-files-01", "segment": "seg-lab-edge",
                "ip": "192.0.2.10", "persona": "linux-file-server",
            },
        },
        segments={"seg-lab-edge": {"id": "seg-lab-edge", "vlan": 110}},
    )
    raw = {
        "eventid": str(uuid4()), "timestamp": "2026-10-29T10:05:02Z",
        "src_ip": "203.0.113.9", "src_port": 45124,
        "dst_ip": "192.0.2.10", "dst_port": 22,
        "session": "c0ffee123456", "protocol": "ssh",
        "message": "cowrie.login.failed",
        "username": "root", "password": "SENSITIVE-PASSWORD-FIXTURE",
    }
    document = cowrie_svc.normalize(
        raw, resolver=resolver, instance_id="cell-lab-01",
        default_device="srv-files-01",
    )
    assert document["event"]["action"] == "login"
    assert document["event"]["outcome"] == "failure"
    assert document["dystopia"]["device_id"] == "srv-files-01"
    assert document["dystopia"]["segment_id"] == "seg-lab-edge"
    assert document["dystopia"]["instance_id"] == "cell-lab-01"
    assert document["dystopia"]["persona"] == "linux-file-server"
    assert document["destination"]["ip"] == "192.0.2.10"
    assert document["dystopia"]["decoy_credentials"].get("password") == (
        "SENSITIVE-PASSWORD-FIXTURE"
    )


def test_pipeline_normalizes_and_reports_confirmed_delivery():
    class Publisher:
        def __init__(self):
            self.documents = []

        def publish(self, document):
            self.documents.append(document)
            return True

    publisher = Publisher()
    pipeline = HoneypotPipeline(
        publisher=publisher,
        resolver=StaticMetadata(devices={"srv-1": {"id": "srv-1", "segment": "seg-1"}}),
        instance_id="cell-1",
        default_device="srv-1",
    )
    document, delivered = pipeline.ingest("cowrie", SAMPLES["cowrie"])
    assert delivered is True
    assert publisher.documents == [document]
    assert document["dystopia"]["segment_id"] == "seg-1"
    assert document["dystopia"]["instance_id"] == "cell-1"
