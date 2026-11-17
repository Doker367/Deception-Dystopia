"""Source/destination attribution must survive native-format differences.

The collector used to understand only ``src_ip``/``src_host``. Native records
that carried the peer in ``connection.remote_ip``, ``source.ip``, ``addr`` or
an Endlessh line were dropped or labelled with the decoy address.
"""

import pytest

from runtime.netfields import canonical_ip, find_destination, find_source
from runtime.normalize import NormalizeError, normalize_raw


@pytest.mark.parametrize(
    ("record", "expected_ip", "expected_port"),
    [
        ({"src_ip": "203.0.113.9", "src_port": 41234}, "203.0.113.9", 41234),
        ({"src_ip": "203.0.113.9:41234"}, "203.0.113.9", 41234),
        ({"src_host": "198.51.100.7"}, "198.51.100.7", None),
        ({"source_ip": "198.51.100.7", "source_port": 2222}, "198.51.100.7", 2222),
        ({"addr": "203.0.113.50:41234"}, "203.0.113.50", 41234),
        ({"addr": "[2001:db8::2]:6379"}, "2001:db8::2", 6379),
        ({"source": {"ip": "2001:db8::1", "port": 443}}, "2001:db8::1", 443),
        ({"source.ip": "192.0.2.5", "source.port": 1234}, "192.0.2.5", 1234),
        ({"connection": {"remote_ip": "198.51.100.7", "remote_port": 5555}},
         "198.51.100.7", 5555),
    ],
)
def test_source_is_found_in_several_spellings(record, expected_ip, expected_port):
    found = find_source(record)
    assert found is not None
    assert found.ip == expected_ip
    assert found.port == expected_port


def test_source_text_fallback_only_when_structure_is_absent():
    record = {"message": "connection accepted from 203.0.113.9 port 2222"}
    found = find_source(record)
    assert found is not None and found.ip == "203.0.113.9"


def test_opencanary_logdata_host_is_destination_not_source():
    # OpenCanary stores the decoy address in logdata.HOST. Treating it as the
    # source would invert the attribution and hide the real attacker.
    record = {"logdata": {"HOST": "10.40.0.11"}, "msg": "GET /admin HTTP/1.1"}
    assert find_source(record) is None


def test_destination_is_found_in_nested_and_text_forms():
    nested = {"connection": {"remote_ip": "198.51.100.7", "local_ip": "10.20.0.10",
                             "local_port": 2222}}
    found = find_destination(nested)
    assert found is not None and found.ip == "10.20.0.10" and found.port == 2222

    cowrie = {
        "src_ip": "203.0.113.9",
        "message": "New connection: 203.0.113.9:41234 (10.20.0.10:2222)",
    }
    found = find_destination(cowrie)
    assert found is not None and found.ip == "10.20.0.10" and found.port == 2222


def test_endlessh_message_does_not_become_a_destination():
    record = {"src_ip": "203.0.113.9", "message": "ACCEPT host=203.0.113.9 port=51422 fd=7"}
    assert find_destination(record) is None


def test_canonical_ip_handles_ports_zones_and_rejects_non_origins():
    assert canonical_ip("[2001:db8::1]:443") == "2001:db8::1"
    assert canonical_ip("1.2.3.4:22") == "1.2.3.4"
    assert canonical_ip("2001:db8::1:443") == "2001:db8::1:443"  # not a port
    assert canonical_ip("fe80::1%eth0") == "fe80::1"
    assert canonical_ip("0.0.0.0") is None
    assert canonical_ip("224.0.0.1") is None


def test_collector_accepts_nested_dionaea_connection_without_flat_aliases():
    raw = {
        "timestamp": "2026-10-28T21:15:01.112233",
        "connection": {
            "protocol": "smbd", "type": "accept",
            "remote_ip": "203.0.113.9", "remote_port": 49152,
            "local_ip": "10.20.0.10", "local_port": 445,
        },
    }
    event = normalize_raw("dionaea", "srv-files-01", raw)
    assert event is not None
    assert event["src_ip"] == "203.0.113.9"
    assert event["src_port"] == 49152
    assert event["dst_ip"] == "10.20.0.10"
    assert event["dst_port"] == 445


def test_collector_still_fails_closed_when_no_origin_exists():
    with pytest.raises(NormalizeError):
        normalize_raw("cowrie", "srv-files-01", {"eventid": "cowrie.session.connect"})
