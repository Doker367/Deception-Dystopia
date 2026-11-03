"""Unit tests for the configurable, idempotent Elasticsearch publisher.

No Elasticsearch, HTTP socket or network is used: the transport is injected.
"""

import logging
import sys
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.services.deception.integrations.elastic_svc import (
    DocumentConflict,
    ElasticPublisher,
    ElasticsearchConfig,
    PublisherDisabled,
    _HttpTransport,
)
from runtime.storage import CapacityError


def document(name="event-one", **changes):
    body = {
        "@timestamp": "2026-09-24T10:00:00Z",
        "event": {"id": str(uuid5(NAMESPACE_URL, "dystopia-test/" + name)), "kind": "event"},
        "observer": {"name": "cowrie"},
    }
    body.update(changes)
    return body


def config(tmp_path=None, **changes):
    values = {
        "enabled": True,
        "url": "https://127.0.0.1:9200",
        "index": "deception-events",
        "queue_path": (tmp_path / "elastic-queue.db") if tmp_path is not None else None,
        "max_retries": 0,
        "backoff": 0.0,
        "max_backoff": 0.0,
    }
    values.update(changes)
    return ElasticsearchConfig(**values)


class FakeTransport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []
        self.credentials_changed = False

    def index(self, event_id, document, timeout):
        self.calls.append({"id": event_id, "document": document, "timeout": timeout})
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response

    def reload_api_key(self):
        return self.credentials_changed


def test_disabled_by_default_and_never_confirms_delivery():
    assert ElasticsearchConfig.from_env({}).enabled is False
    publisher = ElasticPublisher(
        ElasticsearchConfig.from_env({}), transport=FakeTransport(201),
    )
    assert publisher.health()["enabled"] is False
    with pytest.raises(PublisherDisabled):
        publisher.publish(document())


def test_invalid_configuration_fails_closed():
    invalid = [
        {"url": ""},
        {"url": "http://203.0.113.10:9200"},
        {"url": "https://elastic.example:9200"},
        {"url": "https://user:secret@127.0.0.1:9200"},
        {"url": "https://127.0.0.1:9200", "index": "UPPER-CASE"},
        {"url": "https://127.0.0.1:9200", "index": "_hidden"},
        {"url": "https://127.0.0.1:9200", "timeout": 0},
    ]
    for values in invalid:
        with pytest.raises(ValueError):
            config(**values).validate()


def test_from_env_is_opt_in_and_reads_no_secret_value():
    cfg = ElasticsearchConfig.from_env({
        "DYSTOPIA_ELASTIC_ENABLED": "true",
        "DYSTOPIA_ELASTIC_URL": "https://127.0.0.1:9200",
        "DYSTOPIA_ELASTIC_INDEX": "dystopia-events-v1",
        "DYSTOPIA_ELASTIC_QUEUE": "/var/lib/dystopia/control/elastic-queue.db",
        "DYSTOPIA_ELASTIC_RETRIES": "2",
    }).validate()
    assert cfg.enabled is True
    assert cfg.index == "dystopia-events-v1"
    assert str(cfg.queue_path).endswith("elastic-queue.db")
    assert cfg.max_retries == 2


def test_ack_only_after_2xx_and_uses_event_id(tmp_path):
    transport = FakeTransport(201)
    publisher = ElasticPublisher(config(tmp_path), transport=transport, sleep=lambda _: None)
    event = document()
    assert publisher.publish(event) is True
    assert transport.calls[0]["id"] == event["event"]["id"]
    assert transport.calls[0]["timeout"] == 5.0
    health = publisher.health()
    assert health["acked_since_start"] == 1
    assert health["queued"] == 0
    assert health["operator_action_required"] is False


def test_bounded_retries_then_ack(tmp_path):
    transport = FakeTransport(500, 503, 201)
    sleeps = []
    publisher = ElasticPublisher(
        config(tmp_path, max_retries=2, backoff=0.25, max_backoff=1.0),
        transport=transport, sleep=sleeps.append,
    )
    assert publisher.publish(document()) is True
    assert [call["id"] for call in transport.calls] == [document()["event"]["id"]] * 3
    assert sleeps == [0.25, 0.5]
    health = publisher.health()
    assert health["acked_since_start"] == 1
    assert health["retries_since_start"] == 2
    assert health["errors_since_start"] == 2


def test_permanent_rejection_is_kept_and_flagged(tmp_path):
    transport = FakeTransport(400)
    publisher = ElasticPublisher(config(tmp_path), transport=transport, sleep=lambda _: None)
    assert publisher.publish(document()) is False
    assert len(transport.calls) == 1
    health = publisher.health()
    assert health["acked_since_start"] == 0
    assert health["queued"] == 1
    assert health["permanent"] == 1
    assert health["operator_action_required"] is True
    assert health["permanent_failures_since_start"] == 1
    # Quarantined rows are not retried forever.
    assert publisher.flush() == 0
    assert publisher.publish(document()) is False
    assert len(transport.calls) == 1


def test_permanent_rows_do_not_consume_the_live_queue_budget(tmp_path):
    transport = FakeTransport(400, 201)
    publisher = ElasticPublisher(
        config(tmp_path, max_events=1, dead_letter_events=4),
        transport=transport, sleep=lambda _: None,
    )
    assert publisher.publish(document("permanent-one")) is False
    health = publisher.health()
    assert health["live"] == 0
    assert health["permanent"] == 1
    assert health["queued"] == 1

    # The single live slot is free even though a permanent row is retained.
    assert publisher.publish(document("healthy-two")) is True
    health = publisher.health()
    assert health["live"] == 0
    assert health["permanent"] == 1
    assert health["queued"] == 1
    assert health["operator_action_required"] is True


def test_dead_letter_budget_evicts_oldest_and_counts_the_loss(tmp_path):
    transport = FakeTransport(400, 400, 201)
    publisher = ElasticPublisher(
        config(tmp_path, max_events=4, dead_letter_events=1),
        transport=transport, sleep=lambda _: None,
    )
    assert publisher.publish(document("oldest")) is False
    assert publisher.health()["permanent"] == 1
    assert publisher.publish(document("newest")) is False
    health = publisher.health()
    assert health["permanent"] == 1
    assert health["dead_letter_evicted_since_start"] == 1
    assert health["dead_letter_capacity"] == 1
    # Live data still flows after the bounded dead-letter eviction.
    assert publisher.publish(document("healthy")) is True
    assert publisher.health()["live"] == 0


def test_auth_failure_is_retryable_and_does_not_consume_permanent_budget(tmp_path):
    transport = FakeTransport(401, 401, 401)
    publisher = ElasticPublisher(
        config(tmp_path, max_retries=0), transport=transport, sleep=lambda _: None,
    )
    for name in ("one", "two", "three"):
        assert publisher.enqueue(document(name)) is True
    assert publisher.flush() == 0
    # A flush pauses on the first 401 instead of replaying the same bad key.
    assert len(transport.calls) == 1
    health = publisher.health()
    assert health["permanent"] == 0
    assert health["auth_blocked"] == 1
    assert health["live"] == 3
    assert health["operator_action_required"] is True


def test_auth_failure_retries_after_controlled_key_rotation(tmp_path):
    transport = FakeTransport(401)
    publisher = ElasticPublisher(
        config(tmp_path, max_retries=2), transport=transport, sleep=lambda _: None,
    )
    assert publisher.enqueue(document()) is True
    assert publisher.flush() == 0
    assert publisher.health()["auth_blocked"] == 1
    assert publisher.health()["permanent"] == 0

    # Operator rotates the key file: the next attempt sees a changed key and
    # is allowed to retry without a process restart or a permanent entry.
    transport.responses = [401, 201]
    transport.credentials_changed = True
    assert publisher.flush() == 1
    health = publisher.health()
    assert health["auth_blocked"] == 0
    assert health["permanent"] == 0
    assert health["queued"] == 0
    assert health["credential_reloads_since_start"] == 1


def test_transport_reloads_a_rotated_api_key(tmp_path):
    key_file = tmp_path / "elastic-key"
    key_file.write_text("synthetic-key-one", encoding="ascii")
    key_file.chmod(0o600)
    cfg = config(url="https://192.0.2.10:9200", api_key_file=key_file)
    transport = _HttpTransport(cfg)
    assert transport._api_key == "synthetic-key-one"
    assert transport.reload_api_key() is False
    key_file.write_text("synthetic-key-two", encoding="ascii")
    key_file.chmod(0o600)
    assert transport.reload_api_key() is True
    assert transport._api_key == "synthetic-key-two"


def test_dead_letter_can_be_exported_and_purged(tmp_path):
    publisher = ElasticPublisher(
        config(tmp_path, max_events=4, dead_letter_events=4),
        transport=FakeTransport(400, 400), sleep=lambda _: None,
    )
    assert publisher.publish(document("rejected-one")) is False
    assert publisher.publish(document("rejected-two")) is False
    assert publisher.health()["permanent"] == 2

    output = tmp_path / "dead-letter.jsonl"
    assert publisher.export_dead_letter(output) == 2
    lines = output.read_text().splitlines()
    assert len(lines) == 2
    assert publisher.health()["permanent"] == 2  # export is non-destructive

    assert publisher.purge_dead_letter() == 2
    health = publisher.health()
    assert health["permanent"] == 0
    assert health["queued"] == 0
    assert health["operator_action_required"] is False


def test_409_create_conflict_is_deduplicated_not_counted_as_2xx(tmp_path):
    publisher = ElasticPublisher(config(tmp_path), transport=FakeTransport(409))
    assert publisher.publish(document()) is True
    health = publisher.health()
    assert health["duplicates_since_start"] == 1
    assert health["acked_since_start"] == 0
    assert health["queued"] == 0


def test_transport_failure_keeps_event_and_does_not_confirm(tmp_path):
    transport = FakeTransport(OSError("offline"), OSError("offline"))
    publisher = ElasticPublisher(
        config(tmp_path, max_retries=1), transport=transport, sleep=lambda _: None,
    )
    assert publisher.publish(document()) is False
    assert len(transport.calls) == 2
    health = publisher.health()
    assert health["queued"] == 1
    assert health["acked_since_start"] == 0
    assert health["errors_since_start"] == 2
    assert health["retries_since_start"] == 1


def test_persistent_queue_survives_a_new_publisher(tmp_path):
    cfg = config(tmp_path)
    first = ElasticPublisher(cfg, transport=FakeTransport(OSError("down")), sleep=lambda _: None)
    assert first.publish(document()) is False
    assert first.health()["queued"] == 1

    second = ElasticPublisher(cfg, transport=FakeTransport(201))
    assert second.flush() == 1
    assert second.health()["queued"] == 0
    assert second.health()["acked_since_start"] == 1


def test_bounded_queue_rejects_new_event_and_reports_discard():
    publisher = ElasticPublisher(
        config(max_events=1, max_bytes=1024 * 1024), transport=FakeTransport(),
    )
    assert publisher.enqueue(document("one")) is True
    with pytest.raises(CapacityError):
        publisher.enqueue(document("two"))
    health = publisher.health()
    assert health["queued"] == 1
    assert health["discarded_since_start"] == 1


def test_duplicate_enqueue_is_idempotent_but_content_conflict_is_not():
    publisher = ElasticPublisher(config(), transport=FakeTransport())
    assert publisher.enqueue(document("same")) is True
    assert publisher.enqueue(document("same")) is False
    conflicting = document("same")
    conflicting["@timestamp"] = "2026-09-24T10:00:01Z"
    with pytest.raises(DocumentConflict):
        publisher.enqueue(conflicting)
    assert publisher.health()["conflicts_since_start"] == 1


def test_api_key_must_come_from_a_private_file(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    key_file = tmp_path / "elastic-api-key"
    key_file.write_text("synthetic-api-key-value", encoding="ascii")
    key_file.chmod(0o600)
    cfg = config(
        url="https://192.0.2.10:9200", api_key_file=key_file,
    )
    publisher = ElasticPublisher(cfg)
    assert publisher.enabled is True
    assert publisher._transport._api_key == "synthetic-api-key-value"
    assert "synthetic-api-key-value" not in caplog.text

    key_file.chmod(0o644)
    with pytest.raises(PermissionError):
        ElasticPublisher(cfg)
    assert "synthetic-api-key-value" not in caplog.text


def test_health_reports_lag_and_never_logs_payload(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    now = [1000.0]
    publisher = ElasticPublisher(
        config(tmp_path, max_events=1), transport=FakeTransport(),
        clock=lambda: now[0],
    )
    event = document("lag")
    event["dystopia"] = {"decoy_credentials": {"password": "SYNTHETIC-SECRET"}}
    assert publisher.enqueue(event) is True
    now[0] = 1030.0
    health = publisher.health()
    assert health["lag_seconds"] == 30.0
    with pytest.raises(CapacityError):
        publisher.enqueue(document("other"))
    assert "SYNTHETIC-SECRET" not in caplog.text
    assert "payload" not in caplog.text


def test_default_index_matches_the_deception_events_data_stream():
    assert ElasticsearchConfig.from_env({}).index == "deception-events"


class _FakeResponse:
    status = 201

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, _size):
        return b"{}"


class _FakeOpener:
    def __init__(self):
        self.request = None
        self.timeout = None

    def open(self, request, timeout):
        self.request, self.timeout = request, timeout
        return _FakeResponse()


def test_transport_uses_create_endpoint_and_event_id():
    transport = _HttpTransport(config())
    transport.opener = _FakeOpener()
    assert transport.index("abc-123", {"event": {"id": "abc-123"}}, timeout=2.5) == 201
    assert "/deception-events/_create/abc-123" in transport.opener.request.full_url
    assert "op_type=create" not in transport.opener.request.full_url
    assert transport.opener.timeout == 2.5
