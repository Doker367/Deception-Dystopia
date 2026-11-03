"""Offline tests for the log collector: declared sources, tail offsets, rotation."""
import json
from pathlib import Path
import shutil

import pytest

from runtime.logreader import (
    LogReader,
    LogReaderError,
    Source,
    Sources,
    _map_log_path,
    resolve_sources,
)
from runtime.honeypots import load_inventory


def test_inventory_resolves_six_declared_sources(inventory_path):
    reader = resolve_sources(inventory_path)
    engines = [s.engine for s in reader.sources.sources]
    assert engines == ["cowrie", "opencanary", "dionaea", "heralding", "redishoneypot", "endlessh"]
    assert {s.device_id for s in reader.sources.sources} == {"srv-files-01", "sw-access-01", "srv-db-01", "fw-edge-01"}
    for source in reader.sources.sources:
        assert Path(source.path).is_file()
        assert source.format in {"jsonl", "text"}


def test_map_log_path_uses_the_declared_volume_mapping(inventory_path):
    inventory = load_inventory(inventory_path)
    cell_root = "/var/lib/dystopia/honeypots/cells/1"
    cowrie = inventory.engines["cowrie"]
    assert _map_log_path(cell_root, cowrie.log_path, cowrie.volumes) \
        == cell_root + "/cowrie/var/log/cowrie/cowrie.json"
    opencanary = inventory.engines["opencanary"]
    assert _map_log_path(cell_root, opencanary.log_path, opencanary.volumes) \
        == cell_root + "/opencanary/log/opencanary.log"
    with pytest.raises(LogReaderError):
        # Not nested in any declared volume: never guess a host path.
        _map_log_path(cell_root, "/etc/shadow", cowrie.volumes)


def test_map_log_path_blocks_traversal_and_bad_volumes():
    with pytest.raises(LogReaderError):
        _map_log_path("/root", "../../etc/passwd")
    with pytest.raises(LogReaderError):
        _map_log_path("/root", "relative/log")
    with pytest.raises(LogReaderError):
        _map_log_path("/root", "/var/log/app.log", [("../escape", "/var/log")])
    with pytest.raises(LogReaderError):
        _map_log_path("/root", "/var/log/app.log", [("logs", "relative")])


def test_from_inventory_maps_a_cell_root_without_opening_files(inventory_path):
    sources = Sources.from_inventory(inventory_path, data_root="/srv/dystopia", cell=3)
    by_engine = {source.engine: source for source in sources.sources}
    assert by_engine["cowrie"].path \
        == "/srv/dystopia/cells/3/cowrie/var/log/cowrie/cowrie.json"
    assert by_engine["endlessh"].path \
        == "/srv/dystopia/cells/3/endlessh/log/endlessh.log"
    with pytest.raises(LogReaderError):
        Sources.from_inventory(inventory_path, data_root="/srv/dystopia", cell=0)


def test_reader_tails_a_rendered_cell_layout(inventory_path, tmp_path):
    inventory = load_inventory(inventory_path)
    cell_root = tmp_path / "cells" / "7"
    for engine in inventory.engines.values():
        target = Path(_map_log_path(cell_root, engine.log_path, engine.volumes))
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(inventory.base / engine.fixture, target)
    records = resolve_sources(inventory_path, data_root=cell_root).step()
    assert len(records) == 23
    assert {record[0] for record in records} == set(inventory.engines)


def test_step_reads_fixtures_then_stops(inventory_path):
    reader = resolve_sources(inventory_path)
    first = reader.step()
    assert len(first) == 23  # 5+3+3+2+5 cowrie/opencanary/dionaea/heralding/redis + 5 endlessh
    assert reader.step() == []  # cursor advanced; no re-emission


def test_step_emits_engine_device_and_raw_record(inventory_path):
    reader = resolve_sources(inventory_path)
    records = reader.step()
    cowrie = [r for r in records if r[0] == "cowrie"]
    assert cowrie and cowrie[0][1] == "srv-files-01" and cowrie[0][2] == "jsonl"
    assert isinstance(cowrie[0][3], dict)
    endlessh = [r for r in records if r[0] == "endlessh"]
    assert endlessh and endlessh[0][2] == "text"
    assert isinstance(endlessh[0][3], str)


def test_text_tail_partial_line_is_held_back(tmp_path):
    log = tmp_path / "endlessh.log"
    first = b"2026-10-28T21:19:00.123456Z ACCEPT host=203.0.113.44 port=1 fd=1 n=1\n"
    log.write_bytes(first)
    reader = LogReader(Sources([Source("endlessh", str(log), "text", "fw-edge-01")]))
    assert len(reader.step()) == 1
    assert reader.health()["sources"][0]["offset"] == len(first)
    # Append a line without a trailing newline: nothing complete to emit yet.
    with open(log, "ab") as stream:
        stream.write(b"2026-10-28T21:19:12.000000Z ACCEPT host=198.51.100.7 port=2 fd=2 n=2")
    assert reader.step() == []
    # Several polls without a newline must not move the cursor backwards or
    # re-emit the first line.
    assert reader.step() == []
    assert reader.health()["sources"][0]["offset"] == len(first)
    with open(log, "ab") as stream:
        stream.write(b"\n")
    records = reader.step()
    assert len(records) == 1 and "198.51.100.7" in records[0][3]


def test_rotation_restarts_from_beginning(tmp_path):
    log = tmp_path / "cowrie.jsonl"
    log.write_text('{"eventid":"cowrie.session.connect","src_ip":"203.0.113.9","src_port":1}\n', encoding="utf-8")
    reader = LogReader(Sources([Source("cowrie", str(log), "jsonl", "srv-files-01")]))
    assert len(reader.step()) == 1
    # copytruncate: same inode, size shrank below the cursor -> restart.
    with open(log, "w", encoding="utf-8") as stream:
        stream.write('{"a":1}\n')
    assert len(reader.step()) == 1
    # rename + recreate: new inode -> restart from the top of the new file.
    rotated = tmp_path / "cowrie.jsonl.1"
    log.rename(rotated)
    log.write_text('{"eventid":"cowrie.session.connect","src_ip":"203.0.113.9","src_port":3}\n', encoding="utf-8")
    assert len(reader.step()) == 1


def test_invalid_jsonl_is_an_error_not_a_skip(tmp_path):
    log = tmp_path / "bad.jsonl"
    log.write_text('{"eventid":"x"}\nNOT JSON\n', encoding="utf-8")
    reader = LogReader(Sources([Source("cowrie", str(log), "jsonl", "srv-files-01")]))
    # The malformed line is an operator-visible error, never silently dropped.
    with pytest.raises(LogReaderError):
        reader.step()


def test_collect_keeps_records_from_healthy_sources(tmp_path):
    good = tmp_path / "cowrie.jsonl"
    good.write_text('{"eventid":"cowrie.session.connect","src_ip":"203.0.113.9"}\n',
                    encoding="utf-8")
    bad = tmp_path / "opencanary.jsonl"
    bad.write_text("NOT JSON\n", encoding="utf-8")
    reader = LogReader(Sources([
        Source("cowrie", str(good), "jsonl", "srv-files-01"),
        Source("opencanary", str(bad), "jsonl", "sw-access-01"),
    ]))
    records, errors = reader.collect()
    assert [record[0] for record in records] == ["cowrie"]
    assert errors == [{"engine": "opencanary", "error": errors[0]["error"]}]
    assert "invalid JSONL" in errors[0]["error"]
    assert reader.health()["sources"][1]["errors"] == 1
    # The malformed line was consumed and counted; the next poll is clean.
    assert reader.collect() == ([], [])
    # The strict API still fails loudly for callers that opt into it.
    with pytest.raises(LogReaderError):
        LogReader(Sources([Source("opencanary", str(bad), "jsonl", "sw-access-01")])).step()


def test_line_bound_applies_without_a_newline(tmp_path):
    log = tmp_path / "endlessh.log"
    log.write_bytes(b"x" * 17)
    reader = LogReader(Sources([Source("endlessh", str(log), "text", "fw-edge-01")]),
                       max_line_bytes=16)
    records, errors = reader.collect()
    assert records == []
    assert "unterminated line exceeds 16 bytes" in errors[0]["error"]
    assert reader.health()["sources"][0]["offset"] == 17
    assert reader.collect() == ([], [])  # not stuck on the same bytes


def test_missing_or_symlink_log_is_rejected(tmp_path):
    reader = LogReader(Sources([Source("cowrie", str(tmp_path / "absent.jsonl"), "jsonl", "srv-files-01")]))
    with pytest.raises(LogReaderError):
        reader.step()
    link = tmp_path / "link.jsonl"
    link.symlink_to(tmp_path / "target.jsonl")
    reader = LogReader(Sources([Source("cowrie", str(link), "jsonl", "srv-files-01")]))
    with pytest.raises(LogReaderError):
        reader.step()


def test_duplicate_or_unknown_engine_sources_are_rejected(tmp_path):
    source = Source("cowrie", str(tmp_path / "a.jsonl"), "jsonl", "srv-files-01")
    with pytest.raises(LogReaderError):
        Sources([source, source])
    with pytest.raises(LogReaderError):
        Sources([])
    with pytest.raises(LogReaderError):
        Source("cowrie", str(tmp_path / "a.jsonl"), "xml", "srv-files-01")


def test_health_reports_offsets_without_payloads(inventory_path):
    reader = resolve_sources(inventory_path)
    reader.step()
    health = reader.health()
    assert len(health["sources"]) == 6
    assert all("offset" in s and s["offset"] > 0 for s in health["sources"])
    assert "payload" not in json.dumps(health)


def test_inventory_loader_still_accepts_declared_logs(inventory_path):
    inventory = load_inventory(inventory_path)
    for engine in inventory.engines.values():
        assert engine.log_path.startswith("/")
        assert engine.log_format in {"jsonl", "text"}
        assert engine.device_id
