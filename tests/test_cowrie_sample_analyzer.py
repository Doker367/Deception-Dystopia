"""Offline tests for the passive Cowrie sample analyzer."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "analyze_cowrie_samples.py"


def _load_analyzer():
    spec = importlib.util.spec_from_file_location("analyze_cowrie_samples", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_sample_path_never_escapes_downloads_root(tmp_path):
    analyzer = _load_analyzer()
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"not a sample")
    (downloads / "evil").symlink_to(outside)

    assert analyzer.safe_sample_path(downloads, "var/lib/cowrie/downloads/abc") == downloads / "abc"
    assert analyzer.safe_sample_path(downloads, "..") is None
    assert analyzer.safe_sample_path(downloads, "evil") is None
    assert analyzer.safe_sample_path(downloads, None) is None


def test_inspect_sample_hashes_without_execution(tmp_path, monkeypatch):
    analyzer = _load_analyzer()
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    payload = b"MZ" + b"\x00" * 126 + b"fixture"
    sample = downloads / "sample"
    sample.write_bytes(payload)
    monkeypatch.setattr(analyzer.shutil, "which", lambda _name: None)

    event = {
        "outfile": "var/lib/cowrie/downloads/sample",
        "shasum": hashlib.sha256(payload).hexdigest(),
        "session": "session-1",
        "src_ip": "203.0.113.9",
        "url": "http://198.51.100.20/sample",
    }
    result = analyzer.inspect_sample(downloads, event)
    assert result["status"] == "ok"
    assert result["size"] == len(payload)
    assert result["sha256"] == hashlib.sha256(payload).hexdigest()
    assert result["md5"] == hashlib.md5(payload).hexdigest()
    assert result["magic"] == "pe"
    assert result["hash_matches_event"] is True


def test_build_report_reads_only_download_events(tmp_path, monkeypatch):
    analyzer = _load_analyzer()
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    payload = b"#!/bin/sh\necho defensive-fixture\n"
    (downloads / "script").write_bytes(payload)
    log = tmp_path / "cowrie.json"
    records = [
        {"eventid": "cowrie.command.input", "input": "whoami"},
        {
            "eventid": "cowrie.session.file_download",
            "outfile": "var/lib/cowrie/downloads/script",
            "shasum": hashlib.sha256(payload).hexdigest(),
        },
    ]
    log.write_text("\n".join(json.dumps(row) for row in records) + "\n", encoding="utf-8")
    monkeypatch.setattr(analyzer.shutil, "which", lambda _name: None)

    report = analyzer.build_report(log, downloads)
    assert report["download_events"] == 1
    assert report["samples"][0]["status"] == "ok"
    assert report["samples"][0]["magic"] == "script"
