"""Offline tests of the continuous SQLite collector: offsets, dedupe, rotation.

No real honeypot files are involved: every test synthesizes temporary logs in
tmp_path and points the collector at them. The SQLite sink is
``app.services.deception.store_svc`` with ``DB_PATH`` monkeypatched to a
scratch database, following the same offline discipline as the rest of the
runtime data-plane tests.
"""
import json
from pathlib import Path

import pytest

from app.services.deception import store_svc
from runtime.collector import Collector
from runtime.logreader import LogReader, Source, Sources

COWRIE_CONNECT = {"eventid": "cowrie.session.connect", "src_ip": "203.0.113.9",
                  "src_port": 40001, "timestamp": "2026-10-28T21:14:03Z"}
COWRIE_LOGIN = {"eventid": "cowrie.login.failed", "src_ip": "203.0.113.9",
                "username": "root", "password": "demo-password",
                "timestamp": "2026-10-28T21:14:10Z"}

ENDLESSH_TOTALS = "2026-10-28T21:14:03Z TOTALS: 0 connects, 12182 ms idle"


@pytest.fixture
def db(monkeypatch, tmp_path):
    monkeypatch.setattr(store_svc, "DB_PATH", tmp_path / "deception.db")
    return store_svc


def cowrie_record(raw: dict) -> str:
    return json.dumps(raw, sort_keys=True) + "\n"


def make_collector(log: Path, ledger: Path, db, **kwargs) -> Collector:
    reader = LogReader(Sources([Source("cowrie", str(log), "jsonl", "srv-files-01")]))
    return Collector(reader, ledger, store=db, **kwargs)


def test_poll_ingests_and_persists_the_byte_offset(db, tmp_path):
    log = tmp_path / "cowrie.jsonl"
    log.write_text(cowrie_record(COWRIE_CONNECT) + cowrie_record(COWRIE_LOGIN),
                   encoding="utf-8")
    ledger = tmp_path / "ledger.json"
    collector = make_collector(log, ledger, db)

    result = collector.poll_once()
    assert result["ingested"] == 2
    assert collector.ingested == 2
    assert len(db.get_events(limit=10)) == 2

    stored = {e["type"]: e for e in db.get_events(limit=10)}
    assert stored["login_attempt"]["username"] == "root"
    assert stored["login_attempt"]["success"] is False
    detail = stored["login_attempt"]["detail"]
    assert detail["engine"] == "cowrie"
    assert len(detail["source_event_id"]) == 64  # huella SHA-256 estable

    # El offset queda en disco, exactamente al final del fichero.
    state = json.loads(ledger.read_text(encoding="utf-8"))
    assert state["cursors"]["cowrie"]["offset"] == log.stat().st_size


def test_poll_after_no_new_data_and_ledger_restore_does_not_reingest(db, tmp_path):
    log = tmp_path / "cowrie.jsonl"
    log.write_text(cowrie_record(COWRIE_CONNECT), encoding="utf-8")
    ledger = tmp_path / "ledger.json"
    first = make_collector(log, ledger, db)
    first.poll_once()

    # Poll repetido sobre ficheros sin cambios: nada nuevo.
    assert first.poll_once()["ingested"] == 0

    # Restauración desde el ledger: una instancia nueva reanuda el offset.
    log.write_text(cowrie_record(COWRIE_CONNECT) + cowrie_record(COWRIE_LOGIN),
                   encoding="utf-8")
    second = make_collector(log, ledger, db)
    result = second.poll_once()
    assert result["ingested"] == 1  # solo la línea añadida
    assert len(db.get_events(limit=10)) == 2


def test_reprocessing_with_reset_offsets_does_not_duplicate(db, tmp_path):
    log = tmp_path / "cowrie.jsonl"
    log.write_text(cowrie_record(COWRIE_CONNECT) + cowrie_record(COWRIE_LOGIN),
                   encoding="utf-8")
    ledger = tmp_path / "ledger.json"
    make_collector(log, ledger, db).poll_once()
    assert db.get_events(limit=10).__len__() == 2

    # Offsets perdidos (¿otro arranque, ledger borrado?): releer desde 0 NO
    # duplica — la búsqueda por lotes contra la base de datos reconoce las
    # huellas ya guardadas.
    fresh = make_collector(log, tmp_path / "other-ledger.json", db)
    result = fresh.poll_once()
    assert result["ingested"] == 0
    assert result["duplicated"] == 2
    assert len(db.get_events(limit=10)) == 2


def test_in_memory_ring_duplicates_within_the_same_poll(db, tmp_path):
    log = tmp_path / "cowrie.jsonl"
    line = cowrie_record(COWRIE_CONNECT)
    log.write_text(line + line, encoding="utf-8")
    result = make_collector(log, tmp_path / "ledger.json", db).poll_once()
    assert result["ingested"] == 1
    assert result["duplicated"] == 1
    assert len(db.get_events(limit=10)) == 1


def test_dedupe_window_is_bounded(db, tmp_path):
    log = tmp_path / "cowrie.jsonl"
    log.write_text(cowrie_record(COWRIE_CONNECT), encoding="utf-8")
    collector = make_collector(log, tmp_path / "ledger.json", db, dedupe_window=2)
    collector.poll_once()
    assert len(collector._seen) == 1
    for port in (40002, 40003, 40004):
        with open(log, "a", encoding="utf-8") as stream:
            stream.write(cowrie_record({**COWRIE_CONNECT, "src_port": port}))
        collector.poll_once()
    assert len(collector._seen) == 2  # nunca crece más allá de la ventana
    assert collector.ingested == 4    # cada línea nueva sí entró


def test_file_rotation_resets_the_offset(db, tmp_path):
    log = tmp_path / "cowrie.jsonl"
    log.write_text(cowrie_record(COWRIE_CONNECT), encoding="utf-8")
    collector = make_collector(log, tmp_path / "ledger.json", db)
    collector.poll_once()

    # Rotación estilo Windows/unlink+recreate: inodo nuevo, el lector reinicia.
    log.unlink()
    log.write_text(cowrie_record({**COWRIE_CONNECT, "src_port": 40099}),
                   encoding="utf-8")
    result = collector.poll_once()
    assert result["ingested"] == 1
    assert collector.health()["reader"]["sources"][0]["offset"] == log.stat().st_size


def test_truncation_resets_the_offset_and_keeps_ingesting(db, tmp_path):
    log = tmp_path / "cowrie.jsonl"
    log.write_text(cowrie_record(COWRIE_CONNECT), encoding="utf-8")
    collector = make_collector(log, tmp_path / "ledger.json", db)
    assert collector.poll_once()["ingested"] == 1

    # copytruncate: el path sigue, el tamaño cae por debajo del offset.
    log.write_text("", encoding="utf-8")
    assert collector.poll_once()["ingested"] == 0

    log.write_text(cowrie_record(COWRIE_LOGIN), encoding="utf-8")
    assert collector.poll_once()["ingested"] == 1
    assert len(db.get_events(limit=10)) == 2  # 1 del inicio + 1 tras rotar


def test_malformed_lines_are_skipped_and_the_loop_survives(db, tmp_path):
    log = tmp_path / "cowrie.jsonl"
    log.write_text("{not json at all\n", encoding="utf-8")
    collector = make_collector(log, tmp_path / "ledger.json", db)
    result = collector.poll_once()  # no raises
    assert result["read_errors"] == 1
    assert result["ingested"] == 0

    # copytruncate tras la línea rota: el offset se reinicia con un poll vacío
    # y el bucle sigue vivo: datos nuevos se procesan con normalidad.
    log.write_text("", encoding="utf-8")
    collector.poll_once()
    log.write_text(cowrie_record(COWRIE_LOGIN), encoding="utf-8")
    assert collector.poll_once()["ingested"] == 1
    assert len(db.get_events(limit=10)) == 1


def test_records_without_a_usable_source_fail_counted_not_fatal(db, tmp_path):
    log = tmp_path / "cowrie.jsonl"
    log.write_text(
        # JSON válido pero sin src_ip canónico: NormalizeError
        cowrie_record({"eventid": "cowrie.session.connect", "timestamp": "2026-10-28T21:14:03Z"})
        # tras él, un registro sano del mismo poll se procesa igual
        + cowrie_record(COWRIE_CONNECT),
        encoding="utf-8")
    collector = make_collector(log, tmp_path / "ledger.json", db)
    result = collector.poll_once()
    assert result["failed"] == 1
    assert result["ingested"] == 1  # el registro sano del mismo chunk no se pierde

    log.write_text(cowrie_record(COWRIE_LOGIN), encoding="utf-8")
    assert collector.poll_once()["ingested"] == 1


def test_endlessh_totals_lines_are_skipped_not_stored(db, tmp_path):
    reader = LogReader(Sources([Source("endlessh", str(tmp_path / "endlessh.log"),
                                       "text", "fw-edge-01")]))
    (tmp_path / "endlessh.log").write_text(ENDLESSH_TOTALS + "\n", encoding="utf-8")
    collector = Collector(reader, tmp_path / "ledger.json", store=db)
    result = collector.poll_once()
    assert result["skipped"] == 1
    assert result["ingested"] == 0
    assert db.get_events(limit=10) == []


def test_unknown_event_type_degrades_to_other(db, tmp_path):
    log = tmp_path / "cowrie.jsonl"
    # ``cowrie.session.closed`` normaliza a ``disconnect``, que no existe en
    # el enum del control plane: degrada a OTHER, nunca se descarta.
    log.write_text(
        cowrie_record({"eventid": "cowrie.session.closed", "src_ip": "203.0.113.9",
                       "timestamp": "2026-10-28T21:14:20Z"}),
        encoding="utf-8")
    make_collector(log, tmp_path / "ledger.json", db).poll_once()
    events = db.get_events(limit=10)
    assert len(events) == 1
    assert events[0]["type"] == "other"


def test_health_reports_counters_and_ledger(db, tmp_path):
    log = tmp_path / "cowrie.jsonl"
    log.write_text(cowrie_record(COWRIE_CONNECT), encoding="utf-8")
    ledger = tmp_path / "ledger.json"
    collector = make_collector(log, ledger, db)
    collector.poll_once()
    health = collector.health()
    assert health["ingested"] == 1
    assert health["ledger"]["path"] == str(ledger)
    assert len(health["reader"]["sources"]) == 1
    assert health["reader"]["sources"][0]["device_id"] == "srv-files-01"


def test_stop_signals_terminate_run_forever(db, tmp_path):
    log = tmp_path / "cowrie.jsonl"
    log.write_text(cowrie_record(COWRIE_CONNECT), encoding="utf-8")
    collector = make_collector(log, tmp_path / "ledger.json", db, poll_interval=0.01)
    result = {}
    collector.poll_once()

    import threading
    timer = threading.Timer(0.05, collector.stop)
    timer.start()
    result = collector.run_forever(interval=0.01)
    timer.join()
    assert result["ingested"] == 1


# ── Revisión GPT: offsets en SQLite, heartbeat, dead-letter, atomicidad ──


def test_default_offset_store_is_sqlite_and_resumes(db, tmp_path):
    log = tmp_path / "cowrie.jsonl"
    log.write_text(cowrie_record(COWRIE_CONNECT), encoding="utf-8")
    reader = LogReader(Sources([Source("cowrie", str(log), "jsonl", "srv-files-01")]))

    first = Collector(reader, store=db)
    assert first.health()["offset_store"] == "SqliteOffsetStore"
    assert first.poll_once()["ingested"] == 1

    # Otra instancia (sin ledger JSON) reanuda desde la tabla de offsets.
    reader2 = LogReader(Sources([Source("cowrie", str(log), "jsonl", "srv-files-01")]))
    second = Collector(reader2, store=db)
    assert second.poll_once()["ingested"] == 0
    assert len(db.get_events(limit=10)) == 1


def test_poll_writes_heartbeat_and_reports_active_collector(db, tmp_path):
    log = tmp_path / "cowrie.jsonl"
    log.write_text(cowrie_record(COWRIE_CONNECT), encoding="utf-8")
    collector = make_collector(log, tmp_path / "ledger.json", db)
    collector.poll_once()

    health = collector.health()
    assert health["db_heartbeat"]["status"] == "ok"
    assert health["db_heartbeat"]["polls"] == 1
    assert db.get_collector_health()["status"] == "ok"


def test_malformed_line_goes_to_dead_letters(db, tmp_path):
    log = tmp_path / "cowrie.jsonl"
    log.write_text(json.dumps({"eventid": "cowrie.login.failed"}) + "\n",
                   encoding="utf-8")
    collector = make_collector(log, tmp_path / "ledger.json", db)
    result = collector.poll_once()

    assert result["failed"] == 1
    assert collector.dead_letters == 1
    with db._connect() as conn:
        rows = conn.execute(
            "SELECT engine, error FROM collector_dead_letters").fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "cowrie"
    assert rows[0][1].startswith("NormalizeError")


def test_batch_failure_does_not_advance_offsets(db, tmp_path, monkeypatch):
    log = tmp_path / "cowrie.jsonl"
    log.write_text(cowrie_record(COWRIE_CONNECT), encoding="utf-8")
    collector = make_collector(log, tmp_path / "ledger.json", db)
    original = db.log_events_batch

    def boom(*_args, **_kwargs):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(db, "log_events_batch", boom)
    result = collector.poll_once()
    assert result["failed"] == 1
    assert db.get_events(limit=10) == []
    db._ensure_db()
    with db._connect() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM collector_offsets").fetchone()[0] == 0

    monkeypatch.setattr(db, "log_events_batch", original)
    assert collector.poll_once()["ingested"] == 1
    assert len(db.get_events(limit=10)) == 1
