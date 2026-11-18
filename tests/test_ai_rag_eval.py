"""Tests del harness de evaluación del RAG (scripts/eval_rag.py).

El harness debe ser determinista (misma semilla, mismos corpus y gold) y sus
métricas consistentes: recall@8 y citation_hit@1 dentro de [0, 1] y el modo
``rerank`` nunca peor que el baseline RRF en el corpus sintético.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

REPO = Path(__file__).resolve().parent.parent
EVAL_PATH = REPO / "scripts" / "eval_rag.py"


@pytest.fixture(scope="module")
def eval_module():
    spec = importlib.util.spec_from_file_location("eval_rag", EVAL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_eval_module_importa_y_casos_completos(eval_module):
    """15 casos en 6 categorías del dominio y corpus con 8+ documentos."""
    categories = {case[0] for case in eval_module.CASES}
    assert len(eval_module.CASES) >= 15
    assert categories == {
        "ataques_ip", "credenciales", "mitre", "dispositivos",
        "movimiento_lateral", "puertos",
    }
    assert len(eval_module._EVENT_BODIES) >= 8
    golds = {case[2] for case in eval_module.CASES}
    assert golds <= set(eval_module._EVENT_BODIES), "gold debe existir en corpus"


def test_eval_inicializa_corrupto_o_exacto(eval_module, tmp_path):
    """Dos índices con la misma semilla producen mismos chunk_ids."""
    emb = eval_module.FakeEmbedder(dim=64)
    one = eval_module.build_index(tmp_path / "one.db", chunks=60, embedder=emb)
    other = eval_module.build_index(tmp_path / "two.db", chunks=60, embedder=emb)
    ids_one = [row[0] for row in one.execute("SELECT id FROM rag_chunks ORDER BY id")]
    ids_other = [row[0] for row in other.execute("SELECT id FROM rag_chunks ORDER BY id")]
    assert ids_one == ids_other
    one.close()
    other.close()


def test_eval_metricas_y_mejora_rerank(eval_module, tmp_path):
    """El conjunto rerank no empeora recall@8 y mejora hit@1 en este corpus."""
    emb = eval_module.FakeEmbedder(dim=eval_module.DIM_FAKE)
    conn = eval_module.build_index(tmp_path / "quality.db",
                                   chunks=eval_module.CHUNKS, embedder=emb)
    try:
        baseline = eval_module.evaluate_metadata_with_rerank(
            conn, emb, rerank=False)
        rerank = eval_module.evaluate_metadata_with_rerank(conn, emb, rerank=True)
    finally:
        conn.close()
        eval_module.settings.RAG_RERANK_ENABLED = False
    assert 0.0 <= baseline["recall@8"] <= 1.0
    assert 0.0 <= rerank["recall@8"] <= 1.0
    assert rerank["recall@8"] >= baseline["recall@8"] - 0.001
    assert rerank["citation_hit@1"] >= baseline["citation_hit@1"]
    assert rerank["mode"] == "rerank" and baseline["mode"] == "rrf"


def test_eval_real_db_si_existe(eval_module):
    """Con la base real indexada (43 docs), el recall doc-level se mide."""
    if not eval_module.REAL_DB.is_file():
        pytest.skip("sin base real deception/rag.db")
    emb = eval_module.FakeEmbedder(dim=eval_module.DIM_FAKE)
    report = eval_module.evaluate_real_db(emb, rerank=False)
    assert report["questions"] == len(eval_module.REAL_CASES)
    assert report["docs"] >= 40
    assert 0.0 <= report["doc_recall@8"] <= 1.0


def test_eval_salida_json_con_perf(eval_module, tmp_path, monkeypatch):
    """--perf Produce latencias p50/p95 y keys esperadas (corpus acotado)."""
    monkeypatch.setattr(eval_module, "PERF_CHUNKS", 400)
    out = tmp_path / "perf.json"
    monkeypatch.setattr(sys, "argv", ["eval_rag.py", "--perf",
                                      "--chunks", "60", "--out", str(out)])
    code = eval_module.main()
    assert code == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["latencies"] is not None
    assert report["latencies"]["corpus_chunks"] >= 400
    for key in ("keyword_p50_ms", "vector_p50_ms", "hybrid_rrf_p50_ms"):
        assert key in report["latencies"]
