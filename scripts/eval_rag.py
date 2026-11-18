#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Evaluacion de calidad del RAG: recall@k y citas correctas (corpus sintetico)."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
import sqlite3
import math
import random
import hashlib
import re

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core import settings
from app.services.ai.rag import store
from app.services.ai.rag.retriever import search as rag_search

SEED = 20261115
DIM_FAKE = 128
PERF_DIM = 1024
TOP_K = 8
CHUNKS = 200
PERF_CHUNKS = 10000
REPEATS = 5


CASES = [
    # (categoria, consulta, doc_key gold del corpus sintetico)
    ("ataques_ip", "que ataques de fuerza bruta ssh hubo",
     "event:203.0.113.9:2026-11-15T03"),
    ("ataques_ip", "exploit CVE camara Hikvision webapp",
     "event:203.0.113.9:2026-11-15T08"),
    ("ataques_ip", "escaneo masivo con masscan en la subred",
     "event:198.51.100.23:2026-11-15T20"),
    ("credenciales", "que contrasena de fabrica uso la camara",
     "event:203.0.113.9:2026-11-15T08"),
    ("credenciales", "credenciales capturadas en cam-cam01",
     "event:203.0.113.9:2026-11-15T08"),
    ("mitre", "que tecnica mitre aplica a la fuerza bruta ssh",
     "event:203.0.113.9:2026-11-15T03"),
    ("mitre", "que mitre describe el escaneo de puertos",
     "event:198.51.100.23:2026-11-15T20"),
    ("mitre", "tecnica mitre explotacion de aplicacion publica",
     "event:203.0.113.9:2026-11-15T08"),
    ("dispositivos", "que senuelo imita una camara hikvision",
     "device:cam-cam01"),
    ("dispositivos", "que senuelo simula un router mikrotik winbox",
     "device:rtr-mikrotik"),
    ("movimiento_lateral", "hubo movimiento lateral con pass the hash",
     "event:45.148.10.77:2026-11-16T13"),
    ("movimiento_lateral", "pivoteo smb desde srv-backup al router",
     "event:45.148.10.77:2026-11-16T13"),
    ("puertos", "que protocolo industrial corre en el puerto 502",
     "event:45.148.10.77:2026-11-16T21"),
    ("puertos", "que puertos expone winbox de mikrotik",
     "device:rtr-mikrotik"),
    ("puertos", "escaneo con sesiones VNC y RDP abiertas",
     "event:198.51.100.23:2026-11-15T20"),
]

_EVENT_BODIES = {
    "event:203.0.113.9:2026-11-15T03":
        "Fuerza bruta SSH contra el router de control: 412 intentos con"
        " hydra y diccionario rockyou; usuarios probados admin y root;"
        " tecnica MITRE T1110 (fuerza bruta de credenciales).",
    "event:203.0.113.9:2026-11-15T08":
        "Camara cama-cam01 Hikvision: exploit CVE-2021-36260 en /webapp/"
        " con credenciales de fabrica; tecnica MITRE T1190 (explotacion"
        " de aplicacion publica).",
    "event:198.51.100.23:2026-11-15T20":
        "Escaneo masivo de puertos con masscan en la subred industrial:"
        " respondieron 22, 23, 80, 445, 3389, 5900 y 8291; sesiones VNC"
        " y RDP; tecnica MITRE T1046 (descubrimiento de servicios).",
    "event:45.148.10.77:2026-11-16T13":
        "Movimiento lateral con pass the hash desde srv-backup hacia el"
        " router MikroTik; pivoteo SMB y credenciales compartidas; NTLM.",
    "event:192.42.116.15:2026-11-17T09":
        "Nevera inteligente iot-fridge: credenciales UPnP por defecto y"
        " camara interna; panel industrial sin contrasena.",
    "event:203.0.113.9:2026-11-16T21":
        "Sesion interactiva en cam-cam02: comandos id y uname -a; el"
        " atacante uso credenciales de fabrica en la cama-cam02.",
    "event:45.148.10.77:2026-11-16T21":
        "Protocolo Modbus TCP en el puerto 502 del PLC industrial; sin"
        " autenticacion ni cifrado; escrituras maliciosas en bombas.",
    "device:cam-cam01":
        "Dispositivo senuelo cam-cam01: camara IP Hikvision con firmware"
        " v5.55 y credenciales de fabrica; CVE-2021-36260 en /webapp/.",
    "device:rtr-mikrotik":
        "Dispositivo senuelo rtr-mikrotik: RouterOS 6.44 con Winbox en el"
        " puerto 8291 y ssh en el 22; credenciales admin compartidas.",
}

class FakeEmbedder:
    """Bolsa de palabras con hash; determinista y sin servicios."""

    def __init__(self, dim: int = DIM_FAKE) -> None:
        self.dim = dim

    def embed(self, texts):
        out = []
        for text in texts:
            vec = [0.0] * self.dim
            for token in re.findall(r"[^\W_]+", (text or "").lower()):
                digest = int(hashlib.sha256(token.encode("utf-8")).hexdigest(), 16)
                vec[digest % self.dim] += 1.0
            norm = math.sqrt(sum(v * v for v in vec)) or 1.0
            out.append([v / norm for v in vec])
        return out


def build_index(db_path: Path, *, chunks: int, embedder) -> sqlite3.Connection:
    conn = store.connect(db_path)
    for doc_key, body in _EVENT_BODIES.items():
        if doc_key.startswith("device:"):
            piece = {
                "doc_key": doc_key, "kind": "device", "source": doc_key[7:],
                "src_ip": None, "ts": None,
                "text": body, "heading": doc_key[7:],
            }
        else:
            ip, ts = doc_key[6:].split(":")[0], doc_key.split(":")[-1]
            piece = {
                "doc_key": doc_key, "kind": "event", "source": "deception_events",
                "src_ip": ip or None, "ts": ts or None,
                "text": body, "heading": doc_key,
            }
        indexer_index_doc(conn, piece, embedder)
    vocab = ("ssh router camara camera mikrotik hikvision dahua vnc winbox"
             " masscan nmap hydra rockyou smb ntlm nthash modbus plc dnp3"
             " credenciales contrasena fabrica admin root ubuntu guest"
             " fuerza bruta lateral pivote escaneo puertos sesion").split()
    for offset in range(chunks - len(_EVENT_BODIES)):
        rng = random.Random(SEED + offset)
        text = "Bitacora operativa " + " ".join(rng.choice(vocab) for _ in range(18))
        piece = {
            "doc_key": f"filler:{offset}", "kind": "event", "source": "filler",
            "src_ip": None, "ts": "2026-01", "text": text, "heading": "bitacora",
        }
        indexer_index_doc(conn, piece, embedder)
    return conn


def indexer_index_doc(conn, piece, embedder) -> None:
    upsert = store.upsert_doc
    upsert(
        conn,
        doc_key=piece["doc_key"], kind=piece["kind"], source=piece["source"],
        src_ip=piece["src_ip"], ts=piece["ts"],
        chunks=[{"text": piece["text"], "heading": piece["heading"]}],
        embedder=embedder, meta={},
    )


def gold_chunk_for(case_doc_marker: str, conn: sqlite3.Connection):
    row = conn.execute(
        "SELECT c.id FROM rag_chunks c WHERE c.doc_key = ? LIMIT 1",
        (case_doc_marker,),
    ).fetchone()
    return row[0] if row else None


def evaluate_metadata_with_rerank(
    conn, embedder, *, rerank: bool, k: int = TOP_K,
) -> dict:
    """Calidad en corpus sintetico: recall@k, hit@1 (cita en gold), mrr."""
    previous = getattr(settings, "RAG_RERANK_ENABLED", False)
    settings.RAG_RERANK_ENABLED = rerank
    rows = []
    hits = top1 = 0
    reciprocal = 0.0
    for category, query, gold_doc in CASES:
        answer = rag_search(query, conn=conn, embedder=embedder, k=k)
        results = answer.get("results") or []
        chunk_ids = [int(item["chunk_id"]) for item in results]
        golds = _gold_ids_by_doc(conn, gold_doc)
        rank = next((pos for pos, cid in enumerate(chunk_ids, start=1)
                     if cid in golds), 0)
        rows.append({
            "category": category, "query": query,
            "gold_doc": gold_doc, "rank": rank,
            "top1": bool(rank == 1),
        })
        if rank:
            hits += 1
            reciprocal += 1.0 / rank
        if rank == 1:
            top1 += 1
    total = max(1, len(rows))
    out = {
        "questions": total,
        "recall@8": round(hits / total, 3),
        "citation_hit@1": round(top1 / total, 3),
        "mrr": round(reciprocal / total, 3),
        "mode": "rerank" if rerank else "rrf",
    }
    settings.RAG_RERANK_ENABLED = previous
    return out


def _gold_ids_by_doc(conn: sqlite3.Connection, doc_key: str) -> list[int]:
    """Chunk ids del doc_key gold (un documento, pocos fragmentos)."""
    out = []
    for row in conn.execute(
        "SELECT c.id FROM rag_chunks c JOIN rag_docs d ON d.id = c.doc_id"
        " WHERE d.doc_key = ? ORDER BY c.ord",
        (doc_key,),
    ):
        out.append(int(row[0]))
    return out


def perf_benchmark(tmp: Path, embedder) -> dict:
    """Latencias: keyword vs vector vs hibrida (RRF y rerank) a 10k trozos."""
    db_path = tmp / "perf-rag.db"
    conn = store.connect(db_path)
    stats = store.stats(conn)
    if stats.get("chunks") != PERF_CHUNKS:
        for doc_key, body in _EVENT_BODIES.items():
            piece = {
                "doc_key": doc_key, "kind": "event", "source": "deception_events",
                "src_ip": doc_key[6:].split(":")[0] or None,
                "ts": doc_key.split(":")[-1], "text": body, "heading": doc_key,
            }
            indexer_index_doc(conn, piece, embedder)
        vocab = ("ssh router camara camera mikrotik hikvision dahua vnc winbox"
                 " masscan nmap hydra rockyou smb ntlm nthash modbus plc dnp3"
                 " credenciales contrasena fabrica admin root ubuntu guest"
                 " fuerza bruta lateral pivote escaneo puertos sesion").split()
        for offset in range(PERF_CHUNKS - len(_EVENT_BODIES)):
            rng = random.Random(SEED + offset * 977)
            text = "Bitacora operativa " + " ".join(
                rng.choice(vocab) for _ in range(18))
            piece = {
                "doc_key": f"perf:{offset}", "kind": "event", "source": "filler",
                "src_ip": None, "ts": "2026-01", "text": text,
                "heading": "bitacora",
            }
            indexer_index_doc(conn, piece, embedder)
    stats = store.stats(conn)
    queries = [case[1] for case in CASES]
    timed = {"keyword": [], "vector": [], "hybrid_rrf": [], "hybrid_rerank": []}
    for repeat in range(REPEATS):
        for query in queries:
            start = time.perf_counter()
            _keyword_scoped(conn, query)
            timed["keyword"].append(time.perf_counter() - start)
            vec = embedder.embed([query])[0]
            start = time.perf_counter()
            _vector_scoped(conn, vec)
            timed["vector"].append(time.perf_counter() - start)
            settings.RAG_RERANK_ENABLED = False
            start = time.perf_counter()
            rag_search(query, conn=conn, embedder=embedder, k=TOP_K)
            timed["hybrid_rrf"].append(time.perf_counter() - start)
            settings.RAG_RERANK_ENABLED = True
            start = time.perf_counter()
            rag_search(query, conn=conn, embedder=embedder, k=TOP_K)
            timed["hybrid_rerank"].append(time.perf_counter() - start)
    settings.RAG_RERANK_ENABLED = False
    out = {"corpus_chunks": stats.get("chunks", 0)}
    for key in sorted(timed):
        times = sorted(timed[key])
        p50 = times[len(times) // 2]
        p95 = times[int(len(times) * 0.95) - 1]
        out[key + "_p50_ms"] = round(p50 * 1000, 2)
        out[key + "_p95_ms"] = round(p95 * 1000, 2)
    conn.close()
    return out


def _keyword_scoped(conn, query: str, limit: int = 40):
    return store.keyword_search(conn, query, limit=limit, kinds=None, src_ip=None)


def _vector_scoped(conn, vec, limit: int = 40):
    return store.vector_search(conn, vec, limit=limit, kinds=None, src_ip=None)


def main() -> int:
    """CLI: calidad y latencias del RAG, con baseline y rerank en un run."""
    import tempfile

    parser = argparse.ArgumentParser(description="Evaluacion de calidad del RAG")
    parser.add_argument("--chunks", type=int, default=CHUNKS)
    parser.add_argument("--k", type=int, default=TOP_K)
    parser.add_argument("--perf", action="store_true")
    parser.add_argument("--real", action="store_true")
    parser.add_argument("--out", default="reports/rag_eval/eval-quality.json")
    args = parser.parse_args()
    embedder = FakeEmbedder(dim=DIM_FAKE)
    tmp_root = Path(tempfile.mkdtemp(prefix="eval-rag-"))
    try:
        conn = build_index(tmp_root / "rag-quality.db",
                           chunks=args.chunks, embedder=embedder)
        baseline = evaluate_metadata_with_rerank(
            conn, embedder, rerank=False, k=args.k)
        after = evaluate_metadata_with_rerank(
            conn, embedder, rerank=True, k=args.k)
        conn.close()
        perf = None
        real = None
        if args.perf:
            perf = perf_benchmark(tmp_root, FakeEmbedder(dim=PERF_DIM))
        if args.real:
            real = {
                "baseline": evaluate_real_db(embedder, rerank=False, k=args.k),
                "rerank": evaluate_real_db(embedder, rerank=True, k=args.k),
            }
    finally:
        pass
    report = {
        "meta": {
            "seed": SEED, "chunks": args.chunks, "top_k": args.k,
            "embedder": "fake", "queries": len(CASES),
            "real_db": bool(args.real and real),
        },
        "baseline": baseline,
        "rerank": after,
        "latencies": perf,
        "real_db": real,
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0




# Base REAL (deception/rag.db): consultas de conocimiento con doc gold anotado.
# Solo se evaluan si la base existe; gold a nivel de documento (43 docs).
REAL_DB = Path(__file__).resolve().parents[1] / "deception" / "rag.db"

REAL_CASES = [
    ("MITRE ATT&CK fuerza bruta T1110", "doc:README.md"),
    ("monitor proactivo hallazgo triage", "doc:docs/AI-RAG.md"),
    ("notificaciones push ntfy sid", "doc:docs/AI-RAG.md"),
    ("configuración RAG min score top_k", "doc:docs/AI-RAG.md"),
    ("docker compose servicio", "doc:docs/fase3-netbox.md"),
    ("exportar evidencia CSV JSON", "doc:README.md"),
]


def evaluate_real_db(embedder, *, rerank: bool, k: int = TOP_K) -> dict:
    """Recall doc-level en la base real (si existe), con sus golds."""
    previous = getattr(settings, "RAG_RERANK_ENABLED", False)
    settings.RAG_RERANK_ENABLED = rerank
    if not REAL_DB.is_file():
        return {"note": "sin base real", "chunks": 0}
    conn = store.connect(REAL_DB)
    stats = store.stats(conn)
    hits = top1 = 0
    rows = []
    for query, gold_doc in REAL_CASES:
        answer = rag_search(query, conn=conn, embedder=embedder, k=k)
        doc_keys = [str(item.get("doc_key") or "") for item in answer.get("results") or []]
        rank = next((pos for pos, key in enumerate(doc_keys, start=1)
                     if key == gold_doc), 0)
        rows.append({"query": query, "gold_doc": gold_doc, "rank": rank,
                     "top1": bool(rank == 1)})
        if rank:
            hits += 1
        if rank == 1:
            top1 += 1
    conn.close()
    total = max(1, len(rows))
    settings.RAG_RERANK_ENABLED = previous
    return {
        "questions": total,
        "docs": stats.get("docs", 0),
        "chunks": stats.get("chunks", 0),
        "doc_recall@8": round(hits / total, 3),
        "doc_hit@1": round(top1 / total, 3),
        "rows": rows,
    }


if __name__ == "__main__":
    raise SystemExit(main())
