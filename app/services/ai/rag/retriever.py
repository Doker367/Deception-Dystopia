"""Recuperación híbrida: FTS5 + similitud semántica fusionadas con RRF.

Si el servidor de embeddings no está disponible, la búsqueda sigue siendo
léxica y se marca ``degraded``. Nunca se inventan fragmentos.
"""

from __future__ import annotations

import sqlite3
from typing import Optional, Sequence

from app.core import settings
from app.services.ai.rag import store
from app.services.ai.rag import vectors as vec_utils
from app.services.ai.rag.errors import RagUnavailable
from app.services.ai.rag.rerank import rerank, signal_weights

RRF_K = 60


def _rerank_enabled() -> bool:
    """Reranking determinista activado por env (defecto: true)."""
    return bool(getattr(settings, "RAG_RERANK_ENABLED", True))


def search(
    query: str,
    *,
    conn: sqlite3.Connection,
    embedder,
    k: Optional[int] = None,
    candidates: Optional[int] = None,
    kinds: Optional[Sequence[str]] = None,
    src_ip: Optional[str] = None,
    min_similarity: Optional[float] = None,
    max_per_doc: Optional[int] = None,
) -> dict:
    """Devuelve los fragmentos más relevantes con su procedencia."""
    query = (query or "").strip()
    if not query:
        return {"query": "", "mode": "empty", "results": [], "degraded": False}

    k = settings.RAG_TOP_K if k is None else max(1, min(k, 50))
    candidates = settings.RAG_CANDIDATES if candidates is None else max(k, candidates)
    min_similarity = settings.RAG_MIN_SCORE if min_similarity is None else min_similarity
    max_per_doc = settings.RAG_MAX_PER_DOC if max_per_doc is None else max_per_doc

    degraded = False
    embed_error: Optional[str] = None
    vector_hits: list[tuple[int, float]] = []
    if embedder is None:
        degraded = True
        embed_error = "embedder no disponible (None): degradación léxica"
    else:
        try:
            query_vector, _ = vec_utils.normalize(embedder.embed([query])[0])
            vector_hits = store.vector_search(
                conn, query_vector, limit=candidates, kinds=kinds, src_ip=src_ip,
                max_vectors=settings.RAG_MAX_VECTORS,
            )
        except RagUnavailable as exc:
            degraded = True
            embed_error = str(exc)

    keyword_hits = store.keyword_search(
        conn, query, limit=candidates, kinds=kinds, src_ip=src_ip
    )

    fused: dict[int, float] = {}
    similarity: dict[int, float] = {}
    matched: dict[int, set[str]] = {}
    keyword_rank: dict[int, int] = {}

    for rank, (chunk_id, score) in enumerate(vector_hits):
        fused[chunk_id] = fused.get(chunk_id, 0.0) + 1.0 / (RRF_K + rank + 1)
        similarity[chunk_id] = score
        matched.setdefault(chunk_id, set()).add("vector")
    for rank, (chunk_id, _bm25) in enumerate(keyword_hits):
        fused[chunk_id] = fused.get(chunk_id, 0.0) + 1.0 / (RRF_K + rank + 1)
        matched.setdefault(chunk_id, set()).add("keyword")
        keyword_rank[chunk_id] = rank

    ordered = sorted(fused.items(), key=lambda item: (-item[1], item[0]))
    selected: list[tuple[int, float]] = []
    per_doc: dict[str, int] = {}
    for chunk_id, score in ordered:
        sim = similarity.get(chunk_id)
        keyword_top = keyword_rank.get(chunk_id, 999) <= 2
        if sim is not None and sim < min_similarity and not keyword_top:
            continue
        selected.append((chunk_id, score))
        if len(selected) >= k * 3:
            break

    # El límite por documento se aplica tras recuperar metadatos.
    rows = store.fetch_chunks(conn, [chunk_id for chunk_id, _ in selected])
    results: list[dict] = []
    for chunk_id, score in selected:
        chunk = rows.get(chunk_id)
        if not chunk:
            continue
        used = per_doc.get(chunk["doc_key"], 0)
        if used >= max_per_doc:
            continue
        per_doc[chunk["doc_key"]] = used + 1
        results.append({
            **chunk,
            "score": round(score, 6),
            "similarity": round(similarity[chunk_id], 4) if chunk_id in similarity else None,
            "matched_by": sorted(matched.get(chunk_id, set())),
        })
        if len(results) >= k:
            break

    if _rerank_enabled() and results:
        try:
            rerank(results, query, signal_weights())
        except Exception as exc:  # pragma: no cover - defensa barata
            embed_error = embed_error or f"rerank falló: {str(exc)[:120]}"
            results.sort(key=lambda item: (-float(item["score"]), item["chunk_id"]))

    mode = "keyword" if degraded else "hybrid"
    return {
        "query": query,
        "mode": mode + ("+rerank" if (_rerank_enabled() and results) else ""),
        "degraded": degraded,
        "error": embed_error,
        "results": results,
    }
