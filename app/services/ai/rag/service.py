"""Fachada del RAG para el router y la CLI.

Concentra la configuración vigente, la apertura segura del índice y las
comprobaciones de compatibilidad del modelo de embeddings.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional, Sequence

from app.core import settings
from app.services.ai.rag import answer, indexer, retriever, store
from app.services.ai.rag.embedding import get_embedder
from app.services.ai.rag.errors import RagDisabled, RagNotIndexed, RagUnavailable
from app.services.ai.rag.llm import get_llm


def is_enabled() -> bool:
    return bool(settings.RAG_ENABLED)


def status() -> dict:
    """Estado barato (sin llamar a los modelos) para diagnóstico."""
    path = Path(settings.RAG_DB)
    out: dict = {
        "enabled": is_enabled(),
        "db": str(path),
        "indexed": False,
        "embed": {
            "url": settings.RAG_EMBED_URL,
            "model": settings.RAG_EMBED_MODEL,
            "dim": settings.RAG_EMBED_DIM,
        },
        "llm": {
            "url": settings.RAG_LLM_URL,
            "model": settings.RAG_LLM_MODEL,
            "disable_thinking": settings.RAG_LLM_DISABLE_THINKING,
        },
        "limits": {
            "top_k": settings.RAG_TOP_K,
            "min_score": settings.RAG_MIN_SCORE,
            "context_chars": settings.RAG_CONTEXT_CHARS,
            "max_vectors": settings.RAG_MAX_VECTORS,
            "event_days": settings.RAG_EVENT_DAYS,
        },
        "monitor": {
            "enabled": settings.RAG_MONITOR_ENABLED,
            "window_min": settings.RAG_MONITOR_WINDOW_MIN,
            "min_events": settings.RAG_MONITOR_MIN_EVENTS,
            "min_confidence": settings.RAG_MONITOR_MIN_CONFIDENCE,
            "cooldown_min": settings.RAG_MONITOR_COOLDOWN_MIN,
        },
        "privacy": {"include_payload": settings.RAG_INCLUDE_PAYLOAD},
    }
    if not path.is_file():
        return out
    try:
        conn = store.connect(path)
        try:
            out["indexed"] = True
            out.update(store.stats(conn))
            out["embedding_match"] = _embedding_matches(conn)
            out["monitor"]["last_scan"] = store.meta_get(conn, "monitor_last_scan")
        finally:
            conn.close()
    except sqlite3.Error as exc:
        out["error"] = str(exc)
    return out


def search(
    query: str,
    *,
    k: Optional[int] = None,
    kinds: Optional[Sequence[str]] = None,
    src_ip: Optional[str] = None,
) -> dict:
    conn = _open(create=False)
    try:
        return retriever.search(
            query, conn=conn, embedder=get_embedder(), k=k, kinds=kinds, src_ip=src_ip
        )
    finally:
        conn.close()


def ask(
    question: str,
    *,
    k: Optional[int] = None,
    kinds: Optional[Sequence[str]] = None,
    src_ip: Optional[str] = None,
    mode: str = "analysis",
    extra_context: Optional[str] = None,
) -> dict:
    conn = _open(create=False)
    try:
        return answer.ask(
            question,
            conn=conn,
            embedder=get_embedder(),
            llm=get_llm(),
            k=k,
            kinds=kinds,
            src_ip=src_ip,
            mode=mode,
            extra_context=extra_context,
        )
    finally:
        conn.close()


def index(
    *,
    scope: str = "all",
    force: bool = False,
    events_db: Optional[Path] = None,
    notes_db: Optional[Path] = None,
) -> dict:
    conn = _open(create=True)
    try:
        scopes = ("knowledge", "events", "notes") if scope == "all" else (scope,)
        _assert_embedding_compatible(conn, force=force)
        result = indexer.index_all(
            conn, get_embedder(), scopes=scopes, force=force,
            events_db=events_db, notes_db=notes_db,
        )
        result["stats"] = store.stats(conn)
        return result
    finally:
        conn.close()


def feedback(
    *,
    question: str,
    predicted: str,
    label: str,
    analyst: str = "",
    src_ip: str = "",
    notes: str = "",
) -> dict:
    conn = _open(create=False)
    try:
        return store.add_feedback(
            conn, question=question, predicted=predicted, label=label,
            analyst=analyst, src_ip=src_ip, notes=notes,
        )
    finally:
        conn.close()


def metrics() -> dict:
    conn = _open(create=False)
    try:
        return store.feedback_metrics(conn)
    finally:
        conn.close()


def findings(limit: int = 50, *, unacked_only: bool = False) -> dict:
    conn = _open(create=False)
    try:
        items = store.list_findings(conn, limit=limit, unacked_only=unacked_only)
        return {"items": items, "unacked": store.stats(conn)["unacked_findings"]}
    finally:
        conn.close()


def ack(finding_id: int, actor: str) -> dict:
    conn = _open(create=False)
    try:
        return {"id": finding_id, "ack": store.ack_finding(conn, finding_id, actor)}
    finally:
        conn.close()


def scan(**options) -> dict:
    """Ejecuta el monitor proactivo (indexa, evalúa y notifica)."""
    if not settings.RAG_ENABLED:
        raise RagDisabled("RAG deshabilitado (NETPULSE_RAG_ENABLED=false)")
    from app.services.ai.rag import monitor

    return monitor.scan(**options)


def _open(*, create: bool) -> sqlite3.Connection:
    if not is_enabled():
        raise RagDisabled("RAG deshabilitado (NETPULSE_RAG_ENABLED=false)")
    path = Path(settings.RAG_DB)
    if not create and not path.is_file():
        raise RagNotIndexed(f"no existe el índice RAG en {path}")
    conn = store.connect(path)
    if not create:
        _assert_embedding_compatible(conn, force=False)
    return conn


def _embedding_matches(conn: sqlite3.Connection) -> Optional[bool]:
    saved_model = store.meta_get(conn, "embed_model")
    saved_dim = store.meta_get(conn, "embed_dim")
    if not saved_model and not saved_dim:
        return None
    return saved_model == settings.RAG_EMBED_MODEL and str(settings.RAG_EMBED_DIM) == saved_dim


def _assert_embedding_compatible(conn: sqlite3.Connection, *, force: bool) -> None:
    if _embedding_matches(conn) is False and not force:
        raise RagUnavailable(
            "el modelo o la dimensión de embeddings cambió respecto al índice; "
            "reindexe con force=true"
        )
