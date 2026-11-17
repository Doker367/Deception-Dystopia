"""NetPulse — Router del RAG local (memoria de ataques).

Endpoints:
- GET  /api/ai/rag/status    — estado del índice y de los modelos.
- GET  /api/ai/rag/search    — búsqueda híbrida con procedencia.
- POST /api/ai/rag/ask       — respuesta fundamentada con citas.
- POST /api/ai/rag/triage    — veredicto estructurado de un caso.
- POST /api/ai/rag/index     — (admin) indexa eventos, notas y conocimiento.
- POST /api/ai/rag/feedback  — (operator) etiqueta TP/FP del analista.
- GET  /api/ai/rag/metrics   — precisión y recall por separado.

Ninguna ruta modifica eventos, notas ni firewall. La respuesta es asesoría.
"""

from __future__ import annotations

import logging
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.middleware.auth import JWTBearer
from app.middleware.rbac import get_current_user, requires_role
from app.services.ai.rag import service
from app.services.ai.rag.errors import RagDisabled, RagNotIndexed, RagUnavailable
from app.services.analytics_svc import movement_context

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/ai/rag",
    tags=["AI — RAG"],
    dependencies=[Depends(JWTBearer()), Depends(requires_role("viewer"))],
)


class AskRequest(BaseModel):
    question: str = Field(min_length=3, max_length=2000)
    k: Optional[int] = Field(default=None, ge=1, le=50)
    kinds: Optional[list[Literal["event", "note", "knowledge"]]] = None
    src_ip: Optional[str] = Field(default=None, max_length=64)
    mode: Literal["analysis", "triage"] = "analysis"
    # Añade al prompt los movimientos y respuestas del señuelo de esa IP,
    # generados en el servidor desde la misma evidencia de la ficha.
    include_movements: bool = False


class IndexRequest(BaseModel):
    scope: Literal["all", "events", "notes", "knowledge"] = "all"
    force: bool = False


class FeedbackRequest(BaseModel):
    question: str = Field(min_length=3, max_length=2000)
    predicted: Literal["malicious", "suspicious", "benign", "unknown"]
    label: Literal["true_positive", "false_positive"]
    src_ip: str = Field(default="", max_length=64)
    notes: str = Field(default="", max_length=2000)


class ScanRequest(BaseModel):
    notify: bool = True


def _extra_context(body: AskRequest) -> Optional[str]:
    """Contexto local opcional para preguntas abiertas desde una ficha."""
    if not body.include_movements or not body.src_ip:
        return None
    try:
        return movement_context(body.src_ip) or None
    except Exception:  # noqa: BLE001 — el contexto es opcional, no bloquea la respuesta
        logger.warning("rag_movement_context_failed src_ip=%s", body.src_ip)
        return None


@router.get("/status")
def rag_status() -> dict:
    """Estado barato del índice (no llama a los modelos)."""
    return service.status()


@router.get("/search")
def rag_search(
    q: str = Query(min_length=2, max_length=500),
    k: Optional[int] = Query(default=None, ge=1, le=50),
    src_ip: Optional[str] = Query(default=None, max_length=64),
    kinds: Optional[list[str]] = Query(default=None),
) -> dict:
    """Búsqueda híbrida; degrada a léxica si el embedder no responde."""
    return _guard(lambda: service.search(q, k=k, kinds=kinds, src_ip=src_ip))


@router.post("/ask")
def rag_ask(body: AskRequest) -> dict:
    """Respuesta fundamentada; se abstiene si no hay evidencia."""
    return _guard(
        lambda: service.ask(
            body.question, k=body.k, kinds=body.kinds, src_ip=body.src_ip,
            mode=body.mode, extra_context=_extra_context(body),
        )
    )


@router.post("/triage")
def rag_triage(body: AskRequest) -> dict:
    """Fuerza el modo estructurado para clasificar un caso."""
    return _guard(
        lambda: service.ask(
            body.question, k=body.k, kinds=body.kinds, src_ip=body.src_ip,
            mode="triage", extra_context=_extra_context(body),
        )
    )


@router.post("/index", dependencies=[Depends(requires_role("admin"))])
def rag_index(body: IndexRequest) -> dict:
    """Indexa las fuentes locales. Puede tardar; para lotes grandes use la CLI."""
    return _guard(lambda: service.index(scope=body.scope, force=body.force))


@router.post("/feedback", dependencies=[Depends(requires_role("operator"))])
def rag_feedback(body: FeedbackRequest, request: Request) -> dict:
    """Guarda la etiqueta del analista para medir precisión y recall."""
    actor = _actor(request)
    return _guard(
        lambda: service.feedback(
            question=body.question,
            predicted=body.predicted,
            label=body.label,
            analyst=actor,
            src_ip=body.src_ip,
            notes=body.notes,
        )
    )


@router.get("/metrics")
def rag_metrics() -> dict:
    """Métricas binarias calculadas solo con casos etiquetados por humanos."""
    return _guard(service.metrics)


@router.get("/findings")
def rag_findings(
    limit: int = Query(default=50, ge=1, le=200),
    unacked: bool = Query(default=False),
) -> dict:
    """Hallazgos proactivos del monitor (más recientes primero)."""
    return _guard(lambda: service.findings(limit=limit, unacked_only=unacked))


@router.post("/findings/{finding_id}/ack", dependencies=[Depends(requires_role("operator"))])
def rag_ack(finding_id: int, request: Request) -> dict:
    """Marca un hallazgo como revisado; no altera eventos ni firewall."""
    return _guard(lambda: service.ack(finding_id, _actor(request)))


@router.post("/scan", dependencies=[Depends(requires_role("admin"))])
def rag_scan(body: ScanRequest) -> dict:
    """Ejecuta una pasada del monitor: clasifica y notifica hallazgos."""
    return _guard(lambda: service.scan(notify=body.notify))


def _actor(request: Request) -> str:
    principal = get_current_user(request)
    return str(principal.get("username") or principal.get("sub") or "unknown")


def _guard(operation):
    try:
        return operation()
    except RagDisabled as exc:
        raise HTTPException(503, str(exc)) from None
    except RagNotIndexed as exc:
        raise HTTPException(503, str(exc)) from None
    except RagUnavailable as exc:
        raise HTTPException(503, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
