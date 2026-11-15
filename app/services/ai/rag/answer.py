"""Respuesta fundamentada sobre la evidencia recuperada.

Dos modos:

- ``analysis``: explicación libre, con citas ``[n]``.
- ``triage``: veredicto estructurado en JSON para un caso concreto.

Reglas duras: solo se responde con la evidencia entregada; sin evidencia se
abstiene; sin citas se marca ``grounded=false``. El resultado es asesor y
nunca suprime alertas ni bloquea direcciones por sí solo.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Optional, Sequence

from app.core import settings
from app.services.ai.rag.errors import RagUnavailable
from app.services.ai.rag.retriever import search

SYSTEM_ANALYSIS = """Eres un analista de un SOC que opera honeypots y una red de engaño.
Respondes en español, con precisión y sin adornos.

Reglas obligatorias:
1. Usa únicamente la EVIDENCIA numerada que recibes.
2. Cada afirmación debe terminar con una cita [n] del fragmento que la sostiene.
3. Si la evidencia no alcanza, responde exactamente: EVIDENCIA INSUFICIENTE
   y di qué dato falta. No rellenes huecos con conocimiento general.
4. No inventes IPs, dominios, hashes, comandos, usuarios ni fechas.
5. Separa lo OBSERVADO (cita) de lo INFERIDO (tu interpretación, también citada).
6. Una IP observada no prueba la identidad del atacante.
7. No recomiendes bloquear sin evidencia suficiente; puedes proponer pasos de
   verificación.
8. Sé breve: máximo 8 viñetas o 2 párrafos.
No muestres tu cadena de razonamiento."""

SYSTEM_TRIAGE = """Eres un analista de un SOC que clasifica evidencia de honeypots.
Respondes SOLO con un objeto JSON válido, sin markdown ni texto extra.

Esquema:
{"verdict":"malicious|suspicious|benign|unknown","confidence":0.0,
 "mitre":["T####"],"observed":["..."],"inferred":["..."],
 "missing":["..."],"recommended_actions":["..."]}

Reglas obligatorias:
1. Usa únicamente la EVIDENCIA numerada; cada elemento debe citar [n].
2. Si no hay evidencia suficiente: verdict "unknown", confidence 0.0 y
   explica en "missing" qué falta.
3. No inventes IPs, hashes, comandos ni fechas.
4. "benign" exige evidencia de escáner autorizado, health-check, backup o
   tráfico de laboratorio; ante la duda usa "suspicious", nunca "benign".
5. "malicious" exige conducta de adversario observable, no una sola IP.
6. No propongas bloqueo automático: "recommended_actions" describe pasos que
   un humano debe validar.
No muestres tu cadena de razonamiento."""

_CITATION = re.compile(r"\[(\d{1,2})\]")


def ask(
    question: str,
    *,
    conn: sqlite3.Connection,
    embedder,
    llm,
    k: Optional[int] = None,
    kinds: Optional[Sequence[str]] = None,
    src_ip: Optional[str] = None,
    mode: str = "analysis",
) -> dict:
    """Recupera evidencia, pregunta al modelo y valida las citas."""
    if mode not in {"analysis", "triage"}:
        raise ValueError("mode debe ser analysis|triage")
    question = (question or "").strip()
    if not question:
        raise ValueError("la pregunta no puede estar vacía")

    retrieval = search(
        question, conn=conn, embedder=embedder, k=k, kinds=kinds, src_ip=src_ip
    )
    evidence = retrieval["results"]
    base = {
        "mode": mode,
        "question": question,
        "retrieval": {
            "mode": retrieval["mode"],
            "degraded": retrieval["degraded"],
            "error": retrieval.get("error"),
            "count": len(evidence),
        },
        "evidence": [_public(index, item) for index, item in enumerate(evidence, start=1)],
    }

    if not evidence:
        return {
            **base,
            "answer": "EVIDENCIA INSUFICIENTE: no hay fragmentos que respalden la pregunta.",
            "abstained": True,
            "grounded": False,
            "citations": [],
            "structured": None,
            "model": None,
        }
    if llm is None:
        raise RagUnavailable("modelo generativo no configurado (NETPULSE_RAG_LLM_URL)")

    context = build_context(evidence, budget_chars=settings.RAG_CONTEXT_CHARS)
    system = SYSTEM_TRIAGE if mode == "triage" else SYSTEM_ANALYSIS
    user = f"EVIDENCIA:\n{context}\n\nPREGUNTA: {question}"
    if mode == "triage":
        user += (
            "\n\nRecordatorio: cada elemento de observed, inferred, missing y "
            "recommended_actions debe terminar con su cita [n]. Responde solo el JSON."
        )
    else:
        user += "\n\nRecordatorio: cada afirmación debe terminar con su cita [n]."
    completion = llm.complete(system, user)
    text = completion["text"]

    citations = _citations(text, len(evidence))
    abstained = "EVIDENCIA INSUFICIENTE" in text.upper()
    structured = _parse_triage(text) if mode == "triage" else None
    return {
        **base,
        "answer": text,
        "abstained": abstained,
        "grounded": bool(citations) and not abstained,
        "citations": citations,
        "structured": structured,
        "model": completion.get("model"),
        "usage": completion.get("usage"),
    }


def build_context(evidence: Sequence[dict], budget_chars: int = 12_000) -> str:
    """Numera los fragmentos y recorta el presupuesto del prompt."""
    blocks: list[str] = []
    used = 0
    for index, item in enumerate(evidence, start=1):
        header = (
            f"[{index}] tipo={item.get('kind')} fuente={item.get('source')} "
            f"ip={item.get('src_ip') or '-'} fecha={item.get('ts') or '-'}"
        )
        if item.get("heading"):
            header += f" · {item['heading']}"
        body = str(item.get("text") or "")[:1400]
        block = f"{header}\n{body}"
        if used + len(block) > budget_chars and blocks:
            break
        blocks.append(block)
        used += len(block) + 2
    return "\n\n".join(blocks)


def _citations(text: str, total: int) -> list[int]:
    found = sorted({int(match.group(1)) for match in _CITATION.finditer(text or "")})
    return [value for value in found if 1 <= value <= total]


def _public(number: int, item: dict) -> dict:
    return {
        "n": number,
        "chunk_id": item.get("chunk_id"),
        "doc_key": item.get("doc_key"),
        "kind": item.get("kind"),
        "source": item.get("source"),
        "src_ip": item.get("src_ip"),
        "ts": item.get("ts"),
        "heading": item.get("heading"),
        "text": str(item.get("text") or "")[:800],
        "score": item.get("score"),
        "similarity": item.get("similarity"),
        "matched_by": item.get("matched_by"),
    }


def _parse_triage(text: str) -> Optional[dict]:
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    verdict = str(data.get("verdict") or "unknown").lower()
    if verdict not in {"malicious", "suspicious", "benign", "unknown"}:
        verdict = "unknown"
    try:
        confidence = max(0.0, min(1.0, float(data.get("confidence") or 0.0)))
    except (TypeError, ValueError):
        confidence = 0.0
    return {
        "verdict": verdict,
        "confidence": round(confidence, 4),
        "mitre": _strings(data.get("mitre"), 10, 20),
        "observed": _strings(data.get("observed"), 12, 400),
        "inferred": _strings(data.get("inferred"), 12, 400),
        "missing": _strings(data.get("missing"), 12, 300),
        "recommended_actions": _strings(data.get("recommended_actions"), 12, 300),
    }


def _strings(value: object, limit: int, size: int) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value[:limit]:
        text = str(item).strip()
        if text:
            out.append(text[:size])
    return out
