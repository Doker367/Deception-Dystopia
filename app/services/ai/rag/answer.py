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

SYSTEM_ANALYSIS = """Eres un analista de seguridad que ayuda a personas que no son expertas.
Respondes en español claro, con precisión y sin dar nada por sabido.

Usa exactamente este formato, sin markdown y sin tablas:
EN UNA FRASE: qué pasó y si es grave, en lenguaje llano.
QUÉ SE OBSERVÓ:
- máximo 3 viñetas cortas, cada una con su cita [n].
QUÉ SIGNIFICA: una o dos frases; separa lo confirmado de lo supuesto.
QUÉ HACER: una sola frase con el siguiente paso humano.

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
8. Explica las siglas y los términos técnicos la primera vez que aparecen
   (por ejemplo: "T1110 (fuerza bruta de contraseñas)"). Evita jerga de SOC
   que el lector no pueda entender.
9. Máximo 120 palabras en total. Si hay mucha evidencia, elige solo lo que
   cambia la decisión.
10. Empieza por lo importante: si hubo acceso aceptado, dilo primero; si no
    lo hubo, también.
11. No vuelques tablas, YAML, listas de puertos, rutas ni volcados técnicos.
    Resúmelos en una frase.
12. Si la evidencia corresponde a un honeypot o servidor señuelo, dilo
    explícitamente: el acceso fue al señuelo, no a un host real. No lo
    presentes como un compromiso confirmado de la infraestructura.
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
7. Escribe los valores de observed, inferred, missing y recommended_actions en
   lenguaje claro para alguien no especialista. Explica las siglas y términos
   técnicos la primera vez que aparecen.
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
    extra_context: Optional[str] = None,
) -> dict:
    """Recupera evidencia, pregunta al modelo y valida las citas.

    ``extra_context`` permite añadir un bloque local y acotado (por ejemplo,
    los movimientos y respuestas del señuelo de la ficha abierta) como
    evidencia adicional numerada. El llamador es responsable de generarlo en
    el servidor: nunca debe venir de texto libre del navegador.
    """
    if mode not in {"analysis", "triage"}:
        raise ValueError("mode debe ser analysis|triage")
    question = (question or "").strip()
    if not question:
        raise ValueError("la pregunta no puede estar vacía")

    retrieval = search(
        question, conn=conn, embedder=embedder, k=k, kinds=kinds, src_ip=src_ip
    )
    evidence = list(retrieval["results"])
    retrieved_chunk_ids = {
        int(item["chunk_id"]) for item in evidence if item.get("chunk_id")
    }
    extra_context = (extra_context or "").strip()
    if extra_context:
        evidence.insert(0, {
            "kind": "movement",
            "source": "movimientos del señuelo",
            "src_ip": src_ip,
            "ts": None,
            "heading": "Comandos y respuestas del señuelo",
            "text": extra_context,
        })
    base = {
        "mode": mode,
        "question": question,
        "retrieval": {
            "mode": retrieval["mode"],
            "degraded": retrieval["degraded"],
            "error": retrieval.get("error"),
            "count": len(retrieval["results"]),
            "context": bool(extra_context),
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
    retrieval = validate_citations(
        citations, evidence, retrieved_chunk_ids
    ) if retrieved_chunk_ids else {
        "valid": citations, "dropped": [], "chunk_ids": [],
    }
    abstained = "EVIDENCIA INSUFICIENTE" in text.upper()
    structured = _parse_triage(text) if mode == "triage" else None
    return {
        **base,
        "answer": text,
        "abstained": abstained,
        "grounded": bool(retrieval["valid"]) and not abstained,
        "citations": retrieval["valid"],
        "citation_chunks": retrieval["chunk_ids"],
        "dropped_citations": retrieval["dropped"],
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


def _citations(text: str, total: int = 0) -> list[int]:
    """Números [n] citados en el texto, SIN filtrar rango (lo valida antes)."""
    return sorted({int(match.group(1)) for match in _CITATION.finditer(text or "")})


def validate_citations(
    citations: Sequence[int],
    evidence: Sequence[dict],
    retrieved_chunk_ids: set[int],
) -> dict:
    """Valida que la respuesta solo cite fragmentos recuperados.

    Devuelve ``valid`` (números de evidencia citables), ``dropped`` (citas
    fuera de rango o cuyo fragmento no fue recuperado) y ``chunk_ids``
    (fragmentos recuperados a los que apuntan las citas válidas). El
    marcador ``[n]`` se descarta cuando apunta a un chunk_id que el
    recuperador no entregó: así nunca se cita de memoria ni inventa fuente.
    """
    total = len(evidence)
    valid: set[int] = set()
    dropped: set[int] = set()
    chunk_ids: set[int] = set()
    for number in citations:
        if not 1 <= number <= total:
            dropped.add(int(number))
            continue
        chunk_id = evidence[number - 1].get("chunk_id")
        if chunk_id is None:
            # Evidencia extra sin chunk (movimientos del señuelo): sigue siendo
            # evidencia citable, pero no aporta chunk_id al mapa.
            valid.add(int(number))
            continue
        if int(chunk_id) in retrieved_chunk_ids:
            valid.add(int(number))
            chunk_ids.add(int(chunk_id))
        else:
            dropped.add(int(number))
    return {
        "valid": sorted(valid),
        "dropped": sorted(dropped),
        "chunk_ids": sorted(chunk_ids),
    }


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
