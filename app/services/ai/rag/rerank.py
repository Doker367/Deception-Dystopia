# -*- coding: utf-8 -*-
"""Senales baratas y deterministas para el reranking del RAG local.

Mezcla lineal: total = w_rrf*rrf_norm + w_exact*exacto + w_prox*proximidad
+ w_rec*recencia. Cada senal vive en [0, 1]; rrf_norm es el RRF relativo
(score / mejor_score_del_pool). Pesos via entorno NETPULSE_RAG_RERANK_*;
por defecto RRF domina (0.60) y las senales completan (0.20/0.12/0.08).
Ceros = solo RRF (comportamiento anterior). Determinista, sin seed fuera
del calendario de recencia (ts de cada documento).
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone

_TOKEN = re.compile(r"[^\W_]{2,}", re.UNICODE)
_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_PORT = re.compile(r"\b(\d{2,5})\b")


def entity_match_score(query: str, text: str, src_ip: str = "") -> float:
    """Frac. de entidades de consulta (IP, puerto, usuario) en el fragmento."""
    low = (text or "").lower()
    if not query or not low:
        return 0.0
    probe: list[str] = []
    for match in _IPV4.finditer(query):
        probe.append(match.group(1))
    for match in _PORT.finditer(query):
        probe.append(match.group(1))
    probe.extend(tokens(query))
    if not probe:
        return 0.0
    seen: set[str] = set()
    found = 0
    for item in probe:
        if item in seen:
            continue
        seen.add(item)
        if item in low:
            found += 1
    if src_ip and src_ip in low:
        found += 1
    return min(1.0, found / max(1, len(seen)))


def term_proximity(terms: list[str], text: str) -> float:
    """Ventana minima que cubre los terminos; 1/(1+extra) en [0, 1]."""
    if not terms:
        return 0.0
    positions = token_positions(text)
    spots: list[list[int]] = []
    for term in terms:
        found = positions.get(str(term).lower(), [])
        if not found:
            return 0.0
        spots.append(found)
    if len(spots) == 1:
        return 1.0
    best = 10 ** 9
    for combo in _combos(spots):
        best = min(best, max(combo) - min(combo) + 1)
    if best >= 10 ** 9:
        return 0.0
    extra = max(0, best - len(spots))
    return 1.0 / (1.0 + extra)


def recency(ts: str, tau_days: float) -> float:
    """Decaimiento exponencial por antiguedad; sin ts -> 0."""
    if not ts or not tau_days or tau_days <= 0:
        return 0.0
    try:
        parsed = datetime.fromisoformat(str(ts)[:19])
    except ValueError:
        return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    age = max(0.0, (datetime.now(timezone.utc) - parsed).total_seconds())
    return math.exp(-age / (tau_days * 86400.0))


def tokens(text: str) -> list[str]:
    """Tokens minusculas de contenido (>= 2 caracteres)."""
    return [t.lower() for t in _TOKEN.findall(text or "")]


def token_positions(text: str) -> dict[str, list[int]]:
    """Mapa token -> posiciones de aparicion para la ventana minima."""
    out: dict[str, list[int]] = {}
    for index, token in enumerate(_TOKEN.findall(text or "")):
        out.setdefault(token.lower(), []).append(index)
    return out


def _combos(groups: list[list[int]]):
    if not groups:
        yield ()
        return
    for head in groups[0]:
        for tail in _combos(groups[1:]):
            yield (head,) + tail


def signal_weights() -> dict:
    """Pesos senales desde settings, revisados en cada llamada."""
    from app.core import settings as core_settings

    return {
        "w_rrf": float(core_settings.RAG_RERANK_W_RRF),
        "w_exact": float(core_settings.RAG_RERANK_W_EXACT),
        "w_prox": float(core_settings.RAG_RERANK_W_PROXIMITY),
        "w_rec": float(core_settings.RAG_RERANK_W_RECENCY),
        "tau_days": float(core_settings.RAG_RERANK_RECENCY_DAYS),
    }


def rerank(pool: list[dict], query: str, weights: dict) -> list[dict]:
    """Reordena el pool (dict con score/text/ts/src_ip) con senales baratas."""
    if not pool:
        return []
    weights = weights or signal_weights()
    max_rrf = max((float(item.get("score") or 0.0) for item in pool),
                  default=0.0) or 1.0
    terms = tokens(query)
    for item in pool:
        rrf_norm = float(item.get("score") or 0.0) / max_rrf
        signals = {
            "rrf_norm": round(rrf_norm, 6),
            "exact": entity_match_score(query, str(item.get("text") or ""),
                                        str(item.get("src_ip") or "")),
            "proximity": term_proximity(terms, str(item.get("text") or "")),
            "recency": recency(str(item.get("ts") or ""), defaults_tau(weights)),
        }
        total = (
            weights["w_rrf"] * signals["rrf_norm"]
            + weights["w_exact"] * signals["exact"]
            + weights["w_prox"] * signals["proximity"]
            + weights["w_rec"] * signals["recency"]
        )
        item["rerank_score"] = round(total, 6)
        item["signals"] = {k: round(v, 4) for k, v in signals.items()}
    pool.sort(key=lambda item: (-float(item["rerank_score"]),
                                int(item.get("chunk_id") or 0)))
    return pool


def defaults_tau(weights: dict) -> float:
    return float(weights.get("tau_days") or 45.0)
