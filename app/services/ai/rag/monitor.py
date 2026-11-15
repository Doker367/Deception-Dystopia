"""Monitor proactivo: detecta casos candidatos y pide un veredicto a la IA.

Flujo:
1. Lee eventos nuevos desde el último cursor.
2. Aplica reglas deterministas para elegir candidatos (no cada IP).
3. Reindexa la memoria y pide un triage con evidencia.
4. Persiste el hallazgo y, si supera el umbral, lo notifica por los canales
   configurados (webhook, Telegram, Slack, email, ntfy).

Nunca bloquea, aísla ni suprime alertas. Si el modelo falla, emite un
hallazgo por reglas y lo marca como tal.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Sequence

from app.core import settings
from app.services.ai.rag import answer, indexer, store
from app.services.ai.rag.embedding import get_embedder
from app.services.ai.rag.errors import RagDisabled, RagUnavailable
from app.services.ai.rag.llm import get_llm

logger = logging.getLogger(__name__)

_SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_POSITIVE = {"malicious", "suspicious"}
_SENSITIVE = re.compile(
    r"(?i)\b(hydra|nmap|masscan|netcat|nc|curl|wget|chmod|chown|useradd|"
    r"crontab|systemctl|docker|bash\s+-i|python\s+-c|base64\s+-d|"
    r"/etc/passwd|/etc/shadow)\b|\.\./|/admin|/wp-login|/\.env"
)
_VERDICT_LABEL = {
    "malicious": "Ataque probable",
    "suspicious": "Actividad sospechosa",
    "benign": "Tráfico aparentemente benigno",
    "unknown": "Caso sin clasificar",
}


def scan(
    *,
    window_min: Optional[int] = None,
    min_events: Optional[int] = None,
    min_score: Optional[int] = None,
    max_candidates: Optional[int] = None,
    notify: bool = True,
) -> dict:
    """Ejecuta una pasada del monitor y devuelve el resumen."""
    if not settings.RAG_ENABLED:
        raise RagDisabled("RAG deshabilitado (NETPULSE_RAG_ENABLED=false)")

    window_min = settings.RAG_MONITOR_WINDOW_MIN if window_min is None else window_min
    min_events = settings.RAG_MONITOR_MIN_EVENTS if min_events is None else min_events
    min_score = settings.RAG_MONITOR_MIN_SCORE if min_score is None else min_score
    max_candidates = (
        settings.RAG_MONITOR_MAX_CANDIDATES if max_candidates is None else max_candidates
    )

    path = Path(settings.DECEPTION_DB)
    if not path.is_file():
        return {"events_new": 0, "candidates": 0, "findings": 0, "notified": 0,
                "skipped_cooldown": 0, "reason": "sin base de eventos"}

    conn = store.connect(settings.RAG_DB)
    try:
        embedder = get_embedder()
        knowledge_docs = 0
        try:
            # Conocimiento y notas son baratos (los documentos sin cambios se
            # omiten por hash). Se indexan aunque aún no haya eventos nuevos,
            # para que la vista IA tenga memoria desde el primer arranque.
            knowledge_docs = indexer.index_all(
                conn, embedder, scopes=("knowledge", "notes")
            ).get("docs", 0)
        except RagUnavailable as exc:
            logger.warning("[ai-monitor] sin conocimiento/notas: %s", exc)

        # La marca de "último análisis" se actualiza en cada pasada, incluso
        # cuando no hay eventos nuevos, para que la interfaz no muestre una
        # fecha vieja.
        store.meta_set(conn, "monitor_last_scan", datetime.now(timezone.utc).isoformat())

        new_rows, new_cursor = _new_events(path, int(store.meta_get(conn, "monitor_cursor_id") or 0))
        if new_rows is None:
            return {"events_new": 0, "candidates": 0, "findings": 0, "notified": 0,
                    "skipped_cooldown": 0, "indexed_docs": knowledge_docs,
                    "reason": "tabla de eventos ausente"}
        if not new_rows:
            return {"events_new": 0, "candidates": 0, "findings": 0, "notified": 0,
                    "skipped_cooldown": 0, "indexed_docs": knowledge_docs,
                    "cursor": store.meta_get(conn, "monitor_cursor_id")}

        until = _parse_ts(str(new_rows[-1]["ts"])) or datetime.now(timezone.utc)
        since = until - timedelta(minutes=window_min)
        window_rows = _window_events(path, since)
        candidates = _candidates(window_rows, min_events=min_events, min_score=min_score)
        candidates = candidates[:max_candidates]

        indexed = 0
        try:
            indexed = indexer.index_events(
                conn, embedder, path=path, days=settings.RAG_EVENT_DAYS
            ).get("docs", 0)
        except RagUnavailable as exc:
            logger.warning("[ai-monitor] índice sin embeddings: %s", exc)

        findings = 0
        notified = 0
        skipped = 0
        details: list[dict] = []
        for candidate in candidates:
            ip = candidate["src_ip"]
            dedupe = f"ai:{ip}"
            if store.recent_finding(conn, dedupe, settings.RAG_MONITOR_COOLDOWN_MIN):
                skipped += 1
                continue
            finding = _evaluate(conn, embedder, candidate, until)
            stored = store.add_finding(
                conn,
                src_ip=ip,
                verdict=finding["verdict"],
                confidence=finding["confidence"],
                severity=finding["severity"],
                title=finding["title"],
                summary=finding["summary"],
                evidence=finding["evidence"],
                model=finding["model"],
                source=finding["source"],
                dedupe_key=dedupe,
            )
            findings += 1
            should_notify = (
                notify
                and finding["verdict"] in _POSITIVE
                and _SEVERITY[finding["severity"]]
                >= _SEVERITY.get(settings.RAG_MONITOR_NOTIFY_MIN_SEVERITY, 2)
            )
            if finding["verdict"] in _POSITIVE:
                should_notify = should_notify and (
                    finding["confidence"] or 0.0
                ) >= settings.RAG_MONITOR_MIN_CONFIDENCE
            if should_notify and _notify(stored, finding):
                store.mark_notified(conn, stored["id"])
                notified += 1
            details.append({
                "id": stored["id"], "src_ip": ip, "verdict": finding["verdict"],
                "severity": finding["severity"], "confidence": finding["confidence"],
                "notified": should_notify,
            })

        store.meta_set(conn, "monitor_cursor_id", str(new_cursor))
        store.meta_set(conn, "monitor_last_scan", datetime.now(timezone.utc).isoformat())
        return {
            "events_new": len(new_rows),
            "window_events": len(window_rows),
            "indexed_docs": indexed,
            "knowledge_docs": knowledge_docs,
            "candidates": len(candidates),
            "findings": findings,
            "notified": notified,
            "skipped_cooldown": skipped,
            "details": details,
            "cursor": new_cursor,
        }
    finally:
        conn.close()


def _new_events(path: Path, cursor: int) -> tuple[Optional[list[sqlite3.Row]], int]:
    source = _readonly(path)
    if source is None:
        return None, 0
    try:
        rows = source.execute(
            "SELECT * FROM deception_events WHERE id > ? ORDER BY id ASC LIMIT ?",
            (cursor, settings.RAG_MONITOR_BATCH),
        ).fetchall()
    except sqlite3.OperationalError:
        return None, 0
    finally:
        source.close()
    if not rows:
        return [], cursor
    return rows, int(rows[-1]["id"])


def _window_events(path: Path, since: datetime) -> list[sqlite3.Row]:
    source = _readonly(path)
    if source is None:
        return []
    try:
        # Se filtra por fecha en Python: los colectores pueden escribir
        # ``Z`` o ``+00:00`` y la comparación lexicográfica no es fiable.
        rows = source.execute(
            "SELECT * FROM deception_events ORDER BY id DESC LIMIT ?",
            (settings.RAG_MONITOR_BATCH,),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        source.close()
    out = [row for row in rows if (_parse_ts(str(row["ts"])) or since) >= since]
    out.sort(key=lambda row: str(row["ts"]))
    return out


def _candidates(
    rows: Sequence[sqlite3.Row], *, min_events: int, min_score: int
) -> list[dict]:
    groups: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        ip = str(row["src_ip"] or "")
        if ip:
            groups[ip].append(row)

    candidates: list[dict] = []
    for ip, events in groups.items():
        total = len(events)
        logins = sum(1 for event in events if str(event["event_type"]) == "login_attempt")
        successes = sum(
            1 for event in events
            if str(event["event_type"]) == "login_success" or int(event["success"] or 0)
        )
        ports = {
            (int(event["dst_port"]), str(event["proto"] or ""))
            for event in events if event["dst_port"] is not None
        }
        types = Counter(str(event["event_type"]) for event in events)
        sensitive = sum(1 for event in events if _event_is_sensitive(event))
        score = 0
        if total >= min_events:
            score += 2
        if logins >= 5:
            score += 2
        if successes:
            score += 3
        if len(ports) >= 5:
            score += 2
        if sensitive:
            score += 2
        if total >= 50:
            score += 1
        if score < min_score:
            continue
        if _allowlisted(ip):
            continue
        candidates.append({
            "src_ip": ip,
            "count": total,
            "logins": logins,
            "successes": successes,
            "ports": sorted(ports),
            "types": dict(types),
            "sensitive": sensitive,
            "score": score,
            "scope": _scope(ip),
        })
    candidates.sort(key=lambda item: (-item["score"], -item["count"]))
    return candidates


def _evaluate(conn: sqlite3.Connection, embedder, candidate: dict, until: datetime) -> dict:
    ip = candidate["src_ip"]
    question = (
        f"Analizá los eventos del origen {ip} en los últimos "
        f"{settings.RAG_MONITOR_WINDOW_MIN} minutos. "
        f"Hay {candidate['count']} eventos, {candidate['logins']} intentos de login, "
        f"{candidate['successes']} accesos aceptados y {len(candidate['ports'])} destinos. "
        "¿Es un ataque real, sospechoso o tráfico benigno? Citá la evidencia."
    )
    try:
        result = answer.ask(
            question, conn=conn, embedder=embedder, llm=get_llm(),
            k=6, src_ip=ip, mode="triage",
        )
    except RagUnavailable as exc:
        logger.warning("[ai-monitor] triage no disponible para %s: %s", ip, exc)
        result = None

    structured = (result or {}).get("structured")
    if structured:
        verdict = structured["verdict"]
        confidence = structured["confidence"]
        summary_parts = structured["observed"][:3] + structured["inferred"][:3]
        summary = _join_sentences(summary_parts) or "Sin detalle estructurado."
        evidence = (result or {}).get("evidence") or []
        model = (result or {}).get("model")
        source = "ai"
        mitre = structured.get("mitre") or []
    else:
        verdict = "suspicious"
        confidence = min(0.95, 0.35 + 0.08 * candidate["score"])
        summary = _rules_summary(candidate)
        evidence = (result or {}).get("evidence") or []
        model = (result or {}).get("model")
        source = "rules"
        mitre = []

    # Si las reglas ven acceso aceptado o payload sensible, no se acepta un
    # "benign" sin evidencia: se degrada a sospechoso para revisión humana.
    if verdict == "benign" and (candidate["successes"] or candidate["sensitive"]):
        verdict = "suspicious"
        source = "ai+rules"
        summary = (
            "La IA lo clasificó como benigno, pero hay accesos aceptados o "
            "payload sensible. Requiere revisión humana. " + summary
        )

    severity = _severity_for(candidate, verdict, confidence)
    mitre_text = f" MITRE: {', '.join(mitre[:5])}." if mitre else ""
    return {
        "verdict": verdict,
        "confidence": round(float(confidence or 0.0), 4),
        "severity": severity,
        "title": f"{_VERDICT_LABEL.get(verdict, 'Hallazgo')} · {ip}",
        "summary": f"{summary}{mitre_text}".strip(),
        "evidence": evidence,
        "model": model,
        "source": source,
    }


def _severity_for(candidate: dict, verdict: str, confidence: float) -> str:
    if verdict == "benign":
        return "info"
    if candidate["successes"] and candidate["sensitive"]:
        return "critical"
    if candidate["successes"] or candidate["sensitive"] or candidate["count"] >= 20:
        return "high"
    if verdict in _POSITIVE or candidate["count"] >= 8:
        return "medium"
    return "low"


def _join_sentences(items: Sequence[object]) -> str:
    parts: list[str] = []
    for item in items:
        text = str(item).strip()
        if not text:
            continue
        if text[-1] not in ".!?":
            text += "."
        parts.append(text)
    return " ".join(parts)


def _rules_summary(candidate: dict) -> str:
    ports = ", ".join(f"{port}/{proto}" for port, proto in candidate["ports"][:6]) or "sin puerto"
    return (
        f"Se vieron {candidate['count']} eventos desde esta IP: "
        f"{candidate['logins']} intentos de inicio de sesión y "
        f"{candidate['successes']} accesos aceptados. "
        f"Puertos tocados: {ports}. "
        f"Puede ser un escaneo o un intento de intrusión; requiere revisión humana."
    )


def _event_is_sensitive(event: sqlite3.Row) -> bool:
    try:
        import json

        detail = json.loads(event["detail"] or "{}")
    except (json.JSONDecodeError, TypeError):
        detail = {}
    if not isinstance(detail, dict):
        detail = {}
    blob = " ".join(
        str(detail.get(key) or "") for key in ("command", "cmd", "url", "path", "payload")
    )
    return bool(blob and _SENSITIVE.search(blob))


def _notify(stored: dict, finding: dict) -> bool:
    payload = {
        "title": stored["title"],
        "message": stored["summary"][:600],
        "finding_id": stored["id"],
        "src_ip": stored["src_ip"],
        "verdict": stored["verdict"],
        "confidence": stored["confidence"],
        "severity": stored["severity"],
        "mitre": _mitre_from_summary(stored["summary"]),
        "source": stored["source"],
        "model": stored["model"],
        "advisory": "Hallazgo asesor: no se bloqueó ni aisló nada. Requiere revisión humana.",
    }
    try:
        from app.services import notifications_svc

        if not notifications_svc.has_channels("ai_finding"):
            return False
        notifications_svc.notify_event("ai_finding", payload)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("[ai-monitor] notificación falló: %s", exc)
        return False


def _mitre_from_summary(summary: str) -> list[str]:
    return sorted(set(re.findall(r"T\d{4}", summary or "")))


def _allowlisted(ip: str) -> bool:
    try:
        from app.services.deception import allowlist_svc

        return allowlist_svc.is_allowed(ip)
    except Exception:  # noqa: BLE001
        return False


def _scope(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    return "public"


def _parse_ts(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _readonly(path: Path) -> Optional[sqlite3.Connection]:
    if not path.is_file():
        return None
    try:
        conn = sqlite3.connect(f"{path.absolute().as_uri()}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error:
        return None
    conn.row_factory = sqlite3.Row
    return conn
