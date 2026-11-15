"""Construcción de la memoria: eventos, notas de analista y conocimiento.

El indexador lee las fuentes en modo solo-lectura. Nunca escribe en la base
de eventos ni en el almacén privado de investigaciones.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

from app.core import settings
from app.services.ai.rag import store
from app.services.ai.rag.chunker import chunk_markdown, chunk_text
from app.services.ai.rag.sanitize import sanitize

_MITRE = {
    "login_attempt": "T1110 Brute Force (Credential Access)",
    "login_success": "T1078 Valid Accounts (Persistence/Privilege Escalation)",
    "http_request": "T1190 Exploit Public-Facing Application (Initial Access)",
    "scan": "T1046 Network Service Discovery (Discovery)",
    "connect": "T1046 Network Service Discovery (Discovery)",
    "command": "T1059 Command and Scripting Interpreter (Execution)",
    "download": "T1105 Ingress Tool Transfer (Command and Control)",
    "file_download": "T1105 Ingress Tool Transfer (Command and Control)",
}
_KNOWLEDGE_FILES = ("README.md", "SECURITY.md", "DEPLOYMENT.md", "ROLLBACK.md")
_KNOWLEDGE_SUFFIXES = {".md", ".txt", ".yaml", ".yml"}


def index_all(
    conn: sqlite3.Connection,
    embedder,
    *,
    scopes: Sequence[str] = ("knowledge", "events", "notes"),
    force: bool = False,
    events_db: Optional[Path] = None,
    notes_db: Optional[Path] = None,
) -> dict:
    """Indexa los ámbitos pedidos y devuelve contadores agregados."""
    result: dict[str, Any] = {"scopes": {}, "docs": 0, "chunks": 0, "skipped": 0}
    for scope in scopes:
        if scope == "knowledge":
            stats = index_knowledge(conn, embedder, force=force)
        elif scope == "events":
            stats = index_events(conn, embedder, force=force, path=events_db)
        elif scope == "notes":
            stats = index_notes(conn, embedder, force=force, path=notes_db)
        else:
            raise ValueError(f"ámbito desconocido: {scope}")
        result["scopes"][scope] = stats
        for key in ("docs", "chunks", "skipped"):
            result[key] += int(stats.get(key, 0))
    if result["docs"] or result["skipped"]:
        store.meta_set(conn, "embed_model", settings.RAG_EMBED_MODEL)
        store.meta_set(conn, "embed_dim", str(settings.RAG_EMBED_DIM))
    return result


def index_events(
    conn: sqlite3.Connection,
    embedder,
    *,
    path: Optional[Path] = None,
    days: Optional[int] = None,
    limit: Optional[int] = None,
    include_payload: Optional[bool] = None,
    force: bool = False,
) -> dict:
    """Agrupa eventos por ``(src_ip, hora)`` y guarda un resumen por grupo."""
    db_path = Path(path or settings.DECEPTION_DB)
    source = _readonly(db_path)
    if source is None:
        return {"docs": 0, "chunks": 0, "skipped": 0, "note": "sin base de eventos"}

    days = settings.RAG_EVENT_DAYS if days is None else days
    limit = settings.RAG_EVENT_LIMIT if limit is None else limit
    payload = settings.RAG_INCLUDE_PAYLOAD if include_payload is None else include_payload
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    try:
        rows = source.execute(
            "SELECT * FROM ("
            "  SELECT ts, device_id, src_ip, src_port, dst_ip, dst_port, proto,"
            "         event_type, username, success, detail"
            "  FROM deception_events WHERE ts >= ? ORDER BY id DESC LIMIT ?"
            ") ORDER BY ts ASC",
            (cutoff, limit),
        ).fetchall()
    except sqlite3.OperationalError:
        return {"docs": 0, "chunks": 0, "skipped": 0, "note": "tabla de eventos ausente"}
    finally:
        source.close()

    groups: dict[tuple[str, str], list[sqlite3.Row]] = {}
    for row in rows:
        src_ip = str(row["src_ip"] or "")
        hour = str(row["ts"] or "")[:13]
        if not src_ip or not hour:
            continue
        groups.setdefault((src_ip, hour), []).append(row)

    docs = chunks = skipped = 0
    for (src_ip, hour), events in groups.items():
        text = _event_text(src_ip, hour, events, include_payload=payload)
        outcome = store.upsert_doc(
            conn,
            doc_key=f"event:{src_ip}:{hour}",
            kind="event",
            source="deception_events",
            src_ip=src_ip,
            ts=hour,
            meta={
                "events": len(events),
                "hour": hour,
                "payload_indexed": payload,
                "devices": sorted({str(event["device_id"]) for event in events}),
            },
            chunks=[{"text": text, "heading": f"{src_ip} · {hour}"}],
            embedder=embedder,
            force=force,
        )
        docs += 1 if outcome["status"] == "indexed" else 0
        skipped += 1 if outcome["status"] == "skipped" else 0
        chunks += int(outcome.get("chunks", 0))
    return {"docs": docs, "chunks": chunks, "skipped": skipped, "groups": len(groups)}


def index_notes(
    conn: sqlite3.Connection,
    embedder,
    *,
    path: Optional[Path] = None,
    force: bool = False,
) -> dict:
    """Indexa los perfiles de analista (alias, clasificación, notas)."""
    db_path = Path(path or (settings.STATE_DIR / "investigations.db"))
    source = _readonly(db_path)
    if source is None:
        return {"docs": 0, "chunks": 0, "skipped": 0, "note": "sin base de investigaciones"}

    try:
        rows = source.execute(
            "SELECT source, body, updated_at FROM profiles"
        ).fetchall()
    except sqlite3.OperationalError:
        return {"docs": 0, "chunks": 0, "skipped": 0, "note": "tabla de perfiles ausente"}
    finally:
        source.close()

    keep: set[str] = set()
    docs = chunks = skipped = 0
    for row in rows:
        ip = str(row["source"] or "")
        if not ip:
            continue
        try:
            body = json.loads(row["body"] or "{}")
        except json.JSONDecodeError:
            body = {}
        text = _note_text(ip, body if isinstance(body, dict) else {})
        if not text:
            continue
        doc_key = f"note:{ip}"
        keep.add(doc_key)
        outcome = store.upsert_doc(
            conn,
            doc_key=doc_key,
            kind="note",
            source="investigations.profiles",
            src_ip=ip,
            ts=row["updated_at"],
            meta={"classification": body.get("classification"), "handling": body.get("handling")},
            chunks=[{"text": piece, "heading": f"Perfil de analista · {ip}"}
                    for piece in chunk_text(text)],
            embedder=embedder,
            force=force,
        )
        docs += 1 if outcome["status"] == "indexed" else 0
        skipped += 1 if outcome["status"] == "skipped" else 0
        chunks += int(outcome.get("chunks", 0))

    pruned = store.prune_kind(conn, "note", keep)
    return {"docs": docs, "chunks": chunks, "skipped": skipped, "pruned": pruned}


def index_knowledge(
    conn: sqlite3.Connection,
    embedder,
    *,
    force: bool = False,
    roots: Optional[Sequence[Path]] = None,
) -> dict:
    """Indexa documentación local (MITRE, runbooks, arquitectura, inventario)."""
    files = _knowledge_files(roots)
    keep: set[str] = set()
    docs = chunks = skipped = 0
    for path, doc_key in files:
        try:
            if path.stat().st_size > 1_000_000:
                continue
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        keep.add(doc_key)
        outcome = store.upsert_doc(
            conn,
            doc_key=doc_key,
            kind="knowledge",
            source=str(path.name),
            meta={"path": str(path.relative_to(settings.BASE_DIR))
                  if settings.BASE_DIR in path.parents else str(path)},
            chunks=chunk_markdown(raw),
            embedder=embedder,
            force=force,
        )
        docs += 1 if outcome["status"] == "indexed" else 0
        skipped += 1 if outcome["status"] == "skipped" else 0
        chunks += int(outcome.get("chunks", 0))

    pruned = store.prune_kind(conn, "knowledge", keep)
    return {"docs": docs, "chunks": chunks, "skipped": skipped, "pruned": pruned,
            "files": len(files)}


def _event_text(
    src_ip: str, hour: str, events: Sequence[sqlite3.Row], *, include_payload: bool
) -> str:
    devices = Counter(str(event["device_id"]) for event in events)
    types = Counter(str(event["event_type"]) for event in events)
    protos = Counter(str(event["proto"] or "?") for event in events)
    targets = Counter(
        f"{event['dst_port']}/{str(event['proto'] or '?')}"
        for event in events if event["dst_port"] is not None
    )
    successes = sum(1 for event in events if event["success"])
    mitre = sorted({_MITRE[event_type] for event_type in types if event_type in _MITRE})

    lines = [
        f"Resumen de honeypot · origen {src_ip} · {hour}:00 UTC",
        f"Eventos observados: {len(events)}",
        "Dispositivos señuelo: " + ", ".join(f"{name} ({count})" for name, count in devices.most_common(6)),
        "Tipos: " + ", ".join(f"{name}={count}" for name, count in types.most_common(8)),
        "Protocolos: " + ", ".join(f"{name}={count}" for name, count in protos.most_common(6)),
    ]
    if targets:
        lines.append("Destinos: " + ", ".join(f"{name}={count}" for name, count in targets.most_common(8)))
    lines.append(f"Accesos aceptados en señuelo: {successes}")
    if mitre:
        lines.append("MITRE ATT&CK probable (inferido, no confirmado): " + ", ".join(mitre))

    if include_payload:
        usernames, commands, urls = _payload_samples(events)
        if usernames:
            lines.append("Usuarios probados (muestra redactada): " + ", ".join(usernames))
        if commands:
            lines.append("Comandos capturados (muestra redactada): " + " | ".join(commands))
        if urls:
            lines.append("URLs solicitadas (muestra redactada): " + " | ".join(urls))
    return sanitize("\n".join(lines), 4000)


def _payload_samples(events: Sequence[sqlite3.Row]) -> tuple[list[str], list[str], list[str]]:
    usernames: list[str] = []
    commands: list[str] = []
    urls: list[str] = []
    for event in events:
        try:
            detail = json.loads(event["detail"] or "{}")
        except (json.JSONDecodeError, TypeError):
            detail = {}
        if not isinstance(detail, dict):
            continue
        user = event["username"] or detail.get("username") or detail.get("user")
        if user and len(usernames) < 8:
            usernames.append(sanitize(str(user), 60))
        for key in ("command", "cmd", "input", "payload"):
            value = detail.get(key)
            if value and len(commands) < 5:
                commands.append(sanitize(str(value), 220))
        for key in ("url", "path", "uri"):
            value = detail.get(key)
            if value and len(urls) < 5:
                urls.append(sanitize(str(value), 180))
    return (
        list(dict.fromkeys(usernames)),
        list(dict.fromkeys(commands)),
        list(dict.fromkeys(urls)),
    )


def _note_text(ip: str, body: dict) -> str:
    lines = [f"Perfil de analista para {ip}"]
    for key, label in (
        ("alias", "Alias"),
        ("classification", "Clasificación"),
        ("handling", "Manejo"),
        ("tags", "Etiquetas"),
        ("notes", "Notas"),
    ):
        value = body.get(key)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(item) for item in value)
        lines.append(f"{label}: {value}")
    text = sanitize("\n".join(lines), 8000)
    return text if len(text) >= 40 else ""


def _knowledge_files(roots: Optional[Sequence[Path]]) -> list[tuple[Path, str]]:
    if roots is None:
        candidates = [settings.BASE_DIR / "docs"]
        candidates.extend(settings.BASE_DIR / name for name in _KNOWLEDGE_FILES)
        candidates.append(settings.BASE_DIR / "deploy" / "honeypots" / "inventory.yaml")
        candidates.extend(Path(item).expanduser() for item in settings.RAG_KNOWLEDGE_DIRS)
    else:
        candidates = [Path(item) for item in roots]

    files: dict[str, Path] = {}
    for candidate in candidates:
        if candidate.is_file():
            paths = [candidate]
        elif candidate.is_dir():
            paths = [p for p in candidate.rglob("*") if p.is_file()]
        else:
            continue
        for path in paths:
            if path.suffix.lower() not in _KNOWLEDGE_SUFFIXES:
                continue
            try:
                key = f"doc:{path.resolve().relative_to(settings.BASE_DIR.resolve())}"
            except ValueError:
                key = f"doc:external:{path.resolve()}"
            files.setdefault(key, path)
    return sorted(((path, key) for key, path in files.items()), key=lambda item: item[1])


def _readonly(path: Path) -> Optional[sqlite3.Connection]:
    if not path.is_file():
        return None
    try:
        conn = sqlite3.connect(f"{path.absolute().as_uri()}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error:
        return None
    conn.row_factory = sqlite3.Row
    return conn
