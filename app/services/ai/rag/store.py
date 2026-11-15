"""Almacén SQLite del RAG: documentos, fragmentos, FTS5 y vectores.

Un solo archivo, sin servidores extra. La búsqueda léxica usa FTS5 y la
semántica un recorrido de vectores normalizados; el recuperador fusiona ambas.

Límite conocido: el recorrido vectorial es lineal en número de fragmentos.
``NETPULSE_RAG_MAX_VECTORS`` corta antes de agotar memoria; para volúmenes
mayores, migrar a ``sqlite-vec`` manteniendo este contrato.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

from app.services.ai.rag import vectors as vec_utils
from app.services.ai.rag.chunker import estimate_tokens
from app.services.ai.rag.errors import RagUnavailable
from app.services.ai.rag.sanitize import sanitize

SCHEMA = """
CREATE TABLE IF NOT EXISTS rag_docs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    src_ip TEXT,
    ts TEXT,
    sha256 TEXT NOT NULL,
    meta TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS rag_docs_kind ON rag_docs(kind);
CREATE INDEX IF NOT EXISTS rag_docs_src ON rag_docs(src_ip);
CREATE TABLE IF NOT EXISTS rag_chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_id INTEGER NOT NULL REFERENCES rag_docs(id) ON DELETE CASCADE,
    ord INTEGER NOT NULL,
    text TEXT NOT NULL,
    heading TEXT NOT NULL DEFAULT '',
    sha256 TEXT NOT NULL,
    UNIQUE(doc_id, ord)
);
CREATE INDEX IF NOT EXISTS rag_chunks_doc ON rag_chunks(doc_id);
CREATE TABLE IF NOT EXISTS rag_vectors (
    chunk_id INTEGER PRIMARY KEY REFERENCES rag_chunks(id) ON DELETE CASCADE,
    dim INTEGER NOT NULL,
    norm REAL NOT NULL,
    vec BLOB NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS rag_fts USING fts5(
    text,
    tokenize = 'unicode61 remove_diacritics 2'
);
CREATE TABLE IF NOT EXISTS rag_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    question TEXT NOT NULL,
    src_ip TEXT NOT NULL DEFAULT '',
    predicted TEXT NOT NULL,
    label TEXT NOT NULL,
    analyst TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS rag_feedback_ts ON rag_feedback(ts);
CREATE TABLE IF NOT EXISTS rag_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    src_ip TEXT,
    verdict TEXT NOT NULL,
    confidence REAL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '[]',
    model TEXT,
    source TEXT NOT NULL DEFAULT 'ai',
    dedupe_key TEXT NOT NULL DEFAULT '',
    notified INTEGER NOT NULL DEFAULT 0,
    ack INTEGER NOT NULL DEFAULT 0,
    ack_by TEXT,
    ack_at TEXT
);
CREATE INDEX IF NOT EXISTS rag_findings_ts ON rag_findings(ts DESC);
CREATE INDEX IF NOT EXISTS rag_findings_dedupe ON rag_findings(dedupe_key, ts DESC);
CREATE INDEX IF NOT EXISTS rag_findings_ack ON rag_findings(ack);
CREATE TABLE IF NOT EXISTS rag_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_STOPWORDS = frozenset(
    "a al algo como con de del el ella en es esa ese eso esta este esto fue ha hasta la las le "
    "les lo los mas más me mi muy no o para pero por que qué se si sin sobre su sus te tu un una "
    "y ya yo the a an and are as at be by for from has have in is it its of on or that this to "
    "was were with".split()
)
_TOKEN = re.compile(r"[^\W_]{2,}", re.UNICODE)
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Abre (y crea) el índice con WAL, claves foráneas y timeout."""
    path = Path(db_path)
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    ensure_schema(conn)
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def exists(db_path: str | Path) -> bool:
    return Path(db_path).is_file()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _doc_sha(
    kind: str,
    source: str,
    src_ip: Optional[str],
    ts: Optional[str],
    meta: dict,
    texts: Sequence[str],
) -> str:
    blob = json.dumps(
        {"kind": kind, "source": source, "src_ip": src_ip, "ts": ts, "meta": meta,
         "texts": list(texts)},
        sort_keys=True, ensure_ascii=False, default=str,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def upsert_doc(
    conn: sqlite3.Connection,
    *,
    doc_key: str,
    kind: str,
    chunks: Sequence[dict],
    embedder,
    source: str = "",
    src_ip: Optional[str] = None,
    ts: Optional[str] = None,
    meta: Optional[dict] = None,
    force: bool = False,
) -> dict:
    """Indexa (o reemplaza) un documento y sus vectores.

    Los embeddings se calculan antes de abrir la transacción: si el modelo
    falla, el índice anterior queda intacto.
    """
    meta = meta or {}
    prepared = _prepare(chunks)
    if not prepared:
        return {"status": "empty", "doc_key": doc_key, "chunks": 0}

    texts = [item["text"] for item in prepared]
    sha = _doc_sha(kind, source, src_ip, ts, meta, texts)
    row = conn.execute("SELECT id, sha256 FROM rag_docs WHERE doc_key=?", (doc_key,)).fetchone()
    if row and row["sha256"] == sha and not force:
        return {"status": "skipped", "doc_key": doc_key, "chunks": 0}

    embed_inputs = [
        f"{item['heading']}\n{item['text']}" if item["heading"] else item["text"]
        for item in prepared
    ]
    raw_vectors = embedder.embed(embed_inputs)
    if len(raw_vectors) != len(prepared):
        raise RagUnavailable("el embedder devolvió menos vectores que fragmentos")

    with conn:
        if row:
            _delete_chunks(conn, int(row["id"]))
            conn.execute("DELETE FROM rag_docs WHERE id=?", (int(row["id"]),))
        cursor = conn.execute(
            "INSERT INTO rag_docs(doc_key,kind,source,src_ip,ts,sha256,meta,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (doc_key, kind, source, src_ip, ts, sha,
             json.dumps(meta, ensure_ascii=False, default=str), _now()),
        )
        doc_id = int(cursor.lastrowid or 0)
        for order, (item, raw) in enumerate(zip(prepared, raw_vectors)):
            unit, norm = vec_utils.normalize(raw)
            chunk = conn.execute(
                "INSERT INTO rag_chunks(doc_id,ord,text,heading,sha256) VALUES(?,?,?,?,?)",
                (doc_id, order, item["text"], item["heading"],
                 hashlib.sha256(item["text"].encode("utf-8")).hexdigest()),
            )
            chunk_id = int(chunk.lastrowid or 0)
            conn.execute(
                "INSERT INTO rag_vectors(chunk_id,dim,norm,vec) VALUES(?,?,?,?)",
                (chunk_id, len(unit), norm, vec_utils.pack(unit)),
            )
            conn.execute(
                "INSERT INTO rag_fts(rowid,text) VALUES(?,?)",
                (chunk_id, f"{item['heading']} {item['text']}".strip()),
            )
    return {"status": "indexed", "doc_key": doc_key, "chunks": len(prepared)}


def delete_doc(conn: sqlite3.Connection, doc_key: str) -> bool:
    row = conn.execute("SELECT id FROM rag_docs WHERE doc_key=?", (doc_key,)).fetchone()
    if not row:
        return False
    with conn:
        _delete_chunks(conn, int(row["id"]))
        conn.execute("DELETE FROM rag_docs WHERE id=?", (int(row["id"]),))
    return True


def prune_kind(conn: sqlite3.Connection, kind: str, keep_keys: set[str]) -> int:
    """Elimina documentos de un tipo que ya no existen en la fuente."""
    rows = conn.execute("SELECT doc_key FROM rag_docs WHERE kind=?", (kind,)).fetchall()
    stale = [str(row["doc_key"]) for row in rows if str(row["doc_key"]) not in keep_keys]
    for key in stale:
        delete_doc(conn, key)
    return len(stale)


def keyword_search(
    conn: sqlite3.Connection,
    query: str,
    limit: int = 40,
    *,
    kinds: Optional[Sequence[str]] = None,
    src_ip: Optional[str] = None,
) -> list[tuple[int, float]]:
    """Búsqueda FTS5; devuelve ``(chunk_id, rank)`` en orden de relevancia."""
    tokens = _query_tokens(query)
    if not tokens:
        return []
    match = " OR ".join(f'"{token}"' for token in tokens[:12])
    sql = (
        "SELECT f.rowid, bm25(rag_fts) AS rank FROM rag_fts f "
        "JOIN rag_chunks c ON c.id=f.rowid JOIN rag_docs d ON d.id=c.doc_id "
        "WHERE rag_fts MATCH ?"
    )
    params: list[Any] = [match]
    if kinds:
        sql += f" AND d.kind IN ({','.join('?' for _ in kinds)})"
        params.extend(kinds)
    if src_ip:
        sql += " AND d.src_ip=?"
        params.append(src_ip)
    sql += " ORDER BY rank LIMIT ?"
    params.append(limit)
    try:
        rows = conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []
    return [(int(row["rowid"]), float(row["rank"])) for row in rows]


def vector_search(
    conn: sqlite3.Connection,
    query_vector: Sequence[float],
    limit: int = 40,
    *,
    kinds: Optional[Sequence[str]] = None,
    src_ip: Optional[str] = None,
    max_vectors: int = 100_000,
) -> list[tuple[int, float]]:
    """Similitud coseno sobre todos los fragmentos (vectores normalizados)."""
    total = int(conn.execute("SELECT COUNT(*) FROM rag_vectors").fetchone()[0])
    if total > max_vectors:
        raise RagUnavailable(
            f"índice con {total} vectores supera NETPULSE_RAG_MAX_VECTORS={max_vectors}; "
            "reduzca la ventana o migre a sqlite-vec"
        )
    sql = (
        "SELECT v.chunk_id, v.vec FROM rag_vectors v "
        "JOIN rag_chunks c ON c.id=v.chunk_id "
        "JOIN rag_docs d ON d.id=c.doc_id"
    )
    where: list[str] = []
    params: list[Any] = []
    if kinds:
        where.append(f"d.kind IN ({','.join('?' for _ in kinds)})")
        params.extend(kinds)
    if src_ip:
        where.append("d.src_ip=?")
        params.append(src_ip)
    if where:
        sql += " WHERE " + " AND ".join(where)

    scored = (
        (vec_utils.dot_unit(vec_utils.unpack(row["vec"]), query_vector), int(row["chunk_id"]))
        for row in conn.execute(sql, params)
    )
    return [(chunk_id, round(score, 6)) for score, chunk_id in heapq.nlargest(limit, scored)]


def fetch_chunks(conn: sqlite3.Connection, chunk_ids: Sequence[int]) -> dict[int, dict]:
    """Recupera metadatos y texto de los fragmentos pedidos."""
    out: dict[int, dict] = {}
    ids = [int(value) for value in chunk_ids]
    for start in range(0, len(ids), 500):
        batch = ids[start : start + 500]
        if not batch:
            continue
        placeholders = ",".join("?" for _ in batch)
        rows = conn.execute(
            "SELECT c.id, c.text, c.heading, c.ord, d.doc_key, d.kind, d.source, "
            "d.src_ip, d.ts, d.meta FROM rag_chunks c "
            f"JOIN rag_docs d ON d.id=c.doc_id WHERE c.id IN ({placeholders})",
            batch,
        ).fetchall()
        for row in rows:
            out[int(row["id"])] = {
                "chunk_id": int(row["id"]),
                "doc_key": row["doc_key"],
                "kind": row["kind"],
                "source": row["source"],
                "src_ip": row["src_ip"],
                "ts": row["ts"],
                "heading": row["heading"] or "",
                "text": row["text"],
                "ord": int(row["ord"]),
                "tokens": estimate_tokens(row["text"]),
            }
    return out


def stats(conn: sqlite3.Connection) -> dict:
    docs = int(conn.execute("SELECT COUNT(*) FROM rag_docs").fetchone()[0])
    chunks = int(conn.execute("SELECT COUNT(*) FROM rag_chunks").fetchone()[0])
    feedback = int(conn.execute("SELECT COUNT(*) FROM rag_feedback").fetchone()[0])
    findings = int(conn.execute("SELECT COUNT(*) FROM rag_findings").fetchone()[0])
    unacked = int(conn.execute("SELECT COUNT(*) FROM rag_findings WHERE ack=0").fetchone()[0])
    by_kind = {
        str(row["kind"]): int(row["total"])
        for row in conn.execute(
            "SELECT kind, COUNT(*) AS total FROM rag_docs GROUP BY kind ORDER BY kind"
        )
    }
    updated = conn.execute("SELECT MAX(updated_at) FROM rag_docs").fetchone()[0]
    return {
        "docs": docs,
        "chunks": chunks,
        "feedback": feedback,
        "findings": findings,
        "unacked_findings": unacked,
        "docs_by_kind": by_kind,
        "updated_at": updated,
    }


def meta_get(conn: sqlite3.Connection, key: str) -> Optional[str]:
    row = conn.execute("SELECT value FROM rag_meta WHERE key=?", (key,)).fetchone()
    return str(row["value"]) if row else None


def meta_set(conn: sqlite3.Connection, key: str, value: str) -> None:
    with conn:
        conn.execute(
            "INSERT INTO rag_meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def add_feedback(
    conn: sqlite3.Connection,
    *,
    question: str,
    predicted: str,
    label: str,
    analyst: str = "",
    src_ip: str = "",
    notes: str = "",
) -> dict:
    predicted = predicted.strip().lower()
    label = label.strip().lower()
    if predicted not in {"malicious", "suspicious", "benign", "unknown"}:
        raise ValueError("predicted debe ser malicious|suspicious|benign|unknown")
    if label not in {"true_positive", "false_positive"}:
        raise ValueError("label debe ser true_positive|false_positive")
    with conn:
        cursor = conn.execute(
            "INSERT INTO rag_feedback(ts,question,src_ip,predicted,label,analyst,notes) "
            "VALUES(?,?,?,?,?,?,?)",
            (_now(), sanitize(question, 1000), src_ip, predicted, label,
             sanitize(analyst, 120), sanitize(notes, 2000)),
        )
    return {"id": int(cursor.lastrowid or 0), "predicted": predicted, "label": label}


def feedback_metrics(conn: sqlite3.Connection) -> dict:
    """Precisión y recall por separado, a partir de etiquetas del analista."""
    rows = conn.execute(
        "SELECT predicted, label, COUNT(*) AS total FROM rag_feedback GROUP BY predicted, label"
    ).fetchall()
    tp = fp = fn = tn = 0
    for row in rows:
        positive = str(row["predicted"]) in {"malicious", "suspicious"}
        truth = str(row["label"]) == "true_positive"
        count = int(row["total"])
        if positive and truth:
            tp += count
        elif positive and not truth:
            fp += count
        elif not positive and truth:
            fn += count
        else:
            tn += count

    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    if precision is not None and recall is not None and precision + recall:
        f1: Optional[float] = 2 * precision * recall / (precision + recall)
    else:
        f1 = None
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
        "labeled": tp + fp + fn + tn,
        "note": "muestra pequeña: no interpretar sin al menos 30 casos etiquetados",
    }


def add_finding(
    conn: sqlite3.Connection,
    *,
    src_ip: Optional[str],
    verdict: str,
    confidence: Optional[float],
    severity: str,
    title: str,
    summary: str,
    evidence: Optional[Sequence[dict]] = None,
    model: Optional[str] = None,
    source: str = "ai",
    dedupe_key: str = "",
) -> dict:
    """Persiste un hallazgo proactivo del monitor de IA."""
    evidence_json = json.dumps(list(evidence or [])[:8], ensure_ascii=False, default=str)[:12000]
    created = _now()
    with conn:
        cursor = conn.execute(
            "INSERT INTO rag_findings(ts,src_ip,verdict,confidence,severity,title,summary,"
            "evidence,model,source,dedupe_key) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                created, src_ip, verdict, confidence, severity,
                sanitize(title, 240), sanitize(summary, 2400),
                evidence_json, model, source, dedupe_key,
            ),
        )
    return {
        "id": int(cursor.lastrowid or 0),
        "ts": created,
        "src_ip": src_ip,
        "verdict": verdict,
        "confidence": confidence,
        "severity": severity,
        "title": sanitize(title, 240),
        "summary": sanitize(summary, 2400),
        "evidence": list(evidence or [])[:8],
        "model": model,
        "source": source,
        "dedupe_key": dedupe_key,
        "notified": 0,
        "ack": 0,
    }


def list_findings(
    conn: sqlite3.Connection, limit: int = 50, *, unacked_only: bool = False
) -> list[dict]:
    """Lista hallazgos, más recientes primero."""
    sql = "SELECT * FROM rag_findings"
    if unacked_only:
        sql += " WHERE ack=0"
    sql += " ORDER BY id DESC LIMIT ?"
    rows = conn.execute(sql, (max(1, min(limit, 200)),)).fetchall()
    return [_finding_row(row) for row in rows]


def ack_finding(conn: sqlite3.Connection, finding_id: int, actor: str) -> bool:
    """Marca un hallazgo como revisado por un humano."""
    with conn:
        cursor = conn.execute(
            "UPDATE rag_findings SET ack=1, ack_by=?, ack_at=? WHERE id=?",
            (sanitize(actor, 120), _now(), finding_id),
        )
    return bool(cursor.rowcount)


def recent_finding(
    conn: sqlite3.Connection, dedupe_key: str, minutes: int
) -> Optional[dict]:
    """Devuelve el hallazgo más reciente de la misma clave dentro de la ventana."""
    if not dedupe_key:
        return None
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=max(1, minutes))
    row = conn.execute(
        "SELECT * FROM rag_findings WHERE dedupe_key=? AND ts>=? ORDER BY id DESC LIMIT 1",
        (dedupe_key, cutoff.isoformat()),
    ).fetchone()
    return _finding_row(row) if row else None


def mark_notified(conn: sqlite3.Connection, finding_id: int) -> None:
    with conn:
        conn.execute("UPDATE rag_findings SET notified=1 WHERE id=?", (finding_id,))


def _finding_row(row: sqlite3.Row) -> dict:
    try:
        evidence = json.loads(row["evidence"] or "[]")
    except json.JSONDecodeError:
        evidence = []
    return {
        "id": int(row["id"]),
        "ts": row["ts"],
        "src_ip": row["src_ip"],
        "verdict": row["verdict"],
        "confidence": row["confidence"],
        "severity": row["severity"],
        "title": row["title"],
        "summary": row["summary"],
        "evidence": evidence if isinstance(evidence, list) else [],
        "model": row["model"],
        "source": row["source"],
        "dedupe_key": row["dedupe_key"],
        "notified": bool(row["notified"]),
        "ack": bool(row["ack"]),
        "ack_by": row["ack_by"],
        "ack_at": row["ack_at"],
    }


def _prepare(chunks: Sequence[dict]) -> list[dict]:
    prepared: list[dict] = []
    for chunk in chunks:
        text = sanitize(str(chunk.get("text") or ""), 4000)
        if not text:
            continue
        prepared.append({"text": text, "heading": sanitize(str(chunk.get("heading") or ""), 200)})
    return prepared


def _delete_chunks(conn: sqlite3.Connection, doc_id: int) -> None:
    rows = conn.execute("SELECT id FROM rag_chunks WHERE doc_id=?", (doc_id,)).fetchall()
    for row in rows:
        conn.execute("DELETE FROM rag_fts WHERE rowid=?", (int(row["id"]),))
    conn.execute("DELETE FROM rag_chunks WHERE doc_id=?", (doc_id,))


def _query_tokens(query: str) -> list[str]:
    seen: set[str] = set()
    tokens: list[str] = []
    text = query or ""
    # Las IPs se conservan enteras: FTS5 las vuelve a tokenizar por puntos y
    # una frase entrecomillada mantiene la adyacencia.
    for match in _IPV4.finditer(text):
        token = match.group(0)
        if token not in seen:
            seen.add(token)
            tokens.append(token)
    for match in _TOKEN.finditer(_IPV4.sub(" ", text)):
        token = match.group(0).lower()
        if token in _STOPWORDS or token.isdigit() or token in seen:
            continue
        seen.add(token)
        tokens.append(token)
    return tokens
