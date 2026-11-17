"""Tests del RAG local: almacén, recuperación, respuesta y métricas.

No usan red: el embedder y el LLM se sustituyen por dobles deterministas.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core import settings
from app.services.ai.rag import answer, indexer, retriever, service, store
from app.services.ai.rag.chunker import chunk_markdown, chunk_text
from app.services.ai.rag.errors import RagDisabled, RagNotIndexed
from app.services.ai.rag.sanitize import sanitize

DIM = 128


class FakeEmbedder:
    """Bolsa de palabras con hash: determinista y sin dependencias."""

    def __init__(self, dim: int = DIM) -> None:
        self.dim = dim

    def embed(self, texts):
        out = []
        for text in texts:
            vec = [0.0] * self.dim
            for token in re.findall(r"[a-záéíóúñ0-9.]{3,}", text.lower()):
                digest = int(hashlib.sha256(token.encode()).hexdigest(), 16)
                vec[digest % self.dim] += 1.0
            norm = math.sqrt(sum(value * value for value in vec)) or 1.0
            out.append([value / norm for value in vec])
        return out


class FakeLLM:
    def __init__(self, text: str) -> None:
        self.text = text
        self.calls = 0

    def complete(self, system, user, **kwargs):
        self.calls += 1
        assert "EVIDENCIA" in user
        return {"text": self.text, "model": "fake", "usage": {}}


@pytest.fixture()
def rag(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "RAG_ENABLED", True)
    monkeypatch.setattr(settings, "RAG_DB", tmp_path / "rag.db")
    monkeypatch.setattr(settings, "RAG_EMBED_MODEL", "fake")
    monkeypatch.setattr(settings, "RAG_EMBED_DIM", DIM)
    monkeypatch.setattr(settings, "RAG_MIN_SCORE", 0.05)
    conn = store.connect(settings.RAG_DB)
    yield tmp_path, conn, FakeEmbedder()
    conn.close()


def _docs(root: Path, name: str, body: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    path.write_text(body, encoding="utf-8")
    return path


def test_sanitize_redacta_credenciales():
    out = sanitize("password=SuperSecreto token: abc123 user:pass@host")
    assert "SuperSecreto" not in out
    assert "abc123" not in out
    assert "***" in out


def test_chunk_text_respeta_tamano_y_solape():
    text = " ".join(f"Frase numero {i} sobre fuerza bruta SSH." for i in range(60))
    chunks = chunk_text(text, size=300, overlap=60)
    assert len(chunks) > 3
    assert all(len(chunk) <= 300 for chunk in chunks)


def test_chunk_markdown_conserva_encabezados():
    pieces = chunk_markdown("# Título\n\nCuerpo.\n\n## Sección\n\nMás detalle.")
    assert pieces
    assert pieces[-1]["heading"].endswith("Sección")


def test_indexado_idempotente(rag):
    root, conn, embedder = rag
    docs = _docs(root / "docs", "mitre.md", "# T1110\n\nFuerza bruta de credenciales SSH.")
    first = indexer.index_knowledge(conn, embedder, roots=[docs.parent])
    second = indexer.index_knowledge(conn, embedder, roots=[docs.parent])
    assert first["docs"] == 1 and first["chunks"] >= 1
    assert second["docs"] == 0 and second["skipped"] == 1


def test_busqueda_hibrida_y_filtro_por_ip(rag):
    root, conn, embedder = rag
    docs = _docs(
        root / "docs",
        "mitre.md",
        "# T1110\n\nLa fuerza bruta de credenciales SSH genera muchos logins fallidos.",
    )
    indexer.index_knowledge(conn, embedder, roots=[docs.parent])

    notes = root / "investigations.db"
    db = sqlite3.connect(notes)
    db.executescript(
        "CREATE TABLE profiles (source TEXT PRIMARY KEY, revision INTEGER NOT NULL,"
        " body TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL);"
    )
    db.execute(
        "INSERT INTO profiles VALUES(?,?,?,?,?)",
        ("203.0.113.9", 1, json.dumps({"notes": "Fuerza bruta SSH autorizada en laboratorio"}),
         "2026-11-13T19:00:00+00:00", "analista"),
    )
    db.commit()
    db.close()
    assert indexer.index_notes(conn, embedder, path=notes)["docs"] == 1

    result = retriever.search("fuerza bruta SSH", conn=conn, embedder=embedder, k=5)
    assert result["results"]
    assert result["mode"] == "hybrid"

    scoped = retriever.search(
        "fuerza bruta SSH", conn=conn, embedder=embedder, k=5, src_ip="203.0.113.9"
    )
    assert scoped["results"]
    assert {item["kind"] for item in scoped["results"]} == {"note"}


def test_ask_cita_evidencia(rag):
    root, conn, embedder = rag
    docs = _docs(
        root / "docs", "mitre.md",
        "# T1110\n\nLa fuerza bruta SSH se observa como logins fallidos repetidos.",
    )
    indexer.index_knowledge(conn, embedder, roots=[docs.parent])
    llm = FakeLLM("Se observan logins fallidos repetidos [1], compatible con T1110 [1].")
    out = answer.ask("¿Qué indica T1110?", conn=conn, embedder=embedder, llm=llm)
    assert out["grounded"] is True
    assert out["citations"] == [1]
    assert out["evidence"][0]["n"] == 1


def test_ask_incluye_contexto_de_movimientos_como_evidencia(rag):
    _root, conn, embedder = rag
    llm = FakeLLM("El señuelo devolvió la salida del comando id [1].")
    out = answer.ask(
        "¿Qué respondió el señuelo?", conn=conn, embedder=embedder, llm=llm,
        src_ip="203.0.113.7",
        extra_context="Sesión s1 · usuario root\n$ id\n  -> uid=0(root)",
    )
    assert out["grounded"] is True
    assert out["retrieval"]["context"] is True
    assert out["evidence"][0]["kind"] == "movement"
    assert out["evidence"][0]["src_ip"] == "203.0.113.7"
    assert "uid=0(root)" in out["evidence"][0]["text"]


def test_ask_marca_no_fundamentado_sin_citas(rag):
    root, conn, embedder = rag
    docs = _docs(root / "docs", "mitre.md", "# T1110\n\nFuerza bruta SSH con logins fallidos.")
    indexer.index_knowledge(conn, embedder, roots=[docs.parent])
    llm = FakeLLM("Esto es un ataque seguro, sin ninguna cita.")
    out = answer.ask("¿Qué indica T1110?", conn=conn, embedder=embedder, llm=llm)
    assert out["grounded"] is False
    assert out["citations"] == []


def test_ask_se_abstiene_sin_evidencia(rag):
    _root, conn, embedder = rag
    llm = FakeLLM("no debería llamarse")
    out = answer.ask("receta de paella", conn=conn, embedder=embedder, llm=llm)
    assert out["abstained"] is True
    assert llm.calls == 0


def test_eventos_no_indexan_payload_por_defecto(rag, tmp_path):
    _root, conn, embedder = rag
    events = tmp_path / "deception.db"
    db = sqlite3.connect(events)
    db.executescript(
        "CREATE TABLE deception_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,"
        " device_id TEXT NOT NULL, src_ip TEXT NOT NULL, src_port INTEGER, dst_ip TEXT,"
        " dst_port INTEGER, proto TEXT DEFAULT '', event_type TEXT NOT NULL, username TEXT,"
        " success INTEGER, detail TEXT DEFAULT '{}');"
    )
    db.execute(
        "INSERT INTO deception_events(ts,device_id,src_ip,src_port,dst_port,proto,event_type,"
        "username,success,detail) VALUES(?,?,?,?,?,?,?,?,?,?)",
        ("2026-11-13T18:01:00+00:00", "srv-01", "203.0.113.9", 22, 2222, "ssh",
         "login_attempt", "root", 0,
         json.dumps({"command": "hydra -l root -P pass.txt", "password": "hunter2"})),
    )
    db.commit()
    db.close()

    indexer.index_events(conn, embedder, path=events, include_payload=False)
    text = " ".join(
        row[0] for row in conn.execute(
            "SELECT c.text FROM rag_chunks c JOIN rag_docs d ON d.id=c.doc_id WHERE d.kind='event'"
        )
    )
    assert "hydra" not in text and "hunter2" not in text
    assert "intentos de acceso=1" in text

    indexer.index_events(conn, embedder, path=events, include_payload=True, force=True)
    text = " ".join(
        row[0] for row in conn.execute(
            "SELECT c.text FROM rag_chunks c JOIN rag_docs d ON d.id=c.doc_id WHERE d.kind='event'"
        )
    )
    assert "hydra" in text
    assert "hunter2" not in text


def test_triage_estructurado(rag):
    root, conn, embedder = rag
    docs = _docs(root / "docs", "mitre.md", "# T1110\n\nFuerza bruta SSH con logins fallidos.")
    indexer.index_knowledge(conn, embedder, roots=[docs.parent])
    payload = {
        "verdict": "suspicious", "confidence": 0.72, "mitre": ["T1110"],
        "observed": ["logins fallidos repetidos [1]"], "inferred": ["posible fuerza bruta [1]"],
        "missing": ["número de intentos en la ventana"], "recommended_actions": ["revisar [1]"],
    }
    llm = FakeLLM(json.dumps(payload))
    out = answer.ask("Clasificá fuerza bruta SSH", conn=conn, embedder=embedder, llm=llm, mode="triage")
    assert out["structured"]["verdict"] == "suspicious"
    assert out["structured"]["confidence"] == 0.72
    assert out["structured"]["mitre"] == ["T1110"]


def test_feedback_calcula_precision_y_recall(rag):
    _root, conn, _embedder = rag
    for predicted, label in (
        ("malicious", "true_positive"),
        ("malicious", "false_positive"),
        ("benign", "true_positive"),
        ("benign", "false_positive"),
    ):
        store.add_feedback(conn, question="caso", predicted=predicted, label=label)
    metrics = store.feedback_metrics(conn)
    assert (metrics["tp"], metrics["fp"], metrics["fn"], metrics["tn"]) == (1, 1, 1, 1)
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1"] == 0.5


def test_prune_elimina_conocimiento_borrado(rag):
    root, conn, embedder = rag
    docs = root / "docs"
    first = _docs(docs, "uno.md", "# Uno\n\nContenido suficientemente largo sobre SSH.")
    _docs(docs, "dos.md", "# Dos\n\nOtro contenido suficientemente largo sobre T1110.")
    indexer.index_knowledge(conn, embedder, roots=[docs])
    first.unlink()
    stats = indexer.index_knowledge(conn, embedder, roots=[docs])
    assert stats["pruned"] == 1
    assert store.stats(conn)["docs_by_kind"].get("knowledge") == 1


def test_service_falla_cerrado(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "RAG_ENABLED", False)
    with pytest.raises(RagDisabled):
        service.search("ssh")

    monkeypatch.setattr(settings, "RAG_ENABLED", True)
    monkeypatch.setattr(settings, "RAG_DB", tmp_path / "missing.db")
    with pytest.raises(RagNotIndexed):
        service.search("ssh")


def test_status_no_crea_el_indice(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "RAG_ENABLED", True)
    monkeypatch.setattr(settings, "RAG_DB", tmp_path / "nope.db")
    status = service.status()
    assert status["enabled"] is True
    assert status["indexed"] is False
    assert not (tmp_path / "nope.db").exists()


def test_hallazgos_se_listan_y_se_acknowledgen(rag):
    _root, conn, _embedder = rag
    finding = store.add_finding(
        conn, src_ip="203.0.113.9", verdict="suspicious", confidence=0.7,
        severity="medium", title="Actividad sospechosa", summary="Resumen",
        evidence=[{"n": 1, "text": "evidencia"}], dedupe_key="ai:203.0.113.9",
    )
    assert finding["id"] > 0
    assert store.stats(conn)["unacked_findings"] == 1
    assert store.list_findings(conn)[0]["src_ip"] == "203.0.113.9"
    assert store.ack_finding(conn, finding["id"], "analista") is True
    assert store.stats(conn)["unacked_findings"] == 0
    assert store.list_findings(conn, unacked_only=True) == []


def _events_db(path: Path, rows: int = 12) -> Path:
    db = sqlite3.connect(path)
    db.executescript(
        "CREATE TABLE deception_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,"
        " device_id TEXT NOT NULL, src_ip TEXT NOT NULL, src_port INTEGER, dst_ip TEXT,"
        " dst_port INTEGER, proto TEXT DEFAULT '', event_type TEXT NOT NULL, username TEXT,"
        " success INTEGER, detail TEXT DEFAULT '{}');"
    )
    now = "2026-11-13T18:0"
    for index in range(rows):
        success = 1 if index == rows - 1 else 0
        db.execute(
            "INSERT INTO deception_events(ts,device_id,src_ip,src_port,dst_port,proto,event_type,"
            "username,success,detail) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (f"{now}{index % 9}:00+00:00", "srv-01", "203.0.113.9", 5000 + index, 2222,
             "ssh", "login_success" if success else "login_attempt", "root", success,
             json.dumps({"command": "hydra -l root -P pass.txt"})),
        )
    db.commit()
    db.close()
    return path


def test_monitor_crea_hallazgo_y_notifica(rag, tmp_path, monkeypatch):
    _root, _conn, embedder = rag
    events = _events_db(tmp_path / "deception.db")
    monkeypatch.setattr(settings, "DECEPTION_DB", events)
    monkeypatch.setattr(settings, "RAG_MONITOR_MIN_EVENTS", 5)
    monkeypatch.setattr(settings, "RAG_MONITOR_MIN_SCORE", 2)
    monkeypatch.setattr(settings, "RAG_MONITOR_MIN_CONFIDENCE", 0.5)
    monkeypatch.setattr(settings, "RAG_MONITOR_COOLDOWN_MIN", 60)

    triage = {
        "verdict": "malicious", "confidence": 0.91, "mitre": ["T1110"],
        "observed": ["12 intentos de login [1]", "un acceso aceptado [1]"],
        "inferred": ["fuerza bruta SSH [1]"], "missing": [],
        "recommended_actions": ["revisar el señuelo [1]"],
    }

    from app.services.ai.rag import monitor

    monkeypatch.setattr(monitor, "get_embedder", lambda: embedder)
    monkeypatch.setattr(monitor, "get_llm", lambda: FakeLLM(json.dumps(triage)))

    from app.services import notifications_svc

    sent: list[tuple] = []
    monkeypatch.setattr(notifications_svc, "has_channels", lambda event: True)
    monkeypatch.setattr(
        notifications_svc, "notify_event", lambda event, data: sent.append((event, data))
    )

    result = monitor.scan(notify=True)
    assert result["events_new"] == 12
    assert result["findings"] == 1
    assert result["notified"] == 1
    assert sent and sent[0][0] == "ai_finding"
    assert sent[0][1]["src_ip"] == "203.0.113.9"

    second = monitor.scan(notify=True)
    assert second["events_new"] == 0
    assert second["skipped_cooldown"] == 0


def test_monitor_cae_a_reglas_si_el_modelo_falla(rag, tmp_path, monkeypatch):
    _root, _conn, embedder = rag
    events = _events_db(tmp_path / "deception.db")
    monkeypatch.setattr(settings, "DECEPTION_DB", events)
    monkeypatch.setattr(settings, "RAG_MONITOR_MIN_EVENTS", 5)
    monkeypatch.setattr(settings, "RAG_MONITOR_MIN_SCORE", 2)

    from app.services.ai.rag import monitor
    from app.services.ai.rag.errors import RagUnavailable

    monkeypatch.setattr(monitor, "get_embedder", lambda: embedder)

    class BrokenLLM:
        def complete(self, system, user, **kwargs):
            raise RagUnavailable("modelo caído")

    monkeypatch.setattr(monitor, "get_llm", lambda: BrokenLLM())

    result = monitor.scan(notify=False)
    assert result["findings"] == 1
    findings = store.list_findings(store.connect(settings.RAG_DB))
    assert findings[0]["source"] == "rules"
    assert findings[0]["verdict"] in {"suspicious", "malicious"}


def test_api_findings_status_y_ack(tmp_path, monkeypatch):
    """La API exige sesión y rol, y devuelve/actualiza los hallazgos."""
    from fastapi.testclient import TestClient

    from app.core.limiter import limiter
    from app.core.security import hash_password
    from app.main import app
    from app.middleware import audit
    from app.routers import admin_users, auth

    monkeypatch.setattr(limiter, "enabled", False)
    monkeypatch.setattr(audit, "_log_async", lambda **kwargs: None)
    users = tmp_path / "users.yaml"
    users.write_text(
        "users:\n" + "".join(
            f"- username: {role}\n  role: {role}\n  name: {role}\n"
            f"  password_hash: {hash_password('synthetic-password-0123456789')}\n"
            for role in ("admin", "operator", "viewer")
        ),
        encoding="utf-8",
    )
    users.chmod(0o600)
    monkeypatch.setattr(auth, "USERS_FILE", users)
    monkeypatch.setattr(admin_users, "USERS_FILE", users)
    monkeypatch.setattr(settings, "RAG_ENABLED", True)
    monkeypatch.setattr(settings, "RAG_DB", tmp_path / "api-rag.db")

    conn = store.connect(settings.RAG_DB)
    store.add_finding(
        conn, src_ip="203.0.113.9", verdict="malicious", confidence=0.9,
        severity="high", title="Hallazgo API", summary="Resumen", dedupe_key="api:1",
    )
    conn.close()

    with TestClient(app) as client:
        tokens = {}
        for role in ("admin", "operator", "viewer"):
            response = client.post(
                "/api/auth/login",
                json={"username": role, "password": "synthetic-password-0123456789"},
            )
            assert response.status_code == 200, response.text
            tokens[role] = {"Authorization": f"Bearer {response.json()['access_token']}"}

        status_response = client.get("/api/ai/rag/status", headers=tokens["viewer"])
        assert status_response.status_code == 200
        assert status_response.json()["enabled"] is True

        found = client.get("/api/ai/rag/findings", headers=tokens["viewer"])
        assert found.status_code == 200
        assert found.json()["items"][0]["title"] == "Hallazgo API"

        denied = client.post("/api/ai/rag/findings/1/ack", json={}, headers=tokens["viewer"])
        assert denied.status_code == 403
        acked = client.post("/api/ai/rag/findings/1/ack", json={}, headers=tokens["operator"])
        assert acked.status_code == 200
        assert acked.json()["ack"] is True

        # La ficha puede pedir que se adjunten los movimientos del señuelo.
        from app.routers import ai_rag

        captured: dict = {}
        monkeypatch.setattr(
            ai_rag, "movement_context",
            lambda ip: f"Sesión s1 · usuario root\n$ id\n  -> uid=0(root) ({ip})",
        )
        monkeypatch.setattr(
            ai_rag.service, "ask",
            lambda question, **kwargs: captured.update(kwargs) or {"answer": "ok"},
        )
        asked = client.post(
            "/api/ai/rag/ask",
            json={
                "question": "¿Qué respondió el señuelo?",
                "src_ip": "203.0.113.9",
                "include_movements": True,
            },
            headers=tokens["viewer"],
        )
        assert asked.status_code == 200
        assert captured["src_ip"] == "203.0.113.9"
        assert captured["extra_context"].startswith("Sesión s1")
        plain = client.post(
            "/api/ai/rag/ask",
            json={"question": "¿Qué pasó?", "src_ip": "203.0.113.9"},
            headers=tokens["viewer"],
        )
        assert plain.status_code == 200
        assert captured["extra_context"] is None

