"""Pruebas del forwarder de eventos JSONL → control (Fase 5b).

Sin red real: transporte falso de httpx. Cubren offsets persistentes
(no duplica, no pierde), archivo truncado, línea parcial, lotes de 100,
backoff ante 503, descarte de 4xx permanente, líneas inválidas, estado
para /status y modo deshabilitado.
"""

import json
import logging
import sys
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.services.fabric.event_forwarder import (  # noqa: E402
    EventForwarder,
    forwarder_from_env,
)

URL = "http://control.test:8082/api/fabric/events"
TOKEN = "t" * 40


class FakeTransport(httpx.BaseTransport):
    """Transporte falso: cuenta peticiones y responde según un plan."""

    def __init__(self, script=None):
        # script: lista de estados; el último se repite. None = 200.
        self.requests: list[dict] = []
        self.script = list(script) if script is not None else None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        self.requests.append({
            "url": str(request.url),
            "token": request.headers.get("x-fabric-token"),
            "events": body.get("events", []),
        })
        status = 200
        if self.script:
            status = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        return httpx.Response(200 if status == 200 else status, json={"accepted": 0})


def _write_events(path: Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")


def _event(index: int, device_id: str = "pc-01") -> dict:
    return {
        "ts": "2026-11-15T20:00:00+00:00",
        "device_id": device_id,
        "src_ip": "203.0.113.9",
        "src_port": 4242,
        "proto": "ssh",
        "type": "connect",
        "detail": {},
        "username": None,
        "success": False,
        "n": index,
    }


def _forwarder(tmp_path: Path, transport: FakeTransport, **kwargs) -> EventForwarder:
    defaults = dict(
        devices_dir=tmp_path / "logs",
        state_path=tmp_path / "forwarder-state.json",
        url=URL,
        token=TOKEN,
        interval=0.1,
        backoff=0,  # tests: sin esperas
        client=httpx.Client(transport=transport, timeout=2),
    )
    defaults.update(kwargs)
    return EventForwarder(**defaults)


# ── Offsets: no duplica, no pierde ─────────────────────────


def test_envia_y_comite_offset(tmp_path):
    log = tmp_path / "logs" / "pc-01" / "events.jsonl"
    _write_events(log, [_event(1), _event(2)])
    transport = FakeTransport()
    forwarder = _forwarder(tmp_path, transport)

    result = forwarder.run_once()
    assert result["sent"] == 2
    assert transport.requests[0]["token"] == TOKEN
    assert transport.requests[0]["url"] == URL

    # Sin duplicar: nuevo ciclo no reenvía.
    assert forwarder.run_once()["sent"] == 0
    assert len(transport.requests) == 1

    # Estado persistido: un forwarder nuevo no reenvía (no pierde ni duplica).
    fresh = _forwarder(tmp_path, FakeTransport())
    assert fresh.run_once()["sent"] == 0


def test_no_pierde_eventos_si_el_envio_falla(tmp_path):
    log = tmp_path / "logs" / "pc-01" / "events.jsonl"
    _write_events(log, [_event(1)])
    transport = FakeTransport(script=[503, 503, 503, 503])
    forwarder = _forwarder(tmp_path, transport)

    first = forwarder.run_once()
    assert first["sent"] == 0
    assert first["error"] and "503" in first["error"]
    assert forwarder.status()["pending"] == 1

    # El siguiente ciclo reintenta (offset sin confirmar) y ahora sí.
    transport.script = [200]
    second = forwarder.run_once()
    assert second["sent"] == 1
    assert forwarder.status()["sent"] == 1
    assert forwarder.run_once()["sent"] == 0


def test_archivo_truncado_reinicia_offset(tmp_path):
    log = tmp_path / "logs" / "pc-01" / "events.jsonl"
    _write_events(log, [_event(1), _event(2)])
    transport = FakeTransport()
    forwarder = _forwarder(tmp_path, transport)
    assert forwarder.run_once()["sent"] == 2

    # El log se trunca (rotación): el offset queda más allá del tamaño.
    log.write_text(json.dumps(_event(3)) + "\n", encoding="utf-8")
    result = forwarder.run_once()
    assert result["sent"] == 1
    assert [request["events"][0]["n"] for request in transport.requests[1:]] == [3]


def test_rotacion_copytruncate_no_pierde_ni_duplica(tmp_path):
    """Simula logrotate con ``copytruncate`` (copia + truncado del mismo inodo).

    El agente mantiene el descriptor abierto en append: tras la rotación el
    inodo se vacía y el agente sigue escribiendo en él. El forwarder debe
    releer desde 0 y enviar exactamente los eventos nuevos.
    """
    log = tmp_path / "logs" / "pc-01" / "events.jsonl"
    _write_events(log, [_event(1), _event(2)])
    transport = FakeTransport()
    forwarder = _forwarder(tmp_path, transport)
    assert forwarder.run_once()["sent"] == 2

    # copytruncate: copia el contenido y trunca el MISMO inodo (no renombra).
    rotated = log.with_name("events.jsonl.1")
    rotated.write_bytes(log.read_bytes())
    with open(log, "r+b") as handle:
        handle.truncate(0)
    # El agente sigue escribiendo en el descriptor original (append).
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(_event(3)) + "\n")
        handle.write(json.dumps(_event(4)) + "\n")

    result = forwarder.run_once()
    assert result["sent"] == 2
    sent = [event["n"] for request in transport.requests[1:] for event in request["events"]]
    assert sent == [3, 4]
    # La copia rotada no se lee (el glob solo cubre ``*/events.jsonl``).
    assert rotated.exists()


def test_logrotate_instalado_es_compatible_con_el_forwarder():
    """El fichero de logrotate del repo rota los JSONL con copytruncate."""
    config = (REPO / "deploy" / "logrotate" / "dystopia-fabric").read_text(
        encoding="utf-8"
    )
    directives = {
        line.strip() for line in config.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    assert "/var/lib/dystopia/fabric/logs/*/events.jsonl {" in directives
    # copytruncate conserva el inodo que el agente tiene abierto; sin él el
    # agente escribiría en el fichero rotado y no llegaría al forwarder.
    assert "copytruncate" in directives
    assert "su root root" in directives
    assert {"daily", "compress", "missingok", "notifempty"} <= directives
    assert any(line.startswith("rotate 7") for line in directives)


def test_linea_parcial_no_se_consume(tmp_path):
    log = tmp_path / "logs" / "pc-01" / "events.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(_event(1)) + "\n")
        handle.write('{"device_id": "pc-01", "partial')  # sin \n
    transport = FakeTransport()
    forwarder = _forwarder(tmp_path, transport)

    assert forwarder.run_once()["sent"] == 1  # solo la línea completa
    with open(log, "a", encoding="utf-8") as handle:
        handle.write('": "x"}\n')  # se completa la línea parcial
    result = forwarder.run_once()
    assert result["sent"] == 1
    assert transport.requests[1]["events"][0]["device_id"] == "pc-01"


def test_linea_json_invalida_se_descarta(tmp_path):
    log = tmp_path / "logs" / "pc-01" / "events.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "a", encoding="utf-8") as handle:
        handle.write("{no es json}\n")
        handle.write(json.dumps(_event(1)) + "\n")
    transport = FakeTransport()
    forwarder = _forwarder(tmp_path, transport)

    result = forwarder.run_once()
    assert result["sent"] == 1
    assert forwarder.status()["failed"] >= 1
    assert forwarder.run_once()["sent"] == 0  # la línea mala no se relee


# ── Lotes ──────────────────────────────────────────────────


def test_lotes_de_maximo_100(tmp_path):
    log = tmp_path / "logs" / "pc-01" / "events.jsonl"
    _write_events(log, [_event(index) for index in range(250)])
    transport = FakeTransport()
    forwarder = _forwarder(tmp_path, transport)

    result = forwarder.run_once()
    assert result["sent"] == 250
    assert result["pending"] == 0
    sizes = [len(request["events"]) for request in transport.requests]
    assert sizes == [100, 100, 50]


def test_multiples_dispositivos(tmp_path):
    _write_events(tmp_path / "logs" / "pc-01" / "events.jsonl", [_event(1)])
    _write_events(tmp_path / "logs" / "srv-01" / "events.jsonl", [_event(2, "srv-01")])
    transport = FakeTransport()
    forwarder = _forwarder(tmp_path, transport)

    result = forwarder.run_once()
    assert result["sent"] == 2
    devices = {event["device_id"] for request in transport.requests
               for event in request["events"]}
    assert devices == {"pc-01", "srv-01"}
    assert forwarder.run_once()["sent"] == 0


# ── Reintentos y errores permanentes ───────────────────────


def test_503_reintenta_con_backoff(tmp_path):
    log = tmp_path / "logs" / "pc-01" / "events.jsonl"
    _write_events(log, [_event(1)])
    transport = FakeTransport(script=[503, 503, 200])
    forwarder = _forwarder(tmp_path, transport)

    result = forwarder.run_once()
    assert result["sent"] == 1
    assert len(transport.requests) == 3  # 2 fallos + éxito, sin más reintentos


def test_4xx_permanente_descarta_el_lote(tmp_path):
    log = tmp_path / "logs" / "pc-01" / "events.jsonl"
    _write_events(log, [_event(1)])
    transport = FakeTransport(script=[422])
    forwarder = _forwarder(tmp_path, transport)

    result = forwarder.run_once()
    assert result["sent"] == 0
    assert result["failed"] == 1
    assert "422" in (result["error"] or "")
    assert len(transport.requests) == 1  # sin reintentos
    # Descartado: el siguiente ciclo no repite el lote.
    assert forwarder.run_once()["sent"] == 0


# ── Estado y configuración ─────────────────────────────────


def test_status_refleja_contadores(tmp_path):
    log = tmp_path / "logs" / "pc-01" / "events.jsonl"
    _write_events(log, [_event(1), _event(2)])
    transport = FakeTransport(script=[503, 503, 503, 503])
    forwarder = _forwarder(tmp_path, transport)
    forwarder.run_once()

    status = forwarder.status()
    assert {
        key: status[key] for key in ("enabled", "pending", "sent", "failed")
    } == {"enabled": True, "pending": 2, "sent": 0, "failed": 2}
    assert "503" in (status["last_error"] or "")
    # Diagnóstico de operación: archivos y offsets visibles en /status.
    assert status["dir"] == str(tmp_path / "logs")
    assert status["files"] == [str(log)]
    # Sin envío confirmado el offset sigue vacío: se reintenta el lote.
    assert status["offsets"] == {}

    transport.script = [200]
    forwarder.run_once()
    status = forwarder.status()
    assert status["sent"] == 2
    assert status["pending"] == 0
    assert status["last_error"] is None


def test_deshabilitado_no_envia(tmp_path):
    log = tmp_path / "logs" / "pc-01" / "events.jsonl"
    _write_events(log, [_event(1)])
    transport = FakeTransport()
    forwarder = _forwarder(tmp_path, transport, enabled=False)
    assert forwarder.run_once() == {"sent": 0, "failed": 0, "pending": 0, "error": None}
    assert transport.requests == []
    assert forwarder.status()["enabled"] is False


def test_forwarder_desde_entorno(tmp_path, monkeypatch):
    monkeypatch.setenv("DYSTOPIA_FABRIC_EVENTS_ENABLED", "false")
    assert forwarder_from_env(TOKEN) is None

    monkeypatch.setenv("DYSTOPIA_FABRIC_EVENTS_ENABLED", "true")
    monkeypatch.setenv("DYSTOPIA_FABRIC_EVENTS_URL", URL)
    monkeypatch.setenv("DYSTOPIA_FABRIC_EVENTS_INTERVAL", "2")
    monkeypatch.setenv("DYSTOPIA_FABRIC_EVENTS_TOKEN", "e" * 40)
    monkeypatch.setenv("DYSTOPIA_FABRIC_DEVICES_DIR", str(tmp_path / "logs"))
    forwarder = forwarder_from_env(TOKEN)
    assert forwarder is not None
    assert forwarder._url == URL
    assert forwarder._interval == 2
    assert forwarder._devices_dir == tmp_path / "logs"
    assert forwarder._state_path == tmp_path / "forwarder-state.json"


def test_forwarder_usa_token_de_eventos(tmp_path, monkeypatch):
    monkeypatch.setenv("DYSTOPIA_FABRIC_EVENTS_ENABLED", "true")
    monkeypatch.setenv("DYSTOPIA_FABRIC_EVENTS_TOKEN", "e" * 40)
    monkeypatch.setenv("DYSTOPIA_FABRIC_DEVICES_DIR", str(tmp_path / "logs"))
    forwarder = forwarder_from_env("o" * 40)
    assert forwarder is not None
    assert forwarder._token == "e" * 40


def test_forwarder_sin_token_de_eventos_no_se_crea(tmp_path, monkeypatch, caplog):
    """Fase 9: sin token de eventos no hay fallback al token de operación."""
    monkeypatch.setenv("DYSTOPIA_FABRIC_EVENTS_ENABLED", "true")
    monkeypatch.delenv("DYSTOPIA_FABRIC_EVENTS_TOKEN", raising=False)
    monkeypatch.setenv("DYSTOPIA_FABRIC_DEVICES_DIR", str(tmp_path / "logs"))
    caplog.set_level(logging.WARNING)
    assert forwarder_from_env("o" * 40) is None
    assert "DYSTOPIA_FABRIC_EVENTS_TOKEN" in caplog.text
