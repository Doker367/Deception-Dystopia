"""Pruebas del agente de dispositivo del fabric (Fase 5a), sin red real.

Cubren el schema de ``device.json``, el sink JSONL (formato, flush, sin
credenciales), el mapeo engine→listener nativo y el arranque fallido sin
servicios/listeners. También el hook de sink de ``BaseListener``.
"""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.models.deception import DeceptionEventType  # noqa: E402
from app.services.deception.listeners import base  # noqa: E402
from app.services.deception.listeners.base import BaseListener  # noqa: E402
from app.services.deception.listeners.http_listener import HttpListener  # noqa: E402
from fabric import agent  # noqa: E402


def _config(**overrides) -> dict:
    config = {
        "device_id": "pc-01",
        "role": "pc",
        "persona": {"vendor": "dell", "os": "windows", "hostname": "PC-01"},
        "services": [
            {"port": 22, "proto": "ssh", "engine": "native", "banner": "OpenSSH_8.9"},
            {"port": 80, "proto": "http", "engine": "native"},
        ],
        "credentials": [
            {"username": "admin", "password": "admin123", "service": "ssh"},
        ],
    }
    config.update(overrides)
    return config


def _write_config(tmp_path: Path, config: dict) -> Path:
    path = tmp_path / "device.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _reset_sink():
    base.set_event_sink(None)
    yield
    base.set_event_sink(None)


# ── device.json ─────────────────────────────────────────────


def test_config_valida(tmp_path):
    config = agent.load_device_config(_write_config(tmp_path, _config()))
    assert config.device_id == "pc-01"
    assert config.role == "pc"
    assert config.persona.vendor == "dell"
    assert [service.port for service in config.services] == [22, 80]
    assert config.services[0].engine == "native"
    assert config.credentials[0].username == "admin"


def test_config_sin_device_id(tmp_path):
    raw = _config()
    raw.pop("device_id")
    with pytest.raises(agent.AgentConfigError) as excinfo:
        agent.load_device_config(_write_config(tmp_path, raw))
    assert "device_id" in str(excinfo.value)


def test_service_sin_proto(tmp_path):
    raw = _config(services=[{"port": 22, "engine": "native"}])
    with pytest.raises(agent.AgentConfigError) as excinfo:
        agent.load_device_config(_write_config(tmp_path, raw))
    assert "proto" in str(excinfo.value)


def test_config_json_invalido(tmp_path):
    path = tmp_path / "device.json"
    path.write_text("{no es json", encoding="utf-8")
    with pytest.raises(agent.AgentConfigError) as excinfo:
        agent.load_device_config(path)
    assert "JSON inválido" in str(excinfo.value)


def test_config_inexistente(tmp_path):
    with pytest.raises(agent.AgentConfigError) as excinfo:
        agent.load_device_config(tmp_path / "no-existe.json")
    assert "No se puede leer" in str(excinfo.value)


# ── Sink JSONL ──────────────────────────────────────────────


def test_sink_formato_exacto(tmp_path):
    sink = agent.JsonlSink(tmp_path / "events.jsonl")
    sink(
        "pc-01", "203.0.113.9", "ssh", "login_attempt",
        detail={"service": "ssh"}, username="admin", success=False, src_port=4242,
    )
    lines = (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert set(record) == {
        "ts", "device_id", "src_ip", "src_port", "proto",
        "type", "detail", "username", "success",
    }
    assert record["device_id"] == "pc-01"
    assert record["src_ip"] == "203.0.113.9"
    assert record["src_port"] == 4242
    assert record["proto"] == "ssh"
    assert record["type"] == "login_attempt"
    assert record["detail"] == {"service": "ssh"}
    assert record["username"] == "admin"
    assert record["success"] is False
    datetime.fromisoformat(record["ts"])  # ISO-8601 válido


def test_sink_credencial_capturada_y_configuracion_fuera(tmp_path):
    """La password capturada llega; la lista de credenciales del manifiesto no."""
    sink = agent.JsonlSink(tmp_path / "events.jsonl")
    sink(
        "pc-01", "203.0.113.9", "ssh", "login_success",
        detail={
            "service": "ssh",
            "password": "admin123",  # capturada del atacante
            "command": "ls",
            "credentials": [  # forma de configuración (manifiesto): fuera
                {"username": "admin", "password": "admin123"},
            ],
            "nested": {"token": "abc", "password": "toor"},
        },
        username="admin", success=True,
    )
    text = (tmp_path / "events.jsonl").read_text(encoding="utf-8")
    record = json.loads(text)
    # Capturada del atacante: presente.
    assert record["detail"]["password"] == "admin123"
    assert record["detail"]["nested"]["password"] == "toor"
    assert record["detail"]["command"] == "ls"
    # Configuración del manifiesto: nunca aparece.
    assert "credentials" not in record["detail"]
    assert "credentials" not in record["detail"]["nested"]
    assert "token" not in record["detail"]["nested"]
    assert record["username"] == "admin"


def test_sink_contenido_de_device_json_no_aparece(tmp_path):
    """El contenido del manifiesto (credenciales configuradas) no se loguea."""
    config = agent.load_device_config(_write_config(tmp_path, _config()))
    sink = agent.JsonlSink(tmp_path / "events.jsonl")
    # El sink no recibe la config; un evento normal no puede arrastrarla.
    sink(config.device_id, "203.0.113.9", "ssh", "connect")
    text = (tmp_path / "events.jsonl").read_text(encoding="utf-8")
    assert "admin123" not in text  # password configurada en device.json
    assert '"credentials"' not in text


def test_sink_append_y_flush(tmp_path):
    path = tmp_path / "events.jsonl"
    sink = agent.JsonlSink(path)
    sink("pc-01", "1.1.1.1", "http", "connect")
    sink("pc-01", "1.1.1.1", "http", "http_request")
    text = path.read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert len(text.splitlines()) == 2


def test_sink_acepta_enum(tmp_path):
    sink = agent.JsonlSink(tmp_path / "events.jsonl")
    sink("pc-01", "1.1.1.1", "ssh", DeceptionEventType.LOGIN_ATTEMPT)
    record = json.loads((tmp_path / "events.jsonl").read_text(encoding="utf-8"))
    assert record["type"] == "login_attempt"


# ── engine → listener ───────────────────────────────────────


def test_engine_native_mapea_listener_nativo(tmp_path):
    config = agent.load_device_config(_write_config(tmp_path, _config(
        services=[{"port": 8080, "proto": "http", "engine": "native"}],
    )))
    listeners, warnings = agent.create_listeners(config)
    assert warnings == []
    assert len(listeners) == 1
    assert isinstance(listeners[0], HttpListener)
    assert listeners[0].host == "0.0.0.0"
    assert listeners[0].port == 8080


def test_engine_desconocido_usa_nativo_con_warning(tmp_path):
    config = agent.load_device_config(_write_config(tmp_path, _config(
        services=[{"port": 8080, "proto": "http", "engine": "cowrie"}],
    )))
    listeners, warnings = agent.create_listeners(config)
    assert len(listeners) == 1
    assert isinstance(listeners[0], HttpListener)
    assert any("no enlazado en Fase 5a" in warning for warning in warnings)


def test_proto_no_soportado_se_omite(tmp_path):
    config = agent.load_device_config(_write_config(tmp_path, _config(
        services=[{"port": 1234, "proto": "gopher", "engine": "native"}],
    )))
    listeners, warnings = agent.create_listeners(config)
    assert listeners == []
    assert any("no soportado" in warning for warning in warnings)


# ── Arranque ────────────────────────────────────────────────


def test_agente_sin_servicios_falla(tmp_path):
    config_path = _write_config(tmp_path, _config(services=[]))
    with pytest.raises(agent.AgentConfigError) as excinfo:
        asyncio.run(agent.run_agent(config_path, tmp_path / "logs"))
    assert "no declara servicios" in str(excinfo.value)


def test_agente_sin_listeners_falla_y_configura_host_key(tmp_path, monkeypatch):
    monkeypatch.setenv(agent.HOST_KEY_ENV, "/tmp/original-key")
    config_path = _write_config(tmp_path, _config(
        services=[{"port": 1234, "proto": "gopher", "engine": "native"}],
    ))
    log_dir = tmp_path / "logs"
    with pytest.raises(agent.AgentConfigError) as excinfo:
        asyncio.run(agent.run_agent(config_path, log_dir))
    assert "ningún listener" in str(excinfo.value)
    assert base.get_event_sink() is None
    import os
    assert os.environ[agent.HOST_KEY_ENV] == str(log_dir / "keys" / "ssh_host_rsa_key")


# ── Hook de sink en BaseListener ────────────────────────────


class _Listener(BaseListener):
    async def handle(self, reader, writer, src_ip, src_port) -> None:  # pragma: no cover
        return None


def test_emit_sin_sink_delega_en_telemetry(monkeypatch):
    calls = []

    async def fake_emit(*args, **kwargs):
        calls.append((args, kwargs))
        return {"telemetry": True}

    monkeypatch.setattr(base.telemetry_svc, "emit", fake_emit)
    listener = _Listener("pc-01", "pc", "127.0.0.1", 0, proto="http")
    result = asyncio.run(listener.emit("203.0.113.9", "connect", src_port=1))
    assert result == {"telemetry": True}
    assert calls


def test_emit_con_sink_no_llama_a_telemetry(monkeypatch):
    async def fail_emit(*args, **kwargs):  # pragma: no cover
        raise AssertionError("telemetry_svc.emit no debe llamarse con sink")

    monkeypatch.setattr(base.telemetry_svc, "emit", fail_emit)
    seen = []

    def sink(device_id, src_ip, proto, event_type, **kwargs):
        seen.append((device_id, src_ip, proto, event_type, kwargs))
        return {"sink": True}

    base.set_event_sink(sink)
    listener = _Listener("pc-01", "pc", "127.0.0.1", 0, proto="http")
    result = asyncio.run(listener.emit("203.0.113.9", "connect", src_port=1))
    assert result == {"sink": True}
    assert seen[0][:4] == ("pc-01", "203.0.113.9", "http", "connect")
    assert seen[0][4]["src_port"] == 1


def test_emit_con_sink_asincrono(monkeypatch):
    async def fail_emit(*args, **kwargs):  # pragma: no cover
        raise AssertionError("telemetry_svc.emit no debe llamarse con sink")

    monkeypatch.setattr(base.telemetry_svc, "emit", fail_emit)

    async def sink(device_id, src_ip, proto, event_type, **kwargs):
        return {"async": True}

    base.set_event_sink(sink)
    listener = _Listener("pc-01", "pc", "127.0.0.1", 0, proto="http")
    assert asyncio.run(listener.emit("1.2.3.4", "connect")) == {"async": True}


def test_emit_sync_usa_sink(monkeypatch):
    def fail_emit_sync(*args, **kwargs):  # pragma: no cover
        raise AssertionError("telemetry_svc.emit_sync no debe llamarse con sink")

    monkeypatch.setattr(base.telemetry_svc, "emit_sync", fail_emit_sync)
    seen = []
    base.set_event_sink(lambda device_id, src_ip, proto, event_type, **kw:
                        seen.append((device_id, event_type)) or {"sync": True})
    assert base.emit_sync("pc-01", "1.2.3.4", "ssh", "connect") == {"sync": True}
    assert seen == [("pc-01", "connect")]
