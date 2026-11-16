"""Pruebas de la ingesta de eventos del fabric (POST /api/fabric/events).

Autenticación por token de servicio (X-Fabric-Token), fail-closed 503,
límites de lote (413/422), device_id ajeno (403), eventos inválidos que
no tumban el lote y llamada correcta a ``telemetry_svc.emit_sync``.
"""

import json
import sys
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.main import app  # noqa: E402
from app.services.deception import telemetry_svc  # noqa: E402
from app.services.fabric import controller as controller_mod  # noqa: E402
from app.services.fabric.controller import NullFabricEngine  # noqa: E402

TOKEN = "t" * 40
AUTH = {"X-Fabric-Token": TOKEN}


def _manifest() -> dict:
    """Fabric con dos VLANs y un dispositivo cada una."""
    return {
        "segments": [
            {"id": "vlan-10", "vlan_id": 10, "cidr": "10.10.0.0/24"},
            {"id": "vlan-20", "vlan_id": 20, "cidr": "10.20.0.0/24"},
        ],
        "devices": [
            {"id": "pc-01", "role": "pc", "segment": "vlan-10", "ip": "10.10.0.21"},
            {"id": "srv-01", "role": "server", "segment": "vlan-20", "ip": "10.20.0.10"},
        ],
        "fabric": {
            "enabled": True,
            "switches": [{"id": "sw-a", "vlans": [10, 20]}],
            "device_overrides": [{
                "id": "pc-01",
                "interfaces": [{
                    "segment": "vlan-10", "ip": "10.10.0.21/24",
                    "mac": "00:1c:42:10:10:21", "vlan_tag": 10, "switch": "sw-a",
                }],
            }],
        },
    }


def _event(**overrides) -> dict:
    event = {
        "device_id": "pc-01",
        "proto": "ssh",
        "type": "login_attempt",
        "src_ip": "203.0.113.9",
        "src_port": 4242,
        "detail": {"service": "ssh"},
        "username": "admin",
        "success": False,
        "ts": "2026-11-15T20:00:00+00:00",
    }
    event.update(overrides)
    return event


@pytest.fixture()
def fabric_env(tmp_path, monkeypatch):
    """Control con manifiesto temporal, engine stub y token de ingesta."""
    monkeypatch.setenv("DYSTOPIA_FABRIC_EVENTS_TOKEN", TOKEN)
    monkeypatch.delenv("DYSTOPIA_FABRIC_REMOTE_TOKEN", raising=False)
    target = tmp_path / "network.yaml"
    target.write_text(yaml.safe_dump(_manifest()), encoding="utf-8")
    monkeypatch.setattr(controller_mod.topology_svc, "NETWORK_FILE", target)
    controller_mod.topology_svc.invalidate_cache()
    controller_mod.reset_controller(
        engine=NullFabricEngine(),
        db_path=tmp_path / "fabric.db",
        manifest_loader=lambda: _manifest(),
    )
    yield
    controller_mod.topology_svc.invalidate_cache()


@pytest.fixture()
def client(fabric_env):
    return TestClient(app)


@pytest.fixture()
def emitted(monkeypatch):
    calls = []

    def fake_emit_sync(device_id, src_ip, proto, event_type, **kwargs):
        calls.append({
            "device_id": device_id, "src_ip": src_ip, "proto": proto,
            "event_type": event_type, **kwargs,
        })
        return {"stored": True}

    monkeypatch.setattr(telemetry_svc, "emit_sync", fake_emit_sync)
    return calls


# ── Autenticación ──────────────────────────────────────────


def test_sin_token_configurado_503(client, monkeypatch):
    monkeypatch.delenv("DYSTOPIA_FABRIC_EVENTS_TOKEN", raising=False)
    response = client.post("/api/fabric/events", json={"events": [_event()]})
    assert response.status_code == 503
    assert "fail-closed" in response.json()["detail"] or "deshabilitada" in response.json()["detail"]


def test_sin_header_401(client):
    response = client.post("/api/fabric/events", json={"events": [_event()]})
    assert response.status_code == 401


def test_token_invalido_401(client):
    response = client.post(
        "/api/fabric/events", json={"events": [_event()]},
        headers={"X-Fabric-Token": "z" * 40},
    )
    assert response.status_code == 401


def test_jwt_admin_no_sirve(client):
    """El emisor es un servicio: el JWT no sustituye al token de servicio."""
    from app.core.security import create_access_token

    token = create_access_token({"sub": "admin", "role": "admin"})
    response = client.post(
        "/api/fabric/events", json={"events": [_event()]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401


# ── Lote válido ────────────────────────────────────────────


def test_lote_valido_llama_a_emit_sync(client, emitted):
    response = client.post(
        "/api/fabric/events", headers=AUTH,
        json={"events": [_event(), _event(device_id="srv-01", proto="http")]},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload == {"accepted": 2, "rejected": 0, "errors": []}
    assert len(emitted) == 2
    first = emitted[0]
    assert first["device_id"] == "pc-01"
    assert first["src_ip"] == "203.0.113.9"
    assert first["proto"] == "ssh"
    assert first["event_type"] == "login_attempt"
    assert first["detail"] == {
        "service": "ssh", "credentials": {"username": "admin"},
    }
    assert first["username"] == "admin"
    assert first["success"] is False
    assert first["src_port"] == 4242
    assert first["ts"] == "2026-11-15T20:00:00+00:00"


def test_proto_se_normaliza_a_minusculas(client, emitted):
    response = client.post(
        "/api/fabric/events", headers=AUTH, json={"events": [_event(proto="SSH")]},
    )
    assert response.status_code == 200
    assert emitted[0]["proto"] == "ssh"


# ─ device_id ajeno / límites / esquema ─────────────────────


def test_device_id_ajeno_403(client, emitted):
    response = client.post(
        "/api/fabric/events", headers=AUTH,
        json={"events": [_event(), _event(device_id="intruso")]},
    )
    assert response.status_code == 403
    assert any("intruso" in error for error in response.json()["detail"]["errors"])
    assert emitted == []


def test_lote_demasiado_grande_413(client):
    response = client.post(
        "/api/fabric/events", headers=AUTH,
        json={"events": [_event() for _ in range(201)]},
    )
    assert response.status_code == 413


def test_cuerpo_demasiado_grande_413(client):
    huge = "x" * (256 * 1024)
    response = client.post(
        "/api/fabric/events", headers=AUTH,
        json={"events": [_event(detail={"blob": huge})]},
    )
    assert response.status_code == 413


@pytest.mark.parametrize("body", [
    {"no_events": []},
    {"events": "no-es-lista"},
    {"events": [{"device_id": "pc-01"}]},
    {"events": [_event(device_id="pc-01", extra_field="x")]},
    {"events": [{"device_id": "pc-01", "proto": "ssh", "type": "connect",
                 "src_ip": "1.2.3.4", "detail": "no-dict"}]},
])
def test_esquema_invalido_422(client, emitted, body):
    response = client.post("/api/fabric/events", headers=AUTH, json=body)
    assert response.status_code == 422
    assert emitted == []


def test_json_invalido_422(client):
    response = client.post(
        "/api/fabric/events", headers=AUTH, content="{no json",
    )
    assert response.status_code == 422


# ── Eventos inválidos no tumban el lote ────────────────────


def test_evento_invalido_cuenta_y_sigue(client, emitted):
    batch = [
        _event(),                                   # válido
        _event(proto="gopher"),                     # proto fuera de catálogo
        _event(type="exploit"),                     # type fuera de catálogo
        _event(src_ip="no-es-ip"),                  # src_ip inválida
        _event(ts="ayer"),                          # ts inválido
        _event(device_id="srv-01", proto="http"),   # válido
    ]
    response = client.post("/api/fabric/events", headers=AUTH, json={"events": batch})
    assert response.status_code == 200
    payload = response.json()
    assert payload["accepted"] == 2
    assert payload["rejected"] == 4
    assert [error["index"] for error in payload["errors"]] == [1, 2, 3, 4]
    assert [call["device_id"] for call in emitted] == ["pc-01", "srv-01"]


def test_emit_que_falla_no_tumba_el_lote(client, emitted, monkeypatch):
    def failing_emit(device_id, src_ip, proto, event_type, **kwargs):
        if device_id == "srv-01":
            raise RuntimeError("sqlite bloqueada")
        return {"stored": True}

    monkeypatch.setattr(telemetry_svc, "emit_sync", failing_emit)
    response = client.post(
        "/api/fabric/events", headers=AUTH,
        json={"events": [_event(), _event(device_id="srv-01")]},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["accepted"] == 1
    assert payload["rejected"] == 1
    assert "sqlite bloqueada" in payload["errors"][0]["error"]


# ── Fase 7: credenciales capturadas y alertas del fabric ───


def test_normaliza_credenciales_capturadas(client, emitted):
    batch = [_event(detail={
        "service": "ssh", "username": "admin", "password": "admin123",
    })]
    response = client.post("/api/fabric/events", headers=AUTH, json={"events": batch})
    assert response.status_code == 200
    assert response.json()["accepted"] == 1
    assert emitted[0]["detail"] == {
        "service": "ssh",
        "credentials": {"username": "admin", "password": "admin123"},
    }


def test_credenciales_ya_normalizadas_no_duplican(client, emitted):
    batch = [_event(detail={
        "service": "ssh",
        "credentials": {"username": "admin", "password": "admin123"},
    })]
    response = client.post("/api/fabric/events", headers=AUTH, json={"events": batch})
    assert response.status_code == 200
    assert emitted[0]["detail"] == {
        "service": "ssh",
        "credentials": {"username": "admin", "password": "admin123"},
    }


def test_credenciales_invalidas_rechazan_el_evento(client, emitted):
    batch = [
        _event(),
        _event(device_id="srv-01", detail={"credentials": {"username": 123}}),
        _event(device_id="srv-01", detail={"credentials": "no-dict"}),
        _event(device_id="srv-01", detail={
            "credentials": {"password": "x" * 300},
        }),
    ]
    response = client.post("/api/fabric/events", headers=AUTH, json={"events": batch})
    assert response.status_code == 200
    payload = response.json()
    assert payload["accepted"] == 1
    assert payload["rejected"] == 3
    assert len(payload["errors"]) == 3
    assert len(emitted) == 1


def test_credenciales_largas_acotadas(client, emitted):
    batch = [_event(detail={
        "credentials": {"username": "u" * 129, "password": "p"},
    })]
    response = client.post("/api/fabric/events", headers=AUTH, json={"events": batch})
    assert response.status_code == 200
    assert response.json()["rejected"] == 1
    assert "128" in response.json()["errors"][0]["error"]
    assert emitted == []


def test_alertas_del_fabric_se_despachan(client, tmp_path, monkeypatch):
    from app.services.deception import alert_svc, store_svc

    monkeypatch.setattr(store_svc, "DB_PATH", tmp_path / "deception.db")
    captured = []
    monkeypatch.setattr(
        alert_svc, "dispatch_external",
        lambda alerts: captured.extend(alerts) or alerts,
    )

    # El atacante aparece en la VLAN 10 (pc-01) y luego en la 20 (srv-01).
    # ts=None: el store usa "ahora" (un ts fijo quedaría fuera de la ventana).
    assert client.post(
        "/api/fabric/events", headers=AUTH,
        json={"events": [_event(device_id="pc-01", src_ip="198.51.100.7", ts=None)]},
    ).status_code == 200
    assert client.post(
        "/api/fabric/events", headers=AUTH,
        json={"events": [_event(device_id="srv-01", src_ip="198.51.100.7", ts=None)]},
    ).status_code == 200

    rules = [alert["rule"] for alert in captured]
    assert "fabric_lateral_movement" in rules
    assert "fabric_new_device_probed" in rules
    lateral = next(alert for alert in captured
                   if alert["rule"] == "fabric_lateral_movement")
    assert lateral["severity"] == "high"
    assert lateral["detail"]["vlans"] == [10, 20]
    assert json.dumps(captured).count("admin123") == 0  # sin credenciales


def test_fallo_de_alertas_no_tumba_la_ingesta(client, emitted, monkeypatch):
    import app.services.fabric.fabric_alerts as fabric_alerts_module

    def failing_evaluate(records, topology=None, window=None):
        raise RuntimeError("alertas caídas")

    monkeypatch.setattr(fabric_alerts_module, "evaluate_batch", failing_evaluate)
    response = client.post(
        "/api/fabric/events", headers=AUTH, json={"events": [_event()]},
    )
    assert response.status_code == 200
    assert response.json()["accepted"] == 1
    assert len(emitted) == 1


# ── Fase 8: separación de tokens ───────────────────────────


def test_token_de_operacion_no_sirve_para_ingesta(client, monkeypatch):
    monkeypatch.setenv("DYSTOPIA_FABRIC_EVENTS_TOKEN", "e" * 40)
    monkeypatch.setenv("DYSTOPIA_FABRIC_REMOTE_TOKEN", "r" * 40)
    body = {"events": [_event()]}
    assert client.post(
        "/api/fabric/events", headers={"X-Fabric-Token": "r" * 40}, json=body,
    ).status_code == 401
    assert client.post(
        "/api/fabric/events", headers={"X-Fabric-Token": "e" * 40}, json=body,
    ).status_code == 200


def test_solo_token_de_eventos(client, monkeypatch):
    monkeypatch.setenv("DYSTOPIA_FABRIC_EVENTS_TOKEN", "e" * 40)
    monkeypatch.delenv("DYSTOPIA_FABRIC_REMOTE_TOKEN", raising=False)
    response = client.post(
        "/api/fabric/events", headers={"X-Fabric-Token": "e" * 40},
        json={"events": [_event()]},
    )
    assert response.status_code == 200


def test_sin_fallback_al_token_de_operacion(client, monkeypatch):
    """Fase 9: el token del engine remote ya NO sirve para la ingesta."""
    monkeypatch.delenv("DYSTOPIA_FABRIC_EVENTS_TOKEN", raising=False)
    monkeypatch.setenv("DYSTOPIA_FABRIC_REMOTE_TOKEN", "r" * 40)
    response = client.post(
        "/api/fabric/events", headers={"X-Fabric-Token": "r" * 40},
        json={"events": [_event()]},
    )
    assert response.status_code == 503
    assert "DYSTOPIA_FABRIC_EVENTS_TOKEN" in response.json()["detail"]


def test_token_de_eventos_corto_503(client, monkeypatch):
    """Un token de menos de 32 caracteres cuenta como no configurado."""
    monkeypatch.setenv("DYSTOPIA_FABRIC_EVENTS_TOKEN", "corto")
    response = client.post(
        "/api/fabric/events", headers={"X-Fabric-Token": "corto"},
        json={"events": [_event()]},
    )
    assert response.status_code == 503
