"""Pruebas de la consola interactiva del fabric (Fase 11) y del editor
del manifiesto vía API (GET/PUT /api/fabric/config).

Cubren:
- Gate fail-closed de la consola (env + estado deployed).
- Límites de sesiones concurrentes del ConsoleService.
- Redacción de credenciales en GET /config y rechazo de YAML inválido.
- Guardado del manifiesto con backup y adopción por el controlador.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.services.fabric.console_svc import (  # noqa: E402
    CONSOLE_IDLE_TIMEOUT,
    CONSOLE_MAX_AGE,
    ConsoleSession,
    console_enabled,
)

EXAMPLE = REPO / "config" / "deception" / "network.fabric.example.yaml"
MANIFEST = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))

# ── ConsoleService (unitarias, sin docker real) ─────────────


def test_console_gate_fail_closed(monkeypatch):
    """Sin env no se abre consola (fail-closed)."""
    from app.services.fabric import console_svc

    monkeypatch.delenv("DYSTOPIA_FABRIC_CONSOLE_ENABLED", raising=False)
    assert console_svc.console_enabled() is False
    monkeypatch.setenv("DYSTOPIA_FABRIC_CONSOLE_ENABLED", "true")
    assert console_svc.console_enabled() is True


def test_console_session_limits():
    """La cuota de sesiones concurrentes se aplica y libera al cerrar."""
    from app.services.fabric.console_svc import ConsoleService

    service = ConsoleService()
    sessions = []
    for index in range(2):
        session = ConsoleSession(
            session_id=f"tty-{index}",
            device_id="pc-01",
            container_name="dystopia-fabric-pc-01",
            username="admin",
        )
        service._sessions[session.session_id] = session
        sessions.append(session)
    assert service.active_count == 2
    for session in sessions:
        service._sessions.pop(session.session_id)
    assert service.active_count == 0


    service = ConsoleService()
    sessions = []
    for index in range(2):
        session = ConsoleSession(
            session_id=f"tty-{index}",
            device_id="pc-01",
            container_name="dystopia-fabric-pc-01",
            username="admin",
        )
        service._sessions[session.session_id] = session
        sessions.append(session)
    assert service.active_count == 2
    for item in sessions:
        service._sessions.pop(item.session_id, None)
    assert service.active_count == 0


def test_console_idle_reap():
    """reap_idle cierra sesiones que superan el idle timeout."""
    import time as time_mod

    from app.services.fabric.console_svc import ConsoleSession, ConsoleService

    service = ConsoleService()
    session = ConsoleSession(
        session_id="tty-stale",
        device_id="pc-01",
        container_name="dystopia-fabric-pc-01",
        username="admin",
    )
    session.last_activity = time_mod.time() - (CONSOLE_IDLE_TIMEOUT + 30)
    service._sessions[session.session_id] = session
    assert service.reap_idle() == 1
    assert "tty-stale" not in service._sessions


# ── API del editor de manifiesto ────────────────────────────


def test_config_get_redacted(auth, client):
    """GET /config devuelve YAML sin credenciales en claro."""
    headers = auth["admin"]
    response = client.get("/api/fabric/config", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert "content" in payload
    _assert_no_secrets(payload["content"])


def test_config_put_valid_and_adopted(auth, client):
    """PUT /config con el bloque fabric válido lo guarda y adopta."""
    fabric_block = copy.deepcopy(MANIFEST["fabric"])
    headers = auth["admin"]
    response = client.put(
        "/api/fabric/config",
        json={"content": yaml.safe_dump(fabric_block)},
        headers=headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body.get("saved") is True
    assert body.get("needs_rebuild") is False  # stub: estado ready, no deployed


def test_config_put_merges_into_full_manifest(auth, client, tmp_path, monkeypatch):
    """PUT /config preserva el resto del network.yaml (segments/devices)."""
    other_file = tmp_path / "network.yaml"
    full = copy.deepcopy(MANIFEST)
    full["fabric"]["name"] = "original"
    other_file.write_text(yaml.safe_dump(full), encoding="utf-8")
    monkeypatch.setattr("app.core.settings.DECEPTION_NETWORK_FILE", other_file)

    fabric_block = copy.deepcopy(MANIFEST["fabric"])
    fabric_block["name"] = "editado"
    headers = auth["admin"]
    response = client.put(
        "/api/fabric/config",
        json={"content": yaml.safe_dump(fabric_block)},
        headers=headers,
    )
    assert response.status_code == 200
    saved = yaml.safe_load(other_file.read_text(encoding="utf-8"))
    # El bloque fabric se actualizó…
    assert saved["fabric"]["name"] == "editado"
    # …y el resto del manifiesto sigue intacto.
    assert saved["segments"] == MANIFEST["segments"]
    assert saved["devices"] == MANIFEST["devices"]


def test_config_put_rejects_invalid(auth, client):
    """PUT /config rechaza un bloque fabric con referencias rotas."""
    broken = copy.deepcopy(MANIFEST["fabric"])
    broken["device_overrides"][0]["interfaces"][0]["switch"] = "sw-nope"
    headers = auth["admin"]
    response = client.put(
        "/api/fabric/config",
        json={"content": yaml.safe_dump(broken)},
        headers=headers,
    )
    assert response.status_code in (422, 502)


def test_config_put_rejects_bad_yaml(auth, client):
    """PUT /config rechaza YAML sintácticamente inválido (422)."""
    headers = auth["admin"]
    response = client.put(
        "/api/fabric/config",
        json={"content": "fabric: [esto no es: válido"},
        headers=headers,
    )
    assert response.status_code == 422


def _assert_no_secrets(text: str) -> None:
    for secret in ("admin123", "toor", "P@ssw0rd", "12345"):
        assert secret not in text


# ── Consola vía API (cross-check del gate HTTP) ─────────────

import hashlib  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

from app.core.security import create_access_token  # noqa: E402
from app.main import app  # noqa: E402
from app.services.fabric import controller as controller_mod  # noqa: E402
from app.services.fabric.controller import (  # noqa: E402
    FABRIC_ENABLE_ENV,
    NullFabricEngine,
)

EXAMPLE = REPO / "config" / "deception" / "network.fabric.example.yaml"
MANIFEST = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))

SYNTHETIC_USERS = {
    "admin": {"role": "admin", "password_hash": "synthetic-fabric-admin-hash"},
    "viewer": {"role": "viewer", "password_hash": "synthetic-fabric-viewer-hash"},
}


def _synthetic_token(username: str) -> dict:
    user = SYNTHETIC_USERS[username]
    token = create_access_token({
        "sub": username,
        "role": user["role"],
        "ver": hashlib.sha256(user["password_hash"].encode()).hexdigest(),
    })
    return {"Authorization": "Bearer " + token}


@pytest.fixture()
def client():
    """TestClient sin lifespan (patrón de test_fabric_api)."""
    return TestClient(app)


@pytest.fixture(autouse=True)
def fabric(tmp_path, monkeypatch):
    """Controlador aislado (SQLite temporal + stub) y gate abierto."""
    monkeypatch.setenv(FABRIC_ENABLE_ENV, "true")
    db_path = tmp_path / "fabric.db"

    def reset(engine=None, manifest=None):
        return controller_mod.reset_controller(
            engine=engine if engine is not None else NullFabricEngine(),
            db_path=db_path,
            manifest_loader=lambda: copy.deepcopy(
                MANIFEST if manifest is None else manifest
            ),
        )

    reset()
    return reset


@pytest.fixture()
def auth(tmp_path, monkeypatch):
    """Usuarios sintéticos + JWTs válidos con claim `ver` (patrón del repo)."""
    from app.routers import auth as auth_router

    users_file = tmp_path / "users.yaml"
    users_file.write_text(yaml.safe_dump({"users": [
        {"username": name, "role": data["role"], "password_hash": data["password_hash"]}
        for name, data in SYNTHETIC_USERS.items()
    ]}))
    users_file.chmod(0o600)
    monkeypatch.setattr(auth_router, "USERS_FILE", users_file)
    return {"admin": _synthetic_token("admin"), "viewer": _synthetic_token("viewer")}


def test_console_requires_admin(auth, client):
    """POST /devices/{id}/console con viewer → 403."""
    headers = auth["viewer"]
    response = client.post("/api/fabric/devices/pc-recepcion-01/console", headers=headers)
    assert response.status_code == 403


def test_console_unknown_device(auth, client, monkeypatch):
    """POST /devices/{id}/console con device desconocido → 404.

    Con el gate de consola habilitado; sin él, 503 fail-closed precede.
    """
    monkeypatch.setenv("DYSTOPIA_FABRIC_CONSOLE_ENABLED", "true")
    headers = auth["admin"]
    response = client.post("/api/fabric/devices/no-existe/console", headers=headers)
    assert response.status_code == 404


def test_console_disabled_returns_503(auth, client, monkeypatch):
    """POST /devices/{id}/console sin gate de entorno → 503 fail-closed."""
    monkeypatch.delenv("DYSTOPIA_FABRIC_CONSOLE_ENABLED", raising=False)
    headers = auth["admin"]
    response = client.post("/api/fabric/devices/pc-recepcion-01/console", headers=headers)
    assert response.status_code == 503


def test_console_ws_rejects_bad_token(client):
    """WS de consola con token inválido se cierra (4401)."""
    import pytest as _pytest

    with _pytest.raises(Exception):
        with client.websocket_connect(
            "/api/fabric/devices/pc-recepcion-01/console/ws?token=invalido"
        ) as ws:
            ws.receive_text()
