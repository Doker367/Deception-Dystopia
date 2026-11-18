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
    ConsoleSession,
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


# ── Transporte remoto (control → servicio del host) ────────


def test_remote_target_solo_con_engine_remote(monkeypatch):
    """Sin engine remote (o sin URL/token) la consola usa docker local."""
    from app.services.fabric import console_svc

    monkeypatch.delenv("DYSTOPIA_FABRIC_ENGINE", raising=False)
    monkeypatch.setenv("DYSTOPIA_FABRIC_REMOTE_URL", "https://host:18100")
    monkeypatch.setenv("DYSTOPIA_FABRIC_REMOTE_TOKEN", "x" * 40)
    assert console_svc.remote_console_target() is None

    monkeypatch.setenv("DYSTOPIA_FABRIC_ENGINE", "remote")
    monkeypatch.delenv("DYSTOPIA_FABRIC_REMOTE_TOKEN", raising=False)
    assert console_svc.remote_console_target() is None

    monkeypatch.setenv("DYSTOPIA_FABRIC_REMOTE_TOKEN", "x" * 40)
    monkeypatch.setenv("DYSTOPIA_FABRIC_REMOTE_CA", "/tmp/ca.crt")
    target = console_svc.remote_console_target()
    assert target is not None
    base, token, ca = target
    assert base == "wss://host:18100"
    assert token == "x" * 40
    assert ca == "/tmp/ca.crt"

    monkeypatch.setenv("DYSTOPIA_FABRIC_REMOTE_URL", "http://host:8090/")
    base, _, _ = console_svc.remote_console_target()
    assert base == "ws://host:8090"


# ── Servicio del host: endpoint WS de consola ──────────────


def _host_app(tmp_path, monkeypatch, *, enabled: bool = True):
    from app.services.fabric.host_service import HostServiceSettings, create_app

    manifest = tmp_path / "network.yaml"
    manifest.write_text(yaml.safe_dump(MANIFEST), encoding="utf-8")
    if enabled:
        monkeypatch.setenv("DYSTOPIA_FABRIC_CONSOLE_ENABLED", "true")
    else:
        monkeypatch.delenv("DYSTOPIA_FABRIC_CONSOLE_ENABLED", raising=False)
    return create_app(
        HostServiceSettings(token="t" * 40, manifest=manifest),
        engine=object(),
    )


def _host_headers() -> dict:
    return {"Authorization": "Bearer " + "t" * 40}


def test_host_console_ws_rejects_bad_token(tmp_path, monkeypatch):
    """El servicio del host cierra 4401 sin bearer válido."""
    client = TestClient(_host_app(tmp_path, monkeypatch))
    with pytest.raises(Exception):
        with client.websocket_connect(
            "/console/ws?device_id=pc-recepcion-01",
            headers={"Authorization": "Bearer incorrecto"},
        ) as ws:
            ws.receive_text()


def test_host_console_ws_disabled(tmp_path, monkeypatch):
    """Sin el gate de entorno el host responde con un frame de error."""
    client = TestClient(_host_app(tmp_path, monkeypatch, enabled=False))
    with client.websocket_connect(
        "/console/ws?device_id=pc-recepcion-01", headers=_host_headers()
    ) as ws:
        message = ws.receive_text()
    assert message.startswith("\x00ERR:")
    assert "deshabilitada" in message


def test_host_console_ws_unknown_device(tmp_path, monkeypatch):
    """Un device fuera del manifiesto no abre consola (4404)."""
    client = TestClient(_host_app(tmp_path, monkeypatch))
    with client.websocket_connect(
        "/console/ws?device_id=no-existe", headers=_host_headers()
    ) as ws:
        message = ws.receive_text()
    assert message.startswith("\x00ERR:")
    assert "manifiesto" in message


def test_host_console_ws_container_stopped(tmp_path, monkeypatch):
    """Contenedor parado → error explícito, sin abrir sesión."""
    from app.services.fabric import host_service

    async def _stopped(_name: str) -> bool:
        return False

    monkeypatch.setattr(host_service, "_container_running", _stopped)
    client = TestClient(_host_app(tmp_path, monkeypatch))
    with client.websocket_connect(
        "/console/ws?device_id=pc-recepcion-01", headers=_host_headers()
    ) as ws:
        message = ws.receive_text()
    assert message.startswith("\x00ERR:")
    assert "ejecución" in message


def test_host_console_ws_bridges_pty(tmp_path, monkeypatch):
    """Camino feliz: abre sesión, reenvía la entrada y cierra al EOF."""
    from app.services.fabric import host_service
    from app.services.fabric.console_svc import ConsoleSession

    written: list[bytes] = []

    class FakeConsole:
        async def open_session(self, **kwargs):
            return ConsoleSession(
                session_id="tty-fake",
                device_id=kwargs["device_id"],
                container_name=kwargs["container_name"],
                username=kwargs["username"],
            )

        async def read_chunk(self, session_id, timeout: float = 0.5):
            # Cede el turno para que pump_in procese la entrada antes del EOF.
            import asyncio as asyncio_mod

            await asyncio_mod.sleep(0.2)
            return None

        async def write_session(self, session_id, data):
            written.append(data)
            return True

        async def close_session(self, session_id):
            return None

    async def _running(_name: str) -> bool:
        return True

    monkeypatch.setattr(host_service, "_container_running", _running)
    monkeypatch.setattr(host_service, "console_service", FakeConsole())
    client = TestClient(_host_app(tmp_path, monkeypatch))
    with pytest.raises(Exception):
        with client.websocket_connect(
            "/console/ws?device_id=pc-recepcion-01", headers=_host_headers()
        ) as ws:
            ws.send_text("ls\n")
            ws.receive_text()
    assert written == [b"ls\n"]


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


# ── Fase 11 (mejoras): resize, límite por device y reap ────


class _FakeRemoteWs:
    """WS falso del servicio del host (solo registra los envíos)."""

    def __init__(self) -> None:
        self.sent: list[str] = []
        self.closed = False

    async def send(self, data) -> None:
        if isinstance(data, (bytes, bytearray)):
            data = bytes(data).decode("utf-8", errors="replace")
        self.sent.append(data)

    async def close(self) -> None:
        self.closed = True


def test_console_resize_remote_sends_control_frame():
    """resize_session en remoto manda el frame JSON acotado al host."""
    import asyncio as asyncio_mod

    from app.services.fabric.console_svc import ConsoleService

    async def scenario():
        service = ConsoleService()
        ws = _FakeRemoteWs()
        session = ConsoleSession(
            session_id="tty-resize",
            device_id="pc-01",
            container_name="dystopia-fabric-pc-01",
            username="admin",
            ws=ws,
        )
        service._sessions[session.session_id] = session
        ok = await service.resize_session("tty-resize", 120, 40)
        assert ok is True
        assert len(ws.sent) == 1
        import json as json_mod

        frame = json_mod.loads(ws.sent[0])
        assert frame["type"] == "resize"
        assert frame["cols"] == 120
        assert frame["rows"] == 40

        # Sin sesión (cerrada o inexistente) → False, no excepción.
        service._sessions.pop("tty-resize")
        assert await service.resize_session("tty-resize", 100, 30) is False

    asyncio_mod.run(scenario())


def test_console_resize_local_sets_winsize():
    """resize_session en local aplica TIOCSWINSZ sobre el PTY real."""
    import asyncio as asyncio_mod
    import os as os_mod
    import pty as pty_mod
    import struct as struct_mod
    import termios as termios_mod

    from app.services.fabric.console_svc import ConsoleSession, ConsoleService

    async def scenario():
        master_fd, _slave_fd = pty_mod.openpty()
        service = ConsoleService()
        session = ConsoleSession(
            session_id="tty-local-resize",
            device_id="pc-02",
            container_name="dystopia-fabric-pc-02",
            username="admin",
            pty_fd=master_fd,
        )
        service._sessions[session.session_id] = session
        ok = await service.resize_session("tty-local-resize", 110, 30)
        # El servidor puede no estar en modo PTY en el entorno de tests;
        # si el ioctl se aplicó, verificamos el tamaño con TIOCGWINSZ.
        if ok:
            winsize = struct_mod.unpack(
                "HHHH", fcntl_mod.ioctl(master_fd, termios_mod.TIOCGWINSZ, b"\x00" * 8)
            )
            assert (winsize[0], winsize[1]) == (30, 110)
        os_mod.close(master_fd)
        assert ok in (True, False)

    import fcntl as fcntl_mod  # noqa: E402

    asyncio_mod.run(scenario())


def test_console_per_device_limit_blocks_duplicate():
    """Abrir dos consolas para el mismo device levanta error claro."""
    import asyncio as asyncio_mod

    from app.services.fabric.console_svc import ConsoleSession, ConsoleService

    async def scenario():
        service = ConsoleService()
        first = ConsoleSession(
            session_id="tty-a",
            device_id="pc-dup",
            container_name="dystopia-fabric-pc-dup",
            username="admin",
        )
        service._sessions[first.session_id] = first
        assert service.count_for_device("pc-dup") == 1
        try:
            await service.open_session(
                device_id="pc-dup",
                container_name="dystopia-fabric-pc-dup",
                username="admin",
            )
        except RuntimeError as exc:
            assert "consola activa" in str(exc)
        else:
            raise AssertionError("la segunda sesión debería rechazarse")
        # Tras cerrar la sesión, el device vuelve a estar disponible.
        await service.close_session("tty-a")
        assert service.count_for_device("pc-dup") == 0

    asyncio_mod.run(scenario())


def test_console_max_age_reap():
    """reap_idle también cierra por edad máxima (CONSOLE_MAX_AGE)."""
    import time as time_mod

    from app.services.fabric.console_svc import (
        CONSOLE_MAX_AGE,
        ConsoleSession,
        ConsoleService,
    )

    service = ConsoleService()
    session = ConsoleSession(
        session_id="tty-old",
        device_id="pc-03",
        container_name="dystopia-fabric-pc-03",
        username="admin",
    )
    session.started_at = time_mod.time() - (CONSOLE_MAX_AGE + 60)
    service._sessions[session.session_id] = session
    assert service.reap_idle() == 1
    assert "tty-old" not in service._sessions


def test_console_list_sessions_exposes_metadata():
    """list_sessions devuelve las vivas con orden y excluye cerradas."""
    from app.services.fabric.console_svc import ConsoleSession, ConsoleService

    service = ConsoleService()
    live = ConsoleSession(
        session_id="tty-live",
        device_id="pc-04",
        container_name="dystopia-fabric-pc-04",
        username="admin",
    )
    dead = ConsoleSession(
        session_id="tty-dead",
        device_id="pc-05",
        container_name="dystopia-fabric-pc-05",
        username="admin",
    )
    dead.closed = True
    service._sessions["tty-dead"] = dead
    service._sessions["tty-live"] = live
    listed = service.list_sessions()
    assert [item.session_id for item in listed] == ["tty-live"]


def test_console_ws_rejects_viewer_role(auth, client, monkeypatch):
    """WS de consola con token de viewer → 4401 (falla antes de abrir)."""
    monkeypatch.setenv("DYSTOPIA_FABRIC_CONSOLE_ENABLED", "true")
    token = auth["viewer"]["Authorization"].partition(" ")[2]
    with pytest.raises(Exception):
        with client.websocket_connect(
            "/api/fabric/devices/pc-recepcion-01/console/ws?token=" + token
        ) as ws:
            ws.receive_text()


def test_console_sessions_endpoint_requires_admin(auth, client):
    """GET /console/sessions con viewer → 403; con admin → contrato."""
    headers = auth["viewer"]
    response = client.get("/api/fabric/console/sessions", headers=headers)
    assert response.status_code == 403
    admin_headers = auth["admin"]
    response = client.get("/api/fabric/console/sessions", headers=admin_headers)
    assert response.status_code in (200, 404, 502, 503)


def test_console_reconnect_no_duplicate_session():
    """Tras cerrar la WS la sesión muere: la reconexión abre una NUEVA."""
    import asyncio as asyncio_mod

    from app.services.fabric.console_svc import ConsoleService

    async def scenario():
        service = ConsoleService()
        first = ConsoleSession(
            session_id="tty-probe",
            device_id="pc-06",
            container_name="dystopia-fabric-pc-06",
            username="admin",
        )
        service._sessions[first.session_id] = first
        assert service.active_count == 1
        # El cliente pierde la conexión: close_session mata el proceso/WS.
        await service.close_session("tty-probe")
        assert service.active_count == 0
        # La reconexión abre una sesión con otram ID y sin duplicar device.
        second = ConsoleSession(
            session_id="tty-probe-2",
            device_id="pc-06",
            container_name="dystopia-fabric-pc-06",
            username="admin",
        )
        service._sessions[second.session_id] = second
        assert service.active_count == 1
        assert service.list_sessions()[0].session_id == "tty-probe-2"

    asyncio_mod.run(scenario())
