"""Pruebas de la API REST del Network Fabric (§6).

Usan el controlador real con ``NullFabricEngine`` y una SQLite temporal,
un manifiesto de ejemplo con credenciales y los JWT sintéticos del repo.
Cubren auth viewer/admin, todos los endpoints, la state machine vía HTTP,
el doble gate, el engine fallido y AC13 (credenciales fuera de las
respuestas).
"""

import copy
import hashlib
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

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


def _auth_header(username: str) -> dict:
    user = SYNTHETIC_USERS[username]
    token = create_access_token({
        "sub": username,
        "role": user["role"],
        "ver": hashlib.sha256(user["password_hash"].encode()).hexdigest(),
    })
    return {"Authorization": "Bearer " + token}


@pytest.fixture()
def auth(tmp_path, monkeypatch):
    """Usuarios en config temporal + headers JWT válidos con claim `ver`."""
    from app.routers import auth as auth_router

    users_file = tmp_path / "users.yaml"
    users_file.write_text(yaml.safe_dump({"users": [
        {"username": name, "role": data["role"], "password_hash": data["password_hash"]}
        for name, data in SYNTHETIC_USERS.items()
    ]}))
    users_file.chmod(0o600)
    monkeypatch.setattr(auth_router, "USERS_FILE", users_file)
    return {"admin": _auth_header("admin"), "viewer": _auth_header("viewer")}


@pytest.fixture()
def client():
    # Sin contexto: no se ejecuta el lifespan (evita arrancar collectors)
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


@pytest.fixture(autouse=True)
def _audit_aislada(tmp_path, monkeypatch):
    """Redirige el audit middleware a tmp para no tocar el STATE_DIR real."""
    from app.services import audit_svc

    audit_dir = tmp_path / "audit"
    monkeypatch.setattr(audit_svc, "AUDIT_DIR", audit_dir)
    monkeypatch.setattr(audit_svc, "AUDIT_DB", audit_dir / "audit.db")


def _broken_manifest() -> dict:
    manifest = copy.deepcopy(MANIFEST)
    manifest["fabric"]["device_overrides"][0]["interfaces"][0]["switch"] = "sw-nope"
    return manifest


def _assert_no_credentials(value) -> None:
    """Ningún diccionario anidado puede exponer credenciales ni contraseñas."""
    if isinstance(value, dict):
        for key, item in value.items():
            assert key not in {"credentials", "password", "passwd"}
            _assert_no_credentials(item)
    elif isinstance(value, list):
        for item in value:
            _assert_no_credentials(item)


def _assert_no_secrets(text: str) -> None:
    for secret in ("admin123", "toor", "P@ssw0rd", "12345"):
        assert secret not in text


GET_ENDPOINTS = [
    "/api/fabric/status",
    "/api/fabric/topology",
    "/api/fabric/topology/graph",
    "/api/fabric/devices",
    "/api/fabric/devices/pc-recepcion-01",
    "/api/fabric/switches",
    "/api/fabric/switches/sw-core",
    "/api/fabric/health",
]


# ── Auth y montaje ─────────────────────────────────────────


def test_rutas_registradas():
    paths = set(app.openapi().get("paths", {}))
    for path in [
        "/api/fabric/status",
        "/api/fabric/topology",
        "/api/fabric/topology/graph",
        "/api/fabric/validate",
        "/api/fabric/deploy",
        "/api/fabric/destroy",
        "/api/fabric/rebuild",
        "/api/fabric/devices",
        "/api/fabric/devices/{device_id}",
        "/api/fabric/switches",
        "/api/fabric/switches/{switch_id}",
        "/api/fabric/health",
    ]:
        assert path in paths


@pytest.mark.parametrize("path", GET_ENDPOINTS)
def test_get_viewer_ok(path, auth, client):
    response = client.get(path, headers=auth["viewer"])
    assert response.status_code == 200, response.text


def test_get_sin_token_rechazado(client):
    response = client.get("/api/fabric/status")
    assert response.status_code in (401, 403)


@pytest.mark.parametrize("path", [
    "/api/fabric/validate", "/api/fabric/deploy",
    "/api/fabric/destroy", "/api/fabric/rebuild",
])
def test_post_viewer_forbidden(path, auth, client):
    response = client.post(path, headers=auth["viewer"])
    assert response.status_code == 403
    assert response.json()["detail"].startswith("Acceso denegado")


# ── Status, topología y grafo ──────────────────────────────


def test_status_inicial_ready(auth, client):
    status = client.get("/api/fabric/status", headers=auth["viewer"]).json()
    assert status["state"] == "ready"
    assert status["enabled"] is True
    assert status["gate_open"] is True
    assert status["name"] == "corporate-deception-net"
    assert status["switches"] == 4
    assert status["devices"] == 3


def test_topology_sin_credenciales(auth, client):
    response = client.get("/api/fabric/topology", headers=auth["viewer"])
    assert response.status_code == 200
    payload = response.json()
    assert payload["config"]["name"] == "corporate-deception-net"
    _assert_no_credentials(payload)
    _assert_no_secrets(response.text)


def test_graph_estructura_ejemplo(auth, client):
    response = client.get("/api/fabric/topology/graph", headers=auth["viewer"])
    assert response.status_code == 200
    graph = response.json()
    assert set(graph) >= {"nodes", "edges", "groups", "state"}
    assert graph["state"] == "ready"
    assert len(graph["nodes"]) == 7   # 4 switches + 3 dispositivos
    assert len(graph["edges"]) == 6   # 3 troncales + 3 accesos
    assert len(graph["groups"]) == 4  # VLAN 10, 20, 30 y 40 (solo trunk)

    switch = next(node for node in graph["nodes"] if node["id"] == "switch:sw-core")
    assert switch["kind"] == "switch"
    assert switch["group"] == "switch"

    device = next(node for node in graph["nodes"] if node["id"] == "device:srv-files-01")
    assert device["kind"] == "device"
    assert device["group"] == "vlan-20"
    assert device["vlan_tag"] == 20

    trunks = [edge for edge in graph["edges"] if edge["kind"] == "trunk"]
    access = [edge for edge in graph["edges"] if edge["kind"] == "access"]
    assert len(trunks) == 3
    assert len(access) == 3
    assert all(edge["state"] == "down" for edge in graph["edges"])

    _assert_no_credentials(graph)
    _assert_no_secrets(response.text)


def test_graph_estado_up_tras_deploy(auth, client):
    assert client.post("/api/fabric/deploy", headers=auth["admin"]).status_code == 200
    graph = client.get("/api/fabric/topology/graph", headers=auth["viewer"]).json()
    assert all(edge["state"] == "up" for edge in graph["edges"])


# ── Validación ─────────────────────────────────────────────


def test_validate_sin_cuerpo(auth, client):
    response = client.post("/api/fabric/validate", headers=auth["admin"])
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["valid"] is True
    assert report["state"] == "ready"
    assert report["errors"] == []


def test_validate_manifiesto_valido(auth, client):
    response = client.post(
        "/api/fabric/validate", headers=auth["admin"], json=MANIFEST,
    )
    assert response.status_code == 200
    assert response.json()["valid"] is True


def test_validate_manifiesto_invalido(auth, client):
    response = client.post(
        "/api/fabric/validate", headers=auth["admin"], json=_broken_manifest(),
    )
    assert response.status_code == 200
    report = response.json()
    assert report["valid"] is False
    assert any("sw-nope" in error for error in report["errors"])


def test_validate_mientras_deployed_es_informe(auth, client):
    assert client.post("/api/fabric/deploy", headers=auth["admin"]).status_code == 200
    response = client.post(
        "/api/fabric/validate", headers=auth["admin"], json=_broken_manifest(),
    )
    assert response.status_code == 200
    assert response.json()["valid"] is False
    assert client.get("/api/fabric/status", headers=auth["viewer"]).json()["state"] == "deployed"


# ── Ciclo de vida vía HTTP ─────────────────────────────────


def test_deploy_y_destroy(auth, client):
    deploy = client.post("/api/fabric/deploy", headers=auth["admin"])
    assert deploy.status_code == 200, deploy.text
    assert deploy.json()["state"] == "deployed"
    assert client.get("/api/fabric/status", headers=auth["viewer"]).json()["state"] == "deployed"

    destroy = client.post("/api/fabric/destroy", headers=auth["admin"])
    assert destroy.status_code == 200, destroy.text
    assert destroy.json()["state"] == "ready"
    assert client.get("/api/fabric/status", headers=auth["viewer"]).json()["state"] == "ready"


def test_deploy_idempotente(auth, client):
    assert client.post("/api/fabric/deploy", headers=auth["admin"]).status_code == 200
    again = client.post("/api/fabric/deploy", headers=auth["admin"])
    assert again.status_code == 200
    assert again.json()["state"] == "deployed"


def test_rebuild(auth, client):
    assert client.post("/api/fabric/deploy", headers=auth["admin"]).status_code == 200
    rebuild = client.post("/api/fabric/rebuild", headers=auth["admin"])
    assert rebuild.status_code == 200
    assert rebuild.json()["state"] == "deployed"


def test_destroy_sin_desplegar_409(auth, client):
    response = client.post("/api/fabric/destroy", headers=auth["admin"])
    assert response.status_code == 409
    assert "deployed" in response.json()["detail"]
    assert client.get("/api/fabric/status", headers=auth["viewer"]).json()["state"] == "ready"


def test_deploy_desde_error_409(fabric, auth, client):
    fabric(manifest=_broken_manifest())
    status = client.get("/api/fabric/status", headers=auth["viewer"])
    assert status.json()["state"] == "error"
    response = client.post("/api/fabric/deploy", headers=auth["admin"])
    assert response.status_code == 409
    assert "validate" in response.json()["detail"]


def test_engine_fallido_502(fabric, auth, client):
    fabric(engine=NullFabricEngine(fail_deploy=True))
    response = client.post("/api/fabric/deploy", headers=auth["admin"])
    assert response.status_code == 502
    assert "deploy falló" in response.json()["detail"]
    assert client.get("/api/fabric/status", headers=auth["viewer"]).json()["state"] == "error"


# ── Doble gate §9.1 ────────────────────────────────────────


def test_gate_cerrado_deploy_409(auth, client, monkeypatch):
    monkeypatch.delenv(FABRIC_ENABLE_ENV)
    response = client.post("/api/fabric/deploy", headers=auth["admin"])
    assert response.status_code == 409
    assert FABRIC_ENABLE_ENV in response.json()["detail"]
    assert client.get("/api/fabric/status", headers=auth["viewer"]).json()["state"] == "ready"


def test_gate_cerrado_rebuild_409(auth, client, monkeypatch):
    assert client.post("/api/fabric/deploy", headers=auth["admin"]).status_code == 200
    monkeypatch.delenv(FABRIC_ENABLE_ENV)
    response = client.post("/api/fabric/rebuild", headers=auth["admin"])
    assert response.status_code == 409
    assert client.get("/api/fabric/status", headers=auth["viewer"]).json()["state"] == "deployed"


# ── Dispositivos / switches / health ───────────────────────


def test_devices_listado_sin_credenciales(auth, client):
    response = client.get("/api/fabric/devices", headers=auth["viewer"])
    assert response.status_code == 200
    devices = response.json()
    assert [device["device_id"] for device in devices] == [
        "pc-recepcion-01", "srv-files-01", "cam-entrada-01",
    ]
    _assert_no_credentials(devices)
    _assert_no_secrets(response.text)


def test_device_detalle_y_404(auth, client):
    device = client.get("/api/fabric/devices/srv-files-01", headers=auth["viewer"])
    assert device.status_code == 200
    assert device.json()["interfaces"][0]["switch"] == "sw-servidores"
    assert client.get(
        "/api/fabric/devices/no-existe", headers=auth["viewer"]
    ).status_code == 404


def test_switches_listado_y_detalle(auth, client):
    switches = client.get("/api/fabric/switches", headers=auth["viewer"]).json()
    assert [switch["id"] for switch in switches] == [
        "sw-core", "sw-oficina", "sw-servidores", "sw-camaras",
    ]
    core = client.get("/api/fabric/switches/sw-core", headers=auth["viewer"])
    assert core.status_code == 200
    assert core.json()["vlans"] == [10, 20, 30, 40]
    assert client.get(
        "/api/fabric/switches/no-existe", headers=auth["viewer"]
    ).status_code == 404


def test_health_antes_y_despues_de_deploy(auth, client):
    before = client.get("/api/fabric/health", headers=auth["viewer"]).json()
    assert before["healthy"] is False
    assert before["state"] == "ready"

    assert client.post("/api/fabric/deploy", headers=auth["admin"]).status_code == 200
    after = client.get("/api/fabric/health", headers=auth["viewer"]).json()
    assert after["healthy"] is True
    assert after["state"] == "deployed"
