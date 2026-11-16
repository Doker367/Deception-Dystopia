"""Invariantes de seguridad del fabric (Fase 8).

Escaneo de fugas en respuestas de la API, device.json sin credenciales,
fichero .enc sin texto plano y tokens ausentes de logs y respuestas.
"""

import copy
import hashlib
import json
import logging
import sys
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.core.security import create_access_token  # noqa: E402
from app.main import app  # noqa: E402
from app.services.fabric import controller as controller_mod  # noqa: E402
from app.services.fabric.controller import NullFabricEngine  # noqa: E402
from app.services.fabric.deploy import _agent_config  # noqa: E402
from app.services.fabric.parser import parse_manifest  # noqa: E402
from app.services.fabric.runtime import DeviceRuntime, DeviceRuntimeResult  # noqa: E402
from app.services.fabric.topology import build_device_specs  # noqa: E402

EXAMPLE = REPO / "config" / "deception" / "network.fabric.example.yaml"
MANIFEST = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
SECRETS = ("admin123", "toor", "P@ssw0rd", "12345")

SYNTHETIC_USERS = {
    "admin": {"role": "admin", "password_hash": "synthetic-sec-admin-hash"},
    "viewer": {"role": "viewer", "password_hash": "synthetic-sec-viewer-hash"},
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
    from app.routers import auth as auth_router

    users_file = tmp_path / "users.yaml"
    users_file.write_text(yaml.safe_dump({"users": [
        {"username": name, "role": data["role"],
         "password_hash": data["password_hash"]}
        for name, data in SYNTHETIC_USERS.items()
    ]}))
    users_file.chmod(0o600)
    monkeypatch.setattr(auth_router, "USERS_FILE", users_file)
    return {"admin": _auth_header("admin"), "viewer": _auth_header("viewer")}


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def fabric(tmp_path, monkeypatch):
    monkeypatch.setenv(controller_mod.FABRIC_ENABLE_ENV, "true")
    monkeypatch.setenv("DYSTOPIA_FABRIC_EVENTS_TOKEN", "e" * 40)
    controller_mod.reset_controller(
        engine=NullFabricEngine(),
        db_path=tmp_path / "fabric.db",
        manifest_loader=lambda: copy.deepcopy(MANIFEST),
    )
    from app.services import audit_svc

    audit_dir = tmp_path / "audit"
    monkeypatch.setattr(audit_svc, "AUDIT_DIR", audit_dir)
    monkeypatch.setattr(audit_svc, "AUDIT_DB", audit_dir / "audit.db")


def _assert_no_credentials(value) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            assert key not in {"password", "credentials", "token", "passwd"}
            _assert_no_credentials(item)
    elif isinstance(value, list):
        for item in value:
            _assert_no_credentials(item)


def test_respuestas_api_sin_secretos(auth, client):
    paths = [
        "/api/fabric/status",
        "/api/fabric/topology",
        "/api/fabric/topology/graph",
        "/api/fabric/devices",
        "/api/fabric/devices/pc-recepcion-01",
        "/api/fabric/health",
    ]
    for path in paths:
        response = client.get(path, headers=auth["viewer"])
        assert response.status_code == 200, (path, response.text)
        _assert_no_credentials(response.json())
        for secret in SECRETS:
            assert secret not in response.text, (path, secret)


def test_device_json_sin_credenciales(tmp_path):
    topology = parse_manifest(copy.deepcopy(MANIFEST))
    spec = build_device_specs(topology)[0]
    config = _agent_config(topology, spec.device_id)
    assert "credentials" not in config

    runtime = DeviceRuntime(
        runtime=object(),  # no se usa en _device_mounts
        config_root=tmp_path / "cfg",
        logs_root=tmp_path / "logs",
    )
    result = DeviceRuntimeResult(
        device_id=spec.device_id, container_name=spec.container_name,
    )
    mounts = runtime._device_mounts(spec, config, result)
    assert mounts is not None and mounts
    device_json = tmp_path / "cfg" / spec.device_id / "device.json"
    text = device_json.read_text(encoding="utf-8")
    for secret in SECRETS:
        assert secret not in text
    assert "password" not in text
    assert "credentials" not in text


def test_fichero_cifrado_sin_texto_plano(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet

    from app.services.fabric import credential_store

    key_file = tmp_path / "fabric.key"
    key_file.write_bytes(Fernet.generate_key() + b"\n")
    monkeypatch.setattr(credential_store, "KEY_FILE", key_file)
    monkeypatch.setattr(credential_store, "CREDENTIALS_DIR", tmp_path / "credentials")
    monkeypatch.delenv(credential_store.KEY_ENV, raising=False)

    topology = parse_manifest(copy.deepcopy(MANIFEST))
    override = topology.config.device_overrides[0]
    credentials = credential_store.credentials_for(
        override.id, override.credentials,
    )
    path = credential_store.store_for_device(override.id, credentials)
    text = path.read_text(encoding="ascii")
    for secret in SECRETS:
        assert secret not in text
    assert credential_store.load_for_device(override.id) == credentials


def test_token_no_aparece_en_logs_ni_respuestas(auth, client, caplog):
    token = "e" * 40
    caplog.set_level(logging.DEBUG)
    event = {
        "device_id": "pc-recepcion-01", "proto": "ssh", "type": "connect",
        "src_ip": "203.0.113.9", "detail": {},
    }
    response = client.post(
        "/api/fabric/events", headers={"X-Fabric-Token": token},
        json={"events": [event]},
    )
    assert response.status_code == 200
    status = client.get("/api/fabric/status", headers=auth["viewer"])
    assert token not in response.text
    assert token not in status.text
    assert token not in caplog.text


def test_topology_json_persistido_sin_credenciales(auth, client, tmp_path):
    import sqlite3

    assert client.post("/api/fabric/deploy", headers=auth["admin"]).status_code == 200
    db_path = controller_mod.get_controller()._db_path
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT topology_json FROM fabric_state ORDER BY id DESC LIMIT 1"
        ).fetchall()
    assert rows
    payload = rows[0][0]
    _assert_no_credentials(json.loads(payload))
    for secret in SECRETS:
        assert secret not in payload
