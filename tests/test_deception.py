"""Tests de la red señuelo (Deception): topología, CRUD API y telemetría.

Se redirige el YAML y la base SQLite a rutas temporales y se usan tokens
generados directamente (sin pasar por /login) para no agotar el rate
limiter. Los tokens incluyen el claim `ver` (sha256 del password_hash) que
exige app/middleware/auth.py para invalidar credenciales revocadas.
"""

import hashlib
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient

from app.core.security import create_access_token
from app.main import app
from app.models.deception import DeceptionEventIn, DeceptionEventType
from app.services.deception import store_svc, topology_svc

# Usuarios sintéticos: reflejan el contrato de /api/auth/login, donde el JWT
# incluye `ver` = sha256(password_hash) para invalidar tokens tras un cambio
# de contraseña. El middleware rechaza cualquier token sin ese claim.
SYNTHETIC_USERS = {
    "admin": {"role": "admin", "password_hash": "synthetic-deception-admin-hash"},
    "viewer": {"role": "viewer", "password_hash": "synthetic-deception-viewer-hash"},
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


SAMPLE_NETWORK = {
    "segments": [
        {"id": "vlan-oficina", "vlan_id": 10, "cidr": "10.10.0.0/24", "gateway": "10.10.0.1"},
    ],
    "devices": [
        {
            "id": "pc-01",
            "role": "pc",
            "segment": "vlan-oficina",
            "ip": "10.10.0.21",
            "persona": {"vendor": "dell", "os": "windows", "hostname": "PC-01"},
            "services": [{"port": 22, "proto": "ssh", "engine": "native"}],
        }
    ],
}


@pytest.fixture()
def network_file(tmp_path, monkeypatch):
    f = tmp_path / "network.yaml"
    f.write_text(yaml.safe_dump(SAMPLE_NETWORK))
    monkeypatch.setattr(topology_svc, "NETWORK_FILE", f)
    topology_svc.invalidate_cache()
    return f


@pytest.fixture()
def db_path(tmp_path, monkeypatch):
    db = tmp_path / "deception.db"
    monkeypatch.setattr(store_svc, "DB_PATH", db)
    return db


@pytest.fixture()
def client():
    # Sin contexto: no se ejecuta el lifespan (evita arrancar collectors)
    return TestClient(app)


# ── Topología (unit) ─────────────────────────────────────────


def test_cargar_red_y_resumen(network_file):
    summary = topology_svc.summary()
    assert summary["segments"] == 1
    assert summary["devices"] == 1
    assert summary["devices_enabled"] == 1
    assert summary["by_role"] == {"pc": 1}


def test_add_device_segmento_inexistente_falla(network_file):
    with pytest.raises(ValueError, match="no existe"):
        topology_svc.add_device(
            {"id": "x", "role": "server", "segment": "no-existe", "ip": "10.0.0.1"}
        )


def test_crud_device_unit(network_file):
    topology_svc.add_device(
        {"id": "srv-01", "role": "server", "segment": "vlan-oficina", "ip": "10.10.0.30"}
    )
    assert topology_svc.get_device("srv-01")["role"] == "server"
    topology_svc.update_device("srv-01", {"ip": "10.10.0.31"})
    assert topology_svc.get_device("srv-01")["ip"] == "10.10.0.31"
    assert topology_svc.delete_device("srv-01") is True
    assert topology_svc.get_device("srv-01") is None


# ── Telemetría (unit) ────────────────────────────────────────


def test_store_evento_sesion_y_stats(db_path):
    store_svc.log_event(DeceptionEventIn(
        device_id="pc-01", src_ip="203.0.113.9", proto="ssh",
        type=DeceptionEventType.LOGIN_ATTEMPT, username="admin",
    ))
    store_svc.log_event(DeceptionEventIn(
        device_id="pc-01", src_ip="203.0.113.9", proto="ssh",
        type=DeceptionEventType.COMMAND, detail={"cmd": "uname -a"},
    ))

    events = store_svc.get_events()
    assert len(events) == 2
    assert events[0]["type"] == "command"

    sessions = store_svc.get_sessions()
    assert len(sessions) == 1
    assert sessions[0]["event_count"] == 2
    assert sessions[0]["command_count"] == 1

    stats = store_svc.get_stats()
    assert stats["events_total"] == 2
    assert stats["attackers_unique"] == 1
    assert stats["by_type"]["login_attempt"] == 1


def test_store_filtros(db_path):
    store_svc.log_event(DeceptionEventIn(
        device_id="pc-01", src_ip="1.1.1.1", type=DeceptionEventType.CONNECT,
    ))
    store_svc.log_event(DeceptionEventIn(
        device_id="srv-01", src_ip="2.2.2.2", type=DeceptionEventType.PORT_SCAN,
    ))
    assert len(store_svc.get_events(device_id="srv-01")) == 1
    assert len(store_svc.get_events(src_ip="1.1.1.1")) == 1
    assert len(store_svc.get_events(event_type="port_scan")) == 1


# ── API ──────────────────────────────────────────────────────


def test_api_network_y_status(network_file, auth, client):
    r = client.get("/api/deception/network", headers=auth["viewer"])
    assert r.status_code == 200, r.text
    assert len(r.json()["devices"]) == 1

    s = client.get("/api/deception/status", headers=auth["viewer"])
    assert s.status_code == 200
    assert s.json()["devices"] == 1


def test_api_crud_device(network_file, auth, client):
    payload = {
        "id": "cam-01", "role": "camera", "segment": "vlan-oficina",
        "ip": "10.10.0.40", "services": [{"port": 554, "proto": "rtsp"}],
    }
    r = client.post("/api/deception/devices", json=payload, headers=auth["admin"])
    assert r.status_code == 201, r.text

    r = client.get("/api/deception/devices/cam-01", headers=auth["viewer"])
    assert r.status_code == 200

    r = client.delete("/api/deception/devices/cam-01", headers=auth["admin"])
    assert r.status_code == 204


def test_api_viewer_no_puede_crear(network_file, auth, client):
    r = client.post(
        "/api/deception/devices",
        json={"id": "x", "role": "pc", "segment": "vlan-oficina", "ip": "10.10.0.50"},
        headers=auth["viewer"],
    )
    assert r.status_code == 403


def test_api_ingest_heredado_retirado(db_path, client):
    """El ingest local se retiró: usa el servicio TLS independiente /v1/events."""
    body = {
        "device_id": "pc-01", "src_ip": "203.0.113.9", "proto": "ssh",
        "type": "login_success", "username": "root", "success": True,
    }
    r = client.post("/api/deception/ingest", json=body,
                    headers={"X-Deception-Token": "s3cret"})
    assert r.status_code == 410, r.text
    assert "/v1/events" in r.json()["detail"]
    assert store_svc.get_events() == []


def test_api_ingest_sin_fallback_admin(db_path, auth, client):
    """Ni el token compartido ni un JWT admin reactivan el ingest heredado."""
    for headers in (
        {"X-Deception-Token": "malo"},
        auth["admin"],
    ):
        r = client.post(
            "/api/deception/ingest",
            json={"device_id": "pc-01", "src_ip": "1.2.3.4"},
            headers=headers,
        )
        assert r.status_code == 410, r.text
    assert store_svc.get_events() == []


def test_api_timeline_y_csv(db_path, auth, client):
    store_svc.log_event(DeceptionEventIn(
        device_id="pc-01", src_ip="203.0.113.9", proto="ssh",
        type=DeceptionEventType.LOGIN_ATTEMPT, username="admin",
    ))
    tl = client.get("/api/deception/timeline?minutes=30", headers=auth["viewer"])
    assert tl.status_code == 200
    assert isinstance(tl.json(), list)

    csv = client.get("/api/deception/events.csv", headers=auth["viewer"])
    assert csv.status_code == 200
    assert "device_id" in csv.text
    assert "pc-01" in csv.text


def test_api_simulate_ejecucion_heredada_deshabilitada(network_file, db_path, auth, client):
    """La ejecución heredada está bloqueada hasta migrar al servicio aislado."""
    r = client.post("/api/deception/simulate?count=3", headers=auth["admin"])
    assert r.status_code == 409, r.text
    assert "Legacy execution disabled" in r.json()["detail"]
    assert store_svc.get_events() == []
