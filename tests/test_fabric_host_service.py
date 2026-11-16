"""Pruebas del servicio de fabric del host (Fase 4c), sin OVS/Docker.

Usan ``TestClient`` con un engine falso inyectado y un manifiesto
temporal: autenticación bearer, fail-closed sin token, deploy/destroy/
status/health, concurrencia (409), errores del engine (502), AC13 y
configuración por entorno.
"""

import logging
import sys
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.services.fabric.deploy import (  # noqa: E402
    CommandResult,
    DeployResult,
    DestroyResult,
    FabricDeployError,
)
from app.services.fabric.host_service import (  # noqa: E402
    BIND_ENV,
    MANIFEST_ENV,
    PORT_ENV,
    TLS_CERT_ENV,
    TLS_KEY_ENV,
    TOKEN_ENV,
    HostServiceConfigError,
    HostServiceSettings,
    create_app,
    load_settings,
)

TOKEN = "t" * 40
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _manifest() -> dict:
    """Un switch, un dispositivo y credenciales señuelo (para AC13)."""
    return {
        "segments": [
            {"id": "vlan-10", "vlan_id": 10, "cidr": "10.10.0.0/24",
             "gateway": "10.10.0.1"},
        ],
        "devices": [
            {"id": "pc-01", "role": "pc", "segment": "vlan-10", "ip": "10.10.0.21"},
        ],
        "fabric": {
            "enabled": True,
            "switches": [{"id": "sw-a", "vlans": [10]}],
            "device_overrides": [{
                "id": "pc-01",
                "interfaces": [{
                    "segment": "vlan-10", "ip": "10.10.0.21/24",
                    "mac": "00:1c:42:10:10:21", "gateway": "10.10.0.1",
                    "vlan_tag": 10, "switch": "sw-a",
                }],
                "credentials": [
                    {"username": "admin", "password": "admin123", "service": "ssh"},
                    {"username": "root", "password": "toor", "service": "ssh"},
                ],
            }],
        },
    }


class FakeRunner:
    """Runner mínimo: todo responde OK y los puertos son los del plan."""

    def __init__(self, ports: dict[str, list[str]] | None = None):
        self.ports = ports or {}
        self.calls: list[list[str]] = []

    def run(self, args: list[str], check: bool = True) -> CommandResult:
        self.calls.append(list(args))
        stdout = ""
        if args[:2] == ["ovs-vsctl", "list-ports"]:
            stdout = "\n".join(self.ports.get(args[2], []))
        return CommandResult(args=list(args), returncode=0, stdout=stdout)


class FakeDeviceRuntime:
    def device_health(self, spec, known_device_ips=None) -> dict:
        return {
            "device_id": spec.device_id,
            "healthy": True,
            "runtime_available": True,
            "checks": [{"name": "container", "ok": True, "detail": "running"}],
        }


class FakeEngine:
    """Engine falso con resultados estructurados como el OVS real."""

    kind = "ovs"

    def __init__(self, fail_deploy: bool = False, fail_destroy: bool = False):
        self.runner = FakeRunner({"sw-a": ["dv00-pc01"]})
        self.device_runtime = FakeDeviceRuntime()
        self.fail_deploy = fail_deploy
        self.fail_destroy = fail_destroy
        self.last_result = None
        self.last_destroy_result = None
        self.deployed: list = []
        self.destroyed: list = []

    def deploy(self, plan, topology) -> None:
        if self.fail_deploy:
            raise FabricDeployError(["fallo simulado de deploy"])
        self.deployed.append(plan)
        self.last_result = DeployResult(
            bridges_created=[bridge.id for bridge in plan.bridges],
            links_created=[link.id for link in plan.links],
            containers_created=[device.device_id for device in plan.devices],
            device_ports_created=[
                iface.host_veth
                for device in plan.devices for iface in device.interfaces
            ],
            devices=[{
                "device_id": device.device_id,
                "container_id": f"cid-{device.container_name}",
                "pid": 4242,
                "success": True,
                "step": "",
                "error": "",
            } for device in plan.devices],
        )

    def destroy(self, topology) -> None:
        if self.fail_destroy:
            raise FabricDeployError(["fallo simulado de destroy"])
        self.destroyed.append(topology)
        self.last_destroy_result = DestroyResult(
            bridges_removed=["sw-a"],
            containers_removed=["pc-01"],
            devices=[{
                "device_id": "pc-01",
                "container_removed": True,
                "success": True,
                "step": "",
                "error": "",
            }],
        )


@pytest.fixture()
def manifest_file(tmp_path) -> Path:
    path = tmp_path / "network.yaml"
    path.write_text(yaml.safe_dump(_manifest()), encoding="utf-8")
    return path


@pytest.fixture()
def settings(manifest_file) -> HostServiceSettings:
    return HostServiceSettings(token=TOKEN, manifest=manifest_file)


@pytest.fixture()
def engine() -> FakeEngine:
    return FakeEngine()


@pytest.fixture()
def client(settings, engine) -> TestClient:
    return TestClient(create_app(settings, engine))


# ── Configuración y fail-closed ────────────────────────────


def test_fail_closed_sin_token(monkeypatch):
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    with pytest.raises(HostServiceConfigError):
        load_settings()
    with pytest.raises(HostServiceConfigError):
        create_app()


def test_token_corto_rechazado(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "x" * 31)
    with pytest.raises(HostServiceConfigError):
        load_settings()


def test_settings_por_defecto(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    monkeypatch.delenv(MANIFEST_ENV, raising=False)
    monkeypatch.delenv(BIND_ENV, raising=False)
    monkeypatch.delenv(PORT_ENV, raising=False)
    settings = load_settings()
    assert settings.manifest == Path("config/deception/network.yaml")
    assert settings.bind == "127.0.0.1"
    assert settings.port == 8090


def test_settings_por_entorno(monkeypatch, tmp_path):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    monkeypatch.setenv(MANIFEST_ENV, str(tmp_path / "m.yaml"))
    monkeypatch.setenv(BIND_ENV, "10.0.0.5")
    monkeypatch.setenv(PORT_ENV, "9001")
    settings = load_settings()
    assert settings.bind == "10.0.0.5"
    assert settings.port == 9001
    assert settings.manifest == tmp_path / "m.yaml"


@pytest.mark.parametrize("port", ["abc", "0", "70000"])
def test_puerto_invalido(monkeypatch, port):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    monkeypatch.setenv(PORT_ENV, port)
    with pytest.raises(HostServiceConfigError):
        load_settings()


# ── Autenticación ──────────────────────────────────────────


def test_sin_token_401(client):
    response = client.get("/status")
    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"


def test_esquema_no_bearer_401(client):
    response = client.get("/status", headers={"Authorization": f"Basic {TOKEN}"})
    assert response.status_code == 401


def test_token_invalido_401(client):
    response = client.get("/status", headers={"Authorization": "Bearer " + "z" * 40})
    assert response.status_code == 401


def test_token_valido_200(client):
    response = client.get("/status", headers=AUTH)
    assert response.status_code == 200


# ── Status / deploy / destroy ──────────────────────────────


def test_status_inicial(client, manifest_file):
    payload = client.get("/status", headers=AUTH).json()
    assert payload["service"] == "dystopia-fabric"
    assert payload["engine"] == "FakeEngine"
    assert payload["manifest"] == str(manifest_file)
    assert payload["busy"] is False
    assert payload["last_deploy"] is None
    assert payload["last_destroy"] is None
    assert len(payload["manifest_hash"]) == 64


def test_deploy_200(client, engine):
    response = client.post("/deploy", headers=AUTH)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["success"] is True
    assert payload["operation"] == "deploy"
    assert payload["bridges_created"] == ["sw-a"]
    assert payload["containers_created"] == ["pc-01"]
    assert payload["device_ports_created"] == ["dv00-pc01"]
    assert len(engine.deployed) == 1


def test_destroy_200(client, engine):
    assert client.post("/deploy", headers=AUTH).status_code == 200
    response = client.post("/destroy", headers=AUTH)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["operation"] == "destroy"
    assert payload["bridges_removed"] == ["sw-a"]
    assert payload["containers_removed"] == ["pc-01"]
    assert len(engine.destroyed) == 1


def test_status_tras_deploy(client):
    assert client.post("/deploy", headers=AUTH).status_code == 200
    payload = client.get("/status", headers=AUTH).json()
    assert payload["last_deploy"]["bridges_created"] == ["sw-a"]
    assert payload["last_destroy"] is None


def test_health_200(client):
    response = client.get("/health", headers=AUTH)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["service"] == "dystopia-fabric"
    assert payload["ok"] is True
    assert payload["healthy"] is True
    assert payload["runtime_available"] is True
    assert payload["devices_health"][0]["device_id"] == "pc-01"


# ── Errores ────────────────────────────────────────────────


def test_deploy_engine_error_502(settings):
    client = TestClient(create_app(settings, FakeEngine(fail_deploy=True)))
    response = client.post("/deploy", headers=AUTH)
    assert response.status_code == 502
    assert "fallo simulado de deploy" in response.json()["detail"]["errors"]


def test_destroy_engine_error_502(settings):
    client = TestClient(create_app(settings, FakeEngine(fail_destroy=True)))
    response = client.post("/destroy", headers=AUTH)
    assert response.status_code == 502
    assert "fallo simulado de destroy" in response.json()["detail"]["errors"]


def test_manifiesto_invalido_422(settings):
    broken = _manifest()
    broken["fabric"]["device_overrides"][0]["interfaces"][0]["switch"] = "sw-nope"
    settings.manifest.write_text(yaml.safe_dump(broken), encoding="utf-8")
    client = TestClient(create_app(settings, FakeEngine()))
    response = client.post("/deploy", headers=AUTH)
    assert response.status_code == 422
    assert any("sw-nope" in error for error in response.json()["detail"]["errors"])


def test_manifiesto_inexistente_503(tmp_path):
    settings = HostServiceSettings(token=TOKEN, manifest=tmp_path / "no-existe.yaml")
    client = TestClient(create_app(settings, FakeEngine()))
    response = client.post("/deploy", headers=AUTH)
    assert response.status_code == 503
    health = client.get("/health", headers=AUTH)
    assert health.status_code == 200
    assert health.json()["ok"] is False


def test_health_manifiesto_invalido(settings):
    broken = _manifest()
    broken["fabric"]["device_overrides"][0]["interfaces"][0]["switch"] = "sw-nope"
    settings.manifest.write_text(yaml.safe_dump(broken), encoding="utf-8")
    client = TestClient(create_app(settings, FakeEngine()))
    payload = client.get("/health", headers=AUTH).json()
    assert payload["ok"] is False
    assert payload["healthy"] is False
    assert any("sw-nope" in error for error in payload["errors"])


# ── Concurrencia ───────────────────────────────────────────


def test_operacion_concurrente_409(settings, engine):
    app = create_app(settings, engine)
    client = TestClient(app)
    app.state.operation_lock.acquire()
    try:
        response = client.post("/deploy", headers=AUTH)
        assert response.status_code == 409
        assert client.get("/status", headers=AUTH).json()["busy"] is True
        assert engine.deployed == []
    finally:
        app.state.operation_lock.release()
    assert client.post("/deploy", headers=AUTH).status_code == 200


# ── AC13 y logs ────────────────────────────────────────────


def test_respuestas_sin_credenciales(client):
    deploy = client.post("/deploy", headers=AUTH)
    status = client.get("/status", headers=AUTH)
    health = client.get("/health", headers=AUTH)
    for response in (deploy, status, health):
        text = response.text
        assert "admin123" not in text
        assert "toor" not in text
        assert '"password"' not in text
        assert '"credentials"' not in text


def test_token_no_aparece_en_logs(client, caplog):
    caplog.set_level(logging.INFO)
    assert client.post("/deploy", headers=AUTH).status_code == 200
    assert TOKEN not in caplog.text
    assert "admin123" not in caplog.text


# ── TLS opcional ────────────────────────────────────────────


def test_tls_requiere_cert_y_clave_juntos(monkeypatch, tmp_path):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    monkeypatch.setenv(TLS_CERT_ENV, str(tmp_path / "server.crt"))
    monkeypatch.delenv(TLS_KEY_ENV, raising=False)
    with pytest.raises(HostServiceConfigError):
        load_settings()


def test_tls_con_cert_y_clave(monkeypatch, tmp_path):
    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    cert.write_text("cert")
    key.write_text("key")
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    monkeypatch.setenv(TLS_CERT_ENV, str(cert))
    monkeypatch.setenv(TLS_KEY_ENV, str(key))
    settings = load_settings()
    assert settings.tls is True
    assert settings.tls_cert == cert and settings.tls_key == key


def test_tls_cert_inexistente_falla(monkeypatch, tmp_path):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    monkeypatch.setenv(TLS_CERT_ENV, str(tmp_path / "no.crt"))
    monkeypatch.setenv(TLS_KEY_ENV, str(tmp_path / "no.key"))
    with pytest.raises(HostServiceConfigError):
        load_settings()


def test_status_expone_tls_y_cifrado(client):
    payload = client.get("/status", headers=AUTH).json()
    assert "tls" in payload
    assert "credentials_encrypted" in payload
