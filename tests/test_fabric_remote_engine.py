"""Pruebas del engine remoto del fabric (Fase 4d), sin red real.

Usan ``httpx.MockTransport`` como transporte falso: deploy/destroy OK,
cabecera Bearer, verificación de hash del manifiesto, mapeo de errores
(401/409/422/502/503/timeout/red), ausencia de reintentos y resultados
con la misma forma que el engine OVS.
"""

import hashlib
import sys
from pathlib import Path

import httpx
import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.services.fabric.controller import FabricPlan  # noqa: E402
from app.services.fabric.deploy import (  # noqa: E402
    DeployResult,
    DestroyResult,
    FabricDeployError,
)
from app.services.fabric.remote_engine import (  # noqa: E402
    REMOTE_TIMEOUT_ENV,
    REMOTE_TOKEN_ENV,
    REMOTE_URL_ENV,
    RemoteEngineConfigError,
    RemoteEngineSettings,
    RemoteFabricEngine,
    load_remote_settings,
)
from app.services.fabric.parser import parse_manifest  # noqa: E402
from app.services.fabric.topology import (  # noqa: E402
    build_bridge_specs,
    build_device_specs,
    build_link_specs,
)

TOKEN = "t" * 40
BASE_URL = "http://host.test:8090"


def _manifest_text() -> str:
    return yaml.safe_dump({
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
                ],
            }],
        },
    })


def _settings(tmp_path) -> RemoteEngineSettings:
    manifest = tmp_path / "network.yaml"
    manifest.write_text(_manifest_text(), encoding="utf-8")
    return RemoteEngineSettings(
        base_url=BASE_URL, token=TOKEN, timeout=5, manifest=manifest
    )


def _plan_and_topology():
    topology = parse_manifest(yaml.safe_load(_manifest_text()))
    plan = FabricPlan(
        bridges=build_bridge_specs(topology),
        links=build_link_specs(topology),
        devices=build_device_specs(topology),
    )
    return plan, topology


class Recorder:
    """Transporte falso: registra peticiones y responde por (método, ruta)."""

    def __init__(self, responses=None, fail_with=None):
        self.requests: list[tuple[str, str, str | None]] = []
        self.responses = list(responses or [])
        self.fail_with = fail_with

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((
            request.method,
            request.url.path,
            request.headers.get("authorization"),
        ))
        if self.fail_with is not None:
            raise self.fail_with
        for method, path, status, body in self.responses:
            if request.method == method and request.url.path == path:
                return httpx.Response(status, json=body)
        return httpx.Response(404, json={"detail": "ruta no encontrada"})

    def calls(self, method: str, path: str) -> int:
        return sum(
            1 for req_method, req_path, _ in self.requests
            if req_method == method and req_path == path
        )


def _engine(tmp_path, recorder: Recorder) -> RemoteFabricEngine:
    client = httpx.Client(
        base_url=BASE_URL, timeout=5,
        headers={"Authorization": f"Bearer {TOKEN}"},
        transport=httpx.MockTransport(recorder.handler),
    )
    return RemoteFabricEngine(settings=_settings(tmp_path), client=client)


def _deploy_response() -> dict:
    return {
        "success": True,
        "operation": "deploy",
        "service": "dystopia-fabric",
        "manifest": "/opt/dystopia/current/config/deception/network.yaml",
        "manifest_hash": "a" * 64,
        "engine": "OvsFabricEngine",
        "bridges_created": ["sw-a"],
        "bridges_existing": [],
        "links_created": [],
        "links_existing": [],
        "containers_created": ["pc-01"],
        "containers_failed": [],
        "device_ports_created": ["dv00-pc01"],
        "devices": [{
            "device_id": "pc-01", "container_id": "cid-x", "pid": 4242,
            "success": True, "step": "", "error": "",
        }],
        "warnings": [],
        "errors": [],
    }


def _destroy_response() -> dict:
    return {
        "success": True,
        "operation": "destroy",
        "service": "dystopia-fabric",
        "manifest_hash": "a" * 64,
        "engine": "OvsFabricEngine",
        "bridges_removed": ["sw-a"],
        "links_removed": [],
        "containers_removed": ["pc-01"],
        "devices": [{
            "device_id": "pc-01", "container_removed": True,
            "success": True, "step": "", "error": "",
        }],
        "warnings": [],
        "errors": [],
    }


# ── Camino feliz ────────────────────────────────────────────


def test_deploy_ok_con_bearer_y_hash(tmp_path):
    plan, topology = _plan_and_topology()
    local_hash = hashlib.sha256(_manifest_text().encode()).hexdigest()
    recorder = Recorder([
        ("GET", "/status", 200, {"service": "dystopia-fabric", "manifest_hash": local_hash}),
        ("POST", "/deploy", 200, _deploy_response()),
    ])
    engine = _engine(tmp_path, recorder)

    engine.deploy(plan, topology)

    assert [method for method, _, _ in recorder.requests] == ["GET", "POST"]
    assert recorder.requests[0][2] == f"Bearer {TOKEN}"
    assert recorder.requests[1][2] == f"Bearer {TOKEN}"
    assert isinstance(engine.last_result, DeployResult)
    assert engine.last_result.bridges_created == ["sw-a"]
    assert engine.last_result.containers_created == ["pc-01"]
    assert engine.last_result.device_ports_created == ["dv00-pc01"]


def test_destroy_ok(tmp_path):
    plan, topology = _plan_and_topology()
    local_hash = hashlib.sha256(_manifest_text().encode()).hexdigest()
    recorder = Recorder([
        ("GET", "/status", 200, {"manifest_hash": local_hash}),
        ("POST", "/destroy", 200, _destroy_response()),
    ])
    engine = _engine(tmp_path, recorder)

    engine.destroy(topology)

    assert isinstance(engine.last_destroy_result, DestroyResult)
    assert engine.last_destroy_result.bridges_removed == ["sw-a"]
    assert engine.last_destroy_result.containers_removed == ["pc-01"]


def test_hash_distinto_aborta_sin_deploy(tmp_path):
    plan, topology = _plan_and_topology()
    recorder = Recorder([
        ("GET", "/status", 200, {"manifest_hash": "b" * 64}),
    ])
    engine = _engine(tmp_path, recorder)

    with pytest.raises(FabricDeployError) as excinfo:
        engine.deploy(plan, topology)
    assert "difiere del local" in str(excinfo.value)
    assert recorder.calls("POST", "/deploy") == 0


def test_manifiesto_local_ilegible(tmp_path):
    plan, topology = _plan_and_topology()
    settings = RemoteEngineSettings(
        base_url=BASE_URL, token=TOKEN, timeout=5,
        manifest=tmp_path / "no-existe.yaml",
    )
    recorder = Recorder()
    engine = RemoteFabricEngine(
        settings=settings,
        client=httpx.Client(base_url=BASE_URL, timeout=5,
                            transport=httpx.MockTransport(recorder.handler)),
    )
    with pytest.raises(FabricDeployError) as excinfo:
        engine.deploy(plan, topology)
    assert "no se puede leer el manifiesto local" in str(excinfo.value)
    assert recorder.requests == []


# ── Mapeo de errores del host ───────────────────────────────


@pytest.mark.parametrize("status,fragmento,con_detalle", [
    (401, "token inválido", False),
    (409, "ocupado", False),
    (422, "manifiesto del host es inválido", True),
    (503, "no puede leer su manifiesto", True),
    (502, "engine del host falló", True),
    (500, "fallo interno", True),
])
def test_errores_http_se_mapean(tmp_path, status, fragmento, con_detalle):
    plan, topology = _plan_and_topology()
    local_hash = hashlib.sha256(_manifest_text().encode()).hexdigest()
    recorder = Recorder([
        ("GET", "/status", 200, {"manifest_hash": local_hash}),
        ("POST", "/deploy", status, {
            "detail": {"message": "detalle", "errors": ["error del host"]},
        }),
    ])
    engine = _engine(tmp_path, recorder)

    with pytest.raises(FabricDeployError) as excinfo:
        engine.deploy(plan, topology)
    assert fragmento in str(excinfo.value)
    if con_detalle:
        assert "error del host" in str(excinfo.value)
    # Sin reintentos en operaciones mutantes.
    assert recorder.calls("POST", "/deploy") == 1


def test_timeout_se_mapea(tmp_path):
    plan, topology = _plan_and_topology()
    recorder = Recorder(fail_with=httpx.ConnectTimeout("timed out"))
    engine = _engine(tmp_path, recorder)
    with pytest.raises(FabricDeployError) as excinfo:
        engine.deploy(plan, topology)
    assert "no respondió en 5s" in str(excinfo.value)


def test_error_de_red_se_mapea(tmp_path):
    plan, topology = _plan_and_topology()
    recorder = Recorder(fail_with=httpx.ConnectError("connection refused"))
    engine = _engine(tmp_path, recorder)
    with pytest.raises(FabricDeployError) as excinfo:
        engine.deploy(plan, topology)
    assert "no se pudo contactar" in str(excinfo.value)


def test_respuesta_no_json(tmp_path):
    plan, topology = _plan_and_topology()
    recorder = Recorder(fail_with=None)
    recorder.responses = [("POST", "/deploy", 200, {"__invalid__": True})]
    # Simula cuerpo no JSON sustituyendo el handler.
    recorder.handler = lambda request: httpx.Response(200, text="<html>")
    engine = _engine(tmp_path, recorder)
    with pytest.raises(FabricDeployError) as excinfo:
        engine.deploy(plan, topology)
    assert "no JSON" in str(excinfo.value)


# ── Configuración ───────────────────────────────────────────


def test_configuracion_faltante(monkeypatch):
    monkeypatch.delenv(REMOTE_URL_ENV, raising=False)
    monkeypatch.delenv(REMOTE_TOKEN_ENV, raising=False)
    with pytest.raises(RemoteEngineConfigError) as excinfo:
        load_remote_settings()
    assert REMOTE_URL_ENV in str(excinfo.value)


def test_token_corto_rechazado(monkeypatch):
    monkeypatch.setenv(REMOTE_URL_ENV, BASE_URL)
    monkeypatch.setenv(REMOTE_TOKEN_ENV, "corto")
    with pytest.raises(RemoteEngineConfigError) as excinfo:
        load_remote_settings()
    assert REMOTE_TOKEN_ENV in str(excinfo.value)


def test_timeout_invalido_rechazado(monkeypatch):
    monkeypatch.setenv(REMOTE_URL_ENV, BASE_URL)
    monkeypatch.setenv(REMOTE_TOKEN_ENV, TOKEN)
    monkeypatch.setenv(REMOTE_TIMEOUT_ENV, "nunca")
    with pytest.raises(RemoteEngineConfigError) as excinfo:
        load_remote_settings()
    assert REMOTE_TIMEOUT_ENV in str(excinfo.value)


def test_timeout_por_entorno(monkeypatch, tmp_path):
    monkeypatch.setenv(REMOTE_URL_ENV, BASE_URL)
    monkeypatch.setenv(REMOTE_TOKEN_ENV, TOKEN)
    monkeypatch.setenv(REMOTE_TIMEOUT_ENV, "42")
    monkeypatch.setenv("DYSTOPIA_FABRIC_MANIFEST", str(tmp_path / "m.yaml"))
    settings = load_remote_settings()
    assert settings.timeout == 42
    assert settings.manifest == tmp_path / "m.yaml"


def test_status_devuelve_forwarder_del_host(tmp_path):
    recorder = Recorder([(
        "GET", "/status", 200,
        {"forwarder": {"enabled": True, "pending": 0, "sent": 4,
                       "failed": 0, "last_error": None}},
    )])
    engine = _engine(tmp_path, recorder)
    payload = engine.status()
    assert payload["forwarder"]["sent"] == 4
    assert recorder.requests[0][0] == "GET"
    assert recorder.requests[0][1] == "/status"
