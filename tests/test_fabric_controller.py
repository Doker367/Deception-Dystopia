"""Pruebas del Fabric Controller y su máquina de estados (§6.1).

Cubren el arranque (disabled/ready/error), todas las flechas válidas e
inválidas, el doble gate por entorno, la idempotencia de deploy/rebuild,
la persistencia en ``fabric_state`` y la garantía AC13 (credenciales
fuera de ``topology_json`` y de las respuestas).
"""

import copy
import json
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.services.fabric import controller as controller_mod  # noqa: E402
from app.services.fabric.controller import (  # noqa: E402
    FABRIC_ENABLE_ENV,
    FabricController,
    FabricEngine,
    FabricState,
    FabricStateError,
    NullFabricEngine,
)

SECRETS = ("admin123", "toor", "P@ssw0rd")


def _manifest() -> dict:
    """Manifiesto válido con credenciales señuelo (para AC13)."""
    return copy.deepcopy({
        "segments": [
            {
                "id": "vlan-oficina", "vlan_id": 10,
                "cidr": "10.10.0.0/24", "gateway": "10.10.0.1",
            },
            {
                "id": "vlan-servidores", "vlan_id": 20,
                "cidr": "10.20.0.0/24", "gateway": "10.20.0.1",
            },
        ],
        "devices": [
            {"id": "pc-01", "role": "pc", "segment": "vlan-oficina", "ip": "10.10.0.21"},
            {"id": "srv-01", "role": "server", "segment": "vlan-servidores", "ip": "10.20.0.10"},
        ],
        "fabric": {
            "enabled": True,
            "name": "test-fabric",
            "switches": [
                {"id": "sw-core", "vlans": [10, 20]},
                {"id": "sw-oficina", "vlans": [10], "uplink": "sw-core"},
                {"id": "sw-servidores", "vlans": [20], "uplink": "sw-core"},
            ],
            "links": [{"from": "sw-core", "to": "sw-oficina"}],
            "device_overrides": [
                {
                    "id": "pc-01",
                    "interfaces": [{
                        "name": "eth0", "segment": "vlan-oficina",
                        "ip": "10.10.0.21/24", "mac": "00:1c:42:10:10:21",
                        "gateway": "10.10.0.1", "vlan_tag": 10,
                        "switch": "sw-oficina",
                    }],
                    "credentials": [
                        {"username": "admin", "password": "admin123", "service": "ssh"},
                        {"username": "root", "password": "toor", "service": "ssh"},
                    ],
                },
                {
                    "id": "srv-01",
                    "interfaces": [{
                        "name": "eth0", "segment": "vlan-servidores",
                        "ip": "10.20.0.10/24", "mac": "00:1c:42:20:10:10",
                        "gateway": "10.20.0.1", "vlan_tag": 20,
                        "switch": "sw-servidores",
                    }],
                    "credentials": [
                        {"username": "admin", "password": "P@ssw0rd", "service": "ssh"},
                    ],
                },
            ],
        },
    })


@pytest.fixture(autouse=True)
def _gate_abierto(monkeypatch):
    """Por defecto el doble gate está abierto; los tests de gate lo cierran."""
    monkeypatch.setenv(FABRIC_ENABLE_ENV, "true")


def _make(
    tmp_path: Path,
    manifest: dict | None = None,
    engine: NullFabricEngine | None = None,
    loader=None,
    name: str = "fabric.db",
) -> FabricController:
    return FabricController(
        engine=engine if engine is not None else NullFabricEngine(),
        db_path=tmp_path / name,
        manifest_loader=loader if loader is not None else (lambda: manifest or _manifest()),
    )


def _rows(db_path: Path) -> list[dict]:
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(
            "SELECT * FROM fabric_state ORDER BY id"
        )]


def _broken_manifest() -> dict:
    manifest = _manifest()
    manifest["fabric"]["device_overrides"][0]["interfaces"][0]["switch"] = "sw-nope"
    return manifest


# ── Arranque (flechas [*] → ...) ────────────────────────────


def test_estado_inicial_ready(tmp_path):
    controller = _make(tmp_path)
    status = controller.get_status()
    assert status["state"] == "ready"
    assert status["enabled"] is True
    assert status["error"] is None
    assert status["warnings"] == []


def test_estado_inicial_disabled_sin_bloque(tmp_path):
    manifest = _manifest()
    manifest.pop("fabric")
    controller = _make(tmp_path, manifest=manifest)
    assert controller.get_status()["state"] == "disabled"


def test_estado_inicial_disabled_con_enabled_false(tmp_path):
    manifest = _manifest()
    manifest["fabric"]["enabled"] = False
    controller = _make(tmp_path, manifest=manifest)
    assert controller.get_status()["state"] == "disabled"


def test_estado_inicial_error_manifiesto_invalido(tmp_path):
    controller = _make(tmp_path, manifest=_broken_manifest())
    status = controller.get_status()
    assert status["state"] == "error"
    assert "sw-nope" in (status["error"] or "")


# ── Transiciones válidas ────────────────────────────────────


def test_deploy_ready_a_deployed(tmp_path):
    engine = NullFabricEngine()
    controller = _make(tmp_path, engine=engine)
    result = controller.deploy()
    assert result["success"] is True
    assert result["state"] == "deployed"
    assert controller.get_status()["state"] == "deployed"
    assert len(engine.deployed) == 1


def test_deploy_entrega_plan_completo_al_engine(tmp_path):
    engine = NullFabricEngine()
    controller = _make(tmp_path, engine=engine)
    controller.deploy()
    plan = engine.deployed[0]
    assert [b.id for b in plan.bridges] == ["sw-core", "sw-oficina", "sw-servidores"]
    assert len(plan.links) == 2
    assert [d.device_id for d in plan.devices] == ["pc-01", "srv-01"]


def test_destroy_deployed_a_ready(tmp_path):
    engine = NullFabricEngine()
    controller = _make(tmp_path, engine=engine)
    controller.deploy()
    result = controller.destroy()
    assert result["success"] is True
    assert result["state"] == "ready"
    assert len(engine.destroyed) == 1
    assert controller.get_status()["state"] == "ready"


def test_rebuild_desde_deployed(tmp_path):
    engine = NullFabricEngine()
    controller = _make(tmp_path, engine=engine)
    controller.deploy()
    result = controller.rebuild()
    assert result["success"] is True
    assert result["state"] == "deployed"
    assert len(engine.destroyed) == 1
    assert len(engine.deployed) == 2


def test_rebuild_desde_ready_despliega(tmp_path):
    engine = NullFabricEngine()
    controller = _make(tmp_path, engine=engine)
    result = controller.rebuild()
    assert result["success"] is True
    assert result["state"] == "deployed"
    assert engine.destroyed == []
    assert len(engine.deployed) == 1


def test_deploy_fallido_deploying_a_error(tmp_path):
    engine = NullFabricEngine(fail_deploy=True)
    controller = _make(tmp_path, engine=engine)
    result = controller.deploy()
    assert result["success"] is False
    assert result["state"] == "error"
    status = controller.get_status()
    assert status["state"] == "error"
    assert "deploy falló" in (status["error"] or "")


def test_destroy_fallido_destroying_a_error(tmp_path):
    engine = NullFabricEngine()
    controller = _make(tmp_path, engine=engine)
    controller.deploy()
    engine.fail_destroy = True
    result = controller.destroy()
    assert result["success"] is False
    assert result["state"] == "error"
    assert "destroy falló" in (controller.get_status()["error"] or "")


def test_error_a_ready_tras_corregir_y_validar(tmp_path):
    controller = _make(tmp_path, manifest=_broken_manifest())
    assert controller.get_status()["state"] == "error"

    report = controller.validate(_manifest())
    assert report["valid"] is True
    assert report["state"] == "ready"
    assert controller.get_status()["state"] == "ready"
    assert controller.get_status()["error"] is None


def test_error_sigue_error_si_validate_sigue_invalido(tmp_path):
    controller = _make(tmp_path, manifest=_broken_manifest())
    assert controller.get_status()["state"] == "error"
    report = controller.validate(_broken_manifest())
    assert report["valid"] is False
    assert report["state"] == "error"


def test_deploy_idempotente_dos_veces(tmp_path):
    engine = NullFabricEngine()
    controller = _make(tmp_path, engine=engine)
    first = controller.deploy()
    second = controller.deploy()
    assert first["success"] is True
    assert second["success"] is True
    assert controller.get_status()["state"] == "deployed"
    # El segundo deploy destruye el anterior antes de recrearlo.
    assert len(engine.deployed) == 2
    assert len(engine.destroyed) == 1


# ── Transiciones inválidas ─────────────────────────────────


def test_destroy_desde_ready_rechazado(tmp_path):
    controller = _make(tmp_path)
    with pytest.raises(FabricStateError) as excinfo:
        controller.destroy()
    assert "destroy solo aplica desde 'deployed'" in str(excinfo.value)
    assert excinfo.value.state == "ready"


def test_deploy_desde_disabled_rechazado(tmp_path):
    manifest = _manifest()
    manifest["fabric"]["enabled"] = False
    controller = _make(tmp_path, manifest=manifest)
    result = controller.deploy()
    assert result["success"] is False
    assert "deshabilitado" in result["errors"][0]
    assert controller.get_status()["state"] == "disabled"


def test_deploy_desde_error_rechazado(tmp_path):
    controller = _make(tmp_path, manifest=_broken_manifest())
    with pytest.raises(FabricStateError) as excinfo:
        controller.deploy()
    assert "validate()" in str(excinfo.value)


def test_deploy_mientras_deploying_rechazado(tmp_path):
    controller = _make(tmp_path)
    controller.get_status()
    controller._state = FabricState.DEPLOYING
    with pytest.raises(FabricStateError):
        controller.deploy()


def test_deploy_mientras_destroying_rechazado(tmp_path):
    controller = _make(tmp_path)
    controller.get_status()
    controller._state = FabricState.DESTROYING
    with pytest.raises(FabricStateError):
        controller.deploy()


def test_destroy_desde_disabled_rechazado(tmp_path):
    manifest = _manifest()
    manifest["fabric"]["enabled"] = False
    controller = _make(tmp_path, manifest=manifest)
    with pytest.raises(FabricStateError):
        controller.destroy()


def test_rebuild_desde_error_rechazado(tmp_path):
    controller = _make(tmp_path, manifest=_broken_manifest())
    with pytest.raises(FabricStateError):
        controller.rebuild()


def test_validate_mientras_deploying_rechazado(tmp_path):
    controller = _make(tmp_path)
    controller.get_status()
    controller._state = FabricState.DEPLOYING
    with pytest.raises(FabricStateError) as excinfo:
        controller.validate(_manifest())
    assert "operación en curso" in str(excinfo.value)


def test_error_de_transicion_lista_alternativas(tmp_path):
    controller = _make(tmp_path)
    controller.get_status()
    with pytest.raises(FabricStateError) as excinfo:
        controller._transition(FabricState.DISABLED)
    assert excinfo.value.errors
    assert "deploying" in excinfo.value.errors[0]


# ── Doble gate §9.1 ────────────────────────────────────────


def test_gate_cerrado_rechaza_deploy(tmp_path, monkeypatch):
    engine = NullFabricEngine()
    controller = _make(tmp_path, engine=engine)
    controller.get_status()
    monkeypatch.delenv(FABRIC_ENABLE_ENV)

    result = controller.deploy()
    assert result["success"] is False
    assert FABRIC_ENABLE_ENV in result["errors"][0]
    assert result["state"] == "ready"
    assert engine.deployed == []


def test_gate_cerrado_no_destruye_en_rebuild(tmp_path, monkeypatch):
    engine = NullFabricEngine()
    controller = _make(tmp_path, engine=engine)
    controller.deploy()
    monkeypatch.delenv(FABRIC_ENABLE_ENV)

    result = controller.rebuild()
    assert result["success"] is False
    assert controller.get_status()["state"] == "deployed"
    assert engine.destroyed == []


def test_gate_acepta_mayusculas(tmp_path, monkeypatch):
    monkeypatch.setenv(FABRIC_ENABLE_ENV, "TRUE")
    controller = _make(tmp_path)
    assert controller.get_status()["gate_open"] is True
    assert controller.deploy()["success"] is True


# ── Persistencia (§7) ──────────────────────────────────────


def test_persistencia_secuencia_deploy(tmp_path):
    db = tmp_path / "fabric.db"
    controller = _make(tmp_path)
    controller.get_status()
    controller.deploy()
    rows = _rows(db)
    assert [row["state"] for row in rows] == ["ready", "deploying", "deployed"]
    assert all(row["manifest_hash"] for row in rows)


def test_persistencia_ultima_fila_destroy(tmp_path):
    db = tmp_path / "fabric.db"
    controller = _make(tmp_path)
    controller.deploy()
    controller.destroy()
    rows = _rows(db)
    assert [row["state"] for row in rows] == [
        "ready", "deploying", "deployed", "destroying", "ready",
    ]
    assert rows[-1]["destroyed_at"] is not None
    assert rows[-1]["deployed_at"] is None


def test_manifest_hash_sha256_estable(tmp_path):
    controller = _make(tmp_path)
    controller.get_status()
    digest = controller.get_status()["manifest_hash"]
    assert len(digest) == 64
    int(digest, 16)
    assert controller.validate(_manifest())["manifest_hash"] == digest


def test_manifest_hash_cambia_con_el_manifiesto(tmp_path):
    controller = _make(tmp_path)
    controller.get_status()
    before = controller.get_status()["manifest_hash"]
    other = _manifest()
    other["fabric"]["name"] = "otro-fabric"
    assert controller.validate(other)["manifest_hash"] != before


def test_timestamps_deployed_y_destroyed(tmp_path):
    db = tmp_path / "fabric.db"
    controller = _make(tmp_path)
    controller.deploy()
    deployed = _rows(db)[-1]
    assert deployed["state"] == "deployed"
    assert deployed["deployed_at"] is not None
    assert deployed["destroyed_at"] is None

    controller.destroy()
    ready = _rows(db)[-1]
    assert ready["state"] == "ready"
    assert ready["destroyed_at"] is not None
    assert ready["deployed_at"] is None


def test_error_persistido_en_fallo(tmp_path):
    db = tmp_path / "fabric.db"
    controller = _make(tmp_path, engine=NullFabricEngine(fail_deploy=True))
    controller.deploy()
    last = _rows(db)[-1]
    assert last["state"] == "error"
    assert "deploy falló" in last["error"]


def test_fabric_device_state_existe_vacia(tmp_path):
    db = tmp_path / "fabric.db"
    controller = _make(tmp_path)
    controller.deploy()
    with sqlite3.connect(str(db)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM fabric_device_state").fetchone()[0] == 0


def test_db_path_monkeypatchable(tmp_path, monkeypatch):
    custom = tmp_path / "custom-fabric.db"
    monkeypatch.setattr(controller_mod, "DB_PATH", custom)
    controller = FabricController(
        engine=NullFabricEngine(), manifest_loader=lambda: _manifest(),
    )
    controller.get_status()
    assert custom.exists()


# ── Seguridad AC13: credenciales nunca en JSON/respuestas ───


def _assert_no_secrets(payload: str) -> None:
    for secret in SECRETS:
        assert secret not in payload
    assert '"password"' not in payload
    assert '"credentials"' not in payload


def test_topology_json_sin_credenciales(tmp_path):
    db = tmp_path / "fabric.db"
    controller = _make(tmp_path)
    controller.deploy()
    last = _rows(db)[-1]
    assert last["state"] == "deployed"
    _assert_no_secrets(last["topology_json"])


def test_get_topology_sin_credenciales(tmp_path):
    controller = _make(tmp_path)
    topology = controller.get_topology()
    assert topology["config"]["name"] == "test-fabric"
    _assert_no_secrets(json.dumps(topology, ensure_ascii=False))


def test_get_devices_sin_credenciales(tmp_path):
    controller = _make(tmp_path)
    devices = controller.get_devices()
    assert [device["device_id"] for device in devices] == ["pc-01", "srv-01"]
    _assert_no_secrets(json.dumps(devices, ensure_ascii=False))


# ── Validación ─────────────────────────────────────────────


def test_validate_valido_sin_errores(tmp_path):
    controller = _make(tmp_path)
    report = controller.validate(_manifest())
    assert report["valid"] is True
    assert report["errors"] == []
    assert report["warnings"] == []
    assert report["state"] == "ready"


def test_validate_invalido_acumula_errores(tmp_path):
    manifest = _broken_manifest()
    manifest["fabric"]["device_overrides"].append({"id": "fantasma"})
    controller = _make(tmp_path)
    report = controller.validate(manifest)
    assert report["valid"] is False
    assert len(report["errors"]) >= 2
    joined = " ".join(report["errors"])
    assert "sw-nope" in joined
    assert "fantasma" in joined


def test_validate_no_despliega(tmp_path):
    engine = NullFabricEngine()
    controller = _make(tmp_path, engine=engine)
    controller.validate(_manifest())
    assert engine.deployed == []
    assert controller.get_status()["state"] == "ready"


def test_validate_warnings_sin_interfaces_y_vlan_none(tmp_path):
    manifest = _manifest()
    manifest["devices"].append({
        "id": "cam-01", "role": "camera", "segment": "vlan-oficina",
        "ip": "10.10.0.50",
    })
    manifest["fabric"]["device_overrides"].append({"id": "cam-01"})
    manifest["fabric"]["device_overrides"][0]["interfaces"][0]["vlan_tag"] = None
    controller = _make(tmp_path)
    warnings = controller.validate(manifest)["warnings"]
    assert any("no declara interfaces" in warning for warning in warnings)
    assert any("vlan_tag" in warning for warning in warnings)


def test_validate_warnings_fabric_deshabilitado(tmp_path):
    manifest = _manifest()
    manifest["fabric"]["enabled"] = False
    controller = _make(tmp_path)
    report = controller.validate(manifest)
    assert report["valid"] is True
    assert report["state"] == "disabled"
    assert any("enabled" in warning for warning in report["warnings"])


def test_validate_warnings_sin_bloque_fabric(tmp_path):
    manifest = _manifest()
    manifest.pop("fabric")
    controller = _make(tmp_path)
    report = controller.validate(manifest)
    assert report["valid"] is True
    assert report["state"] == "disabled"
    assert any("no declara el bloque 'fabric'" in warning for warning in report["warnings"])


def test_validate_en_deployed_es_informe_puro(tmp_path):
    engine = NullFabricEngine()
    controller = _make(tmp_path, engine=engine)
    controller.deploy()
    report = controller.validate(_broken_manifest())
    assert report["valid"] is False
    assert report["state"] == "deployed"
    # El manifiesto desplegado no se sustituye por uno inválido.
    assert controller.get_topology()["config"]["name"] == "test-fabric"
    assert len(engine.deployed) == 1


# ── Consultas ──────────────────────────────────────────────


def test_get_status_campos(tmp_path):
    controller = _make(tmp_path)
    status = controller.get_status()
    assert status["state"] == "ready"
    assert status["enabled"] is True
    assert status["gate_open"] is True
    assert status["name"] == "test-fabric"
    assert status["switches"] == 3
    assert status["links"] == 1
    assert status["devices"] == 2
    assert status["deployed_at"] is None
    assert status["destroyed_at"] is None


def test_get_topology_estructura(tmp_path):
    controller = _make(tmp_path)
    topology = controller.get_topology()
    assert len(topology["segments"]) == 2
    assert len(topology["config"]["switches"]) == 3
    assert topology["switch_port_map"]["sw-oficina"] == ["pc-01:eth0"]


def test_get_devices_planificados(tmp_path):
    controller = _make(tmp_path)
    devices = controller.get_devices()
    assert len(devices) == 2
    assert devices[0]["container_name"] == "dystopia-fabric-pc-01"
    assert devices[0]["interfaces"][0]["switch"] == "sw-oficina"


def test_get_health_antes_y_despues_de_deploy(tmp_path):
    controller = _make(tmp_path)
    before = controller.get_health()
    assert before["healthy"] is False
    assert before["runtime_available"] is False
    assert before["state"] == "ready"

    controller.deploy()
    after = controller.get_health()
    assert after["healthy"] is True
    assert after["state"] == "deployed"
    assert all(check["ok"] for check in after["checks"])


def test_get_health_tras_error(tmp_path):
    controller = _make(tmp_path, engine=NullFabricEngine(fail_deploy=True))
    controller.deploy()
    health = controller.get_health()
    assert health["healthy"] is False
    assert health["state"] == "error"
    assert health["checks"][0]["ok"] is False


# ── Grafo D3/ECharts ───────────────────────────────────────


def test_get_topology_graph_estructura(tmp_path):
    manifest = _manifest()
    manifest["fabric"]["switches"][0]["vlans"] = [10, 20, 99]
    controller = _make(tmp_path, manifest=manifest)
    graph = controller.get_topology_graph()
    assert graph["state"] == "ready"
    assert {node["id"] for node in graph["nodes"]} == {
        "switch:sw-core", "switch:sw-oficina", "switch:sw-servidores",
        "device:pc-01", "device:srv-01",
    }
    switch = next(n for n in graph["nodes"] if n["id"] == "switch:sw-core")
    assert switch["kind"] == "switch"
    assert switch["group"] == "switch"
    device = next(n for n in graph["nodes"] if n["id"] == "device:pc-01")
    assert device["group"] == "vlan-10"
    assert device["vlan_tag"] == 10
    assert device["role"] == "pc"
    assert {group["id"] for group in graph["groups"]} == {
        "vlan-10", "vlan-20", "vlan-99",
    }


def test_get_topology_graph_enlaces_y_estado(tmp_path):
    controller = _make(tmp_path)
    graph = controller.get_topology_graph()
    trunks = [edge for edge in graph["edges"] if edge["kind"] == "trunk"]
    access = [edge for edge in graph["edges"] if edge["kind"] == "access"]
    assert len(trunks) == 2
    assert len(access) == 2
    assert all(edge["state"] == "down" for edge in graph["edges"])

    controller.deploy()
    deployed = controller.get_topology_graph()
    assert all(edge["state"] == "up" for edge in deployed["edges"])


def test_get_topology_graph_vacio_sin_manifiesto_valido(tmp_path):
    controller = _make(tmp_path, manifest=_broken_manifest())
    assert controller.get_topology_graph() == {
        "nodes": [], "edges": [], "groups": [], "state": "error",
    }


# ── Singleton y engine ─────────────────────────────────────


def test_get_controller_singleton_y_reset(tmp_path):
    first = controller_mod.reset_controller(
        engine=NullFabricEngine(),
        db_path=tmp_path / "singleton-a.db",
        manifest_loader=lambda: _manifest(),
    )
    assert controller_mod.get_controller() is first

    second = controller_mod.reset_controller(
        engine=NullFabricEngine(),
        db_path=tmp_path / "singleton-b.db",
        manifest_loader=lambda: _manifest(),
    )
    assert second is not first
    assert controller_mod.get_controller() is second


def test_null_engine_cumple_el_protocolo():
    engine = NullFabricEngine()
    assert isinstance(engine, FabricEngine)


def test_null_engine_simula_fallos():
    with pytest.raises(RuntimeError):
        NullFabricEngine(fail_deploy=True).deploy(None, None)
    with pytest.raises(RuntimeError):
        NullFabricEngine(fail_destroy=True).destroy(None)


# ── Selección de engine y lifecycle (Fase 3b) ───────────────


def test_engine_stub_por_defecto(tmp_path, monkeypatch):
    monkeypatch.delenv(controller_mod.FABRIC_ENGINE_ENV, raising=False)
    controller = controller_mod.reset_controller(
        db_path=tmp_path / "engine-stub.db", manifest_loader=lambda: _manifest(),
    )
    assert controller.get_status()["engine"] == "stub"


def test_engine_ovs_por_env_sin_ejecutar_ovs(tmp_path, monkeypatch):
    from app.services.fabric.deploy import OvsFabricEngine

    monkeypatch.setenv(controller_mod.FABRIC_ENGINE_ENV, "ovs")
    controller = controller_mod.reset_controller(
        db_path=tmp_path / "engine-ovs.db", manifest_loader=lambda: _manifest(),
    )
    assert controller.get_status()["engine"] == "ovs"
    assert isinstance(controller._engine, OvsFabricEngine)


def test_engine_env_invalido_cae_a_stub(tmp_path, monkeypatch):
    monkeypatch.setenv(controller_mod.FABRIC_ENGINE_ENV, "docker")
    controller = controller_mod.reset_controller(
        db_path=tmp_path / "engine-bogus.db", manifest_loader=lambda: _manifest(),
    )
    assert controller.get_status()["engine"] == "stub"


def test_get_status_mantiene_contrato_y_anade_campos(tmp_path):
    controller = _make(tmp_path)
    status = controller.get_status()
    for key in (
        "state", "enabled", "gate_open", "name", "manifest_hash", "error",
        "warnings", "deployed_at", "destroyed_at", "switches", "links", "devices",
    ):
        assert key in status
    assert status["engine"] == "custom"  # engine inyectado por _make
    assert status["last_operation"] is None


def test_get_last_operation(tmp_path):
    controller = _make(tmp_path)
    assert controller.get_last_operation() == {}
    controller.deploy()
    last = controller.get_last_operation()
    assert last["action"] == "deploy"
    assert last["engine"] == "NullFabricEngine"
    controller.destroy()
    assert controller.get_last_operation()["action"] == "destroy"


def test_get_health_stub_estructural_con_runtime_none(tmp_path):
    controller = _make(tmp_path)
    before = controller.get_health()
    assert before["runtime_available"] is False
    assert before["runtime"] is None
    assert before["healthy"] is False

    controller.deploy()
    after = controller.get_health()
    assert after["healthy"] is True
    assert after["runtime_available"] is False
    assert after["runtime"] is None


class _FakeOvsRunner:
    """Runner mínimo para ejercitar el engine OVS sin OVS real."""

    def __init__(self, pid: int = 4242):
        self.bridges: set[str] = set()
        self.links: set[str] = set()
        self.pairs: dict[str, str] = {}
        self.ports: dict[str, str] = {}
        self.containers: dict[str, dict] = {}
        self.pid = pid
        self.calls: list[list[str]] = []

    def run(self, args: list[str], check: bool = True):
        self.calls.append(list(args))
        returncode, stdout, stderr = self._dispatch(args)
        return SimpleNamespace(
            args=list(args), returncode=returncode, stdout=stdout, stderr=stderr
        )

    def _dispatch(self, args: list[str]) -> tuple[int, str, str]:
        if args[:2] == ["docker", "create"]:
            name = args[args.index("--name") + 1]
            self.containers[name] = {
                "id": f"cid-{name}", "name": name, "state": "created", "pid": 0,
            }
            return (0, f"cid-{name}", "")
        if args[:2] == ["docker", "start"]:
            container = self._by_id(args[2])
            if container is None:
                return (1, "", "no such container")
            container["state"] = "running"
            container["pid"] = self.pid
            return (0, container["id"], "")
        if args[:2] == ["docker", "stop"]:
            container = self._by_id(args[2])
            if container is None:
                return (1, "", "no such container")
            container["state"] = "exited"
            container["pid"] = 0
            return (0, container["id"], "")
        if args[:2] == ["docker", "rm"]:
            container = self._by_id(args[3])
            if container is None:
                return (1, "", "no such container")
            self.containers.pop(container["name"], None)
            return (0, container["id"], "")
        if args[:2] == ["docker", "inspect"]:
            container = self._by_id(args[-1])
            if container is None:
                return (1, "", "no such container")
            if args[3] == "{{.Id}}":
                return (0, container["id"], "")
            payload = {
                "Id": container["id"],
                "Name": f"/{container['name']}",
                "State": {"Pid": container["pid"], "Status": container["state"]},
                "Config": {"Image": "img", "Labels": {}},
            }
            return (0, json.dumps(payload), "")
        if args[:2] == ["ovs-vsctl", "--version"]:
            return (0, "ovs-vsctl 3.1", "")
        if args[:2] == ["nsenter", "-t"]:
            return (0, "", "")
        if args[:2] == ["ip", "-V"]:
            return (0, "ip utility", "")
        if args[:2] == ["ovs-vsctl", "br-exists"]:
            return (0, "", "") if args[2] in self.bridges else (2, "", "")
        if args[:2] == ["ovs-vsctl", "add-br"]:
            self.bridges.add(args[2])
            return (0, "", "")
        if args[:3] == ["ovs-vsctl", "set", "bridge"]:
            return (0, "", "")
        if args[:2] == ["ovs-vsctl", "port-to-br"]:
            if args[2] in self.ports:
                return (0, self.ports[args[2]], "")
            return (1, "", "no such port")
        if args[:2] == ["ovs-vsctl", "add-port"]:
            self.ports[args[3]] = args[2]
            return (0, "", "")
        if args[:2] == ["ovs-vsctl", "del-port"]:
            self.ports.pop(args[3], None)
            return (0, "", "")
        if args[:2] == ["ovs-vsctl", "list-ports"]:
            return (0, "\n".join(
                port for port, bridge in self.ports.items() if bridge == args[2]
            ), "")
        if args[:2] == ["ip", "link"]:
            if args[2] == "show":
                return (0, "", "") if args[3] in self.links else (1, "", "no such device")
            if args[2] == "add":
                self.links.add(args[3])
                self.links.add(args[8])
                self.pairs[args[3]] = args[8]
                self.pairs[args[8]] = args[3]
                return (0, "", "")
            if args[2] == "set":
                return (0, "", "")
            if args[2] == "del":
                peer = self.pairs.pop(args[3], None)
                self.links.discard(args[3])
                if peer is not None:
                    self.links.discard(peer)
                    self.pairs.pop(peer, None)
                return (0, "", "")
        return (1, "", f"comando no soportado: {args}")

    def _by_id(self, value: str) -> dict | None:
        if value in self.containers:
            return self.containers[value]
        for container in self.containers.values():
            if container["id"] == value:
                return container
        return None


def test_get_health_delega_en_lifecycle_con_ovs(tmp_path):
    from app.services.fabric.deploy import OvsFabricEngine

    runner = _FakeOvsRunner()
    controller = controller_mod.reset_controller(
        engine=OvsFabricEngine(runner=runner, privilege_check=lambda: True),
        db_path=tmp_path / "health-ovs.db",
        manifest_loader=lambda: _manifest(),
    )
    controller.deploy()

    health = controller.get_health()
    assert health["runtime_available"] is True
    assert health["healthy"] is True
    assert health["runtime"] is not None
    assert health["runtime"]["bridges"]["missing"] == []
    assert health["runtime"]["links"]["missing"] == []
    assert any(check["name"] == "bridges" for check in health["checks"])

    # Un bridge que desaparece degrada la salud sin cambiar la state machine.
    runner.bridges.discard("sw-oficina")
    runner.ports = {port: bridge for port, bridge in runner.ports.items()
                    if bridge != "sw-oficina"}
    degraded = controller.get_health()
    assert degraded["healthy"] is False
    assert degraded["state"] == "deployed"
    assert degraded["runtime"]["bridges"]["missing"] == ["sw-oficina"]


# ── fabric_device_state y vistas con runtime (Fase 4) ───────


class _StubDeviceRuntime:
    """DeviceRuntime falso para probar persistencia y fallo parcial."""

    def __init__(self, fail_for: set[str] | None = None):
        self.fail_for = set(fail_for or [])

    def deploy_device(self, spec):
        from app.services.fabric.runtime import DeviceRuntimeResult

        if spec.device_id in self.fail_for:
            return DeviceRuntimeResult(
                device_id=spec.device_id, container_name=spec.container_name,
                success=False, error_step="container_create",
                errors=["fallo simulado del device runtime"],
            )
        return DeviceRuntimeResult(
            device_id=spec.device_id, container_name=spec.container_name,
            success=True, container_id=f"cid-{spec.container_name}", pid=4242,
        )

    def destroy_device(self, spec):
        from app.services.fabric.runtime import DeviceDestroyResult

        return DeviceDestroyResult(
            device_id=spec.device_id, container_name=spec.container_name,
            success=True, container_removed=True,
        )

    def device_health(self, spec) -> dict:
        healthy = spec.device_id not in self.fail_for
        return {
            "device_id": spec.device_id,
            "healthy": healthy,
            "runtime_available": True,
            "container": {},
            "interfaces": [],
            "neighbors": [],
            "checks": [],
            "errors": [],
            "warnings": [],
        }


def _device_rows(db_path: Path) -> list[dict]:
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(
            "SELECT * FROM fabric_device_state ORDER BY device_id"
        )]


def _ovs_controller(tmp_path: Path, device_runtime=None, runner=None):
    from app.services.fabric.deploy import OvsFabricEngine

    return controller_mod.reset_controller(
        engine=OvsFabricEngine(
            runner=runner if runner is not None else _FakeOvsRunner(),
            privilege_check=lambda: True,
            device_runtime=device_runtime,
        ),
        db_path=tmp_path / "devices.db",
        manifest_loader=lambda: _manifest(),
    )


def test_fabric_device_state_persistido_tras_deploy(tmp_path):
    db_path = tmp_path / "devices.db"
    controller = _ovs_controller(tmp_path)
    controller.deploy()

    rows = _device_rows(db_path)
    assert [row["device_id"] for row in rows] == ["pc-01", "srv-01"]
    for row in rows:
        assert row["state"] == "running"
        assert row["container_id"] == f"cid-{row['container_name']}"
        assert row["container_name"] == f"dystopia-fabric-{row['device_id']}"
        assert row["last_health"]
    by_id = {row["device_id"]: row for row in rows}
    assert by_id["pc-01"]["ip"] == "10.10.0.21/24"
    assert by_id["pc-01"]["switch_id"] == "sw-oficina"
    assert by_id["pc-01"]["vlan_tag"] == 10
    assert by_id["srv-01"]["switch_id"] == "sw-servidores"
    assert by_id["srv-01"]["vlan_tag"] == 20


def test_fabric_device_state_upsert(tmp_path):
    db_path = tmp_path / "devices.db"
    controller = _ovs_controller(tmp_path)
    controller.deploy()
    controller.deploy()  # idempotente: recrea, no duplica filas
    rows = _device_rows(db_path)
    assert len(rows) == 2
    assert all(row["state"] == "running" for row in rows)


def test_fabric_device_state_tras_destroy(tmp_path):
    db_path = tmp_path / "devices.db"
    controller = _ovs_controller(tmp_path)
    controller.deploy()
    controller.destroy()
    rows = _device_rows(db_path)
    assert len(rows) == 2
    assert all(row["state"] == "stopped" for row in rows)
    assert all(row["container_id"] == "" for row in rows)


def test_get_devices_incluye_runtime(tmp_path):
    controller = _ovs_controller(tmp_path)
    before = controller.get_devices()
    assert [device["runtime"]["state"] for device in before] == ["pending", "pending"]

    controller.deploy()
    after = controller.get_devices()
    assert all(device["runtime"]["state"] == "running" for device in after)
    assert all(device["runtime"]["container_id"] for device in after)
    # Contrato previo intacto: campos del plan presentes.
    assert after[0]["interfaces"][0]["switch"] == "sw-oficina"


def test_get_health_incluye_salud_por_dispositivo(tmp_path):
    controller = _ovs_controller(tmp_path)
    before = controller.get_health()
    # Con engine OVS la salud por dispositivo se evalúa siempre (sin
    # contenedores aún: unhealthy).
    assert len(before["devices_health"]) == 2
    assert all(not device["healthy"] for device in before["devices_health"])
    assert before["healthy"] is False

    controller.deploy()
    health = controller.get_health()
    assert len(health["devices_health"]) == 2
    assert all(device["healthy"] for device in health["devices_health"])
    assert health["healthy"] is True
    assert health["devices_health"][0]["checks"]


def test_get_health_stub_sin_devices_health(tmp_path):
    controller = _make(tmp_path)
    controller.deploy()
    health = controller.get_health()
    assert health["devices_health"] == []
    assert health["runtime"] is None


def test_fallo_parcial_de_device_persiste_error(tmp_path):
    controller = _ovs_controller(
        tmp_path, device_runtime=_StubDeviceRuntime(fail_for={"srv-01"})
    )
    result = controller.deploy()
    assert result["success"] is True  # el resto continúa
    rows = {row["device_id"]: row for row in _device_rows(tmp_path / "devices.db")}
    assert rows["pc-01"]["state"] == "running"
    assert rows["srv-01"]["state"] == "error"
    assert "fallo simulado" in (rows["srv-01"]["error"] or "")
    assert controller.get_health()["healthy"] is False


def test_fallo_global_de_devices_persiste_error_y_estado(tmp_path):
    controller = _ovs_controller(
        tmp_path, device_runtime=_StubDeviceRuntime(fail_for={"pc-01", "srv-01"})
    )
    result = controller.deploy()
    assert result["success"] is False
    assert controller.get_status()["state"] == "error"
    rows = _device_rows(tmp_path / "devices.db")
    assert len(rows) == 2
    assert all(row["state"] == "error" for row in rows)


# ── Modo remote (Fase 4d) ──────────────────────────────────


def test_engine_remote_por_env(tmp_path, monkeypatch):
    from app.services.fabric.remote_engine import RemoteFabricEngine

    monkeypatch.setenv(controller_mod.FABRIC_ENGINE_ENV, "remote")
    monkeypatch.setenv("DYSTOPIA_FABRIC_REMOTE_URL", "http://host.test:8090")
    monkeypatch.setenv("DYSTOPIA_FABRIC_REMOTE_TOKEN", "t" * 40)
    controller = controller_mod.reset_controller(
        db_path=tmp_path / "engine-remote.db", manifest_loader=lambda: _manifest(),
    )
    assert controller.get_status()["engine"] == "remote"
    assert isinstance(controller._engine, RemoteFabricEngine)


def test_engine_remote_sin_url_falla_accionable(tmp_path, monkeypatch):
    monkeypatch.setenv(controller_mod.FABRIC_ENGINE_ENV, "remote")
    monkeypatch.delenv("DYSTOPIA_FABRIC_REMOTE_URL", raising=False)
    monkeypatch.delenv("DYSTOPIA_FABRIC_REMOTE_TOKEN", raising=False)
    with pytest.raises(RuntimeError) as excinfo:
        controller_mod.reset_controller(
            db_path=tmp_path / "engine-remote-sin-url.db",
            manifest_loader=lambda: _manifest(),
        )
    assert "DYSTOPIA_FABRIC_REMOTE_URL" in str(excinfo.value)


def test_engine_remote_sin_token_falla_accionable(tmp_path, monkeypatch):
    monkeypatch.setenv(controller_mod.FABRIC_ENGINE_ENV, "remote")
    monkeypatch.setenv("DYSTOPIA_FABRIC_REMOTE_URL", "http://host.test:8090")
    monkeypatch.delenv("DYSTOPIA_FABRIC_REMOTE_TOKEN", raising=False)
    with pytest.raises(RuntimeError) as excinfo:
        controller_mod.reset_controller(
            db_path=tmp_path / "engine-remote-sin-token.db",
            manifest_loader=lambda: _manifest(),
        )
    assert "DYSTOPIA_FABRIC_REMOTE_TOKEN" in str(excinfo.value)


def test_health_remote_delega_en_el_host(tmp_path, monkeypatch):
    """Con engine remote, /health refleja el estado real del servicio del host."""
    monkeypatch.setenv(controller_mod.FABRIC_ENGINE_ENV, "remote")
    monkeypatch.setenv("DYSTOPIA_FABRIC_REMOTE_URL", "http://host.test:8090")
    monkeypatch.setenv("DYSTOPIA_FABRIC_REMOTE_TOKEN", "t" * 40)
    controller = controller_mod.reset_controller(
        db_path=tmp_path / "health-remote.db", manifest_loader=lambda: _manifest(),
    )
    controller._engine.health = lambda: {  # type: ignore[method-assign]
        "runtime_available": True,
        "healthy": True,
        "checks": [{"name": "bridges", "ok": True, "detail": "4/4"}],
        "devices_health": [
            {"device_id": "pc-01", "healthy": True},
        ],
    }
    health = controller.get_health()
    assert health["runtime_available"] is True
    assert any(check.get("name") == "bridges" for check in health["checks"])
    assert health["devices_health"][0]["device_id"] == "pc-01"


def test_health_remote_caido_no_rompe(tmp_path, monkeypatch):
    """Si el host no responde, /health sigue devolviendo estructura válida."""
    monkeypatch.setenv(controller_mod.FABRIC_ENGINE_ENV, "remote")
    monkeypatch.setenv("DYSTOPIA_FABRIC_REMOTE_URL", "http://host.test:8090")
    monkeypatch.setenv("DYSTOPIA_FABRIC_REMOTE_TOKEN", "t" * 40)
    controller = controller_mod.reset_controller(
        db_path=tmp_path / "health-remote-caido.db", manifest_loader=lambda: _manifest(),
    )

    def _boom():
        raise RuntimeError("sin conexión")

    controller._engine.health = _boom  # type: ignore[method-assign]
    health = controller.get_health()
    assert health["runtime_available"] is False
    assert "healthy" in health


def test_modos_previos_no_cambian(tmp_path, monkeypatch):
    monkeypatch.delenv(controller_mod.FABRIC_ENGINE_ENV, raising=False)
    stub = controller_mod.reset_controller(
        db_path=tmp_path / "modo-stub.db", manifest_loader=lambda: _manifest(),
    )
    assert stub.get_status()["engine"] == "stub"

    monkeypatch.setenv(controller_mod.FABRIC_ENGINE_ENV, "ovs")
    ovs = controller_mod.reset_controller(
        db_path=tmp_path / "modo-ovs.db", manifest_loader=lambda: _manifest(),
    )
    assert ovs.get_status()["engine"] == "ovs"


# ── Restauración de estado tras reinicio (runtime persistente) ──


def test_arranque_restaura_deployed_si_el_manifiesto_coincide(tmp_path):
    """El runtime sobrevive al reinicio: no debe reportarse 'ready' si sigue desplegado."""
    first = _make(tmp_path, name="restore.db")
    first.deploy()
    assert first.get_status()["state"] == "deployed"

    second = _make(tmp_path, name="restore.db")
    status = second.get_status()
    assert status["state"] == "deployed"
    assert status["deployed_at"] is not None


def test_arranque_no_restaura_deployed_si_el_manifiesto_cambio(tmp_path):
    """Un manifiesto distinto exige un deploy nuevo: se queda en 'ready'."""
    first = _make(tmp_path, name="restore-cambio.db")
    first.deploy()

    changed = _manifest()
    changed["fabric"]["name"] = "otro-fabric"
    second = _make(tmp_path, manifest=changed, name="restore-cambio.db")
    assert second.get_status()["state"] == "ready"


def test_arranque_tras_destroy_no_restaura_deployed(tmp_path):
    first = _make(tmp_path, name="restore-destroy.db")
    first.deploy()
    first.destroy()

    second = _make(tmp_path, name="restore-destroy.db")
    assert second.get_status()["state"] == "ready"
