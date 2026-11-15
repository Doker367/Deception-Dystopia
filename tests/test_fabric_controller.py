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
