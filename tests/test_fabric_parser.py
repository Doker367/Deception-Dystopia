"""Pruebas del parser del Network Fabric (``network.yaml``).

Cubren el esquema del bloque ``fabric``, todas las reglas de integridad
del §3.3 (casos válidos e inválidos), la acumulación de errores, los
mapas computados de ``FabricTopology`` y la compatibilidad con
manifiestos sin ``fabric``.
"""

import copy
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.models.deception import DeceptionNetwork  # noqa: E402
from app.services.deception import topology_svc  # noqa: E402
from app.services.fabric.models import FabricConfig, FabricTopology  # noqa: E402
from app.services.fabric.parser import (  # noqa: E402
    FabricValidationError,
    build_topology,
    load_topology,
    parse_fabric,
    parse_manifest,
    validate_fabric,
)

EXAMPLE = REPO / "config" / "deception" / "network.fabric.example.yaml"
LEGACY = REPO / "config" / "deception" / "network.yaml"


def _manifest() -> dict:
    """Manifiesto mínimo válido: 2 segmentos, 2 dispositivos, 3 switches."""
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
                        "vlan_tag": 10, "switch": "sw-oficina",
                    }],
                },
                {
                    "id": "srv-01",
                    "interfaces": [{
                        "name": "eth0", "segment": "vlan-servidores",
                        "ip": "10.20.0.10/24", "mac": "00:1c:42:20:10:10",
                        "vlan_tag": 20, "switch": "sw-servidores",
                    }],
                },
            ],
        },
    })


def _errors(manifest: dict) -> list[str]:
    return validate_fabric(DeceptionNetwork.model_validate(manifest))


def _pc_interface(manifest: dict) -> dict:
    return manifest["fabric"]["device_overrides"][0]["interfaces"][0]


# ── Esquema del bloque fabric ───────────────────────────────


def test_parse_fabric_ausente_devuelve_config_deshabilitada():
    config = parse_fabric(None)
    assert isinstance(config, FabricConfig)
    assert config.enabled is False
    assert config.switches == []


def test_parse_fabric_vacio_usa_defaults():
    config = parse_fabric({})
    assert config == FabricConfig()
    assert config.name == "dystopia-fabric"
    assert config.defaults.cpus == 0.25


def test_parse_fabric_valido_anidado():
    config = parse_fabric(_manifest()["fabric"])
    assert config.enabled is True
    assert config.name == "test-fabric"
    assert config.switches[0].id == "sw-core"
    assert config.switches[1].uplink == "sw-core"
    assert config.links[0].from_ == "sw-core"
    assert config.device_overrides[0].interfaces[0].vlan_tag == 10


def test_parse_fabric_no_mapping_rechazado():
    with pytest.raises(FabricValidationError) as excinfo:
        parse_fabric(["no", "es", "mapping"])
    assert "objeto YAML" in str(excinfo.value)
    assert len(excinfo.value.errors) == 1


def test_parse_fabric_acumula_errores_de_esquema():
    with pytest.raises(FabricValidationError) as excinfo:
        parse_fabric({"switches": "no-es-lista", "links": 42})
    assert len(excinfo.value.errors) >= 2
    joined = " ".join(excinfo.value.errors)
    assert "fabric.switches" in joined
    assert "fabric.links" in joined


def test_parse_fabric_tipo_switch_literal():
    with pytest.raises(FabricValidationError) as excinfo:
        parse_fabric({"switches": [{"id": "sw-1", "type": "linuxbridge"}]})
    assert "fabric.switches.0.type" in str(excinfo.value)


def test_parse_fabric_acepta_alias_from():
    config = parse_fabric({"links": [{"from": "sw-a", "to": "sw-b"}]})
    assert config.links[0].from_ == "sw-a"


# ── Integridad cruzada: casos válidos ───────────────────────


def test_manifiesto_valido_sin_errores():
    assert _errors(_manifest()) == []


def test_red_sin_fabric_es_valida():
    manifest = _manifest()
    manifest.pop("fabric")
    assert _errors(manifest) == []


def test_ip_sin_prefijo_dentro_del_cidr():
    manifest = _manifest()
    _pc_interface(manifest)["ip"] = "10.10.0.21"
    assert _errors(manifest) == []


def test_vlan_tag_none_no_se_valida():
    manifest = _manifest()
    _pc_interface(manifest)["vlan_tag"] = None
    assert _errors(manifest) == []


# ── Integridad cruzada: device_overrides ────────────────────


def test_override_id_inexistente():
    manifest = _manifest()
    manifest["fabric"]["device_overrides"].append({"id": "fantasma"})
    errors = _errors(manifest)
    assert any("fantasma" in e and "device_override" in e for e in errors)


def test_override_duplicado():
    manifest = _manifest()
    manifest["fabric"]["device_overrides"].append({"id": "pc-01"})
    errors = _errors(manifest)
    assert any("más de un device_override" in e for e in errors)


# ── Integridad cruzada: segmentos y switches ────────────────


def test_interfaz_segmento_inexistente():
    manifest = _manifest()
    _pc_interface(manifest)["segment"] = "vlan-nope"
    errors = _errors(manifest)
    assert any("segmento inexistente 'vlan-nope'" in e for e in errors)


def test_interfaz_switch_inexistente():
    manifest = _manifest()
    _pc_interface(manifest)["switch"] = "sw-nope"
    errors = _errors(manifest)
    assert any("switch inexistente 'sw-nope'" in e for e in errors)


def test_uplink_inexistente():
    manifest = _manifest()
    manifest["fabric"]["switches"][1]["uplink"] = "sw-nope"
    errors = _errors(manifest)
    assert any("uplink inexistente 'sw-nope'" in e for e in errors)


def test_uplink_a_si_mismo():
    manifest = _manifest()
    manifest["fabric"]["switches"][0]["uplink"] = "sw-core"
    errors = _errors(manifest)
    assert any("a sí mismo" in e for e in errors)


def test_switch_duplicado():
    manifest = _manifest()
    manifest["fabric"]["switches"].append({"id": "sw-core", "vlans": [10]})
    errors = _errors(manifest)
    assert any("'sw-core' está declarado más de una vez" in e for e in errors)


# ── Integridad cruzada: VLAN e IP ───────────────────────────


def test_vlan_tag_fuera_del_switch():
    manifest = _manifest()
    _pc_interface(manifest)["vlan_tag"] = 20  # sw-oficina solo troncaliza 10
    errors = _errors(manifest)
    assert any("VLAN 20" in e and "sw-oficina" in e for e in errors)


def test_ip_fuera_del_cidr():
    manifest = _manifest()
    _pc_interface(manifest)["ip"] = "10.99.0.21/24"
    errors = _errors(manifest)
    assert any("10.99.0.21/24" in e and "10.10.0.0/24" in e for e in errors)


def test_ip_invalida():
    manifest = _manifest()
    _pc_interface(manifest)["ip"] = "no-es-ip"
    errors = _errors(manifest)
    assert any("no-es-ip" in e and "fuera del CIDR" in e for e in errors)


# ── Integridad cruzada: unicidad IP/MAC ─────────────────────


def test_ip_duplicada():
    manifest = _manifest()
    srv = manifest["fabric"]["device_overrides"][1]["interfaces"][0]
    srv.update({"ip": "10.10.0.21/24", "segment": "vlan-oficina",
                "switch": "sw-oficina", "vlan_tag": 10})
    errors = _errors(manifest)
    assert any("IP duplicada '10.10.0.21/24'" in e for e in errors)


def test_mac_duplicada_case_insensitive():
    manifest = _manifest()
    manifest["fabric"]["device_overrides"][1]["interfaces"][0]["mac"] = "00:1C:42:10:10:21"
    errors = _errors(manifest)
    assert any("MAC duplicada" in e for e in errors)


# ── Integridad cruzada: enlaces ─────────────────────────────


def test_link_switch_inexistente():
    manifest = _manifest()
    manifest["fabric"]["links"] = [{"from": "sw-core", "to": "sw-nope"}]
    errors = _errors(manifest)
    assert any("switch inexistente 'sw-nope'" in e for e in errors)


def test_link_a_si_mismo():
    manifest = _manifest()
    manifest["fabric"]["links"] = [{"from": "sw-core", "to": "sw-core"}]
    errors = _errors(manifest)
    assert any("consigo mismo" in e for e in errors)


# ── Acumulación de errores ──────────────────────────────────


def test_errores_acumulados_sin_cortar_en_el_primero():
    manifest = _manifest()
    manifest["fabric"]["device_overrides"].append({"id": "fantasma"})
    manifest["fabric"]["switches"][1]["uplink"] = "sw-ghost"
    manifest["fabric"]["links"] = [{"from": "sw-core", "to": "sw-ghost"}]
    pc = _pc_interface(manifest)
    pc["segment"] = "vlan-nope"
    pc["switch"] = "sw-nope"

    errors = _errors(manifest)
    assert len(errors) >= 5
    joined = " ".join(errors)
    for expected in (
        "fantasma", "sw-ghost", "vlan-nope", "sw-nope",
    ):
        assert expected in joined
    assert str(FabricValidationError(errors)).count("; ") >= 4


# ── Construcción de FabricTopology ──────────────────────────


def test_build_topology_mapas_computados():
    topology = build_topology(DeceptionNetwork.model_validate(_manifest()))
    assert isinstance(topology, FabricTopology)
    assert topology.config.enabled is True
    assert len(topology.segments) == 2
    assert len(topology.devices) == 2
    # Todos los switches declarados aparecen, aunque no tengan puertos.
    assert topology.switch_port_map == {
        "sw-core": [],
        "sw-oficina": ["pc-01:eth0"],
        "sw-servidores": ["srv-01:eth0"],
    }
    assert topology.device_switch_map == {
        "pc-01": "sw-oficina",
        "srv-01": "sw-servidores",
    }


def test_build_topology_sin_fabric():
    manifest = _manifest()
    manifest.pop("fabric")
    topology = build_topology(DeceptionNetwork.model_validate(manifest))
    assert topology.config == FabricConfig()
    assert topology.switch_port_map == {}
    assert topology.device_switch_map == {}


def test_build_topology_lanza_con_todos_los_errores():
    manifest = _manifest()
    manifest["fabric"]["device_overrides"].append({"id": "fantasma"})
    _pc_interface(manifest)["switch"] = "sw-nope"
    network = DeceptionNetwork.model_validate(manifest)
    with pytest.raises(FabricValidationError) as excinfo:
        build_topology(network)
    assert len(excinfo.value.errors) == 2
    assert "fantasma" in str(excinfo.value)
    assert "sw-nope" in str(excinfo.value)


def test_build_topology_es_determinista():
    network = DeceptionNetwork.model_validate(_manifest())
    first = build_topology(network).model_dump()
    second = build_topology(network).model_dump()
    assert first == second


# ── parse_manifest (manifiesto completo) ────────────────────


def test_parse_manifest_valido():
    topology = parse_manifest(_manifest())
    assert topology.config.name == "test-fabric"
    assert topology.switch_port_map["sw-oficina"] == ["pc-01:eth0"]


def test_parse_manifest_esquema_invalido():
    manifest = _manifest()
    del manifest["devices"][0]["role"]
    with pytest.raises(FabricValidationError) as excinfo:
        parse_manifest(manifest)
    assert any("devices.0.role" in e for e in excinfo.value.errors)


def test_parse_manifest_integridad_invalida():
    manifest = _manifest()
    _pc_interface(manifest)["switch"] = "sw-nope"
    with pytest.raises(FabricValidationError):
        parse_manifest(manifest)


def test_parse_manifest_no_mapping():
    with pytest.raises(FabricValidationError) as excinfo:
        parse_manifest("no soy yaml")
    assert "objeto YAML" in str(excinfo.value)


def test_error_de_validacion_es_value_error():
    with pytest.raises(ValueError) as excinfo:
        parse_manifest({"devices": [{"id": "x"}]})
    assert isinstance(excinfo.value, FabricValidationError)


# ── Ejemplo del §3.2 ────────────────────────────────────────


def test_ejemplo_yaml_valida_completo():
    raw = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    topology = parse_manifest(raw)
    assert topology.config.enabled is True
    assert topology.config.name == "corporate-deception-net"
    assert [s.id for s in topology.config.switches] == [
        "sw-core", "sw-oficina", "sw-servidores", "sw-camaras",
    ]
    assert topology.switch_port_map == {
        "sw-core": [],
        "sw-oficina": ["pc-recepcion-01:eth0"],
        "sw-servidores": ["srv-files-01:eth0"],
        "sw-camaras": ["cam-entrada-01:eth0"],
    }
    assert topology.device_switch_map == {
        "pc-recepcion-01": "sw-oficina",
        "srv-files-01": "sw-servidores",
        "cam-entrada-01": "sw-camaras",
    }


def test_ejemplo_roundtrip_dump_validate():
    raw = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    network = DeceptionNetwork.model_validate(raw)
    dumped = network.model_dump(mode="json", exclude_none=True)
    assert dumped["fabric"]["links"][0]["from"] == "sw-core"

    topology = parse_manifest(raw)
    reloaded = parse_manifest(dumped)
    assert reloaded.model_dump() == topology.model_dump()


# ── Compatibilidad e integración con topology_svc ───────────


def test_network_yaml_real_sin_fabric():
    raw = yaml.safe_load(LEGACY.read_text(encoding="utf-8"))
    assert "fabric" not in raw
    topology = parse_manifest(raw)
    assert topology.config == FabricConfig()
    assert topology.config.enabled is False
    assert topology.switch_port_map == {}
    assert topology.device_switch_map == {}


def test_load_topology_usa_topology_svc(tmp_path, monkeypatch):
    target = tmp_path / "network.yaml"
    target.write_text(EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(topology_svc, "NETWORK_FILE", target)
    topology_svc.invalidate_cache()

    topology = load_topology()
    assert topology.config.enabled is True
    assert topology.switch_port_map["sw-oficina"] == ["pc-recepcion-01:eth0"]


def test_load_topology_sin_fabric(tmp_path, monkeypatch):
    target = tmp_path / "network.yaml"
    target.write_text(yaml.safe_dump({
        "segments": [{"id": "vlan-x", "cidr": "10.0.0.0/24"}],
        "devices": [{
            "id": "dev-1", "role": "pc", "segment": "vlan-x", "ip": "10.0.0.2",
        }],
    }), encoding="utf-8")
    monkeypatch.setattr(topology_svc, "NETWORK_FILE", target)
    topology_svc.invalidate_cache()

    topology = load_topology()
    assert topology.config.enabled is False
    assert topology.switch_port_map == {}
