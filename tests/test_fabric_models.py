"""Pruebas de los modelos Pydantic del Network Fabric.

Cubren tipos, valores por defecto, alias ``from`` de ``FabricLink``, la
configuración vacía y el roundtrip ``model_dump``/``model_validate`` del
esquema YAML del spec (§3.2), además de la compatibilidad hacia atrás de
``DeceptionNetwork``: sin ``fabric`` la clave no se serializa y el YAML
existente se sigue cargando igual.
"""

import re
import sys
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.models.deception import (  # noqa: E402
    DeceptionNetwork,
    DeceptionSegment,
)
from app.services.deception import topology_svc  # noqa: E402
from app.services.fabric.models import (  # noqa: E402
    FabricAdminBehavior,
    FabricConfig,
    FabricCredential,
    FabricDefaults,
    FabricDeviceOverride,
    FabricDeviceResources,
    FabricInterface,
    FabricLink,
    FabricLogging,
    FabricNeighbor,
    FabricRoute,
    FabricSwitch,
    FabricTopology,
)

SPEC_FILE = REPO / "docs" / "specs" / "DYSTOPIA_NETWORK_FABRIC_SPEC.md"


def _spec_manifest() -> dict:
    """Extrae y parsea el bloque YAML completo del spec (§3.2)."""
    text = SPEC_FILE.read_text(encoding="utf-8")
    block = re.search(r"```yaml\n(.*?)```", text, re.S)
    assert block is not None, "el spec debe incluir un bloque YAML"
    return yaml.safe_load(block.group(1))


# ── FabricSwitch ─────────────────────────────────────────────


def test_switch_valores_por_defecto():
    switch = FabricSwitch(id="sw-core")
    assert switch.type == "ovs"
    assert switch.stp is False
    assert switch.vlans == []
    assert switch.uplink is None
    assert switch.description == ""


def test_switch_tipo_literal_rechaza_otros():
    with pytest.raises(ValidationError):
        FabricSwitch(id="sw-core", type="linuxbridge")


def test_switch_vlans_deben_ser_enteros():
    switch = FabricSwitch(id="sw-core", vlans=[10, 20, 30])
    assert switch.vlans == [10, 20, 30]
    with pytest.raises(ValidationError):
        FabricSwitch(id="sw-core", vlans="no-es-lista")


# ── FabricLink ───────────────────────────────────────────────


def test_link_acepta_alias_from():
    link = FabricLink.model_validate({"from": "sw-core", "to": "sw-oficina"})
    assert link.from_ == "sw-core"
    assert link.to == "sw-oficina"


def test_link_acepta_nombre_de_campo_from_():
    link = FabricLink(from_="sw-core", to="sw-oficina")
    assert link.from_ == "sw-core"


def test_link_serializa_con_alias_from():
    link = FabricLink(from_="sw-core", to="sw-oficina")
    assert link.model_dump()["from"] == "sw-core"
    assert "from_" not in link.model_dump()


def test_link_valores_por_defecto():
    link = FabricLink(from_="a", to="b")
    assert link.trunk is True
    assert link.bandwidth is None


def test_link_requiere_from():
    with pytest.raises(ValidationError):
        FabricLink.model_validate({"to": "sw-oficina"})


# ── FabricInterface ──────────────────────────────────────────


def test_interface_requeridos_y_defaults():
    iface = FabricInterface(
        segment="vlan-oficina",
        ip="10.10.0.21/24",
        mac="00:1c:42:10:10:21",
        switch="sw-oficina",
    )
    assert iface.name == "eth0"
    assert iface.gateway is None
    assert iface.vlan_tag is None


def test_interface_requiere_mac():
    with pytest.raises(ValidationError):
        FabricInterface(
            segment="vlan-oficina",
            ip="10.10.0.21/24",
            switch="sw-oficina",
        )


def test_interface_vlan_tag_entero():
    iface = FabricInterface(
        segment="vlan-oficina",
        ip="10.10.0.21/24",
        mac="00:1c:42:10:10:21",
        switch="sw-oficina",
        vlan_tag=10,
    )
    assert iface.vlan_tag == 10


# ── FabricCredential ─────────────────────────────────────────


def test_credential_requeridos_y_defaults():
    cred = FabricCredential(username="admin", password="admin123", service="ssh")
    assert cred.purpose == ""


def test_credential_requiere_password():
    with pytest.raises(ValidationError):
        FabricCredential(username="admin", service="ssh")


# ── FabricNeighbor ───────────────────────────────────────────


def test_neighbor_hostname_por_defecto():
    neighbor = FabricNeighbor(ip="10.10.0.1", mac="00:1c:42:10:10:01")
    assert neighbor.hostname == ""
    assert neighbor.ip == "10.10.0.1"


def test_neighbor_requiere_ip_y_mac():
    with pytest.raises(ValidationError):
        FabricNeighbor(ip="10.10.0.1")


# ── FabricRoute ──────────────────────────────────────────────


def test_route_requiere_destination_y_gateway():
    route = FabricRoute(destination="0.0.0.0/0", gateway="10.10.0.1")
    assert route.destination == "0.0.0.0/0"
    with pytest.raises(ValidationError):
        FabricRoute(destination="0.0.0.0/0")


# ── FabricAdminBehavior ──────────────────────────────────────


def test_admin_behavior_valores_por_defecto():
    behavior = FabricAdminBehavior()
    assert behavior.management_protocol == "ssh"
    assert behavior.management_port == 22
    assert behavior.login_banner == ""
    assert behavior.motd == ""
    assert behavior.shell_prompt == "$ "
    assert behavior.idle_timeout == 300


def test_admin_behavior_puerto_debe_ser_entero():
    with pytest.raises(ValidationError):
        FabricAdminBehavior(management_port="no-es-puerto")


# ── FabricLogging ────────────────────────────────────────────


def test_logging_valores_por_defecto():
    logging_cfg = FabricLogging()
    assert logging_cfg.syslog_target is None
    assert logging_cfg.log_level == "info"
    assert logging_cfg.forward_to_dystopia is True


def test_logging_boolean_estricto():
    with pytest.raises(ValidationError):
        FabricLogging(forward_to_dystopia="tal vez")


# ── FabricDeviceResources / FabricDefaults ───────────────────


def test_device_resources_valores_por_defecto():
    resources = FabricDeviceResources()
    assert resources.image == "dystopia/fabric-device:v1"
    assert resources.mem_limit == "128m"
    assert resources.cpus == 0.25


def test_device_resources_cpus_debe_ser_numero():
    with pytest.raises(ValidationError):
        FabricDeviceResources(cpus="alta")


def test_defaults_valores_por_defecto():
    defaults = FabricDefaults()
    assert defaults.device_image == "dystopia/fabric-device:v1"
    assert defaults.mem_limit == "128m"
    assert defaults.cpus == 0.25


# ── FabricDeviceOverride ────────────────────────────────────


def test_device_override_vacio_listas_y_opcionales():
    override = FabricDeviceOverride(id="pc-01")
    assert override.interfaces == []
    assert override.credentials == []
    assert override.neighbors == []
    assert override.routes == []
    assert override.admin_behavior is None
    assert override.logging is None
    assert override.resources is None


def test_device_override_completo():
    override = FabricDeviceOverride.model_validate({
        "id": "pc-01",
        "interfaces": [{
            "segment": "vlan-oficina",
            "ip": "10.10.0.21/24",
            "mac": "00:1c:42:10:10:21",
            "switch": "sw-oficina",
            "vlan_tag": 10,
        }],
        "credentials": [{"username": "admin", "password": "x", "service": "ssh"}],
        "neighbors": [{"ip": "10.10.0.1", "mac": "00:1c:42:10:10:01"}],
        "routes": [{"destination": "0.0.0.0/0", "gateway": "10.10.0.1"}],
        "admin_behavior": {"management_protocol": "ssh"},
        "logging": {"forward_to_dystopia": False},
        "resources": {"cpus": 0.5},
    })
    assert isinstance(override.interfaces[0], FabricInterface)
    assert isinstance(override.credentials[0], FabricCredential)
    assert isinstance(override.neighbors[0], FabricNeighbor)
    assert isinstance(override.routes[0], FabricRoute)
    assert isinstance(override.admin_behavior, FabricAdminBehavior)
    assert isinstance(override.logging, FabricLogging)
    assert isinstance(override.resources, FabricDeviceResources)
    assert override.resources.cpus == 0.5


# ── FabricConfig ─────────────────────────────────────────────


def test_config_vacia_valores_por_defecto():
    config = FabricConfig()
    assert config.enabled is False
    assert config.name == "dystopia-fabric"
    assert config.defaults == FabricDefaults()
    assert config.switches == []
    assert config.links == []
    assert config.device_overrides == []


def test_config_completa_anidada():
    config = FabricConfig.model_validate({
        "enabled": True,
        "name": "corporate-deception-net",
        "defaults": {"mem_limit": "256m"},
        "switches": [{"id": "sw-core", "vlans": [10, 20]}],
        "links": [{"from": "sw-core", "to": "sw-oficina"}],
        "device_overrides": [{"id": "pc-01"}],
    })
    assert config.enabled is True
    assert config.defaults.mem_limit == "256m"
    assert config.switches[0].id == "sw-core"
    assert config.links[0].from_ == "sw-core"
    assert config.device_overrides[0].id == "pc-01"


# ── FabricTopology ───────────────────────────────────────────


def test_topology_requiere_config_segments_y_devices():
    topology = FabricTopology(
        config=FabricConfig(enabled=True),
        segments=[DeceptionSegment(id="vlan-oficina", cidr="10.10.0.0/24")],
        devices=[],
    )
    assert topology.config.enabled is True
    assert topology.segments[0].id == "vlan-oficina"
    assert topology.switch_port_map == {}
    assert topology.device_switch_map == {}


def test_topology_valida_segmentos_por_forward_ref():
    with pytest.raises(ValidationError):
        FabricTopology(config=FabricConfig(), segments=[{"id": "sin-cidr"}], devices=[])


def test_topology_mapeos_calculados():
    topology = FabricTopology(
        config=FabricConfig(),
        segments=[],
        devices=[],
        switch_port_map={"sw-oficina": ["veth-pc-01"]},
        device_switch_map={"pc-01": "sw-oficina"},
    )
    assert topology.switch_port_map["sw-oficina"] == ["veth-pc-01"]
    assert topology.device_switch_map["pc-01"] == "sw-oficina"


# ── DeceptionNetwork + compatibilidad hacia atrás ───────────


def test_network_sin_fabric_por_defecto():
    network = DeceptionNetwork()
    assert network.fabric is None
    assert "fabric" not in network.model_dump(exclude_none=True)


def test_network_legado_roundtrip_sin_fabric():
    raw = {
        "segments": [{"id": "vlan-oficina", "cidr": "10.10.0.0/24"}],
        "devices": [{
            "id": "pc-01",
            "role": "pc",
            "segment": "vlan-oficina",
            "ip": "10.10.0.21",
        }],
    }
    network = DeceptionNetwork.model_validate(raw)
    dumped = network.model_dump(mode="json", exclude_none=True)
    assert set(dumped) == {"segments", "devices"}
    assert DeceptionNetwork.model_validate(dumped) == network


def test_network_con_fabric_coerciona_config():
    network = DeceptionNetwork.model_validate({
        "segments": [],
        "devices": [],
        "fabric": {"enabled": True, "switches": [{"id": "sw-core"}]},
    })
    assert isinstance(network.fabric, FabricConfig)
    assert network.fabric.enabled is True
    assert network.fabric.switches[0].id == "sw-core"


def test_network_roundtrip_esquema_spec():
    network = DeceptionNetwork.model_validate(_spec_manifest())
    dumped = network.model_dump(mode="json", exclude_none=True)
    # El enlace se serializa con el alias del manifiesto, no con from_.
    assert dumped["fabric"]["links"][0]["from"] == "sw-core"
    assert "from_" not in dumped["fabric"]["links"][0]
    reloaded = DeceptionNetwork.model_validate(dumped)
    assert reloaded.model_dump(exclude_none=True) == network.model_dump(exclude_none=True)


def test_network_esquema_spec_completo():
    network = DeceptionNetwork.model_validate(_spec_manifest())
    assert len(network.segments) == 1
    assert len(network.devices) == 1
    assert network.fabric is not None
    assert network.fabric.enabled is True
    assert network.fabric.name == "corporate-deception-net"
    assert [s.id for s in network.fabric.switches] == [
        "sw-core", "sw-oficina", "sw-servidores", "sw-camaras",
    ]
    assert [o.id for o in network.fabric.device_overrides] == [
        "pc-recepcion-01", "srv-files-01", "cam-entrada-01",
    ]
    assert network.fabric.links[0].from_ == "sw-core"
    assert network.fabric.links[0].bandwidth is None


# ── Persistencia (topology_svc._write) ──────────────────────


def test_write_sin_fabric_no_agrega_clave(tmp_path, monkeypatch):
    target = tmp_path / "network.yaml"
    monkeypatch.setattr(topology_svc, "NETWORK_FILE", target)
    topology_svc.invalidate_cache()

    topology_svc._write(DeceptionNetwork(segments=[
        DeceptionSegment(id="vlan-oficina", cidr="10.10.0.0/24"),
    ]))

    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert "fabric" not in data
    assert data["segments"][0]["id"] == "vlan-oficina"


def test_write_con_fabric_conserva_alias_y_recarga(tmp_path, monkeypatch):
    target = tmp_path / "network.yaml"
    monkeypatch.setattr(topology_svc, "NETWORK_FILE", target)
    topology_svc.invalidate_cache()

    topology_svc._write(DeceptionNetwork.model_validate(_spec_manifest()))

    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert data["fabric"]["links"][0]["from"] == "sw-core"
    assert "from_" not in data["fabric"]["links"][0]

    reloaded = topology_svc.load_network()
    assert reloaded.fabric is not None
    assert reloaded.fabric.links[0].from_ == "sw-core"
