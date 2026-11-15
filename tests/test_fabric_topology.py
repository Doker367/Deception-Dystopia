"""Pruebas del Topology Manager del Network Fabric.

Verifican la transformación pura ``FabricTopology`` → planes de
despliegue: bridges OVS con sus puertos/VLANs, enlaces (uplinks y
explícitos con deduplicación), dispositivos con veths, rutas y ARP, y
las garantías de determinismo, no mutación y límites de nombre de Linux.
"""

import copy
import json
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.models.deception import DeceptionNetwork  # noqa: E402
from app.services.fabric.models import FabricConfig, FabricTopology  # noqa: E402
from app.services.fabric.parser import parse_manifest  # noqa: E402
from app.services.fabric import topology as topology_mod  # noqa: E402
from app.services.fabric.topology import (  # noqa: E402
    DeviceSpec,
    LinkSpec,
    build_bridge_specs,
    build_device_specs,
    build_link_specs,
)

EXAMPLE = REPO / "config" / "deception" / "network.fabric.example.yaml"


def _manifest() -> dict:
    """Manifiesto base: 3 switches, 2 dispositivos y un link duplicado."""
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
            "defaults": {"device_image": "dystopia/fabric-device:v1"},
            "switches": [
                {"id": "sw-core", "vlans": [10, 20]},
                {"id": "sw-oficina", "vlans": [10], "uplink": "sw-core"},
                {"id": "sw-servidores", "vlans": [20], "uplink": "sw-core"},
            ],
            # Duplica el uplink de sw-oficina: debe quedar un solo enlace.
            "links": [{"from": "sw-core", "to": "sw-oficina", "trunk": True}],
            "device_overrides": [
                {
                    "id": "pc-01",
                    "interfaces": [{
                        "name": "eth0", "segment": "vlan-oficina",
                        "ip": "10.10.0.21/24", "mac": "00:1c:42:10:10:21",
                        "gateway": "10.10.0.1", "vlan_tag": 10,
                        "switch": "sw-oficina",
                    }],
                },
                {
                    "id": "srv-01",
                    "interfaces": [{
                        "name": "eth0", "segment": "vlan-servidores",
                        "ip": "10.20.0.10/24", "mac": "00:1c:42:20:10:10",
                        "gateway": "10.20.0.1", "vlan_tag": 20,
                        "switch": "sw-servidores",
                    }],
                    "routes": [{
                        "destination": "0.0.0.0/0", "gateway": "10.20.0.1",
                    }],
                    "neighbors": [{
                        "ip": "10.20.0.1", "mac": "00:1c:42:20:00:01",
                        "hostname": "gateway",
                    }],
                },
            ],
        },
    })


def _topology(manifest: dict | None = None) -> FabricTopology:
    return parse_manifest(manifest or _manifest())


def _switch_ports(bridge_id: str, topology: FabricTopology) -> list:
    bridge = next(b for b in build_bridge_specs(topology) if b.id == bridge_id)
    return bridge.ports


# ── Bridges ─────────────────────────────────────────────────


def test_un_bridge_por_switch_en_orden_declarado():
    bridges = build_bridge_specs(_topology())
    assert [b.id for b in bridges] == ["sw-core", "sw-oficina", "sw-servidores"]


def test_bridges_internal_sin_conectividad_externa():
    assert all(b.internal is True for b in build_bridge_specs(_topology()))


def test_bridge_propaga_stp_y_vlans():
    manifest = _manifest()
    manifest["fabric"]["switches"][0].update({"stp": True, "vlans": [10, 20, 30]})
    topology = _topology(manifest)
    bridges = build_bridge_specs(topology)
    core = next(b for b in bridges if b.id == "sw-core")
    assert core.stp is True
    assert core.vlans == [10, 20, 30]
    assert core.vlans is not topology.config.switches[0].vlans


def test_puertos_de_dispositivo_con_tag_y_peer():
    ports = _switch_ports("sw-oficina", _topology())
    device_ports = [p for p in ports if p.kind == "device"]
    assert len(device_ports) == 1
    port = device_ports[0]
    assert port.tag == 10
    assert port.peer == "pc-01"


def test_puertos_troncales_sin_tag_y_peer():
    ports = _switch_ports("sw-core", _topology())
    trunk_ports = [p for p in ports if p.kind == "trunk"]
    assert {p.peer for p in trunk_ports} == {"sw-oficina", "sw-servidores"}
    assert all(p.tag is None for p in trunk_ports)


def test_puertos_de_dispositivo_antes_que_troncales():
    ports = _switch_ports("sw-oficina", _topology())
    assert [p.kind for p in ports] == ["device", "trunk"]


def test_vlan_tag_none_puerto_sin_etiqueta():
    manifest = _manifest()
    manifest["fabric"]["device_overrides"][0]["interfaces"][0]["vlan_tag"] = None
    port = _switch_ports("sw-oficina", _topology(manifest))[0]
    assert port.tag is None


def test_sin_switches_devuelve_planes_vacios():
    topology = FabricTopology(config=FabricConfig(), segments=[], devices=[])
    assert build_bridge_specs(topology) == []
    assert build_link_specs(topology) == []
    assert build_device_specs(topology) == []


# ── Enlaces ─────────────────────────────────────────────────


def test_dedup_uplink_y_link_explicito():
    links = build_link_specs(_topology())
    assert len(links) == 2
    pairs = [frozenset((link.from_switch, link.to_switch)) for link in links]
    assert len(pairs) == len(set(pairs))


def test_explicito_tiene_prioridad_sobre_uplink():
    links = build_link_specs(_topology())
    link = next(
        item for item in links
        if {item.from_switch, item.to_switch} == {"sw-core", "sw-oficina"}
    )
    assert link.source == "explicit"
    assert link.from_switch == "sw-core"
    assert link.to_switch == "sw-oficina"


def test_uplink_sin_link_explicito_aparece():
    links = build_link_specs(_topology())
    link = next(
        item for item in links
        if {item.from_switch, item.to_switch} == {"sw-core", "sw-servidores"}
    )
    assert link.source == "uplink"
    assert link.from_switch == "sw-servidores"
    assert link.to_switch == "sw-core"
    assert link.trunk is True


def test_link_explicito_conserva_trunk_y_bandwidth():
    manifest = _manifest()
    manifest["fabric"]["links"].append({
        "from": "sw-oficina", "to": "sw-servidores",
        "trunk": False, "bandwidth": 100,
    })
    link = next(
        item for item in build_link_specs(_topology(manifest))
        if {item.from_switch, item.to_switch} == {"sw-oficina", "sw-servidores"}
    )
    assert link.trunk is False
    assert link.bandwidth == 100


def test_links_explicitos_duplicados_se_deduplican():
    manifest = _manifest()
    manifest["fabric"]["links"].append({"from": "sw-core", "to": "sw-oficina"})
    manifest["fabric"]["links"].append({"from": "sw-oficina", "to": "sw-core"})
    links = build_link_specs(_topology(manifest))
    assert len(links) == 2


def test_ids_y_puertos_de_enlace_unicos():
    links = build_link_specs(_topology())
    assert [link.id for link in links] == ["lk00", "lk01"]
    assert len({link.port_from for link in links}) == len(links)
    assert len({link.port_to for link in links}) == len(links)


def test_link_ports_estan_en_sus_bridges():
    topology = _topology()
    bridges = {b.id: b for b in build_bridge_specs(topology)}
    for link in build_link_specs(topology):
        names_from = {p.name for p in bridges[link.from_switch].ports}
        names_to = {p.name for p in bridges[link.to_switch].ports}
        assert link.port_from in names_from
        assert link.port_to in names_to


# ── Dispositivos ────────────────────────────────────────────


def test_container_name_y_labels():
    device = build_device_specs(_topology())[0]
    assert device.container_name == "dystopia-fabric-pc-01"
    assert device.labels == {"dystopia.fabric": "true", "dystopia.device": "pc-01"}


def test_recursos_desde_defaults():
    manifest = _manifest()
    manifest["fabric"]["defaults"] = {
        "device_image": "custom:v1", "mem_limit": "256m", "cpus": 1.5,
    }
    device = build_device_specs(_topology(manifest))[0]
    assert (device.image, device.mem_limit, device.cpus) == ("custom:v1", "256m", 1.5)


def test_recursos_desde_override():
    manifest = _manifest()
    manifest["fabric"]["defaults"] = {
        "device_image": "custom:v1", "mem_limit": "256m", "cpus": 1.5,
    }
    manifest["fabric"]["device_overrides"][0]["resources"] = {
        "image": "override:v2", "mem_limit": "64m", "cpus": 0.1,
    }
    device = build_device_specs(_topology(manifest))[0]
    assert (device.image, device.mem_limit, device.cpus) == ("override:v2", "64m", 0.1)


def test_recursos_parciales_no_mezclan_con_defaults():
    manifest = _manifest()
    manifest["fabric"]["defaults"] = {
        "device_image": "custom:v1", "mem_limit": "256m", "cpus": 1.5,
    }
    manifest["fabric"]["device_overrides"][0]["resources"] = {"cpus": 0.5}
    device = build_device_specs(_topology(manifest))[0]
    # `FabricDeviceResources` completa sus defaults: no hay merge por campo.
    assert device.cpus == 0.5
    assert device.image == "dystopia/fabric-device:v1"
    assert device.mem_limit == "128m"


def test_interfaz_con_campos_de_red():
    device = build_device_specs(_topology())[0]
    iface = device.interfaces[0]
    assert iface.name == "eth0"
    assert iface.container_veth == "eth0"
    assert iface.switch == "sw-oficina"
    assert iface.vlan_tag == 10
    assert iface.ip == "10.10.0.21/24"
    assert iface.mac == "00:1c:42:10:10:21"
    assert iface.gateway == "10.10.0.1"


def test_rutas_vecinos_y_arp_en_el_dispositivo():
    device = next(d for d in build_device_specs(_topology()) if d.device_id == "srv-01")
    assert [(r.destination, r.gateway) for r in device.routes] == [
        ("0.0.0.0/0", "10.20.0.1"),
    ]
    assert [(n.ip, n.mac, n.hostname) for n in device.neighbors] == [
        ("10.20.0.1", "00:1c:42:20:00:01", "gateway"),
    ]
    assert [(a.ip, a.mac) for a in device.arp_entries] == [
        ("10.20.0.1", "00:1c:42:20:00:01"),
    ]


def test_dispositivo_sin_rutas_ni_vecinos():
    device = build_device_specs(_topology())[0]
    assert device.routes == []
    assert device.neighbors == []
    assert device.arp_entries == []


def test_dispositivo_sin_interfaces_no_se_despliega():
    manifest = _manifest()
    manifest["devices"].append({
        "id": "cam-01", "role": "camera", "segment": "vlan-oficina",
        "ip": "10.10.0.50",
    })
    manifest["fabric"]["device_overrides"].append({"id": "cam-01"})
    devices = build_device_specs(_topology(manifest))
    assert [d.device_id for d in devices] == ["pc-01", "srv-01"]
    assert all(p.peer != "cam-01" for b in build_bridge_specs(_topology(manifest)) for p in b.ports)


def test_dispositivo_sin_override_no_aparece():
    manifest = _manifest()
    manifest["devices"].append({
        "id": "router-01", "role": "router", "segment": "vlan-oficina",
        "ip": "10.10.0.60",
    })
    devices = build_device_specs(_topology(manifest))
    assert "router-01" not in {d.device_id for d in devices}


def test_dispositivo_multiple_interfaces():
    manifest = _manifest()
    manifest["fabric"]["device_overrides"][0]["interfaces"].append({
        "name": "eth1", "segment": "vlan-servidores",
        "ip": "10.20.0.50/24", "mac": "00:1c:42:20:00:50",
        "gateway": "10.20.0.1", "vlan_tag": 20,
        "switch": "sw-servidores",
    })
    topology = _topology(manifest)
    device = build_device_specs(topology)[0]
    assert [i.container_veth for i in device.interfaces] == ["eth0", "eth1"]
    assert [i.switch for i in device.interfaces] == ["sw-oficina", "sw-servidores"]
    assert len({i.host_veth for i in device.interfaces}) == 2
    servidor_ports = _switch_ports("sw-servidores", topology)
    assert {p.peer for p in servidor_ports if p.kind == "device"} == {"pc-01", "srv-01"}


# ── Nombres de veth ────────────────────────────────────────


def test_host_veth_respeta_limites_de_linux():
    topology = _topology()
    for device in build_device_specs(topology):
        for iface in device.interfaces:
            assert len(iface.host_veth) <= 13
            assert len(iface.peer_veth) <= 15
            assert iface.peer_veth == f"{iface.host_veth}-c"


def test_veths_unicos_con_ids_de_prefijo_comun():
    manifest = _manifest()
    manifest["devices"].append({
        "id": "pc-recepcion-02", "role": "pc", "segment": "vlan-oficina",
        "ip": "10.10.0.22",
    })
    manifest["fabric"]["device_overrides"].append({
        "id": "pc-recepcion-02",
        "interfaces": [{
            "name": "eth0", "segment": "vlan-oficina",
            "ip": "10.10.0.22/24", "mac": "00:1c:42:10:10:22",
            "vlan_tag": 10, "switch": "sw-oficina",
        }],
    })
    topology = _topology(manifest)
    names = [i.host_veth for d in build_device_specs(topology) for i in d.interfaces]
    assert len(names) == len(set(names))


def test_veths_unicos_entre_todos_los_planes():
    topology = _topology()
    devices = build_device_specs(topology)
    names = [i.host_veth for d in devices for i in d.interfaces]
    names += [i.peer_veth for d in devices for i in d.interfaces]
    names += [
        p.name for b in build_bridge_specs(topology)
        for p in b.ports if p.kind == "trunk"
    ]
    assert len(names) == len(set(names))
    assert all(len(name) <= 15 for name in names)


def test_device_id_largo_no_desborda():
    manifest = _manifest()
    long_id = "camara-de-videovigilancia-entrada-principal-01"
    manifest["devices"].append({
        "id": long_id, "role": "camera", "segment": "vlan-oficina",
        "ip": "10.10.0.70",
    })
    manifest["fabric"]["device_overrides"].append({
        "id": long_id,
        "interfaces": [{
            "name": "eth0", "segment": "vlan-oficina",
            "ip": "10.10.0.70/24", "mac": "00:12:5a:00:00:70",
            "vlan_tag": 10, "switch": "sw-oficina",
        }],
    })
    device = next(d for d in build_device_specs(_topology(manifest)) if d.device_id == long_id)
    assert len(device.interfaces[0].host_veth) <= 13


# ── Consistencia entre planes ──────────────────────────────


def test_puertos_de_bridge_coinciden_con_device_specs():
    topology = _topology()
    device_ports = {
        p.name: p
        for bridge in build_bridge_specs(topology)
        for p in bridge.ports if p.kind == "device"
    }
    for device in build_device_specs(topology):
        for iface in device.interfaces:
            port = device_ports[iface.host_veth]
            assert port.peer == device.device_id
            assert port.tag == iface.vlan_tag


def test_switch_port_map_coincide_con_bridges():
    topology = _topology()
    bridge_ports = {
        p.name for b in build_bridge_specs(topology) for p in b.ports if p.kind == "device"
    }
    devices = {d.device_id: d for d in build_device_specs(topology)}
    expected: set[str] = set()
    for switch_id, labels in topology.switch_port_map.items():
        for label in labels:
            device_id, iface_name = label.split(":", 1)
            iface = next(i for i in devices[device_id].interfaces if i.name == iface_name)
            assert iface.switch == switch_id
            expected.add(iface.host_veth)
    assert expected == bridge_ports


# ── Determinismo y pureza ──────────────────────────────────


def test_planes_deterministas_byte_a_byte():
    topology = _topology()

    def dump() -> str:
        return json.dumps({
            "bridges": [b.model_dump() for b in build_bridge_specs(topology)],
            "links": [link.model_dump() for link in build_link_specs(topology)],
            "devices": [d.model_dump() for d in build_device_specs(topology)],
        }, sort_keys=False)

    assert dump() == dump()


def test_transformacion_no_muta_la_topologia():
    topology = _topology()
    before = topology.model_dump(mode="json")
    build_bridge_specs(topology)
    build_link_specs(topology)
    build_device_specs(topology)
    assert topology.model_dump(mode="json") == before


def test_transformacion_idempotente_tras_roundtrip():
    topology = _topology()
    network = DeceptionNetwork.model_validate(_manifest())
    reloaded = parse_manifest(network.model_dump(mode="json", exclude_none=True))
    assert [b.model_dump() for b in build_bridge_specs(reloaded)] == [
        b.model_dump() for b in build_bridge_specs(topology)
    ]
    assert [link.model_dump() for link in build_link_specs(reloaded)] == [
        link.model_dump() for link in build_link_specs(topology)
    ]
    assert [d.model_dump() for d in build_device_specs(reloaded)] == [
        d.model_dump() for d in build_device_specs(topology)
    ]


def test_specs_son_inmutables():
    device = build_device_specs(_topology())[0]
    with pytest.raises(Exception):
        device.device_id = "otro"


def test_sin_imports_de_runtime():
    source = Path(topology_mod.__file__).read_text(encoding="utf-8")
    for banned in (
        "import docker", "import mininet", "import subprocess",
        "subprocess.", "ovs-vsctl", "os.system",
    ):
        assert banned not in source


# ── Ejemplo del §3.2 ────────────────────────────────────────


def test_ejemplo_genera_planes_completos():
    raw = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    topology = parse_manifest(raw)
    assert len(build_bridge_specs(topology)) == 4
    assert len(build_link_specs(topology)) == 3  # 3 uplinks, 1 dedup con explicit
    assert len(build_device_specs(topology)) == 3


def test_ejemplo_sw_core_troncaliza_las_tres_vlans_de_acceso():
    raw = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    topology = parse_manifest(raw)
    core = next(b for b in build_bridge_specs(topology) if b.id == "sw-core")
    trunk_peers = {p.peer for p in core.ports if p.kind == "trunk"}
    assert trunk_peers == {"sw-oficina", "sw-servidores", "sw-camaras"}
    assert core.vlans == [10, 20, 30, 40]


def test_ejemplo_dispositivos_y_tags():
    raw = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    topology = parse_manifest(raw)
    devices = {d.device_id: d for d in build_device_specs(topology)}
    assert devices["pc-recepcion-01"].interfaces[0].vlan_tag == 10
    assert devices["srv-files-01"].interfaces[0].vlan_tag == 20
    assert devices["cam-entrada-01"].interfaces[0].vlan_tag == 30
    assert devices["pc-recepcion-01"].container_name == "dystopia-fabric-pc-recepcion-01"


def test_tipos_de_specs():
    topology = _topology()
    assert all(isinstance(b, topology_mod.BridgeSpec) for b in build_bridge_specs(topology))
    assert all(isinstance(link, LinkSpec) for link in build_link_specs(topology))
    specs = build_device_specs(topology)
    assert all(isinstance(d, DeviceSpec) for d in specs)
