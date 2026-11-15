"""Integración real del Deployment Engine con Open vSwitch.

Solo se ejecuta en Linux, como root (o con CAP_NET_ADMIN) y con
``ovs-vsctl``/``ip`` disponibles. En macOS o CI sin OVS se omite.

Cómo correr en Ubuntu 24.04::

    sudo apt install openvswitch-switch iproute2
    sudo systemctl start openvswitch-switch
    sudo ./.venv/bin/python -m pytest tests/integration/test_fabric_deploy.py -v

El test crea dos bridges y un enlace troncal con nombres únicos por PID,
verifica puertos y VLANs con ``ovs-vsctl`` y limpia todo al final. Los
puertos de dispositivo no se crean en la Fase 3 (contenedores en Fase 4),
así que la comprobación de ``tag=`` de acceso llegará con esa fase.
"""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from app.services.fabric.controller import FabricPlan  # noqa: E402
from app.services.fabric.deploy import OvsFabricEngine  # noqa: E402
from app.services.fabric.parser import parse_manifest  # noqa: E402
from app.services.fabric.topology import (  # noqa: E402
    build_bridge_specs,
    build_device_specs,
    build_link_specs,
)


def _missing_requirements() -> str | None:
    if platform.system() != "Linux":
        return "requiere Linux (OVS + netns)"
    if os.geteuid() != 0:
        return "requiere root o CAP_NET_ADMIN"
    for tool in ("ovs-vsctl", "ip"):
        if shutil.which(tool) is None:
            return f"falta el comando '{tool}'"
    return None


_SKIP_REASON = _missing_requirements()
pytestmark = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")

_PID = os.getpid() % 10000
SW_A = f"dst{_PID}a"
SW_B = f"dst{_PID}b"


def _manifest() -> dict:
    return {
        "segments": [
            {"id": "vlan-10", "vlan_id": 10, "cidr": "10.10.0.0/24"},
            {"id": "vlan-20", "vlan_id": 20, "cidr": "10.20.0.0/24"},
        ],
        "devices": [
            {"id": "pc-01", "role": "pc", "segment": "vlan-10", "ip": "10.10.0.21"},
        ],
        "fabric": {
            "enabled": True,
            "switches": [
                {"id": SW_A, "vlans": [10, 20]},
                {"id": SW_B, "vlans": [10], "uplink": SW_A},
            ],
            "links": [],
            "device_overrides": [{
                "id": "pc-01",
                "interfaces": [{
                    "segment": "vlan-10", "ip": "10.10.0.21/24",
                    "mac": "00:1c:42:10:10:21", "vlan_tag": 10, "switch": SW_B,
                }],
            }],
        },
    }


def _plan():
    topology = parse_manifest(_manifest())
    plan = FabricPlan(
        bridges=build_bridge_specs(topology),
        links=build_link_specs(topology),
        devices=build_device_specs(topology),
    )
    return topology, plan


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, check=False)


def _cleanup(plan: FabricPlan) -> None:
    """Limpieza defensiva si un assert falla antes del destroy normal."""
    for link in plan.links:
        for port in (link.port_from, link.port_to):
            _run("ip", "link", "del", port)
    for bridge in (SW_A, SW_B):
        _run("ovs-vsctl", "--if-exists", "del-br", bridge)


def test_deploy_y_destroy_con_ovs_real():
    topology, plan = _plan()
    link = plan.links[0]
    device_port = plan.devices[0].interfaces[0].host_veth
    engine = OvsFabricEngine()

    try:
        engine.deploy(plan, topology)

        assert engine.last_result is not None
        assert set(engine.last_result.bridges_created) == {SW_A, SW_B}
        assert engine.last_result.links_created == [link.id]
        assert engine.last_result.device_ports_skipped == [device_port]

        for bridge in (SW_A, SW_B):
            assert _run("ovs-vsctl", "br-exists", bridge).returncode == 0

        ports_a = set(_run("ovs-vsctl", "list-ports", SW_A).stdout.split())
        ports_b = set(_run("ovs-vsctl", "list-ports", SW_B).stdout.split())
        # Aislamiento: solo el extremo del enlace interno, ningún uplink del host.
        assert ports_a == {link.port_to}
        assert ports_b == {link.port_from}

        trunks_a = _run("ovs-vsctl", "get", "port", link.port_to, "trunks").stdout
        trunks_b = _run("ovs-vsctl", "get", "port", link.port_from, "trunks").stdout
        assert "10" in trunks_a and "20" in trunks_a
        assert "10" in trunks_b

        # Fase 3 no crea puertos de dispositivo.
        assert _run("ip", "link", "show", device_port).returncode != 0
    finally:
        engine.destroy(topology)
        _cleanup(plan)

    for bridge in (SW_A, SW_B):
        assert _run("ovs-vsctl", "br-exists", bridge).returncode != 0
    for port in (link.port_from, link.port_to):
        assert _run("ip", "link", "show", port).returncode != 0
    assert engine.last_destroy_result is not None
    assert set(engine.last_destroy_result.bridges_removed) == {SW_A, SW_B}

    # Destroy idempotente: una segunda pasada no falla ni deja huérfanos.
    engine.destroy(topology)
    assert engine.last_destroy_result is not None
    assert engine.last_destroy_result.bridges_removed == []
    assert engine.last_destroy_result.links_removed == []
