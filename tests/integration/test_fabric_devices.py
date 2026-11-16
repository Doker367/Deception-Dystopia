"""Integración REAL del Device Runtime: AC5 (ping same-VLAN) y AC6 (aislamiento).

Solo se ejecuta en Linux, como root, con Docker (demonio activo) y OVS
instalados. En macOS/CI se omite.

Cómo correr en Debian trixie / Ubuntu 24.04::

    sudo apt install openvswitch-switch iproute2 docker.io
    sudo systemctl start openvswitch-switch docker
    sudo ./.venv/bin/python -m pytest tests/integration/test_fabric_devices.py -v

Qué hace:

1. Construye la imagen ``dystopia/fabric-device:v1`` desde
   ``fabric/Dockerfile`` si aún no existe (una vez por sesión).
2. Despliega una topología inline: 2 switches OVS (VLAN 10/20) y 3
   dispositivos endurecidos (2 en VLAN 10, 1 en VLAN 20).
3. Verifica contenedores (``docker ps``), puertos OVS con ``tag``
   correcto y la configuración del netns (IP/MAC/ruta) con ``nsenter``.
4. AC5: ping entre los dos dispositivos de la VLAN 10 → OK.
   AC6: ping de VLAN 10 a VLAN 20 → falla (sin router).
5. Destroy: sin contenedores, bridges ni veths huérfanos (limpieza
   defensiva en ``finally``).
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

_IMAGE = "dystopia/fabric-device:v1"
_PID = os.getpid() % 1000
SW_X = f"dstx{_PID}"
SW_Y = f"dsty{_PID}"
PCA = f"pca{_PID}"
PCB = f"pcb{_PID}"
SRV = f"srv{_PID}"


def _missing_requirements() -> str | None:
    if platform.system() != "Linux":
        return "requiere Linux (OVS + Docker + netns)"
    if os.geteuid() != 0:
        return "requiere root o CAP_NET_ADMIN"
    for tool in ("ovs-vsctl", "ip", "docker"):
        if shutil.which(tool) is None:
            return f"falta el comando '{tool}'"
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        return "el demonio de Docker no está disponible"
    return None


_SKIP_REASON = _missing_requirements()
pytestmark = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")


def _manifest() -> dict:
    """2 switches; 2 dispositivos en VLAN 10 (sw-x) y 1 en VLAN 20 (sw-y)."""
    return {
        "segments": [
            {"id": "vlan-10", "vlan_id": 10, "cidr": "10.210.0.0/24",
             "gateway": "10.210.0.1"},
            {"id": "vlan-20", "vlan_id": 20, "cidr": "10.220.0.0/24",
             "gateway": "10.220.0.1"},
        ],
        "devices": [
            {"id": PCA, "role": "pc", "segment": "vlan-10", "ip": "10.210.0.11",
             "services": [{"port": 80, "proto": "http", "engine": "native"}]},
            {"id": PCB, "role": "pc", "segment": "vlan-10", "ip": "10.210.0.12",
             "services": [{"port": 80, "proto": "http", "engine": "native"}]},
            {"id": SRV, "role": "server", "segment": "vlan-20", "ip": "10.220.0.10",
             "services": [{"port": 80, "proto": "http", "engine": "native"}]},
        ],
        "fabric": {
            "enabled": True,
            "switches": [
                {"id": SW_X, "vlans": [10, 20]},
                {"id": SW_Y, "vlans": [20], "uplink": SW_X},
            ],
            "links": [],
            "device_overrides": [
                {
                    "id": PCA,
                    "interfaces": [{
                        "segment": "vlan-10", "ip": "10.210.0.11/24",
                        "mac": "00:1c:42:a0:00:11", "gateway": "10.210.0.1",
                        "vlan_tag": 10, "switch": SW_X,
                    }],
                    "routes": [{"destination": "0.0.0.0/0", "gateway": "10.210.0.1"}],
                    "neighbors": [
                        {"ip": "10.210.0.12", "mac": "00:1c:42:a0:00:12",
                         "hostname": PCB},
                    ],
                },
                {
                    "id": PCB,
                    "interfaces": [{
                        "segment": "vlan-10", "ip": "10.210.0.12/24",
                        "mac": "00:1c:42:a0:00:12", "gateway": "10.210.0.1",
                        "vlan_tag": 10, "switch": SW_X,
                    }],
                    "routes": [{"destination": "0.0.0.0/0", "gateway": "10.210.0.1"}],
                    "neighbors": [
                        {"ip": "10.210.0.11", "mac": "00:1c:42:a0:00:11",
                         "hostname": PCA},
                    ],
                },
                {
                    "id": SRV,
                    "interfaces": [{
                        "segment": "vlan-20", "ip": "10.220.0.10/24",
                        "mac": "00:1c:42:b0:00:10", "gateway": "10.220.0.1",
                        "vlan_tag": 20, "switch": SW_Y,
                    }],
                    "routes": [{"destination": "0.0.0.0/0", "gateway": "10.220.0.1"}],
                },
            ],
        },
    }


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, check=False)


@pytest.fixture(scope="module")
def device_image():
    """Construye la imagen base una vez si no existe en el host."""
    if _run("docker", "image", "inspect", _IMAGE).returncode == 0:
        yield _IMAGE
        return
    build = _run(
        "docker", "build", "-t", _IMAGE,
        "-f", str(REPO / "fabric" / "Dockerfile"), str(REPO),
    )
    assert build.returncode == 0, build.stderr[-2000:]
    yield _IMAGE


def _plan(topology):
    return FabricPlan(
        bridges=build_bridge_specs(topology),
        links=build_link_specs(topology),
        devices=build_device_specs(topology),
    )


def _container_pid(name: str) -> int:
    result = _run("docker", "inspect", "-f", "{{.State.Pid}}", name)
    assert result.returncode == 0, result.stderr
    return int(result.stdout.strip())


def _cleanup(topology) -> None:
    """Limpieza defensiva: contenedores, veths y bridges del test."""
    plan = _plan(topology)
    for spec in plan.devices:
        _run("docker", "rm", "-f", spec.container_name)
        for iface in spec.interfaces:
            _run("ip", "link", "del", iface.host_veth)
    for link in plan.links:
        _run("ip", "link", "del", link.port_from)
        _run("ip", "link", "del", link.port_to)
    for bridge in (SW_X, SW_Y):
        _run("ovs-vsctl", "--if-exists", "del-br", bridge)


def test_ac5_ac6_despliegue_y_aislamiento(device_image):
    topology = parse_manifest(_manifest())
    plan = _plan(topology)
    engine = OvsFabricEngine()

    try:
        engine.deploy(plan, topology)

        # ── Contenedores running (solo los de este test) ────
        ps = _run("docker", "ps", "--format", "{{.Names}}", "--filter",
                  "label=dystopia.fabric=true")
        expected = {
            f"dystopia-fabric-{PCA}", f"dystopia-fabric-{PCB}", f"dystopia-fabric-{SRV}",
        }
        running = set(ps.stdout.split()) & expected
        assert running == expected, (running, ps.stdout)

        # ── Puertos OVS con tag correcto ────────────────────
        for spec, expected_tag in ((plan.devices[0], "10"), (plan.devices[1], "10"),
                                   (plan.devices[2], "20")):
            port = spec.interfaces[0].host_veth
            tag = _run("ovs-vsctl", "get", "port", port, "tag").stdout.strip()
            assert tag == expected_tag, (port, tag)
        ports_x = set(_run("ovs-vsctl", "list-ports", SW_X).stdout.split())
        ports_y = set(_run("ovs-vsctl", "list-ports", SW_Y).stdout.split())
        # Aislamiento: solo puertos del fabric, ningún uplink del host.
        assert ports_x == {
            plan.links[0].port_to,
            plan.devices[0].interfaces[0].host_veth,
            plan.devices[1].interfaces[0].host_veth,
        }
        assert ports_y == {
            plan.links[0].port_from,
            plan.devices[2].interfaces[0].host_veth,
        }

        # ── Configuración del netns (IP/MAC/ruta) ───────────
        pid_a = _container_pid(f"dystopia-fabric-{PCA}")
        addr = _run("nsenter", "-t", str(pid_a), "-n", "--",
                    "ip", "addr", "show", "eth0")
        assert "10.210.0.11/24" in addr.stdout
        assert "00:1c:42:a0:00:11" in addr.stdout.lower()
        routes = _run("nsenter", "-t", str(pid_a), "-n", "--", "ip", "route")
        assert "default via 10.210.0.1" in routes.stdout

        # ── AC5: ping entre dispositivos de la misma VLAN ───
        ip_b = plan.devices[1].interfaces[0].ip.split("/")[0]
        same_vlan = _run("nsenter", "-t", str(pid_a), "-n", "--",
                         "ping", "-c", "1", "-W", "2", ip_b)
        assert same_vlan.returncode == 0, same_vlan.stderr

        # ── AC6: ping entre VLANs distintas falla (sin router) ──
        ip_srv = plan.devices[2].interfaces[0].ip.split("/")[0]
        cross_vlan = _run("nsenter", "-t", str(pid_a), "-n", "--",
                          "ping", "-c", "1", "-W", "2", ip_srv)
        assert cross_vlan.returncode != 0
    finally:
        engine.destroy(topology)
        _cleanup(topology)

    # ── Destroy limpio: sin huérfanos de este test ─────
    leftovers = _run("docker", "ps", "-a", "--format", "{{.Names}}",
                     "--filter", "label=dystopia.fabric=true")
    expected_names = {
        f"dystopia-fabric-{PCA}", f"dystopia-fabric-{PCB}", f"dystopia-fabric-{SRV}",
    }
    assert not (set(leftovers.stdout.split()) & expected_names), leftovers.stdout
    for bridge in (SW_X, SW_Y):
        assert _run("ovs-vsctl", "br-exists", bridge).returncode != 0
    for spec in plan.devices:
        assert _run("ip", "link", "show", spec.interfaces[0].host_veth).returncode != 0
    for link in plan.links:
        assert _run("ip", "link", "show", link.port_from).returncode != 0

    # Destroy idempotente: segunda pasada sin cambios.
    engine.destroy(topology)
    assert engine.last_destroy_result is not None
    assert engine.last_destroy_result.bridges_removed == []
