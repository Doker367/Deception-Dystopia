"""Integración real de la emulación WAN (``tc netem``) del Network Fabric.

Solo se ejecuta en Linux, como root (o con CAP_NET_ADMIN) y con
``ovs-vsctl``/``ip``/``tc`` disponibles. En macOS o CI sin OVS se omite.

Cómo correr en Ubuntu 24.04 / Debian trixie::

    sudo apt install openvswitch-switch iproute2
    sudo systemctl start openvswitch-switch
    sudo ./.venv/bin/python -m pytest tests/integration/test_fabric_wan.py -v

Qué comprueba:

1. Un enlace entre dos switches con ``latency_ms: 50`` deja un qdisc
   ``netem`` en **ambos** extremos del veth (simetría).
2. Dos dispositivos, uno en cada switch, se ven por ICMP y el RTT medio
   es ≥ 45 ms (50 ms de latencia por sentido: 100 ms ida y vuelta; el
   umbral 45 ms deja margen para el primer paquete y para hosts con
   ``icmp_echo_ignore_all`` desactivado por defecto).
3. ``destroy`` elimina los qdisc (``tc qdisc show`` sin ``netem``) y los
   veths, y es idempotente.

Los dispositivos se levantan como contenedores Docker (``fabric/Dockerfile``);
si la imagen no está construida el test se omite con instrucciones::

    sudo docker build -t dystopia/fabric-device:v1 -f fabric/Dockerfile .
"""

import os
import platform
import re
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

DEVICE_IMAGE = "dystopia/fabric-device:v1"


def _missing_requirements() -> str | None:
    if platform.system() != "Linux":
        return "requiere Linux (OVS + tc netem)"
    if os.geteuid() != 0:
        return "requiere root o CAP_NET_ADMIN"
    for tool in ("ovs-vsctl", "ip", "tc", "docker"):
        if shutil.which(tool) is None:
            return f"falta el comando '{tool}'"
    if subprocess.run(
        ["docker", "image", "inspect", DEVICE_IMAGE],
        capture_output=True, check=False,
    ).returncode != 0:
        return (
            f"falta la imagen '{DEVICE_IMAGE}'; constrúyela con "
            "'sudo docker build -t dystopia/fabric-device:v1 -f fabric/Dockerfile .'"
        )
    return None


_SKIP_REASON = _missing_requirements()
pytestmark = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")

_PID = os.getpid() % 10000
SW_A = f"dwn{_PID}a"
SW_B = f"dwn{_PID}b"
LATENCY_MS = 50
RTT_MIN_MS = 45


def _manifest() -> dict:
    return {
        "segments": [
            {"id": "vlan-10", "vlan_id": 10, "cidr": "10.10.0.0/24",
             "gateway": "10.10.0.1"},
        ],
        "devices": [
            {"id": "pc-a", "role": "pc", "segment": "vlan-10", "ip": "10.10.0.21"},
            {"id": "pc-b", "role": "pc", "segment": "vlan-10", "ip": "10.10.0.22"},
        ],
        "fabric": {
            "enabled": True,
            "switches": [
                {"id": SW_A, "vlans": [10]},
                {"id": SW_B, "vlans": [10]},
            ],
            "links": [{
                "from": SW_A, "to": SW_B, "trunk": True,
                "latency_ms": LATENCY_MS,
            }],
            "defaults": {"device_image": DEVICE_IMAGE},
            "device_overrides": [
                {
                    "id": "pc-a",
                    "interfaces": [{
                        "segment": "vlan-10", "ip": "10.10.0.21/24",
                        "mac": "00:1c:42:10:10:21", "vlan_tag": 10, "switch": SW_A,
                    }],
                },
                {
                    "id": "pc-b",
                    "interfaces": [{
                        "segment": "vlan-10", "ip": "10.10.0.22/24",
                        "mac": "00:1c:42:10:10:22", "vlan_tag": 10, "switch": SW_B,
                    }],
                },
            ],
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


def _container_pid(device_id: str) -> int:
    """PID del proceso principal del contenedor del dispositivo."""
    name = f"dystopia-fabric-{device_id}"
    out = _run("docker", "inspect", "-f", "{{.State.Pid}}", name)
    return int(out.stdout.strip() or 0)


def _ping_from(device_id: str, target: str, count: int = 5) -> float:
    """RTT medio (ms) de ``ping`` lanzado dentro del netns del dispositivo."""
    pid = _container_pid(device_id)
    assert pid > 0, f"el contenedor de '{device_id}' no está corriendo"
    out = _run(
        "nsenter", "-t", str(pid), "-n", "--",
        "ping", "-c", str(count), "-W", "2", target,
    )
    match = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", out.stdout)
    assert match, f"ping sin estadísticas: {out.stdout}{out.stderr}"
    return float(match.group(1))


def _qdisc_has_netem(port: str) -> bool:
    return "netem" in _run("tc", "qdisc", "show", "dev", port).stdout


def _cleanup(plan: FabricPlan) -> None:
    """Limpieza defensiva si un assert falla antes del destroy normal."""
    for link in plan.links:
        for port in (link.port_from, link.port_to):
            _run("tc", "qdisc", "del", "dev", port, "root")
            _run("ip", "link", "del", port)
    for bridge in (SW_A, SW_B):
        _run("ovs-vsctl", "--if-exists", "del-br", bridge)


def test_wan_latencia_simetrica_y_limpieza():
    topology, plan = _plan()
    link = plan.links[0]
    engine = OvsFabricEngine()

    try:
        engine.deploy(plan, topology)
        assert engine.last_result is not None
        assert engine.last_result.wan_links == [{
            "id": link.id,
            "from": SW_A,
            "to": SW_B,
            "latency_ms": float(LATENCY_MS),
            "jitter_ms": None,
            "loss_pct": None,
            "bandwidth_mbps": None,
            "ports": [link.port_from, link.port_to],
        }]

        # Simetría: netem en los dos extremos del veth.
        assert _qdisc_has_netem(link.port_from)
        assert _qdisc_has_netem(link.port_to)

        # RTT: 50 ms por sentido ≈ 100 ms ida y vuelta.
        avg = _ping_from("pc-a", "10.10.0.22")
        assert avg >= RTT_MIN_MS, f"RTT medio {avg:.1f} ms < {RTT_MIN_MS} ms"
    finally:
        engine.destroy(topology)
        _cleanup(plan)

    # Destroy deja los qdisc y los veths limpios.
    for port in (link.port_from, link.port_to):
        assert not _qdisc_has_netem(port)
        assert _run("ip", "link", "show", port).returncode != 0
    assert engine.last_destroy_result is not None
    assert set(engine.last_destroy_result.wan_cleared) == {
        link.port_from, link.port_to,
    }

    # Destroy idempotente: segunda pasada sin fallos.
    engine.destroy(topology)
    assert engine.last_destroy_result is not None
    assert engine.last_destroy_result.wan_cleared == []
