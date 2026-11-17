"""Integración REAL del pipeline de eventos del fabric (AC8/§11.2).

Solo en Linux, como root, con Docker (demonio), OVS y el entorno del
control (JWT secret). En macOS/CI se omite.

Cómo correr en Debian trixie / Ubuntu 24.04::

    sudo apt install openvswitch-switch iproute2 docker.io
    sudo systemctl start openvswitch-switch docker
    sudo ./.venv/bin/python -m pytest tests/integration/test_fabric_events_e2e.py -v

Qué hace:

1. Levanta la API del control en un hilo (uvicorn, puerto efímero) con la
   SQLite de deception temporal y el manifiesto del test.
2. Despliega el fabric real (2 dispositivos: ssh y http).
3. Desde el netns del dispositivo http se conecta al puerto 22 del ssh:
   el listener del agente emite ``connect`` al JSONL.
4. El forwarder (offsets persistentes) envía el lote a
   ``POST /api/fabric/events`` del control.
5. Verifica que el evento quedó en la SQLite de deception
   (``deception_events``, device_id/type correctos).
"""

import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from app.services.deception import store_svc  # noqa: E402

_IMAGE = "dystopia/fabric-device:v1"
_TOKEN = "t" * 40
_CONTROL_PORT = 18099
_PID = os.getpid() % 1000
SW = f"dsts{_PID}"
PCA = f"pca{_PID}"   # ssh
PCB = f"pcb{_PID}"   # http (origen de la conexión)


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
    """Dos dispositivos en la misma VLAN: pca (ssh) y pcb (http)."""
    return {
        "segments": [
            {"id": "vlan-10", "vlan_id": 10, "cidr": "10.230.0.0/24",
             "gateway": "10.230.0.1"},
        ],
        "devices": [
            {"id": PCA, "role": "server", "segment": "vlan-10",
             "ip": "10.230.0.11",
             "services": [{"port": 22, "proto": "ssh", "engine": "native"}]},
            {"id": PCB, "role": "pc", "segment": "vlan-10",
             "ip": "10.230.0.12",
             "services": [{"port": 80, "proto": "http", "engine": "native"}]},
        ],
        "fabric": {
            "enabled": True,
            "switches": [{"id": SW, "vlans": [10]}],
            "device_overrides": [
                {
                    "id": PCA,
                    "interfaces": [{
                        "segment": "vlan-10", "ip": "10.230.0.11/24",
                        "mac": "00:1c:42:e0:00:11", "gateway": "10.230.0.1",
                        "vlan_tag": 10, "switch": SW,
                    }],
                    "routes": [{"destination": "0.0.0.0/0", "gateway": "10.230.0.1"}],
                    "neighbors": [
                        {"ip": "10.230.0.12", "mac": "00:1c:42:e0:00:12",
                         "hostname": PCB},
                    ],
                },
                {
                    "id": PCB,
                    "interfaces": [{
                        "segment": "vlan-10", "ip": "10.230.0.12/24",
                        "mac": "00:1c:42:e0:00:12", "gateway": "10.230.0.1",
                        "vlan_tag": 10, "switch": SW,
                    }],
                    "routes": [{"destination": "0.0.0.0/0", "gateway": "10.230.0.1"}],
                    "neighbors": [
                        {"ip": "10.230.0.11", "mac": "00:1c:42:e0:00:11",
                         "hostname": PCA},
                    ],
                },
            ],
        },
    }


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, check=False)


def _plan(topology):
    from app.services.fabric.controller import FabricPlan
    from app.services.fabric.topology import (
        build_bridge_specs,
        build_device_specs,
        build_link_specs,
    )

    return FabricPlan(
        bridges=build_bridge_specs(topology),
        links=build_link_specs(topology),
        devices=build_device_specs(topology),
    )


def _cleanup(topology) -> None:
    from app.services.fabric.deploy import OvsFabricEngine

    try:
        OvsFabricEngine().destroy(topology)
    except Exception:
        pass
    plan = _plan(topology)
    for spec in plan.devices:
        _run("docker", "rm", "-f", spec.container_name)
        for iface in spec.interfaces:
            _run("ip", "link", "del", iface.host_veth)
    for bridge in (SW,):
        _run("ovs-vsctl", "--if-exists", "del-br", bridge)


@pytest.fixture(scope="module")
def device_image():
    if _run("docker", "image", "inspect", _IMAGE).returncode == 0:
        yield _IMAGE
        return
    build = _run("docker", "build", "-t", _IMAGE,
                 "-f", str(REPO / "fabric" / "Dockerfile"), str(REPO))
    assert build.returncode == 0, build.stderr[-2000:]
    yield _IMAGE


@pytest.fixture()
def control(tmp_path, monkeypatch):
    """API del control en un hilo con SQLite y manifiesto del test."""
    import uvicorn
    from app.main import app as control_app
    from app.services.fabric import controller as controller_mod

    monkeypatch.setenv("DYSTOPIA_FABRIC_REMOTE_TOKEN", _TOKEN)
    # La ingesta de eventos usa un token dedicado (fail-closed sin él).
    monkeypatch.setenv("DYSTOPIA_FABRIC_EVENTS_TOKEN", _TOKEN)
    monkeypatch.setattr(store_svc, "DB_PATH", tmp_path / "deception.db")

    from app.services import audit_svc

    audit_dir = tmp_path / "audit"
    monkeypatch.setattr(audit_svc, "AUDIT_DIR", audit_dir)
    monkeypatch.setattr(audit_svc, "AUDIT_DB", audit_dir / "audit.db")

    manifest = _manifest()
    target = tmp_path / "network.yaml"
    target.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(controller_mod.topology_svc, "NETWORK_FILE", target)
    controller_mod.topology_svc.invalidate_cache()
    controller_mod.reset_controller(
        db_path=tmp_path / "fabric.db",
        manifest_loader=lambda: manifest,
    )

    config = uvicorn.Config(control_app, host="127.0.0.1", port=_CONTROL_PORT,
                            log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)
    assert server.started, "el control no arrancó"
    yield f"http://127.0.0.1:{_CONTROL_PORT}"
    server.should_exit = True
    thread.join(timeout=5)
    controller_mod.topology_svc.invalidate_cache()


def test_evento_llega_a_sqlite(control, device_image, tmp_path):
    from app.services.fabric.deploy import OvsFabricEngine
    from app.services.fabric.event_forwarder import EventForwarder
    from app.services.fabric.parser import parse_manifest
    from app.services.fabric.runtime import DeviceRuntime, DockerCliRuntime

    topology = parse_manifest(_manifest())
    plan = _plan(topology)
    # Raíces aisladas: el directorio real puede contener eventos de
    # despliegues anteriores y el control rechaza el lote entero si
    # aparece un device_id ajeno al manifiesto de este test.
    logs_root = tmp_path / "fabric-logs"
    engine = OvsFabricEngine(
        device_runtime=DeviceRuntime(
            DockerCliRuntime(),
            config_root=tmp_path / "fabric-config",
            logs_root=logs_root,
        )
    )

    try:
        engine.deploy(plan, topology)
        spec_a, spec_b = plan.devices[0], plan.devices[1]
        ip_a = spec_a.interfaces[0].ip.split("/")[0]

        pid_b = int(_run(
            "docker", "inspect", "-f", "{{.State.Pid}}", spec_b.container_name,
        ).stdout.strip())
        assert pid_b > 0

        # Conexión desde el netns de pcb al puerto 22 de pca (SSH señuelo).
        # El listener tarda un instante en cargar la host key: se sondea el
        # puerto en vez de asumir que está listo tras crear el contenedor.
        outcome = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            outcome = _run("nsenter", "-t", str(pid_b), "-n", "--", "timeout", "5",
                           "bash", "-c", f"exec 3<>/dev/tcp/{ip_a}/22")
            if outcome.returncode == 0:
                break
            time.sleep(0.5)
        assert outcome is not None and outcome.returncode == 0, (
            outcome.stderr if outcome is not None else "sin intentos"
        )

        # Un connect TCP crudo no completa el handshake SSH y, por tanto, no
        # genera el evento ``connect``. Se ejecuta paramiko dentro del netns
        # de pcb (mismo mount namespace del host) para negociar SSH de verdad.
        ssh_probe = (
            "import socket, sys, paramiko\n"
            "sock = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=10)\n"
            "transport = paramiko.Transport(sock)\n"
            "transport.start_client(timeout=10)\n"
            "transport.close()\n"
        )
        handshake = _run("nsenter", "-t", str(pid_b), "-n", "--",
                         sys.executable, "-c", ssh_probe, ip_a, "22")
        assert handshake.returncode == 0, handshake.stderr

        # El listener HTTP de pcb también debe emitir su connect: se prueba
        # desde el netns de pca para cubrir ambos sentidos del segmento.
        spec_b_ip = spec_b.interfaces[0].ip.split("/")[0]
        pid_a = int(_run(
            "docker", "inspect", "-f", "{{.State.Pid}}", spec_a.container_name,
        ).stdout.strip())
        http_outcome = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            http_outcome = _run(
                "nsenter", "-t", str(pid_a), "-n", "--", "timeout", "5",
                "bash", "-c", f"exec 3<>/dev/tcp/{spec_b_ip}/80",
            )
            if http_outcome.returncode == 0:
                break
            time.sleep(0.5)
        assert http_outcome is not None and http_outcome.returncode == 0, (
            http_outcome.stderr if http_outcome is not None else "sin intentos"
        )

        # El agente escribe el JSONL en su volumen aislado.
        jsonl = logs_root / spec_a.device_id / "events.jsonl"
        for _ in range(50):
            if jsonl.exists() and "connect" in jsonl.read_text(encoding="utf-8"):
                break
            time.sleep(0.2)
        assert jsonl.exists(), "el agente no escribió events.jsonl"

        # El forwarder envía el lote al control (offsets persistentes).
        forwarder = EventForwarder(
            devices_dir=logs_root,
            state_path=tmp_path / "forwarder-state.json",
            url=f"{control}/api/fabric/events",
            token=_TOKEN,
            interval=0.1,
            backoff=0,
        )
        result = forwarder.run_once()
        assert result["sent"] >= 2, result  # connect de pca y pcb

        # El evento está en la SQLite de deception.
        with sqlite3.connect(str(store_svc.DB_PATH)) as conn:
            rows = conn.execute(
                "SELECT device_id, event_type, src_ip FROM deception_events "
                "WHERE device_id = ? AND event_type = 'connect'",
                (spec_a.device_id,),
            ).fetchall()
        assert rows, "el evento connect no llegó a deception_events"
        assert rows[0][2] == "10.230.0.12"  # src_ip = pcb
    finally:
        _cleanup(topology)
