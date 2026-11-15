"""Pruebas del Device Runtime de Docker (Fase 4), sin Docker real.

Un ``FakeRunner`` con estado emula ``docker``, ``ip``, ``nsenter`` y
``ovs-vsctl`` para verificar la secuencia exacta del attachment §4.2,
las flags de hardening, VLANs, rutas/ARP, idempotencia, errores
estructurados, destroy y health. Corre en macOS y Linux.
"""

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.services.fabric.deploy import CommandResult  # noqa: E402
from app.services.fabric.parser import parse_manifest  # noqa: E402
from app.services.fabric.runtime import (  # noqa: E402
    ContainerRuntimeError,
    ContainerSpec,
    DeviceRuntime,
    DockerCliRuntime,
)
from app.services.fabric.topology import build_device_specs  # noqa: E402


def _manifest() -> dict:
    """Un switch y un dispositivo con ruta por defecto y un vecino."""
    return {
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
                "routes": [{"destination": "0.0.0.0/0", "gateway": "10.10.0.1"}],
                "neighbors": [{
                    "ip": "10.10.0.1", "mac": "00:1c:42:10:10:01",
                    "hostname": "gateway",
                }],
                "resources": {
                    "image": "dystopia/fabric-device:v1",
                    "mem_limit": "128m", "cpus": 0.25,
                },
            }],
        },
    }


def _device():
    return build_device_specs(parse_manifest(_manifest()))[0]


class FakeRunner:
    """Runner con estado que emula docker/ip/nsenter/ovs-vsctl."""

    def __init__(self, pid: int = 4242, ping_ok: bool = True, fail_if=None):
        self.calls: list[list[str]] = []
        self.containers: dict[str, dict] = {}
        self.links: set[str] = set()
        self.pairs: dict[str, str] = {}
        self.ports: dict[str, str] = {}
        self.pid = pid
        self.ping_ok = ping_ok
        self.fail_if = fail_if

    def run(self, args: list[str], check: bool = True) -> CommandResult:
        self.calls.append(list(args))
        if self.fail_if and self.fail_if(args):
            returncode, stdout, stderr = 1, "", "fallo simulado"
        else:
            returncode, stdout, stderr = self._dispatch(args)
        result = CommandResult(
            args=list(args), returncode=returncode, stdout=stdout, stderr=stderr
        )
        if check and returncode != 0:
            raise RuntimeError(f"comando falló: {args}")
        return result

    def _by_id(self, value: str) -> dict | None:
        if value in self.containers:
            return self.containers[value]
        for container in self.containers.values():
            if container["id"] == value:
                return container
        return None

    def _dispatch(self, args: list[str]) -> tuple[int, str, str]:
        if args[:2] == ["docker", "create"]:
            name = args[args.index("--name") + 1]
            labels = {}
            for index, arg in enumerate(args):
                if arg == "--label":
                    key, _, value = args[index + 1].partition("=")
                    labels[key] = value
            container = {
                "id": f"cid-{name}",
                "name": name,
                "state": "created",
                "pid": 0,
                "image": args[-1],
                "labels": labels,
            }
            self.containers[name] = container
            return (0, container["id"], "")
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
                "Config": {
                    "Image": container["image"],
                    "Labels": container["labels"],
                },
            }
            return (0, json.dumps(payload), "")
        if args[:2] == ["ip", "link"]:
            if args[2] == "show":
                return (0, "", "") if args[3] in self.links else (1, "", "no such device")
            if args[2] == "add":
                self.links.add(args[3])
                self.links.add(args[8])
                self.pairs[args[3]] = args[8]
                self.pairs[args[8]] = args[3]
                return (0, "", "")
            if args[2] == "del":
                peer = self.pairs.pop(args[3], None)
                self.links.discard(args[3])
                if peer is not None:
                    self.links.discard(peer)
                    self.pairs.pop(peer, None)
                return (0, "", "")
            if args[2] == "set":
                return (0, "", "")
        if args[:2] == ["nsenter", "-t"]:
            if args[-2:] == ["-W", "1"] or "ping" in args:
                return (0, "1 packets transmitted", "") if self.ping_ok else (1, "", "100% packet loss")
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
        return (1, "", f"comando no soportado: {args}")


def _runtime(runner: FakeRunner) -> DeviceRuntime:
    return DeviceRuntime(DockerCliRuntime(runner=runner), runner=runner)


def _create_call(runner: FakeRunner) -> list[str]:
    return next(call for call in runner.calls if call[:2] == ["docker", "create"])


# ── Secuencia del attachment §4.2 ───────────────────────────


def test_deploy_device_secuencia_exacta():
    runner = FakeRunner()
    result = _runtime(runner).deploy_device(_device())

    assert result.success is True
    assert result.pid == 4242
    assert result.container_id == "cid-dystopia-fabric-pc-01"
    assert runner.calls == [
        ["docker", "inspect", "-f", "{{.Id}}", "dystopia-fabric-pc-01"],
        _create_call(runner),
        ["docker", "start", "cid-dystopia-fabric-pc-01"],
        ["docker", "inspect", "-f", "{{json .}}", "cid-dystopia-fabric-pc-01"],
        ["ip", "link", "show", "dv00-pc01"],
        ["ip", "link", "add", "dv00-pc01", "type", "veth", "peer", "name", "dv00-pc01-c"],
        ["ip", "link", "set", "dv00-pc01-c", "netns", "4242"],
        ["nsenter", "-t", "4242", "-n", "--", "ip", "link", "set", "dv00-pc01-c", "name", "eth0"],
        ["nsenter", "-t", "4242", "-n", "--", "ip", "link", "set", "eth0", "address", "00:1c:42:10:10:21"],
        ["nsenter", "-t", "4242", "-n", "--", "ip", "addr", "add", "10.10.0.21/24", "dev", "eth0"],
        ["nsenter", "-t", "4242", "-n", "--", "ip", "link", "set", "eth0", "up"],
        ["ip", "link", "set", "dv00-pc01", "up"],
        ["ovs-vsctl", "port-to-br", "dv00-pc01"],
        ["ovs-vsctl", "add-port", "sw-a", "dv00-pc01", "tag=10"],
        ["nsenter", "-t", "4242", "-n", "--", "ip", "route", "add", "0.0.0.0/0", "via", "10.10.0.1"],
        ["nsenter", "-t", "4242", "-n", "--", "ip", "neigh", "replace", "10.10.0.1",
         "lladdr", "00:1c:42:10:10:01", "dev", "eth0", "nud", "permanent"],
    ]


def test_create_con_hardening():
    runner = FakeRunner()
    _runtime(runner).deploy_device(_device())
    create = _create_call(runner)

    assert create == [
        "docker", "create",
        "--name", "dystopia-fabric-pc-01",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--pids-limit", "64",
        "--memory", "128m",
        "--cpus", "0.25",
        "--user", "2000:2000",
        "--label", "dystopia.fabric=true",
        "--label", "dystopia.device=pc-01",
        "dystopia/fabric-device:v1",
    ]


def test_sin_privileged_ni_socket_ni_host_network():
    runner = FakeRunner()
    _runtime(runner).deploy_device(_device())
    flat = " ".join(" ".join(call) for call in runner.calls)
    assert "--privileged" not in flat
    assert "docker.sock" not in flat
    assert "--network host" not in flat
    assert "--volume" not in flat
    assert " -v " not in flat


def test_vlan_tag_en_puerto_de_acceso():
    runner = FakeRunner()
    _runtime(runner).deploy_device(_device())
    add_port = next(call for call in runner.calls if call[:2] == ["ovs-vsctl", "add-port"])
    assert add_port == ["ovs-vsctl", "add-port", "sw-a", "dv00-pc01", "tag=10"]


def test_sin_vlan_tag_avisa_y_no_etiqueta():
    device = _device()
    iface = device.interfaces[0].model_copy(update={"vlan_tag": None})
    device = device.model_copy(update={"interfaces": [iface]})
    runner = FakeRunner()
    result = _runtime(runner).deploy_device(device)
    add_port = next(call for call in runner.calls if call[:2] == ["ovs-vsctl", "add-port"])
    assert add_port == ["ovs-vsctl", "add-port", "sw-a", "dv00-pc01"]
    assert any("sin etiqueta" in warning for warning in result.warnings)


def test_rutas_y_arp_estatico():
    runner = FakeRunner()
    _runtime(runner).deploy_device(_device())
    nsenter = [call for call in runner.calls if call[:2] == ["nsenter", "-t"]]
    route = ["nsenter", "-t", "4242", "-n", "--", "ip", "route", "add",
             "0.0.0.0/0", "via", "10.10.0.1"]
    arp = ["nsenter", "-t", "4242", "-n", "--", "ip", "neigh", "replace",
           "10.10.0.1", "lladdr", "00:1c:42:10:10:01", "dev", "eth0",
           "nud", "permanent"]
    assert route in nsenter
    assert arp in nsenter


# ── Idempotencia y errores ──────────────────────────────────


def test_contenedor_existente_se_recrea():
    device = _device()
    runner = FakeRunner()
    runner.containers[device.container_name] = {
        "id": "cid-viejo", "name": device.container_name, "state": "running",
        "pid": 1111, "image": device.image, "labels": {},
    }
    result = _runtime(runner).deploy_device(device)
    assert result.success is True
    assert ["docker", "stop", "dystopia-fabric-pc-01"] in runner.calls
    assert ["docker", "rm", "-f", "dystopia-fabric-pc-01"] in runner.calls
    assert any("recreado" in warning for warning in result.warnings)


def test_pid_invalido_falla_sin_veth():
    runner = FakeRunner(pid=0)
    result = _runtime(runner).deploy_device(_device())
    assert result.success is False
    assert result.error_step == "container_pid"
    assert any("PID inválido" in error for error in result.errors)
    assert not any(call[:3] == ["ip", "link", "add"] for call in runner.calls)


def test_fallo_en_veth_devuelve_error_estructurado():
    runner = FakeRunner(fail_if=lambda args: args[:3] == ["ip", "link", "add"])
    result = _runtime(runner).deploy_device(_device())
    assert result.success is False
    assert result.error_step == "veth_create"
    assert result.errors
    step = next(step for step in result.steps if step.name == "veth_create")
    assert step.ok is False
    assert step.command[:3] == ["ip", "link", "add"]
    assert step.stderr == "fallo simulado"
    assert not any(call[:2] == ["nsenter", "-t"] for call in runner.calls)


def test_fallo_en_nsenter_devuelve_paso():
    runner = FakeRunner(fail_if=lambda args: "name" in args and args[:2] == ["nsenter", "-t"])
    result = _runtime(runner).deploy_device(_device())
    assert result.success is False
    assert result.error_step == "netns_rename"
    assert result.errors


def test_fallo_en_ovs_devuelve_paso():
    runner = FakeRunner(fail_if=lambda args: args[:2] == ["ovs-vsctl", "add-port"])
    result = _runtime(runner).deploy_device(_device())
    assert result.success is False
    assert result.error_step == "ovs_add_port"


def test_fallo_en_docker_create():
    runner = FakeRunner(fail_if=lambda args: args[:2] == ["docker", "create"])
    result = _runtime(runner).deploy_device(_device())
    assert result.success is False
    assert result.error_step == "container_create"
    assert result.steps[-1].command[:2] == ["docker", "create"]


def test_dispositivo_sin_interfaces():
    device = _device().model_copy(update={"interfaces": []})
    runner = FakeRunner()
    result = _runtime(runner).deploy_device(device)
    assert result.success is False
    assert any("no declara interfaces" in error for error in result.errors)
    assert runner.calls == []


def test_nombre_de_veth_invalido():
    device = _device()
    bad = device.interfaces[0].model_copy(update={"host_veth": "dv00-demasiado-largo"})
    device = device.model_copy(update={"interfaces": [bad]})
    runner = FakeRunner()
    result = _runtime(runner).deploy_device(device)
    assert result.success is False
    assert any("15 caracteres" in error for error in result.errors)
    assert runner.calls == []


# ── Destroy ─────────────────────────────────────────────────


def test_destroy_limpio():
    runner = FakeRunner()
    runtime = _runtime(runner)
    assert runtime.deploy_device(_device()).success is True
    result = runtime.destroy_device(_device())
    assert result.success is True
    assert result.container_removed is True
    assert result.ports_removed == ["dv00-pc01"]
    assert result.veths_removed == ["dv00-pc01"]
    assert runner.containers == {}
    assert runner.ports == {}
    assert runner.links == set()


def test_destroy_tolera_ausencias():
    runner = FakeRunner()
    result = _runtime(runner).destroy_device(_device())
    assert result.success is True
    assert result.container_removed is False
    assert result.ports_removed == []
    assert result.veths_removed == []
    assert any("ausente" in warning for warning in result.warnings)


# ── Health ──────────────────────────────────────────────────


def test_health_ok():
    runner = FakeRunner()
    runtime = _runtime(runner)
    runtime.deploy_device(_device())
    health = runtime.device_health(_device())
    assert health["healthy"] is True
    assert health["runtime_available"] is True
    assert health["container"]["running"] is True
    assert health["interfaces"][0]["port_present"] is True
    assert health["neighbors"] == [{"ip": "10.10.0.1", "reachable": True}]
    assert all(check["ok"] for check in health["checks"])


def test_health_sin_contenedor():
    runner = FakeRunner()
    health = _runtime(runner).device_health(_device())
    assert health["healthy"] is False
    assert health["container"]["exists"] is False
    assert any(check["name"] == "container" and not check["ok"]
               for check in health["checks"])


def test_health_puerto_faltante():
    runner = FakeRunner()
    runtime = _runtime(runner)
    runtime.deploy_device(_device())
    runner.ports.clear()
    health = runtime.device_health(_device())
    assert health["healthy"] is False
    assert health["interfaces"][0]["port_present"] is False


def test_health_ping_falla():
    runner = FakeRunner(ping_ok=False)
    runtime = _runtime(runner)
    runtime.deploy_device(_device())
    health = runtime.device_health(_device())
    assert health["healthy"] is False
    assert health["neighbors"] == [{"ip": "10.10.0.1", "reachable": False}]


# ── DockerCliRuntime ────────────────────────────────────────


def test_docker_cli_runtime_inspect_parsea_estado():
    runner = FakeRunner()
    docker = DockerCliRuntime(runner=runner)
    container_id = docker.create(ContainerSpec(name="c1", image="img:v1"))
    docker.start(container_id)
    info = docker.inspect(container_id)
    assert info is not None
    assert info.pid == 4242
    assert info.state == "running"
    assert info.name == "c1"
    assert docker.exists("c1") is True


def test_docker_cli_runtime_inspect_ausente():
    docker = DockerCliRuntime(runner=FakeRunner())
    assert docker.inspect("no-existe") is None
    assert docker.exists("no-existe") is False


def test_docker_cli_runtime_error_estructurado():
    runner = FakeRunner(fail_if=lambda args: args[:2] == ["docker", "create"])
    with pytest.raises(ContainerRuntimeError) as excinfo:
        DockerCliRuntime(runner=runner).create(ContainerSpec(name="c1", image="img:v1"))
    assert excinfo.value.step == "container_create"
    assert excinfo.value.command[:2] == ["docker", "create"]
    assert "fallo simulado" in excinfo.value.stderr
