"""Pruebas unitarias del Deployment Engine OVS (sin OVS real).

Usan un ``FakeCommandRunner`` con estado (bridges, veths y puertos) para
verificar la secuencia exacta de comandos, VLANs, idempotencia,
aislamiento y manejo de errores. Corren en macOS y Linux.
"""

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.services.fabric.controller import FabricEngine, FabricPlan  # noqa: E402
from app.services.fabric.deploy import (  # noqa: E402
    CommandError,
    CommandResult,
    FabricDeployError,
    OvsFabricEngine,
    SubprocessRunner,
)
from app.services.fabric.parser import parse_manifest  # noqa: E402
from app.services.fabric.runtime import (  # noqa: E402
    DeviceDestroyResult,
    DeviceRuntimeResult,
)
from app.services.fabric.topology import (  # noqa: E402
    build_bridge_specs,
    build_device_specs,
    build_link_specs,
)


def _manifest() -> dict:
    """2 switches (sw-b uplink a sw-a) y un dispositivo en sw-b."""
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
                {"id": "sw-a", "vlans": [10, 20]},
                {"id": "sw-b", "vlans": [10], "uplink": "sw-a"},
            ],
            "links": [],
            "device_overrides": [{
                "id": "pc-01",
                "interfaces": [{
                    "segment": "vlan-10", "ip": "10.10.0.21/24",
                    "mac": "00:1c:42:10:10:21", "vlan_tag": 10, "switch": "sw-b",
                }],
            }],
        },
    }


def _topology_and_plan():
    topology = parse_manifest(_manifest())
    plan = FabricPlan(
        bridges=build_bridge_specs(topology),
        links=build_link_specs(topology),
        devices=build_device_specs(topology),
    )
    return topology, plan


class FakeCommandRunner:
    """Runner con estado que emula ovs-vsctl/ip sin tocar el host."""

    def __init__(
        self,
        bridges=None,
        links=None,
        ports=None,
        fail_if=None,
        ovs_available: bool = True,
        ip_available: bool = True,
    ):
        self.bridges = set(bridges or [])
        self.links = set(links or [])
        self.ports = dict(ports or {})
        self.calls: list[list[str]] = []
        self.fail_if = fail_if
        self.ovs_available = ovs_available
        self.ip_available = ip_available

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
            raise CommandError(f"comando falló: {args}", result)
        return result

    def _dispatch(self, args: list[str]) -> tuple[int, str, str]:
        if args[:2] == ["ovs-vsctl", "--version"]:
            return (0, "ovs-vsctl 3.1", "") if self.ovs_available else (1, "", "not found")
        if args[:2] == ["ip", "-V"]:
            return (0, "ip utility", "") if self.ip_available else (1, "", "not found")
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
        if args[:2] == ["ovs-vsctl", "del-br"]:
            self.bridges.discard(args[2])
            self.ports = {port: bridge for port, bridge in self.ports.items()
                          if bridge != args[2]}
            return (0, "", "")
        if args[:2] == ["ip", "link"]:
            if args[2] == "show":
                return (0, "", "") if args[3] in self.links else (1, "", "no such device")
            if args[2] == "add":
                self.links.add(args[3])
                self.links.add(args[8])
                return (0, "", "")
            if args[2] == "set":
                return (0, "", "")
            if args[2] == "del":
                self.links.discard(args[3])
                return (0, "", "")
        return (1, "", f"comando no soportado: {args}")


def _engine(runner: FakeCommandRunner, privileged: bool = True) -> OvsFabricEngine:
    return OvsFabricEngine(
        runner=runner,
        privilege_check=lambda: privileged,
        device_runtime=StubDeviceRuntime(),
    )


class StubDeviceRuntime:
    """DeviceRuntime falso: registra llamadas y simula éxito/fallo."""

    def __init__(self, fail_for: set[str] | None = None):
        self.deployed: list[str] = []
        self.destroyed: list[str] = []
        self.fail_for = set(fail_for or [])

    def deploy_device(self, spec, agent_config=None) -> DeviceRuntimeResult:
        self.deployed.append(spec.device_id)
        if spec.device_id in self.fail_for:
            return DeviceRuntimeResult(
                device_id=spec.device_id,
                container_name=spec.container_name,
                success=False,
                error_step="container_create",
                errors=["fallo simulado del device runtime"],
            )
        return DeviceRuntimeResult(
            device_id=spec.device_id,
            container_name=spec.container_name,
            success=True,
            container_id=f"cid-{spec.container_name}",
            pid=4242,
        )

    def destroy_device(self, spec) -> DeviceDestroyResult:
        self.destroyed.append(spec.device_id)
        return DeviceDestroyResult(
            device_id=spec.device_id,
            container_name=spec.container_name,
            success=True,
            container_removed=True,
        )


def _add_port_calls(runner: FakeCommandRunner) -> list[list[str]]:
    return [call for call in runner.calls if call[:2] == ["ovs-vsctl", "add-port"]]


# ── Secuencia y VLANs ───────────────────────────────────────


def test_deploy_secuencia_exacta():
    runner = FakeCommandRunner()
    engine = _engine(runner)
    topology, plan = _topology_and_plan()

    engine.deploy(plan, topology)

    assert runner.calls == [
        ["ovs-vsctl", "--version"],
        ["ip", "-V"],
        ["ovs-vsctl", "br-exists", "sw-a"],
        ["ovs-vsctl", "add-br", "sw-a"],
        ["ovs-vsctl", "set", "bridge", "sw-a", "stp_enable=false"],
        ["ovs-vsctl", "br-exists", "sw-b"],
        ["ovs-vsctl", "add-br", "sw-b"],
        ["ovs-vsctl", "set", "bridge", "sw-b", "stp_enable=false"],
        ["ip", "link", "show", "lk00a-swb"],
        ["ip", "link", "show", "lk00b-swa"],
        ["ip", "link", "add", "lk00a-swb", "type", "veth", "peer", "name", "lk00b-swa"],
        ["ip", "link", "set", "lk00a-swb", "up"],
        ["ip", "link", "set", "lk00b-swa", "up"],
        ["ovs-vsctl", "port-to-br", "lk00a-swb"],
        ["ovs-vsctl", "add-port", "sw-b", "lk00a-swb", "trunks=10"],
        ["ovs-vsctl", "port-to-br", "lk00b-swa"],
        ["ovs-vsctl", "add-port", "sw-a", "lk00b-swa", "trunks=10,20"],
    ]


def test_trunks_por_bridge_y_no_tag_en_troncales():
    runner = FakeCommandRunner()
    engine = _engine(runner)
    topology, plan = _topology_and_plan()
    engine.deploy(plan, topology)

    add_ports = _add_port_calls(runner)
    assert ["ovs-vsctl", "add-port", "sw-b", "lk00a-swb", "trunks=10"] in add_ports
    assert ["ovs-vsctl", "add-port", "sw-a", "lk00b-swa", "trunks=10,20"] in add_ports
    assert all(not any(arg.startswith("tag=") for arg in call) for call in add_ports)


def test_stp_se_propaga_al_bridge():
    manifest = _manifest()
    manifest["fabric"]["switches"][0]["stp"] = True
    topology = parse_manifest(manifest)
    plan = FabricPlan(
        bridges=build_bridge_specs(topology),
        links=build_link_specs(topology),
        devices=build_device_specs(topology),
    )
    runner = FakeCommandRunner()
    _engine(runner).deploy(plan, topology)
    assert ["ovs-vsctl", "set", "bridge", "sw-a", "stp_enable=true"] in runner.calls


def test_resultado_estructurado():
    runner = FakeCommandRunner()
    engine = _engine(runner)
    topology, plan = _topology_and_plan()
    engine.deploy(plan, topology)

    result = engine.last_result
    assert result is not None
    assert result.bridges_created == ["sw-a", "sw-b"]
    assert result.bridges_existing == []
    assert result.links_created == ["lk00"]
    assert result.links_existing == []
    assert result.containers_created == ["pc-01"]
    assert result.containers_failed == []
    assert result.device_ports_created == ["dv00-pc01"]
    assert result.devices == [{
        "device_id": "pc-01",
        "container_id": "cid-dystopia-fabric-pc-01",
        "pid": 4242,
        "success": True,
        "step": "",
        "error": "",
    }]
    assert result.errors == []
    assert result.warnings == []


def test_puertos_de_dispositivo_en_resultado():
    runner = FakeCommandRunner()
    engine = _engine(runner)
    topology, plan = _topology_and_plan()
    engine.deploy(plan, topology)

    device_ports = {
        port.name for bridge in plan.bridges for port in bridge.ports
        if port.kind == "device"
    }
    assert device_ports == {"dv00-pc01"}
    # El engine no emite comandos OVS para puertos de dispositivo: los
    # añade el DeviceRuntime (con tag) durante su propio attachment.
    added = {call[3] for call in _add_port_calls(runner)}
    assert added.isdisjoint(device_ports)
    assert engine.last_result is not None
    assert engine.last_result.device_ports_created == ["dv00-pc01"]


def test_enlace_trunk_false_avisa_pero_se_configura_troncal():
    topology, plan = _topology_and_plan()
    link = plan.links[0].model_copy(update={"trunk": False})
    plan = plan.model_copy(update={"links": [link]})
    runner = FakeCommandRunner()
    engine = _engine(runner)
    engine.deploy(plan, topology)
    assert engine.last_result is not None
    assert any("trunk=false" in warning for warning in engine.last_result.warnings)
    assert any(call[:2] == ["ovs-vsctl", "add-port"] for call in runner.calls)


# ── Idempotencia ────────────────────────────────────────────


def test_deploy_idempotente_con_recursos_existentes():
    runner = FakeCommandRunner(
        bridges={"sw-a", "sw-b"},
        links={"lk00a-swb", "lk00b-swa"},
        ports={"lk00a-swb": "sw-b", "lk00b-swa": "sw-a"},
    )
    engine = _engine(runner)
    topology, plan = _topology_and_plan()
    engine.deploy(plan, topology)

    assert not any(call[:2] == ["ovs-vsctl", "add-br"] for call in runner.calls)
    assert not _add_port_calls(runner)
    assert not any(call[:3] == ["ip", "link", "add"] for call in runner.calls)
    assert engine.last_result is not None
    assert engine.last_result.bridges_existing == ["sw-a", "sw-b"]
    assert engine.last_result.links_existing == ["lk00"]


def test_estado_inconsistente_de_enlace_falla():
    runner = FakeCommandRunner(links={"lk00a-swb"})
    engine = _engine(runner)
    topology, plan = _topology_and_plan()
    with pytest.raises(FabricDeployError) as excinfo:
        engine.deploy(plan, topology)
    assert "Estado inconsistente" in str(excinfo.value)


def test_puerto_en_otro_bridge_falla():
    runner = FakeCommandRunner(
        bridges={"sw-a", "sw-b"},
        links={"lk00a-swb", "lk00b-swa"},
        ports={"lk00a-swb": "sw-a"},
    )
    engine = _engine(runner)
    topology, plan = _topology_and_plan()
    with pytest.raises(FabricDeployError) as excinfo:
        engine.deploy(plan, topology)
    assert "ya pertenece al bridge 'sw-a'" in str(excinfo.value)


# ── Preflight y validación ──────────────────────────────────


def test_preflight_sin_privilegios():
    runner = FakeCommandRunner()
    topology, plan = _topology_and_plan()
    with pytest.raises(FabricDeployError) as excinfo:
        _engine(runner, privileged=False).deploy(plan, topology)
    assert "root o CAP_NET_ADMIN" in str(excinfo.value)
    assert runner.calls == []


def test_preflight_sin_ovs_vsctl():
    runner = FakeCommandRunner(ovs_available=False)
    topology, plan = _topology_and_plan()
    with pytest.raises(FabricDeployError) as excinfo:
        _engine(runner).deploy(plan, topology)
    assert "ovs-vsctl" in str(excinfo.value)
    assert runner.calls == [["ovs-vsctl", "--version"]]


def test_preflight_sin_ip():
    runner = FakeCommandRunner(ip_available=False)
    topology, plan = _topology_and_plan()
    with pytest.raises(FabricDeployError) as excinfo:
        _engine(runner).deploy(plan, topology)
    assert "'ip'" in str(excinfo.value)
    assert runner.calls == [["ovs-vsctl", "--version"], ["ip", "-V"]]


def test_nombre_de_puerto_largo_rechazado():
    topology, plan = _topology_and_plan()
    long_link = plan.links[0].model_copy(update={"port_from": "lk00a-demasiado-largo"})
    plan = plan.model_copy(update={"links": [long_link]})
    runner = FakeCommandRunner()
    with pytest.raises(FabricDeployError) as excinfo:
        _engine(runner).deploy(plan, topology)
    assert "supera los 15 caracteres" in str(excinfo.value)
    assert runner.calls == []


def test_nombre_de_bridge_largo_rechazado():
    topology, plan = _topology_and_plan()
    long_bridge = plan.bridges[0].model_copy(update={"id": "sw-demasiado-largo"})
    plan = plan.model_copy(update={"bridges": [long_bridge, plan.bridges[1]]})
    runner = FakeCommandRunner()
    with pytest.raises(FabricDeployError) as excinfo:
        _engine(runner).deploy(plan, topology)
    assert "supera los 15 caracteres" in str(excinfo.value)
    assert runner.calls == []


def test_nombre_con_guion_inicial_rechazado():
    topology, plan = _topology_and_plan()
    bad = plan.links[0].model_copy(update={"port_from": "-lk00a"})
    plan = plan.model_copy(update={"links": [bad]})
    runner = FakeCommandRunner()
    with pytest.raises(FabricDeployError) as excinfo:
        _engine(runner).deploy(plan, topology)
    assert "no puede empezar por '-'" in str(excinfo.value)
    assert runner.calls == []


def test_bridge_no_interno_rechazado():
    topology, plan = _topology_and_plan()
    external = plan.bridges[0].model_copy(update={"internal": False})
    plan = plan.model_copy(update={"bridges": [external, plan.bridges[1]]})
    runner = FakeCommandRunner()
    with pytest.raises(FabricDeployError) as excinfo:
        _engine(runner).deploy(plan, topology)
    assert "§9.1" in str(excinfo.value)
    assert runner.calls == []


def test_fallo_de_comando_es_accionable():
    runner = FakeCommandRunner(
        fail_if=lambda args: args[:3] == ["ip", "link", "add"]
    )
    engine = _engine(runner)
    topology, plan = _topology_and_plan()
    with pytest.raises(FabricDeployError) as excinfo:
        engine.deploy(plan, topology)
    message = str(excinfo.value)
    assert "ip link add lk00a-swb" in message
    assert "fallo simulado" in message
    assert engine.last_result is None


# ── Aislamiento §9.1 ────────────────────────────────────────


def test_aislamiento_solo_puertos_de_enlace():
    runner = FakeCommandRunner()
    engine = _engine(runner)
    topology, plan = _topology_and_plan()
    engine.deploy(plan, topology)

    link_ports = {
        port for link in plan.links for port in (link.port_from, link.port_to)
    }
    bridges = {bridge.id for bridge in plan.bridges}
    add_ports = _add_port_calls(runner)
    assert add_ports
    for call in add_ports:
        assert call[2] in bridges
        assert call[3] in link_ports
        assert not call[3].startswith(("eth", "ens", "enp", "wlan", "br-"))
    assert not any("br-ex" in call for call in runner.calls)


def test_engine_cumple_el_protocolo():
    assert isinstance(_engine(FakeCommandRunner()), FabricEngine)


class DockerFakeCommandRunner(FakeCommandRunner):
    """Fake con soporte de docker para ejercitar engine + DeviceRuntime."""

    def __init__(self, pid: int = 4242, **kwargs):
        super().__init__(**kwargs)
        self.containers: dict[str, dict] = {}
        self.pid = pid

    def _dispatch(self, args: list[str]) -> tuple[int, str, str]:
        if args[:2] == ["docker", "create"]:
            name = args[args.index("--name") + 1]
            container = {
                "id": f"cid-{name}", "name": name, "state": "created", "pid": 0,
            }
            self.containers[name] = container
            return (0, container["id"], "")
        if args[:2] == ["docker", "start"]:
            container = self.containers.get(args[2]) or self._by_id(args[2])
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
        if args[:2] == ["nsenter", "-t"]:
            return (0, "", "")
        return super()._dispatch(args)

    def _by_id(self, value: str) -> dict | None:
        if value in self.containers:
            return self.containers[value]
        for container in self.containers.values():
            if container["id"] == value:
                return container
        return None


def _real_engine(runner: DockerFakeCommandRunner) -> OvsFabricEngine:
    """Engine con el DeviceRuntime real (DockerCliRuntime) sobre el fake."""
    from app.services.fabric.runtime import DeviceRuntime, DockerCliRuntime

    return OvsFabricEngine(
        runner=runner,
        privilege_check=lambda: True,
        device_runtime=DeviceRuntime(DockerCliRuntime(runner=runner), runner=runner),
    )


def test_orden_switches_links_y_devices():
    """§8.1: los contenedores se crean después de bridges y enlaces."""
    runner = DockerFakeCommandRunner()
    engine = _real_engine(runner)
    topology, plan = _topology_and_plan()
    engine.deploy(plan, topology)

    first_docker = next(
        index for index, call in enumerate(runner.calls)
        if call[:2] == ["docker", "create"]
    )
    last_trunk = max(
        index for index, call in enumerate(runner.calls)
        if call[:2] == ["ovs-vsctl", "add-port"]
        and any(arg.startswith("trunks=") for arg in call)
    )
    device_port = min(
        index for index, call in enumerate(runner.calls)
        if call[:2] == ["ovs-vsctl", "add-port"] and call[3].startswith("dv")
    )
    assert last_trunk < first_docker < device_port
    add_port = runner.calls[device_port]
    assert add_port == ["ovs-vsctl", "add-port", "sw-b", "dv00-pc01", "tag=10"]


def test_destroy_orden_inverso_devices():
    """§8.2: los dispositivos se destruyen antes que enlaces y bridges."""
    runner = DockerFakeCommandRunner()
    engine = _real_engine(runner)
    topology, plan = _topology_and_plan()
    engine.deploy(plan, topology)
    engine.destroy(topology)

    docker_rm = next(
        index for index, call in enumerate(runner.calls)
        if call[:2] == ["docker", "rm"]
    )
    first_link_delport = min(
        index for index, call in enumerate(runner.calls)
        if call[:2] == ["ovs-vsctl", "del-port"] and call[3].startswith("lk")
    )
    assert docker_rm < first_link_delport
    assert engine.last_destroy_result is not None
    assert engine.last_destroy_result.containers_removed == ["pc-01"]


def _manifest_dos_dispositivos() -> dict:
    manifest = _manifest()
    manifest["devices"].append({
        "id": "srv-01", "role": "server", "segment": "vlan-20", "ip": "10.20.0.10",
    })
    manifest["fabric"]["device_overrides"].append({
        "id": "srv-01",
        "interfaces": [{
            "segment": "vlan-20", "ip": "10.20.0.10/24",
            "mac": "00:1c:42:20:10:10", "vlan_tag": 20, "switch": "sw-a",
        }],
    })
    return manifest


def test_fallo_parcial_de_dispositivo_no_aborta():
    topology = parse_manifest(_manifest_dos_dispositivos())
    plan = FabricPlan(
        bridges=build_bridge_specs(topology),
        links=build_link_specs(topology),
        devices=build_device_specs(topology),
    )
    runtime = StubDeviceRuntime(fail_for={"srv-01"})
    runner = FakeCommandRunner()
    engine = OvsFabricEngine(
        runner=runner, privilege_check=lambda: True, device_runtime=runtime,
    )
    engine.deploy(plan, topology)

    result = engine.last_result
    assert result is not None
    assert result.containers_created == ["pc-01"]
    assert [failed["device_id"] for failed in result.containers_failed] == ["srv-01"]
    assert result.containers_failed[0]["error"] == "fallo simulado del device runtime"
    assert any("srv-01" in warning for warning in result.warnings)
    assert runtime.deployed == ["pc-01", "srv-01"]


def test_todos_los_dispositivos_fallan_lanza():
    topology = parse_manifest(_manifest_dos_dispositivos())
    plan = FabricPlan(
        bridges=build_bridge_specs(topology),
        links=build_link_specs(topology),
        devices=build_device_specs(topology),
    )
    runtime = StubDeviceRuntime(fail_for={"pc-01", "srv-01"})
    engine = OvsFabricEngine(
        runner=FakeCommandRunner(), privilege_check=lambda: True,
        device_runtime=runtime,
    )
    with pytest.raises(FabricDeployError) as excinfo:
        engine.deploy(plan, topology)
    assert "Ningún dispositivo" in str(excinfo.value)


def test_destroy_registra_dispositivos_en_resultado():
    runner = FakeCommandRunner()
    engine = _engine(runner)
    topology, plan = _topology_and_plan()
    engine.deploy(plan, topology)
    engine.destroy(topology)
    result = engine.last_destroy_result
    assert result is not None
    assert result.containers_removed == ["pc-01"]
    assert result.credentials_removed == []
    assert result.devices == [{
        "device_id": "pc-01",
        "container_removed": True,
        "credentials_removed": [],
        "success": True,
        "step": "",
        "error": "",
    }]


def test_destroy_agrega_credenciales_borradas():
    """El engine propaga al DestroyResult los ``.enc`` que borró el runtime."""

    class CredentialDestroyRuntime(StubDeviceRuntime):
        def destroy_device(self, spec) -> DeviceDestroyResult:
            outcome = super().destroy_device(spec)
            outcome.credentials_removed = [spec.device_id]
            return outcome

    runner = FakeCommandRunner()
    engine = OvsFabricEngine(
        runner=runner,
        privilege_check=lambda: True,
        device_runtime=CredentialDestroyRuntime(),
    )
    topology, plan = _topology_and_plan()
    engine.deploy(plan, topology)
    engine.destroy(topology)
    result = engine.last_destroy_result
    assert result is not None
    assert result.credentials_removed == ["pc-01"]
    assert result.devices[0]["credentials_removed"] == ["pc-01"]


# ── Destroy ─────────────────────────────────────────────────


def test_destroy_limpia_y_es_idempotente():
    runner = FakeCommandRunner()
    engine = _engine(runner)
    topology, plan = _topology_and_plan()
    engine.deploy(plan, topology)

    engine.destroy(topology)
    assert runner.bridges == set()
    assert runner.links == set()
    assert runner.ports == {}
    assert engine.last_destroy_result is not None
    assert engine.last_destroy_result.bridges_removed == ["sw-b", "sw-a"]
    assert engine.last_destroy_result.links_removed == ["lk00"]
    assert engine.last_destroy_result.warnings == []

    calls_before = len(runner.calls)
    engine.destroy(topology)
    second = runner.calls[calls_before:]
    assert not any(call[:2] == ["ovs-vsctl", "del-br"] for call in second)
    assert not any(call[:2] == ["ovs-vsctl", "del-port"] for call in second)
    assert not any(call[:3] == ["ip", "link", "del"] for call in second)
    assert engine.last_destroy_result is not None
    assert engine.last_destroy_result.bridges_removed == []


def test_destroy_tolera_recursos_ausentes():
    runner = FakeCommandRunner()
    engine = _engine(runner)
    topology, _ = _topology_and_plan()
    engine.destroy(topology)
    assert engine.last_destroy_result is not None
    assert engine.last_destroy_result.bridges_removed == []
    assert engine.last_destroy_result.links_removed == []
    assert not any(call[:2] == ["ovs-vsctl", "del-br"] for call in runner.calls)


def test_destroy_registra_warning_si_del_falla():
    runner = FakeCommandRunner(fail_if=lambda args: args[:2] == ["ovs-vsctl", "del-br"])
    engine = _engine(runner)
    topology, plan = _topology_and_plan()
    engine.deploy(plan, topology)
    engine.destroy(topology)
    assert engine.last_destroy_result is not None
    assert engine.last_destroy_result.warnings
    assert "del-br falló" in engine.last_destroy_result.warnings[0]


# ── SubprocessRunner ────────────────────────────────────────


def test_subprocess_runner_exito():
    result = SubprocessRunner().run([sys.executable, "-c", "print('hola')"])
    assert result.returncode == 0
    assert result.stdout.strip() == "hola"
    assert result.stderr == ""


def test_subprocess_runner_fallo_con_check():
    args = [sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(3)"]
    with pytest.raises(CommandError) as excinfo:
        SubprocessRunner().run(args)
    assert "boom" in str(excinfo.value)
    assert excinfo.value.result is not None
    assert excinfo.value.result.returncode == 3


def test_subprocess_runner_fallo_sin_check():
    args = [sys.executable, "-c", "import sys; sys.exit(4)"]
    result = SubprocessRunner().run(args, check=False)
    assert result.returncode == 4


def test_subprocess_runner_timeout():
    args = [sys.executable, "-c", "import time; time.sleep(1)"]
    with pytest.raises(CommandError) as excinfo:
        SubprocessRunner(timeout=0.1).run(args)
    assert "excedió 0.1s" in str(excinfo.value)


# ── Fase 8: credenciales fuera de device.json y cifradas aparte ──


def _manifest_con_credenciales() -> dict:
    manifest = _manifest()
    manifest["fabric"]["device_overrides"][0]["credentials"] = [
        {"username": "admin", "password": "admin123", "service": "ssh"},
    ]
    return manifest


class FakeCredentialStore:
    """Store falso: registra lo que el engine cifraría."""

    def __init__(self, configured: bool = True):
        self.configured = configured
        self.stored: list[tuple[str, list[dict]]] = []

    def is_configured(self) -> bool:
        return self.configured

    def store_for_device(self, device_id, credentials) -> None:
        self.stored.append((device_id, credentials))


def test_agent_config_sin_credenciales():
    from app.services.fabric.deploy import _agent_config

    topology = parse_manifest(_manifest_con_credenciales())
    config = _agent_config(topology, "pc-01")
    assert "credentials" not in config
    assert "admin123" not in json.dumps(config)


def test_engine_cifra_credenciales_aparte():
    topology = parse_manifest(_manifest_con_credenciales())
    plan = FabricPlan(
        bridges=build_bridge_specs(topology),
        links=build_link_specs(topology),
        devices=build_device_specs(topology),
    )
    store = FakeCredentialStore()
    engine = OvsFabricEngine(
        runner=FakeCommandRunner(), privilege_check=lambda: True,
        device_runtime=StubDeviceRuntime(), credential_store=store,
    )
    engine.deploy(plan, topology)
    assert store.stored == [("pc-01", [{
        "username": "admin", "password": "admin123",
        "service": "ssh", "purpose": "",
    }])]
    assert engine.last_result is not None
    assert not any("no cifradas" in warning for warning in engine.last_result.warnings)


def test_engine_sin_clave_avisa_pero_despliega():
    topology = parse_manifest(_manifest_con_credenciales())
    plan = FabricPlan(
        bridges=build_bridge_specs(topology),
        links=build_link_specs(topology),
        devices=build_device_specs(topology),
    )
    store = FakeCredentialStore(configured=False)
    engine = OvsFabricEngine(
        runner=FakeCommandRunner(), privilege_check=lambda: True,
        device_runtime=StubDeviceRuntime(), credential_store=store,
    )
    engine.deploy(plan, topology)
    assert store.stored == []
    assert engine.last_result is not None
    assert any("no cifradas" in warning for warning in engine.last_result.warnings)
