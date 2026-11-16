"""Pruebas del Lifecycle Manager del fabric (Fase 3b).

Sin OVS real: un ``FakeRunner`` con estado emula ``ovs-vsctl``/``ip``
(bridges, puertos, veths) para verificar preflight, salud contra OVS,
reconciliación/limpieza de huérfanos y la orquestación idempotente
deploy/destroy/rebuild con propagación de errores.
"""

import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.services.deception import topology_svc  # noqa: E402
from app.services.fabric.controller import NullFabricEngine  # noqa: E402
from app.services.fabric.deploy import (  # noqa: E402
    CommandResult,
    FabricDeployError,
    OvsFabricEngine,
)
from app.services.fabric.controller import FabricPlan  # noqa: E402
from app.services.fabric.lifecycle import (  # noqa: E402
    cleanup_orphans,
    deploy,
    destroy,
    health,
    preflight,
    rebuild,
    reconcile,
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


def _topology():
    return parse_manifest(_manifest())


def _plan(topology=None) -> FabricPlan:
    topo = topology or _topology()
    return FabricPlan(
        bridges=build_bridge_specs(topo),
        links=build_link_specs(topo),
        devices=build_device_specs(topo),
    )


class FakeRunner:
    """Runner con estado que emula ovs-vsctl/ip sin tocar el host."""

    def __init__(
        self,
        bridges=None,
        links=None,
        ports=None,
        ovs_available: bool = True,
        fail_if=None,
    ):
        self.bridges = set(bridges or [])
        self.links = set(links or [])
        self.ports = dict(ports or {})
        self.ovs_available = ovs_available
        self.fail_if = fail_if
        self.calls: list[list[str]] = []

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
            raise FabricDeployError([f"comando falló: {args}"])
        return result

    def _dispatch(self, args: list[str]) -> tuple[int, str, str]:
        if args[0] == "ovs-vsctl" and not self.ovs_available:
            return (1, "", "not found")
        if args[:2] == ["ip", "-V"]:
            return (0, "ip utility", "")
        if args[:2] == ["tc", "-V"]:
            return (0, "tc utility, iproute2-6.1.0", "")
        if args[:2] == ["ovs-vsctl", "--version"]:
            return (0, "ovs-vsctl 3.1", "")
        if args[:2] == ["ovs-vsctl", "list-br"]:
            return (0, "\n".join(sorted(self.bridges)), "")
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
        if args[:2] == ["ovs-vsctl", "list-ports"]:
            return (0, "\n".join(
                port for port, bridge in self.ports.items() if bridge == args[2]
            ), "")
        if args[:2] == ["ovs-vsctl", "del-br"]:
            self.bridges.discard(args[2])
            self.ports = {p: b for p, b in self.ports.items() if b != args[2]}
            return (0, "", "")
        if args[:3] == ["ip", "-o", "link"]:
            return (0, "\n".join(
                f"{index}: {name}: <BROADCAST,UP>"
                for index, name in enumerate(sorted(self.links))
            ), "")
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


@pytest.fixture()
def net_file(tmp_path, monkeypatch):
    """network.yaml temporal válido (para el check de manifiesto)."""
    target = tmp_path / "network.yaml"
    target.write_text(yaml.safe_dump(_manifest()), encoding="utf-8")
    monkeypatch.setattr(topology_svc, "NETWORK_FILE", target)
    topology_svc.invalidate_cache()
    yield target
    topology_svc.invalidate_cache()


class StubDeviceRuntime:
    """DeviceRuntime falso para los tests de orquestación."""

    def __init__(self, fail_for: set[str] | None = None):
        self.deployed: list[str] = []
        self.destroyed: list[str] = []
        self.fail_for = set(fail_for or [])

    def deploy_device(self, spec, agent_config=None) -> DeviceRuntimeResult:
        self.deployed.append(spec.device_id)
        if spec.device_id in self.fail_for:
            return DeviceRuntimeResult(
                device_id=spec.device_id, container_name=spec.container_name,
                success=False, error_step="container_create",
                errors=["fallo simulado del device runtime"],
            )
        return DeviceRuntimeResult(
            device_id=spec.device_id, container_name=spec.container_name,
            success=True, container_id=f"cid-{spec.container_name}", pid=4242,
        )

    def destroy_device(self, spec) -> DeviceDestroyResult:
        self.destroyed.append(spec.device_id)
        return DeviceDestroyResult(
            device_id=spec.device_id, container_name=spec.container_name,
            success=True, container_removed=True,
        )


def _ovs_engine(runner: FakeRunner, privileged: bool = True) -> OvsFabricEngine:
    return OvsFabricEngine(
        runner=runner,
        privilege_check=lambda: privileged,
        device_runtime=StubDeviceRuntime(),
    )


# ── Preflight ───────────────────────────────────────────────


def test_preflight_ok_con_ovs(net_file):
    report = preflight(engine=_ovs_engine(FakeRunner()))
    assert report["ok"] is True
    assert report["errors"] == []
    assert [check["name"] for check in report["checks"]] == ["runtime", "manifiesto"]


def test_preflight_sin_ovs(net_file):
    report = preflight(engine=_ovs_engine(FakeRunner(ovs_available=False)))
    assert report["ok"] is False
    assert any("ovs-vsctl" in error for error in report["errors"])


def test_preflight_sin_privilegios(net_file):
    report = preflight(engine=_ovs_engine(FakeRunner(), privileged=False))
    assert report["ok"] is False
    assert any("root o CAP_NET_ADMIN" in error for error in report["errors"])


def test_preflight_manifiesto_invalido(tmp_path, monkeypatch):
    target = tmp_path / "network.yaml"
    broken = _manifest()
    broken["fabric"]["device_overrides"][0]["interfaces"][0]["switch"] = "sw-nope"
    target.write_text(yaml.safe_dump(broken), encoding="utf-8")
    monkeypatch.setattr(topology_svc, "NETWORK_FILE", target)
    topology_svc.invalidate_cache()
    report = preflight(engine=_ovs_engine(FakeRunner()))
    assert report["ok"] is False
    assert any("sw-nope" in error for error in report["errors"])


def test_preflight_con_stub_engine_solo_avisa(net_file):
    report = preflight(engine=NullFabricEngine())
    assert report["ok"] is True
    assert any("stub" in warning for warning in report["warnings"])


# ── Salud contra OVS ────────────────────────────────────────


def test_health_todo_presente():
    topology = _topology()
    link = _plan(topology).links[0]
    runner = FakeRunner(
        bridges={"sw-a", "sw-b"},
        links={link.port_from, link.port_to},
        ports={link.port_from: "sw-b", link.port_to: "sw-a"},
    )
    report = health(runner=runner, topology=topology)
    assert report["runtime_available"] is True
    assert report["healthy"] is True
    assert report["bridges"]["missing"] == []
    assert report["links"]["missing"] == []
    assert report["extra_ports"] == []


def test_health_bridge_faltante():
    topology = _topology()
    link = _plan(topology).links[0]
    runner = FakeRunner(
        bridges={"sw-a"},
        links={link.port_from, link.port_to},
        ports={link.port_from: "sw-b", link.port_to: "sw-a"},
    )
    report = health(runner=runner, topology=topology)
    assert report["healthy"] is False
    assert report["bridges"]["missing"] == ["sw-b"]
    assert report["links"]["missing"] == ["lk00"]


def test_health_puerto_de_enlace_faltante():
    topology = _topology()
    runner = FakeRunner(bridges={"sw-a", "sw-b"})
    report = health(runner=runner, topology=topology)
    assert report["healthy"] is False
    assert report["links"]["missing"] == ["lk00"]
    assert report["bridges"]["missing"] == []


def test_health_puerto_extra_se_reporta():
    topology = _topology()
    link = _plan(topology).links[0]
    runner = FakeRunner(
        bridges={"sw-a", "sw-b"},
        links={link.port_from, link.port_to, "dv99-huerfano"},
        ports={
            link.port_from: "sw-b",
            link.port_to: "sw-a",
            "dv99-huerfano": "sw-a",
        },
    )
    report = health(runner=runner, topology=topology)
    assert report["extra_ports"] == ["dv99-huerfano"]
    assert any("dv99-huerfano" in warning for warning in report["warnings"])


def test_health_sin_ovs():
    topology = _topology()
    report = health(runner=FakeRunner(ovs_available=False), topology=topology)
    assert report["runtime_available"] is False
    assert report["healthy"] is False
    assert any("Sin OVS" in warning for warning in report["warnings"])


def test_health_dispositivos_son_informativos():
    topology = _topology()
    link = _plan(topology).links[0]
    runner = FakeRunner(
        bridges={"sw-a", "sw-b"},
        links={link.port_from, link.port_to},
        ports={link.port_from: "sw-b", link.port_to: "sw-a"},
    )
    report = health(runner=runner, topology=topology)
    # El veth del dispositivo no existe (Fase 4): se reporta pero no rompe.
    assert report["devices"]["missing"] == ["dv00-pc01"]
    assert report["healthy"] is True
    assert "Fase 4" in (report["devices"]["note"] or "")


def test_health_sin_topologia_valida(tmp_path, monkeypatch):
    target = tmp_path / "network.yaml"
    broken = _manifest()
    broken["fabric"]["device_overrides"][0]["interfaces"][0]["switch"] = "sw-nope"
    target.write_text(yaml.safe_dump(broken), encoding="utf-8")
    monkeypatch.setattr(topology_svc, "NETWORK_FILE", target)
    topology_svc.invalidate_cache()
    report = health(runner=FakeRunner())
    assert report["healthy"] is False
    assert report["runtime_available"] is False
    assert any("topología válida" in error for error in report["errors"])


# ── Reconciliación y limpieza de huérfanos ──────────────────


def test_reconcile_detecta_bridge_huerfano():
    topology = _topology()
    link = _plan(topology).links[0]
    runner = FakeRunner(
        bridges={"sw-a", "sw-b", "sw-huerfano"},
        links={link.port_from, link.port_to, "lk99-huerf"},
        ports={
            link.port_from: "sw-b",
            link.port_to: "sw-a",
            "lk99-huerf": "sw-huerfano",
        },
    )
    report = reconcile(runner=runner, topology=topology)
    assert report["ok"] is True
    assert [orphan["bridge"] for orphan in report["orphans"]["bridges"]] == ["sw-huerfano"]
    assert report["orphans"]["bridges"][0]["ports"] == ["lk99-huerf"]
    # El veth del bridge huérfano también queda marcado (no está en el plan).
    assert "lk99-huerf" in report["orphans"]["veths"]


def test_reconcile_detecta_veth_huerfano():
    topology = _topology()
    link = _plan(topology).links[0]
    runner = FakeRunner(
        bridges={"sw-a", "sw-b"},
        links={link.port_from, link.port_to, "dv99-ghost"},
        ports={link.port_from: "sw-b", link.port_to: "sw-a"},
    )
    report = reconcile(runner=runner, topology=topology)
    assert report["orphans"]["veths"] == ["dv99-ghost"]
    assert report["orphans"]["bridges"] == []


def test_reconcile_sin_huerfanos():
    topology = _topology()
    link = _plan(topology).links[0]
    runner = FakeRunner(
        bridges={"sw-a", "sw-b"},
        links={link.port_from, link.port_to},
        ports={link.port_from: "sw-b", link.port_to: "sw-a"},
    )
    report = reconcile(runner=runner, topology=topology)
    assert report["orphans"] == {"bridges": [], "veths": []}


def test_reconcile_no_toca_bridges_ajenos():
    topology = _topology()
    runner = FakeRunner(bridges={"lan-externo"}, ports={})
    report = reconcile(runner=runner, topology=topology)
    # Un bridge sin puertos de fabric no se considera huérfano.
    assert report["orphans"]["bridges"] == []
    assert not any(call[:2] == ["ovs-vsctl", "del-br"] for call in runner.calls)


def test_reconcile_sin_ovs():
    report = reconcile(runner=FakeRunner(ovs_available=False), topology=_topology())
    assert report["ok"] is False
    assert report["runtime_available"] is False
    assert any("ovs-vsctl" in error for error in report["errors"])


def test_cleanup_elimina_exactamente_los_huerfanos():
    topology = _topology()
    link = _plan(topology).links[0]
    runner = FakeRunner(
        bridges={"sw-a", "sw-b", "sw-huerfano"},
        links={link.port_from, link.port_to, "lk99-huerf", "dv99-ghost"},
        ports={
            link.port_from: "sw-b",
            link.port_to: "sw-a",
            "lk99-huerf": "sw-huerfano",
        },
    )
    result = cleanup_orphans(runner=runner, topology=topology)
    assert result["ok"] is True
    assert result["removed"]["bridges"] == ["sw-huerfano"]
    assert sorted(result["removed"]["veths"]) == ["dv99-ghost", "lk99-huerf"]
    # El bridge huérfano se borra junto a su puerto lk*; los veths sueltos también.
    assert "sw-huerfano" not in runner.bridges
    assert "lk99-huerf" not in runner.ports
    assert "dv99-ghost" not in runner.links
    # Los recursos del plan siguen intactos.
    assert runner.bridges == {"sw-a", "sw-b"}
    assert {link.port_from, link.port_to} <= runner.links


def test_cleanup_tolera_fallo_al_borrar():
    topology = _topology()
    link = _plan(topology).links[0]
    runner = FakeRunner(
        bridges={"sw-a", "sw-b", "sw-huerfano"},
        links={link.port_from, link.port_to, "lk99-huerf"},
        ports={
            link.port_from: "sw-b",
            link.port_to: "sw-a",
            "lk99-huerf": "sw-huerfano",
        },
        fail_if=lambda args: args[:2] == ["ovs-vsctl", "del-br"],
    )
    result = cleanup_orphans(runner=runner, topology=topology)
    assert result["removed"]["bridges"] == []
    assert result["removed"]["veths"] == ["lk99-huerf"]
    assert any("del-br" in warning for warning in result["warnings"])


def test_cleanup_sin_ovs():
    result = cleanup_orphans(runner=FakeRunner(ovs_available=False), topology=_topology())
    assert result["ok"] is False
    assert result["removed"] == {"bridges": [], "veths": []}


# ── Orquestación deploy/destroy/rebuild ─────────────────────


def test_deploy_wrapper_devuelve_resultado_estructurado():
    topology = _topology()
    engine = _ovs_engine(FakeRunner())
    summary = deploy(engine, _plan(topology), topology)
    assert summary["engine"] == "OvsFabricEngine"
    assert summary["bridges_created"] == ["sw-a", "sw-b"]
    assert summary["links_created"] == ["lk00"]
    assert summary["device_ports_created"] == ["dv00-pc01"]
    assert summary["devices"][0]["success"] is True
    assert summary["warnings"] == []


def test_deploy_wrapper_con_stub():
    topology = _topology()
    engine = NullFabricEngine()
    summary = deploy(engine, _plan(topology), topology)
    assert summary == {"engine": "NullFabricEngine"}
    assert len(engine.deployed) == 1


def test_destroy_wrapper_devuelve_eliminados():
    topology = _topology()
    engine = _ovs_engine(FakeRunner())
    deploy(engine, _plan(topology), topology)
    summary = destroy(engine, topology)
    assert summary["engine"] == "OvsFabricEngine"
    assert summary["bridges_removed"] == ["sw-b", "sw-a"]
    assert summary["links_removed"] == ["lk00"]
    assert summary["containers_removed"] == ["pc-01"]


def test_rebuild_wrapper_es_idempotente():
    topology = _topology()
    plan = _plan(topology)
    link = plan.links[0]
    runner = FakeRunner()
    engine = _ovs_engine(runner)
    deploy(engine, plan, topology)
    result = rebuild(engine, plan, topology)
    assert result["engine"] == "OvsFabricEngine"
    assert result["destroy"]["bridges_removed"] == ["sw-b", "sw-a"]
    assert result["deploy"]["bridges_created"] == ["sw-a", "sw-b"]
    assert result["deploy"]["containers_created"] == ["pc-01"]
    # El estado final replica el plan (destroy limpio + create).
    assert runner.bridges == {"sw-a", "sw-b"}
    assert {link.port_from, link.port_to} <= runner.links
    assert runner.ports == {link.port_from: "sw-b", link.port_to: "sw-a"}


def test_errores_del_engine_se_propagan():
    topology = _topology()
    plan = _plan(topology)
    runner = FakeRunner(fail_if=lambda args: args[:3] == ["ip", "link", "add"])
    engine = _ovs_engine(runner)
    with pytest.raises(FabricDeployError):
        deploy(engine, plan, topology)
