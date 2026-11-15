"""NetPulse — Fabric: Lifecycle Manager (Fase 3b).

Orquesta el ciclo de vida del fabric sobre el engine inyectado:
preflight agregado, salud contra el estado real de OVS, reconciliación
de huérfanos y wrappers deploy/destroy/rebuild que devuelven un
resultado estructurado.

Reglas:

- ``preflight`` reutiliza el preflight del engine
  (``OvsFabricEngine.check_environment``) en vez de duplicarlo; con el
  engine stub solo comprueba el manifiesto.
- ``health`` compara lo esperado (``FabricTopology`` → plan) contra el
  estado real de OVS. Los puertos de dispositivo son informativos (los
  contenedores llegan en la Fase 4) y no afectan a ``healthy``; los
  bridges y enlaces troncales sí.
- ``reconcile`` detecta recursos huérfanos con una heurística
  documentada: bridges que no están en el manifiesto pero contienen
  puertos con prefijo de fabric (``lk*``/``dv*``), y veths con esos
  prefijos que ya no pertenecen al plan. ``cleanup_orphans`` los elimina
  de forma explícita y registrada (el audit trail de ``audit_svc``
  llega en la Fase 8).
- Los wrappers de ciclo de vida no capturan excepciones: el engine puede
  fallar y el controller decide la transición de la máquina de estados.
"""

import logging
from typing import Optional

from app.services.fabric.controller import FabricPlan
from app.services.fabric.deploy import (
    CommandRunner,
    OvsFabricEngine,
    SubprocessRunner,
)
from app.services.fabric.models import FabricTopology
from app.services.fabric.parser import FabricValidationError, load_topology
from app.services.fabric.topology import (
    build_bridge_specs,
    build_device_specs,
    build_link_specs,
)

logger = logging.getLogger(__name__)

# Prefijos que el Topology Manager usa para veths del fabric; la
# heurística de huérfanos se apoya en ellos (nombres generados, no del host).
_FABRIC_PORT_PREFIXES = ("lk", "dv")
_DEVICE_NOTE = "Los contenedores de dispositivo se despliegan en la Fase 4"


def engine_name(engine) -> str:
    """Nombre del engine para resultados y logs."""
    return type(engine).__name__


def _plan_from(topology: FabricTopology) -> FabricPlan:
    """Planes del Topology Manager compuestos en un ``FabricPlan``."""
    return FabricPlan(
        bridges=build_bridge_specs(topology),
        links=build_link_specs(topology),
        devices=build_device_specs(topology),
    )


def _safe_topology() -> Optional[FabricTopology]:
    """Topología del manifiesto actual; ``None`` si es inválida."""
    try:
        return load_topology()
    except FabricValidationError as exc:
        logger.warning("[fabric] topología inválida para lifecycle: %s", exc)
        return None


def _engine_runner(engine) -> Optional[CommandRunner]:
    """Runner del engine si lo expone (``OvsFabricEngine``)."""
    runner = getattr(engine, "runner", None)
    return runner if runner is not None else None


# ── Preflight ───────────────────────────────────────────────


def preflight(engine=None, runner: Optional[CommandRunner] = None) -> dict:
    """Comprobaciones agregadas antes de operar el fabric.

    - Herramientas y privilegios: delega en el preflight del engine OVS
      (``check_environment``) cuando hay runner/engine real; con el stub
      queda como aviso, no como error.
    - Manifiesto: ``load_topology()`` valida el ``network.yaml`` actual.

    Devuelve ``{"ok", "checks", "errors", "warnings"}``.
    """
    checks: list[dict] = []
    errors: list[str] = []
    warnings: list[str] = []

    ovs_engine = engine if isinstance(engine, OvsFabricEngine) else None
    if ovs_engine is None and runner is not None:
        ovs_engine = OvsFabricEngine(runner=runner)

    if ovs_engine is not None:
        environment_errors = ovs_engine.check_environment()
        errors.extend(environment_errors)
        checks.append({
            "name": "runtime",
            "ok": not environment_errors,
            "detail": "root/CAP_NET_ADMIN, ovs-vsctl e ip disponibles"
                      if not environment_errors else "; ".join(environment_errors),
        })
    else:
        warnings.append(
            "El engine activo es el stub: no se comprueba runtime OVS ni permisos"
        )
        checks.append({"name": "runtime", "ok": True, "detail": "stub (sin comprobaciones)"})

    try:
        topology = load_topology()
        detail = "fabric habilitado" if topology.config.enabled else "fabric deshabilitado"
        checks.append({"name": "manifiesto", "ok": True, "detail": detail})
        if not topology.config.enabled:
            warnings.append("fabric.enabled=false: el deploy será rechazado por el controller")
    except FabricValidationError as exc:
        errors.extend(exc.errors)
        checks.append({
            "name": "manifiesto",
            "ok": False,
            "detail": "; ".join(exc.errors) or "manifiesto inválido",
        })

    return {"ok": not errors, "checks": checks, "errors": errors, "warnings": warnings}


# ── Salud contra OVS real ───────────────────────────────────


def health(
    engine=None,
    runner: Optional[CommandRunner] = None,
    topology: Optional[FabricTopology] = None,
) -> dict:
    """Salud del fabric comparando el plan esperado con el estado real de OVS.

    Sin OVS disponible devuelve ``runtime_available=false`` (y
    ``healthy=false``: la salud no es verificable). Los dispositivos son
    informativos en la Fase 3; los bridges y enlaces troncales sí
    determinan ``healthy``.
    """
    topo = topology if topology is not None else _safe_topology()
    if topo is None:
        return {
            "healthy": False,
            "runtime_available": False,
            "checks": [{"name": "manifiesto", "ok": False,
                        "detail": "el manifiesto actual no es válido"}],
            "bridges": {"expected": [], "present": [], "missing": []},
            "links": {"expected": [], "present": [], "missing": []},
            "devices": {"expected": [], "present": [], "missing": [], "note": _DEVICE_NOTE},
            "extra_ports": [],
            "errors": ["No hay una topología válida que comprobar"],
            "warnings": [],
        }

    plan = _plan_from(topo)
    active_runner = runner or _engine_runner(engine) or SubprocessRunner()
    ovs = active_runner.run(["ovs-vsctl", "--version"], check=False)
    runtime_available = ovs.returncode == 0

    errors: list[str] = []
    warnings: list[str] = []
    checks = [{
        "name": "ovs",
        "ok": runtime_available,
        "detail": "ovs-vsctl responde" if runtime_available else "ovs-vsctl no disponible",
    }]

    expected_bridges = [bridge.id for bridge in plan.bridges]
    expected_link_ids = [link.id for link in plan.links]
    device_ports_expected = {
        iface.host_veth: iface.switch for spec in plan.devices for iface in spec.interfaces
    }

    if not runtime_available:
        warnings.append("Sin OVS no se puede verificar el runtime del fabric")
        return {
            "healthy": False,
            "runtime_available": False,
            "checks": checks,
            "bridges": {"expected": expected_bridges, "present": [], "missing": expected_bridges},
            "links": {"expected": expected_link_ids, "present": [], "missing": expected_link_ids},
            "devices": {
                "expected": sorted(device_ports_expected),
                "present": [],
                "missing": sorted(device_ports_expected),
                "note": _DEVICE_NOTE,
            },
            "extra_ports": [],
            "errors": errors,
            "warnings": warnings,
        }

    bridge_ports: dict[str, set[str]] = {}
    present_bridges: list[str] = []
    missing_bridges: list[str] = []
    for bridge_id in expected_bridges:
        if active_runner.run(["ovs-vsctl", "br-exists", bridge_id], check=False).returncode == 0:
            present_bridges.append(bridge_id)
            listing = active_runner.run(["ovs-vsctl", "list-ports", bridge_id], check=False)
            if listing.returncode == 0:
                bridge_ports[bridge_id] = set(listing.stdout.split())
            else:
                bridge_ports[bridge_id] = set()
                warnings.append(f"list-ports falló para el bridge '{bridge_id}'")
        else:
            missing_bridges.append(bridge_id)
            bridge_ports[bridge_id] = set()
    checks.append({
        "name": "bridges",
        "ok": not missing_bridges,
        "detail": f"{len(present_bridges)}/{len(expected_bridges)} bridges presentes",
    })

    present_links: list[str] = []
    missing_links: list[str] = []
    for link in plan.links:
        attached = (
            link.port_from in bridge_ports.get(link.from_switch, set())
            and link.port_to in bridge_ports.get(link.to_switch, set())
        )
        (present_links if attached else missing_links).append(link.id)
    checks.append({
        "name": "links",
        "ok": not missing_links,
        "detail": f"{len(present_links)}/{len(expected_link_ids)} enlaces troncales activos",
    })

    present_devices: list[str] = []
    missing_devices: list[str] = []
    for port in sorted(device_ports_expected):
        if active_runner.run(["ip", "link", "show", port], check=False).returncode == 0:
            present_devices.append(port)
        else:
            missing_devices.append(port)
    checks.append({
        "name": "devices",
        "ok": True,  # informativo en Fase 3: no afecta a healthy
        "detail": f"{len(present_devices)} interfaces presentes · "
                  f"{len(missing_devices)} pendientes",
    })

    expected_all = set(device_ports_expected) | {
        port for link in plan.links for port in (link.port_from, link.port_to)
    }
    extra_ports = sorted({
        port
        for ports in bridge_ports.values()
        for port in ports
        if port not in expected_all
    })
    if extra_ports:
        warnings.append(f"Puertos no declarados en bridges del fabric: {', '.join(extra_ports)}")

    return {
        "healthy": not missing_bridges and not missing_links and not errors,
        "runtime_available": True,
        "checks": checks,
        "bridges": {
            "expected": expected_bridges,
            "present": present_bridges,
            "missing": missing_bridges,
        },
        "links": {
            "expected": expected_link_ids,
            "present": present_links,
            "missing": missing_links,
        },
        "devices": {
            "expected": sorted(device_ports_expected),
            "present": present_devices,
            "missing": missing_devices,
            "note": _DEVICE_NOTE,
        },
        "extra_ports": extra_ports,
        "errors": errors,
        "warnings": warnings,
    }


# ── Reconciliación de huérfanos ─────────────────────────────


def _iface_names(output: str) -> list[str]:
    """Nombres de interfaz desde ``ip -o link show`` (sin sufijos @peer)."""
    names: list[str] = []
    for line in output.splitlines():
        parts = line.split(":", 2)
        if len(parts) < 2:
            continue
        name = parts[1].strip().split("@", 1)[0]
        if name:
            names.append(name)
    return names


def reconcile(
    runner: Optional[CommandRunner] = None,
    topology: Optional[FabricTopology] = None,
) -> dict:
    """Detecta recursos huérfanos del fabric sin modificar nada.

    Heurística documentada: un bridge es huérfano si no está en el
    manifiesto pero contiene puertos con prefijo de fabric (``lk*``/``dv*``);
    un veth del host es huérfano si tiene ese prefijo y ya no pertenece al
    plan. Los bridges sin puertos de fabric no se tocan (pueden ser del
    operador).
    """
    active_runner = runner or SubprocessRunner()
    topo = topology if topology is not None else _safe_topology()
    plan = _plan_from(topo) if topo is not None else FabricPlan()
    expected_bridges = {bridge.id for bridge in plan.bridges}
    expected_ports = {
        port for link in plan.links for port in (link.port_from, link.port_to)
    } | {iface.host_veth for spec in plan.devices for iface in spec.interfaces}

    listing = active_runner.run(["ovs-vsctl", "list-br"], check=False)
    if listing.returncode != 0:
        return {
            "ok": False,
            "runtime_available": False,
            "orphans": {"bridges": [], "veths": []},
            "errors": ["ovs-vsctl no disponible; no se puede auditar el host"],
            "warnings": [],
        }

    errors: list[str] = []
    warnings: list[str] = []
    orphan_bridges: list[dict] = []
    for bridge in listing.stdout.split():
        if bridge in expected_bridges:
            continue
        ports_out = active_runner.run(["ovs-vsctl", "list-ports", bridge], check=False)
        ports = ports_out.stdout.split() if ports_out.returncode == 0 else []
        fabric_ports = sorted(p for p in ports if p.startswith(_FABRIC_PORT_PREFIXES))
        if fabric_ports:
            orphan_bridges.append({"bridge": bridge, "ports": fabric_ports})

    orphan_veths: list[str] = []
    links_out = active_runner.run(["ip", "-o", "link", "show"], check=False)
    if links_out.returncode == 0:
        orphan_veths = sorted(
            name for name in _iface_names(links_out.stdout)
            if name.startswith(_FABRIC_PORT_PREFIXES) and name not in expected_ports
        )
    else:
        warnings.append("ip -o link show falló; no se auditaron los veths del host")

    return {
        "ok": not errors,
        "runtime_available": True,
        "orphans": {"bridges": orphan_bridges, "veths": orphan_veths},
        "errors": errors,
        "warnings": warnings,
    }


def cleanup_orphans(
    runner: Optional[CommandRunner] = None,
    topology: Optional[FabricTopology] = None,
) -> dict:
    """Elimina los huérfanos que ``reconcile`` detecta, de forma explícita.

    Cada eliminación se registra en el log (el audit trail de
    ``audit_svc`` se cablea en la Fase 8). Un fallo al borrar no aborta el
    resto: se acumula en ``warnings``.
    """
    active_runner = runner or SubprocessRunner()
    report = reconcile(runner=active_runner, topology=topology)
    warnings = list(report.get("warnings", []))
    errors = list(report.get("errors", []))

    if not report.get("runtime_available"):
        return {
            "ok": False,
            "runtime_available": False,
            "removed": {"bridges": [], "veths": []},
            "warnings": warnings,
            "errors": errors,
        }

    removed_bridges: list[str] = []
    removed_veths: list[str] = []
    for orphan in report["orphans"]["bridges"]:
        bridge = orphan["bridge"]
        outcome = active_runner.run(["ovs-vsctl", "del-br", bridge], check=False)
        if outcome.returncode == 0:
            removed_bridges.append(bridge)
            logger.info("[fabric] huérfano eliminado: bridge '%s'", bridge)
        else:
            detail = outcome.stderr.strip() or outcome.stdout.strip() or "sin salida"
            warnings.append(f"del-br '{bridge}' falló (rc={outcome.returncode}): {detail}")

    for veth in report["orphans"]["veths"]:
        outcome = active_runner.run(["ip", "link", "del", veth], check=False)
        if outcome.returncode == 0:
            removed_veths.append(veth)
            logger.info("[fabric] huérfano eliminado: veth '%s'", veth)
        else:
            detail = outcome.stderr.strip() or outcome.stdout.strip() or "sin salida"
            warnings.append(f"ip link del '{veth}' falló (rc={outcome.returncode}): {detail}")

    return {
        "ok": not errors,
        "runtime_available": True,
        "removed": {"bridges": removed_bridges, "veths": removed_veths},
        "warnings": warnings,
        "errors": errors,
    }


# ── Orquestación del ciclo de vida ──────────────────────────


def deploy(engine, plan: FabricPlan, topology: FabricTopology) -> dict:
    """Ejecuta el deploy del engine y devuelve el resultado estructurado.

    Las excepciones del engine se propagan: el controller decide la
    transición de la máquina de estados.
    """
    engine.deploy(plan, topology)
    summary: dict = {"engine": engine_name(engine)}
    last = getattr(engine, "last_result", None)
    if last is not None:
        summary.update(last.model_dump())
    return summary


def destroy(engine, topology: FabricTopology) -> dict:
    """Ejecuta el destroy del engine y devuelve el resultado estructurado."""
    engine.destroy(topology)
    summary: dict = {"engine": engine_name(engine)}
    last = getattr(engine, "last_destroy_result", None)
    if last is not None:
        summary.update(last.model_dump())
    return summary


def rebuild(engine, plan: FabricPlan, topology: FabricTopology) -> dict:
    """Destroy + deploy en un solo paso (idempotente)."""
    destroyed = destroy(engine, topology)
    deployed = deploy(engine, plan, topology)
    return {
        "engine": deployed.get("engine", engine_name(engine)),
        "destroy": destroyed,
        "deploy": deployed,
        "warnings": [
            *destroyed.get("warnings", []),
            *deployed.get("warnings", []),
        ],
    }
