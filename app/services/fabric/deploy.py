"""NetPulse — Fabric: Deployment Engine sobre OVS (Fases 3 y 4).

Ejecuta el ``FabricPlan`` del Topology Manager sobre Open vSwitch y
Docker: bridges, enlaces troncales con veth pairs y contenedores de
dispositivo conectados por el ``DeviceRuntime`` (§4.2).

Decisión de diseño: OVS directo en vez de Mininet
-------------------------------------------------
El §4.4 del spec propone Mininet como librería. Este engine usa las
mismas primitivas que Mininet invoca por debajo (``ovs-vsctl`` e ``ip``)
porque ``OVSSwitch`` es un wrapper de ``ovs-vsctl`` que exige una sesión
Mininet viva, root y un ciclo de vida de proceso corto; el controlador de
Dystopia es un servicio de larga vida y los tests deben ser deterministas
sin OVS real. Las operaciones de red resultantes son idénticas. El
Protocol ``CommandRunner`` queda inyectable para tests y para sustituir
la ejecución por otra implementación.

Invariante de aislamiento (§9.1)
--------------------------------
Ningún bridge recibe puertos externos: el engine solo añade los extremos
de ``LinkSpec`` (troncales entre switches) y el ``DeviceRuntime`` añade
los puertos de dispositivo con ``tag=<vlan>`` al switch declarado. Sin
uplinks del host.

Orden de despliegue (§8.1/§8.2)
-------------------------------
Deploy: switches → enlaces → dispositivos. Destroy: dispositivos en
orden inverso → enlaces → bridges. Un dispositivo que falla no aborta el
deploy: el resto continúa y el resultado lo reporta en
``containers_failed``; solo se lanza ``FabricDeployError`` si no queda
ningún dispositivo desplegado (un fabric sin dispositivos no es un
despliegue válido).

Idempotencia
------------
Antes de crear se comprueba la existencia (``ovs-vsctl br-exists``,
``ovs-vsctl port-to-br``, ``ip link show``); el ``DeviceRuntime`` recrea
contenedores de forma determinista. ``destroy`` tolera recursos ya
ausentes y no falla por ellos.
"""

import logging
import os
import re
import subprocess
from typing import TYPE_CHECKING, Callable, Optional, Protocol

from pydantic import BaseModel, ConfigDict, Field

from app.services.fabric.controller import FabricPlan
from app.services.fabric.models import FabricTopology
from app.services.fabric.topology import (
    BridgeSpec,
    LinkSpec,
    build_bridge_specs,
    build_device_specs,
    build_link_specs,
)

if TYPE_CHECKING:  # pragma: no cover - solo para tipos
    from app.services.fabric.runtime import DeviceRuntime

logger = logging.getLogger(__name__)

# IFNAMSIZ - 1: límite de Linux para nombres de interfaz (incluye bridges).
_IFNAME_MAX = 15
_IFNAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_CAP_NET_ADMIN = 12


class CommandResult(BaseModel):
    """Resultado de un comando externo."""

    model_config = ConfigDict(frozen=True)

    args: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandError(RuntimeError):
    """El comando externo falló (check=True) o no pudo ejecutarse."""

    def __init__(self, message: str, result: Optional[CommandResult] = None):
        self.result = result
        super().__init__(message)


class FabricDeployError(RuntimeError):
    """Fallo accionable del Deployment Engine.

    Acumula los motivos en ``errors`` (mismo patrón que
    ``FabricValidationError``/``FabricStateError``).
    """

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors) if self.errors else "fallo del deployment engine")


class CommandRunner(Protocol):
    """Ejecutor de comandos inyectable (tests o runtime alternativo)."""

    def run(self, args: list[str], check: bool = True) -> CommandResult:
        """Ejecuta ``args`` sin shell y devuelve el resultado."""


class SubprocessRunner:
    """``CommandRunner`` real basado en ``subprocess.run``.

    No usa shell, captura stdout/stderr y aplica timeout. Con
    ``check=True`` lanza ``CommandError`` si el comando falla, no existe o
    excede el timeout.
    """

    def __init__(self, timeout: float = 30.0):
        self._timeout = timeout

    def run(self, args: list[str], check: bool = True) -> CommandResult:
        try:
            completed = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            result = CommandResult(
                args=list(args), returncode=127, stderr=f"ejecutable no encontrado: {exc}"
            )
            if check:
                raise CommandError(
                    f"No se encontró el ejecutable '{args[0]}': {exc}", result
                ) from exc
            return result
        except subprocess.TimeoutExpired as exc:
            result = CommandResult(
                args=list(args),
                returncode=124,
                stderr=f"timeout tras {self._timeout}s: {exc}",
            )
            if check:
                raise CommandError(
                    f"El comando '{' '.join(args)}' excedió {self._timeout}s", result
                ) from exc
            return result
        except OSError as exc:
            result = CommandResult(
                args=list(args), returncode=126, stderr=f"no se pudo ejecutar: {exc}"
            )
            if check:
                raise CommandError(
                    f"No se pudo ejecutar '{' '.join(args)}': {exc}", result
                ) from exc
            return result

        result = CommandResult(
            args=list(args),
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )
        if check and result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "sin salida"
            raise CommandError(
                f"El comando '{' '.join(args)}' falló (rc={result.returncode}): {detail}",
                result,
            )
        return result


class DeployResult(BaseModel):
    """Resumen estructurado de un deploy (sin credenciales)."""

    bridges_created: list[str] = Field(default_factory=list)
    bridges_existing: list[str] = Field(default_factory=list)
    links_created: list[str] = Field(default_factory=list)
    links_existing: list[str] = Field(default_factory=list)
    containers_created: list[str] = Field(default_factory=list)
    containers_failed: list[dict] = Field(default_factory=list)
    device_ports_created: list[str] = Field(default_factory=list)
    devices: list[dict] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class DestroyResult(BaseModel):
    """Resumen estructurado de un destroy."""

    bridges_removed: list[str] = Field(default_factory=list)
    links_removed: list[str] = Field(default_factory=list)
    containers_removed: list[str] = Field(default_factory=list)
    devices: list[dict] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


def _has_net_admin() -> bool:
    """True si el proceso es root o tiene CAP_NET_ADMIN (Linux)."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() == 0:
        return True
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("CapEff:"):
                    return bool(int(line.split()[1], 16) & (1 << _CAP_NET_ADMIN))
    except (OSError, ValueError, IndexError):
        return False
    return False


def _validate_ifname(name: str, role: str, errors: list[str]) -> None:
    """Valida un nombre de interfaz de Linux (longitud y caracteres)."""
    if not name:
        errors.append(f"El {role} tiene un nombre vacío")
    elif len(name) > _IFNAME_MAX:
        errors.append(
            f"El nombre de {role} '{name}' supera los {_IFNAME_MAX} caracteres de Linux "
            "(IFNAMSIZ); acorta el id en network.yaml"
        )
    elif name.startswith("-"):
        errors.append(
            f"El nombre de {role} '{name}' no puede empezar por '-' (se confundiría "
            "con una opción de ip/ovs-vsctl)"
        )
    elif name in {".", ".."} or not _IFNAME_RE.fullmatch(name):
        errors.append(
            f"El nombre de {role} '{name}' contiene caracteres no válidos "
            "(usa [A-Za-z0-9_.-])"
        )


class OvsFabricEngine:
    """Implementación de ``FabricEngine`` con primitivas OVS/ip.

    El resultado del último deploy queda en ``last_result`` y el del
    último destroy en ``last_destroy_result`` (el Protocol devuelve
    ``None``); el controller/API podrá exponerlos en la Fase 3b.
    """

    kind = "ovs"  # selector de ``DYSTOPIA_FABRIC_ENGINE``

    def __init__(
        self,
        runner: Optional[CommandRunner] = None,
        privilege_check: Optional[Callable[[], bool]] = None,
        device_runtime: Optional["DeviceRuntime"] = None,
    ):
        self._runner: CommandRunner = runner or SubprocessRunner()
        self._privilege_check = privilege_check or _has_net_admin
        if device_runtime is not None:
            self._device_runtime = device_runtime
        else:
            # Import perezoso: runtime importa deploy (CommandRunner), así
            # que no puede ser un import de módulo sin ciclo.
            from app.services.fabric.runtime import DeviceRuntime, DockerCliRuntime

            self._device_runtime = DeviceRuntime(
                DockerCliRuntime(runner=self._runner), runner=self._runner
            )
        self.last_result: Optional[DeployResult] = None
        self.last_destroy_result: Optional[DestroyResult] = None

    @property
    def runner(self) -> CommandRunner:
        """Runner inyectado (lo reutiliza el Lifecycle Manager)."""
        return self._runner

    @property
    def device_runtime(self) -> "DeviceRuntime":
        """Runtime de dispositivos (lo usa el health del controller)."""
        return self._device_runtime

    def check_environment(self) -> list[str]:
        """Errores de entorno (privilegios/herramientas); vacío si todo ok.

        Reutiliza el preflight interno sin mutar el host: es la pieza que
        el Lifecycle Manager agrega en su informe.
        """
        try:
            self._preflight()
            return []
        except FabricDeployError as exc:
            return list(exc.errors)

    # ── FabricEngine ────────────────────────────────────────

    def deploy(self, plan: FabricPlan, topology: FabricTopology) -> None:
        """Crea bridges, enlaces y puertos troncales del plan."""
        self.last_result = None
        self._validate_plan(plan)
        self._preflight()

        result = DeployResult()
        bridges = {bridge.id: bridge for bridge in plan.bridges}

        for bridge in plan.bridges:
            if self._ensure_bridge(bridge):
                result.bridges_created.append(bridge.id)
            else:
                result.bridges_existing.append(bridge.id)

        for link in plan.links:
            if link.from_switch not in bridges or link.to_switch not in bridges:
                raise FabricDeployError([
                    f"El enlace '{link.id}' referencia un switch fuera del plan "
                    f"('{link.from_switch}' → '{link.to_switch}')"
                ])
            if not link.trunk:
                result.warnings.append(
                    f"El enlace '{link.id}' declara trunk=false; el MVP lo configura troncal"
                )
            if self._ensure_link(link, bridges):
                result.links_created.append(link.id)
            else:
                result.links_existing.append(link.id)

        # §8.1: switches → enlaces → dispositivos. Un fallo de dispositivo
        # no aborta el deploy; solo si no queda ninguno desplegado.
        for device in plan.devices:
            outcome = self._device_runtime.deploy_device(device)
            detail = {
                "device_id": device.device_id,
                "container_id": outcome.container_id,
                "pid": outcome.pid,
                "success": outcome.success,
                "step": outcome.error_step or "",
                "error": "; ".join(outcome.errors),
            }
            result.devices.append(detail)
            if outcome.success:
                result.containers_created.append(device.device_id)
                result.device_ports_created.extend(
                    iface.host_veth for iface in device.interfaces
                )
            else:
                result.containers_failed.append({
                    "device_id": device.device_id,
                    "step": detail["step"],
                    "error": detail["error"] or "fallo desconocido",
                })
                result.warnings.append(
                    f"Dispositivo '{device.device_id}' falló "
                    f"({detail['step'] or 'sin paso'}): {detail['error']}"
                )

        if plan.devices and not result.containers_created:
            raise FabricDeployError([
                *result.warnings,
                "Ningún dispositivo del fabric se pudo desplegar",
            ])

        self.last_result = result
        logger.info(
            "[fabric] deploy OVS: %d bridges (%d nuevos), %d enlaces (%d nuevos), "
            "%d contenedores (%d fallidos)",
            len(plan.bridges), len(result.bridges_created),
            len(plan.links), len(result.links_created),
            len(result.containers_created), len(result.containers_failed),
        )

    def destroy(self, topology: FabricTopology) -> None:
        """Elimina puertos, veths y bridges en orden inverso (idempotente)."""
        self.last_destroy_result = None
        plan = FabricPlan(
            bridges=build_bridge_specs(topology),
            links=build_link_specs(topology),
            devices=build_device_specs(topology),
        )
        self._validate_plan(plan)
        self._preflight()

        result = DestroyResult()

        # §8.2: dispositivos en orden inverso → enlaces → bridges.
        for device in reversed(plan.devices):
            outcome = self._device_runtime.destroy_device(device)
            detail = {
                "device_id": device.device_id,
                "container_removed": outcome.container_removed,
                "success": outcome.success,
                "step": outcome.error_step or "",
                "error": "; ".join(outcome.errors),
            }
            result.devices.append(detail)
            result.warnings.extend(outcome.warnings)
            if outcome.success:
                if outcome.container_removed:
                    result.containers_removed.append(device.device_id)
            else:
                result.warnings.append(
                    f"destroy de '{device.device_id}' falló "
                    f"({detail['step'] or 'sin paso'}): {detail['error']}"
                )

        for link in reversed(plan.links):
            removed = False
            for bridge_id, port in (
                (link.from_switch, link.port_from),
                (link.to_switch, link.port_to),
            ):
                if self._exists(["ovs-vsctl", "port-to-br", port]):
                    outcome = self._run(["ovs-vsctl", "del-port", bridge_id, port], check=False)
                    if outcome.returncode != 0:
                        result.warnings.append(self._failure("del-port", outcome))
                    else:
                        removed = True
                if self._exists(["ip", "link", "show", port]):
                    outcome = self._run(["ip", "link", "del", port], check=False)
                    if outcome.returncode != 0:
                        result.warnings.append(self._failure("ip link del", outcome))
                    else:
                        removed = True
            if removed:
                result.links_removed.append(link.id)

        for bridge in reversed(plan.bridges):
            if not self._exists(["ovs-vsctl", "br-exists", bridge.id]):
                continue
            outcome = self._run(["ovs-vsctl", "del-br", bridge.id], check=False)
            if outcome.returncode != 0:
                result.warnings.append(self._failure("del-br", outcome))
            else:
                result.bridges_removed.append(bridge.id)

        self.last_destroy_result = result
        logger.info(
            "[fabric] destroy OVS: %d bridges, %d enlaces, %d contenedores eliminados",
            len(result.bridges_removed), len(result.links_removed),
            len(result.containers_removed),
        )

    # ── Preflight y validación ──────────────────────────────

    def _validate_plan(self, plan: FabricPlan) -> None:
        """Valida nombres antes de tocar el host (falla claro y temprano)."""
        errors: list[str] = []
        for bridge in plan.bridges:
            _validate_ifname(bridge.id, "bridge", errors)
            if not bridge.internal:
                errors.append(
                    f"El bridge '{bridge.id}' no es interno; §9.1 exige bridges sin "
                    "conectividad externa"
                )
            for port in bridge.ports:
                _validate_ifname(port.name, "puerto", errors)
        for link in plan.links:
            _validate_ifname(link.port_from, "puerto de enlace", errors)
            _validate_ifname(link.port_to, "puerto de enlace", errors)
        if errors:
            raise FabricDeployError(errors)

    def _preflight(self) -> None:
        """Comprueba privilegios y herramientas antes de mutar el host."""
        if not self._privilege_check():
            raise FabricDeployError([
                "Se requieren permisos root o CAP_NET_ADMIN para crear bridges y "
                "veths; ejecuta Dystopia con la capability o como root"
            ])
        ovs = self._runner.run(["ovs-vsctl", "--version"], check=False)
        if ovs.returncode != 0:
            detail = ovs.stderr.strip() or ovs.stdout.strip() or "sin salida"
            raise FabricDeployError([
                f"ovs-vsctl no está disponible o no responde ({detail}); "
                "instala openvswitch-switch en Ubuntu 24.04"
            ])
        ip = self._runner.run(["ip", "-V"], check=False)
        if ip.returncode != 0:
            detail = ip.stderr.strip() or ip.stdout.strip() or "sin salida"
            raise FabricDeployError([
                f"El comando 'ip' no está disponible o no responde ({detail}); "
                "instala iproute2"
            ])

    # ── Operaciones OVS ─────────────────────────────────────

    def _ensure_bridge(self, bridge: BridgeSpec) -> bool:
        """Crea el bridge si falta y fija STP. Devuelve si lo creó."""
        exists = self._exists(["ovs-vsctl", "br-exists", bridge.id])
        if not exists:
            self._run(["ovs-vsctl", "add-br", bridge.id])
        self._run([
            "ovs-vsctl", "set", "bridge", bridge.id,
            f"stp_enable={'true' if bridge.stp else 'false'}",
        ])
        return not exists

    def _ensure_link(self, link: LinkSpec, bridges: dict[str, BridgeSpec]) -> bool:
        """Crea el veth pair, lo levanta y lo añade como troncal a ambos bridges."""
        from_exists = self._exists(["ip", "link", "show", link.port_from])
        to_exists = self._exists(["ip", "link", "show", link.port_to])
        if from_exists != to_exists:
            present = link.port_from if from_exists else link.port_to
            raise FabricDeployError([
                f"Estado inconsistente del enlace '{link.id}': solo existe '{present}'; "
                "destruye el fabric y vuelve a desplegar"
            ])

        created = not from_exists
        if created:
            self._run([
                "ip", "link", "add", link.port_from,
                "type", "veth", "peer", "name", link.port_to,
            ])
        self._run(["ip", "link", "set", link.port_from, "up"])
        self._run(["ip", "link", "set", link.port_to, "up"])

        allowed = {
            (link.from_switch, link.port_from),
            (link.to_switch, link.port_to),
        }
        self._ensure_trunk_port(
            link.from_switch, link.port_from, bridges[link.from_switch].vlans, allowed
        )
        self._ensure_trunk_port(
            link.to_switch, link.port_to, bridges[link.to_switch].vlans, allowed
        )
        return created

    def _ensure_trunk_port(
        self,
        bridge_id: str,
        port: str,
        vlans: list[int],
        allowed: set[tuple[str, str]],
    ) -> bool:
        """Añade el puerto al bridge como troncal, si no está ya."""
        if (bridge_id, port) not in allowed:
            raise FabricDeployError([
                f"Aislamiento §9.1: el puerto '{port}' no pertenece a un enlace "
                f"interno del fabric (bridge '{bridge_id}')"
            ])
        current = self._run(["ovs-vsctl", "port-to-br", port], check=False)
        if current.returncode == 0:
            owner = current.stdout.strip()
            if owner != bridge_id:
                raise FabricDeployError([
                    f"El puerto '{port}' ya pertenece al bridge '{owner}', "
                    f"se esperaba '{bridge_id}'"
                ])
            return False

        args = ["ovs-vsctl", "add-port", bridge_id, port]
        if vlans:
            args.append("trunks=" + ",".join(str(vlan) for vlan in vlans))
        self._run(args)
        return True

    # ── Utilidades ──────────────────────────────────────────

    def _run(self, args: list[str], check: bool = True) -> CommandResult:
        """Ejecuta y convierte un fallo en ``FabricDeployError`` accionable."""
        result = self._runner.run(args, check=False)
        if check and result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "sin salida"
            raise FabricDeployError([
                f"El comando '{' '.join(args)}' falló (rc={result.returncode}): {detail}"
            ])
        return result

    def _exists(self, args: list[str]) -> bool:
        return self._run(args, check=False).returncode == 0

    @staticmethod
    def _failure(action: str, result: CommandResult) -> str:
        detail = result.stderr.strip() or result.stdout.strip() or "sin salida"
        return f"{action} falló (rc={result.returncode}): {detail}"

