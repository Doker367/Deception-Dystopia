"""NetPulse — Fabric: Device Runtime de Docker (Fase 4).

Despliega los contenedores de dispositivo del fabric y los conecta a los
bridges OVS siguiendo el §4.2: contenedor ``--network=none``, veth pair,
peer movido al netns del contenedor, configuración dentro del namespace
con ``nsenter`` y extremo del host añadido al bridge con ``tag=<vlan>``.

Decisión de diseño: CLI de Docker, no SDK
----------------------------------------
El control endurecido no incluye el SDK ``docker`` en
``deploy/requirements-control.lock``; añadirlo obligaría a rehacer el lock
con hashes. La CLI es estable, ya es la vía de operación del host y
mantiene el runtime determinista y testeable con ``FakeCommandRunner``.
Toda ejecución pasa por el ``CommandRunner`` de ``deploy.py`` (sin shell).

Hardening (§9.1)
----------------
El contenedor se crea con ``--network none``, ``--read-only``,
``--cap-drop ALL``, ``--security-opt no-new-privileges:true``,
``--pids-limit``, ``--memory``, ``--cpus`` y usuario no root. No se monta
el socket de Docker, no se usa ``--privileged`` ni ``--network host``. El
spec sugiere ``cap_add NET_ADMIN/NET_RAW``; aquí **no** hacen falta porque
la configuración de la interfaz se ejecuta desde el host con ``nsenter``,
no dentro del contenedor.

ARP estático
------------
Se usa ``ip neigh replace <ip> lladdr <mac> dev <iface> nud permanent``
en lugar de ``arp -s``: ``replace`` es idempotente (no falla si la entrada
ya existe) y usa iproute2, ya requerido por el resto del fabric (sin
depender de net-tools).

PID y puerto sin VLAN
---------------------
El PID se obtiene con ``docker inspect -f '{{json .}}'`` y se lee
``State.Pid`` (equivalente al ``-f '{{.State.Pid}}'`` del §4.2, pero en
una sola llamada que también trae estado, imagen y labels). Si la
interfaz no declara ``vlan_tag`` el puerto OVS se añade **sin etiqueta**
(acceso untagged) y se avisa: ``DeviceSpec`` no incluye las VLANs del
switch, así que no se puede construir un trunk correcto aquí.

Idempotencia
------------
Si el contenedor ya existe se **recrea** de forma determinista
(``stop`` + ``rm -f`` + ``create`` + ``start``): el manifiesto puede haber
cambiado (imagen, recursos) y un estado limpio evita netns y veths
colgados. Los veths previos se eliminan antes de recrearlos y el puerto
OVS se re-añade para aplicar la VLAN actual. Un fallo a mitad deja los
recursos para ``destroy_device``/la reconciliación; no se lanzan
excepciones crípticas: el resultado es estructurado por dispositivo.
"""

import json
import logging
import re
from typing import Optional, Protocol

from pydantic import BaseModel, ConfigDict, Field

from app.services.fabric.deploy import (
    CommandResult,
    CommandRunner,
    SubprocessRunner,
)
from app.services.fabric.topology import DeviceSpec, InterfaceSpec

logger = logging.getLogger(__name__)

_IFNAME_MAX = 15
_IFNAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_DEFAULT_PIDS_LIMIT = 64
_DEFAULT_USER = "2000:2000"


class ContainerRuntimeError(RuntimeError):
    """Fallo estructurado de una operación del runtime de contenedores."""

    def __init__(
        self,
        step: str,
        message: str,
        command: Optional[list[str]] = None,
        stderr: str = "",
    ):
        self.step = step
        self.command = list(command or [])
        self.stderr = stderr
        super().__init__(message)


class ContainerInfo(BaseModel):
    """Estado mínimo de un contenedor para el attachment."""

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    pid: int
    state: str
    image: str = ""
    labels: dict[str, str] = Field(default_factory=dict)


class ContainerSpec(BaseModel):
    """Especificación de creación de un contenedor endurecido."""

    model_config = ConfigDict(frozen=True)

    name: str
    image: str
    labels: dict[str, str] = Field(default_factory=dict)
    mem_limit: str = "128m"
    cpus: float = 0.25
    pids_limit: int = _DEFAULT_PIDS_LIMIT
    user: str = _DEFAULT_USER
    network_mode: str = "none"
    read_only: bool = True
    cap_drop: list[str] = Field(default_factory=lambda: ["ALL"])
    security_opts: list[str] = Field(
        default_factory=lambda: ["no-new-privileges:true"]
    )
    command: list[str] = Field(default_factory=list)


class ContainerRuntime(Protocol):
    """Interfaz inyectable del runtime de contenedores."""

    def create(self, spec: ContainerSpec) -> str:
        """Crea el contenedor y devuelve su id."""

    def start(self, container_id: str) -> None:
        """Arranca el contenedor."""

    def stop(self, container_id: str) -> None:
        """Detiene el contenedor."""

    def remove(self, container_id: str) -> None:
        """Elimina el contenedor."""

    def inspect(self, container_id: str) -> Optional[ContainerInfo]:
        """Estado del contenedor; ``None`` si no existe."""

    def exists(self, container_id: str) -> bool:
        """True si el contenedor existe (por id o nombre)."""


class DockerCliRuntime:
    """``ContainerRuntime`` sobre la CLI de Docker y un ``CommandRunner``."""

    def __init__(self, runner: Optional[CommandRunner] = None):
        self._runner: CommandRunner = runner or SubprocessRunner()

    def _run(self, step: str, args: list[str]) -> CommandResult:
        result = self._runner.run(args, check=False)
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "sin salida"
            raise ContainerRuntimeError(
                step, f"{step} falló: {detail}", args, detail
            )
        return result

    def create(self, spec: ContainerSpec) -> str:
        args = ["docker", "create", "--name", spec.name, "--network", spec.network_mode]
        if spec.read_only:
            args.append("--read-only")
        for capability in spec.cap_drop:
            args += ["--cap-drop", capability]
        for option in spec.security_opts:
            args += ["--security-opt", option]
        args += [
            "--pids-limit", str(spec.pids_limit),
            "--memory", spec.mem_limit,
            "--cpus", f"{spec.cpus:g}",
            "--user", spec.user,
        ]
        for key, value in spec.labels.items():
            args += ["--label", f"{key}={value}"]
        args.append(spec.image)
        args += list(spec.command)
        result = self._run("container_create", args)
        container_id = result.stdout.strip()
        if not container_id:
            raise ContainerRuntimeError(
                "container_create", "docker create no devolvió un id", args
            )
        return container_id

    def start(self, container_id: str) -> None:
        self._run("container_start", ["docker", "start", container_id])

    def stop(self, container_id: str) -> None:
        self._run("container_stop", ["docker", "stop", container_id])

    def remove(self, container_id: str) -> None:
        self._run("container_remove", ["docker", "rm", "-f", container_id])

    def exists(self, container_id: str) -> bool:
        result = self._runner.run(
            ["docker", "inspect", "-f", "{{.Id}}", container_id], check=False
        )
        return result.returncode == 0

    def inspect(self, container_id: str) -> Optional[ContainerInfo]:
        args = ["docker", "inspect", "-f", "{{json .}}", container_id]
        result = self._runner.run(args, check=False)
        if result.returncode != 0:
            return None
        try:
            data = json.loads(result.stdout)
            state = data.get("State") or {}
            config = data.get("Config") or {}
            return ContainerInfo(
                id=str(data.get("Id") or container_id),
                name=str(data.get("Name") or "").lstrip("/"),
                pid=int(state.get("Pid") or 0),
                state=str(state.get("Status") or ""),
                image=str(config.get("Image") or ""),
                labels=dict(config.get("Labels") or {}),
            )
        except (TypeError, ValueError) as exc:
            raise ContainerRuntimeError(
                "container_inspect",
                f"no se pudo parsear docker inspect: {exc}",
                args,
                result.stdout[:200],
            ) from exc


class RuntimeStep(BaseModel):
    """Paso del attachment con su comando y stderr (diagnóstico)."""

    name: str
    ok: bool
    command: list[str] = Field(default_factory=list)
    stderr: str = ""


class DeviceRuntimeResult(BaseModel):
    """Resultado estructurado del deploy de un dispositivo."""

    device_id: str
    container_name: str
    success: bool = False
    container_id: str = ""
    pid: int = 0
    steps: list[RuntimeStep] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    error_step: Optional[str] = None


class DeviceDestroyResult(BaseModel):
    """Resultado estructurado del destroy de un dispositivo."""

    device_id: str
    container_name: str
    success: bool = False
    container_removed: bool = False
    ports_removed: list[str] = Field(default_factory=list)
    veths_removed: list[str] = Field(default_factory=list)
    steps: list[RuntimeStep] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    error_step: Optional[str] = None


def _validate_ifname(name: str, role: str, errors: list[str]) -> None:
    if not name:
        errors.append(f"El {role} tiene un nombre vacío")
    elif len(name) > _IFNAME_MAX:
        errors.append(
            f"El nombre de {role} '{name}' supera los {_IFNAME_MAX} caracteres de Linux"
        )
    elif name.startswith("-") or name in {".", ".."} or not _IFNAME_RE.fullmatch(name):
        errors.append(f"El nombre de {role} '{name}' no es válido")


class DeviceRuntime:
    """Attachment de dispositivos al fabric (§4.2) con Docker + OVS."""

    def __init__(
        self,
        runtime: ContainerRuntime,
        runner: Optional[CommandRunner] = None,
        pids_limit: int = _DEFAULT_PIDS_LIMIT,
        user: str = _DEFAULT_USER,
    ):
        self._runtime = runtime
        self._runner: CommandRunner = runner or SubprocessRunner()
        self._pids_limit = pids_limit
        self._user = user

    # ── Deploy ──────────────────────────────────────────────

    def deploy_device(self, spec: DeviceSpec) -> DeviceRuntimeResult:
        """Crea el contenedor, el veth y configura el netns y el puerto OVS."""
        result = DeviceRuntimeResult(
            device_id=spec.device_id, container_name=spec.container_name
        )
        if not spec.interfaces:
            result.errors.append("El dispositivo no declara interfaces")
            return result

        name_errors: list[str] = []
        for iface in spec.interfaces:
            _validate_ifname(iface.host_veth, "puerto del host", name_errors)
            _validate_ifname(iface.peer_veth, "peer del veth", name_errors)
            _validate_ifname(iface.name, "interfaz del contenedor", name_errors)
        if name_errors:
            result.errors.extend(name_errors)
            return result

        container_id, pid = self._prepare_container(spec, result)
        if container_id is None or pid is None:
            return result

        result.container_id = container_id
        result.pid = pid

        for index, iface in enumerate(spec.interfaces):
            if not self._attach_interface(spec, iface, pid, result):
                return result
            if index == 0:
                # Rutas y ARP son del namespace: se aplican una sola vez.
                if not self._configure_routes(spec, pid, result):
                    return result
                if not self._configure_arp(spec, iface, pid, result):
                    return result

        result.success = True
        logger.info(
            "[fabric] dispositivo %s desplegado (container=%s pid=%d)",
            spec.device_id, container_id, pid,
        )
        return result

    def _prepare_container(
        self, spec: DeviceSpec, result: DeviceRuntimeResult
    ) -> tuple[Optional[str], Optional[int]]:
        """Recrea/crea el contenedor y devuelve (id, pid)."""
        try:
            if self._runtime.exists(spec.container_name):
                result.warnings.append(
                    "Contenedor existente recreado de forma determinista"
                )
                self._runtime.stop(spec.container_name)
                self._runtime.remove(spec.container_name)
            result.steps.append(RuntimeStep(name="container_exists", ok=True))

            container_spec = ContainerSpec(
                name=spec.container_name,
                image=spec.image,
                labels=dict(spec.labels),
                mem_limit=spec.mem_limit,
                cpus=spec.cpus,
                pids_limit=self._pids_limit,
                user=self._user,
            )
            container_id = self._runtime.create(container_spec)
            result.steps.append(RuntimeStep(name="container_create", ok=True))
            self._runtime.start(container_id)
            result.steps.append(RuntimeStep(name="container_start", ok=True))
            info = self._runtime.inspect(container_id)
        except ContainerRuntimeError as exc:
            return self._container_failure(result, exc)

        if info is None or info.state != "running" or info.pid <= 0:
            state = info.state if info is not None else "ausente"
            pid = info.pid if info is not None else 0
            result.steps.append(RuntimeStep(name="container_pid", ok=False))
            result.error_step = "container_pid"
            result.errors.append(
                f"PID inválido para '{spec.container_name}' (estado={state}, pid={pid}); "
                "el contenedor debe estar running"
            )
            return None, None

        result.steps.append(RuntimeStep(name="container_pid", ok=True))
        return container_id, info.pid

    def _attach_interface(
        self,
        spec: DeviceSpec,
        iface: InterfaceSpec,
        pid: int,
        result: DeviceRuntimeResult,
    ) -> bool:
        """Crea el veth, lo configura en el netns y lo añade a OVS."""
        if self._ip_exists(iface.host_veth):
            if not self._host(
                result, "veth_cleanup",
                ["ip", "link", "del", iface.host_veth],
            ):
                return False
        if not self._host(
            result, "veth_create",
            ["ip", "link", "add", iface.host_veth,
             "type", "veth", "peer", "name", iface.peer_veth],
        ):
            return False
        if not self._host(
            result, "veth_move",
            ["ip", "link", "set", iface.peer_veth, "netns", str(pid)],
        ):
            return False

        ns = ["nsenter", "-t", str(pid), "-n", "--"]
        if not self._host(
            result, "netns_rename",
            [*ns, "ip", "link", "set", iface.peer_veth, "name", iface.name],
        ):
            return False
        if not self._host(
            result, "netns_mac",
            [*ns, "ip", "link", "set", iface.name, "address", iface.mac],
        ):
            return False
        if not self._host(
            result, "netns_addr",
            [*ns, "ip", "addr", "add", iface.ip, "dev", iface.name],
        ):
            return False
        if not self._host(
            result, "netns_up",
            [*ns, "ip", "link", "set", iface.name, "up"],
        ):
            return False
        if not self._host(
            result, "host_up",
            ["ip", "link", "set", iface.host_veth, "up"],
        ):
            return False
        return self._attach_ovs(iface, result)

    def _attach_ovs(self, iface: InterfaceSpec, result: DeviceRuntimeResult) -> bool:
        """Añade el extremo del host al bridge con tag de acceso."""
        current = self._port_bridge(iface.host_veth)
        if current is not None:
            if not self._host(
                result, "ovs_del_port",
                ["ovs-vsctl", "del-port", current, iface.host_veth],
            ):
                return False
        args = ["ovs-vsctl", "add-port", iface.switch, iface.host_veth]
        if iface.vlan_tag is not None:
            args.append(f"tag={iface.vlan_tag}")
        else:
            result.warnings.append(
                f"La interfaz '{iface.name}' no declara vlan_tag; "
                "el puerto quedará sin etiqueta"
            )
        return self._host(result, "ovs_add_port", args)

    def _configure_routes(
        self,
        spec: DeviceSpec,
        pid: int,
        result: DeviceRuntimeResult,
    ) -> bool:
        ns = ["nsenter", "-t", str(pid), "-n", "--"]
        for route in spec.routes:
            if not self._host(
                result, "netns_route",
                [*ns, "ip", "route", "add", route.destination, "via", route.gateway],
            ):
                return False
        return True

    def _configure_arp(
        self,
        spec: DeviceSpec,
        iface: InterfaceSpec,
        pid: int,
        result: DeviceRuntimeResult,
    ) -> bool:
        ns = ["nsenter", "-t", str(pid), "-n", "--"]
        for neighbor in spec.neighbors:
            if not self._host(
                result, "netns_arp",
                [*ns, "ip", "neigh", "replace", neighbor.ip,
                 "lladdr", neighbor.mac, "dev", iface.name, "nud", "permanent"],
            ):
                return False
        return True

    # ── Destroy ─────────────────────────────────────────────

    def destroy_device(self, spec: DeviceSpec) -> DeviceDestroyResult:
        """Detiene/elimina el contenedor y limpia puertos OVS y veths."""
        result = DeviceDestroyResult(
            device_id=spec.device_id, container_name=spec.container_name
        )
        try:
            if self._runtime.exists(spec.container_name):
                self._runtime.stop(spec.container_name)
                self._runtime.remove(spec.container_name)
                result.container_removed = True
                result.steps.append(RuntimeStep(name="container_remove", ok=True))
            else:
                result.warnings.append(f"Contenedor '{spec.container_name}' ausente")
        except ContainerRuntimeError as exc:
            result.steps.append(RuntimeStep(
                name=exc.step, ok=False, command=exc.command, stderr=exc.stderr
            ))
            result.error_step = exc.step
            result.errors.append(str(exc))

        for iface in spec.interfaces:
            current = self._port_bridge(iface.host_veth)
            if current is not None:
                if self._host(
                    result, "ovs_del_port",
                    ["ovs-vsctl", "del-port", current, iface.host_veth],
                ):
                    result.ports_removed.append(iface.host_veth)
            if self._ip_exists(iface.host_veth):
                if self._host(
                    result, "veth_delete",
                    ["ip", "link", "del", iface.host_veth],
                ):
                    result.veths_removed.append(iface.host_veth)

        result.success = not result.errors
        return result

    # ── Salud ───────────────────────────────────────────────

    def device_health(
        self, spec: DeviceSpec, known_device_ips: Optional[set[str]] = None
    ) -> dict:
        """Contenedor running + puerto OVS + ping a vecinos que son dispositivos.

        ``neighbors`` puede declarar hosts ficticios (gateway, otras estaciones)
        que no existen en el fabric: hacerles ping daría siempre "sin
        respuesta" y marcaría el fabric como no sano. Solo se prueban los
        vecinos cuyo IP pertenece a otro dispositivo real, que el llamante
        pasa en ``known_device_ips`` (IPs sin máscara).
        """
        checks: list[dict] = []
        errors: list[str] = []
        warnings: list[str] = []
        container = {"exists": False, "running": False, "pid": 0, "state": "ausente"}

        try:
            exists = self._runtime.exists(spec.container_name)
            info = self._runtime.inspect(spec.container_name) if exists else None
        except ContainerRuntimeError as exc:
            return {
                "device_id": spec.device_id,
                "healthy": False,
                "runtime_available": False,
                "container": container,
                "interfaces": [],
                "neighbors": [],
                "checks": [{"name": "container", "ok": False, "detail": str(exc)}],
                "errors": [str(exc)],
                "warnings": [],
            }

        if info is not None:
            container = {
                "exists": True,
                "running": info.state == "running" and info.pid > 0,
                "pid": info.pid,
                "state": info.state,
            }
        checks.append({
            "name": "container",
            "ok": container["running"],
            "detail": f"estado={container['state']} pid={container['pid']}",
        })

        interfaces: list[dict] = []
        for iface in spec.interfaces:
            current = self._port_bridge(iface.host_veth)
            present = current == iface.switch
            interfaces.append({
                "name": iface.name,
                "host_veth": iface.host_veth,
                "switch": iface.switch,
                "vlan_tag": iface.vlan_tag,
                "port_present": present,
            })
            checks.append({
                "name": f"port:{iface.host_veth}",
                "ok": present,
                "detail": f"bridge={current or 'ausente'}",
            })

        neighbors: list[dict] = []
        # Solo los vecinos que son dispositivos reales del fabric son
        # verificables; el resto (gateway, hosts ficticios) es informativo.
        probe = [
            neighbor for neighbor in spec.neighbors
            if known_device_ips is not None and neighbor.ip in known_device_ips
        ]
        for neighbor in spec.neighbors:
            if neighbor not in probe:
                neighbors.append({
                    "ip": neighbor.ip,
                    "reachable": None,
                    "note": "vecino declarado sin contenedor propio",
                })
        if container["running"]:
            pid = int(container["pid"])
            for neighbor in probe:
                outcome = self._runner.run(
                    ["nsenter", "-t", str(pid), "-n", "--",
                     "ping", "-c", "1", "-W", "1", neighbor.ip],
                    check=False,
                )
                reachable = outcome.returncode == 0
                neighbors.append({"ip": neighbor.ip, "reachable": reachable})
                checks.append({
                    "name": f"ping:{neighbor.ip}",
                    "ok": reachable,
                    "detail": outcome.stderr.strip() or ("ok" if reachable else "sin respuesta"),
                })
        elif probe:
            warnings.append("Sin contenedor running no se pueden probar los vecinos")

        return {
            "device_id": spec.device_id,
            "healthy": all(check["ok"] for check in checks),
            "runtime_available": True,
            "container": container,
            "interfaces": interfaces,
            "neighbors": neighbors,
            "checks": checks,
            "errors": errors,
            "warnings": warnings,
        }

    # ── Utilidades ──────────────────────────────────────────

    def _host(
        self,
        result: DeviceRuntimeResult | DeviceDestroyResult,
        step: str,
        args: list[str],
    ) -> bool:
        """Ejecuta un comando del host y registra el paso."""
        outcome = self._runner.run(args, check=False)
        if outcome.returncode != 0:
            detail = outcome.stderr.strip() or outcome.stdout.strip() or "sin salida"
            result.steps.append(RuntimeStep(
                name=step, ok=False, command=list(args), stderr=detail
            ))
            result.error_step = step
            result.errors.append(f"{step} falló: {detail}")
            return False
        result.steps.append(RuntimeStep(name=step, ok=True, command=list(args)))
        return True

    def _container_failure(
        self, result: DeviceRuntimeResult, exc: ContainerRuntimeError
    ) -> tuple[None, None]:
        result.steps.append(RuntimeStep(
            name=exc.step, ok=False, command=exc.command, stderr=exc.stderr
        ))
        result.error_step = exc.step
        result.errors.append(str(exc))
        return None, None

    def _ip_exists(self, name: str) -> bool:
        return self._runner.run(["ip", "link", "show", name], check=False).returncode == 0

    def _port_bridge(self, port: str) -> Optional[str]:
        outcome = self._runner.run(["ovs-vsctl", "port-to-br", port], check=False)
        return outcome.stdout.strip() if outcome.returncode == 0 else None
