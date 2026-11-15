"""NetPulse — Fabric: controlador y máquina de estados.

Orquesta Parser → Topology → Deployment Engine y expone las operaciones
que usará la API (Fase 6): estado, validación, deploy, destroy, rebuild,
topología, dispositivos y salud.

La máquina de estados replica el §6.1::

    [*] → disabled | ready | error
    ready → deploying → deployed | error
    deployed → destroying → ready | error
    deployed → deploying            (rebuild)
    error → ready                   (manifiesto corregido + validate)

Las transiciones fuera de ese grafo se rechazan con ``FabricStateError``.
En los estados sin runtime (disabled/ready/error) ``validate()`` vuelve a
aplicar el estado inicial del manifiesto ([*] → …); las flechas estrictas
gobiernan en cuanto hay un despliegue.

El motor real (OVS+Docker) llega en la Fase 3: aquí solo existe el
Protocol ``FabricEngine`` y el stub ``NullFabricEngine``. Nada de Docker,
Mininet ni subprocess en este módulo.

Persistencia: la tabla ``fabric_state`` del §7 vive en la misma SQLite que
la telemetría de deception (``DECEPTION_DB``). Cada transición inserta una
fila con hash del manifiesto y ``topology_json`` **sin credenciales**
(AC13). ``fabric_device_state`` se crea vacía; la llenará el runtime.
"""

import hashlib
import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from app.core.settings import DECEPTION_DB
from app.models.deception import DeceptionNetwork
from app.services.deception import topology_svc
from app.services.fabric.models import FabricTopology
from app.services.fabric.parser import FabricValidationError, parse_manifest
from app.services.fabric.topology import (
    BridgeSpec,
    DeviceSpec,
    LinkSpec,
    build_bridge_specs,
    build_device_specs,
    build_link_specs,
)

logger = logging.getLogger(__name__)

# Ruta de la SQLite del fabric (monkeypatch-able en tests). §7: comparte la
# base de deception para que los eventos y el estado convivan.
DB_PATH = DECEPTION_DB

# Doble gate §9.1: el JWT admin lo valida la API (Fase 6); aquí el entorno.
FABRIC_ENABLE_ENV = "DYSTOPIA_FABRIC_ENABLED"

# Un solo writer a la vez en el proceso (patrón de store_svc/audit_svc).
_write_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS fabric_state (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    state         TEXT    NOT NULL,
    manifest_hash TEXT    NOT NULL,
    topology_json TEXT    NOT NULL,
    error         TEXT    DEFAULT NULL,
    deployed_at   TEXT    DEFAULT NULL,
    destroyed_at  TEXT    DEFAULT NULL
);
CREATE TABLE IF NOT EXISTS fabric_device_state (
    device_id      TEXT    PRIMARY KEY,
    container_id   TEXT,
    container_name TEXT,
    state          TEXT    NOT NULL,
    ip             TEXT,
    mac            TEXT,
    switch_id      TEXT,
    vlan_tag       INTEGER,
    last_health    TEXT,
    error          TEXT    DEFAULT NULL
);
"""


class FabricState(str, Enum):
    """Estados de la máquina del §6.1."""

    DISABLED = "disabled"
    READY = "ready"
    DEPLOYING = "deploying"
    DEPLOYED = "deployed"
    DESTROYING = "destroying"
    ERROR = "error"


# Grafo exacto del §6.1. ``deployed → deploying`` es la flecha del rebuild.
_TRANSITIONS: dict[FabricState, frozenset[FabricState]] = {
    FabricState.DISABLED: frozenset(),
    FabricState.READY: frozenset({FabricState.DEPLOYING}),
    FabricState.DEPLOYING: frozenset({FabricState.DEPLOYED, FabricState.ERROR}),
    FabricState.DEPLOYED: frozenset({FabricState.DESTROYING, FabricState.DEPLOYING}),
    FabricState.DESTROYING: frozenset({FabricState.READY, FabricState.ERROR}),
    FabricState.ERROR: frozenset({FabricState.READY}),
}

# Estados de configuración (sin runtime activo): validate() puede
# re-aplicar el estado inicial del manifiesto entre ellos.
_CONFIG_STATES = frozenset({FabricState.DISABLED, FabricState.READY, FabricState.ERROR})


class FabricStateError(ValueError):
    """Transición u operación inválida para el estado actual.

    Acumula los motivos en ``errors`` (patrón de
    ``FabricValidationError``) y expone el estado en ``state``.
    """

    def __init__(self, errors: list[str], state: str):
        self.errors = list(errors)
        self.state = state
        super().__init__("; ".join(self.errors) if self.errors else "operación inválida")


class FabricPlan(BaseModel):
    """Plan completo de despliegue que consume el motor (Fase 3)."""

    model_config = ConfigDict(frozen=True)

    bridges: list[BridgeSpec] = Field(default_factory=list)
    links: list[LinkSpec] = Field(default_factory=list)
    devices: list[DeviceSpec] = Field(default_factory=list)


@runtime_checkable
class FabricEngine(Protocol):
    """Interfaz del motor de despliegue (implementación real en Fase 3)."""

    def deploy(self, plan: FabricPlan, topology: FabricTopology) -> None:
        """Crea bridges, enlaces y contenedores descritos por ``plan``."""

    def destroy(self, topology: FabricTopology) -> None:
        """Deshace el despliegue de ``topology``."""


class NullFabricEngine:
    """Engine no-op para tests y arranque sin runtime real.

    Simula éxito y registra las llamadas en ``deployed``/``destroyed``.
    ``fail_deploy``/``fail_destroy`` permiten ejercitar las flechas de
    error de la máquina de estados.
    """

    def __init__(self, fail_deploy: bool = False, fail_destroy: bool = False):
        self.fail_deploy = fail_deploy
        self.fail_destroy = fail_destroy
        self.deployed: list[FabricPlan] = []
        self.destroyed: list[FabricTopology] = []

    def deploy(self, plan: FabricPlan, topology: FabricTopology) -> None:
        if self.fail_deploy:
            raise RuntimeError("fallo simulado de deploy")
        self.deployed.append(plan)

    def destroy(self, topology: FabricTopology) -> None:
        if self.fail_destroy:
            raise RuntimeError("fallo simulado de destroy")
        self.destroyed.append(topology)


# ── Helpers ─────────────────────────────────────────────────


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _gate_open() -> bool:
    """True solo si ``DYSTOPIA_FABRIC_ENABLED`` es exactamente ``true``."""
    return os.getenv(FABRIC_ENABLE_ENV, "false").strip().lower() == "true"


def _fabric_enabled_intent(raw: Any) -> bool:
    """Intenta leer ``fabric.enabled`` aunque el resto del bloque sea inválido."""
    fabric = raw.get("fabric") if isinstance(raw, dict) else None
    if not isinstance(fabric, dict):
        return False
    value = fabric.get("enabled", False)
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return bool(value)


def _manifest_hash(raw: Any) -> str:
    """SHA-256 del manifiesto en JSON canónico (claves ordenadas)."""
    if not isinstance(raw, dict):
        return ""
    payload = json.dumps(
        raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _strip_credentials(value: Any) -> Any:
    """Copia recursiva del payload sin credenciales ni contraseñas (AC13)."""
    if isinstance(value, dict):
        return {
            key: _strip_credentials(item)
            for key, item in value.items()
            if key not in {"credentials", "password"}
        }
    if isinstance(value, list):
        return [_strip_credentials(item) for item in value]
    return value


def _collect_warnings(network: DeceptionNetwork, topology: FabricTopology) -> list[str]:
    """Avisos no bloqueantes del manifiesto (el parser solo da errores)."""
    warnings: list[str] = []
    config = topology.config
    if network.fabric is None:
        warnings.append(
            "network.yaml no declara el bloque 'fabric'; el fabric queda deshabilitado"
        )
        return warnings
    if not config.enabled:
        warnings.append(
            "El bloque 'fabric' está presente pero 'enabled' es false; no se desplegará"
        )
        return warnings
    if not config.switches:
        warnings.append("El fabric no declara switches")
    if not config.device_overrides:
        warnings.append("El fabric no declara device_overrides")
    for override in config.device_overrides:
        if not override.interfaces:
            warnings.append(
                f"El device_override '{override.id}' no declara interfaces; "
                "no participa en el fabric runtime"
            )
        for iface in override.interfaces:
            if iface.vlan_tag is None:
                warnings.append(
                    f"La interfaz '{iface.name}' de '{override.id}' no declara "
                    "vlan_tag; el puerto quedará sin etiqueta"
                )
    return warnings


def _build_plan(topology: FabricTopology) -> FabricPlan:
    """Compone los tres planes del Topology Manager en uno solo."""
    return FabricPlan(
        bridges=build_bridge_specs(topology),
        links=build_link_specs(topology),
        devices=build_device_specs(topology),
    )


# ── Controlador ─────────────────────────────────────────────


class FabricController:
    """Orquestador del ciclo de vida del fabric.

    Uso normal: ``get_controller()`` (singleton de módulo). Los tests
    pueden instanciar uno propio con ``db_path`` y ``engine`` aislados.
    """

    def __init__(
        self,
        engine: Optional[FabricEngine] = None,
        db_path: Optional[Path] = None,
        manifest_loader: Optional[Callable[[], dict]] = None,
    ):
        self._engine: FabricEngine = engine if engine is not None else NullFabricEngine()
        self._db_path = Path(db_path) if db_path is not None else DB_PATH
        self._manifest_loader = manifest_loader or self._load_manifest
        self._lock = threading.RLock()
        self._state = FabricState.DISABLED
        self._enabled = False
        self._topology: Optional[FabricTopology] = None
        self._manifest_hash = ""
        self._error: Optional[str] = None
        self._warnings: list[str] = []
        self._deployed_at: Optional[str] = None
        self._destroyed_at: Optional[str] = None
        self._loaded = False

    # ── Carga y validación ──────────────────────────────────

    def _load_manifest(self) -> dict:
        """Manifiesto actual desde ``topology_svc`` (caché por firma)."""
        return topology_svc.load_network().model_dump(mode="json", exclude_none=True)

    def _ensure_loaded(self) -> None:
        with self._lock:
            if self._loaded:
                return
            raw = self._manifest_loader()
            self._evaluate(raw, initial=True, adopt=True)
            self._loaded = True

    def validate(self, manifest: Optional[dict] = None) -> dict:
        """Valida un manifiesto sin desplegar y devuelve errores/warnings.

        ``manifest`` ausente usa el ``network.yaml`` actual. En ``ready``,
        ``disabled`` y ``error`` adopta el manifiesto validado (y aplica la
        flecha ``error → ready`` si corresponde). En ``deployed`` es un
        informe puro: no toca el despliegue en curso. Durante
        ``deploying``/``destroying`` se rechaza.
        """
        with self._lock:
            if not self._loaded:
                raw = manifest if manifest is not None else self._manifest_loader()
                report = self._evaluate(raw, initial=True, adopt=True)
                self._loaded = True
                return report

            state = self._state
            if state in (FabricState.DEPLOYING, FabricState.DESTROYING):
                raise FabricStateError(
                    [f"No se puede validar mientras hay una operación en curso "
                     f"(estado '{state.value}')"],
                    state.value,
                )
            raw = manifest if manifest is not None else self._manifest_loader()
            return self._evaluate(raw, initial=False, adopt=state != FabricState.DEPLOYED)

    def _evaluate(self, raw: dict, *, initial: bool, adopt: bool) -> dict:
        """Valida, aplica el estado resultante (si procede) y persiste."""
        errors: list[str] = []
        warnings: list[str] = []
        topology: Optional[FabricTopology] = None

        try:
            topology = parse_manifest(raw)
        except FabricValidationError as exc:
            errors = list(exc.errors)

        report_hash = _manifest_hash(raw)

        if topology is None:
            if initial:
                enabled_intent = _fabric_enabled_intent(raw)
                self._state = (
                    FabricState.ERROR if enabled_intent else FabricState.DISABLED
                )
                self._enabled = enabled_intent
                self._topology = None
                self._manifest_hash = report_hash
                self._warnings = []
                self._error = "; ".join(errors) or "manifiesto inválido"
                self._persist()
            elif adopt and self._state == FabricState.ERROR:
                # Sigue en error: no hay flecha error → error, pero el
                # mensaje y el hash del manifiesto propuesto se actualizan.
                self._manifest_hash = report_hash
                self._error = "; ".join(errors)
            logger.warning("[fabric] manifiesto inválido: %s", "; ".join(errors))
            return self._report(False, errors, [], report_hash)

        network = DeceptionNetwork.model_validate(raw)
        warnings = _collect_warnings(network, topology)
        enabled = topology.config.enabled

        if initial:
            target = FabricState.READY if enabled else FabricState.DISABLED
            self._state = target
            self._adopt(topology, enabled, warnings, report_hash)
            self._persist()
        elif adopt:
            if self._state == FabricState.ERROR:
                target = FabricState.READY if enabled else FabricState.DISABLED
            elif self._state in _CONFIG_STATES:
                target = FabricState.READY if enabled else FabricState.DISABLED
            else:  # pragma: no cover - deploying/destroying ya se rechazan
                target = self._state
            self._adopt(topology, enabled, warnings, report_hash)
            self._set_config_state(target)
            self._persist()
        # Si no es initial ni adopt (validate mientras deployed), es un
        # informe puro: no se altera el estado ni el manifiesto en curso.

        return self._report(True, [], warnings, report_hash)

    def _adopt(
        self,
        topology: FabricTopology,
        enabled: bool,
        warnings: list[str],
        manifest_hash: str,
    ) -> None:
        self._topology = topology
        self._enabled = enabled
        self._manifest_hash = manifest_hash
        self._warnings = list(warnings)
        self._error = None

    def _report(
        self,
        valid: bool,
        errors: list[str],
        warnings: list[str],
        manifest_hash: str,
    ) -> dict:
        return {
            "valid": valid,
            "state": self._state.value,
            "errors": list(errors),
            "warnings": list(warnings),
            "manifest_hash": manifest_hash,
        }

    def _set_config_state(self, target: FabricState) -> None:
        """Aplica el estado inicial del manifiesto en estados sin runtime.

        ``error → ready`` es una flecha del §6.1; ``disabled ↔ ready``
        re-aplica la flecha de arranque [*] → … cuando no hay despliegue.
        """
        if target == self._state:
            return
        if self._state in _CONFIG_STATES and target in _CONFIG_STATES:
            logger.info("[fabric] %s → %s (manifiesto)", self._state.value, target.value)
            self._state = target
            return
        self._transition(target)

    # ── Operaciones de ciclo de vida ────────────────────────

    def deploy(self) -> dict:
        """Construye y arranca el fabric (idempotente: destruye primero).

        Devuelve ``{"success", "state", "errors", ...}``. El gate de
        entorno cerrado y el manifiesto deshabilitado se devuelven como
        error accionable, no como excepción. Una transición inválida
        (p. ej. desde ``error``) lanza ``FabricStateError``.
        """
        with self._lock:
            self._ensure_loaded()
            state = self._state

            if state == FabricState.DISABLED:
                return self._reject(
                    "El fabric está deshabilitado en el manifiesto "
                    "(fabric.enabled=false); no hay nada que desplegar"
                )
            if not _gate_open():
                return self._reject(
                    "Activación bloqueada: la variable de entorno "
                    f"{FABRIC_ENABLE_ENV} debe ser 'true' (doble gate §9.1)"
                )
            if state == FabricState.ERROR:
                raise FabricStateError(
                    ["No se puede desplegar en estado 'error'; corrija el "
                     "manifiesto y ejecute validate()"],
                    state.value,
                )
            if state in (FabricState.DEPLOYING, FabricState.DESTROYING):
                raise FabricStateError(
                    [f"Hay una operación en curso (estado '{state.value}')"],
                    state.value,
                )
            if state == FabricState.DEPLOYED:
                result = self._destroy_locked()
                if not result["success"]:
                    return result

            return self._deploy_locked()

    def destroy(self) -> dict:
        """Deshace el despliegue. Solo es válido desde ``deployed``."""
        with self._lock:
            self._ensure_loaded()
            if self._state != FabricState.DEPLOYED:
                raise FabricStateError(
                    [f"No hay fabric desplegado (estado '{self._state.value}'); "
                     "destroy solo aplica desde 'deployed'"],
                    self._state.value,
                )
            return self._destroy_locked()

    def rebuild(self) -> dict:
        """Alias destroy+deploy (desde ``deployed``) o deploy (desde ``ready``)."""
        with self._lock:
            self._ensure_loaded()
            if self._state not in (FabricState.READY, FabricState.DEPLOYED):
                raise FabricStateError(
                    [f"rebuild requiere estado 'ready' o 'deployed' "
                     f"(actual '{self._state.value}')"],
                    self._state.value,
                )
            return self.deploy()

    def _deploy_locked(self) -> dict:
        if self._topology is None:
            raise FabricStateError(
                ["No hay topología validada para desplegar"], self._state.value
            )
        plan = _build_plan(self._topology)
        self._transition(FabricState.DEPLOYING)
        self._error = None
        self._persist()

        try:
            self._engine.deploy(plan, self._topology)
        except Exception as exc:  # el engine puede fallar de cualquier forma
            self._error = f"deploy falló: {exc}"
            self._transition(FabricState.ERROR)
            self._persist()
            logger.exception("[fabric] deploy falló")
            return {
                "success": False,
                "state": self._state.value,
                "errors": [self._error],
                "manifest_hash": self._manifest_hash,
            }

        self._deployed_at = _utc_now()
        self._destroyed_at = None
        self._transition(FabricState.DEPLOYED)
        self._persist()
        logger.info("[fabric] desplegado (%d dispositivos)", len(plan.devices))
        return {
            "success": True,
            "state": self._state.value,
            "errors": [],
            "manifest_hash": self._manifest_hash,
            "devices": len(plan.devices),
            "switches": len(plan.bridges),
            "links": len(plan.links),
            "deployed_at": self._deployed_at,
        }

    def _destroy_locked(self) -> dict:
        if self._topology is None:
            raise FabricStateError(
                ["No hay topología validada que destruir"], self._state.value
            )
        self._transition(FabricState.DESTROYING)
        self._error = None
        self._persist()

        try:
            self._engine.destroy(self._topology)
        except Exception as exc:  # el engine puede fallar de cualquier forma
            self._error = f"destroy falló: {exc}"
            self._transition(FabricState.ERROR)
            self._persist()
            logger.exception("[fabric] destroy falló")
            return {
                "success": False,
                "state": self._state.value,
                "errors": [self._error],
                "manifest_hash": self._manifest_hash,
            }

        self._destroyed_at = _utc_now()
        self._deployed_at = None
        self._transition(FabricState.READY)
        self._persist()
        logger.info("[fabric] destruido; estado ready")
        return {
            "success": True,
            "state": self._state.value,
            "errors": [],
            "manifest_hash": self._manifest_hash,
            "destroyed_at": self._destroyed_at,
        }

    def _transition(self, target: FabricState) -> None:
        """Aplica una flecha del grafo o lanza ``FabricStateError``."""
        allowed = _TRANSITIONS[self._state]
        if target not in allowed:
            options = ", ".join(sorted(state.value for state in allowed)) or "ninguna"
            raise FabricStateError(
                [f"Transición inválida '{self._state.value}' → '{target.value}'; "
                 f"desde '{self._state.value}' solo se permite: {options}"],
                self._state.value,
            )
        logger.info("[fabric] %s → %s", self._state.value, target.value)
        self._state = target

    def _reject(self, message: str) -> dict:
        logger.warning("[fabric] %s", message)
        return {
            "success": False,
            "state": self._state.value,
            "errors": [message],
            "manifest_hash": self._manifest_hash,
        }

    # ── Consultas ───────────────────────────────────────────

    def get_status(self) -> dict:
        """Estado actual, gate, hash del manifiesto y conteos del plan."""
        with self._lock:
            self._ensure_loaded()
            topology = self._topology
            devices = build_device_specs(topology) if topology is not None else []
            return {
                "state": self._state.value,
                "enabled": self._enabled,
                "gate_open": _gate_open(),
                "name": topology.config.name if topology is not None else None,
                "manifest_hash": self._manifest_hash,
                "error": self._error,
                "warnings": list(self._warnings),
                "deployed_at": self._deployed_at,
                "destroyed_at": self._destroyed_at,
                "switches": len(topology.config.switches) if topology else 0,
                "links": len(topology.config.links) if topology else 0,
                "devices": len(devices),
            }

    def get_topology(self) -> dict:
        """Topología validada (sin credenciales, AC13); ``{}`` si no hay."""
        with self._lock:
            self._ensure_loaded()
            if self._topology is None:
                return {}
            return _strip_credentials(self._topology.model_dump(mode="json"))

    def get_devices(self) -> list[dict]:
        """Dispositivos planificados para el fabric.

        El estado de runtime (container/salud) llegará con
        ``fabric_device_state`` en la Fase 3/4.
        """
        with self._lock:
            self._ensure_loaded()
            if self._topology is None:
                return []
            return [spec.model_dump() for spec in build_device_specs(self._topology)]

    def get_health(self) -> dict:
        """Salud estructural del fabric.

        Sin runtime todavía no se comprueban contenedores ni reachability:
        ``runtime_available`` es false y la salud se limita a manifiesto y
        estado de la máquina.
        """
        with self._lock:
            self._ensure_loaded()
            topology = self._topology
            manifest_ok = topology is not None and self._error is None
            state_ok = self._state == FabricState.DEPLOYED
            return {
                "healthy": manifest_ok and state_ok,
                "state": self._state.value,
                "gate_open": _gate_open(),
                "manifest_hash": self._manifest_hash,
                "checks": [
                    {
                        "name": "manifest",
                        "ok": manifest_ok,
                        "detail": self._error or "manifiesto validado",
                    },
                    {
                        "name": "state",
                        "ok": state_ok,
                        "detail": self._state.value,
                    },
                ],
                "switches": len(topology.config.switches) if topology else 0,
                "links": len(topology.config.links) if topology else 0,
                "devices": len(build_device_specs(topology)) if topology else 0,
                "runtime_available": False,
            }

    def get_topology_graph(self) -> dict:
        """Grafo ``{nodes, edges, groups}`` para D3/ECharts (§6).

        - Nodos ``switch:<id>`` y ``device:<id>``; los dispositivos se
          agrupan por la VLAN de su interfaz primaria (``vlan-<id>``).
        - Aristas ``trunk`` entre switches y ``access`` switch↔dispositivo,
          con el nombre del puerto OVS.
        - ``groups`` incluye las VLANs de los segmentos y las extra
          declaradas solo en switches, para colorear el diagrama.

        Sin runtime real el estado de las aristas es ``up`` solo cuando la
        máquina está ``deployed``; en el resto, ``down``.
        """
        with self._lock:
            self._ensure_loaded()
            if self._topology is None:
                return {
                    "nodes": [], "edges": [], "groups": [],
                    "state": self._state.value,
                }

            topology = self._topology
            segments = {segment.id: segment for segment in topology.segments}
            roles = {device.id: device.role.value for device in topology.devices}
            segment_by_device = {
                override.id: override.interfaces[0].segment
                for override in topology.config.device_overrides
                if override.interfaces
            }
            devices = build_device_specs(topology)
            edge_state = "up" if self._state == FabricState.DEPLOYED else "down"

            groups: list[dict] = []
            seen_groups: set[str] = set()

            def add_group(group_id: str, label: str, vlan_id: Optional[int],
                          segment_id: Optional[str]) -> None:
                if group_id in seen_groups:
                    return
                seen_groups.add(group_id)
                groups.append({
                    "id": group_id,
                    "label": label,
                    "vlan_id": vlan_id,
                    "segment": segment_id,
                })

            for segment in topology.segments:
                if segment.vlan_id is not None:
                    add_group(
                        f"vlan-{segment.vlan_id}",
                        f"VLAN {segment.vlan_id}",
                        segment.vlan_id,
                        segment.id,
                    )
            extra_vlans = sorted({
                vlan
                for switch in topology.config.switches
                for vlan in switch.vlans
                if f"vlan-{vlan}" not in seen_groups
            })
            for vlan in extra_vlans:
                add_group(f"vlan-{vlan}", f"VLAN {vlan}", vlan, None)

            nodes: list[dict] = []
            for switch in topology.config.switches:
                nodes.append({
                    "id": f"switch:{switch.id}",
                    "label": switch.id,
                    "kind": "switch",
                    "group": "switch",
                    "switch_id": switch.id,
                    "stp": switch.stp,
                    "vlans": list(switch.vlans),
                })

            for spec in devices:
                primary = spec.interfaces[0]
                segment_id = segment_by_device.get(spec.device_id, "")
                segment = segments.get(segment_id)
                if segment is not None and segment.vlan_id is not None:
                    group_id = f"vlan-{segment.vlan_id}"
                else:
                    group_id = f"segment-{segment_id}"
                    add_group(group_id, segment_id, None, segment_id)
                nodes.append({
                    "id": f"device:{spec.device_id}",
                    "label": spec.device_id,
                    "kind": "device",
                    "group": group_id,
                    "device_id": spec.device_id,
                    "container_name": spec.container_name,
                    "role": roles.get(spec.device_id),
                    "segment": segment_id,
                    "switch": primary.switch,
                    "vlan_tag": primary.vlan_tag,
                    "ip": primary.ip,
                    "mac": primary.mac,
                })

            edges: list[dict] = []
            for link in build_link_specs(topology):
                edges.append({
                    "id": link.id,
                    "source": f"switch:{link.from_switch}",
                    "target": f"switch:{link.to_switch}",
                    "kind": "trunk",
                    "label": "trunk",
                    "trunk": link.trunk,
                    "bandwidth": link.bandwidth,
                    "state": edge_state,
                })
            for spec in devices:
                for iface in spec.interfaces:
                    edges.append({
                        "id": f"attach:{spec.device_id}:{iface.name}",
                        "source": f"switch:{iface.switch}",
                        "target": f"device:{spec.device_id}",
                        "kind": "access",
                        "label": f"VLAN {iface.vlan_tag}" if iface.vlan_tag is not None
                                 else "sin etiqueta",
                        "vlan_tag": iface.vlan_tag,
                        "port": iface.host_veth,
                        "state": edge_state,
                    })

            return {
                "nodes": nodes,
                "edges": edges,
                "groups": groups,
                "state": self._state.value,
            }

    # ── Persistencia ────────────────────────────────────────

    def _ensure_db(self) -> None:
        """Crea el directorio/BD y aplica el esquema del §7."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(self._db_path), timeout=10) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.executescript(_SCHEMA)

    def _persist(self) -> None:
        """Inserta una fila de snapshot con el estado actual (sin credenciales)."""
        topology_json = (
            json.dumps(
                _strip_credentials(self._topology.model_dump(mode="json")),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            if self._topology is not None
            else "{}"
        )
        try:
            with _write_lock:
                self._ensure_db()
                with sqlite3.connect(str(self._db_path), timeout=10) as conn:
                    conn.execute(
                        """INSERT INTO fabric_state
                           (state, manifest_hash, topology_json, error,
                            deployed_at, destroyed_at)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (
                            self._state.value,
                            self._manifest_hash,
                            topology_json,
                            self._error,
                            self._deployed_at,
                            self._destroyed_at,
                        ),
                    )
        except sqlite3.Error:
            # El runtime no debe caerse porque falle el histórico; se
            # registra y la operación sigue (patrón de audit_svc).
            logger.exception("[fabric] no se pudo persistir fabric_state")


# ── Singleton de módulo ────────────────────────────────────

_controller: Optional[FabricController] = None
_controller_lock = threading.Lock()


def get_controller() -> FabricController:
    """Instancia compartida del controlador (patrón *_svc del repo)."""
    global _controller
    with _controller_lock:
        if _controller is None:
            _controller = FabricController()
        return _controller


def reset_controller(
    engine: Optional[FabricEngine] = None,
    db_path: Optional[Path] = None,
    manifest_loader: Optional[Callable[[], dict]] = None,
) -> FabricController:
    """(Re)crea el singleton; útil en tests y para inyectar el engine."""
    global _controller
    with _controller_lock:
        _controller = FabricController(
            engine=engine, db_path=db_path, manifest_loader=manifest_loader
        )
        return _controller
