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
(AC13). ``fabric_device_state`` se rellena tras cada deploy/destroy con
engine real (upsert por ``device_id``); con el engine stub los
dispositivos permanecen ``pending``.
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
# Selección del engine: ``stub`` (default) | ``ovs`` (Fase 3).
FABRIC_ENGINE_ENV = "DYSTOPIA_FABRIC_ENGINE"

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

    kind = "stub"  # selector de ``DYSTOPIA_FABRIC_ENGINE``
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


def _default_engine() -> tuple[FabricEngine, str]:
    """Engine por defecto según ``DYSTOPIA_FABRIC_ENGINE``.

    ``stub`` (default) mantiene el comportamiento actual y funciona en
    macOS; ``ovs`` importa perezosamente ``OvsFabricEngine`` para no
    romper entornos sin OVS ni los tests existentes; ``remote`` habla con
    el servicio del host (``DYSTOPIA_FABRIC_REMOTE_URL``/``_TOKEN``) y
    falla accionablemente al construirse si falta la configuración.
    """
    choice = os.getenv(FABRIC_ENGINE_ENV, "stub").strip().lower()
    if choice == "ovs":
        from app.services.fabric.deploy import OvsFabricEngine  # import perezoso

        return OvsFabricEngine(), "ovs"
    if choice == "remote":
        from app.services.fabric.remote_engine import (  # import perezoso
            RemoteFabricEngine,
        )

        return RemoteFabricEngine(), "remote"
    if choice not in {"stub", ""}:
        logger.warning(
            "[fabric] %s=%r no reconocido; se usa el engine stub",
            FABRIC_ENGINE_ENV, choice,
        )
    return NullFabricEngine(), "stub"


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
        self._engine_kind = "custom" if engine is not None else "stub"
        if engine is None:
            self._engine, self._engine_kind = _default_engine()
        self._last_operation: Optional[dict] = None
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
            from app.services.fabric import lifecycle  # import perezoso anti-ciclo

            summary = lifecycle.deploy(self._engine, plan, self._topology)
        except Exception as exc:  # el engine puede fallar de cualquier forma
            self._error = f"deploy falló: {exc}"
            self._transition(FabricState.ERROR)
            self._persist()
            if getattr(self._engine, "kind", "") == "ovs":
                self._persist_device_state(self._error_device_rows(
                    plan, f"deploy falló: {exc}"
                ))
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
        if getattr(self._engine, "kind", "") == "ovs":
            self._persist_device_state(self._deploy_device_rows(plan, summary))
        self._last_operation = {"action": "deploy", "at": self._deployed_at, **summary}
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
            **summary,
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
            from app.services.fabric import lifecycle  # import perezoso anti-ciclo

            summary = lifecycle.destroy(self._engine, self._topology)
        except Exception as exc:  # el engine puede fallar de cualquier forma
            self._error = f"destroy falló: {exc}"
            self._transition(FabricState.ERROR)
            self._persist()
            if getattr(self._engine, "kind", "") == "ovs":
                self._persist_device_state(self._error_device_rows(
                    _build_plan(self._topology), f"destroy falló: {exc}"
                ))
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
        if getattr(self._engine, "kind", "") == "ovs":
            self._persist_device_state(self._destroy_device_rows(
                _build_plan(self._topology), summary
            ))
        self._last_operation = {"action": "destroy", "at": self._destroyed_at, **summary}
        logger.info("[fabric] destruido; estado ready")
        return {
            "success": True,
            "state": self._state.value,
            "errors": [],
            "manifest_hash": self._manifest_hash,
            "destroyed_at": self._destroyed_at,
            **summary,
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
        """Estado actual, gate, hash del manifiesto y conteos del plan.

        Añade ``engine`` (stub/ovs/custom) y ``last_operation`` (resultado
        estructurado del último deploy/destroy) sin alterar los campos
        previos que consume la UI.
        """
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
                "engine": self._engine_kind,
                "last_operation": dict(self._last_operation) if self._last_operation else None,
            }

    def get_last_operation(self) -> dict:
        """Resumen estructurado del último deploy/destroy; ``{}`` si no hay.

        El detalle vive en memoria (no se persiste en ``fabric_state``);
        se reinicia con el proceso.
        """
        with self._lock:
            self._ensure_loaded()
            return dict(self._last_operation) if self._last_operation else {}

    def get_topology(self) -> dict:
        """Topología validada (sin credenciales, AC13); ``{}`` si no hay."""
        with self._lock:
            self._ensure_loaded()
            if self._topology is None:
                return {}
            return _strip_credentials(self._topology.model_dump(mode="json"))

    def get_devices(self) -> list[dict]:
        """Dispositivos planificados para el fabric.

        Con engine real añade ``runtime`` (estado de
        ``fabric_device_state``: running/stopped/error/pending, container,
        última salud y error) sin alterar los campos previos de la UI.
        """
        with self._lock:
            self._ensure_loaded()
            if self._topology is None:
                return []
            states = self._load_device_state()
            out: list[dict] = []
            for spec in build_device_specs(self._topology):
                dump = spec.model_dump()
                row = states.get(spec.device_id)
                dump["runtime"] = {
                    "state": row["state"] if row else "pending",
                    "container_id": row["container_id"] if row else "",
                    "last_health": row["last_health"] if row else None,
                    "error": row["error"] if row else None,
                }
                out.append(dump)
            return out

    def get_health(self) -> dict:
        """Salud del fabric.

        Con el engine stub mantiene el informe estructural previo
        (``runtime_available=false``). Con el engine OVS delega en
        ``lifecycle.health`` y agrega el detalle de runtime en ``runtime``
        (bridges/links/devices/extra_ports) más ``devices_health`` (salud
        por dispositivo: contenedor, puerto OVS y reachability), sin
        quitar campos.
        """
        with self._lock:
            self._ensure_loaded()
            topology = self._topology
            manifest_ok = topology is not None and self._error is None
            state_ok = self._state == FabricState.DEPLOYED
            checks = [
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
            ]
            runtime: Optional[dict] = None
            devices_health: list[dict] = []
            runtime_available = False
            if getattr(self._engine, "kind", "") == "ovs" and topology is not None:
                from app.services.fabric import lifecycle  # import perezoso anti-ciclo

                runtime = lifecycle.health(engine=self._engine, topology=topology)
                runtime_available = bool(runtime.get("runtime_available"))
                checks.extend(runtime.get("checks", []))
                device_runtime = getattr(self._engine, "device_runtime", None)
                health_fn = getattr(device_runtime, "device_health", None)
                if health_fn is not None:
                    devices_health = [
                        health_fn(spec) for spec in build_device_specs(topology)
                    ]
            elif getattr(self._engine, "kind", "") == "remote":
                # El runtime vive en el host: su /health es la fuente de verdad.
                remote_health = getattr(self._engine, "health", None)
                if remote_health is not None:
                    try:
                        runtime = remote_health()
                    except Exception as exc:  # noqa: BLE001 - se reporta, no se propaga
                        logger.warning("[fabric] health remoto no disponible: %s", exc)
                        runtime = None
                    if runtime is not None:
                        runtime_available = bool(runtime.get("runtime_available"))
                        checks.extend(runtime.get("checks", []))
                        devices_health = list(runtime.get("devices_health") or [])
            healthy = manifest_ok and state_ok
            if runtime is not None:
                healthy = healthy and bool(runtime.get("healthy"))
            if devices_health:
                healthy = healthy and all(
                    bool(device.get("healthy")) for device in devices_health
                )
            return {
                "healthy": healthy,
                "state": self._state.value,
                "gate_open": _gate_open(),
                "manifest_hash": self._manifest_hash,
                "checks": checks,
                "switches": len(topology.config.switches) if topology else 0,
                "links": len(topology.config.links) if topology else 0,
                "devices": len(build_device_specs(topology)) if topology else 0,
                "runtime_available": runtime_available,
                "devices_health": devices_health,
                "runtime": runtime,
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

    # ── Estado por dispositivo (fabric_device_state, §7) ────

    def _device_rows(
        self,
        plan: FabricPlan,
        summary: dict,
        *,
        running_state: str,
    ) -> list[dict]:
        """Filas de ``fabric_device_state`` desde el detalle del engine."""
        detail_by_device = {
            device.get("device_id"): device for device in summary.get("devices", [])
        }
        now = _utc_now()
        rows: list[dict] = []
        for spec in plan.devices:
            detail = detail_by_device.get(spec.device_id, {})
            ok = bool(detail.get("success"))
            iface = spec.interfaces[0] if spec.interfaces else None
            rows.append({
                "device_id": spec.device_id,
                "container_id": str(detail.get("container_id") or ""),
                "container_name": spec.container_name,
                "state": running_state if ok else "error",
                "ip": iface.ip if iface else "",
                "mac": iface.mac if iface else "",
                "switch_id": iface.switch if iface else "",
                "vlan_tag": iface.vlan_tag if iface else None,
                "last_health": now if ok else None,
                "error": detail.get("error") or None,
            })
        return rows

    def _deploy_device_rows(self, plan: FabricPlan, summary: dict) -> list[dict]:
        return self._device_rows(plan, summary, running_state="running")

    def _destroy_device_rows(self, plan: FabricPlan, summary: dict) -> list[dict]:
        return self._device_rows(plan, summary, running_state="stopped")

    def _error_device_rows(self, plan: FabricPlan, message: str) -> list[dict]:
        """Tras un fallo global, todos los dispositivos planificados en error."""
        return [{
            "device_id": spec.device_id,
            "container_id": "",
            "container_name": spec.container_name,
            "state": "error",
            "ip": spec.interfaces[0].ip if spec.interfaces else "",
            "mac": spec.interfaces[0].mac if spec.interfaces else "",
            "switch_id": spec.interfaces[0].switch if spec.interfaces else "",
            "vlan_tag": spec.interfaces[0].vlan_tag if spec.interfaces else None,
            "last_health": None,
            "error": message,
        } for spec in plan.devices]

    def _persist_device_state(self, rows: list[dict]) -> None:
        """Upsert de ``fabric_device_state`` por ``device_id`` (§7)."""
        if not rows:
            return
        try:
            with _write_lock:
                self._ensure_db()
                with sqlite3.connect(str(self._db_path), timeout=10) as conn:
                    conn.executemany(
                        """INSERT INTO fabric_device_state
                           (device_id, container_id, container_name, state, ip,
                            mac, switch_id, vlan_tag, last_health, error)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                           ON CONFLICT(device_id) DO UPDATE SET
                             container_id=excluded.container_id,
                             container_name=excluded.container_name,
                             state=excluded.state,
                             ip=excluded.ip,
                             mac=excluded.mac,
                             switch_id=excluded.switch_id,
                             vlan_tag=excluded.vlan_tag,
                             last_health=excluded.last_health,
                             error=excluded.error""",
                        [(
                            row["device_id"], row["container_id"],
                            row["container_name"], row["state"], row["ip"],
                            row["mac"], row["switch_id"], row["vlan_tag"],
                            row["last_health"], row["error"],
                        ) for row in rows],
                    )
        except sqlite3.Error:
            logger.exception("[fabric] no se pudo persistir fabric_device_state")

    def _load_device_state(self) -> dict[str, dict]:
        """Estado runtime por device_id; ``{}`` si no hay tabla/datos."""
        if not self._db_path.exists():
            return {}
        try:
            with sqlite3.connect(str(self._db_path), timeout=10) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT * FROM fabric_device_state").fetchall()
                return {row["device_id"]: dict(row) for row in rows}
        except sqlite3.Error:
            logger.exception("[fabric] no se pudo leer fabric_device_state")
            return {}


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
