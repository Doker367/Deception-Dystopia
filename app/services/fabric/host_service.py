"""NetPulse — Fabric: servicio del host (Fase 4c).

El control de Dystopia corre en un contenedor endurecido sin acceso a
OVS/Docker. El fabric real se ejecuta como **servicio del host**
(systemd) con los privilegios necesarios; el control le habla por la red
local con un token bearer.

Esta aplicación FastAPI es independiente: **no** se monta en
``app.main``. Expone el ciclo de vida mínimo que consume el control:

- ``POST /deploy``   → switches → enlaces → dispositivos (``OvsFabricEngine``)
- ``POST /destroy``  → orden inverso, idempotente
- ``GET  /status``   → estado del servicio y del último deploy/destroy
- ``GET  /health``   → salud del runtime (bridges/enlaces/dispositivos)

Seguridad:

- ``DYSTOPIA_FABRIC_TOKEN`` (≥ 32 caracteres) obligatorio: sin token el
  servicio **no arranca** (fail-closed). Comparación en tiempo constante.
- Bind ``127.0.0.1`` por defecto; nunca ``0.0.0.0`` salvo elección
  explícita del operador (se avisa en el log).
- Un solo deploy/destroy concurrente (lock de proceso → 409).
- Las respuestas no incluyen credenciales del manifiesto (AC13); el token
  nunca se registra en logs.

Arranque: ``python -m app.services.fabric.host_service`` (ver
``deploy/systemd/dystopia-fabric.service``).
"""

import asyncio
import hashlib
import logging
import os
import secrets
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml
from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    WebSocket,
)

from app.services.fabric.console_svc import (
    ERROR_PREFIX,
    console_enabled,
    console_service,
)
from app.services.fabric.controller import FabricPlan
from app.services.fabric.deploy import FabricDeployError, OvsFabricEngine
from app.services.fabric.models import FabricTopology
from app.services.fabric.parser import FabricValidationError, parse_manifest
from app.services.fabric.topology import (
    build_bridge_specs,
    build_device_specs,
    build_link_specs,
)

logger = logging.getLogger(__name__)

TOKEN_ENV = "DYSTOPIA_FABRIC_TOKEN"
MANIFEST_ENV = "DYSTOPIA_FABRIC_MANIFEST"
BIND_ENV = "DYSTOPIA_FABRIC_BIND"
PORT_ENV = "DYSTOPIA_FABRIC_PORT"
EVENTS_URL_ENV = "DYSTOPIA_FABRIC_EVENTS_URL"
EVENTS_INTERVAL_ENV = "DYSTOPIA_FABRIC_EVENTS_INTERVAL"
EVENTS_ENABLED_ENV = "DYSTOPIA_FABRIC_EVENTS_ENABLED"
DEVICES_DIR_ENV = "DYSTOPIA_FABRIC_DEVICES_DIR"
TLS_CERT_ENV = "DYSTOPIA_FABRIC_TLS_CERT"
TLS_KEY_ENV = "DYSTOPIA_FABRIC_TLS_KEY"

DEFAULT_MANIFEST = "config/deception/network.yaml"
DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 8090
DEFAULT_DEVICES_DIR = "/var/lib/dystopia/fabric/logs"
DEFAULT_EVENTS_URL = "http://127.0.0.1:8082/api/fabric/events"
DEFAULT_EVENTS_INTERVAL = 5.0
MIN_TOKEN_LENGTH = 32
SERVICE_NAME = "dystopia-fabric"

router = APIRouter()


class HostServiceConfigError(RuntimeError):
    """Configuración inválida del servicio del host (fail-closed)."""


@dataclass(frozen=True)
class HostServiceSettings:
    """Configuración inmutable del servicio (sin secretos en logs)."""

    token: str
    manifest: Path
    bind: str = DEFAULT_BIND
    port: int = DEFAULT_PORT
    # Forwarder de eventos del agente → control (Fase 5b).
    events_url: str = DEFAULT_EVENTS_URL
    events_interval: float = DEFAULT_EVENTS_INTERVAL
    events_enabled: bool = True
    devices_dir: Path = Path(DEFAULT_DEVICES_DIR)
    # TLS opcional del servicio (cert+clave). Ambos o ninguno.
    tls_cert: Optional[Path] = None
    tls_key: Optional[Path] = None

    @property
    def tls(self) -> bool:
        return self.tls_cert is not None and self.tls_key is not None


def load_settings() -> HostServiceSettings:
    """Lee la configuración del entorno; falla cerrado si falta el token."""
    token = os.getenv(TOKEN_ENV, "")
    if len(token) < MIN_TOKEN_LENGTH:
        raise HostServiceConfigError(
            f"{TOKEN_ENV} debe existir y tener al menos {MIN_TOKEN_LENGTH} "
            "caracteres; el servicio no arranca sin token (fail-closed)"
        )
    manifest = Path(os.getenv(MANIFEST_ENV, DEFAULT_MANIFEST))
    bind = os.getenv(BIND_ENV, DEFAULT_BIND).strip() or DEFAULT_BIND
    raw_port = os.getenv(PORT_ENV, str(DEFAULT_PORT)).strip()
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise HostServiceConfigError(
            f"{PORT_ENV} debe ser un entero (recibido {raw_port!r})"
        ) from exc
    if not 1 <= port <= 65535:
        raise HostServiceConfigError(f"{PORT_ENV} fuera de rango: {port}")
    events_url = os.getenv(EVENTS_URL_ENV, DEFAULT_EVENTS_URL).strip() or DEFAULT_EVENTS_URL
    raw_interval = os.getenv(EVENTS_INTERVAL_ENV, str(DEFAULT_EVENTS_INTERVAL)).strip()
    try:
        events_interval = max(0.5, float(raw_interval))
    except ValueError as exc:
        raise HostServiceConfigError(
            f"{EVENTS_INTERVAL_ENV} debe ser un número de segundos ({raw_interval!r})"
        ) from exc
    events_enabled = os.getenv(EVENTS_ENABLED_ENV, "true").strip().lower() != "false"
    devices_dir = Path(os.getenv(DEVICES_DIR_ENV, DEFAULT_DEVICES_DIR))
    raw_cert = os.getenv(TLS_CERT_ENV, "").strip()
    raw_key = os.getenv(TLS_KEY_ENV, "").strip()
    if bool(raw_cert) != bool(raw_key):
        raise HostServiceConfigError(
            f"{TLS_CERT_ENV} y {TLS_KEY_ENV} deben definirse juntos (o ninguno)"
        )
    tls_cert = Path(raw_cert) if raw_cert else None
    tls_key = Path(raw_key) if raw_key else None
    if tls_cert is not None:
        for label, path in (("certificado", tls_cert), ("clave", tls_key)):
            if not path.is_file():
                raise HostServiceConfigError(
                    f"TLS: no existe el {label} en {path}"
                )
    return HostServiceSettings(
        token=token, manifest=manifest, bind=bind, port=port,
        events_url=events_url, events_interval=events_interval,
        events_enabled=events_enabled, devices_dir=devices_dir,
        tls_cert=tls_cert, tls_key=tls_key,
    )


def _client(request: Request) -> str:
    return request.client.host if request.client else "desconocido"


async def _require_token(request: Request) -> None:
    """Valida el bearer token en tiempo constante (401 si falta o no cuadra)."""
    settings: HostServiceSettings = request.app.state.settings
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value:
        logger.warning("[fabric-host] petición sin bearer token desde %s", _client(request))
        raise HTTPException(
            401, "Token bearer requerido", headers={"WWW-Authenticate": "Bearer"}
        )
    if not secrets.compare_digest(
        value.encode("utf-8"), settings.token.encode("utf-8")
    ):
        logger.warning("[fabric-host] token inválido desde %s", _client(request))
        raise HTTPException(
            401, "Token inválido", headers={"WWW-Authenticate": "Bearer"}
        )


def _manifest_hash(settings: HostServiceSettings) -> str:
    try:
        return hashlib.sha256(settings.manifest.read_bytes()).hexdigest()
    except OSError:
        return ""


def _load_topology(settings: HostServiceSettings) -> FabricTopology:
    """Manifiesto → ``FabricTopology``; 503 si no se puede leer, 422 si inválido."""
    try:
        raw = yaml.safe_load(settings.manifest.read_text(encoding="utf-8")) or {}
    except OSError as exc:
        logger.error("[fabric-host] no se puede leer el manifiesto: %s", exc)
        raise HTTPException(503, detail={
            "message": f"No se puede leer el manifiesto: {exc}",
            "errors": [str(exc)],
        }) from exc
    try:
        return parse_manifest(raw)
    except FabricValidationError as exc:
        logger.error("[fabric-host] manifiesto inválido: %s", "; ".join(exc.errors))
        raise HTTPException(422, detail={
            "message": "Manifiesto inválido",
            "errors": list(exc.errors),
        }) from exc


def _plan(topology: FabricTopology) -> FabricPlan:
    return FabricPlan(
        bridges=build_bridge_specs(topology),
        links=build_link_specs(topology),
        devices=build_device_specs(topology),
    )


def _acquire(request: Request) -> None:
    lock: threading.Lock = request.app.state.operation_lock
    if not lock.acquire(blocking=False):
        logger.warning("[fabric-host] operación concurrente rechazada desde %s",
                       _client(request))
        raise HTTPException(409, "Ya hay una operación de fabric en curso")


def _release(request: Request) -> None:
    lock: threading.Lock = request.app.state.operation_lock
    if lock.locked():
        lock.release()


def _engine(request: Request) -> Any:
    return request.app.state.engine


@router.post("/deploy", dependencies=[Depends(_require_token)])
def deploy(request: Request) -> dict:
    """Despliega el manifiesto (switches → enlaces → dispositivos)."""
    settings: HostServiceSettings = request.app.state.settings
    engine = _engine(request)
    _acquire(request)
    try:
        topology = _load_topology(settings)
        plan = _plan(topology)
        logger.info(
            "[fabric-host] deploy solicitado por %s (bridges=%d links=%d devices=%d)",
            _client(request), len(plan.bridges), len(plan.links), len(plan.devices),
        )
        try:
            engine.deploy(plan, topology)
        except FabricDeployError as exc:
            logger.error("[fabric-host] deploy falló: %s", "; ".join(exc.errors))
            raise HTTPException(502, detail={
                "message": "deploy falló",
                "errors": list(exc.errors),
            }) from exc
        except Exception as exc:  # el engine puede fallar de cualquier forma
            logger.exception("[fabric-host] deploy falló de forma inesperada")
            raise HTTPException(500, detail={
                "message": f"deploy falló: {exc}",
                "errors": [str(exc)],
            }) from exc
        result = getattr(engine, "last_result", None)
        payload = result.model_dump() if result is not None else {}
        logger.info(
            "[fabric-host] deploy completado: %d bridges, %d enlaces, %d contenedores",
            len(payload.get("bridges_created", [])),
            len(payload.get("links_created", [])),
            len(payload.get("containers_created", [])),
        )
        return {
            "success": True,
            "operation": "deploy",
            "service": SERVICE_NAME,
            "manifest": str(settings.manifest),
            "manifest_hash": _manifest_hash(settings),
            "engine": type(engine).__name__,
            **payload,
        }
    finally:
        _release(request)


@router.post("/destroy", dependencies=[Depends(_require_token)])
def destroy(request: Request) -> dict:
    """Destruye el fabric en orden inverso (idempotente)."""
    settings: HostServiceSettings = request.app.state.settings
    engine = _engine(request)
    _acquire(request)
    try:
        topology = _load_topology(settings)
        logger.info("[fabric-host] destroy solicitado por %s", _client(request))
        try:
            engine.destroy(topology)
        except FabricDeployError as exc:
            logger.error("[fabric-host] destroy falló: %s", "; ".join(exc.errors))
            raise HTTPException(502, detail={
                "message": "destroy falló",
                "errors": list(exc.errors),
            }) from exc
        except Exception as exc:  # el engine puede fallar de cualquier forma
            logger.exception("[fabric-host] destroy falló de forma inesperada")
            raise HTTPException(500, detail={
                "message": f"destroy falló: {exc}",
                "errors": [str(exc)],
            }) from exc
        result = getattr(engine, "last_destroy_result", None)
        payload = result.model_dump() if result is not None else {}
        logger.info(
            "[fabric-host] destroy completado: %d bridges, %d enlaces, %d contenedores, "
            "%d credenciales borradas",
            len(payload.get("bridges_removed", [])),
            len(payload.get("links_removed", [])),
            len(payload.get("containers_removed", [])),
            len(payload.get("credentials_removed", [])),
        )
        return {
            "success": True,
            "operation": "destroy",
            "service": SERVICE_NAME,
            "manifest": str(settings.manifest),
            "manifest_hash": _manifest_hash(settings),
            "engine": type(engine).__name__,
            **payload,
        }
    finally:
        _release(request)


@router.get("/status", dependencies=[Depends(_require_token)])
def status(request: Request) -> dict:
    """Estado del servicio y resultado del último deploy/destroy."""
    settings: HostServiceSettings = request.app.state.settings
    engine = _engine(request)
    last_deploy = getattr(engine, "last_result", None)
    last_destroy = getattr(engine, "last_destroy_result", None)
    lock: threading.Lock = request.app.state.operation_lock
    forwarder = getattr(request.app.state, "forwarder", None)
    from app.services.fabric import credential_store

    return {
        "service": SERVICE_NAME,
        "engine": type(engine).__name__,
        "manifest": str(settings.manifest),
        "manifest_hash": _manifest_hash(settings),
        "busy": lock.locked(),
        "tls": settings.tls,
        "credentials_encrypted": credential_store.is_configured(),
        "last_deploy": last_deploy.model_dump() if last_deploy is not None else None,
        "last_destroy": last_destroy.model_dump() if last_destroy is not None else None,
        "forwarder": (
            forwarder.status() if forwarder is not None
            else {"enabled": False, "pending": 0, "sent": 0,
                  "failed": 0, "last_error": None}
        ),
    }


@router.get("/health", dependencies=[Depends(_require_token)])
def health(request: Request) -> dict:
    """Salud del runtime comparada con el manifiesto (bridges/enlaces/devices)."""
    from app.services.fabric import lifecycle  # import perezoso anti-ciclo

    settings: HostServiceSettings = request.app.state.settings
    engine = _engine(request)
    try:
        topology = _load_topology(settings)
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        return {
            "service": SERVICE_NAME,
            "ok": False,
            "healthy": False,
            "runtime_available": False,
            "manifest": str(settings.manifest),
            "manifest_hash": _manifest_hash(settings),
            "checks": [{"name": "manifest", "ok": False,
                        "detail": detail.get("message", "manifiesto inválido")}],
            "bridges": {"expected": [], "present": [], "missing": []},
            "links": {"expected": [], "present": [], "missing": []},
            "devices": [],
            "devices_health": [],
            "errors": list(detail.get("errors", [])),
            "warnings": [],
        }

    report = lifecycle.health(engine=engine, topology=topology)
    devices_health: list[dict] = []
    device_runtime = getattr(engine, "device_runtime", None)
    health_fn = getattr(device_runtime, "device_health", None)
    if health_fn is not None:
        device_specs = build_device_specs(topology)
        # Solo los IPs de dispositivos reales son verificables con ping.
        known_ips = {
            iface.ip.split("/")[0]
            for spec in device_specs
            for iface in spec.interfaces
        }
        devices_health = [
            health_fn(spec, known_device_ips=known_ips) for spec in device_specs
        ]
    healthy = bool(report.get("healthy")) and all(
        bool(device.get("healthy")) for device in devices_health
    )
    return {
        "service": SERVICE_NAME,
        "ok": True,
        "manifest": str(settings.manifest),
        "manifest_hash": _manifest_hash(settings),
        **report,
        "healthy": healthy,
        "devices_health": devices_health,
    }


# ── Consola interactiva (Fase 11) ────────────────────────────


async def _container_running(container_name: str) -> bool:
    """``docker inspect`` acotado: solo el estado del contenedor del manifiesto."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "inspect", "--format", "{{.State.Running}}", container_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
    except (OSError, asyncio.TimeoutError):
        return False
    return stdout.decode("utf-8", errors="replace").strip() == "true"


@router.websocket("/console/ws")
async def console_ws(
    websocket: WebSocket,
    device_id: str = Query(default=""),
    cols: int = Query(default=80),
    rows: int = Query(default=24),
) -> None:
    """Puente WS↔PTY hacia un contenedor señuelo del manifiesto.

    Solo para el control (bearer token en la cabecera). El control no tiene
    socket de Docker; este servicio sí, así que la consola real se abre
    aquí y el control reenvía los bytes del navegador. Fail-closed:

    - token bearer válido (4401 si no),
    - ``DYSTOPIA_FABRIC_CONSOLE_ENABLED=true`` en el servicio,
    - ``device_id`` presente en el manifiesto (4404),
    - contenedor en ejecución,
    - cuota/idle del ``console_service``.
    """
    settings: HostServiceSettings = websocket.app.state.settings
    header = websocket.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if (
        scheme.lower() != "bearer"
        or not value
        or not secrets.compare_digest(value.encode("utf-8"), settings.token.encode("utf-8"))
    ):
        await websocket.close(code=4401)
        return

    async def _fail(message: str, code: int = 1011) -> None:
        await websocket.accept()
        await websocket.send_text(ERROR_PREFIX + message)
        await websocket.close(code=code)

    if not console_enabled():
        await _fail(
            "Consola deshabilitada en el servicio del host: exporta "
            "DYSTOPIA_FABRIC_CONSOLE_ENABLED=true (fail-closed)"
        )
        return
    try:
        topology = _load_topology(settings)
    except HTTPException as exc:
        await _fail(str(exc.detail))
        return
    spec = next(
        (item for item in build_device_specs(topology) if item.device_id == device_id),
        None,
    )
    if spec is None:
        await _fail("Dispositivo no encontrado en el manifiesto", code=4404)
        return
    if not await _container_running(spec.container_name):
        await _fail("El contenedor del dispositivo no está en ejecución")
        return
    try:
        session = await console_service.open_session(
            device_id=spec.device_id,
            container_name=spec.container_name,
            username="fabric-host",
            cols=cols,
            rows=rows,
        )
    except RuntimeError as exc:
        await _fail(str(exc))
        return

    await websocket.accept()

    async def pump_out() -> None:
        while True:
            chunk = await console_service.read_chunk(session.session_id)
            if chunk is None:
                return
            if chunk:
                await websocket.send_bytes(chunk)

    async def pump_in() -> None:
        while True:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                return
            data = message.get("bytes")
            if data is None:
                text = message.get("text")
                if text is None:
                    continue
                data = text.encode("utf-8")
            if not await console_service.write_session(session.session_id, data):
                return

    tasks = [asyncio.create_task(pump_out()), asyncio.create_task(pump_in())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        await console_service.close_session(session.session_id)
        try:
            await websocket.close(code=1000)
        except Exception:  # noqa: BLE001 - el cliente ya se desconectó
            pass


def create_app(
    settings: Optional[HostServiceSettings] = None,
    engine: Optional[Any] = None,
    forwarder: Optional[Any] = None,
) -> FastAPI:
    """Construye la app; sin token válido lanza ``HostServiceConfigError``."""
    resolved = settings or load_settings()
    if len(resolved.token) < MIN_TOKEN_LENGTH:
        raise HostServiceConfigError(
            f"{TOKEN_ENV} debe tener al menos {MIN_TOKEN_LENGTH} caracteres"
        )
    app = FastAPI(
        title="Dystopia Fabric Host Service",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = resolved
    app.state.engine = engine if engine is not None else OvsFabricEngine()
    app.state.operation_lock = threading.Lock()
    app.state.forwarder = forwarder
    app.include_router(router)
    return app


def main() -> None:
    """Entrypoint del servicio systemd (uvicorn, bind/puerto por entorno)."""
    import logging

    import uvicorn

    # Sin esto, los logger.info de los módulos propios no llegan al journal
    # (uvicorn solo configura sus loggers). Los WARNING/ERROR sí salían, lo
    # que hacía invisible el arranque del forwarder y del propio servicio.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    settings = load_settings()
    if settings.bind in {"0.0.0.0", "::", "[::]"}:
        logger.warning(
            "[fabric-host] bind %s expone el servicio en todas las interfaces",
            settings.bind,
        )
    from app.services.fabric.event_forwarder import forwarder_from_env

    forwarder = None
    if settings.events_enabled:
        forwarder = forwarder_from_env(
            settings_token=settings.token,
            devices_dir=settings.devices_dir,
            state_path=settings.devices_dir.parent / "forwarder-state.json",
        )
        if forwarder is not None:
            forwarder.start()  # hilo daemon: nunca bloquea deploy/destroy
    app = create_app(settings, forwarder=forwarder)
    logger.info(
        "[fabric-host] escuchando en %s:%d (manifest=%s, tls=%s)",
        settings.bind, settings.port, settings.manifest, settings.tls,
    )
    tls_kwargs = {}
    if settings.tls:
        tls_kwargs = {
            "ssl_certfile": str(settings.tls_cert),
            "ssl_keyfile": str(settings.tls_key),
        }
    try:
        uvicorn.run(
            app, host=settings.bind, port=settings.port, log_level="info",
            **tls_kwargs,
        )
    finally:
        if forwarder is not None:
            forwarder.stop()


if __name__ == "__main__":  # pragma: no cover - arranque del servicio
    main()
