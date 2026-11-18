"""NetPulse — Fabric Router.

API del Network Fabric (§6): estado de la máquina, validación del
manifiesto, ciclo de vida (deploy/destroy/rebuild), topología, grafo para
D3/ECharts, dispositivos, switches, salud e ingestión de eventos del
agente (§7).

Las rutas GET requieren rol ``viewer`` y las mutaciones ``admin``, igual
que el resto de routers. Las credenciales del manifiesto nunca salen en
una respuesta (AC13): el controlador ya las elimina y aquí se aplica un
segundo filtro recursivo en la frontera HTTP.

``POST /api/fabric/events`` es la excepción de autenticación: no usa JWT
porque el emisor es un **servicio** (el forwarder del host service), no un
usuario; se autentica con ``X-Fabric-Token`` contra
``DYSTOPIA_FABRIC_EVENTS_TOKEN``, un secreto **dedicado a la ingesta**
distinto del token de operación ``DYSTOPIA_FABRIC_REMOTE_TOKEN``.
A diferencia del ingest legacy retirado (410), es una ruta interna
control→servicio del host: secreto de servicio dedicado, lotes acotados y
solo ``device_id`` presentes en el manifiesto del fabric.

Migración (Fase 9)
------------------
Hasta la Fase 8 la ingesta aceptaba como *fallback* deprecado
``DYSTOPIA_FABRIC_REMOTE_TOKEN`` cuando faltaba el token de eventos. Ese
fallback **se retiró**: reutilizar el token de operación (que viaja en
cada petición de deploy/destroy) ampliaba su superficie de exposición y
mezclaba dos privilegios distintos. Si el operador no define
``DYSTOPIA_FABRIC_EVENTS_TOKEN`` en el ``.env`` del control, la ingesta
responde **503 fail-closed** (no 401: el endpoint está deshabilitado, no
mal autenticado) y el forwarder del host deja de enviar. Pasos:

1. Copia ``DYSTOPIA_FABRIC_EVENTS_TOKEN`` de ``/etc/dystopia/fabric.env``
   (lo genera el instalador) al ``.env`` de ``deploy/local``.
2. Recrea el control: ``docker compose up -d control``.
3. Verifica ``GET /api/fabric/status`` → ``forwarder.failed`` estable y
   ``pending`` a 0 tras unos ciclos.
"""

import asyncio
import ipaddress
import json
import logging
import os
import secrets
from datetime import datetime
from typing import Any, Optional

from fastapi import (
    APIRouter,
    Body,
    Depends,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.security import verify_token
from app.middleware.auth import JWTBearer
from app.middleware.rbac import get_current_user, requires_role
from app.models.deception import DeceptionEventType
from app.services.deception import telemetry_svc
from app.services.fabric import console_service
from app.services.fabric.console_svc import (
    CONSOLE_IDLE_TIMEOUT,
    CONSOLE_MAX_AGE,
    CONSOLE_MAX_PER_DEVICE,
    CONSOLE_MAX_SESSIONS,
    ERROR_PREFIX,
    console_enabled,
    remote_console_target,
)
from app.services.fabric.controller import (
    FabricState,
    FabricStateError,
    get_controller,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/fabric", tags=["Fabric"])

AUTH = [Depends(JWTBearer()), Depends(requires_role("viewer"))]
ADMIN = [Depends(JWTBearer()), Depends(requires_role("admin"))]

_FORBIDDEN_KEYS = frozenset({"credentials", "password"})

# ── Ingesta de eventos del fabric (§7) ──────────────────────
SERVICE_TOKEN_ENV = "DYSTOPIA_FABRIC_EVENTS_TOKEN"
MIN_SERVICE_TOKEN = 32
MAX_EVENTS = 200
MAX_BODY_BYTES = 256 * 1024
# Protocolos servidos por los listeners nativos del agente.
FABRIC_EVENT_PROTOS = frozenset({
    "ssh", "telnet", "http", "https", "rtsp", "smb", "snmp", "ftp", "mysql",
})
_EVENT_TYPES = frozenset(event_type.value for event_type in DeceptionEventType)


class FabricEventIn(BaseModel):
    """Evento tal como lo emite el agente (JSONL del fabric).

    ``extra="forbid"``: nada de campos libres que acaben en la DB.
    """

    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(..., min_length=1, max_length=128)
    proto: str = Field(..., min_length=1, max_length=16)
    type: str = Field(..., min_length=1, max_length=32)
    src_ip: str = Field(..., min_length=1, max_length=45)
    src_port: Optional[int] = Field(default=None, ge=0, le=65535)
    detail: dict = Field(default_factory=dict)
    username: Optional[str] = Field(default=None, max_length=128)
    success: bool = False
    ts: Optional[str] = Field(default=None, max_length=64)


def _without_credentials(value: Any) -> Any:
    """Copia recursiva sin ``credentials`` ni ``password`` (AC13)."""
    if isinstance(value, dict):
        return {
            key: _without_credentials(item)
            for key, item in value.items()
            if key not in _FORBIDDEN_KEYS
        }
    if isinstance(value, list):
        return [_without_credentials(item) for item in value]
    return value


def _lifecycle(action: str, username: str = "system") -> dict:
    """Ejecuta deploy/destroy/rebuild y traduce el resultado a HTTP.

    - Transición inválida de la state machine → 409.
    - Gate cerrado o fabric deshabilitado → 409.
    - Fallo del engine (estado ``error``) → 502.
    """
    controller = get_controller()
    try:
        result = getattr(controller, action)(username=username)
    except FabricStateError as exc:
        raise HTTPException(409, "; ".join(exc.errors)) from exc

    if not result.get("success"):
        detail = "; ".join(result.get("errors") or ["Operación rechazada"])
        status = 502 if result.get("state") == FabricState.ERROR.value else 409
        raise HTTPException(status, detail)
    return result


def _switch_summaries(topology: dict) -> list[dict]:
    """Vista resumida de los switches declarados en la topología."""
    return [
        {
            "id": switch["id"],
            "type": switch.get("type", "ovs"),
            "stp": switch.get("stp", False),
            "vlans": list(switch.get("vlans", [])),
            "uplink": switch.get("uplink"),
            "description": switch.get("description", ""),
        }
        for switch in topology.get("config", {}).get("switches", [])
    ]


# ── Estado y topología ──────────────────────────────────────


@router.get("/status", dependencies=AUTH)
def get_status():
    """Estado de la máquina del fabric, gate, hash y conteos del plan."""
    return get_controller().get_status()


@router.get("/topology", dependencies=AUTH)
def get_topology():
    """Topología validada (switches, enlaces, dispositivos) sin credenciales."""
    return _without_credentials(get_controller().get_topology())


@router.get("/topology/graph", dependencies=AUTH)
def get_topology_graph():
    """Grafo ``{nodes, edges, groups}`` para D3/ECharts, sin credenciales."""
    return _without_credentials(get_controller().get_topology_graph())


# ── Validación y ciclo de vida ──────────────────────────────


@router.post("/validate", dependencies=ADMIN)
def validate_manifest(
    manifest: Optional[dict] = Body(default=None),
    user: dict = Depends(get_current_user),
):
    """Valida un manifiesto completo sin desplegar.

    Sin cuerpo valida el ``network.yaml`` actual. Responde 200 con
    ``valid: false`` y el listado de errores/warnings si el manifiesto es
    inválido.
    """
    try:
        return _without_credentials(get_controller().validate(
            manifest, username=user.get("sub", "system"),
        ))
    except FabricStateError as exc:
        raise HTTPException(409, "; ".join(exc.errors)) from exc


@router.post("/deploy", dependencies=ADMIN)
def deploy(user: dict = Depends(get_current_user)):
    """Construye y arranca el fabric (idempotente: destruye primero)."""
    return _lifecycle("deploy", user.get("sub", "system"))


@router.post("/destroy", dependencies=ADMIN)
def destroy(user: dict = Depends(get_current_user)):
    """Destruye el fabric desplegado y vuelve a ``ready``."""
    return _lifecycle("destroy", user.get("sub", "system"))


@router.post("/rebuild", dependencies=ADMIN)
def rebuild(user: dict = Depends(get_current_user)):
    """Alias destroy+deploy del ciclo de vida."""
    return _lifecycle("rebuild", user.get("sub", "system"))


# ── Dispositivos y switches ─────────────────────────────────


@router.get("/devices", dependencies=AUTH)
def list_devices():
    """Dispositivos planificados del fabric (sin credenciales)."""
    return _without_credentials(get_controller().get_devices())


@router.get("/devices/{device_id}", dependencies=AUTH)
def get_device(device_id: str):
    """Detalle de un dispositivo: plan, runtime (pid/puertos/vecinos) y servicios."""
    device = get_controller().get_device(device_id)
    if device is None:
        raise HTTPException(404, "Dispositivo de fabric no encontrado")
    return _without_credentials(device)


@router.get("/events", dependencies=AUTH)
def list_events(
    device_id: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=200),
):
    """Últimos eventos del fabric (solo device_ids del manifiesto).

    Vista de lectura para el drawer del dispositivo. ``device_id`` ajeno al
    manifiesto → 403 (no se filtra información de otros dispositivos);
    ``limit`` acotado a 200.
    """
    from app.services.deception import store_svc  # import local: solo lectura

    known = _fabric_device_ids()
    if device_id is not None and device_id not in known:
        raise HTTPException(403, "device_id ajeno al manifiesto del fabric")
    if device_id is not None:
        return store_svc.get_events(limit=limit, device_id=device_id)
    events: list[dict] = []
    for fabric_device in sorted(known):
        events.extend(store_svc.get_events(limit=limit, device_id=fabric_device))
    events.sort(key=lambda event: event.get("id", 0), reverse=True)
    return events[:limit]


@router.get("/switches", dependencies=AUTH)
def list_switches():
    """Switches declarados en la topología validada."""
    return _switch_summaries(get_controller().get_topology())


@router.get("/switches/{switch_id}", dependencies=AUTH)
def get_switch(switch_id: str):
    """Detalle de un switch del fabric."""
    for switch in _switch_summaries(get_controller().get_topology()):
        if switch["id"] == switch_id:
            return switch
    raise HTTPException(404, "Switch de fabric no encontrado")


@router.get("/health", dependencies=AUTH)
def get_health():
    """Salud estructural del fabric (sin runtime real todavía)."""
    return get_controller().get_health()


# ── Configuración del manifiesto (editor YAML) ──────────────


class ConfigPayload(BaseModel):
    """Cuerpo de PUT /api/fabric/config."""

    content: str = Field(..., min_length=1, max_length=512 * 1024)


@router.get("/config", dependencies=ADMIN)
def get_config() -> dict:
    """YAML del bloque ``fabric:`` para el editor (solo admin).

    Devuelve el bloque ``fabric:`` del manifiesto; las credenciales
    señuelo se enmascaran como ``__REDACTED__`` para no exponerlas
    (AC13). Al guardar, PUT restaura los valores enmascarados desde el
    manifiesto vigente y hace *merge* del bloque en el documento
    completo (preserva segments/devices).
    """
    import yaml

    from app.core.settings import DECEPTION_NETWORK_FILE

    try:
        raw = yaml.safe_load(DECEPTION_NETWORK_FILE.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        raw = {}
    fabric_block = raw.get("fabric") or {}
    for override in fabric_block.get("device_overrides") or []:
        for credential in override.get("credentials") or []:
            if isinstance(credential, dict) and credential.get("password"):
                credential["password"] = "__REDACTED__"
    return {
        "path": str(DECEPTION_NETWORK_FILE),
        "content": yaml.safe_dump(fabric_block, sort_keys=False, allow_unicode=True),
    }


@router.put("/config", dependencies=ADMIN)
def put_config(payload: ConfigPayload, user: dict = Depends(get_current_user)) -> dict:
    """Guarda el YAML editado (bloque ``fabric:``) y valida el resultado.

    El editor recibe/devuelve **solo el bloque ``fabric:``**; aquí se hace
    *merge* en el documento completo del manifiesto (preservando
    ``segments``/``devices``/etc.), se valida el documento completo con el
    parser del fabric y se escribe atómicamente con backup ``.bak``.

    En ``ready``/``disabled`` el controlador adopta el manifiesto (los
    cambios aparecen al momento); en ``deployed`` es un informe puro y la
    respuesta incluye ``needs_rebuild: true``.
    """
    import yaml

    from app.core.settings import DECEPTION_NETWORK_FILE as MANIFEST_PATH

    try:
        fabric_block = yaml.safe_load(payload.content)
    except yaml.YAMLError as exc:
        raise HTTPException(422, f"YAML inválido: {exc}") from exc
    if not isinstance(fabric_block, dict):
        raise HTTPException(422, "El YAML debe ser el bloque 'fabric:'")

    # Documento vigente (puede no existir todavía).
    try:
        current = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8")) or {}
    except (FileNotFoundError, yaml.YAMLError):
        current = {}
    if not isinstance(current, dict):
        current = {}

    # Restaura las contraseñas enmascaradas (AC13) desde el manifiesto
    # vigente: un ``__REDACTED__`` significa "sin cambio".
    current_passwords: dict[tuple, str] = {}
    for override in (current.get("fabric") or {}).get("device_overrides") or []:
        for credential in override.get("credentials") or []:
            if isinstance(credential, dict):
                key = (
                    override.get("id"), credential.get("service"),
                    credential.get("username"),
                )
                current_passwords[key] = credential.get("password", "")
    for override in fabric_block.get("device_overrides") or []:
        for credential in override.get("credentials") or []:
            if (
                isinstance(credential, dict)
                and credential.get("password") == "__REDACTED__"
            ):
                key = (
                    override.get("id"), credential.get("service"),
                    credential.get("username"),
                )
                credential["password"] = current_passwords.get(key, "")

    # Merge: reemplaza SOLO la clave fabric del documento completo.
    full_doc = {**current, "fabric": fabric_block}

    try:
        report = get_controller().validate(full_doc)
    except FabricStateError as exc:
        raise HTTPException(409, "; ".join(exc.errors)) from exc
    if not report.get("valid"):
        raise HTTPException(422, detail={
            "message": "El manifiesto propuesto no valida",
            "errors": report.get("errors", []),
            "warnings": report.get("warnings", []),
        })

    backup = MANIFEST_PATH.with_suffix(MANIFEST_PATH.suffix + ".bak")
    try:
        MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
        if MANIFEST_PATH.exists():
            backup.write_bytes(MANIFEST_PATH.read_bytes())
        MANIFEST_PATH.write_text(
            yaml.safe_dump(full_doc, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
    except OSError as exc:
        raise HTTPException(500, f"No se pudo escribir el manifiesto: {exc}") from exc

    state = report.get("state")
    return {
        "saved": True,
        "path": str(MANIFEST_PATH),
        "state": state,
        # En deployed el informe es puro: el manifiesto guardado se
        # aplicará en el próximo rebuild (no se toca el despliegue vivo).
        "needs_rebuild": state == FabricState.DEPLOYED.value,
    }


# ── Ingesta de eventos del fabric (control ← host service) ──


def _events_token() -> str:
    """Token de ingesta (solo ``DYSTOPIA_FABRIC_EVENTS_TOKEN``) o ``""``.

    Sin fallback: el token de operación del engine remote ya no sirve para
    la ingesta (ver "Migración (Fase 9)" en el docstring del módulo).
    """
    token = os.getenv(SERVICE_TOKEN_ENV, "").strip()
    return token if len(token) >= MIN_SERVICE_TOKEN else ""


async def _require_service_token(request: Request) -> None:
    """Token de servicio en ``X-Fabric-Token``; 503 si no está configurado."""
    token = _events_token()
    if not token:
        raise HTTPException(
            503,
            "Ingesta de eventos deshabilitada: "
            f"{SERVICE_TOKEN_ENV} no está configurado (fail-closed); "
            "define el token de eventos en el .env del control",
        )
    header = request.headers.get("x-fabric-token", "")
    if not header or not secrets.compare_digest(
        header.encode("utf-8"), token.encode("utf-8")
    ):
        logger.warning("[fabric] token de servicio inválido desde %s",
                       request.client.host if request.client else "?")
        raise HTTPException(401, "Token de servicio inválido")


def _fabric_device_ids() -> set[str]:
    """device_ids del manifiesto del fabric (vacío → fail-closed)."""
    try:
        topology = get_controller().get_topology()
    except Exception:  # noqa: BLE001 - sin topología no se acepta nada
        return set()
    return {
        device.get("id") for device in topology.get("devices", [])
        if isinstance(device, dict) and device.get("id")
    }


def _normalize_credentials(detail: dict, username: Optional[str] = None) -> dict:
    """Mueve las credenciales capturadas a ``detail.credentials`` (§12 Fase 7).

    El agente escribe ``username``/``password`` capturados en la raíz del
    ``detail`` (y el listener SSH pone ``username`` a nivel de evento); aquí
    se agrupan en ``credentials = {"username", "password"}`` sin duplicar si
    ya vienen normalizados y conservando el resto del ``detail``. Solo aplica
    a credenciales del **atacante**: las del manifiesto nunca llegan por esta
    vía (las elimina el agente).
    """
    normalized = dict(detail or {})
    existing = normalized.get("credentials")
    if existing is not None and not isinstance(existing, dict):
        # Valor malformado: se deja tal cual para que la validación lo
        # rechace (no se "arregla" silenciosamente con el username del evento).
        return normalized
    if isinstance(existing, dict) and (
        "username" in existing or "password" in existing
    ):
        return normalized  # ya normalizado: no duplicar
    captured_user = normalized.pop("username", None) or username
    password = normalized.pop("password", None)
    if captured_user is None and password is None:
        return normalized
    credentials = existing if isinstance(existing, dict) else {}
    if captured_user is not None:
        credentials.setdefault("username", captured_user)
    if password is not None:
        credentials.setdefault("password", password)
    normalized["credentials"] = credentials
    return normalized


def _credentials_error(detail: dict) -> Optional[str]:
    """``credentials`` debe ser un objeto de strings acotados (128/256)."""
    credentials = detail.get("credentials")
    if credentials is None:
        return None
    if not isinstance(credentials, dict):
        return "credentials debe ser un objeto {clave: valor}"
    limits = {"username": 128, "password": 256}
    for key, value in credentials.items():
        if not isinstance(key, str) or not isinstance(value, str):
            return "credentials solo admite claves y valores de texto"
        if len(key) > 64:
            return "clave de credentials demasiado larga (máx 64)"
        limit = limits.get(key, 256)
        if len(value) > limit:
            return f"valor de '{key}' demasiado largo (máx {limit})"
    return None


def _event_error(event: FabricEventIn) -> Optional[str]:
    """Validación semántica por evento; ``None`` si es válido."""
    if event.proto.strip().lower() not in FABRIC_EVENT_PROTOS:
        return f"proto no permitido '{event.proto}'"
    if event.type not in _EVENT_TYPES:
        return f"type no permitido '{event.type}'"
    try:
        ipaddress.ip_address(event.src_ip)
    except ValueError:
        return f"src_ip inválida '{event.src_ip}'"
    if event.ts:
        try:
            datetime.fromisoformat(event.ts.replace("Z", "+00:00"))
        except ValueError:
            return f"ts inválido '{event.ts}'"
    return None


@router.post("/events", dependencies=[Depends(_require_service_token)])
async def receive_events(request: Request) -> dict:
    """Ingesta de eventos del fabric (lotes del forwarder del host).

    Lote: ``{"events": [...]}``, máx. 200 eventos / 256 KB. El esquema se
    valida estrictamente (422); un ``device_id`` ajeno al manifiesto
    rechaza todo el lote (403); los eventos con proto/type/src_ip/ts
    inválidos se cuentan y no tumban el resto. Cada evento válido entra
    por ``telemetry_svc.emit_sync`` (store + Prometheus + Loki + alertas).
    """
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise HTTPException(413, f"Cuerpo demasiado grande (máx {MAX_BODY_BYTES} bytes)")
    try:
        payload = json.loads(raw or b"{}")
    except ValueError as exc:
        raise HTTPException(422, f"JSON inválido: {exc}") from exc
    events = payload.get("events") if isinstance(payload, dict) else None
    if not isinstance(events, list):
        raise HTTPException(422, "Se espera {'events': [...]}")
    if len(events) > MAX_EVENTS:
        raise HTTPException(413, f"Demasiados eventos (máx {MAX_EVENTS})")

    try:
        parsed = [FabricEventIn.model_validate(event) for event in events]
    except ValidationError as exc:
        errors = [
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors()
        ]
        raise HTTPException(422, detail={
            "message": "Esquema de eventos inválido", "errors": errors,
        }) from exc

    known_devices = _fabric_device_ids()
    if not known_devices:
        # Sin topología cargada (arranque, manifiesto inválido) no se puede
        # validar: 503 para que el forwarder reintente, nunca 403 (perdería
        # los eventos por un fallo transitorio del control).
        raise HTTPException(503, detail={
            "message": "topología del fabric no disponible; reintenta",
        })

    accepted = 0
    rejected = 0
    errors: list[dict] = []
    records: list[dict] = []
    for index, event in enumerate(parsed):
        if event.device_id not in known_devices:
            # Un device_id ajeno no invalida el resto del lote: se cuenta y
            # se sigue (p. ej. logs huérfanos de pruebas). No se filtra nada.
            rejected += 1
            errors.append({
                "index": index,
                "error": f"device_id desconocido: '{event.device_id}'",
            })
            continue
        problem = _event_error(event)
        if problem is None:
            normalized_detail = _normalize_credentials(
                event.detail, username=event.username
            )
            problem = _credentials_error(normalized_detail)
        if problem is None:
            try:
                record = telemetry_svc.emit_sync(
                    event.device_id, event.src_ip, event.proto.strip().lower(),
                    event.type, detail=normalized_detail,
                    username=event.username,
                    success=event.success, src_port=event.src_port, ts=event.ts,
                )
                records.append(record)
                accepted += 1
            except Exception as exc:  # noqa: BLE001 - un fallo no tumba el lote
                rejected += 1
                errors.append({"index": index, "error": f"emit falló: {exc}"})
                logger.exception("[fabric] emit falló para '%s'", event.device_id)
        else:
            rejected += 1
            errors.append({"index": index, "error": problem})

    # Alertas específicas del fabric (Fase 7): fallo no tumba la ingesta.
    if records:
        try:
            from app.services.fabric import fabric_alerts
            from app.services.fabric.parser import (
                FabricValidationError,
                load_topology,
            )
            try:
                topology = load_topology()
            except FabricValidationError:
                topology = None
            fabric_alerts.evaluate_batch(records, topology)
        except Exception:  # noqa: BLE001
            logger.exception("[fabric] evaluación de alertas del fabric falló")

    return {"accepted": accepted, "rejected": rejected, "errors": errors}


# ── Consola interactiva (WebSocket↔PTY, Fase 11) ────────────


@router.post("/devices/{device_id}/console", dependencies=ADMIN)
async def open_device_console(device_id: str, user: dict = Depends(get_current_user)) -> dict:
    """Preflight de la consola interactiva (no abre sesión).

    Valida los mismos gates que el WebSocket —fabric ``deployed``, device en
    el manifiesto y ``DYSTOPIA_FABRIC_CONSOLE_ENABLED=true``— para que la UI
    pueda avisar antes de conectar. La sesión real la abre el WS.
    """
    del user  # autenticado vía dependencies=ADMIN
    if not console_enabled():
        raise HTTPException(
            503,
            "Consola deshabilitada: exporta DYSTOPIA_FABRIC_CONSOLE_ENABLED=true "
            "(fail-closed)",
        )
    controller = get_controller()
    topology = controller.get_topology()
    known = {
        device.get("id") for device in (topology.get("devices") or [])
        if isinstance(device, dict) and device.get("id")
    }
    if device_id not in known:
        raise HTTPException(404, "Dispositivo de fabric no encontrado")
    status = controller.get_status()
    if status.get("state") != FabricState.DEPLOYED.value:
        raise HTTPException(409, "El fabric no está desplegado; no hay consola disponible")
    container_name = next(
        (
            spec.get("container_name", "")
            for spec in controller.get_devices()
            if spec.get("device_id") == device_id
        ),
        "",
    )
    if not container_name:
        raise HTTPException(502, "El dispositivo no tiene contenedor asociado")
    return {
        "available": True,
        "device_id": device_id,
        "transport": "remote" if remote_console_target() else "docker",
    }


@router.websocket("/devices/{device_id}/console/ws")
async def device_console_ws(
    websocket: WebSocket,
    device_id: str,
    token: str = Query(default=""),
    cols: int = Query(default=80),
    rows: int = Query(default=24),
):
    """Puente WebSocket↔PTY de una sesión de consola del fabric.

    Autenticación por JWT en el query ``token`` (los navegadores no pueden
    fijar headers en el handshake WS). Solo con el fabric ``deployed`` y
    el device en el manifiesto; cierra con códigos WS dedicados (4401 no
    autenticado, 4404 device desconocido, 1011 estado no disponible).

    El transporte real lo elige ``console_service``: ``docker exec`` local o
    WS contra el servicio del host cuando el motor es ``remote``.
    """
    payload = verify_token(token)
    if payload is None or payload.get("role") != "admin":
        await websocket.close(code=4401)
        return

    async def fail(message: str, code: int = 1011) -> None:
        await websocket.accept()
        await websocket.send_text(ERROR_PREFIX + message)
        await websocket.close(code=code)

    if not console_enabled():
        await fail(
            "Consola deshabilitada: exporta DYSTOPIA_FABRIC_CONSOLE_ENABLED=true "
            "(fail-closed)"
        )
        return
    controller = get_controller()
    try:
        status = controller.get_status()
    except Exception:
        status = {}
    if not isinstance(status, dict) or status.get("state") != FabricState.DEPLOYED.value:
        await fail("El fabric no está desplegado; no hay consola disponible")
        return
    topology = controller.get_topology()
    known = {
        device.get("id") for device in (topology.get("devices") or [])
        if isinstance(device, dict) and device.get("id")
    }
    if device_id not in known:
        await fail("Dispositivo desconocido", code=4404)
        return
    container_name = next(
        (
            spec.get("container_name", "")
            for spec in controller.get_devices()
            if spec.get("device_id") == device_id
        ),
        "",
    )
    if not container_name:
        await fail("El dispositivo no tiene contenedor asociado")
        return

    try:
        session = await console_service.open_session(
            device_id=device_id,
            container_name=container_name,
            username=payload.get("sub", "admin"),
            cols=cols,
            rows=rows,
        )
    except RuntimeError as exc:
        await fail(str(exc))
        return

    await websocket.accept()

    async def pump_output() -> None:
        """Reenvía la salida del PTY al cliente mientras haya datos."""
        while True:
            chunk = await console_service.read_chunk(session.session_id)
            if chunk is None:  # EOF del proceso
                await websocket.close(code=1000)
                return
            if chunk:
                await websocket.send_text(chunk.decode("utf-8", errors="replace"))

    pump_task = asyncio.create_task(pump_output())
    try:
        while True:
            message = await websocket.receive_text()
            # Mensajes de control del cliente (resize): frame JSON, no raw.
            if message.startswith("{"):
                try:
                    control = json.loads(message)
                except json.JSONDecodeError:
                    control = None
                if isinstance(control, dict) and control.get("type") == "resize":
                    ok = await console_service.resize_session(
                        session.session_id, control.get("cols", 80), control.get("rows", 24)
                    )
                    if not ok:
                        await console_service.close_session(session.session_id)
                        break
                    continue
            await console_service.write_session(session.session_id, message.encode("utf-8"))
    except WebSocketDisconnect:
        pass
    finally:
        pump_task.cancel()
        await console_service.close_session(session.session_id)


@router.get("/console/sessions", dependencies=ADMIN)
async def list_console_sessions(user: dict = Depends(get_current_user)) -> dict:
    """Sesiones de consola activas (estado, transport, device) para la UI."""
    sessions = console_service.list_sessions()
    return {
        "sessions": [
            {
                "session_id": s.session_id,
                "device_id": s.device_id,
                "state": "open" if s.ws is not None or s.pty_fd is not None else "zombie",
                "transport": "remote" if s.ws is not None else "docker",
                "started_at": s.started_at,
                "last_activity": s.last_activity,
                "container_name": s.container_name,
                "username": s.username,
            }
            for s in sessions
        ],
        "active": console_service.active_count,
        "max_sessions": CONSOLE_MAX_SESSIONS,
        "per_device_max": CONSOLE_MAX_PER_DEVICE,
        "idle_timeout": CONSOLE_IDLE_TIMEOUT,
        "max_age": CONSOLE_MAX_AGE,
    }

