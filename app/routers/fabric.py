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
``DYSTOPIA_FABRIC_REMOTE_TOKEN`` (el mismo secreto del engine remote).
A diferencia del ingest legacy retirado (410), es una ruta interna
control→servicio del host: secreto de servicio dedicado, lotes acotados y
solo ``device_id`` presentes en el manifiesto del fabric.
"""

import ipaddress
import json
import logging
import os
import secrets
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.middleware.auth import JWTBearer
from app.middleware.rbac import get_current_user, requires_role
from app.models.deception import DeceptionEventType
from app.services.deception import telemetry_svc
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
# Fallback deprecado: antes la ingesta reutilizaba el token del engine remote.
LEGACY_SERVICE_TOKEN_ENV = "DYSTOPIA_FABRIC_REMOTE_TOKEN"
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


# ── Ingesta de eventos del fabric (control ← host service) ──


_legacy_token_warned = False


def _events_token() -> tuple[str, bool]:
    """Token de ingesta y si viene del env legacy (deprecado)."""
    token = os.getenv(SERVICE_TOKEN_ENV, "").strip()
    if len(token) >= MIN_SERVICE_TOKEN:
        return token, False
    legacy = os.getenv(LEGACY_SERVICE_TOKEN_ENV, "").strip()
    if len(legacy) >= MIN_SERVICE_TOKEN:
        return legacy, True
    return "", False


async def _require_service_token(request: Request) -> None:
    """Token de servicio en ``X-Fabric-Token``; 503 si no está configurado."""
    global _legacy_token_warned
    token, legacy = _events_token()
    if not token:
        raise HTTPException(
            503,
            "Ingesta de eventos deshabilitada: "
            f"{SERVICE_TOKEN_ENV} no está configurado (fail-closed)",
        )
    if legacy and not _legacy_token_warned:
        _legacy_token_warned = True
        logger.warning(
            "[fabric] %s no configurado; usando %s (deprecado: separa los tokens)",
            SERVICE_TOKEN_ENV, LEGACY_SERVICE_TOKEN_ENV,
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
    unknown = sorted({event.device_id for event in parsed} - known_devices)
    if unknown:
        raise HTTPException(403, detail={
            "message": "device_id ajeno al manifiesto del fabric",
            "errors": [f"device_id desconocido: '{device_id}'" for device_id in unknown],
        })

    accepted = 0
    rejected = 0
    errors: list[dict] = []
    records: list[dict] = []
    for index, event in enumerate(parsed):
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
