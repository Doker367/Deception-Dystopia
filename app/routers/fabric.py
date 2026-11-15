"""NetPulse — Fabric Router.

API del Network Fabric (§6): estado de la máquina, validación del
manifiesto, ciclo de vida (deploy/destroy/rebuild), topología, grafo para
D3/ECharts, dispositivos, switches y salud.

Las rutas GET requieren rol ``viewer`` y las mutaciones ``admin``, igual
que el resto de routers. Las credenciales del manifiesto nunca salen en
una respuesta (AC13): el controlador ya las elimina y aquí se aplica un
segundo filtro recursivo en la frontera HTTP.
"""

import logging
from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, HTTPException

from app.middleware.auth import JWTBearer
from app.middleware.rbac import requires_role
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


def _lifecycle(action: str) -> dict:
    """Ejecuta deploy/destroy/rebuild y traduce el resultado a HTTP.

    - Transición inválida de la state machine → 409.
    - Gate cerrado o fabric deshabilitado → 409.
    - Fallo del engine (estado ``error``) → 502.
    """
    controller = get_controller()
    try:
        result = getattr(controller, action)()
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
def validate_manifest(manifest: Optional[dict] = Body(default=None)):
    """Valida un manifiesto completo sin desplegar.

    Sin cuerpo valida el ``network.yaml`` actual. Responde 200 con
    ``valid: false`` y el listado de errores/warnings si el manifiesto es
    inválido.
    """
    try:
        return _without_credentials(get_controller().validate(manifest))
    except FabricStateError as exc:
        raise HTTPException(409, "; ".join(exc.errors)) from exc


@router.post("/deploy", dependencies=ADMIN)
def deploy():
    """Construye y arranca el fabric (idempotente: destruye primero)."""
    return _lifecycle("deploy")


@router.post("/destroy", dependencies=ADMIN)
def destroy():
    """Destruye el fabric desplegado y vuelve a ``ready``."""
    return _lifecycle("destroy")


@router.post("/rebuild", dependencies=ADMIN)
def rebuild():
    """Alias destroy+deploy del ciclo de vida."""
    return _lifecycle("rebuild")


# ── Dispositivos y switches ─────────────────────────────────


@router.get("/devices", dependencies=AUTH)
def list_devices():
    """Dispositivos planificados del fabric (sin credenciales)."""
    return _without_credentials(get_controller().get_devices())


@router.get("/devices/{device_id}", dependencies=AUTH)
def get_device(device_id: str):
    """Detalle de un dispositivo del fabric."""
    for device in _without_credentials(get_controller().get_devices()):
        if device.get("device_id") == device_id:
            return device
    raise HTTPException(404, "Dispositivo de fabric no encontrado")


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
