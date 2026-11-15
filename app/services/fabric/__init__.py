"""NetPulse — Fabric (red virtual señuelo).

Subpaquete del Network Fabric: modelos Pydantic del bloque ``fabric:`` de
``network.yaml``, parser del manifiesto, Topology Manager y controlador
con su máquina de estados. Los modelos se exportan aquí para que el resto
de la aplicación no dependa de la ruta interna del módulo.

El controlador se exporta de forma perezosa (PEP 562): importarlo aquí de
forma directa cerraría un ciclo con ``app.models.deception``, que importa
``FabricConfig`` de este paquete al cargarse.
"""

from app.services.fabric.models import (
    FabricAdminBehavior,
    FabricConfig,
    FabricCredential,
    FabricDefaults,
    FabricDeviceOverride,
    FabricDeviceResources,
    FabricInterface,
    FabricLink,
    FabricLogging,
    FabricNeighbor,
    FabricRoute,
    FabricSwitch,
    FabricTopology,
)

__all__ = [
    "FabricAdminBehavior",
    "FabricConfig",
    "FabricController",
    "FabricCredential",
    "FabricDefaults",
    "FabricDeviceOverride",
    "FabricDeviceResources",
    "FabricEngine",
    "FabricInterface",
    "FabricLink",
    "FabricLogging",
    "FabricNeighbor",
    "FabricPlan",
    "FabricRoute",
    "FabricState",
    "FabricStateError",
    "FabricSwitch",
    "FabricTopology",
    "NullFabricEngine",
    "get_controller",
    "reset_controller",
]

_CONTROLLER_EXPORTS = frozenset({
    "FabricController",
    "FabricEngine",
    "FabricPlan",
    "FabricState",
    "FabricStateError",
    "NullFabricEngine",
    "get_controller",
    "reset_controller",
})


def __getattr__(name: str):
    """Resuelve los exports del controlador bajo demanda (anti-ciclo)."""
    if name in _CONTROLLER_EXPORTS:
        from app.services.fabric import controller

        return getattr(controller, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
