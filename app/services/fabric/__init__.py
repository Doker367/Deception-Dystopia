"""NetPulse — Fabric (red virtual señuelo).

Subpaquete del Network Fabric: agrupa los modelos Pydantic del bloque
``fabric:`` de ``network.yaml`` y, en fases posteriores, el parser del
manifiesto, el gestor de topología, el motor de despliegue y el ciclo de
vida. Los modelos se exportan aquí para que el resto de la aplicación no
dependa de la ruta interna del módulo.
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
    "FabricCredential",
    "FabricDefaults",
    "FabricDeviceOverride",
    "FabricDeviceResources",
    "FabricInterface",
    "FabricLink",
    "FabricLogging",
    "FabricNeighbor",
    "FabricRoute",
    "FabricSwitch",
    "FabricTopology",
]
