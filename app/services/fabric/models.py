"""NetPulse — Fabric: modelos de la red virtual.

Representación validada del bloque ``fabric:`` de
``config/deception/network.yaml``: switches virtuales OVS, enlaces,
interfaces, credenciales, vecinos (ARP), rutas, comportamiento
administrativo, logging y límites de recursos de los dispositivos.

``FabricTopology`` referencia los modelos del núcleo de deception
(``DeceptionSegment`` y ``DeceptionDevice``). Para evitar el import
circular —``app.models.deception`` importa ``FabricConfig`` desde aquí—
esas referencias se resuelven por forward-ref al terminar de cargarse
``app.models.deception`` (ver ``rebuild_topology_model``).
"""

from typing import TYPE_CHECKING, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:  # pragma: no cover - solo para tipos
    from app.models.deception import DeceptionDevice, DeceptionSegment


class FabricSwitch(BaseModel):
    """Switch virtual del fabric (siempre Open vSwitch en el MVP)."""

    id: str = Field(..., description="Identificador del switch", examples=["sw-core"])
    type: Literal["ovs"] = Field(default="ovs", description="Tipo de switch (solo OVS)")
    stp: bool = Field(default=False, description="Spanning Tree Protocol activo")
    vlans: list[int] = Field(
        default_factory=list, description="VLANs que troncaliza el switch"
    )
    uplink: Optional[str] = Field(
        default=None,
        description="Switch de agregación; crea un enlace troncal automático",
        examples=["sw-core"],
    )
    description: str = Field(default="")


class FabricLink(BaseModel):
    """Enlace explícito entre dos switches del fabric.

    ``from`` es palabra reservada de Python, así que el campo se declara
    como ``from_`` con alias ``from``. ``populate_by_name`` acepta ambas
    formas al validar y ``serialize_by_alias`` vuelve a emitir ``from`` al
    serializar (el YAML conserva el esquema del manifiesto).
    """

    model_config = ConfigDict(populate_by_name=True, serialize_by_alias=True)

    from_: str = Field(..., alias="from", description="Switch de origen", examples=["sw-core"])
    to: str = Field(..., description="Switch de destino", examples=["sw-oficina"])
    trunk: bool = Field(default=True, description="Enlace troncal (802.1Q)")
    bandwidth: Optional[int] = Field(
        default=None, description="Ancho de banda reservado (Fase 2)"
    )


class FabricInterface(BaseModel):
    """Interfaz de red de un dispositivo del fabric."""

    name: str = Field(default="eth0", description="Nombre de la interfaz", examples=["eth0"])
    segment: str = Field(..., description="Segmento/VLAN asociado", examples=["vlan-oficina"])
    ip: str = Field(
        ..., description="Dirección en notación CIDR", examples=["10.10.0.21/24"]
    )
    mac: str = Field(..., description="MAC de la interfaz", examples=["00:1c:42:10:10:21"])
    gateway: Optional[str] = Field(default=None, description="Gateway de la interfaz")
    vlan_tag: Optional[int] = Field(
        default=None, description="Etiqueta 802.1Q del puerto en el switch"
    )
    switch: str = Field(..., description="Switch al que se conecta", examples=["sw-oficina"])


class FabricCredential(BaseModel):
    """Credencial señuelo de un servicio del dispositivo (cifrada en reposo)."""

    username: str = Field(..., description="Usuario de la credencial", examples=["admin"])
    password: str = Field(..., description="Contraseña señuelo (cifrada en reposo)")
    service: str = Field(..., description="Servicio asociado", examples=["ssh"])
    purpose: str = Field(default="", description="Propósito de la credencial")


class FabricNeighbor(BaseModel):
    """Vecino declarado en la red (entrada ARP estática en el contenedor)."""

    ip: str = Field(..., description="IP del vecino", examples=["10.10.0.1"])
    mac: str = Field(..., description="MAC del vecino", examples=["00:1c:42:10:10:01"])
    hostname: str = Field(default="", description="Hostname visible del vecino")


class FabricRoute(BaseModel):
    """Ruta estática de un dispositivo del fabric."""

    destination: str = Field(
        ..., description="Red destino en notación CIDR", examples=["0.0.0.0/0"]
    )
    gateway: str = Field(..., description="Gateway de la ruta", examples=["10.10.0.1"])


class FabricAdminBehavior(BaseModel):
    """Comportamiento administrativo simulado del dispositivo."""

    management_protocol: str = Field(
        default="ssh", description="Protocolo de gestión", examples=["ssh"]
    )
    management_port: int = Field(default=22, description="Puerto de gestión")
    login_banner: str = Field(default="", description="Banner mostrado en el login")
    motd: str = Field(default="", description="Mensaje del día")
    shell_prompt: str = Field(default="$ ", description="Prompt de shell simulado")
    idle_timeout: int = Field(default=300, description="Timeout de inactividad (segundos)")


class FabricLogging(BaseModel):
    """Destino y nivel de los logs del dispositivo."""

    syslog_target: Optional[str] = Field(
        default=None, description="Colector syslog remoto", examples=["10.20.0.10"]
    )
    log_level: str = Field(default="info", description="Nivel de log")
    forward_to_dystopia: bool = Field(
        default=True, description="Reenviar eventos al pipeline de telemetría"
    )


class FabricDeviceResources(BaseModel):
    """Límites de recursos del contenedor del dispositivo."""

    image: str = Field(
        default="dystopia/fabric-device:v1", description="Imagen Docker del dispositivo"
    )
    mem_limit: str = Field(default="128m", description="Límite de memoria")
    cpus: float = Field(default=0.25, description="Cuota de CPU")


class FabricDeviceOverride(BaseModel):
    """Extensión de fabric para un dispositivo del listado ``devices``."""

    id: str = Field(..., description="Id del dispositivo de nivel superior", examples=["pc-01"])
    interfaces: list[FabricInterface] = Field(default_factory=list)
    credentials: list[FabricCredential] = Field(default_factory=list)
    neighbors: list[FabricNeighbor] = Field(default_factory=list)
    routes: list[FabricRoute] = Field(default_factory=list)
    admin_behavior: Optional[FabricAdminBehavior] = None
    logging: Optional[FabricLogging] = None
    resources: Optional[FabricDeviceResources] = None


class FabricDefaults(BaseModel):
    """Valores por defecto globales del fabric."""

    device_image: str = Field(
        default="dystopia/fabric-device:v1", description="Imagen Docker por defecto"
    )
    mem_limit: str = Field(default="128m", description="Límite de memoria por defecto")
    cpus: float = Field(default=0.25, description="Cuota de CPU por defecto")


class FabricConfig(BaseModel):
    """Raíz del bloque ``fabric:`` en ``network.yaml``."""

    enabled: bool = Field(
        default=False, description="Activa el Network Fabric (opt-in)"
    )
    name: str = Field(default="dystopia-fabric", description="Nombre lógico del fabric")
    defaults: FabricDefaults = Field(default_factory=FabricDefaults)
    switches: list[FabricSwitch] = Field(default_factory=list)
    links: list[FabricLink] = Field(default_factory=list)
    device_overrides: list[FabricDeviceOverride] = Field(default_factory=list)


class FabricTopology(BaseModel):
    """Representación validada e inmutable de la red completa del fabric."""

    config: FabricConfig
    segments: list["DeceptionSegment"]
    devices: list["DeceptionDevice"]
    # Calculados al validar la topología (Topology Manager):
    switch_port_map: dict[str, list[str]] = Field(default_factory=dict)
    device_switch_map: dict[str, str] = Field(default_factory=dict)


def rebuild_topology_model() -> None:
    """Resuelve los forward-refs de ``FabricTopology``.

    ``app.models.deception`` importa ``FabricConfig`` de este módulo y, al
    terminar de definir sus modelos, invoca esta función. Así Pydantic
    conoce ``DeceptionSegment`` y ``DeceptionDevice`` sin que exista un
    import circular en tiempo de carga.
    """
    from app.models.deception import DeceptionDevice, DeceptionSegment

    FabricTopology.model_rebuild(
        _types_namespace={
            "DeceptionSegment": DeceptionSegment,
            "DeceptionDevice": DeceptionDevice,
        }
    )


# Si este módulo se importa antes que app.models.deception, la resolución
# ocurre aquí (el import tardío de deception completará sus modelos y
# volverá a reconstruir la topología). Si deception está a medio cargar,
# el ImportError es esperado y la resolución la hará ese módulo al final.
try:  # pragma: no cover - depende del orden de importación
    rebuild_topology_model()
except ImportError:
    pass
