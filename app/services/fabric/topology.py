"""NetPulse — Fabric: Topology Manager (transformación pura).

Traduce una ``FabricTopology`` ya validada a los planes de despliegue que
ejecutará el Deployment Engine (Fase 3): bridges OVS, enlaces entre
switches y contenedores de dispositivo con sus interfaces.

Sin efectos secundarios: no hay I/O, ni Docker, ni OVS, ni Mininet. La
misma topología produce siempre los mismos planes, en el mismo orden; la
determinación del grafo se apoya en el orden de declaración del YAML.

Los tipos de los planes (``BridgeSpec``, ``LinkSpec``, ``DeviceSpec``)
viven aquí y no en ``models.py``: ``models.py`` es el contrato del
manifiesto (§5) y este módulo es la frontera hacia el runtime (§2.2).
Son modelos Pydantic congelados (``frozen=True``) para que un plan no se
modifique después de construirse.
"""

import re
from typing import Literal, NamedTuple, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.services.fabric.models import (
    FabricConfig,
    FabricDeviceOverride,
    FabricInterface,
    FabricLink,
    FabricTopology,
)

# Límite de Linux para nombres de interfaz (IFNAMSIZ - 1).
_IFNAMSIZ = 15
# El extremo del host reserva 2 caracteres para su peer temporal ("-c").
_HOST_VETH_MAX = _IFNAMSIZ - 2

# Caracteres admitidos en un nombre de interfaz de Linux (se simplifican).
_IFNAME_NOISE = re.compile(r"[^a-z0-9]+")


# ── Especificaciones de despliegue ──────────────────────────


class ArpEntrySpec(BaseModel):
    """Entrada ARP estática derivada de un vecino declarado."""

    model_config = ConfigDict(frozen=True)

    ip: str
    mac: str


class RouteSpec(BaseModel):
    """Ruta estática del namespace del dispositivo."""

    model_config = ConfigDict(frozen=True)

    destination: str
    gateway: str


class NeighborSpec(BaseModel):
    """Vecino declarado en el manifiesto (para ARP y health checks)."""

    model_config = ConfigDict(frozen=True)

    ip: str
    mac: str
    hostname: str = ""


class InterfaceSpec(BaseModel):
    """Interfaz de un contenedor conectada a un puerto OVS.

    ``host_veth`` es el extremo que permanece en el host (≤ 13 caracteres
    para que ``peer_veth`` —``f"{host_veth}-c"``— quepa en los 15 de
    Linux). ``peer_veth`` se mueve al netns del contenedor y se renombra
    a ``container_veth`` (§4.2): por defecto ``eth0``, y en dispositivos
    con varias interfaces se conserva el nombre declarado para que no
    colisionen.
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Nombre declarado en el manifiesto")
    container_veth: str = Field(..., description="Nombre dentro del netns")
    host_veth: str = Field(..., description="Extremo del host, ≤ 13 caracteres")
    peer_veth: str = Field(..., description="Extremo temporal que se mueve al netns")
    switch: str = Field(..., description="Switch OVS de destino")
    vlan_tag: Optional[int] = Field(default=None, description="VLAN de acceso; None = sin etiqueta")
    ip: str
    mac: str
    gateway: Optional[str] = None


class DeviceSpec(BaseModel):
    """Plan de despliegue de un dispositivo del fabric.

    Rutas, vecinos y entradas ARP son del namespace del contenedor (§4.2
    los configura una sola vez tras mover la interfaz), por eso viven en
    el dispositivo y no en cada interfaz.

    Solo los dispositivos con al menos una interfaz declarada tienen
    plan: un ``device_override`` sin interfaces no participa en el fabric
    runtime y sigue funcionando como hasta hoy.
    """

    model_config = ConfigDict(frozen=True)

    device_id: str
    container_name: str
    labels: dict[str, str]
    image: str
    mem_limit: str
    cpus: float
    interfaces: list[InterfaceSpec] = Field(default_factory=list)
    routes: list[RouteSpec] = Field(default_factory=list)
    neighbors: list[NeighborSpec] = Field(default_factory=list)
    arp_entries: list[ArpEntrySpec] = Field(default_factory=list)


class BridgePortSpec(BaseModel):
    """Puerto de un bridge OVS.

    ``kind="device"``: extremo de un veth de contenedor, con ``tag`` de
    acceso (``None`` = puerto sin etiqueta). ``kind="trunk"``: extremo de
    un enlace entre switches, siempre troncal (``tag=None``).
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Nombre del puerto en el host")
    kind: Literal["device", "trunk"]
    tag: Optional[int] = Field(default=None, description="VLAN de acceso; None = troncal")
    peer: str = Field(..., description="device_id o switch del otro extremo")


class BridgeSpec(BaseModel):
    """Bridge OVS de un switch del fabric.

    ``internal=True`` implementa el aislamiento del §9.1: el bridge no
    tiene conectividad externa. Los uplinks automáticos y los enlaces
    explícitos aparecen como puertos troncales del bridge.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    stp: bool
    vlans: list[int] = Field(default_factory=list, description="VLANs troncales")
    internal: bool = True
    ports: list[BridgePortSpec] = Field(default_factory=list)


class LinkSpec(BaseModel):
    """Enlace entre dos switches (par de veths host-host).

    ``source`` indica qué declaración lo originó: un ``uplink`` de switch
    o una entrada de ``links``. Los extremos se listan en el orden de esa
    declaración.

    Los parámetros WAN (Fase 10) se copian tal cual del manifiesto y son
    ``None`` cuando no se declaran: el engine solo aplica ``tc netem`` si
    hay al menos uno. ``bandwidth_mbps`` ya resuelve el alias deprecado
    ``bandwidth`` (``bandwidth_mbps`` prevalece), así que el engine no
    necesita conocer la compatibilidad.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    from_switch: str
    to_switch: str
    port_from: str
    port_to: str
    trunk: bool = True
    latency_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    loss_pct: Optional[float] = None
    bandwidth_mbps: Optional[float] = None
    source: Literal["uplink", "explicit"]

    @property
    def wan_enabled(self) -> bool:
        """True si el enlace declara algún parámetro de emulación WAN."""
        return any(
            value is not None
            for value in (self.latency_ms, self.jitter_ms, self.loss_pct,
                          self.bandwidth_mbps)
        )


# ── Nombres de interfaz deterministas ───────────────────────


def _slug(value: str, limit: int = 8) -> str:
    """Fragmento legible para un nombre de interfaz (minúsculas alfanuméricas)."""
    slug = _IFNAME_NOISE.sub("", value.lower())
    return (slug or "x")[:limit]


def _ifname(base: str) -> str:
    """Recorta un nombre al máximo que deja espacio al peer ``-c``."""
    return base[:_HOST_VETH_MAX]


def _device_host_veth(device_id: str, index: int) -> str:
    """Extremo del host para una interfaz de dispositivo.

    Esquema ``dv<índice>-<slug>``: el índice global de interfaz garantiza
    unicidad (el truncado de ``device_id`` del §4.2 podía colisionar) y el
    slug mantiene el nombre legible. Longitud máxima 13, de modo que
    ``f"{host_veth}-c"`` (14) sigue cabiendo en 15.
    """
    return _ifname(f"dv{index:02d}-{_slug(device_id)}")


def _link_host_veths(index: int, from_switch: str, to_switch: str) -> tuple[str, str]:
    """Extremos host-host de un enlace inter-switch.

    Esquema ``lk<índice><lado>-<slug>``: el índice del enlace es único y
    los lados ``a``/``b`` distinguen ambos extremos incluso si los slugs
    de los switches truncados coinciden.
    """
    port_from = _ifname(f"lk{index:02d}a-{_slug(from_switch)}")
    port_to = _ifname(f"lk{index:02d}b-{_slug(to_switch)}")
    return port_from, port_to


# ── Helpers de recorrido ────────────────────────────────────


def _device_interfaces(
    config: FabricConfig,
) -> list[tuple[FabricDeviceOverride, FabricInterface, int]]:
    """Interfaces de dispositivo en orden de manifiesto, con índice global.

    El índice es el que usan tanto ``build_device_specs`` como
    ``build_bridge_specs``; así el ``host_veth`` del plan de dispositivo y
    el puerto del bridge son siempre el mismo nombre.
    """
    out: list[tuple[FabricDeviceOverride, FabricInterface, int]] = []
    index = 0
    for override in config.device_overrides:
        for iface in override.interfaces:
            out.append((override, iface, index))
            index += 1
    return out


class _PlannedLink(NamedTuple):
    """Enlace lógico previo a la asignación de puertos."""

    from_switch: str
    to_switch: str
    trunk: bool
    latency_ms: Optional[float]
    jitter_ms: Optional[float]
    loss_pct: Optional[float]
    bandwidth_mbps: Optional[float]
    source: Literal["uplink", "explicit"]


def _effective_bandwidth(link: FabricLink) -> Optional[float]:
    """Ancho de banda efectivo: ``bandwidth_mbps`` manda sobre el alias."""
    if link.bandwidth_mbps is not None:
        return link.bandwidth_mbps
    if link.bandwidth is not None:
        return float(link.bandwidth)
    return None


def _planned_links(config: FabricConfig) -> list[_PlannedLink]:
    """Lista canónica de enlaces, sin duplicados por par de switches.

    Reglas de deduplicación (deterministas y documentadas):

    1. Los ``links`` explícitos van primero, en orden de declaración: son
       la declaración más específica (``trunk`` y parámetros WAN).
    2. Después, cada ``uplink`` de switch en orden de declaración. Si el
       par ya existe, se omite: el enlace explícito manda.
    3. Solo hay un enlace lógico por par de switches en el MVP (no hay
       haces/LAG); los pares se comparan sin orden (``frozenset``).
    """
    planned: list[_PlannedLink] = []
    seen: set[frozenset[str]] = set()

    for link in config.links:
        key = frozenset((link.from_, link.to))
        if key in seen:
            continue
        seen.add(key)
        planned.append(_PlannedLink(
            from_switch=link.from_,
            to_switch=link.to,
            trunk=link.trunk,
            latency_ms=link.latency_ms,
            jitter_ms=link.jitter_ms,
            loss_pct=link.loss_pct,
            bandwidth_mbps=_effective_bandwidth(link),
            source="explicit",
        ))

    for switch in config.switches:
        if switch.uplink is None:
            continue
        key = frozenset((switch.id, switch.uplink))
        if key in seen:
            continue
        seen.add(key)
        planned.append(_PlannedLink(
            from_switch=switch.id,
            to_switch=switch.uplink,
            trunk=True,
            latency_ms=None,
            jitter_ms=None,
            loss_pct=None,
            bandwidth_mbps=None,
            source="uplink",
        ))

    return planned


# ── Planes de despliegue ────────────────────────────────────


def build_bridge_specs(topology: FabricTopology) -> list[BridgeSpec]:
    """Bridges OVS del fabric, uno por switch declarado.

    Los puertos se ordenan de forma determinista: primero los de
    dispositivo (orden del manifiesto) y después los troncales (orden de
    ``build_link_specs``). Todos los bridges son ``internal`` (§9.1).
    """
    config = topology.config
    link_specs = build_link_specs(topology)

    trunk_ports: dict[str, list[BridgePortSpec]] = {sw.id: [] for sw in config.switches}
    for link in link_specs:
        trunk_ports[link.from_switch].append(BridgePortSpec(
            name=link.port_from, kind="trunk", tag=None, peer=link.to_switch,
        ))
        trunk_ports[link.to_switch].append(BridgePortSpec(
            name=link.port_to, kind="trunk", tag=None, peer=link.from_switch,
        ))

    device_ports: dict[str, list[BridgePortSpec]] = {sw.id: [] for sw in config.switches}
    for override, iface, index in _device_interfaces(config):
        device_ports[iface.switch].append(BridgePortSpec(
            name=_device_host_veth(override.id, index),
            kind="device",
            tag=iface.vlan_tag,
            peer=override.id,
        ))

    return [
        BridgeSpec(
            id=switch.id,
            stp=switch.stp,
            vlans=list(switch.vlans),
            internal=True,
            ports=device_ports[switch.id] + trunk_ports[switch.id],
        )
        for switch in config.switches
    ]


def build_link_specs(topology: FabricTopology) -> list[LinkSpec]:
    """Enlaces inter-switch: uplinks automáticos + ``links`` explícitos.

    La deduplicación sigue ``_planned_links``: un explicit y un uplink
    para el mismo par producen un único enlace, con la declaración
    explícita como ganadora. El ``id`` y los puertos derivan del índice en
    esa lista canónica, así que son estables entre ejecuciones.
    """
    specs: list[LinkSpec] = []
    for index, planned in enumerate(_planned_links(topology.config)):
        port_from, port_to = _link_host_veths(
            index, planned.from_switch, planned.to_switch
        )
        specs.append(LinkSpec(
            id=f"lk{index:02d}",
            from_switch=planned.from_switch,
            to_switch=planned.to_switch,
            port_from=port_from,
            port_to=port_to,
            trunk=planned.trunk,
            latency_ms=planned.latency_ms,
            jitter_ms=planned.jitter_ms,
            loss_pct=planned.loss_pct,
            bandwidth_mbps=planned.bandwidth_mbps,
            source=planned.source,
        ))
    return specs


def build_device_specs(topology: FabricTopology) -> list[DeviceSpec]:
    """Contenedores de dispositivo del fabric, en orden de manifiesto.

    Solo se incluyen overrides con al menos una interfaz: sin interfaces
    no hay attachment al bridge, así que el dispositivo no participa en
    el fabric runtime (decisión documentada ante la ambigüedad del spec).

    ``resources``, si existe, se usa completo; si no, se usan los
    ``defaults`` globales. No hay mezcla campo a campo porque el modelo
    de recursos no distingue un valor omitido de su default.
    """
    specs: list[DeviceSpec] = []
    index = 0
    for override in topology.config.device_overrides:
        if not override.interfaces:
            continue

        if override.resources is not None:
            image = override.resources.image
            mem_limit = override.resources.mem_limit
            cpus = override.resources.cpus
        else:
            image = topology.config.defaults.device_image
            mem_limit = topology.config.defaults.mem_limit
            cpus = topology.config.defaults.cpus

        interfaces: list[InterfaceSpec] = []
        for iface in override.interfaces:
            host_veth = _device_host_veth(override.id, index)
            index += 1
            interfaces.append(InterfaceSpec(
                name=iface.name,
                container_veth=iface.name,
                host_veth=host_veth,
                peer_veth=f"{host_veth}-c",
                switch=iface.switch,
                vlan_tag=iface.vlan_tag,
                ip=iface.ip,
                mac=iface.mac,
                gateway=iface.gateway,
            ))

        specs.append(DeviceSpec(
            device_id=override.id,
            container_name=f"dystopia-fabric-{override.id}",
            labels={"dystopia.fabric": "true", "dystopia.device": override.id},
            image=image,
            mem_limit=mem_limit,
            cpus=cpus,
            interfaces=interfaces,
            routes=[
                RouteSpec(destination=r.destination, gateway=r.gateway)
                for r in override.routes
            ],
            neighbors=[
                NeighborSpec(ip=n.ip, mac=n.mac, hostname=n.hostname)
                for n in override.neighbors
            ],
            arp_entries=[
                ArpEntrySpec(ip=n.ip, mac=n.mac) for n in override.neighbors
            ],
        ))
    return specs
