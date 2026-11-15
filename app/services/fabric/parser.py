"""NetPulse — Fabric: parser del manifiesto.

Valida el bloque ``fabric:`` de ``config/deception/network.yaml`` y lo
cruza con los ``segments``/``devices`` de nivel superior para producir
una ``FabricTopology`` lista para el Topology Manager.

La validación es acumulativa: todos los fallos de esquema y de
integridad referencial se recogen en ``FabricValidationError.errors``
para que el operador pueda corregirlos de una vez. La lectura del YAML y
su caché por firma (mtime/tamaño) viven en
``app.services.deception.topology_svc``; este módulo solo transforma y
valida datos.
"""

import ipaddress
from typing import Optional

from pydantic import ValidationError

from app.models.deception import DeceptionNetwork, DeceptionSegment
from app.services.deception import topology_svc
from app.services.fabric.models import FabricConfig, FabricSwitch, FabricTopology


class FabricValidationError(ValueError):
    """Manifiesto del fabric inválido.

    Hereda de ``ValueError`` para seguir el patrón del resto de servicios
    (``topology_svc`` lanza ``ValueError`` con los errores unidos). El
    listado completo queda en ``errors`` y ``str(exc)`` los une con
    ``"; "``.
    """

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__(
            "; ".join(self.errors) if self.errors else "manifiesto fabric inválido"
        )


# ── Esquema (bloque fabric) ─────────────────────────────────


def _format_validation_errors(exc: ValidationError, prefix: str = "") -> list[str]:
    """Aplana los errores de Pydantic a mensajes ``ruta: detalle``."""
    out: list[str] = []
    for err in exc.errors():
        loc = err["loc"]
        path = ".".join(
            str(part) for part in ((prefix,) if prefix else ()) + tuple(loc)
        )
        out.append(f"{path}: {err['msg']}" if path else err["msg"])
    return out


def parse_fabric(raw_fabric: Optional[dict] = None) -> FabricConfig:
    """Valida el bloque ``fabric:`` del YAML y devuelve su modelo.

    ``None`` o un bloque vacío producen ``FabricConfig()`` (deshabilitado
    y con defaults), que es el contrato de compatibilidad: sin ``fabric``
    el resto de Dystopia funciona igual.

    Lanza ``FabricValidationError`` con todos los errores de esquema si el
    bloque no es un mapping o sus campos no respetan los tipos del §5.
    """
    if raw_fabric is None:
        return FabricConfig()
    if not isinstance(raw_fabric, dict):
        raise FabricValidationError(
            [f"fabric: debe ser un objeto YAML (mapping), no {type(raw_fabric).__name__}"]
        )
    try:
        return FabricConfig.model_validate(raw_fabric)
    except ValidationError as exc:
        raise FabricValidationError(_format_validation_errors(exc, prefix="fabric")) from exc


# ── Integridad cruzada (§3.3) ───────────────────────────────


def _ip_address(ip: str) -> str:
    """Dirección sin prefijo CIDR (``10.10.0.21/24`` → ``10.10.0.21``).

    Las interfaces del fabric declaran la IP en notación CIDR, pero
    ``topology_svc._ip_in_segment`` espera una dirección.
    """
    return ip.split("/", 1)[0].strip()


def _normalized_ip(ip: str) -> str:
    """Clave canónica para detectar IPs repetidas (tolera formatos)."""
    try:
        return str(ipaddress.ip_address(_ip_address(ip)))
    except ValueError:
        return ip.strip()


def _normalized_mac(mac: str) -> str:
    """Clave canónica para detectar MACs repetidas (sin distinguir caja)."""
    return mac.strip().lower()


def validate_fabric(network: DeceptionNetwork) -> list[str]:
    """Errores de integridad referencial del manifiesto completo.

    Aplica las reglas del §3.3: overrides contra ``devices``, segmentos,
    switches y uplinks existentes, consistencia VLAN/interfaz, IP dentro
    del CIDR del segmento y unicidad global de IP/MAC entre interfaces.
    ``vlan_tag`` es opcional: si no se declara, el puerto queda sin
    etiqueta y no hay VLAN que contrastar. Devuelve la lista de errores
    (vacía si todo es válido).
    """
    config = network.fabric or FabricConfig()
    errors: list[str] = []

    switches: dict[str, FabricSwitch] = {}
    for switch in config.switches:
        if switch.id in switches:
            errors.append(f"El switch '{switch.id}' está declarado más de una vez")
        else:
            switches[switch.id] = switch

    for switch in config.switches:
        if switch.uplink is None:
            continue
        if switch.uplink == switch.id:
            errors.append(
                f"El switch '{switch.id}' no puede tener como uplink a sí mismo"
            )
        elif switch.uplink not in switches:
            errors.append(
                f"El switch '{switch.id}' usa el uplink inexistente '{switch.uplink}'"
            )

    for link in config.links:
        for endpoint in (link.from_, link.to):
            if endpoint not in switches:
                errors.append(
                    f"El enlace '{link.from_}' → '{link.to}' referencia el switch "
                    f"inexistente '{endpoint}'"
                )
        if link.from_ == link.to:
            errors.append(
                f"El enlace '{link.from_}' → '{link.to}' no puede conectar un "
                "switch consigo mismo"
            )

    segments: dict[str, DeceptionSegment] = {s.id: s for s in network.segments}
    devices = {d.id for d in network.devices}
    overrides_seen: set[str] = set()
    ip_owner: dict[str, str] = {}
    mac_owner: dict[str, str] = {}

    for override in config.device_overrides:
        if override.id not in devices:
            errors.append(
                f"El device_override '{override.id}' no coincide con ningún "
                "dispositivo de 'devices'"
            )
        if override.id in overrides_seen:
            errors.append(
                f"El dispositivo '{override.id}' tiene más de un device_override"
            )
        overrides_seen.add(override.id)

        for iface in override.interfaces:
            where = f"El device_override '{override.id}' (interfaz '{iface.name}')"

            segment = segments.get(iface.segment)
            if segment is None:
                errors.append(
                    f"{where} referencia el segmento inexistente '{iface.segment}'"
                )
            elif not topology_svc._ip_in_segment(_ip_address(iface.ip), segment.cidr):
                errors.append(
                    f"{where} tiene la IP '{iface.ip}' fuera del CIDR "
                    f"'{segment.cidr}' del segmento '{iface.segment}'"
                )

            switch = switches.get(iface.switch)
            if switch is None:
                errors.append(
                    f"{where} referencia el switch inexistente '{iface.switch}'"
                )
            elif iface.vlan_tag is not None and iface.vlan_tag not in switch.vlans:
                errors.append(
                    f"{where} usa la VLAN {iface.vlan_tag}, no declarada en el "
                    f"switch '{iface.switch}' (vlans: {switch.vlans})"
                )

            label = f"{override.id}/{iface.name}"
            ip_key = _normalized_ip(iface.ip)
            if ip_key in ip_owner:
                errors.append(
                    f"IP duplicada '{iface.ip}' en '{ip_owner[ip_key]}' y '{label}'"
                )
            else:
                ip_owner[ip_key] = label

            mac_key = _normalized_mac(iface.mac)
            if mac_key in mac_owner:
                errors.append(
                    f"MAC duplicada '{iface.mac}' en '{mac_owner[mac_key]}' y '{label}'"
                )
            else:
                mac_owner[mac_key] = label

    return errors


# ── Construcción de la topología ────────────────────────────


def build_topology(network: DeceptionNetwork) -> FabricTopology:
    """Valida la red y construye la ``FabricTopology``.

    Los mapas computados son deterministas y siguen el orden de
    declaración del manifiesto:

    - ``switch_port_map``: switch → puertos de dispositivo, etiquetados
      como ``"<device_id>:<interfaz>"``. Los enlaces entre switches no
      entran aquí (están en ``config.links``).
    - ``device_switch_map``: device → switch de su primera interfaz (el
      switch primario).

    Lanza ``FabricValidationError`` con todos los errores si la
    validación cruzada falla. Sin bloque ``fabric`` devuelve una
    topología deshabilitada y vacía (compatibilidad hacia atrás).
    """
    config = network.fabric or FabricConfig()
    errors = validate_fabric(network)
    if errors:
        raise FabricValidationError(errors)

    switch_port_map: dict[str, list[str]] = {sw.id: [] for sw in config.switches}
    device_switch_map: dict[str, str] = {}
    for override in config.device_overrides:
        for iface in override.interfaces:
            switch_port_map[iface.switch].append(f"{override.id}:{iface.name}")
        if override.interfaces:
            device_switch_map[override.id] = override.interfaces[0].switch

    return FabricTopology(
        config=config,
        segments=list(network.segments),
        devices=list(network.devices),
        switch_port_map=switch_port_map,
        device_switch_map=device_switch_map,
    )


def parse_manifest(raw_manifest: dict) -> FabricTopology:
    """Valida un manifiesto YAML completo (``network.yaml``) y devuelve su topología.

    Es la puerta de entrada del parser: ``segments``/``devices`` se
    validan con ``DeceptionNetwork`` y el bloque ``fabric`` se cruza
    contra ellos. Acumula en ``FabricValidationError`` tanto los errores
    de esquema del manifiesto como los de integridad referencial.
    """
    if not isinstance(raw_manifest, dict):
        raise FabricValidationError(
            ["El manifiesto debe ser un objeto YAML (mapping), "
             f"no {type(raw_manifest).__name__}"]
        )
    try:
        network = DeceptionNetwork.model_validate(raw_manifest)
    except ValidationError as exc:
        raise FabricValidationError(_format_validation_errors(exc)) from exc
    return build_topology(network)


def load_topology() -> FabricTopology:
    """Construye la topología desde ``config/deception/network.yaml``.

    Reutiliza ``topology_svc.load_network()``, que ya cachea el parseo por
    firma de archivo y escribe de forma atómica; así el parser no duplica
    esa lógica ni puede leer una versión a medio escribir.
    """
    return build_topology(topology_svc.load_network())
