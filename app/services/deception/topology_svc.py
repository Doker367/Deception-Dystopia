"""NetPulse — Deception Topology Service.

Carga, valida y persiste la red señuelo declarada en
``config/deception/network.yaml``: segmentos (VLANs) y dispositivos
simulados con su persona y servicios.

Sigue el patrón de ``app/services/inventory_svc.py``: caché en memoria
por firma mtime/tamaño y escritura atómica (tmp + os.replace).
"""

import copy
import ipaddress
import logging
import os
import tempfile
from typing import Optional

import yaml
from pydantic import ValidationError

from app.core.settings import DECEPTION_NETWORK_FILE
from app.models.deception import (
    EXTERNAL_ENGINES,
    INSTANCE_ID_PATTERN,
    DeceptionDevice,
    DeceptionNetwork,
    DeceptionSegment,
)

logger = logging.getLogger(__name__)

# Ruta del YAML (monkeypatch-able en tests)
NETWORK_FILE = DECEPTION_NETWORK_FILE

DEFAULT_NETWORK = DeceptionNetwork()

# Caché en memoria (parseo único por firma de archivo)
_cache_signature: Optional[tuple] = None
_cache_data: Optional[DeceptionNetwork] = None


def invalidate_cache() -> None:
    """Invalida la caché de topología (tras escrituras o en tests)."""
    global _cache_signature, _cache_data
    _cache_signature = None
    _cache_data = None


def _signature() -> Optional[tuple]:
    if not NETWORK_FILE.exists():
        return None
    st = NETWORK_FILE.stat()
    return (str(NETWORK_FILE), st.st_mtime_ns, st.st_size)


def _read() -> DeceptionNetwork:
    """Lee y valida el YAML, usando la caché si el archivo no cambió."""
    global _cache_signature, _cache_data
    sig = _signature()
    if sig is None:
        return _cache_data or DEFAULT_NETWORK
    if _cache_data is not None and _cache_signature == sig:
        return _cache_data
    try:
        with open(NETWORK_FILE, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        data = DeceptionNetwork.model_validate(raw)
    except (yaml.YAMLError, ValidationError) as exc:
        logger.error("network.yaml inválido (%s); usando caché o vacío", exc)
        return _cache_data or DEFAULT_NETWORK

    _cache_signature = sig
    _cache_data = data
    return data


def _write(network: DeceptionNetwork) -> None:
    """Escritura atómica del YAML (tmp en el mismo dir + os.replace)."""
    NETWORK_FILE.parent.mkdir(parents=True, exist_ok=True)
    clean = network.model_dump(mode="json", exclude_none=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(NETWORK_FILE.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            yaml.safe_dump(clean, f, default_flow_style=False, allow_unicode=True)
        os.replace(tmp_path, NETWORK_FILE)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    finally:
        invalidate_cache()


# ── Lectura ──────────────────────────────────────────────────


def load_network() -> DeceptionNetwork:
    """Devuelve la red señuelo completa (copia profunda)."""
    return copy.deepcopy(_read())


def list_segments() -> list[dict]:
    """Lista segmentos/VLANs."""
    return [s.model_dump(mode="json") for s in _read().segments]


def list_devices() -> list[dict]:
    """Lista dispositivos señuelo."""
    return [d.model_dump(mode="json") for d in _read().devices]


def get_device(device_id: str) -> Optional[dict]:
    """Busca un dispositivo señuelo por id."""
    for d in _read().devices:
        if d.id == device_id:
            return d.model_dump(mode="json")
    return None


def get_segment(segment_id: str) -> Optional[dict]:
    """Busca un segmento por id."""
    for s in _read().segments:
        if s.id == segment_id:
            return s.model_dump(mode="json")
    return None


# ── Binding de honeypots externos (declarativo, sin arranque) ─

_EXTERNAL_VALUES = frozenset(e.value for e in EXTERNAL_ENGINES)


def _ip_in_segment(ip: str, cidr: str) -> bool:
    """True si ``ip`` pertenece al CIDR del segmento (ambos válidos)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == net.version and addr in net


def external_bindings(network: Optional[DeceptionNetwork] = None) -> list[dict]:
    """Vista de configuración de honeypots externos para adaptadores.

    Solo lectura y declarativa: no expone credenciales, no inicia
    servicios ni toca el runtime. Cada servicio señuelo con motor externo
    (cowrie/opencanary/dionaea/heralding/redishoneypot/endlessh) e
    ``instance`` explícita se publica con sus referencias de topología
    (device/segment/persona) resolubles, de modo que el adaptador de ese
    motor pueda correlacionar eventos hacia
    ``{device_id, segment_id, instance_id, persona}``. ``engine``/``instance``
    son los campos de binding; un mismo (engine, instance) puede servir
    varios puertos del mismo dispositivo.
    """
    data = network or _read()
    out: list[dict] = []
    for d in data.devices:
        for s in d.services:
            if s.engine not in EXTERNAL_ENGINES or not s.instance:
                continue
            out.append({
                "engine": s.engine.value,
                "instance": s.instance,
                "device_id": d.id,
                "segment_id": d.segment,
                "device_ip": d.ip,
                "device_enabled": d.enabled,
                "proto": s.proto,
                "port": s.port,
                "banner": s.banner,
                "persona": d.persona.model_dump(mode="json"),
                "tags": list(d.tags),
            })
    return out


def binding_status(network: Optional[DeceptionNetwork] = None) -> dict:
    """Resumen de bindings: cuota vinculada y declaraciones legacy sin instancia."""
    data = network or _read()
    bound = external_bindings(data)
    by_engine: dict[str, int] = {}
    for b in bound:
        by_engine[b["engine"]] = by_engine.get(b["engine"], 0) + 1
    unbound = [
        {"device_id": d.id, "segment_id": d.segment, "engine": s.engine.value,
         "proto": s.proto, "port": s.port}
        for d in data.devices for s in d.services
        if s.engine in EXTERNAL_ENGINES and not s.instance
    ]
    return {
        "bound": len(bound),
        "by_engine": by_engine,
        "instances": sorted({b["instance"] for b in bound}),
        "unbound": unbound,
    }


def resolve_instance(
    instance_id: str, engine: Optional[str] = None,
    network: Optional[DeceptionNetwork] = None,
) -> Optional[dict]:
    """Resuelve (device_id, segment_id, persona) para una instancia señalada.

    Contrato de eventos: ``instance_id`` debe ser siempre resoluble desde
    la topología dirigida por Dystopia. Devuelve ``None`` si la instancia
    no está declarada (o si se filtra por un ``engine`` que no coincide).
    """
    data = network or _read()
    for d in data.devices:
        matches = [
            s for s in d.services
            if s.instance == instance_id
            and (engine is None or s.engine.value == engine)
        ]
        if not matches:
            continue
        engines = sorted({s.engine.value for s in matches})
        return {
            "instance_id": instance_id,
            "engine": engines[0] if len(engines) == 1 else engines,
            "device_id": d.id,
            "segment_id": d.segment,
            "device_ip": d.ip,
            "enabled": d.enabled,
            "persona": d.persona.model_dump(mode="json"),
            "bindings": [
                {"proto": s.proto, "port": s.port, "banner": s.banner}
                for s in matches
            ],
        }
    return None


def validate_topology(network: Optional[DeceptionNetwork] = None) -> dict:
    """Chequeo cruzado de la red señuelo (sin mutar ni desplegar nada).

    Errores: segmento inexistente, IP fuera del CIDR del segmento,
    (puerto, proto) duplicado en un dispositivo, identificador de
    instancia con formato inválido y (engine, instance) repartidos entre
    varios dispositivos. Warnings: motores externos sin ``instance``
    (declaración legacy, hoja no consumible por adaptadores).
    """
    report = _validation_errors(
        network or _read(), devices=None,
        require_instance=False,
    )
    return {"errors": report["errors"], "warnings": report["warnings"]}


def _validation_errors(
    network: DeceptionNetwork,
    devices: Optional[set[str]] = None,
    require_instance: bool = False,
) -> dict:
    """Errores/warnings de la red; errores estrictos solo de ``devices``.

    Los conflictos de instancias (mismo (engine, instance) en dispositivos
    distintos) siempre se reportan: son globales. ``require_instance``
    exige ``instance`` en motores externos del dispositivo afectado.
    """
    errors: list[str] = []
    warnings: list[str] = []
    segments = {s.id: s for s in network.segments}
    for d in network.devices:
        scoped = devices is None or d.id in devices
        if scoped and d.segment not in segments:
            errors.append(f"El dispositivo '{d.id}' referencia el segmento inexistente '{d.segment}'")
        elif scoped and d.segment in segments and not _ip_in_segment(d.ip, segments[d.segment].cidr):
            errors.append(
                f"La IP '{d.ip}' del dispositivo '{d.id}' no pertenece al "
                f"CIDR '{segments[d.segment].cidr}' del segmento '{d.segment}'"
            )
        if scoped:
            seen: set[tuple[int, str]] = set()
            for s in d.services:
                key = (s.port, s.proto)
                if key in seen:
                    errors.append(
                        f"El dispositivo '{d.id}' duplica el servicio "
                        f"{s.proto}/{s.port}"
                    )
                seen.add(key)
        for s in d.services:
            if s.engine not in EXTERNAL_ENGINES:
                continue
            if s.instance:
                if not INSTANCE_ID_PATTERN.fullmatch(s.instance):
                    errors.append(
                        f"Identificador de instancia inválido '{s.instance}' "
                        f"en el dispositivo '{d.id}'"
                    )
            elif require_instance and scoped:
                errors.append(
                    f"El servicio {s.engine.value} '{s.proto}/{s.port}' del "
                    f"dispositivo '{d.id}' requiere una 'instance' explícita "
                    "para el binding a honeypot externo"
                )
            elif not s.instance:
                warnings.append(
                    f"El servicio {s.engine.value} '{s.proto}/{s.port}' del "
                    f"dispositivo '{d.id}' no declara 'instance' "
                    "(sin binding a adaptador externo)"
                )
    owner: dict[tuple[str, str], str] = {}
    for d in network.devices:
        for s in d.services:
            if s.engine not in EXTERNAL_ENGINES or not s.instance:
                continue
            key = (s.engine.value, s.instance)
            if key in owner and owner[key] != d.id and (
                devices is None or d.id in devices or owner[key] in devices
            ):
                errors.append(
                    f"La instancia '{key[0]}/{key[1]}' ya está vinculada al "
                    f"dispositivo '{owner[key]}' (conflicto con '{d.id}')"
                )
            owner.setdefault(key, d.id)
    return {"errors": errors, "warnings": warnings}


# ── Escritura (CRUD) ─────────────────────────────────────────


def add_device(device: DeceptionDevice | dict) -> dict:
    """Agrega un dispositivo señuelo (valida y persiste)."""
    new = device if isinstance(device, DeceptionDevice) else DeceptionDevice(**device)
    network = copy.deepcopy(_read())
    if any(d.id == new.id for d in network.devices):
        raise ValueError(f"El dispositivo señuelo '{new.id}' ya existe")
    if new.segment and not any(s.id == new.segment for s in network.segments):
        raise ValueError(f"El segmento '{new.segment}' no existe")
    network.devices.append(new)
    report = _validation_errors(network, devices={new.id}, require_instance=True)
    if report["errors"]:
        raise ValueError("; ".join(report["errors"]))
    _write(network)
    return new.model_dump(mode="json")


def update_device(device_id: str, updates: dict) -> Optional[dict]:
    """Actualiza un dispositivo señuelo existente."""
    network = copy.deepcopy(_read())
    for i, d in enumerate(network.devices):
        if d.id != device_id:
            continue
        merged = d.model_dump(mode="python")
        merged.update({k: v for k, v in updates.items() if v is not None})
        merged["id"] = device_id
        try:
            updated = DeceptionDevice.model_validate(merged)
        except ValidationError as exc:
            raise ValueError(str(exc)) from exc
        if updated.segment and not any(s.id == updated.segment for s in network.segments):
            raise ValueError(f"El segmento '{updated.segment}' no existe")
        network.devices[i] = updated
        # En updates, la instancia faltante es warning (devices legados
        # permanecen editables); los errores estrictos siguen aplicando.
        report = _validation_errors(network, devices={device_id},
                                    require_instance=False)
        if report["errors"]:
            raise ValueError("; ".join(report["errors"]))
        _write(network)
        return updated.model_dump(mode="json")
    return None


def delete_device(device_id: str) -> bool:
    """Elimina un dispositivo señuelo."""
    network = copy.deepcopy(_read())
    original = len(network.devices)
    network.devices = [d for d in network.devices if d.id != device_id]
    if len(network.devices) < original:
        _write(network)
        return True
    return False


def add_segment(segment: DeceptionSegment | dict) -> dict:
    """Agrega un segmento/VLAN."""
    new = segment if isinstance(segment, DeceptionSegment) else DeceptionSegment(**segment)
    try:
        ipaddress.ip_network(new.cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"CIDR inválido para el segmento '{new.id}': {exc}") from exc
    network = copy.deepcopy(_read())
    if any(s.id == new.id for s in network.segments):
        raise ValueError(f"El segmento '{new.id}' ya existe")
    network.segments.append(new)
    _write(network)
    return new.model_dump(mode="json")


def delete_segment(segment_id: str) -> bool:
    """Elimina un segmento si no tiene dispositivos asociados."""
    network = copy.deepcopy(_read())
    if any(d.segment == segment_id for d in network.devices):
        raise ValueError(f"El segmento '{segment_id}' tiene dispositivos asociados")
    original = len(network.segments)
    network.segments = [s for s in network.segments if s.id != segment_id]
    if len(network.segments) < original:
        _write(network)
        return True
    return False


# ── Resumen ──────────────────────────────────────────────────


def summary() -> dict:
    """Conteo de segmentos y dispositivos (total/habilitados) por rol."""
    network = _read()
    by_role: dict[str, int] = {}
    for d in network.devices:
        by_role[d.role.value] = by_role.get(d.role.value, 0) + 1
    bindings = binding_status(network)
    return {
        "segments": len(network.segments),
        "devices": len(network.devices),
        "devices_enabled": sum(1 for d in network.devices if d.enabled),
        "by_role": by_role,
        "external_bound": bindings["bound"],
        "external_unbound": len(bindings["unbound"]),
    }


# ── Sync desde NetBox ────────────────────────────────────────

_ROLE_HINTS = {
    "firewall": "firewall", "fortigate": "firewall", "palo": "firewall",
    "switch": "switch", "catalyst": "switch", "nexus": "switch",
    "camera": "camera", "cam": "camera", "hikvision": "camera",
    "server": "server", "poweredge": "server", "proliant": "server",
    "router": "router", "isr": "router", "mikrotik": "router",
}

_DEFAULT_SERVICES = {
    "pc": [{"port": 22, "proto": "ssh"}, {"port": 80, "proto": "http"}],
    "server": [{"port": 22, "proto": "ssh"}, {"port": 445, "proto": "smb"}],
    "camera": [{"port": 80, "proto": "http"}, {"port": 554, "proto": "rtsp"}],
    "switch": [{"port": 22, "proto": "ssh"}, {"port": 161, "proto": "snmp"}],
    "firewall": [{"port": 443, "proto": "https"}, {"port": 22, "proto": "ssh"}],
    "router": [{"port": 22, "proto": "ssh"}, {"port": 161, "proto": "snmp"}],
}


def _role_from_model(model: Optional[str]) -> str:
    text = (model or "").lower()
    for hint, role in _ROLE_HINTS.items():
        if hint in text:
            return role
    return "pc"


def sync_from_netbox() -> dict:
    """Compatibility endpoint: NetBox sync is intentionally unavailable."""
    return {"success": False, "disabled": True, "reason": "standalone Dystopia"}
