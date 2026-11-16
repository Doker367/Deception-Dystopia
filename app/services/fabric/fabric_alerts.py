"""NetPulse — Fabric: alertas específicas del fabric (Fase 7).

Dos reglas sobre los eventos que llegan por ``POST /api/fabric/events``:

- ``fabric_new_device_probed`` (severidad **media**): primer evento
  registrado para un ``device_id`` del fabric (consulta al store).
- ``fabric_lateral_movement`` (severidad **alta**): el mismo ``src_ip``
  aparece en dispositivos de **≥ 2 VLANs distintas** dentro de una ventana
  (default 10 min). Usa el mapa device→VLAN de la topología y consulta el
  store por ``src_ip`` reciente.

El cooldown y el dispatch (métricas + auditoría + notificaciones) se
reutilizan de ``alert_svc.dispatch_external``; una regla por atacante fija
``device_id=None`` para silenciarse por ``(regla, src_ip)``. Las alertas
**nunca** incluyen credenciales capturadas: solo device_id, src_ip, proto
y las VLANs implicadas.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

from app.services.deception import alert_svc, store_svc
from app.services.fabric.models import FabricTopology

logger = logging.getLogger(__name__)

RULE_NEW_DEVICE = "fabric_new_device_probed"
RULE_LATERAL_MOVEMENT = "fabric_lateral_movement"
LATERAL_WINDOW = 600.0  # segundos (10 min); env DYSTOPIA_FABRIC_LATERAL_WINDOW
LATERAL_WINDOW_ENV = "DYSTOPIA_FABRIC_LATERAL_WINDOW"
MAX_LOOKUP = 200  # eventos revisados por consulta al store


def lateral_window() -> float:
    """Ventana de lateral movement configurable por entorno."""
    raw = os.getenv(LATERAL_WINDOW_ENV, str(LATERAL_WINDOW))
    try:
        return max(1.0, float(raw))
    except ValueError:
        return LATERAL_WINDOW


def _parse_ts(value) -> Optional[float]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _vlan_map(topology: Optional[FabricTopology]) -> dict[str, Optional[int]]:
    """device_id → vlan_id del segmento declarado (None si no participa)."""
    if topology is None:
        return {}
    segments = {segment.id: segment.vlan_id for segment in topology.segments}
    return {device.id: segments.get(device.segment) for device in topology.devices}


def _is_first_event(record: dict) -> bool:
    """True si este registro es el primer evento del device en el store.

    Compara por id (el lote ya está almacenado cuando se evalúa, así que el
    conteo no basta para detectar el primer contacto de un lote grande).
    Sin id en el registro (embeddings/sinks falsos) usa la heurística de
    conteo.
    """
    device_id = record.get("device_id")
    record_id = record.get("id")
    events = store_svc.get_events(device_id=device_id, limit=MAX_LOOKUP)
    ids = [
        event.get("id") for event in events
        if isinstance(event.get("id"), int)
    ]
    if isinstance(record_id, int):
        return bool(ids) and record_id == min(ids)
    return len(ids) <= 1


def _vlans_for_src(
    src_ip: str,
    topology: Optional[FabricTopology],
    window: float,
) -> set[int]:
    """VLANs distintas donde el atacante apareció dentro de la ventana."""
    vlan_by_device = _vlan_map(topology)
    if not vlan_by_device:
        return set()
    cutoff = time.time() - window
    vlans: set[int] = set()
    for event in store_svc.get_events(src_ip=src_ip, limit=MAX_LOOKUP):
        ts = _parse_ts(event.get("timestamp"))
        if ts is None:
            continue
        if ts < cutoff:
            break  # vienen ordenados desc por id; el resto es más viejo
        vlan = vlan_by_device.get(event.get("device_id"))
        if vlan is not None:
            vlans.add(vlan)
    return vlans


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_device_alert(record: dict) -> dict:
    device_id = record.get("device_id")
    return {
        "rule": RULE_NEW_DEVICE,
        "severity": "medium",
        "title": "Primer contacto con dispositivo del fabric",
        "message": (
            f"[MEDIUM] Primer contacto con el dispositivo señuelo '{device_id}' "
            f"desde {record.get('src_ip')} ({record.get('proto')})"
        ),
        "device_id": device_id,
        "src_ip": record.get("src_ip"),
        "proto": record.get("proto"),
        "username": None,
        "detail": {},  # credenciales capturadas: solo en el store, nunca aquí
        "timestamp": _now(),
    }


def _lateral_alert(record: dict, vlans: set[int]) -> dict:
    return {
        "rule": RULE_LATERAL_MOVEMENT,
        "severity": "high",
        "title": "Movimiento lateral entre VLANs del fabric",
        "message": (
            f"[HIGH] El atacante {record.get('src_ip')} apareció en las VLANs "
            f"{sorted(vlans)} del fabric (último: '{record.get('device_id')}')"
        ),
        "device_id": None,  # cooldown por (regla, src_ip), no por dispositivo
        "src_ip": record.get("src_ip"),
        "proto": record.get("proto"),
        "username": None,
        "detail": {"vlans": sorted(vlans), "device_id": record.get("device_id")},
        "timestamp": _now(),
    }


def _detect(
    records: list[dict],
    topology: Optional[FabricTopology],
    window: float,
) -> list[dict]:
    """Reglas sobre un lote; deduplica consultas por device/src_ip."""
    alerts: list[dict] = []
    seen_devices: set[str] = set()
    seen_ips: set[str] = set()
    for record in records:
        device_id = record.get("device_id")
        src_ip = record.get("src_ip")
        if not device_id or not src_ip:
            continue
        if device_id not in seen_devices:
            seen_devices.add(device_id)
            if _is_first_event(record):
                alerts.append(_new_device_alert(record))
        if src_ip not in seen_ips:
            seen_ips.add(src_ip)
            vlans = _vlans_for_src(src_ip, topology, window)
            if len(vlans) >= 2:
                alerts.append(_lateral_alert(record, vlans))
    return alerts


def evaluate_batch(
    records: list[dict],
    topology: Optional[FabricTopology] = None,
    window: Optional[float] = None,
) -> list[dict]:
    """Detecta y despacha las alertas del fabric para un lote de eventos.

    El fallo del dispatch se registra y devuelve ``[]``: la ingesta nunca
    se tumba por las alertas.
    """
    alerts = _detect(records, topology, window if window is not None else lateral_window())
    if not alerts:
        return []
    try:
        return alert_svc.dispatch_external(alerts)
    except Exception as exc:  # noqa: BLE001 - las alertas no tumban la ingesta
        logger.warning("[fabric] dispatch de alertas falló: %s", exc)
        return []


def evaluate(
    record: dict,
    topology: Optional[FabricTopology] = None,
    window: Optional[float] = None,
) -> list[dict]:
    """Evalúa un único evento almacenado (conveniencia)."""
    return evaluate_batch([record], topology, window)


def _dump(alert: dict) -> str:  # pragma: no cover - utilidad de depuración
    return json.dumps(alert, ensure_ascii=False)
