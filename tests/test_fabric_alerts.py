"""Pruebas de las alertas específicas del fabric (Fase 7).

SQLite temporal y cooldown aislado por test. Cubren primer contacto,
cooldown, lateral movement entre VLANs, misma VLAN, ventana expirada,
topología ausente y ausencia de credenciales en las alertas.
"""

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.models.deception import DeceptionEventIn  # noqa: E402
from app.services.deception import alert_svc, store_svc  # noqa: E402
from app.services.fabric import fabric_alerts  # noqa: E402
from app.services.fabric.parser import parse_manifest  # noqa: E402


def _manifest() -> dict:
    """Dos VLANs con un dispositivo cada una."""
    return {
        "segments": [
            {"id": "vlan-10", "vlan_id": 10, "cidr": "10.10.0.0/24"},
            {"id": "vlan-20", "vlan_id": 20, "cidr": "10.20.0.0/24"},
        ],
        "devices": [
            {"id": "pc-01", "role": "pc", "segment": "vlan-10", "ip": "10.10.0.21"},
            {"id": "srv-01", "role": "server", "segment": "vlan-20", "ip": "10.20.0.10"},
        ],
        "fabric": {
            "enabled": True,
            "switches": [{"id": "sw-a", "vlans": [10, 20]}],
            "device_overrides": [],
        },
    }


def _store_event(device_id: str, src_ip: str, *, event_type: str = "connect",
                 ts: str | None = None, detail: dict | None = None) -> dict:
    return store_svc.log_event(DeceptionEventIn(
        device_id=device_id, src_ip=src_ip, proto="ssh",
        type=event_type, ts=ts, detail=detail or {},
    ))


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    """Store temporal y cooldown de alertas vacío."""
    monkeypatch.setattr(store_svc, "DB_PATH", tmp_path / "deception.db")
    alert_svc._last_fired.clear()
    yield
    alert_svc._last_fired.clear()


@pytest.fixture()
def topology():
    return parse_manifest(_manifest())


# ── fabric_new_device_probed ────────────────────────────────


def test_primer_evento_genera_alerta(topology):
    record = _store_event("pc-01", "203.0.113.9")
    fired = fabric_alerts.evaluate(record, topology)
    assert len(fired) == 1
    alert = fired[0]
    assert alert["rule"] == "fabric_new_device_probed"
    assert alert["severity"] == "medium"
    assert alert["device_id"] == "pc-01"
    assert alert["src_ip"] == "203.0.113.9"


def test_segundo_evento_mismo_device_sin_alerta(topology):
    _store_event("pc-01", "203.0.113.9")
    second = _store_event("pc-01", "203.0.113.10")  # otro atacante
    fired = fabric_alerts.evaluate(second, topology)
    assert fired == []  # ya no es el primer contacto


def test_cooldown_por_regla_y_src_ip(topology):
    # Lateral movement: mismo atacante en dos VLANs.
    _store_event("pc-01", "203.0.113.9")            # VLAN 10
    _store_event("srv-01", "203.0.113.9")           # VLAN 20
    record = _store_event("srv-01", "203.0.113.9", event_type="login_attempt")
    first = fabric_alerts.evaluate(record, topology)
    assert any(alert["rule"] == "fabric_lateral_movement" for alert in first)

    # Repetición inmediata del mismo (regla, src_ip): silenciada por cooldown.
    again = _store_event("pc-01", "203.0.113.9")
    second = fabric_alerts.evaluate(again, topology)
    assert not any(alert["rule"] == "fabric_lateral_movement" for alert in second)


# ── fabric_lateral_movement ─────────────────────────────────


def test_lateral_movement_dos_vlans(topology):
    _store_event("pc-01", "198.51.100.7")            # VLAN 10
    record = _store_event("srv-01", "198.51.100.7")  # VLAN 20
    fired = fabric_alerts.evaluate(record, topology)
    lateral = [alert for alert in fired if alert["rule"] == "fabric_lateral_movement"]
    assert len(lateral) == 1
    alert = lateral[0]
    assert alert["severity"] == "high"
    assert alert["device_id"] is None  # cooldown por (regla, src_ip)
    assert alert["detail"]["vlans"] == [10, 20]


def test_mismo_src_ip_misma_vlan_sin_alerta(topology):
    _store_event("pc-01", "198.51.100.7")
    record = _store_event("pc-01", "198.51.100.7", event_type="login_attempt")
    fired = fabric_alerts.evaluate(record, topology)
    assert not any(alert["rule"] == "fabric_lateral_movement" for alert in fired)


def test_ventana_expirada_sin_alerta(topology):
    old_ts = "2020-01-01T00:00:00+00:00"
    _store_event("pc-01", "198.51.100.7", ts=old_ts)
    record = _store_event("srv-01", "198.51.100.7")
    fired = fabric_alerts.evaluate(record, topology)
    assert not any(alert["rule"] == "fabric_lateral_movement" for alert in fired)


def test_ventana_personalizada(topology):
    _store_event("pc-01", "198.51.100.7", ts="2020-01-01T00:00:00+00:00")
    record = _store_event("srv-01", "198.51.100.7")
    # Con una ventana enorme, el evento viejo vuelve a contar.
    fired = fabric_alerts.evaluate(record, topology, window=10**9)
    assert any(alert["rule"] == "fabric_lateral_movement" for alert in fired)


def test_sin_topologia_no_rompe_y_sigue_el_primer_contacto():
    record = _store_event("pc-01", "203.0.113.9")
    fired = fabric_alerts.evaluate(record, None)
    assert [alert["rule"] for alert in fired] == ["fabric_new_device_probed"]


def test_lote_deduplica_consultas(topology):
    records = [
        _store_event("pc-01", "203.0.113.9"),
        _store_event("pc-01", "203.0.113.9", event_type="login_attempt"),
    ]
    fired = fabric_alerts.evaluate_batch(records, topology)
    # Solo la primera aparición del device genera la alerta de primer contacto.
    assert [alert["rule"] for alert in fired] == ["fabric_new_device_probed"]


# ── Sin credenciales en las alertas ─────────────────────────


def test_alertas_sin_credenciales(topology):
    record = _store_event(
        "pc-01", "203.0.113.9", event_type="login_success",
        detail={"service": "ssh", "password": "admin123",
                "credentials": {"username": "admin", "password": "admin123"}},
    )
    fired = fabric_alerts.evaluate(record, topology)
    assert fired
    for alert in fired:
        text = json.dumps(alert, ensure_ascii=False)
        assert "admin123" not in text
        assert "password" not in text
        assert "credentials" not in text
        assert alert["detail"] in ({}, {"vlans": [10], "device_id": "pc-01"})


def test_despacho_registrado_en_auditoria(topology):
    record = _store_event("pc-01", "203.0.113.9")
    fired = fabric_alerts.evaluate(record, topology)
    assert fired
    events = alert_svc.recent(limit=10)
    assert any(event.get("action") == "deception_alert" for event in events)
