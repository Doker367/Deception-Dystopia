"""Tests de GeoIP, mapa global de ataques y firewall (dry-run)."""

import sys
import threading
import time
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.models.deception import DeceptionEventIn, DeceptionEventType
from app.services.deception import (
    blocklist_svc,
    firewall_svc,
    geo_svc,
    geoip_svc,
    store_svc,
)


@pytest.fixture()
def db_path(tmp_path, monkeypatch):
    monkeypatch.setattr(store_svc, "DB_PATH", tmp_path / "deception.db")


@pytest.fixture()
def block_file(tmp_path, monkeypatch):
    monkeypatch.setattr(blocklist_svc, "BLOCKLIST_FILE", tmp_path / "blocklist.json")


# ── GeoIP ────────────────────────────────────────────────────


def test_geoip_privadas_none():
    assert geoip_svc.lookup("127.0.0.1") is None
    assert geoip_svc.lookup("10.0.0.5") is None
    assert geoip_svc.lookup("no-es-ip") is None


def test_geoip_scope_etiquetas():
    assert geoip_svc.scope("8.8.8.8") == "public"
    assert geoip_svc.scope("10.0.0.5") == "private"
    assert geoip_svc.scope("127.0.0.1") == "loopback"
    assert geoip_svc.scope("203.0.113.9") == "documentation"
    assert geoip_svc.scope("224.0.0.1") == "multicast"
    assert geoip_svc.scope("no-es-ip") == "invalid"
    assert geoip_svc.scope_label("private") == "Red privada"
    assert geoip_svc.describe("203.0.113.9")["scope_label"] == "Reservada · documentación"


@pytest.mark.skipif(not geoip_svc.available(), reason="sin base GeoIP")
def test_geoip_publica():
    geo = geoip_svc.lookup("8.8.8.8")
    assert geo is not None
    assert geo["country_code"] == "US"
    assert geo["lat"] is not None


def test_geoip_unknown_public_ip_gets_an_explicit_approximate_point(monkeypatch):
    monkeypatch.setattr(geoip_svc, "_get_readers", lambda: [])
    monkeypatch.setattr(geoip_svc, "_override_for", lambda _ip: None)
    geo = geoip_svc.lookup("8.8.8.8")
    assert geo is not None
    assert geo["approximate"] is True
    assert geo["country_code"] == "ZZ"
    assert geo["lat"] is not None and geo["lon"] is not None
    # Privadas/documentación siguen fuera del mapa.
    assert geoip_svc.lookup("10.1.2.3") is None


def test_geoip_reader_loading_is_thread_safe(monkeypatch):
    """La primera carga concurrente no debe devolver una lista vacía.

    La UI pide origen/eventos/timeline en paralelo nada más arrancar. Si el
    hilo que abre la base pública ``_readers_loaded`` antes de rellenar la
    lista, el resto ve ``[]`` y cachea "Sin país" para todas las IPs.
    """
    monkeypatch.setattr(geoip_svc, "_reader", None)
    monkeypatch.setattr(geoip_svc, "_readers", [])
    monkeypatch.setattr(geoip_svc, "_readers_loaded", False)
    monkeypatch.setattr(geoip_svc, "_tried", False)

    entered = threading.Event()
    release = threading.Event()

    class SlowReader:
        def __init__(self, _path):
            entered.set()
            release.wait(timeout=5)

    fake_database = types.ModuleType("geoip2.database")
    fake_database.Reader = SlowReader
    fake_package = types.ModuleType("geoip2")
    fake_package.database = fake_database
    monkeypatch.setitem(sys.modules, "geoip2", fake_package)
    monkeypatch.setitem(sys.modules, "geoip2.database", fake_database)
    monkeypatch.setattr(geoip_svc, "_find_dbs", lambda: ["/tmp/fake-GeoLite2-City.mmdb"])

    results: list[list] = []

    def load() -> None:
        results.append(geoip_svc._get_readers())

    first = threading.Thread(target=load)
    first.start()
    assert entered.wait(timeout=5)

    second = threading.Thread(target=load)
    second.start()
    # Da tiempo a que el segundo hilo compruebe el estado antes de publicarlo.
    time.sleep(0.05)
    release.set()

    first.join(timeout=5)
    second.join(timeout=5)
    assert len(results) == 2
    assert all(len(readers) == 1 for readers in results)


def test_geoip_override_file_has_priority(tmp_path, monkeypatch):
    overrides = tmp_path / "geoip-overrides.json"
    overrides.write_text(
        '{"62.217.157.73": {"country_code": "AZ", "country": "Azerbaijan",'
        ' "subdivision": "Baku", "subdivision_code": "BA", "city": "Baku",'
        ' "lat": 40.6253, "lon": 46.9756, "time_zone": "Asia/Baku"}}',
        encoding="utf-8",
    )
    monkeypatch.setenv("NETPULSE_GEOIP_OVERRIDES", str(overrides))
    monkeypatch.setattr(geoip_svc, "_overrides_cache", (None, {}))

    geo = geoip_svc.lookup("62.217.157.73")
    assert geo is not None
    assert geo["country_code"] == "AZ"
    assert geo["city"] == "Baku"
    assert geo["lat"] == 40.6253
    assert geo["location_source"] == "override"


def test_geoip_lookup_fills_missing_fields_from_secondary_sources(monkeypatch):
    class Country:
        iso_code = "MX"
        name = "Mexico"

    class CountryResponse:
        country = Country()
        subdivisions = None
        city = None
        location = None

    class CityResponse:
        country = Country()
        city = type("City", (), {"name": "Tuxtla Gutierrez"})()
        location = type("Location", (), {
            "latitude": 16.7387, "longitude": -93.1414,
            "accuracy_radius": 20, "time_zone": "America/Merida",
        })()
        subdivisions = type("Subs", (), {
            "most_specific": type("Sub", (), {
                "name": "Chiapas", "iso_code": "CHP",
            })(),
        })()

    class Reader:
        def __init__(self, city):
            self._city = city

        def city(self, _ip):
            if self._city is None:
                raise ValueError("not found")
            return self._city

        def country(self, _ip):
            return CountryResponse()

    monkeypatch.setattr(
        geoip_svc, "_get_readers", lambda: [Reader(None), Reader(CityResponse())],
    )
    monkeypatch.setattr(geoip_svc, "_override_for", lambda _ip: None)
    geo = geoip_svc.lookup("187.188.32.206")
    assert geo is not None
    assert geo["country_code"] == "MX"
    assert geo["subdivision_code"] == "CHP"
    assert geo["city"] == "Tuxtla Gutierrez"



# ── Mapa global ──────────────────────────────────────────────


def test_attack_map(db_path):
    store_svc.log_event(DeceptionEventIn(
        device_id="srv-01", src_ip="8.8.8.8", proto="ssh",
        type=DeceptionEventType.LOGIN_ATTEMPT,
    ))
    # IP privada: no debe aparecer en el mapa
    store_svc.log_event(DeceptionEventIn(
        device_id="srv-01", src_ip="10.0.0.9", proto="ssh",
        type=DeceptionEventType.CONNECT,
    ))
    data = geo_svc.attack_map()
    assert "target" in data and "points" in data
    if geoip_svc.available():
        assert any(p["ip"] == "8.8.8.8" for p in data["points"])
        assert all(p["ip"] != "10.0.0.9" for p in data["points"])


# ── Firewall ─────────────────────────────────────────────────


def test_firewall_block_denegado(block_file):
    """El plano de control no muta el firewall del host."""
    with pytest.raises(RuntimeError, match="isolation"):
        firewall_svc.block("203.0.113.9", "test")
    assert not blocklist_svc.is_blocked("203.0.113.9")


def test_firewall_status(block_file):
    st = firewall_svc.status()
    assert st["enabled"] is False
    assert st["applied"] is False
    assert st["blocked"] == []
    assert "reason" in st
