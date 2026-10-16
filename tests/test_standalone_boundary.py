"""Frontera de Dystopia: independiente del NOC y fail-closed por defecto.

Prueba estática/sin red: inspecciona enrutado, defaults y disponibilidad de
módulos. No abre sockets, no arranca listeners y no contacta ningún equipo.

Nota: FastAPI 0.141 envuelve los routers incluidos en ``_IncludedRouter``, por
lo que ``app.routes`` no los aplana; se usa ``app.openapi()`` para las rutas.
"""

import importlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Superficie de administración de red real: no debe existir en Dystopia.
FORBIDDEN_PREFIXES = (
    "/api/devices",
    "/api/facts",
    "/api/config",
    "/api/bulk",
    "/api/netbox",
    "/api/command",
    "/api/templates",
    "/api/compliance",
    "/api/groups",
    "/api/scheduler",
    "/api/export",
    "/api/topology",
    "/api/traffic",
    "/api/ops",
    "/api/collectors",
    "/api/system",
    "/api/sftp",
    "/api/firewall",
)

# Módulos que pertenecen al NOC y que Dystopia ya no debe poder importar.
FORBIDDEN_MODULES = (
    "app.services.napalm_svc",
    "app.services.netmiko_svc",
    "app.services.nornir_svc",
    "app.services.fortios_svc",
    "app.services.sftp_svc",
    "app.services.inventory_svc",
    "app.services.scheduler_svc",
    "app.services.ops.health_svc",
    "app.services.integrations.netbox_sync",
)

# Este archivo menciona rutas de otros productos a propósito al definir la
# frontera, por lo que se excluye del escaneo de rutas cruzadas.
_SELF = Path(__file__).resolve()


def _http_paths() -> set[str]:
    from app.main import app

    return set(app.openapi().get("paths", {}))


def test_no_noc_routes_registered():
    leaked = sorted(
        path
        for path in _http_paths()
        if any(path.startswith(prefix) for prefix in FORBIDDEN_PREFIXES)
    )
    assert leaked == [], f"rutas del NOC dentro de Dystopia: {leaked}"


def test_deception_surface_present():
    paths = _http_paths()
    assert any(p.startswith("/api/deception") for p in paths), "falta /api/deception"
    assert any(p.startswith("/api/vms") for p in paths), "falta /api/vms"
    assert any(p.startswith("/api/auth") for p in paths), "falta auth propia"


def test_noc_modules_are_not_importable():
    for module in FORBIDDEN_MODULES:
        try:
            importlib.import_module(module)
        except ModuleNotFoundError:
            continue
        raise AssertionError(f"Dystopia no debe incluir {module}")


def test_fail_closed_defaults():
    from app.core import settings

    assert settings.API_HOST == "127.0.0.1"
    assert settings.SYSLOG_ENABLED is False
    assert settings.METRICS_ENABLED is False
    assert settings.VMS_ENABLED is False
    assert settings.DECEPTION_ENABLED is False
    assert settings.FIREWALL_ENABLED is False


def test_no_shared_paths_with_the_other_product():
    """Ningún archivo propio debe apuntar a rutas del NOC o del original."""
    offenders = []
    for path in ROOT.rglob("*.py"):
        if ".git" in path.parts or path.resolve() == _SELF:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for needle in ("/Users/doker/Netpulse", "/Users/doker/netpulse-noc"):
            if needle in text:
                offenders.append(f"{path}: {needle}")
    assert offenders == [], f"rutas cruzadas: {offenders}"
