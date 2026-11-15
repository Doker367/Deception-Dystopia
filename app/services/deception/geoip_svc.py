"""NetPulse — GeoIP offline (MaxMind GeoLite2).

Resuelve país/ciudad/coordenadas de una IP usando una base MaxMind local
(.mmdb). Por defecto autodetecta la incluida en el paquete
``maxminddb-geolite2`` o la que el despliegue monte en
``config/geoip``/``deploy/local/geoip`` (sin servicios externos). Si no hay
base, el servicio queda deshabilitado y devuelve None para IPs públicas.

Además de la geolocalización, clasifica el *ámbito* de la IP (pública,
privada, loopback, documentación…) para que la consola no muestre una celda
vacía cuando una dirección no puede geolocalizarse por diseño.
"""

import glob
import ipaddress
import logging
import os
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_reader = None
_lock = threading.Lock()
_tried = False

# Rangos de documentación (RFC 5737 / RFC 3849). Python los marca como
# ``is_private``, pero para el operador son direcciones de ejemplo, no una
# red interna real.
_DOCUMENTATION_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

_SCOPE_LABEL = {
    "public": "Pública",
    "private": "Red privada",
    "loopback": "Loopback local",
    "link_local": "Enlace local",
    "documentation": "Reservada · documentación",
    "multicast": "Multicast",
    "unspecified": "No especificada",
    "invalid": "IP inválida",
}

# Centroides aproximados por país. Se usan solo cuando MaxMind conoce el
# país pero no entrega coordenadas (bases Country-only o registros parciales),
# de modo que el mapa pueda pintar el origen sin inventar una ciudad.
_CENTROIDS_RAW = """
US 39.8 -98.6
CA 56.1 -106.3
MX 23.6 -102.5
BR -14.2 -51.9
AR -38.4 -63.6
CL -35.7 -71.5
CO 4.6 -74.3
PE -9.2 -75.0
VE 6.4 -66.6
EC -1.8 -78.2
BO -16.3 -63.6
PY -23.4 -58.4
UY -32.5 -55.8
CR 9.7 -83.8
PA 8.5 -80.8
GT 15.8 -90.2
HN 15.2 -86.2
SV 13.8 -88.9
NI 12.9 -85.2
DO 18.7 -70.2
CU 21.5 -77.8
PR 18.2 -66.6
GB 54.0 -2.0
IE 53.4 -8.2
FR 46.2 2.2
DE 51.2 10.4
NL 52.1 5.3
BE 50.5 4.5
LU 49.8 6.1
ES 40.5 -3.7
PT 39.4 -8.2
IT 41.9 12.6
CH 46.8 8.2
AT 47.5 14.6
SE 60.1 18.6
NO 60.5 8.5
DK 56.3 9.5
FI 61.9 25.7
IS 64.9 -19.0
PL 51.9 19.1
CZ 49.8 15.5
SK 48.7 19.7
HU 47.2 19.5
RO 45.9 24.9
BG 42.7 25.5
GR 39.1 21.8
TR 38.9 35.2
RU 61.5 60.0
UA 48.4 31.2
BY 53.7 27.9
RS 44.0 21.0
HR 45.1 15.2
SI 46.2 15.0
BA 43.9 17.7
AL 41.2 20.2
MK 41.6 21.7
ME 42.7 19.4
XK 42.6 20.9
IL 31.0 34.9
SA 23.9 45.1
AE 24.0 54.0
QA 25.3 51.2
KW 29.3 47.5
BH 26.0 50.6
OM 21.0 57.0
JO 31.2 36.8
LB 33.9 35.9
EG 26.8 30.8
ZA -30.6 22.9
NG 9.1 8.7
KE -0.0 37.9
MA 31.8 -7.1
DZ 28.0 1.7
TN 33.9 9.5
LY 26.3 17.2
ET 9.1 40.5
GH 7.9 -1.0
CI 7.5 -5.5
SN 14.5 -14.5
CM 3.9 11.5
UG 1.4 32.3
TZ -6.4 34.9
CN 35.9 104.2
JP 36.2 138.3
KR 36.5 127.9
KP 40.3 127.5
IN 20.6 79.0
ID -0.8 113.9
VN 14.1 108.3
TH 15.9 101.0
MY 4.2 101.9
SG 1.35 103.8
PH 12.9 121.8
BN 4.5 114.7
KH 12.6 104.9
LA 19.9 102.5
MM 21.9 95.9
AU -25.3 133.8
NZ -40.9 174.9
PK 30.4 69.3
BD 23.7 90.4
LK 7.9 80.8
NP 28.4 84.1
BT 27.5 90.4
MV 3.2 73.2
TW 23.7 121.0
HK 22.3 114.2
MO 22.2 113.5
KZ 48.0 66.9
UZ 41.4 64.6
KG 41.2 74.8
TJ 38.9 71.3
TM 38.9 59.6
AZ 40.1 47.6
GE 42.3 43.4
AM 40.1 45.0
IR 32.4 53.7
IQ 33.2 43.7
AF 33.9 67.7
MN 46.9 103.8
FJ -17.7 178.1
PG -6.3 143.9
SB -9.6 160.2
VU -15.4 166.9
NC -20.9 165.6
PF -17.7 -149.4
GL 71.7 -42.6
FO 61.9 -6.9
MT 35.9 14.4
CY 35.1 33.4
MD 47.4 28.4
EE 58.6 25.0
LV 56.9 24.6
LT 55.2 23.9
BY 53.7 27.9
GE 42.3 43.4
"""

COUNTRY_CENTROIDS: dict[str, tuple[float, float]] = {}
for _line in _CENTROIDS_RAW.strip().splitlines():
    _parts = _line.split()
    if len(_parts) == 3:
        try:
            COUNTRY_CENTROIDS[_parts[0].upper()] = (float(_parts[1]), float(_parts[2]))
        except ValueError:  # pragma: no cover - defensa ante edición manual
            pass


def _find_db() -> Optional[str]:
    """Localiza la base City/Country más específica disponible en el host."""
    from app.core.settings import BASE_DIR, CONFIG_DIR, GEOIP_DB

    candidates: list[Path] = []
    if GEOIP_DB:
        candidates.append(Path(GEOIP_DB).expanduser())

    directories = [
        CONFIG_DIR,
        CONFIG_DIR / "geoip",
        BASE_DIR / "config" / "geoip",
        BASE_DIR / "deploy" / "local" / "geoip",
    ]
    extra_dir = os.getenv("NETPULSE_GEOIP_DIR", "").strip()
    if extra_dir:
        directories.insert(0, Path(extra_dir).expanduser())

    # Preferir City (ciudad + coordenadas) sobre Country.
    names = (
        "GeoLite2-City.mmdb", "GeoIP2-City.mmdb",
        "GeoLite2-Country.mmdb", "GeoIP2-Country.mmdb",
    )
    for directory in directories:
        for name in names:
            candidates.append(directory / name)

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    # Fallback: bases incluidas por paquetes Python. El paquete
    # ``maxminddb-geolite2`` expone el directorio ``_maxminddb_geolite2`` y
    # ``geoip2`` vive junto a él dentro de site-packages.
    for module_name in ("_maxminddb_geolite2", "maxminddb_geolite2", "geoip2"):
        try:
            module = __import__(module_name)
        except Exception:  # noqa: BLE001
            continue
        package_dir = Path(module.__file__).resolve().parent
        roots = [package_dir]
        if module_name == "geoip2":
            roots.append(package_dir.parent)
        found: list[str] = []
        for root in roots:
            found.extend(
                path for path in glob.glob(str(root / "**" / "*.mmdb"), recursive=True)
                if path.lower().endswith(".mmdb")
            )
        if not found:
            continue

        def _rank(path: str) -> tuple[int, int]:
            lowered = os.path.basename(path).lower()
            city = 0 if "city" in lowered else 1
            country = 0 if "country" in lowered else 1
            return city, country

        return sorted(set(found), key=_rank)[0]
    return None


def _get_reader():
    global _reader, _tried
    if _reader is not None or _tried:
        return _reader
    with _lock:
        if _reader is not None or _tried:
            return _reader
        _tried = True
        db = _find_db()
        if not db:
            logger.info("[geoip] sin base .mmdb; GeoIP deshabilitado")
            return None
        try:
            import geoip2.database  # type: ignore

            _reader = geoip2.database.Reader(db)
            logger.info("[geoip] base cargada: %s", db)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[geoip] no se pudo abrir la base: %s", exc)
    return _reader


def available() -> bool:
    """True si hay una base GeoIP cargada."""
    return _get_reader() is not None


def scope(ip: str) -> str:
    """Clasifica el ámbito de una IP sin consultar la base.

    Returns:
        ``public``, ``private``, ``loopback``, ``link_local``,
        ``documentation``, ``multicast``, ``unspecified`` o ``invalid``.
    """
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return "invalid"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if any(addr in network for network in _DOCUMENTATION_NETS):
        return "documentation"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private:
        return "private"
    return "public"


def scope_label(value: str) -> str:
    """Etiqueta en español para un ámbito de ``scope()``."""
    return _SCOPE_LABEL.get(value, "Sin clasificar")


def _centroid(country_code: Optional[str]) -> Optional[tuple[float, float]]:
    if not country_code:
        return None
    return COUNTRY_CENTROIDS.get(str(country_code).upper())


def lookup(ip: str) -> Optional[dict]:
    """Geolocaliza una IP pública.

    Returns:
        ``{country_code, country, subdivision, subdivision_code, city, lat,
        lon, accuracy_radius, time_zone, location_source}`` o None si es
        privada, inválida o no está en la base.
    """
    if scope(ip) != "public":
        return None

    reader = _get_reader()
    if reader is None:
        return None

    for method in ("city", "country"):
        try:
            resp = getattr(reader, method)(ip)
        except Exception:  # noqa: BLE001
            continue
        country = getattr(resp, "country", None)
        if country is None or not country.iso_code:
            continue
        result = {
            "country_code": country.iso_code.upper(),
            "country": country.name or country.iso_code,
            "subdivision": None,
            "subdivision_code": None,
            "city": None,
            "lat": None,
            "lon": None,
            "accuracy_radius": None,
            "time_zone": None,
            "location_source": "maxmind",
        }
        try:
            subdivisions = getattr(resp, "subdivisions", None)
            most = getattr(subdivisions, "most_specific", None) if subdivisions else None
            if most is not None:
                result["subdivision"] = most.name
                result["subdivision_code"] = most.iso_code
        except Exception:  # noqa: BLE001
            pass
        city = getattr(resp, "city", None)
        if city is not None:
            result["city"] = city.name
        loc = getattr(resp, "location", None)
        if loc is not None:
            result["lat"] = loc.latitude
            result["lon"] = loc.longitude
            result["accuracy_radius"] = getattr(loc, "accuracy_radius", None)
            result["time_zone"] = getattr(loc, "time_zone", None)
        if result["lat"] is None or result["lon"] is None:
            centroid = _centroid(result["country_code"])
            if centroid is not None:
                result["lat"], result["lon"] = centroid
                result["location_source"] = "country_centroid"
        return result
    return None


def describe(ip: str) -> dict:
    """Resumen apto para la consola, incluso si la IP no es geolocalizable."""
    kind = scope(ip)
    if kind != "public":
        return {
            "scope": kind,
            "scope_label": scope_label(kind),
            "country_code": None,
            "country": None,
            "city": None,
            "subdivision": None,
            "lat": None,
            "lon": None,
        }
    geo = lookup(ip)
    if geo is None:
        return {
            "scope": "public",
            "scope_label": "Sin geolocalización",
            "country_code": None,
            "country": None,
            "city": None,
            "subdivision": None,
            "lat": None,
            "lon": None,
        }
    return {"scope": "public", "scope_label": geo.get("country") or "Pública", **geo}
