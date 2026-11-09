# Datos cartográficos de terceros

El código propio está bajo MIT; para las licencias de dependencias y honeypots,
consulta [LICENSE-THIRD-PARTY.md](LICENSE-THIRD-PARTY.md).

| Archivos distribuidos | Origen | Licencia |
|---|---|---|
| `web/public/regions/mx.geo.json` (32 entidades) | [Natural Earth, admin-1 states/provinces 1:10m](https://github.com/nvkelso/natural-earth-vector/blob/ca96624a56bd078437bca8184e78163e5039ad19/geojson/ne_10m_admin_1_states_provinces.geojson) | [Dominio público (términos oficiales)](https://www.naturalearthdata.com/about/terms-of-use/) |
| `web/public/regions/ca.geo.json` (13 entidades) | [Natural Earth, admin-1 states/provinces 1:50m](https://github.com/nvkelso/natural-earth-vector/blob/ca96624a56bd078437bca8184e78163e5039ad19/geojson/ne_50m_admin_1_states_provinces.geojson) | [Dominio público (términos oficiales)](https://www.naturalearthdata.com/about/terms-of-use/) |

**Transformación:** [`scripts/build_map_regions.py`](scripts/build_map_regions.py) fija la
revisión upstream `ca96624a56bd078437bca8184e78163e5039ad19`, extrae únicamente los
polígonos admin-1 de cada país, conserva las geometrías originales y reduce las
propiedades a `code` (ISO 3166-2 sin `MX-`/`CA-`) y `name`. En México se omite
la isla menor sin asignación administrativa (`MX-X01~`, sin código ISO ni nombre)
y se actualiza la denominación/código históricos de Distrito Federal (`DIF`)
a Ciudad de México (`CMX`). La escala 1:50m no incluye subdivisiones de México,
por lo que se usa 1:10m para ese país.

Natural Earth permite expresamente la modificación y redistribución comercial
sin atribución obligatoria; se acredita aquí para facilitar su trazabilidad.
