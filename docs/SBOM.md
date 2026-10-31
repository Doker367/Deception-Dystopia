# SBOM de la cadena de suministro offline

## Qué se generó

Dos documentos **CycloneDX 1.6 JSON**, uno por lock, a partir de los wheels
reales descargados para CPython 3.12 / Linux amd64 (`manylinux_2_28`):

| Archivo | Bundle de origen | Componentes | SHA-256 del SBOM |
| --- | --- | --- | --- |
| `deploy/sbom/control-cyclonedx.json` | `deploy/requirements-control.lock` | 29 | `a094ca6f8a117bc418813acca1358109ac9647575f90b145f6f3ab98d1114267` |
| `deploy/sbom/test-cyclonedx.json` | `deploy/requirements-test.lock` | 37 | `d3aea2e1b4419d44b2885dcc6a76b2645f61fe75e343e3ed4499171b6aab69e0` |

Cada componente incluye:

- `name` y `version` leídos del `METADATA` del wheel;
- `purl` con forma `pkg:pypi/<nombre-normalizado>@<versión>`;
- un hash `SHA-256` calculado sobre el archivo `.whl` descargado;
- la licencia declarada en `METADATA` (`License-Expression`, `License` o
  clasificador), con la fuente registrada en la propiedad
  `dystopia:license-source`;
- el nombre del wheel y la plataforma objetivo como propiedades.

No se inventaron licencias ni hashes. Si un wheel no declarara licencia, el
generador registraría `NOASSERTION`; en estos dos bundles los 29 y 37
componentes declaran alguna licencia en sus metadatos.

## Cómo se generó

Los SBOM se obtuvieron de los bundles construidos por
`scripts/build_offline_bundle.sh`, no directamente del lock:

```bash
PYTHON=/ruta/a/python3.12 ./scripts/build_offline_bundle.sh \
  deploy/requirements-control.lock build/offline-bundle
PYTHON=/ruta/a/python3.12 ./scripts/build_offline_bundle.sh \
  deploy/requirements-test.lock build/offline-bundle-test

python3 scripts/generate_sbom.py build/offline-bundle \
  deploy/sbom/control-cyclonedx.json dystopia-control
python3 scripts/generate_sbom.py build/offline-bundle-test \
  deploy/sbom/test-cyclonedx.json dystopia-tests
```

`scripts/generate_sbom.py` vuelve a calcular el SHA-256 de cada wheel y falla si
no coincide con `hashes.json`. El `serialNumber` se deriva de forma determinista
del conjunto de wheels; no se usa la fecha actual, de modo que repetir la
generación sobre el mismo bundle produce el mismo documento.

Los hashes del SBOM son los de los wheels Linux descargados. No son los hashes
del lock completo (el lock contiene además digests de otras plataformas
compatibles) ni sustituyen a `hashes.json` del bundle.

## Distribución de licencias

Datos tal como los declara cada distribución, sin normalización legal:

| Licencia declarada | Control | Tests |
| --- | --- | --- |
| MIT | 13 | 16 |
| BSD-3-Clause | 5 | 7 |
| Apache-2.0 | 3 | 4 |
| BSD-2-Clause | 2 | 3 |
| MPL-2.0 | 0 | 1 |
| MIT-0 | 1 | 1 |
| Apache-2.0 OR BSD-3-Clause | 1 | 1 |
| Apache-2.0 OR BSD-2-Clause | 1 | 1 |
| Apache-2.0 AND BSD-2-Clause | 1 | 1 |
| PSF-2.0 | 1 | 1 |
| MIT License | 1 | 1 |

La cadena `MIT License` proviene del clasificador de un paquete y no es un
identificador SPDX canónico. El SBOM la conserva como nombre declarado; no se
reescribió a `MIT` para no alterar la evidencia.

## Validación

`tests/hardening/test_supply_chain.py` comprueba que:

- ambos SBOM son CycloneDX, tienen componentes y cada componente incluye
  nombre, versión, `purl`, un SHA-256 de 64 hex y una licencia no vacía;
- cada hash del SBOM aparece en alguno de los locks (no hay hashes ajenos);
- los locks tienen versión exacta y al menos un hash por requisito;
- el lock de control no contiene pytest, pytest-asyncio, ruff ni pyright;
- no hay wheels ni archivos comprimidos versionados bajo `deploy/`;
- no aparecen placeholders ni patrones de credenciales en los artefactos de
  esta ola.

## Limitaciones

- El SBOM describe los wheels descargados para Linux amd64; no certifica que se
  hayan instalado o ejecutado en ese destino.
- Las licencias son metadatos del publicador, no una conclusión legal ni una
  revisión de compatibilidad de licencias.
- No hay firma, atestación de procedencia, VEX ni análisis de explotabilidad.
- Los avisos de seguridad se documentan en `docs/OFFLINE-BUNDLE.md`; el SBOM no
  duplica el estado de vulnerabilidades, que cambia con el tiempo.
- Si se regenera un lock, hay que reconstruir el bundle y volver a generar el
  SBOM; no se debe editar el JSON a mano.
