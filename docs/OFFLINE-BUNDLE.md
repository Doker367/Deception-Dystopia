# Bundle offline y locks de suministro

## Estado

Artefactos de cadena de suministro para el objetivo **CPython 3.12 / Linux amd64**.
Los locks son reproducibles y verificables, pero **no constituyen aprobación de
producción**: la aprobación sigue en revisión formal (véase [Auditoría](#auditoría)).
Los bloqueos previos de `python-jose`, `ecdsa` y Starlette quedaron **resueltos**
en la remediación del 2026-11-02: py-audit ya no reporta avisos en ningún lock.
El bundle de wheels no se versiona.

Este trabajo se ejecutó en un host macOS arm64. La resolución y descarga se
hicieron para la plataforma Linux amd64; los wheels **no se instalaron ni se
ejecutaron** en Linux desde este host.

## Contrato que exige `runtime/install.py`

El instalador no instala paquetes: exige un bundle offline revisado y verifica
su contenido en `verify_bundle()`:

- El bundle es un directorio con `hashes.json`, `requirements.lock` y los
  `*.whl` como hijos directos (sin symlinks ni rutas absolutas).
- `hashes.json` es un objeto JSON que mapea cada ruta relativa a un SHA-256
  hexadecimal de 64 caracteres. Debe incluir la clave `requirements.lock` y
  cubrir exactamente todos los `*.whl` del bundle.
- Cada línea lógica no comentada de `requirements.lock` debe cumplir
  `nombre[extras]==versión` seguido de uno o más `--hash=sha256:<64 hex>`.
  Se permiten continuaciones de línea con barra invertida.
- Si falta un artefacto, sobra un wheel, un digest no coincide o una línea no
  tiene versión exacta y hash, el instalador falla cerrado.

`scripts/build_offline_bundle.sh` produce exactamente esa estructura. El
instalador sigue sin descargar, compilar ni instalar paquetes Python: el venv
inmutable lo construye el administrador en una fase aprobada.

## Plataforma objetivo

| Parámetro | Valor |
| --- | --- |
| Implementación / versión | CPython 3.12 (ABI `cp312`) |
| Sistema / arquitectura | Linux x86_64 (amd64) |
| Línea base manylinux | `manylinux_2_28` (glibc >= 2.28) |
| Plataforma de resolución | `x86_64-manylinux_2_28` con uv 0.12.18 |
| Host de generación | macOS arm64, Python 3.12.14, pip 26.2.2 |

Ubuntu 24.04 (glibc 2.39) es compatible con la línea base elegida. El script
acepta además `manylinux_2_17_x86_64` y `manylinux2014_x86_64` para wheels
publicados con etiquetas más antiguas, siempre que el hash esté en el lock.

## Archivos generados

| Archivo | Contenido | Paquetes | SHA-256 |
| --- | --- | --- | --- |
| `deploy/requirements-control.lock` | cierre de control, solo wheels | 27 | `53016f893c91651e6b4bbd39db653f1f9eea9a2db83dd06b5de9ce36f98765c0` |
| `deploy/requirements-test.lock` | control + herramientas de test | 35 | `27b90b3f00253845079d71a643015bb7b2a8d1397669120ed5c4145fc660c745` |
| `deploy/sbom/control-cyclonedx.json` | SBOM CycloneDX 1.6 de control | 27 componentes | véase `docs/SBOM.md` |
| `deploy/sbom/test-cyclonedx.json` | SBOM CycloneDX 1.6 de tests | 35 componentes | véase `docs/SBOM.md` |

El lock de control tiene 505 entradas `--hash` y el de tests 521, porque uv
emite los digests de todas las distribuciones compatibles con la plataforma
resuelta; el bundle descarga un único wheel Linux por requisito y lo valida
contra ese conjunto. No hay sdists ni dependencias fuera del lock. El lock de
tests es un superconjunto del de control y **no debe instalarse en la superficie
de control productiva**.

Remediación del 2026-11-02 respecto al cierre anterior: se eliminaron
`python-jose 3.5.0` y sus transitivas `ecdsa 0.19.2`, `rsa` y `pyasn1`; entraron
`PyJWT 2.15.1` (con el extra `crypto`, que reutiliza el `cryptography 50.0.2`
ya bloqueado), `FastAPI 0.115.12 → 0.162.0`, `Starlette 0.46.2 → 1.10.0`
(pin explícito en el `.in`) y las transitivas nuevas de FastAPI
(`annotated-doc 0.0.5`, `opentelemetry-api 1.45.2`). `uvicorn`, `pydantic`,
`slowapi`, `bcrypt`, `PyYAML`, `prometheus-client` y `python-multipart`
mantienen su pin.

Los archivos `.in` (`deploy/requirements-control.in`,
`deploy/requirements-test.in`) siguen siendo entradas candidatas, no locks.

## Regeneración de los locks

Los locks se generaron con el estado del índice congelado en
`2026-10-30T23:59:59Z`. Repetir los comandos con la misma versión de uv y un
índice que conserve los artefactos debe producir el mismo contenido; si el
índice cambia, el archivo versionado sigue siendo la referencia y cualquier
regeneración requiere revisión y diff explícito. No editar hashes a mano.

```bash
uv pip compile deploy/requirements-control.in \
  --python-version 3.12 \
  --python-platform x86_64-manylinux_2_28 \
  --generate-hashes --only-binary :all: \
  --exclude-newer 2026-10-30T23:59:59Z \
  --no-annotate --no-header \
  -o deploy/requirements-control.lock

uv pip compile deploy/requirements-control.in deploy/requirements-test.in \
  --python-version 3.12 \
  --python-platform x86_64-manylinux_2_28 \
  --generate-hashes --only-binary :all: \
  --exclude-newer 2026-10-30T23:59:59Z \
  --no-annotate --no-header \
  -o deploy/requirements-test.lock
```

Los encabezados de comentario de los locks documentan el comando y la fecha de
corte. Un lock sin hashes o con una línea no pinneada es rechazado antes de
tocar la red.

## Construcción del bundle

```bash
PYTHON=/ruta/a/python3.12 ./scripts/build_offline_bundle.sh \
  deploy/requirements-control.lock build/offline-bundle
```

El directorio de salida debe estar vacío; por defecto es `build/offline-bundle`,
que ya está ignorado por git. El script:

1. valida el lock con la misma sintaxis que `runtime/install.py`;
2. copia el lock como `requirements.lock`;
3. ejecuta `pip download --no-deps --require-hashes --only-binary=:all:`
   con `--python-version 3.12`, `--implementation cp`, `--abi cp312` y las
   plataformas manylinux indicadas;
4. rechaza sdists, archivos ajenos, wheels sobrantes o faltantes y cualquier
   digest que no coincida con el lock;
5. escribe `hashes.json` con el SHA-256 real de `requirements.lock` y de cada
   wheel.

El script no imprime secretos, no lee `.env` y falla cerrado sin lock, con lock
malformado o con un wheel ausente. Para tests:

```bash
PYTHON=/ruta/a/python3.12 ./scripts/build_offline_bundle.sh \
  deploy/requirements-test.lock build/offline-bundle-test
```

Verificación de que el bundle satisface al instalador:

```bash
python3 -c "from runtime.install import verify_bundle; print(verify_bundle('build/offline-bundle'))"
```

## Auditoría

### Auditoría previa (2026-10-30, cierre antiguo)

Se documentan los 9 avisos del cierre de 2026-10-30 por trazabilidad; **todos
quedaron cubiertos por la remediación del 2026-11-02** y ninguna versión de ese
cierre permanece en los locks actuales:

| Paquete | Versión | Aviso | Corrección declarada | Resolución en esta ola |
| --- | --- | --- | --- | --- |
| `python-jose` | 3.5.0 | `PYSEC-2024-232`, `PYSEC-2026-4298`; aliases `CVE-2024-33663`, `CVE-2026-85394`, `GHSA-3qf3-8w2g-rqmx`, `GHSA-6c5p-j8vq-pqhj` | ninguna | Dependencia eliminada; JWT en PyJWT 2.15.1 (`app/core/security.py`). |
| `ecdsa` | 0.19.2 | `PYSEC-2026-1325` (`CVE-2024-23342`, `GHSA-wj6h-64fc-37mp`) | ninguna | Transitiva eliminada con python-jose. |
| `starlette` | 0.46.2 | `PYSEC-2026-161` (`CVE-2026-48710`) | 1.0.1 | Starlette 1.10.0 ≥ 1.0.1. |
| `starlette` | 0.46.2 | `PYSEC-2026-1941` (`CVE-2025-54121`) | 0.47.2 | Starlette 1.10.0 ≥ 0.47.2. |
| `starlette` | 0.46.2 | `PYSEC-2026-1942` (`CVE-2025-62727`) | 0.49.1 | Starlette 1.10.0 ≥ 0.49.1. |
| `starlette` | 0.46.2 | `PYSEC-2026-2280` (`CVE-2026-48817`) | 1.1.0 | Starlette 1.10.0 ≥ 1.1.0. |
| `starlette` | 0.46.2 | `PYSEC-2026-2281` (`CVE-2026-48818`) | 1.1.0 | Starlette 1.10.0 ≥ 1.1.0. |
| `starlette` | 0.46.2 | `PYSEC-2026-248` (`CVE-2026-54282`, corregido en 1.3.0) | 1.3.0 | Starlette 1.10.0 ≥ 1.3.0. |
| `starlette` | 0.46.2 | `PYSEC-2026-249` (`CVE-2026-54283`, corregido en 1.3.1) | 1.3.1 | Starlette 1.10.0 ≥ 1.3.1. |

La combinación elegida es la que existe y fue verificada (host macOS arm64):
`FastAPI 0.162.0` de declara `starlette>=0.46.0` **sin límite superior**, de modo
que con el pin directo `starlette==1.10.0` el cierre ya no contiene ninguna de
las 7 versiones afectadas. Las versiones de Starlette anteriores a 1.3.1
siguen afectadas si otra resolución retrocede; el pin explícito del `.in` evita
eso en los locks regenerados.

### Auditoría actual (2026-11-02, cierre remediado)

Ejecutada con pip-audit (vía `uvx`, mismo comando y servicio OSV):

```bash
uvx pip-audit -r deploy/requirements-control.lock \
  --no-deps --vulnerability-service osv --progress-spinner off --format columns
uvx pip-audit -r deploy/requirements-test.lock \
  --no-deps --vulnerability-service osv --progress-spinner off --format columns
```

Resultado real de ambas ejecuciones: **"No known vulnerabilities found"**,
incluidos `PyJWT 2.15.1`, `FastAPI 0.162.0`, `Starlette 1.10.0`,
`cryptography 50.0.2`, `annotated-doc 0.0.5` y `opentelemetry-api 1.45.2`.

### Prueba real del bundle

```bash
bash -n scripts/build_offline_bundle.sh                     # sintaxis OK
PYTHON=/…/.py312/bin/python ./scripts/build_offline_bundle.sh \
  deploy/requirements-control.lock build/offline-bundle-deps    # 27 wheels, hashes.json
PYTHON=/…/.py312/bin/python ./scripts/build_offline_bundle.sh \
  deploy/requirements-test.lock build/offline-bundle-test-deps  # 35 wheels, hashes.json
python3 -c "from runtime.install import verify_bundle; \
  print(verify_bundle('build/offline-bundle-deps'), \
        verify_bundle('build/offline-bundle-test-deps'))"     # True True
```

Ambos bundles pasan la verificación exacta del instalador
(`runtime/install.py::verify_bundle`). Los directorios de bundle son
temporales, no se versionan.

### Ruta JWT de la aplicación

`app/core/security.py` usa PyJWT con allowlist estricto de algoritmos
(`algorithms=["HS256"]`) y `options={"require": ["exp"]}`, que conserva la
exigencia de `exp` que python-jose imponía por defecto (PyJWT no la impone).
Las pruebas de `tests/auth/test_jwt_remediation.py` cubren: login correcto,
JWT mal firmado, token sin `ver`, usuario cambiado/revocado y separación entre
API key (`np_...`) y JWT. La suite completa (367 tests + 173 subtests) pasa.

### Estado de la aprobación

Los bloqueos por vulnerabilidad conocida quedan levantados: **ya no queda
ninguna advertencia abierta en los locks**. La aprobación de producción exige
además el cierre formal previsto en `docs/DEPENDENCY-PROVENANCE.md`
(instalación/puesta en marcha en el destino Linux, `pip check` en el venv real
y aceptación explícita). Placeholder de aprobación:

```
APPROVAL: [PENDING]
- Dependency remediation complete:      [x] 2026-11-02
- pip-audit/OSV clean on both locks:    [x] 2026-11-02
- Bundle verified by runtime installer: [x] 2026-11-02
- Linux destination run (pip check +
  controlled boot):                     [ ]
- Formal release sign-off:              [ ]                     (revisiones: ____ fecha: ____)
```

## Limitaciones

- Host macOS arm64: los wheels Linux se descargaron y verificaron, pero no se
  instalaron ni se ejecutaron en Linux.
- No se probó el venv inmutable ni el arranque de la aplicación en el destino.
- El lock fija el cierre resuelto, pero la reproducibilidad futura depende de
  que PyPI conserve los artefactos y de usar la misma versión de uv.
- Los hashes de plataforma proceden de la resolución; no hay firma de
  procedencia, atestación SLSA ni revisión legal de licencias.
- pip-audit consulta una base pública en una fecha concreta; no se evaluó la
  aplicabilidad real de cada aviso en el código.
- No se commitearon wheels, certificados, claves ni archivos de entorno.

## Pasos pendientes en Linux

1. Verificar el SHA-256 de ambos locks contra este documento.
2. Construir el bundle en Linux (o transferirlo) y conservar `hashes.json` como
   raíz de confianza revisada por el operador.
3. Crear un venv con Python 3.12 e instalar solo desde el bundle:

   ```bash
   python3.12 -m venv /opt/dystopia/venv
   /opt/dystopia/venv/bin/pip install --no-index \
     --find-links build/offline-bundle --only-binary=:all: \
     --require-hashes -r build/offline-bundle/requirements.lock
   ```

4. Ejecutar `pip check`, la suite de tests y un arranque controlado; repetir
   `pip-audit` sobre el venv real.
5. ~~Resolver el bloqueo de FastAPI/Starlette y python-jose/ecdsa, regenerar
   los locks, regenerar el SBOM y repetir la auditoría.~~ **Hecho el
   2026-11-02** (PyJWT 2.15.1, FastAPI 0.162.0, Starlette 1.10.0; auditoría
   limpia).
6. Solo tras aprobación explícita, registrar `hashes.json` y el lock en el
   proceso de release del instalador.
