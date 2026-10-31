# Bundle offline y locks de suministro

## Estado

Artefactos de cadena de suministro para el objetivo **CPython 3.12 / Linux amd64**.
Los locks son reproducibles y verificables, pero **no constituyen aprobación de
producción**: la auditoría de vulnerabilidades mantiene bloqueada la aprobación
(véase [Auditoría](#auditoría)). El bundle de wheels no se versiona.

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
| `deploy/requirements-control.lock` | cierre de control, solo wheels | 29 | `1b6326eabf1e9944cf783b8d98a20106c73d6f3245996ab74231529124e748fb` |
| `deploy/requirements-test.lock` | control + herramientas de test | 37 | `992c684935ab43f631701d5183043a62025fac7db437ee74d1aba8b955d1a8b5` |
| `deploy/sbom/control-cyclonedx.json` | SBOM CycloneDX 1.6 de control | 29 componentes | véase `docs/SBOM.md` |
| `deploy/sbom/test-cyclonedx.json` | SBOM CycloneDX 1.6 de tests | 37 componentes | véase `docs/SBOM.md` |

El lock de control tiene 509 entradas `--hash` y el de tests 525, porque uv
emite los digests de todas las distribuciones compatibles con la plataforma
resuelta; el bundle descarga un único wheel Linux por requisito y lo valida
contra ese conjunto. No hay sdists ni dependencias fuera del lock. El lock de
tests es un superconjunto del de control y **no debe instalarse en la superficie
de control productiva**.

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

Ejecutada el **2026-10-30** con pip-audit 2.10.1 y el servicio OSV:

```bash
uvx pip-audit -r deploy/requirements-control.lock \
  --no-deps --vulnerability-service osv --progress-spinner off --format columns
uvx pip-audit -r deploy/requirements-test.lock \
  --no-deps --vulnerability-service osv --progress-spinner off --format columns
```

Resultado: **9 avisos únicos en 3 paquetes** (18 filas por aliases duplicados).
El lock de tests presenta los mismos 9 avisos; sus herramientas de test no
añadieron avisos nuevos.

| Paquete | Versión | Aviso | Corrección declarada | Nota |
| --- | --- | --- | --- | --- |
| `python-jose` | 3.5.0 | `PYSEC-2024-232`, `PYSEC-2026-4298`; aliases `CVE-2024-33663`, `CVE-2026-85394`, `GHSA-3qf3-8w2g-rqmx`, `GHSA-6c5p-j8vq-pqhj` | ninguna | Confusión de algoritmos evadida con claves públicas DER. Aviso conocido y bloqueo de aprobación. |
| `ecdsa` | 0.19.2 | `PYSEC-2026-1325` (`CVE-2024-23342`, `GHSA-wj6h-64fc-37mp`) | ninguna | Ataque de temporización Minerva sobre P-256; transitiva de python-jose. |
| `starlette` | 0.46.2 | `PYSEC-2026-161` (`CVE-2026-48710`) | 1.0.1 | Falta de validación del header Host; corrupción de `request.url.path`. |
| `starlette` | 0.46.2 | `PYSEC-2026-1941` (`CVE-2025-54121`) | 0.47.2 | DoS al parsear multipart grandes. |
| `starlette` | 0.46.2 | `PYSEC-2026-1942` (`CVE-2025-62727`) | 0.49.1 | DoS O(n^2) en `FileResponse` por Range. |
| `starlette` | 0.46.2 | `PYSEC-2026-2280` (`CVE-2026-48817`) | 1.1.0 | Dispatch de métodos HTTP arbitrarios en `HTTPEndpoint`. |
| `starlette` | 0.46.2 | `PYSEC-2026-2281` (`CVE-2026-48818`) | 1.1.0 | SSRF / robo de credenciales NTLM con rutas UNC en StaticFiles (Windows). |
| `starlette` | 0.46.2 | `PYSEC-2026-248` (`CVE-2026-54282`) | 1.3.0 | Path no validado concatenado en la autoridad de la URL. |
| `starlette` | 0.46.2 | `PYSEC-2026-249` (`CVE-2026-54283`) | 1.3.1 | Límites de `request.form()` ignorados para formularios urlencoded. |

`FastAPI 0.115.12` restringe `starlette<0.47.0`; por tanto, dentro del pin
directo actual no existe una versión de Starlette que corrija los avisos. Se
requiere una actualización revisada de FastAPI (y probablemente de Starlette a
la línea 1.x), seguida de nueva resolución, tests y auditoría. No se cambió el
pin en esta ola.

La ruta JWT de la aplicación usa `algorithms=["HS256"]` de forma explícita
(lectura estática de `app/core/security.py`), lo que no demuestra la
precondición del aviso de python-jose, pero **no es una mitigación certificada**
ni una aprobación de la dependencia. La aprobación del bundle permanece
bloqueada hasta revisión y aceptación formal.

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
5. Resolver el bloqueo de FastAPI/Starlette y python-jose/ecdsa, regenerar los
   locks, regenerar el SBOM y repetir la auditoría.
6. Solo tras aprobación explícita, registrar `hashes.json` y el lock en el
   proceso de release del instalador.
