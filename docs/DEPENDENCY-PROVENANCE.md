# Procedencia de dependencias de control

## Alcance y estado

Consulta de metadatos públicos de PyPI: **2026-10-16**, revalidada el
**2026-11-02** para los pins cambiados (America/Mexico_City).

Se prepararon únicamente [requirements-control.in](<../deploy/requirements-control.in>), este documento y el archivo opcional separado [requirements-test.in](<../deploy/requirements-test.in>). Son **entradas candidatas**, no autorización para instalar ni desplegar. No se modificó el archivo raíz de dependencias ni otros archivos existentes. *(Lo anterior describe la sesión original del 2026-10-16; las olas posteriores — Ola A 2026-10-30 y remediación 2026-11-02 — sí ejecutaron resolución, construcción de bundles, auditoría y tests. Ver secciones correspondientes.)*

No se descargaron wheels ni sdists en esa sesión y no se instalaron paquetes. Las consultas HTTP obtuvieron solamente JSON de metadatos; que esos JSON enumeren artefactos y digests no implica haber descargado o verificado los artefactos.

## Pins verificados

Cada URL versionada de la tabla respondió HTTP 200. Se comprobaron `info.name`, `info.version`, `info.requires_python`, `info.yanked` y los clasificadores de Python. Todas las versiones seleccionadas son publicaciones finales (sin sufijos de prerelease), con `yanked: false`, y declaran Python 3.12 en sus clasificadores. Sus rangos `Requires-Python` incluyen 3.12. Esto es una **declaración del publicador**, no una prueba de compatibilidad. Los metadatos de los pins cambiados se revalidaron el **2026-11-02**.

No se afirma que sean las versiones más recientes. La selección conserva una base de releases finales verificables; “final” no equivale al clasificador PyPI `Production/Stable` (algunos proyectos aún declaran `Beta`).

| Superficie | Dependencia | Pin exacto | Requires-Python declarado | Metadatos consultados |
| --- | --- | --- | --- | --- |
| Control | fastapi, sin extras | `0.162.0` | `>=3.10` | [PyPI JSON](https://pypi.org/pypi/fastapi/0.162.0/json) |
| Control | starlette, pin directo, sin extras | `1.10.0` | `>=3.11` | [PyPI JSON](https://pypi.org/pypi/starlette/1.10.0/json) |
| Control | uvicorn, **sin standard** | `0.34.3` | `>=3.9` | [PyPI JSON](https://pypi.org/pypi/uvicorn/0.34.3/json) |
| Control | pydantic | `2.11.7` | `>=3.9` | [PyPI JSON](https://pypi.org/pypi/pydantic/2.11.7/json) |
| Control | slowapi, sin extras | `0.1.9` | `>=3.7,<4.0` | [PyPI JSON](https://pypi.org/pypi/slowapi/0.1.9/json) |
| Control | PyJWT, extra `crypto` | `2.15.1` | `>=3.9` | [PyPI JSON](https://pypi.org/pypi/PyJWT/2.15.1/json) |
| Control | bcrypt | `4.3.0` | `>=3.8` | [PyPI JSON](https://pypi.org/pypi/bcrypt/4.3.0/json) |
| Control | PyYAML | `6.0.2` | `>=3.8` | [PyPI JSON](https://pypi.org/pypi/PyYAML/6.0.2/json) |
| Control | prometheus-client | `0.22.1` | `>=3.9` | [PyPI JSON](https://pypi.org/pypi/prometheus-client/0.22.1/json) |
| Control | python-multipart | `0.0.31` | `>=3.10` | [PyPI JSON](https://pypi.org/pypi/python-multipart/0.0.31/json) |
| Tests opcionales | httpx, sin extras | `0.28.1` | `>=3.8` | [PyPI JSON](https://pypi.org/pypi/httpx/0.28.1/json) |
| Tests opcionales | pytest | `9.0.3` | `>=3.10` | [PyPI JSON](https://pypi.org/pypi/pytest/9.0.3/json) |
| Tests opcionales | pytest-asyncio | `1.3.0` | `>=3.10` | [PyPI JSON](https://pypi.org/pypi/pytest-asyncio/1.3.0/json) |

El archivo de control contiene exactamente los diez paquetes directos actuales (con `python-jose` sustituido por `PyJWT` y `starlette` promovida a pin directo). No incluye herramientas de tests, extras `standard`, Redis ni dependencias de otras superficies. El archivo de tests contiene solamente tres dependencias directas adicionales; para una futura resolución de tests aprobada se considerará junto al de control, sin incorporarlo al bundle productivo.

`PyJWT[crypto]` fija la distribución `pyjwt` y activa el extra `crypto`, que requiere `cryptography>=3.4`; el cierre reutiliza el `cryptography 50.0.2` ya bloqueado. A diferencia de `python-jose`, PyJWT **no** arrastra `ecdsa`, `rsa` ni `pyasn1`. Desde FastAPI 0.140.0 la dependencia se declara como `starlette>=0.46.0` **sin límite superior**; por eso se añadió `starlette==1.10.0` como pin directo para asegurar la línea 1.x en cada regeneración del lock.

## Avisos encontrados y decisiones pendientes

- **~~Bloqueo de aprobación de python-jose 3.5.0~~ — RESUELTO (2026-11-02):** el [JSON versionado](https://pypi.org/pypi/python-jose/3.5.0/json) devolvía `CVE-2026-85394` / `GHSA-3qf3-8w2g-rqmx` con `fixed_in: []` (aceptación de claves públicas DER como secretos HMAC). **Resolución:** `python-jose` fue eliminado del `.in`, del lock y del código; la ruta JWT usa PyJWT 2.15.1 (ver [reemplazo de python-jose](#remediación-2026-11-02-jwt-y-starlette)). El histórico del aviso se conserva como evidencia del bloqueo original.
- Se descartó [python-multipart 0.0.20](https://pypi.org/pypi/python-multipart/0.0.20/json): sus metadatos señalan avisos de traversal, agotamiento de recursos y diferencias de parsing, con correcciones hasta `0.0.31`. Se verificó y seleccionó `0.0.31`, cuyo JSON consultado devuelve `vulnerabilities: []`.
- Se descartó [pytest 8.4.1](https://pypi.org/pypi/pytest/8.4.1/json): sus metadatos señalan `CVE-2025-71176` y corrección en `9.0.3`. Se verificó y seleccionó `9.0.3`. También se consultó [pytest-asyncio 1.0.0](https://pypi.org/pypi/pytest-asyncio/1.0.0/json), cuyo requisito `pytest<9` excluye ese candidato; se seleccionó `1.3.0`, que declara `pytest>=8.2,<10`.
- Una consulta exploratoria al [JSON general de FastAPI](https://pypi.org/pypi/fastapi/json) no se utilizó como evidencia del pin: la tabla usa el endpoint versionado.
- **Avisos de ecdsa 0.19.2 y Starlette 0.46.2 (2026-10-30):** `ecdsa` (transitiva de python-jose, sin corrección) ya no está en el lock; los 7 avisos de Starlette se cubren con `starlette==1.10.0`. Detalle por aviso en `docs/OFFLINE-BUNDLE.md` ([Auditoría previa](OFFLINE-BUNDLE.md#auditoría)).

### Remediación 2026-11-02 (JWT y Starlette)

Acciones reales ejecutadas en esta ola (rama `wave/deps-remediation`, sin push ni merge):

1. **python-jose 3.5.0 → PyJWT 2.15.1 (`PyJWT[crypto]`):** mantenida, con soporte oficial de Python 3.12; el extra `crypto` está cubierto por `cryptography 50.0.2`. Elimina además las transitivas `ecdsa`/`rsa`/`pyasn1`/`six`.
2. **FastAPI 0.115.12 → 0.162.0** y **Starlette 0.46.2 → 1.10.0** (pin directo en `requirements-control.in`): la línea 1.10.0 cubre las correcciones declaradas de los 7 avisos de Starlette (≥ 1.3.1 para el último).
3. **Código:** `app/core/security.py` migrado de `jose.jwt` a `jwt` (PyJWT), con `algorithms=["HS256"]` y `options={"require": ["exp"]}` (mantiene la exigencia de `exp` que python-jose imponía por defecto). Pruebas nuevas en `tests/auth/test_jwt_remediation.py`: login correcto, JWT mal firmado, token sin `ver`, usuario cambiado/revocado y separación API key/JWT.
4. **Locks regenerados** con uv 0.12.18 para CPython 3.12 / Linux amd64 (`x86_64-manylinux_2_28`), congelando el índice en `2026-10-30T23:59:59Z` (misma fecha que el cierre anterior). Bundles construidos y aceptados por `runtime/install.py::verify_bundle`; SBOM determinista regenerado desde `hashes.json` del bundle.
5. **pip-audit/OSV sobre ambos locks (2026-11-02):** `No known vulnerabilities found`. Nuevas vulnerabilidades detectadas en la remediación: **ninguna**.
6. Suite completa (367 pruebas + 173 subtests), ruff y pyright pasan en el intérprete 3.12 del host.

Vulnerabilidades nuevas introducidas por las versiones nuevas: **ninguna conocida** según la base OSV consultada; las transitivas nuevas (`annotated-doc 0.0.5`, `opentelemetry-api 1.45.2`) no devuelven avisos. Estado del bloqueo de producción: **desbloqueado por avisos conocidos**; la aprobación formal sigue supeditada a la puesta en marcha en el destino Linux y a la firma del release (placeholder en `docs/OFFLINE-BUNDLE.md`).

## Qué NO está validado

**No validamos compatibilidad de la aplicación, compatibilidad conjunta, resolución transitiva ni hashlock.** No se verificaron imports, APIs, fixtures, comportamiento de autenticación, configuración ni cobertura de la superficie mínima mediante ejecución. Tampoco se verificaron wheels disponibles para cada combinación final de sistema operativo, arquitectura, ABI y Python 3.12.

Leer algunos requisitos declarados para evitar una contradicción directa evidente no constituye una resolución. No se emitieron pins transitivos ni se generó un lock. Los cambios de versiones pueden exigir cambios de aplicación o tests, especialmente con Pydantic 2 y pytest/pytest-asyncio; eso queda fuera de este trabajo.

## Contrato obligatorio para el instalador

El instalador **requiere un bundle offline aprobado y un `requirements.lock` con hashes SHA-256 reales de todos los wheels necesarios**, tanto directos como transitivos, incluidos los activados por extras y marcadores del entorno destino. Estos archivos `.in` no sustituyen ese lock y no deben usarse directamente para instalar en producción.

Antes de autorizar una instalación, en una fase posterior expresamente aprobada:

1. Definir la plataforma destino (Python 3.12, ABI, sistema y arquitectura), resolver el cierre completo y revisar compatibilidad, licencias y avisos, incluido el bloqueo de python-jose.
2. Obtener y aprobar los wheels exactos mediante el proceso de suministro autorizado; comprobar sus bytes y registrar sus hashes reales, origen y selección de plataforma.
3. Producir el `requirements.lock` completo con versiones exactas y hashes de cada wheel autorizado, sin dependencias implícitas fuera del lock. Mantener un bundle de tests separado si se necesita.
4. Hacer que el instalador use únicamente el bundle aprobado, sin índice ni acceso de red, con verificación obligatoria de hashes y sin fallback a sdists o compilación. Debe fallar cerrado si falta el lock, un wheel, un hash, la aprobación o hay cualquier discrepancia.

**No se creó ni se certifica la existencia de un bundle o `requirements.lock` aprobado en este trabajo.** No se inventaron hashes, URLs de artefactos, referencias de aprobación ni evidencias de instalación. Los digests visibles en PyPI no se copiaron como si constituyeran un hashlock completo y validado.

## Actualización posterior (Ola A, 2026-10-30)

Se generaron locks candidatos con versiones exactas y hashes SHA-256 para
CPython 3.12 / Linux amd64:

- `deploy/requirements-control.lock` (29 paquetes),
- `deploy/requirements-test.lock` (37 paquetes, superconjunto de control).

También se añadieron `scripts/build_offline_bundle.sh`, dos SBOM CycloneDX en
`deploy/sbom/` y la documentación `docs/OFFLINE-BUNDLE.md` y `docs/SBOM.md`.
La auditoría con pip-audit/OSV encontró 9 avisos únicos en `python-jose`,
`ecdsa` y `starlette`; el detalle y las correcciones declaradas están en
`docs/OFFLINE-BUNDLE.md`.

Estos artefactos permiten verificar hashes y construir un bundle, **no aprueban
el despliegue** por sí solos. El bloqueo de python-jose y los avisos de
FastAPI/Starlette que existían en esa ola quedaron **resueltos el 2026-11-02**
(mediante la sustitución PyJWT/FastAPI/Starlette documentada arriba); el detalle
de vulnerabilidad está en `docs/OFFLINE-BUNDLE.md`. Los wheels no se versionan.
