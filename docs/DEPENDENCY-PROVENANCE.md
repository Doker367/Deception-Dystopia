# Procedencia de dependencias de control

## Alcance y estado

Consulta de metadatos públicos de PyPI: **2026-10-16**, fecha de la sesión (America/Mexico_City).

Se prepararon únicamente [requirements-control.in](<../deploy/requirements-control.in>), este documento y el archivo opcional separado [requirements-test.in](<../deploy/requirements-test.in>). Son **entradas candidatas**, no autorización para instalar ni desplegar. No se modificó el archivo raíz de dependencias ni otros archivos existentes.

No se ejecutaron comandos, Python, gestores de paquetes, resolutores ni tests. No se descargaron wheels ni sdists y no se instalaron paquetes. Las consultas HTTP obtuvieron solamente JSON de metadatos; que esos JSON enumeren artefactos y digests no implica haber descargado o verificado los artefactos.

## Pins verificados

Cada URL versionada de la tabla respondió HTTP 200. Se comprobaron `info.name`, `info.version`, `info.requires_python`, `info.yanked` y los clasificadores de Python. Todas las versiones seleccionadas son publicaciones finales (sin sufijos de prerelease), con `yanked: false`, y declaran Python 3.12 en sus clasificadores. Sus rangos `Requires-Python` incluyen 3.12. Esto es una **declaración del publicador**, no una prueba de compatibilidad.

No se afirma que sean las versiones más recientes. La selección conserva una base de releases finales verificables; “final” no equivale al clasificador PyPI `Production/Stable` (algunos proyectos aún declaran `Beta`).

| Superficie | Dependencia | Pin exacto | Requires-Python declarado | Metadatos consultados |
| --- | --- | --- | --- | --- |
| Control | fastapi, sin extras | `0.115.12` | `>=3.8` | [PyPI JSON](https://pypi.org/pypi/fastapi/0.115.12/json) |
| Control | uvicorn, **sin standard** | `0.34.3` | `>=3.9` | [PyPI JSON](https://pypi.org/pypi/uvicorn/0.34.3/json) |
| Control | pydantic | `2.11.7` | `>=3.9` | [PyPI JSON](https://pypi.org/pypi/pydantic/2.11.7/json) |
| Control | slowapi, sin extras | `0.1.9` | `>=3.7,<4.0` | [PyPI JSON](https://pypi.org/pypi/slowapi/0.1.9/json) |
| Control | python-jose[cryptography] | `3.5.0` | `>=3.9` | [PyPI JSON](https://pypi.org/pypi/python-jose/3.5.0/json) |
| Control | bcrypt | `4.3.0` | `>=3.8` | [PyPI JSON](https://pypi.org/pypi/bcrypt/4.3.0/json) |
| Control | PyYAML | `6.0.2` | `>=3.8` | [PyPI JSON](https://pypi.org/pypi/PyYAML/6.0.2/json) |
| Control | prometheus-client | `0.22.1` | `>=3.9` | [PyPI JSON](https://pypi.org/pypi/prometheus-client/0.22.1/json) |
| Control | python-multipart | `0.0.31` | `>=3.10` | [PyPI JSON](https://pypi.org/pypi/python-multipart/0.0.31/json) |
| Tests opcionales | httpx, sin extras | `0.28.1` | `>=3.8` | [PyPI JSON](https://pypi.org/pypi/httpx/0.28.1/json) |
| Tests opcionales | pytest | `9.0.3` | `>=3.10` | [PyPI JSON](https://pypi.org/pypi/pytest/9.0.3/json) |
| Tests opcionales | pytest-asyncio | `1.3.0` | `>=3.10` | [PyPI JSON](https://pypi.org/pypi/pytest-asyncio/1.3.0/json) |

El archivo de control contiene exactamente los nueve paquetes directos solicitados. No incluye herramientas de tests, extras `standard`, Redis ni dependencias de otras superficies. El archivo de tests contiene solamente tres dependencias directas adicionales; para una futura resolución de tests aprobada se considerará junto al de control, sin incorporarlo al bundle productivo.

`python-jose[cryptography]` mantiene el extra solicitado. El pin fija la distribución `python-jose`, **no fija la versión de cryptography**. Según sus metadatos, también requiere `ecdsa`, `rsa` y `pyasn1`; seleccionar el extra no elimina estas dependencias. Igualmente, quitar `uvicorn[standard]` no elimina las dependencias básicas de Uvicorn. “Mínima” describe la superficie directa, no un cierre transitivo resuelto.

## Avisos encontrados y decisiones pendientes

- **Bloqueo de aprobación de python-jose 3.5.0:** el [JSON versionado](https://pypi.org/pypi/python-jose/3.5.0/json) devuelve `CVE-2026-85394` / `GHSA-3qf3-8w2g-rqmx`, con `fixed_in: []`. El aviso describe aceptación de claves públicas DER como secretos HMAC cuando no se restringen explícitamente los algoritmos. Se conserva el pin como candidato verificable solicitado, **no como dependencia aprobada**. Antes de aprobar el bundle se debe revisar la aplicabilidad, la restricción explícita de algoritmos y las pruebas de autenticación; no se ha verificado aquí una versión corregida ni una mitigación en el código. El campo vacío no demuestra que nunca vaya a existir una corrección.
- Se descartó [python-multipart 0.0.20](https://pypi.org/pypi/python-multipart/0.0.20/json): sus metadatos señalan avisos de traversal, agotamiento de recursos y diferencias de parsing, con correcciones hasta `0.0.31`. Se verificó y seleccionó `0.0.31`, cuyo JSON consultado devuelve `vulnerabilities: []`.
- Se descartó [pytest 8.4.1](https://pypi.org/pypi/pytest/8.4.1/json): sus metadatos señalan `CVE-2025-71176` y corrección en `9.0.3`. Se verificó y seleccionó `9.0.3`. También se consultó [pytest-asyncio 1.0.0](https://pypi.org/pypi/pytest-asyncio/1.0.0/json), cuyo requisito `pytest<9` excluye ese candidato; se seleccionó `1.3.0`, que declara `pytest>=8.2,<10`.
- Una consulta exploratoria al [JSON general de FastAPI](https://pypi.org/pypi/fastapi/json) no se utilizó como evidencia del pin: la tabla usa el endpoint versionado.

No se hizo una auditoría de vulnerabilidades ni se revisó el cierre transitivo. Un array `vulnerabilities: []` no certifica seguridad, ausencia de vulnerabilidades ni vigencia de soporte. Todos los candidatos siguen sujetos a revisión, incluida la selección de versiones de Starlette y otras transitivas.

### Revisión posterior de la ruta JWT

La lectura estática de [security.py](<../app/core/security.py>) confirma `jwt.decode(..., algorithms=["HS256"])` y ausencia de clave por defecto; el instalador genera una clave simétrica aleatoria independiente. Por ello no se ha demostrado la precondición del aviso (selección de algoritmos no restringida) en esta ruta. Esto no constituye una prueba dinámica ni una aprobación de la librería/cierre transitivo: mantener la revisión de suministro pendiente antes del despliegue.

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
