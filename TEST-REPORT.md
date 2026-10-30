# Informe de pruebas

## Iteración puente de consulta — 2026-10-17 (resultado actual)

**Código implementado; pruebas dinámicas NO EJECUTADAS en esta iteración.** `sandbox-exec -f` falló con `sandbox_apply: Operation not permitted` incluso para `/usr/bin/true`; el entorno no ofrece el sandbox OS exigido para ejecutar código del repositorio sin exponer el host, servicios compartidos o secretos. No se aplicaron unidades ni permisos al host. Se validó solamente sintaxis de **129 archivos Python (AST Python 3.11, 0 errores)**, sintaxis JavaScript con `node --check` (exit 0, sin ejecutar aplicación), `ruff check --no-cache --select F,E9,E7` en módulos modificados (exit 0) y estructura INI estática de **6 unidades**, sin errores de secciones, y detector estático de interfaz con **0 hallazgos**; `systemd-analyze verify` no existe en este macOS, por lo que su semántica permanece pendiente. **No trasladar las cifras históricas de abajo al puente nuevo**. Probar `tests/integration/test_query_bridge.py` (incluye sensor spool → ASGI ingest → BD → socket scratch → ASGI control → CSV sintéticos), `tests/ui`, `tests/hardening` y suite completa en un sandbox/Linux desechable autorizado; registrar resultados reales, no inferirlos. La prueba preparada **no sustituye** la matriz de permisos UID reales ni una inspección del navegador.

Consulta el [plan de despliegue del puente](<docs/QUERY-BRIDGE.md>) y la [clasificación de fallos heredados](<docs/HARDENING-TESTS.md>). Contención Linux y pruebas visuales de navegador siguen pendientes. Preparación/activación continúan devolviendo 409 por código.

## Consola operativa — ejecución 2026-10-16

Se añadieron pruebas ASGI de contratos de celdas y telemetría (`tests/ui`): alta de borrador, validación por revisión, invalidación al editar, conflicto 409, preparación/activación 409, permisos viewer/operator/admin, errores de campos, lectura de ingestión explícita, filtros/orden/paginación, CSV con protección de fórmulas, auditoría mínima y límite de login sin confiar en `X-Forwarded-For`.

- `tests/ui tests/hardening`: **68 passed**, 41 subtests, 1 warning deprecación Starlette/httpx; sintaxis Python de **125 archivos, 0 errores**; `node --check app/static/console.js` exitoso; detector de diseño **0 hallazgos**.
- Suite completa (`tests/`): **120 passed, 17 failed, 4 errors**, 41 subtests; los 21 rojos siguen siendo los casos antiguos incompatibles. La prueba nueva de health no asume contadores globales en cero tras ejecutar otros tests.
- Contraste matemático de pares principales/semánticos: 6.46:1–16.59:1 (pares muestreados), pero prueba visual Chrome en 1440/1024/390 **bloqueada** (`sandbox initialization failed: Operation not permitted` / inspector CDP timeout). Sin capturas verificadas ni conformidad WCAG AA certificada.
- Sin `nft`, libvirt, QEMU, cambios de red ni despliegue. El servidor de demostración anterior con credenciales publicadas fue detenido y sus credenciales temporales eliminadas.

Ver contratos, matriz de roles y guía de operación en [consola](<docs/CONSOLE-OPERATIONS.md>).

## Endurecimiento anterior — ejecutado 2026-10-16

Host macOS de desarrollo, intérprete **prestado** (`/Users/doker/Netpulse/.venv`: Python 3.14.7, FastAPI 0.141.1, pytest 9.1.1), sin instalar ni descargar nada, sin sandbox disponible.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  <python> -B -m pytest tests/hardening -p no:cacheprovider
```

| Ámbito | Resultado |
|---|---|
| Sintaxis (120 archivos `.py`, AST modo 3.11) | **0 errores** |
| `tests/hardening` (separación, identidad, cuotas, instalación, aislamiento) | **53 passed, 0 failed**, 41 subtests |
| Suite heredada completa (`tests/`) | **105 passed, 17 failed, 4 errores** |
| Arranque real del plano de control (loopback 8099) | OK; único socket en escucha, sin puertos de señuelo |
| Cadena login→token→endpoint; revocación por cambio de contraseña | 200/200; token anterior 401 |
| Rutas retiradas (engine, ingest, VM start, simulate, firewall) | 409/410 sin ejecución |
| Datos existentes (`config/`, `deception/`, `audit/`, `backups/`) | intactos |

**Contención real: NO VERIFICADA.** No se ejecutaron `nft`, libvirt, QEMU, `useradd` ni `systemctl`; el aislamiento se probó con mocks. El resultado no valida Ubuntu 24.04, Python 3.12 ni los pins candidatos.

Los 21 casos rojos de la suite heredada corresponden a contratos **retirados a propósito** (token de ingestión compartido, arranque de listeners/VM desde la API, tailer en el control, supresión de alertas por flag/allowlist/IA, comandos de firewall, router de monitoring y tokens JWT fabricados fuera de `/api/auth/login`). El mapeo completo está en la [matriz de validación](<docs/HARDENING-TESTS.md>). No deben arreglarse revirtiendo el endurecimiento.

Cambios de infraestructura de pruebas en esta sesión: se añadió [tests/conftest.py](<tests/conftest.py>) con un secreto JWT **sintético solo para pytest** (el código dejó de tener secreto por defecto y la suite no coleccionaba). `make test` ejecuta únicamente `tests/hardening`.

---

## Informe histórico del commit 1278db4

Suite propia de Dystopia (11 archivos).

## Resultado de la última ejecución

```
cd /Users/doker/Dystopia
NETPULSE_METRICS_ENABLED=false NETPULSE_SYSLOG_ENABLED=false \
NETPULSE_FIREWALL_ENABLED=false NETPULSE_AI_ENABLED=false \
NETPULSE_VMS_ENABLED=false NETPULSE_DECEPTION_ENABLED=false \
  <python> -m pytest
```

- **73 passed, 0 failed** (4 s), intérprete del entorno de desarrollo, sin
  instalaciones ni descargas durante la prueba.

Evidencia de frontera (prueba `tests/test_standalone_boundary.py`, 5/5 PASS):

- 60 rutas HTTP registradas (`app.openapi()`): incluye `/api/deception/*`,
  `/api/vms/*`, `/api/auth`, `/api/audit`, `/api/monitoring`, `/api/ai`.
- **Ninguna** ruta bajo `/api/devices`, `/api/facts`, `/api/config`,
  `/api/bulk`, `/api/netbox`, `/api/command`, `/api/templates`,
  `/api/compliance`, `/api/groups`, `/api/scheduler`, `/api/export`,
  `/api/topology`, `/api/traffic`, `/api/ops`, `/api/collectors`,
  `/api/system`, `/api/sftp`, `/api/firewall`.
- No importables: `napalm_svc`, `netmiko_svc`, `nornir_svc`, `fortios_svc`,
  `sftp_svc`, `inventory_svc`, `scheduler_svc`, `ops.health_svc`,
  `integrations.netbox_sync`.
- Defaults fail-closed: `API_HOST=127.0.0.1`, syslog/métricas/VMs/deception/
  firewall en `false`.
- Sin rutas absolutas hacia `/Users/doker/Netpulse` o `/Users/doker/netpulse-noc`.

| Ámbito | Estado |
|---|---|
| Sintaxis Python (`ast.parse`, 0 errores) | PASS |
| Suite completa de pruebas | PASS (73) |
| Frontera sin NOC | PASS |
| Motor de deception (listeners en loopback, fixtures) | PASS |
| Alertas, FP con Laya, GeoIP, Cowrie/OpenCanary, telemetría, blocklist/IOC | PASS |
| Auth propia, auditoría, monitoring | PASS |
| Go (`go test`/`go build`) | NO_EJECUTADA (requiere descarga de módulos; prohibido en validación) |
| Listeners/Cowrie/OpenCanary/QEMU reales | NO_EJECUTADA (no se arrancaron contenedores ni VMs) |

## Cambios de contrato respecto al monorepo

- `tests/test_deception_extras.py::test_sync_from_netbox` →
  `test_sync_from_netbox_disabled_in_standalone`: NetBox es propiedad del NOC,
  por lo que la prueba ahora verifica que Dystopia **no** sincroniza y **no**
  importa `integrations.netbox_sync` (antes verificaba el sync real).
- Retiradas de este repositorio las pruebas de administración de red real
  (permanecen en `netpulse-noc`): `test_auth_security.py`,
  `test_fase1_hardening.py`, `test_fase2.py`, `test_fase2_noc.py`,
  `test_fase4_performance.py`, `test_inventory_api.py`,
  `test_legacy_routing.py`, `test_netmiko_svc.py`, `test_sftp_api.py`.

No se eliminó ninguna prueba de deception: el catálogo de Dystopia está completo.

## Nota sobre el entorno

No hay `.venv` en este repositorio. Cree un entorno propio por repositorio
(`python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt`) para
no compartir dependencias con el NOC.

No se contactó ningún equipo real ni se abrieron listeners externos.
