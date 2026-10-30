# Validación y evidencia del endurecimiento

## Ejecución histórica del endurecimiento inicial (2026-10-16, host macOS)

Las cifras de esta sección anteceden a consola y puente; ver [informe actual](<TEST-REPORT.md>). La iteración del puente no ejecutó pruebas dinámicas por fallo del sandbox OS.

**Suite de endurecimiento: 53 passed, 0 failed, 41 subtests (exit 0). Suite heredada completa: 105 passed, 17 failed, 4 errores. Contención real: SIGUE SIN VERIFICARSE.**

Ejecutado con un intérprete **prestado** (`/Users/doker/Netpulse/.venv`, Python 3.14.7, FastAPI 0.141.1, pytest 9.1.1), sin instalar ni descargar nada. Advertencias obligatorias sobre este resultado:

- **No es el objetivo soportado**: ni Ubuntu 24.04 ni Python 3.12 ni los pins candidatos de [procedencia](<docs/DEPENDENCY-PROVENANCE.md>). Prueba lógica de aplicación, no compatibilidad de despliegue.
- No se ejecutaron `nft`, libvirt, QEMU, `useradd`, `systemctl` ni nada con privilegios. Las pruebas de aislamiento usan mocks de runner; **no demuestran contención**.
- La suite heredada no está verde porque 21 casos codifican contratos **retirados a propósito** (tabla más abajo). Ninguno es una regresión inesperada; ninguno de ellos debe "arreglarse" reintroduciendo el comportamiento inseguro.

### Verificado en esta ejecución

| Comprobación | Resultado |
|---|---|
| Sintaxis de 120 archivos Python (AST, modo 3.11) | 0 errores |
| Suite endurecimiento (`tests/hardening`) | 53 passed, 0 failed |
| Arranque real del plano de control (`runtime.cli control`, loopback) | OK, `Application startup complete` |
| Sockets en escucha del control | **solo** `127.0.0.1:8099`; ningún puerto de señuelo |
| `GET /api/health` | 200 `sensors_started: false`, contadores de auditoría en 0 |
| Cadena login → token → endpoint (`/api/auth/login` → `/api/auth/me`) | 200 / 200 con rol admin |
| Revocación al cambiar contraseña | token anterior → 401 |
| Rutas retiradas (`engine/start`, `ingest`, `vms/*/start`, `simulate`, `firewall/block`) | 409 / 410, sin ejecución |
| Credencial de sensor inválida / dispositivo no asignado / flag `simulated` | 401 / 403 / 422 |
| Plan del instalador (dry-run) | sin escrituras ni comandos de host |

### Hallazgo operativo real (corregido en documentación)

Con el `audit/audit.db` preexistente en modo `0644`, el almacén endurecido **rechaza la base** y toda la auditoría falla cerrada (`control_audit_storage_unavailable`), visible en `/api/health`, sin perder datos pero sin registrar nuevos eventos. Es intencional (los datos capturados no deben ser legibles por otros) y requiere migración explícita de permisos: ver [operaciones](<docs/HARDENING-OPERATIONS.md>) y [migración](<MIGRATION.md>).

## Matriz de criterios

| Criterio | Evidencia | Estado |
|---|---|---|
| API sin puertos honeypot incluso con flags viejos | [control](<tests/hardening/test_control.py>) en ASGI, sockets/procesos prohibidos + arranque real con `lsof` | **PASS en host de desarrollo** |
| Sensor sin secretos/imports de administración | [telemetría](<tests/hardening/test_telemetry.py>), análisis de dependencias | **PASS (unitario)** |
| No suplantación/dispositivos no asignados | contrato estricto, identidad de registro, 403/422 | **PASS (unitario)** |
| Invalidación/rotación/revocación/expiración | exclusión transaccional y fallo de publicación del token | **PASS (unitario)** |
| Red insegura no activa | [aislamiento](<tests/hardening/test_isolation.py>), validación de instalación | **PASS (mock)**; activación bloqueada en código |
| IA falla sin eliminar reglas/detección | importación prohibida y detección de IP privada; outbox sin IA | **PASS (unitario)** |
| Saturación limitada/observable | cuotas store/spool, 503, contadores, retry, cuarentena de lote | **PASS (unitario)** |
| Plan no modifica host | [instalación](<tests/hardening/test_install.py>), snapshot/operaciones prohibidas | **PASS (unitario)** |
| Reprovisión conserva secretos/config | primitivas exclusivas, bootstrap repetido, fallo de fsync | unitario PASS; reinstalación Linux pendiente |
| Sin red QEMU accidental | stub legacy sin `subprocess` + XML con NIC explícita down | unitario PASS; arranque real pendiente |
| Reglas sobreviven pérdida de control | backend sin cleanup/flush/delete, tests con mocks | unitario PASS; **kernel real pendiente** |

No se usa un mock, un `isolated=true`, una VLAN o `internal=true` como prueba de contención. La palabra **verificado** está reservada y el helper nunca produce ese estado.

## Pruebas heredadas que codifican contratos retirados

No son regresiones: cada una exige el comportamiento inseguro que se eliminó. Se conservan para trazabilidad; su migración es trabajo pendiente y **no** debe hacerse revirtiendo el endurecimiento.

| Prueba heredada | Contrato retirado | Sustituto |
|---|---|---|
| `test_deception.py::test_api_ingest_con_token`, `::test_api_ingest_token_incorrecto` | ingestión con token compartido en el API | `test_telemetry.py::test_invalid_revoked_rotated_expired_credentials` |
| `test_deception.py::test_api_simulate` | generador de ataques simulados con credenciales falsas | eliminado a propósito (sin sustituto) |
| `test_deception_engine.py::test_engine_start_stop` | la API arranca listeners | `test_control.py::test_control_never_starts_honeypots_even_with_legacy_flags` |
| `test_deception_integrations.py::test_tailer_ingesta` | tailer dentro del proceso de control | sensor pendiente de portado |
| `test_deception_extras.py::test_alert_ignora_simulado/loopback/allowlisted` | supresión por flag del sensor, loopback y allowlist sin caducidad | detección siempre activa (sin sustituto) |
| `test_deception_fp.py` (4 errores) | IA suprimiendo alertas | IA consultiva sin autoridad |
| `test_deception_geo.py::test_firewall_dry_run/status` | control emitiendo comandos de firewall | `firewall_svc` sin autoridad |
| `test_monitoring_api.py` (3) | router de monitoring en el control mínimo | reducción deliberada de superficie |
| `test_deception.py::test_api_viewer_no_puede_crear`, `::test_api_timeline_y_csv`, `::test_api_network_y_status`, `::test_api_crud_device` | tokens JWT emitidos fuera de `/api/auth/login` sin vínculo a usuario | `test_control.py` + verificación manual login→token→endpoint |

### Reclasificación para el puente v1 (sin ejecución nueva)

| Casos históricos | Clase | Acción pendiente / sustitución |
|---|---|---|
| `test_deception.py` network/status, CRUD, viewer, timeline/CSV | **Contrato sustituido** y JWT ligado a usuario real | Migrar aserciones a borrador/celda y `tests/ui/test_console_contract.py`; timeline/CSV debe pasar por `tests/integration/test_query_bridge.py`, con socket real en sandbox. No emitir JWT fabricado. |
| `test_deception.py` ingest compartido, simulate; engine/start; alert ignore; geo/firewall; monitoring API; 4 errores IA/FP | **Contrato retirado deliberadamente** | Conservar como trazabilidad hasta reemplazar por pruebas de negación (`409`/`410`) y reglas/identidad v1. El router monitoring y la supresión por IA no se reintroducen para poner la suite verde. |
| `test_deception_integrations.py::test_tailer_ingesta` | **Dependencia de portación/laboratorio** | Adaptadores Cowrie/OpenCanary no portados ni verificados; crear fixture de spool/ingest independiente, no tailer dentro de control. |
| Nuevos fallos posibles en esta iteración | **Regresión sin clasificar** | Imposible descartarla sin ejecutar suite dinámica en sandbox OS; ejecutar, investigar cada caso, corregir y registrar nuevo resultado. |

Los 17 fallos y 4 errores son **históricos** (última suite antes del puente: 120 passed, 17 failed, 4 errors). No se añadió exclusión, `xfail` o `skip` general para ocultarlos. La clasificación no reemplaza la migración ni convierte una suite sin ejecutar en verde.

La última fila es la ruptura de compatibilidad con más impacto operativo: **los tokens deben emitirse por `/api/auth/login`**; cualquiera fabricado a mano sin el claim de versión de credenciales obtiene 401. Los tokens ya emitidos quedan invalidados.


## Ejecutar unitarios con controles de ejecución

Usar únicamente herramientas/dependencias ya aprobadas y disponibles. No resolver paquetes durante las pruebas. Requerir sandbox OS con:

- red externa denegada (ni siquiera listeners loopback son necesarios para TestClient/ASGI);
- entorno vacío y allowlist explícita; `HOME`, temporales, caches y estado bajo scratch;
- fuente/toolchain montados solo lectura, sin directorio personal, credenciales, Docker/libvirt sockets o servicios compartidos;
- scratch con cota de disco (256 MiB es un punto de partida), CPU 60 s, pared 90 s, RAM 1 GiB, 64 procesos, 256 FDs y límite de archivo 128 MiB;
- todo el grupo de procesos terminado al alcanzar el timeout; no ejecutar si falta algún control.

Dentro de ese sandbox, con Python 3.12 y dependencias ya presentes:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python -B -m pytest tests/hardening -q -p no:cacheprovider
```

Los tests proporcionan secretos **sintéticos** (ver [conftest.py](<tests/conftest.py>)), usan archivos temporales y ASGI in-process. Registrar comando, controles efectivos, versiones del intérprete/paquetes, resultados y límites; nunca copiar el entorno ambiente o capturas con credenciales.

En la ejecución del 2026-10-16 en macOS **no hubo sandbox disponible**: los comandos corrieron sin las cotas de arriba y con un venv prestado de otro producto, por lo que el resultado acredita lógica de aplicación, **no** reproducibilidad ni aislamiento de ejecución. Pendiente repetir con el sandbox de la lista, en Python 3.12/Ubuntu y con los pins aprobados, más lint y `systemd-analyze verify`.

## Laboratorio real pendiente: Ubuntu 24.04 + guest root

Preparación exclusiva por administrador autorizado:

1. Crear host/hipervisor desechable sin uplinks a producción, gestión real o Internet. Un cliente sintético, célula 1, célula 2 y destinos separados para gestión/producción/Internet **simulados**. No reutilizar redes ni cuentas reales.
2. Preparar disco RAW con hash aprobado, AppArmor/libvirt y topología dedicada de [aislamiento](<docs/hardening-isolation.md>). No saltarse `activate` en producción: el prototipo todavía no ofrece verificador ni arranque. Un ingeniero debe construir/revisar el fixture del laboratorio independientemente para probar los artefactos renderizados.
3. Revisar interfaces/masters/IPs IPv4+IPv6, ausencia de rutas/bridges alternos, NAT, NICs adicionales, SR-IOV/passthrough, interfaces macvtap/túneles, VLAN filtering, offloads y guest↔hipervisor. Probar que VNC/serial/control/discos no son alcanzables desde guest. Vecinos estáticos por la política restrictiva; ARP/ND no se autorizan implícitamente.
4. Desplegar servicios **sintéticos** vivos en cada destino. El servicio de prueba devuelve exactamente `DYSTOPIA-LAB-v1\n`. Desde cliente de baseline probar accesibilidad real antes y después; un puerto muerto o una ruta inexistente **no prueban aislamiento**.
5. Instalar las tablas generadas solo en el laboratorio, registrar ruleset/counters y capturas en ambos lados. Usar el [probe manual](<tests/integration/lab_probe.py>) solo tras crear dentro de cada nodo un marcador root-owned de autorización con `purpose=dystopia-disposable-lab` y `authorization_id` del ejercicio. No hay fixture de host autoejecutable ni instalación de red automática.
6. Desde cliente permitido probar [ingress IPv4/IPv6](<tests/integration/ingress-targets.example.json>); desde invitado con root probar [egress denegado](<tests/integration/egress-targets.example.json>). El probe no cambia firewall ni rutas y solo admite destinos sintéticos literales, hasta 16 conexiones con timeout de 2 s. No envía exploits.

```sh
python3 tests/integration/lab_probe.py --targets tests/integration/ingress-targets.example.json \
  --confirm DISPOSABLE-LAB-ONLY
python3 tests/integration/lab_probe.py --targets tests/integration/egress-targets.example.json \
  --confirm DISPOSABLE-LAB-ONLY
```

7. Correlacionar negativos con capturas/counters del filtro externo y baseline vivo. El probe siempre emite `containment_verified=false`: su exit 0 solo indica observaciones compatibles, NO una certificación. Repetir con firewall del invitado neutralizado **solo dentro del invitado del laboratorio y con autorización**, para comprobar que no era este quien bloqueaba tráfico.
8. Matriz adicional autorizada: Ethernet fuente/MAC/IP falsos, IPv6 link-local/RA/ND, VLAN simple/doble, multicast/broadcast, fragmentos, encabezados de extensión, UDP, sesiones establecidas frente a nuevos flujos inversos y puertos no aprobados. Tráfico acotado, no ataques de disponibilidad. Conntrack compartido y cuotas por celda requieren evaluación aparte; los mocks no la cubren.
9. Con sesiones activas, detener/matar **solo el proceso de control de la celda** y repetir egress. Confirmar que reglas siguen en kernel. Aplicar cuarentena y comprobar que corta también sesiones existentes. Revisar recuperación sin borrar reglas ajenas. Repetir ante error de apply y pérdida del receptor de telemetría; observar saturación/retry en volumen scratch acotado.
10. Reinicio del hipervisor y reconciliación son una prueba distinta: siguen pendientes de implementar el guard de boot/verificador. No habilitar autostart de celdas antes de resolverlos.

## Evidencia mínima para levantar bloqueos en un cambio futuro

Versiones exactas de kernel/libvirt/nft/systemd/QEMU; hashes de política/XML/disco; topología y unidades efectivas; baseline positivo; capturas y counters negativos IPv4/IPv6/L2 con guest root; pérdida de controlador/cuarentena; pruebas de permisos/rotación/TLS/saturación; informe firmado por responsable con alcance y fecha. No añadir un booleano de aprobación al API como sustituto. El código actual no consume informes de cliente para habilitar celdas.
