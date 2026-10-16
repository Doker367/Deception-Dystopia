# Informe de pruebas

Suite propia de Dystopia (11 archivos):

| Archivo | Ámbito |
|---|---|
| `tests/test_standalone_boundary.py` | Frontera: sin rutas/módulos del NOC, defaults fail-closed, sin rutas cruzadas |
| `tests/test_deception.py` | Núcleo de deception |
| `tests/test_deception_alerts.py` | Alertas |
| `tests/test_deception_engine.py` | Motor nativo |
| `tests/test_deception_extras.py` | Extras (paneles, personas) |
| `tests/test_deception_fp.py` | Falsos positivos con IA |
| `tests/test_deception_geo.py` | GeoIP / mapa |
| `tests/test_deception_integrations.py` | Cowrie / OpenCanary |
| `tests/test_fase3_deception.py` | Fase 3 |
| `tests/test_ai_decision_svc.py` | Laya (motor de decisiones) |
| `tests/test_monitoring_api.py` | API de monitoring propia |

| Prueba | Estado | Evidencia |
|---|---|---|
| Sintaxis Python completa | PASS | `ast.parse`, 0 errores |
| Git independiente/limpio/fsck | PASS | repo propio, historial nuevo |
| Imports NOC eliminados del entrypoint | PASS | routers NOC no registrados; imports rotos corregidos |
| Defaults loopback/fail-closed | PASS (estático) | API, syslog, metrics, deception y VMs off/loopback |
| Laya independiente | PASS (estático) | backend/stub/router/compose local presentes |
| Secretos/runtime por nombres versionados | PASS | sin coincidencias |
| pytest | NO_EJECUTADA | falta entorno virtual; instalar dependencias en cada repo |
| Go test/build | NO_EJECUTADA | no se permite descarga de módulos/cache no garantizada |
| Listeners/QEMU/Cowrie/OpenCanary | NO_EJECUTADA | por política no se arrancaron sockets, VMs o contenedores |

## Pruebas del NOC retiradas de este repositorio

Estos archivos probaban administración de red real y se movieron/eliminaron al
separar los productos (permanecen en `netpulse-noc`):
`test_auth_security.py`, `test_fase1_hardening.py`, `test_fase2.py`,
`test_fase2_noc.py`, `test_fase4_performance.py`, `test_inventory_api.py`,
`test_legacy_routing.py`, `test_netmiko_svc.py`, `test_sftp_api.py`.

No se eliminó ninguna prueba de deception: el catálogo de Dystopia está completo.

No se realizó ninguna conexión de red ni se arrancaron listeners.
