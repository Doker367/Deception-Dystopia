# Informe de pruebas

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
