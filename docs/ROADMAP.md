# Roadmap — primer PR y despliegue del sistema unificado

Este roadmap ordena el trabajo desde la rama actual hasta el primer PR y, después,
hasta una validación real en Linux. La regla es simple: **no abrir un PR mientras
CI esté rojo y no mezclar cambios no certificados con el camino canónico.**

## Estado de partida

- Rama de trabajo: `feature/unified-deception`
- Base: `origin/main` en `1278db4`
- Commits locales: rama `feature/unified-deception` (ver `git log --oneline main..HEAD`)
- Árbol de trabajo: limpio
- Suite completa: **297 passed, 3 skipped, 175 subtests passed**
- Ruff: **verde**
- Python 3.12 y 3.14: **verde**
- Suites relevantes de la integración: verdes
- Rama remota: `origin/feature/unified-deception`
- PR: [#1](https://github.com/Doker367/Deception-Dystopia/pull/1)
- CI de GitHub Actions: **verde**

## Definición de “primer PR listo”

El primer PR puede abrirse cuando se cumplan todos estos puntos:

1. `python3.12 -m pytest -q` termina con exit `0`. ✅
2. `ruff check app tests` termina con exit `0`. ✅
3. `tests/integration_unified` pasa. ✅
4. El generador de Kibana produce el mismo bundle y hash. ✅
5. No hay secretos, certificados, claves, estado local ni artefactos
   experimentales en el diff. ✅
6. La documentación de operación y validación está enlazada desde `README.md`. ✅
7. El PR explica qué se validó en macOS y qué sigue pendiente en Linux. ✅
8. CI de GitHub Actions queda verde en la rama. ✅

## Hitos

| Hito | Objetivo | Criterio de salida |
|---|---|---|
| M0 | Base y preservación de cambios | Rama y commits locales |
| M1 | Reconciliar pruebas heredadas | Suite completa verde |
| M2 | Calidad estática y CI | Ruff/pytest verdes en Actions |
| M3 | Primer push y PR | PR abierto con CI verde ✅ |
| M4 | Laboratorio Linux | Instalación, red, honeypots y E2E validados |
| M5 | Producción | TLS, backups, observabilidad y runbooks probados |

## Olas de trabajo

### Ola 0 — Base (completada)

- Crear `feature/unified-deception`.
- Separar el trabajo en commits lógicos.
- Documentar alcance, evidencias y pendientes.
- Excluir artefactos experimentales de Maps.

### Ola 1 — Contratos de autenticación y API (completada)

**Problema:** las pruebas generan JWT sin el campo `ver` que exige la
invalidación por cambio de usuario. También esperan tokens de ingesta y
simulación heredados.

**Archivos principales:**

- `tests/test_deception.py`
- `app/middleware/auth.py`
- `app/routers/auth.py`
- `app/routers/deception.py`
- `app/core/security.py`

**Decisiones:**

- Actualizar las pruebas para crear tokens con el contrato actual (`sub`,
  `role`, `ver`).
- Mantener el rechazo de tokens revocados; no relajar seguridad para pasar tests.
- Decidir si la simulación heredada debe seguir devolviendo `409` o si se elimina
  definitivamente la prueba.
- Eliminar las pruebas del token de ingesta compartido si ya no existe.

**Criterio de salida:** pruebas de API de deception verdes sin desactivar RBAC ni
la invalidación de tokens.

### Ola 2 — Retirar o reescribir pruebas de funciones eliminadas (completada)

**Problema:** varias pruebas todavía importan constantes o endpoints de la
arquitectura anterior.

**Clusters:**

- `tests/test_monitoring_api.py`: endpoints `/api/monitoring/*` retirados.
- `tests/test_deception_engine.py`: arranque del motor nativo retirado.
- `tests/test_deception_geo.py`: `FIREWALL_ENABLED` retirado.
- `tests/test_deception_extras.py`: filtros de alertas movidos a configuración.
- `tests/test_deception_integrations.py`: `SOURCES` del tailer retirado.
- `tests/test_deception_fp.py`: constantes `DECEPTION_AI_FP_*` retiradas.

**Decisión por prueba:** actualizar al contrato nuevo o retirar con una nota que
explique qué la sustituye. No usar `skip` permanente para ocultar fallos.

**Criterio de salida:** ninguna prueba referencia APIs o constantes inexistentes;
la cobertura nueva vive en `tests/hardening`, `tests/integration_unified` y
`tests/ui`.

### Ola 3 — Portabilidad del puente de consulta (completada)

**Problema:** `tests/integration/test_query_bridge.py` falla en macOS con
`OSError: AF_UNIX path too long`.

**Archivos:**

- `tests/integration/test_query_bridge.py`
- `tests/integration/query_permissions_probe.py`
- `app/services/query_client.py`
- `runtime/query.py`

**Decisión:** usar directorios temporales cortos y limpiar sockets; validar en
macOS y Linux. No cambiar el transporte Unix ni debilitar permisos.

**Criterio de salida:** los tres tests del puente pasan en macOS y en CI Linux.

### Ola 4 — Lint, tipos y CI (completada en local)

**Trabajo:**

1. Instalar `ruff` y `pyright` desde `requirements-dev.txt`.
2. Corregir violaciones reales; no ampliar `ignore` sin justificación.
3. Verificar que CI usa Python 3.12, no el 3.14 del entorno local.
4. Añadir job de artefactos:
   - ejecutar `tests/integration_unified`;
   - regenerar el bundle y comparar SHA-256;
   - validar el manifiesto.
5. Añadir escaneo de secretos y `git diff --check`.
6. Mantener `typecheck` informativo hasta que Pyright esté limpio.

**Criterio de salida:** `ruff` y `pytest` verdes en local y en GitHub Actions.

### Ola 5 — Primer push y PR (completada)

1. Push de `feature/unified-deception`.
2. Abrir PR contra `main`.
3. Incluir en la descripción:
   - arquitectura;
   - evidencias de laboratorio;
   - hash del bundle;
   - resultados de tests;
   - pendientes Linux;
   - riesgos y rollback.
4. Revisar el diff por commits.
5. No hacer merge hasta CI verde y revisión humana.

### Ola 6 — Laboratorio Linux

- Ubuntu Server 24.04 en máquina objetivo o VM de laboratorio.
- `runtime.install --dry-run` y luego instalación real.
- systemd, usuarios, permisos y directorios.
- KVM/libvirt y celdas.
- nftables, routing, segmentos e ingress/egress autorizados.
- Construcción real de los seis honeypots.
- E2E: evento simulado → sensor → ingesta → procesador → Elasticsearch → Kibana.

### Ola 7 — Producción

- Kibana detrás de TLS/reverse proxy.
- Snapshots y restauración probada.
- Rotación de API keys y secretos.
- Observabilidad, alertas y retención.
- Runbook de incidentes, upgrade y rollback.
- Revisión de seguridad y threat model.

## Reglas para trabajar en olas paralelas

- La Ola 1 puede partir de la rama actual.
- Cada builder trabaja en un **worktree** o rama corta independiente.
- Un solo escritor por archivo; nada de dos agentes editando `tests/test_deception.py`.
- Los agentes no hacen push ni commit sin revisión.
- Cada ola termina con tests y un resumen de archivos tocados.
- Si una ola toca seguridad, se revisa antes de integrar.
- La integración de olas se hace siempre sobre `feature/unified-deception`.

## Qué falta exactamente para el primer push

- [x] Resolver los 21 fallos y 4 errores.
- [x] Confirmar que no hay regresión real en autenticación.
- [x] Corregir el socket Unix del puente de consulta.
- [x] Retirar/reescribir pruebas de features eliminadas.
- [x] Instalar y pasar `ruff`.
- [x] Probar la suite con Python 3.12.
- [x] Añadir o ajustar el workflow de CI.
- [x] Revisar el diff completo y secretos.
- [x] Push de la rama.
- [x] Abrir PR y esperar CI verde.

## Comandos de referencia

```bash
# Suite completa
.venv/bin/python -m pytest -q

# Integración unificada
.venv/bin/python -m pytest -q tests/integration_unified

# Lint (cuando ruff esté instalado)
.venv/bin/ruff check app tests

# Regenerar bundle y verificar hash
cd deploy/kibana-dashboards
python3 tools/build_dashboards.py
```
