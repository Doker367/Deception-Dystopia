# Validación del sistema unificado Dystopia + T-Pot

Este documento registra **qué se implementó, qué se probó y qué queda pendiente**
en la integración del plano de deception de Dystopia con Elasticsearch/Kibana y
los honeypots de T-Pot. Es un informe de laboratorio, no una certificación de
producción.

Fecha de la validación local: **2026-10-30**
Stack: **Elasticsearch 9.3.5 + Kibana 9.3.5** sobre macOS/Colima.

## 1. Alcance validado

| Área | Estado | Evidencia |
|---|---|---|
| Contrato ECS + `dystopia.*` | Validado offline | Tests de contrato y mappings |
| Plantillas e ILM de Elasticsearch | Validado contra ES real | `bootstrap-security.sh --all` |
| Roles y usuarios de mínimo privilegio | Validado contra ES real | API `_security` |
| API key del publicador | Validada | Escritura `201`, permisos `0600` |
| Data streams | Validados | `deception-events`, `deception-alerts` + backing indices |
| Ingesta y deduplicación | Validada | `201` en creación, `409` en duplicado |
| Separación writer/analyst | Validada | writer no lee `403`; analyst lee `200` y no escribe `403` |
| Bundle de Kibana | Validado | 53/53 objetos importados |
| Dashboards | Validado visualmente | 7 dashboards renderizados con datos sintéticos |
| Discover | Validado | data view `deception-events*` y `defaultIndex` operativo |
| Contención KVM/nftables | **No validado** | Requiere Linux real |
| Honeypots reales | **No validado** | Solo fixtures/adaptadores y pruebas offline |
| Despliegue en máquina objetivo | **Pendiente** | No se instalaron servicios ni se abrió red señuelo |

## 2. Flujo implementado

```text
Dystopia (topología, dispositivos, segmentos)
        │
        ├── runtime/contracts.py       contrato de eventos v1
        ├── runtime/sensor.py          sensor de logs
        ├── runtime/ingest.py          recepción y persistencia
        ├── runtime/processor.py       normalización y alertas
        └── runtime/query.py           consulta de solo lectura
                │
                ▼
        contrato ECS + dystopia.*
                │
                ▼
        publicador Elasticsearch
                │
                ├── deception-events
                └── deception-alerts
                        │
                        ▼
                Kibana 9.3.5
                (7 dashboards)
```

La topología sigue siendo propiedad de Dystopia. Elasticsearch/Kibana es solo el
plano analítico; no sustituye la fuente de verdad de máquinas, segmentos ni
dispositivos.

## 3. Contrato de datos

- Data streams canónicos: `deception-events` y `deception-alerts`.
- Plantillas: nombre exacto y patrón `<nombre>-*`.
- Data views de Kibana: `deception-events*` / `deception-alerts*`.
- Idempotencia de ingesta: `event.id` como `_id`.
- Campos principales: `@timestamp`, `event.*`, `source.*`, `destination.*`,
  `network.*`, `observer.*`, `session.id` y `dystopia.*`.
- `dystopia.decoy_credentials` guarda **identificadores**, nunca valores de
  credenciales.
- Top-level `dynamic: false`; el bloque `dystopia` es `dynamic: strict`.

## 4. Seguridad aplicada

- Acceso anónimo deshabilitado; API keys habilitadas solo para el publicador.
- Roles separados: `deception-ingest-writer`, `deception-analyst`,
  `deception-admin`.
- El writer solo escribe en los data streams de deception y no tiene acceso a
  Kibana.
- El analyst tiene lectura y `minimal_read` en Kibana; no administra seguridad.
- El admin administra el espacio `deception-*` sin `manage_security`.
- API key escrita con permisos `0600` fuera del repositorio.
- Certificados de CA, nodo y Kibana con AKI/SKI y SAN; verificados por
  Python/OpenSSL y `curl`.
- Sin contraseñas por defecto ni secretos versionados.

## 5. Evidencia de la validación

| Prueba | Resultado |
|---|---|
| `bootstrap-security.sh --all` | exit `0`, idempotente |
| Escritura con API key | HTTP `201` |
| Repetición del mismo `event.id` | HTTP `409` |
| Writer intentando leer | HTTP `403` |
| Analyst leyendo | HTTP `200` |
| Analyst intentando escribir | HTTP `403` |
| Import Kibana | `success=true`, `53/53`, `0` errores |
| Bundle | 2 data views + 44 visualizaciones + 7 dashboards |
| Dashboards | 7/7 renderizados |
| Discover | data view `deception-events*` visible |
| Kibana `/api/status` | HTTP `200` |

Artefacto canónico:

- `deploy/kibana-dashboards/artifacts/deception-kibana-bundle.ndjson`
- SHA-256: `47477017d8737bd61c782c7611eee0855026d395ed1edde09c5dc45e70e586aa`
- Manifiesto: `deploy/kibana-dashboards/artifacts/MANIFEST.json`

## 6. Pruebas ejecutadas

Suites relevantes que pasan:

```text
tests/integration_unified
tests/deception/test_elastic_export.py
tests/deception/test_elasticsearch_publisher.py
tests/deception/test_external_adapters.py
tests/deception/test_topology_bindings.py
tests/ui
```

La suite completa quedó verde tras reconciliar las pruebas heredadas de
monitoring, firewall, engine, tokens antiguos y el puente de consulta:

```text
297 passed, 3 skipped, 175 subtests passed
```

Verificado en Python 3.14 y Python 3.12. `ruff check app tests` pasa sin
errores. Los 3 tests omitidos son opt-in de laboratorio, no fallos ocultos.

## 7. Pendientes antes de producción

1. **Linux real:** validar KVM/libvirt, systemd, permisos, usuarios de servicio,
   nftables y aislamiento por segmento.
2. **Honeypots:** construir y probar Cowrie, OpenCanary, Dionaea, Heralding,
   RedisHoneyPot y Endlessh con sus imágenes reales y healthchecks.
3. **Despliegue:** ejecutar `runtime.install` en la máquina objetivo, sin abrir
   listeners hasta completar la verificación.
4. **Red:** validar ingress/egress autorizados, NAT, rutas y ausencia de
   exposición a gestión.
5. **TLS:** terminar Kibana tras reverse proxy; no exponerlo directamente.
6. **Backup/restore:** registrar repositorio de snapshots y probar restauración.
7. **Observabilidad:** healthchecks, métricas, logs, alertas de caída y
   retención.
8. **CI:** la suite, `ruff` y el job de artefactos ya están configurados; falta
   validar el workflow en GitHub Actions y, opcionalmente, importar el bundle en
   un Kibana efímero.
9. **Operación:** runbook de incidentes, rotación de API keys, upgrade,
   rollback y respuesta a fuga de datos.

## 8. Plan de publicación recomendado

El trabajo ya está separado en commits lógicos sobre
`feature/unified-deception`. El árbol está limpio y las pruebas heredadas fueron
reconciliadas. Para el primer push:

- revisar el diff completo una última vez;
- confirmar que no hay secretos ni estado local;
- hacer push de la rama;
- abrir PR contra `main`, no push directo a `main`;
- esperar CI verde antes del merge.

## 9. Conclusión

El plano analítico y la integración de ingesta **están funcionales y
demostrados en el laboratorio**. Lo que falta no es “ver el dashboard”, sino
convertir esta base en un despliegue operable y certificado en Linux: red,
contención, honeypots reales, servicios, backups y CI verde.
