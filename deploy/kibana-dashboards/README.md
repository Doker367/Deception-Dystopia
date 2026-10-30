# deploy/kibana-dashboards — panel analítico Dystopia

Artefactos versionados del panel analítico `deception-*`. El bundle canónico
**está importado y validado** contra Kibana `9.3.5` en el laboratorio macOS:
53/53 objetos, 7 dashboards y 44 visualizaciones con datos sintéticos.

La fuente de verdad de máquinas, segmentos, dispositivos y personas sigue
siendo Dystopia. Kibana solo consulta el plano analítico `deception-events` /
`deception-alerts`.

## Estructura

| Ruta | Rol |
|---|---|
| `specs/deception-dashboards-spec.json` | **Contrato versionado** (`$version`) de 7 dashboards, 44 visualizaciones y 2 data views |
| `tools/build_dashboards.py` | Generador sin dependencias nuevas (stdlib). Valida campos, referencias, ids y sintaxis |
| `artifacts/deception-kibana-bundle.ndjson` | Bundle canónico (53 objetos) |
| `artifacts/deception-kibana-bundle-MANIFEST.json` | Hash SHA-256 + conteos del bundle canónico |
| `artifacts/...-with-map-EXPERIMENTAL.ndjson` | Variante con saved object Maps; no es el camino canónico |

## Dashboards

1. `deception-overview` — total, timeline, categorías, top IPs, protocolos, severidad y países.
2. `deception-geo-map` — países, ASN, zonas horarias y puertos de destino.
3. `deception-devices-segments` — `device_id`, `segment_id`, persona y timeline por dispositivo.
4. `deception-ssh-telnet` — sesiones SSH/Telnet, top IPs, puertos, outcome y credenciales señuelo.
5. `deception-decoy-credentials` — matches, identificadores, realms, timeline y persona.
6. `deception-dionaea-malware` — acciones, protocolos, top IPs y timeline.
7. `deception-ingest-health` — últimos 15 min, procedencia y lag de ingesta.

## Regeneración

```bash
cd deploy/kibana-dashboards
python3 tools/build_dashboards.py
python3 tools/build_dashboards.py --with-map \
  --out artifacts/deception-kibana-bundle-with-map-EXPERIMENTAL.ndjson
```

El generador falla si una visualización usa un campo fuera de su data view, si
un dashboard apunta a una visualización inexistente o si hay ids duplicados.

## Import (operador)

Con Elasticsearch y Kibana desplegados y `bootstrap-security.sh --all` ya
ejecutado:

```bash
curl -X POST -u deception_admin:"${DECEPTION_ADMIN_PASSWORD}" \
  "http://127.0.0.1:5601/api/saved_objects/_import?overwrite=true" \
  -H 'kbn-xsrf: true' \
  -F file=@artifacts/deception-kibana-bundle.ndjson
```

Usar `deception_admin`, nunca `elastic`. **No usar `createNewCopies=true`**:
Kibana regenera los IDs y deja de coincidir `defaultIndex:
deception-events-dv`. El import canónico conserva los IDs del bundle.

El `defaultIndex` se configura en `config/kibana/kibana.yml` y apunta al ID
`saved object` del data view, no al título.

## Formato del bundle (Kibana 9)

El import real obligó a corregir estos puntos, ya incorporados al generador:

- Data views con título `deception-events*` / `deception-alerts*` e ID
  `deception-events-dv` / `deception-alerts-dv`.
- `searchSourceJSON` dentro de `kibanaSavedObjectMeta`, con
  `indexRefName: kibanaSavedObjectMeta.searchSourceJSON.index`.
- Paneles de dashboard con `panelRefName`; el formato antiguo con `id`
  desplazaba las referencias durante la migración de Kibana 9.
- `seriesParams[].data = {id, label}` para line/histogram; sin ese objeto el
  panel quedaba en blanco o lanzaba `Cannot read properties of undefined`.
- Barras guardadas como `histogram` y paleta por defecto cuando no se declara.
- `format: "date"` en `date_histogram`, no un objeto.
- Filtro de rango DSL para “últimos 15 min”, con su referencia de índice.

## Validación realizada

En macOS con Elasticsearch/Kibana `9.3.5`:

- `bootstrap-security.sh --all` idempotente: roles, usuarios, API key `0600`,
  ILM, plantillas y data streams.
- Escritura real con API key `201`, duplicado `409`, writer sin lectura `403`,
  analyst lectura `200`, analyst sin escritura `403`.
- Data streams reales `deception-events` y `deception-alerts` con sus backing
  indices y política ILM.
- Import Kibana `53/53`, sin errores; 7 dashboards con referencias íntegras.
- Capturas headless de los 7 dashboards con datos sintéticos: metrics, pie,
  table, line e histogram renderizan.

## Pendiente / fuera de alcance de macOS

- Contención KVM/nftables, networking de segmentos y builds reales de
  honeypots no se pueden certificar en macOS.
- Despliegue en la máquina objetivo y TLS de Kibana tras reverse proxy.
- El saved object `map` de la variante experimental no es el camino canónico;
  el dashboard `deception-geo-map` canónico usa visualizaciones estándar.
