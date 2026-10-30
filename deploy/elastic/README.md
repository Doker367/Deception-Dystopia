# deploy/elastic — Elasticsearch + Kibana (Dystopia)

Panel analítico de eventos normalizados de honeypots. **Dystopia conserva
configuración/control**; la salud del stack la sigue el stack
Prometheus/Loki/Grafana (área de otro agente), no este.

## Contenido

| Ruta | Rol |
|---|---|
| `docker-compose.elastic.yml` | Compose **no autoejecutable** (profile `deception-elastic`), versiones fijadas, bind solo en localhost/gestión |
| `.env.example` | Plantilla de variables **obligatorias** (NO versionar el real: `.env`) |
| `scripts/generate-certs.sh` | PKI única con openssl (ES http+transport y Kibana). Claves de nodo sin passphrase, chmod 0600/umask 077 |
| `scripts/bootstrap-security.sh` | Idempotente: roles + usuarios + ILM + index templates vía API autenticada |
| `roles/deception-ingest-writer.json` | Escritor: solo `deception-events*`/`deception-alerts*`, sin Kibana |
| `roles/deception-analyst.json` | Read-only en los data streams + `minimal_read` en Kibana |
| `roles/deception-admin.json` | Admin día a día sin `manage_security`; el superusuario solo para bootstrap/emergencias |

## Versiones

**Elasticsearch / Kibana 9.3.5** (`docker.elastic.co/...`), misma familia de stack
que tpotce 24.04.x (`tpotce/docker/elk/*/Dockerfile` define `ES_VER/KB_VER=9.3.5`).
NUNCA `latest`.

## Preparación de seguridad (diff con tpotce)

tpotce trae el stack con `xpack.security.enabled: false`; aquí es **opuesto**:
autenticación obligatoria, TLS en HTTP y transport, roles mínimos, sin
credenciales por defecto ni compartidas (`elastic` solo bootstrap; `deception_admin`
sin gestión de usuarios; `deception_writer` sin acceso a Kibana; `deception_analyst`
read-only, cada uno con password independiente en `.env`).

## Flujo de instalación (operador)

1. `cp .env.example .env` y rellenar TODOS los `CHANGEME_*`
   (passwords únicas por instancia, 16+ chars). El compose usa `:?` para obligar.
2. `chmod +x scripts/*.sh`
3. `./scripts/generate-certs.sh`
4. `sudo chown -R 1000:1000 <ELASTIC_CERTS_DIR>` (UID contenedor)
5. `mkdir -p data/elastic data/kibana && sudo chown -R 1000:1000 data/`
6. `docker compose -f deploy/elastic/docker-compose.elastic.yml --profile deception-elastic --env-file deploy/elastic/.env up -d`
   (requiere `vm.max_map_count >= 262144` en el host, estándar de ES)
7. `./scripts/bootstrap-security.sh --all`
8. Importar dashboards con `overwrite=true`: ver `../kibana-dashboards/README.md`.
9. Configurar la ingesta de Dystopia con
   `DYSTOPIA_ELASTIC_API_KEY_FILE=<ELASTIC_API_KEY_DIR>/dystopia-ingest-writer.api-key`
   apuntando a `https://127.0.0.1:${ELASTIC_HTTP_PORT}` con `ca.crt`. El
   usuario `deception_writer`/password queda para diagnóstico, no para el
   publicador normal.

## Retención (ILM)

`config/elasticsearch/ilm/*.json` + `ILM_DECEPTION_EVENTS_DAYS` (30d) /
`ILM_DECEPTION_ALERTS_DAYS` (90d) en `.env`. `bootstrap-security.sh
--install-templates` los aplica. Sin plugins externos (solo features base).

## Mappings / contratos

`config/elasticsearch/templates/deception-{events,alerts}-template.json`:
data streams `deception-events` / `deception-alerts` compatibles ECS 8.x con
`@timestamp`, `event.*`, `source.*` (geo incl. `geo_point`), `destination.*`,
`network.*`, `observer.*`, `session.id` y el bloque `dystopia` (`dynamic: strict`).
Las plantillas aceptan el nombre exacto y el patrón `<nombre>-*`. Los data views
de Kibana usan `deception-events*` / `deception-alerts*`.
Top-level `dynamic: false`: cualquier campo no declarado (payloads) queda en
`_source` pero **no se indexa ni agrega**. `decoy_credentials` guarda
IDENTIFICADORES, nunca valores.

## Validación real en macOS (Elasticsearch/Kibana 9.3.5)

Ejecutado en el laboratorio local con Colima, sin tocar KVM/nftables:

- Stack `green`/healthy; Kibana sirve `/api/status` con HTTP 200.
- `bootstrap-security.sh --all` idempotente: 3 roles, usuarios, API key `0600`,
  ILM, plantillas y data streams reales.
- Correcciones nacidas de la API real: `create_index` no es privilegio de
  clúster, `manage_ilm` sustituye a `manage_index_lifecycle`, metadata sin `_`,
  `active_only` en la consulta de API keys y `role_descriptors` en lugar de
  `roles` al crear la key.
- Certificados con `authorityKeyIdentifier`/`subjectKeyIdentifier`; Python/OpenSSL
  y `curl` verifican CA, nodo y Kibana.
- Ingesta real: `201` con API key, duplicado `409`, writer sin lectura `403`,
  analyst lectura `200` y sin escritura `403`.
- Los data streams se crean explícitamente con `PUT /_data_stream/<nombre>`;
  indexar un doc de arranque creaba un índice plano y no un data stream.
- Kibana importa el bundle con `53/53` objetos y los 7 dashboards renderizan
  con datos sintéticos (ver `../kibana-dashboards/README.md`).

## Riesgos y validaciones pendientes

- Contención KVM/nftables, networking de segmentos y builds reales de honeypots
  no se pueden certificar en macOS.
- Despliegue en la máquina objetivo, permisos definitivos de directorios y TLS
  de Kibana tras reverse proxy.
- Backup/snapshots de Elasticsearch: `path.repo` existe en Compose, pero no hay
  repositorio registrado ni restauración probada.
