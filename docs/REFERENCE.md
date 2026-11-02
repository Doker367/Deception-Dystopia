# Referencia técnica de Dystopia

Documento de consulta transversal: mapa del repositorio, componentes, variables,
puertos, roles, superficie de API, contrato de datos y comandos. No sustituye a
los runbooks de instalación y operación; enlaza a ellos para los procedimientos
largos.

**Estado del árbol:** código y artefactos presentes; instalación en Ubuntu
24.04, contención KVM/nftables y despliegue real siguen **pendientes de
validación**. Nada de este documento autoriza a arrancar servicios, abrir redes
o activar celdas.

---

## 1. Mapa del repositorio

```text
.
├── app/                     Plano de control FastAPI (solo gestión)
│   ├── core/                settings, JWT/bcrypt, rate limit
│   ├── middleware/          autenticación JWT, RBAC, auditoría, cabeceras
│   ├── models/              esquemas Pydantic (usuarios, deception)
│   ├── routers/             auth, admin_users, deception, vms, console
│   ├── services/            lógica de deception, consola, auditoría, métricas
│   ├── static/              dashboard/consola y assets locales
│   └── utils/               errores comunes
├── runtime/                 Procesos independientes del host
│   ├── cli.py               entrypoint: control, ingest, query, sensor, admin
│   ├── contracts.py         contrato de telemetría v1 (validación estricta)
│   ├── ingest.py            receptor HTTPS /v1/events
│   ├── sensor.py            spool + transporte HTTPS por sensor
│   ├── processor.py         worker de outbox/notificaciones
│   ├── query.py             lector SQLite de solo lectura + socket Unix
│   ├── storage.py           SQLite acotado (DELETE journal, cuotas)
│   ├── identity.py          registro y credenciales de sensores
│   ├── install.py           instalador offline (plan/apply/diagnose)
│   ├── localfiles.py        creación/lectura de archivos privados
│   ├── health.py            snapshot de estado de spool/eventos
│   └── isolation/           política, render y backend KVM/contenedor
├── config/                  Configuración versionada (no secretos)
│   ├── deception/           network.yaml / network.dev.yaml
│   ├── elasticsearch/       elasticsearch.yml, templates, ILM
│   ├── kibana/              kibana.yml
│   ├── groups.yaml          definición de grupos
│   ├── prometheus*.yml      observabilidad heredada
│   ├── loki-config.yml      logs
│   ├── promtail-config.yml  recolección de logs
│   ├── alertmanager.yml.template
│   └── webhooks.json
├── deploy/
│   ├── elastic/             compose ES/Kibana, roles, scripts, .env.example
│   ├── systemd/             5 services + 1 socket + 2 templates de aislamiento
│   ├── isolation/           contratos de celdas contenedor y operación
│   ├── honeypots/           inventario, perfiles, fixtures y adaptadores
│   ├── kibana-dashboards/   spec, generador y bundle NDJSON
│   ├── install.example.json plantilla sintética del instalador
│   ├── cell.example.json    plantilla sintética de celda
│   └── requirements-*.in    dependencias de control y test
├── tests/                   unitarios, hardening, integración, UI, deception
├── scripts/                 utilidades explícitas (smoke, seed, export, demo)
├── docs/                    runbooks, arquitectura, validaciones e informes
├── docker/                  Dockerfile auxiliar (Laya)
├── deception-engine/        data plane Go heredado/experimental
├── docker-compose.*.yml     compose de analítica, IA y laboratorio
├── Makefile                 plan, test y lint
├── pyproject.toml           ruff, pytest, pyright
└── requirements*.txt        dependencias de ejecución y desarrollo
```

Puntos de entrada reales:

- Control HTTP: `app.main:app`, lanzado por `runtime.cli control`.
- Ingesta: `runtime.cli ingest` (aplicación FastAPI propia en `runtime.ingest`).
- Consulta: `runtime.cli query` (socket Unix, sin TCP).
- Sensor: `runtime.cli sensor-drain`.
- Procesador: `python -m runtime.processor`.
- Instalador: `python -m runtime.install`.

`deception-engine/` es un data plane en Go que **no forma parte del camino de
ejecución certificado**; el control Python no lo arranca. Los compose
`docker-compose.deception.yml` y `docker-compose.lab.yml` están retirados y
declaran `services: {}`.

---

## 2. Componentes y tecnologías

| Componente | Implementación | Estado / límite |
|---|---|---|
| Control | Python 3.12+, FastAPI, Uvicorn, Pydantic, slowapi, JWT HS256, bcrypt, PyYAML | Solo gestión y lectura; no arranca sensores, VMs ni firewall |
| Sensor | `runtime.sensor` (spool SQLite + HTTPS) | Transporte entregado; colector de logs de honeypot por sensor pendiente |
| Ingesta | `runtime.ingest`, FastAPI separada, TLS directo, bearer por sensor | Proceso y contrato v1; despliegue TLS/red real pendiente |
| Procesador | `runtime.processor` (outbox transaccional) | Observa outbox; notificaciones externas requieren configuración explícita |
| Consulta | `runtime.query` sobre SQLite `mode=ro` y socket Unix | Implementado; no instalado ni verificado con UIDs Linux reales |
| Analítica | Elasticsearch 9.3.5 + Kibana 9.3.5 (Docker) | TLS y seguridad activas; validado en laboratorio macOS/Colima |
| Dashboards | Bundle NDJSON generado desde una spec versionada | 53 objetos, 7 dashboards; import con `overwrite=true` |
| Estado | SQLite (eventos, spool, registro de sensores, celdas) + YAML | Cuotas y journal `DELETE`; sin borrado automático |
| Contenedores | Docker / Docker Compose | Solo analítica e IA; compose de deception retirado |
| Servicios | systemd, usuarios de sistema sin login, sandbox por unidad | Sintaxis versionada; soporte efectivo de cgroup/BPF pendiente |
| Aislamiento | KVM/libvirt, nftables, `runtime.isolation` | Prototipo; activación bloqueada y contención **no verificada** |
| Calidad | pytest, ruff, pyright informativo, GitHub Actions | CI configurada en `.github/workflows/ci.yml` |

### Fronteras de confianza

```text
operador -> control (JWT, 127.0.0.1:8082) -> socket Unix -> query (solo lectura)
sensor -> HTTPS /v1/events -> ingest (escribe events.db) -> processor (outbox)
events.db -> publicador opt-in -> Elasticsearch -> Kibana
```

- El control **no** recibe ruta ni permisos de la base de ingestión.
- El sensor **no** recibe JWT, usuarios, CA privada ni base central.
- Elasticsearch/Kibana son el plano analítico; no sustituyen la topología.
- Una red Docker `internal`, una VLAN o un `nft --check` correcto no prueban
  contención.

Detalle: [UNIFIED-DECEPTION.md](UNIFIED-DECEPTION.md),
[hardening-isolation.md](hardening-isolation.md) y
[deploy/isolation/README.md](../deploy/isolation/README.md).

---

## 3. Variables de entorno

No hay secretos por defecto. El `.env` de la raíz es **solo referencia** y no se
carga automáticamente: el lanzador/systemd entrega el entorno de cada servicio.
`app/core/settings.py` conserva una función de carga de `.env` que no se invoca.

### 3.1 Control

| Variable | Obligatoria | Origen / efecto |
|---|---|---|
| `NETPULSE_JWT_SECRET` | **Sí**, al importar `app.core.security` | Firma JWT HS256; mínimo 32 bytes y distinto del valor de desarrollo. Si falta, el proceso falla cerrado. El instalador genera `secrets.token_urlsafe(48)` en `/etc/dystopia/control.env` (root `0600`) y nunca lo imprime. |
| `NETPULSE_ENV` | Sí en instalación | `production` en `control.env`; también gobierna la etiqueta de entorno de la consola. |
| `DYSTOPIA_CONTROL_STATE` | Sí en instalación | Estado del control. Instalador: `/var/lib/dystopia/control`. |
| `DYSTOPIA_CONTROL_CONFIG` | Sí en instalación | Configuración privada. Instalador: `/var/lib/dystopia/control/config`. |
| `NETPULSE_HOST` / `NETPULSE_PORT` | No | Bind del control; por defecto `127.0.0.1:8082`. La unidad fija `--host 127.0.0.1 --port 8082`. |
| `NETPULSE_TOKEN_EXPIRE` | No | Minutos de vida del JWT; por defecto `30`. |
| `NETPULSE_SSL_CERTFILE` / `NETPULSE_SSL_KEYFILE` | No | TLS del control; ambos o ninguno. Sin TLS, solo loopback. |
| `DYSTOPIA_QUERY_SOCKET` | Sí para consola | Ruta del socket; la unidad usa `/run/dystopia-query/query.sock`. |
| `DYSTOPIA_ENVIRONMENT` | No | Alternativa local a `NETPULSE_ENV` (`laboratory`/`production`). |

`/etc/dystopia/control.env` debe contener exactamente estas cuatro entradas:
`NETPULSE_JWT_SECRET`, `DYSTOPIA_CONTROL_STATE`, `DYSTOPIA_CONTROL_CONFIG` y
`NETPULSE_ENV`; el instalador rechaza cualquier otra composición.

### 3.2 Elasticsearch / Kibana

Se definen en `deploy/elastic/.env` (no versionado), a partir de
`deploy/elastic/.env.example`. El compose falla si faltan las marcadas `:?`.

| Variable | Obligatoria | Nota |
|---|---|---|
| `ELASTIC_VERSION` | Sí | Versión fijada; el ejemplo usa `9.3.5`. Nunca `latest`. |
| `ELASTIC_PASSWORD` | Sí | Password inicial del superusuario `elastic`; única por instancia. Si se omite en el primer arranque, el nodo puede generar una clave de arranque en log, que debe registrarse en el gestor de secretos. |
| `KIBANA_SYSTEM_PASSWORD` | Sí | Password del usuario de servicio `kibana_system`. |
| `KIBANA_SAVED_OBJECTS_ENCRYPTION_KEY` | Sí | 32 bytes en hex (64 caracteres); generar con `openssl rand -hex 32`. |
| `KIBANA_SECURE_SAVED_OBJECTS_ENCRYPTION_KEY` | Sí | Igual que la anterior, valor distinto. |
| `DECEPTION_WRITER_PASSWORD` | Sí | Password del usuario funcional `deception_writer` (diagnóstico). |
| `DECEPTION_ANALYST_PASSWORD` | Sí | Password del usuario `deception_analyst`. |
| `DECEPTION_ADMIN_PASSWORD` | Sí | Password del usuario `deception_admin`. |
| `ELASTIC_CA_PASSPHRASE` | Sí para `generate-certs.sh` | Frase de la CA; mínimo 20 caracteres. |
| `ELASTIC_API_KEY_DIR` | Sí para bootstrap | Directorio privado de API keys, modo `0700`; por defecto `deploy/elastic/api-keys`. |
| `DYSTOPIA_ELASTIC_API_KEY_FILE` | Sí si se publica | Ruta del fichero de la API key del publicador, nunca su valor. |
| `ELASTIC_DATA_DIR` / `KIBANA_DATA_DIR` | Sí en compose | Rutas de datos del host; usar rutas fuera del repo en un laboratorio real. |
| `ELASTIC_CERTS_DIR` | Sí | Directorio de certificados; por defecto `deploy/elastic/certs`. |
| `ELASTIC_BIND_IP` / `KIBANA_BIND_IP` | Sí | Bind de gestión; nunca `0.0.0.0`. Por defecto `127.0.0.1`. |
| `ELASTIC_HTTP_PORT` / `KIBANA_HTTP_PORT` | Sí | `9200` / `5601` por defecto. |
| `ELASTIC_JAVA_OPTS` / `ELASTIC_MEMORY_LIMIT` / `KIBANA_MEMORY_LIMIT` | No | Heap y límites de contenedor; el límite debe cubrir el heap con margen. |
| `ILM_DECEPTION_EVENTS_DAYS` / `ILM_DECEPTION_ALERTS_DAYS` | No | Retención aplicada por el bootstrap; ejemplo `30` / `90`. |
| `TZ`, `KIBANA_PUBLIC_BASE_URL`, `KIBANA_REPORTING_ENABLED` | No | Identificación del panel; reporting desactivado por defecto. |

Generación de secretos de Elastic:

- Passwords y frase de CA: los define el operador, únicos por instancia, y se
  guardan solo en `deploy/elastic/.env` o en el gestor de secretos.
- Claves de cifrado de Kibana: `openssl rand -hex 32`.
- API key del publicador: la crea `deploy/elastic/scripts/bootstrap-security.sh
  --create-api-key` en `ELASTIC_API_KEY_DIR`, con permisos privados.
- Certificados: `deploy/elastic/scripts/generate-certs.sh`.

### 3.3 Runtime, servicios y publicación

| Variable | Obligatoria | Uso |
|---|---|---|
| `DYSTOPIA_INGEST_BIND` | Sí en `ingest.env` | IP literal de bind del receptor; se pasa como `--host`. |
| `DYSTOPIA_INGEST_ENDPOINT` | Sí en `sensor.env` | URL HTTPS exacta terminada en `/v1/events`, con IP literal. |
| `DYSTOPIA_QUERY_GROUP` | Sí en unidades de ingest/processor | Grupo `dystopia-query` para el acceso de solo lectura a `events.db`. |
| `DYSTOPIA_ELASTIC_ENABLED` | No (por defecto `false`) | Activa el publicador; sin `true` no publica. |
| `DYSTOPIA_ELASTIC_URL` | Si el publicador está activo | Endpoint HTTPS de Elasticsearch. |
| `DYSTOPIA_ELASTIC_INDEX` | No | Data stream destino; por defecto `deception-events`. |
| `DYSTOPIA_ELASTIC_API_KEY_FILE` | Si el publicador está activo | Fichero privado con la API key. |
| `DYSTOPIA_ELASTIC_CA_FILE` | Si el publicador está activo | CA para validar Elasticsearch. |
| `DYSTOPIA_ELASTIC_TIMEOUT`, `_RETRIES`, `_BACKOFF`, `_MAX_BACKOFF`, `_BATCH` | No | Límites de entrega y reintentos. |
| `DYSTOPIA_ELASTIC_QUEUE`, `_QUEUE_MAX`, `_QUEUE_BYTES` | No | Cola durable y sus cuotas. Sin ruta, la cola es en memoria. |
| `NETPULSE_ALERTMANAGER_TOKEN` | No | Token de servicio para el webhook de Alertmanager; si falta, se exige JWT admin. No aplica a los routers montados en el build actual. |
| `NETPULSE_DECEPTION_*`, `NETPULSE_VMS_*`, `NETPULSE_FIREWALL_ENABLED` | No | Flags heredados; el build endurecido mantiene estas rutas bloqueadas. |

Credenciales de sensor: se generan con `runtime.cli rotate-sensor`, que escribe
un fichero nuevo (nunca las imprime). El receptor guarda solo el digest.

### 3.4 Laboratorio

| Variable | Obligatoria | Uso |
|---|---|---|
| `DYSTOPIA_ENVIRONMENT` | No | `laboratory` o `production` cuando no existe `NETPULSE_ENV`; ausente u otro valor = `unconfigured`. |
| `DYSTOPIA_LAB_CONFIRM` | Sí en modo lab | Debe ser exactamente `DISPOSABLE-LAB-ONLY`. |
| `DYSTOPIA_LAB_MARKER` | Sí en modo lab | Fichero marcador con propósito y autorización. |
| `DYSTOPIA_LAB_TARGETS` | Sí en modo lab | Allowlist explícita de destinos RFC1918/loopback. |
| `DYSTOPIA_LAB_SCENARIO` | Sí en modo lab | Escenario autorizado. |
| `DYSTOPIA_LAB_E2E` | No | `preflight` o `full`. |
| `DYSTOPIA_LAB_SSH_PERFORMED` | Sí en `full` | Testigo de que el operador realizó el login benigno. |

Los smoke tests offline eliminan estas variables del entorno para no activar
pruebas de red por herencia.

---

## 4. Puertos y rutas

### Puertos de Dystopia

| Puerto | Protocolo | Bind | Uso |
|---|---|---|---|
| `8082` | TCP | `127.0.0.1` | API de control y consola |
| `5601` | TCP | `127.0.0.1` / gestión | Kibana; debe ir tras proxy/TLS en producción |
| `9200` | TCP | `127.0.0.1` / gestión | Elasticsearch; nunca público |
| `8443` | TCP/TLS | red de telemetría | Ingesta `runtime.ingest` (`/v1/events`); deshabilitada por defecto |
| `5900+` | TCP | local | Consola VNC de VMs señuelo (registro/heredado, no certificado) |
| `45000+` | TCP | local | Puerto serie de VMs señuelo (registro/heredado) |
| Unix socket | local | `/run/dystopia-query/query.sock` | Consulta de solo lectura, sin TCP |

Los puertos de honeypots dependen de la celda y del perfil; están inventariados
en [deploy/honeypots/inventory.yaml](../deploy/honeypots/inventory.yaml).

**T-Pot:** los puertos `64294`, `64295` y `64297` pertenecen a la gestión de
T-Pot. **Dystopia no los usa**; no se abren por analogía.

### Rutas de estado y configuración

| Ruta | Contenido | Permisos esperados |
|---|---|---|
| `/var/lib/dystopia/control` | Estado privado del control, backups, reportes | `dystopia-control`, `0700` |
| `/var/lib/dystopia/control/config` | `users.yaml`, topología y configuración privada | `dystopia-control`, `0700` |
| `/var/lib/dystopia/control/audit` | Auditoría local | `dystopia-control`, `0700` |
| `/var/lib/dystopia/control/deception` | Estado de deception y DB heredada | `dystopia-control`, `0700` |
| `/var/lib/dystopia/ingest` | `events.db`, `sensors.db`, certificado y clave TLS | `dystopia-ingest:dystopia-query`, `0710` de travesía |
| `/var/lib/dystopia/ingest/events.db` | Eventos v1 | `dystopia-ingest:dystopia-query`, `0640` tras provisión |
| `/var/lib/dystopia/ingest/sensors.db` | Registro de sensores y digests | `dystopia-ingest`, `0600` |
| `/var/lib/dystopia/sensor` | Spool y credencial del sensor | `dystopia-sensor`, `0700` |
| `/run/dystopia-query/query.sock` | Socket de consulta | `dystopia-control:dystopia-control`, `0600` |
| `/etc/dystopia/control.env` | Entorno del control y JWT | root, `0600` |
| `/etc/dystopia/ingest.env` | Bind de ingesta | root, `0600` |
| `/etc/dystopia/sensor.env` | Endpoint de ingesta | root, `0600` |
| `/opt/dystopia/current` | Release inmutable, root-owned, sin secretos | root, sin escritura de grupo/otros |
| `/opt/dystopia/venv` | Virtualenv offline atestado al lock | root |
| `config/` (repo) | Configuración versionada, sin secretos | — |
| `deploy/elastic/certs/` | CA y certificados | ignorado por git; `0600`/`0700` |
| `deploy/elastic/api-keys/` | API keys emitidas | ignorado por git; `0700` |

Rutas de desarrollo (sin instalador): el estado y la configuración caen por
defecto en la raíz del repo (`BASE_DIR`), y `deploy/elastic/.env`, `certs/` y
`api-keys/` están excluidos de git. No usar estas rutas para producción.

---

## 5. Roles y permisos

Hay **tres modelos distintos** que no deben confundirse:

### 5.1 Roles de la aplicación (JWT)

| Rol JWT | Nivel | Uso |
|---|---|---|
| `viewer` | 1 | Lectura de consola, eventos, topología y registro de VMs |
| `operator` | 2 | Puede validar borradores de celda; no crea ni edita |
| `admin` | 3 | Usuarios, auditoría, topología, borradores y configuración |

La jerarquía es `admin > operator > viewer`. El token incluye `sub`, `role` y
`ver` (hash del password); cambiar el password o borrar el usuario invalida el
token. El login está limitado a 5 intentos/minuto por IP. No hay MFA ni
revocación individual de sesión.

### 5.2 Roles de Elasticsearch / Kibana

| Identidad | Tipo | Permisos |
|---|---|---|
| `deception-admin` | rol + usuario funcional | Administración diaria de `deception-events*` y `deception-alerts*` (índices, plantillas, ILM, pipelines) y de `.kibana*`; **sin** `manage_security` |
| `deception-analyst` | rol + usuario funcional | `read` + `view_index_metadata` en los data streams y `minimal_read` en Kibana; sin escritura |
| `deception-ingest-writer` | rol + API key | `create_doc`, `create_index`, `view_index_metadata` solo en `deception-events*`/`deception-alerts*`; sin Kibana ni lectura general |
| `kibana_system` | usuario de servicio | Conexión interna de Kibana a Elasticsearch |
| `elastic` | superusuario integrado | Solo bootstrap y emergencias; no uso diario |

`deception_writer`, `deception_analyst` y `deception_admin` son los nombres de
usuario que crea el bootstrap; los roles se llaman con guiones. No comparten
passwords ni API keys.

### 5.3 Usuarios de sistema

| Usuario | Función | Restricciones |
|---|---|---|
| `dystopia-control` | Control y consola | Sin login, sin grupos extra, sin acceso a ingestión |
| `dystopia-ingest` | Ingesta y processor | Escribe `events.db`; sin control ni sensores |
| `dystopia-sensor` | Spool/transporte del sensor | Sin acceso a configuración administrativa |
| `dystopia-query` | Lector SQLite | Sin grupos suplementarios, sin escritura, sin JWT |

Los servicios se ejecutan con `NoNewPrivileges`, capacidades vacías,
`ProtectSystem=strict`, filtros de llamadas y de direcciones. La unidad de
aislamiento es la única con `CAP_NET_ADMIN`/`CAP_NET_RAW` y solo se inicia de
forma explícita (sin `[Install]`).

---

## 6. API

Superficie real montada por `app.main`: **58 paths y 71 operaciones** en el
OpenAPI (sin contar la ruta heredada oculta). Se puede regenerar con:

```bash
NETPULSE_JWT_SECRET='<secreto-sintetico-de-32-o-mas-bytes>' \
  python -c "from app.main import app; print(app.openapi())"
```

### 6.1 Autenticación y salud

| Método | Ruta | Rol | Nota |
|---|---|---|---|
| POST | `/api/auth/login` | público | Devuelve JWT; 5/min por IP |
| GET | `/api/auth/me` | autenticado | Usuario y rol actuales |
| GET | `/api/health` | público | Estado del plano de control y auditoría |
| GET | `/` | público | Dashboard estático |
| GET | `/favicon.svg` | público | Icono |

### 6.2 Administración de usuarios

Todas requieren rol `admin`.

| Método | Ruta |
|---|---|
| GET | `/api/admin/users` |
| POST | `/api/admin/users` |
| GET | `/api/admin/users/{username}` |
| PUT | `/api/admin/users/{username}` |
| DELETE | `/api/admin/users/{username}` |

### 6.3 Deception

`viewer` = lectura; `admin` = mutación permitida. El resto de mutaciones se
bloquea antes de leer el cuerpo (ver 6.6).

| Método | Ruta | Rol | Estado |
|---|---|---|---|
| GET | `/api/deception/status` | viewer | Estado bloqueado del subsistema |
| GET | `/api/deception/network` | viewer | Topología completa |
| GET | `/api/deception/segments` | viewer | Segmentos |
| POST | `/api/deception/segments` | admin | Crear |
| DELETE | `/api/deception/segments/{segment_id}` | admin | Borrar si está vacío |
| GET | `/api/deception/devices` | viewer | Dispositivos |
| POST | `/api/deception/devices` | admin | Crear |
| GET | `/api/deception/devices/{device_id}` | viewer | Detalle |
| PUT | `/api/deception/devices/{device_id}` | admin | Actualizar |
| DELETE | `/api/deception/devices/{device_id}` | admin | Borrar |
| GET | `/api/deception/bindings` | viewer | Vista declarativa para honeypots |
| GET | `/api/deception/bindings/resolve/{instance_id}` | viewer | Resolver device/segment/persona |
| GET | `/api/deception/events` | viewer | Eventos (DB heredada) |
| GET | `/api/deception/sessions` | viewer | Sesiones agregadas |
| GET | `/api/deception/alerts` | viewer | Alertas |
| GET | `/api/deception/false-positives` | viewer | Alertas suprimidas |
| GET | `/api/deception/timeline` | viewer | Serie temporal |
| GET | `/api/deception/events.csv` | viewer | Export CSV |
| GET | `/api/deception/stats` | viewer | Estadísticas |
| GET | `/api/deception/blocklist` | viewer | IPs bloqueadas |
| GET | `/api/deception/iocs` | viewer | IOCs |
| GET | `/api/deception/iocs.csv` | viewer | Export de IOCs |
| GET | `/api/deception/allowlist` | viewer | Legacy, no aplicada |
| GET | `/api/deception/geo` | viewer | Mapa de ataques |
| GET | `/api/deception/geoip/{ip}` | viewer | GeoIP offline |
| GET | `/api/deception/firewall/status` | viewer | Estado del firewall |
| GET | `/api/deception/engine/status` | viewer | Estado del motor nativo |
| GET | `/api/deception/integrations/status` | viewer | Estado del tailer |

Rutas presentes en el router pero **bloqueadas**:

| Método | Ruta | Respuesta |
|---|---|---|
| POST | `/api/deception/ingest` | `410` — usar el servicio TLS `/v1/events` (oculta del OpenAPI) |
| POST | `/api/deception/simulate` | `409` — ejecución heredada deshabilitada |
| POST | `/api/deception/engine/start` | `409` — ejecución heredada deshabilitada |
| POST | `/api/deception/engine/stop` | `409` — ejecución heredada deshabilitada |
| POST | `/api/deception/integrations/start` | `409` — ejecución heredada deshabilitada |
| POST | `/api/deception/integrations/stop` | `409` — ejecución heredada deshabilitada |
| POST | `/api/deception/blocklist` | `409` — ejecución heredada deshabilitada |
| DELETE | `/api/deception/blocklist/{ip}` | `409` — ejecución heredada deshabilitada |
| POST | `/api/deception/sync-netbox` | `409` — ejecución heredada deshabilitada |
| POST | `/api/deception/allowlist` | `409` — ejecución heredada deshabilitada |
| DELETE | `/api/deception/allowlist/{cidr}` | `409` — ejecución heredada deshabilitada |
| POST | `/api/deception/firewall/block` | `409` — ejecución heredada deshabilitada |
| POST | `/api/deception/firewall/unblock` | `409` — ejecución heredada deshabilitada |

### 6.4 Consola

Todas requieren JWT y rol mínimo `viewer`; los eventos exigen además una sesión
humana (se rechazan API keys `np_` en esa superficie).

| Método | Ruta | Rol | Nota |
|---|---|---|---|
| GET | `/api/console/capabilities` | viewer | Entorno y capacidades |
| GET | `/api/console/cells` | viewer | Celdas declarativas |
| GET | `/api/console/cells/{cell_id}` | viewer | Detalle |
| POST | `/api/console/cells/{cell_id}` | admin | Crear borrador |
| PUT | `/api/console/cells/{cell_id}` | admin | Editar con revisión |
| POST | `/api/console/cells/{cell_id}/validate` | operator | Validación declarativa |
| POST | `/api/console/cells/{cell_id}/prepare` | admin | **Siempre 409** `ActivationBlocked` |
| POST | `/api/console/cells/{cell_id}/activate` | admin | **Siempre 409** `ActivationBlocked` |
| GET | `/api/console/cells/{cell_id}/history` | viewer | Historial |
| GET | `/api/console/events` | viewer | Vía socket Unix |
| GET | `/api/console/events/{sensor}/{event_id}` | viewer | Detalle permitido |
| GET | `/api/console/activity` | viewer | Actividad |
| GET | `/api/console/audit` | admin | Auditoría |
| GET | `/api/console/events.csv` | viewer | Export acotado |

Sin socket, DB o índice, los eventos devuelven **503 con `X-Query-Error-ID`**;
nunca un cero falso ni fallback a SQLite desde el control.

### 6.5 VMs

| Método | Ruta | Rol | Estado |
|---|---|---|---|
| GET | `/api/vms` | viewer | Registro de solo lectura |
| GET | `/api/vms/isos` | viewer | ISOs disponibles |
| POST | `/api/vms` | admin | **409** — lifecycle local, no API |
| POST | `/api/vms/isos` | admin | **409** — lifecycle local, no API |
| POST | `/api/vms/{vm_id}/start` | admin | **409** — lifecycle local, no API |
| POST | `/api/vms/{vm_id}/stop` | admin | **409** — lifecycle local, no API |
| DELETE | `/api/vms/{vm_id}` | admin | **409** — lifecycle local, no API |

### 6.6 Routers no montados

`app/routers/` conserva módulos que `app.main` **no incluye**: `ai.py`,
`audit.py`, `metrics.py`, `monitoring.py`, `notifications.py`,
`prometheus_proxy.py` y `security_ext.py`. No forman parte de la superficie
expuesta y no deben documentarse como endpoints disponibles.

La frontera `control_boundary` se evalúa antes que el cuerpo de la petición:
solo `GET/HEAD/OPTIONS` y las rutas de configuración
`/api/deception/devices*` y `/api/deception/segments*` pueden mutar. Por eso
`simulate`, `engine/*`, `integrations/*`, `blocklist`, `allowlist`, `firewall/*`
y `sync-netbox` responden `409` aunque su dependencia declare rol `admin`.

---

## 7. Contrato de datos

Existen dos contratos complementarios:

1. **Transporte v1** (`runtime.contracts`): lo que el sensor envía al receptor.
2. **Documento ECS/Dystopia** (`app/services/deception/integrations/ecs.py`):
   lo que el publicador escribe en Elasticsearch.

### 7.1 Transporte v1

- Lote JSON exacto: `{"version": 1, "events": [...]}`.
- Máximo 64 eventos/lote, 256 KiB/lote y 8 KiB/evento.
- Campos obligatorios del evento: `event_id`, `device_id`, `observed_at`,
  `src_ip`, `type`, `proto`; opcionales: `src_port`, `detail`.
- `event_id`: UUID4 canónico.
- `device_id`: identificador `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`.
- `observed_at`: ISO 8601 con zona; se normaliza a UTC. Es una declaración **no
  confiable**; las ventanas operativas usan `received_at`.
- `src_ip`: IP canónica (sin `%zona`).
- `type`: `connect`, `disconnect`, `login_attempt`, `login_success`, `command`,
  `file_download`, `port_scan`, `other`.
- `proto`: `tcp`, `udp`, `ssh`, `telnet`, `http`, `ftp`, `mysql`, `snmp`.
- `detail`: hasta 16 claves de identificador y valores string de hasta 2 KiB;
  sin objetos anidados. Se rechazan `simulated`, `sensor_id`, `trusted` y
  `suppress`.

La deduplicación del receptor es `(sensor, event_id)`. El mismo ID con contenido
distinto es conflicto; no se sobrescribe.

### 7.2 Documento ECS/Dystopia

| Campo | Tipo / contenido |
|---|---|
| `@timestamp` | `date`; instante del evento normalizado |
| `event.id` | `keyword`; ID estable e idempotente |
| `event.kind` | `event`, `alert`, etc. |
| `event.category` | array ECS (`network`, `authentication`, `process`, `file`, `web`, `host`) |
| `event.type` | array ECS (`connection`, `start`, `end`, `access`, `change`, `info`) |
| `event.action` | acción normalizada (`login`, `command`, `file_download`, …) |
| `event.severity` | entero 1–5: info, low, medium, high, critical |
| `event.outcome` | `success`/`failure` cuando aplica |
| `event.dataset` | origen lógico, p. ej. `deception.cowrie` |
| `event.ingested` | instante de ingesta |
| `source.ip`, `source.port` | origen; `source.as`, `source.geo` enriquecidos |
| `source.geo.location` | `geo_point` |
| `destination.ip`, `destination.port` | señuelo/servicio |
| `network.transport`, `network.protocol` | transporte y protocolo |
| `network.bytes`, `network.packets` | volumetría cuando existe |
| `observer.type`, `observer.name`, `observer.product`, `observer.vendor`, `observer.version` | sensor/honeypot |
| `session.id` | correlación de sesión |
| `dystopia.schema_version` | versión del esquema (`keyword`) |
| `dystopia.device_id`, `segment_id`, `instance_id`, `persona` | topología declarativa |
| `dystopia.decoy_credentials` | **identificadores** de credenciales señuelo, nunca valores |
| `dystopia.decoy_credential_matches`, `decoy_credential_realm` | coincidencias y realm |
| `dystopia.raw_reference` | referencia opaca al origen |
| `dystopia.ingest_source`, `control_version` | procedencia y versión |

Mapeo: `config/elasticsearch/templates/deception-events-template.json` y
`deception-alerts-template.json`. El nivel superior es `dynamic: false`: los
campos no declarados quedan en `_source` pero no se indexan. El objeto
`dystopia` es `dynamic: strict`: un campo no declarado rechaza el documento.

Los payloads hostiles y secretos capturados no se indexan; `dystopia_restricted`
es el contenedor no indexado previsto para ellos.

### 7.3 Data streams e idempotencia

| Data stream | Plantilla | ILM por defecto |
|---|---|---|
| `deception-events` | `deception-events-template.json` | 30 días (configurable) |
| `deception-alerts` | `deception-alerts-template.json` | 90 días (configurable) |

- Las plantillas aceptan el nombre exacto y el patrón `<nombre>-*`.
- Los data views de Kibana usan `deception-events*` y `deception-alerts*`.
- El publicador usa `PUT /<índice>/_create/<event.id>`: reproducir la misma
  línea no crea un segundo documento.
- Un `409` de `_create` se considera éxito (el estado deseado ya existe); un
  2xx elimina la fila de la cola. Otros errores dejan el evento encolado.
- El mismo `event.id` con contenido distinto se detecta como conflicto en la
  cola (`DocumentConflict`) y no se sobrescribe.
- La cola es SQLite acotada o en memoria; el llenado es un fallo explícito,
  nunca un ACK silencioso.

---

## 8. Comandos de referencia

Todos los comandos se ejecutan desde la raíz del repo salvo que se indique otra
cosa. No descargan dependencias ni arrancan servicios por sí solos.

### Tests y calidad

```bash
# Suite completa (requiere dependencias de requirements-dev.txt)
python3 -m pytest tests -q

# Suite de hardening preparada para sandbox
python3 -m pytest tests/hardening -q -p no:cacheprovider

# Contratos de integración y UI
python3 -m pytest -q tests/integration_unified tests/ui

# Lint (mismo comando que CI)
ruff check app tests

# Typecheck informativo
pyright app --pythonpath "$(which python)"
```

`make test` ejecuta solo `tests/hardening`.

### Instalación: plan y dry-run

```bash
# Plan guiado, sin escribir nada
python3 -m runtime.install --guided

# Dry-run con la plantilla sintética
python3 -m runtime.install --dry-run --config deploy/install.example.json

# Equivalente vía Makefile
make plan CONFIG=deploy/install.example.json
```

`--dry-run`/`--plan` valida el esquema y devuelve el plan; no crea usuarios,
directorios, unidades ni redes. `--apply` exige root, Ubuntu 24.04, bundle
offline revisado y la confirmación `APPLY-MANAGEMENT-ONLY`.

### Bundle de Kibana

```bash
cd deploy/kibana-dashboards
python3 tools/build_dashboards.py
python3 tools/build_dashboards.py --with-map \
  --out artifacts/deception-kibana-bundle-with-map-EXPERIMENTAL.ndjson
```

El generador valida campos, referencias e IDs y reescribe el bundle canónico.
El import se hace con `overwrite=true` y el usuario `deception_admin`; el
procedimiento está en [deploy/kibana-dashboards/README.md](../deploy/kibana-dashboards/README.md).

### Bootstrap de Elasticsearch

```bash
cp deploy/elastic/.env.example deploy/elastic/.env   # rellenar CHANGEME_*
chmod +x deploy/elastic/scripts/*.sh
deploy/elastic/scripts/generate-certs.sh
deploy/elastic/scripts/bootstrap-security.sh --all
```

`--all` es idempotente: roles, usuarios, ILM, plantillas, data streams y API key
del writer. No imprime secretos por stdout.

### Primer administrador local

```bash
cd /opt/dystopia/current
runuser -u dystopia-control -- /opt/dystopia/venv/bin/python -m runtime.cli \
  bootstrap-admin \
  --users /var/lib/dystopia/control/config/users.yaml \
  --username NOMBRE_ELEGIDO
```

La contraseña se introduce por TTY (mínimo 16 caracteres, máximo 72 bytes
UTF-8). El bootstrap no sobrescribe usuarios existentes.

### Evento sintético y export

```bash
# Ver el documento sin enviarlo
python3 scripts/seed_demo_event.py --dry-run

# Enviar un evento sintético al data stream (requiere API key y CA)
python3 scripts/seed_demo_event.py --url https://127.0.0.1:9200 \
  --ca-cert deploy/elastic/certs/ca.crt \
  --api-key-file deploy/elastic/api-keys/deception-ingest-writer.api-key

# Export runtime -> Elasticsearch, deshabilitado salvo --enable-elastic
python3 scripts/run_elastic_export.py \
  --events /var/lib/dystopia/ingest/events.db \
  --state /var/lib/dystopia/control/export-cursor.db
```

El seed usa `PUT /deception-events/_create/<event.id>` y solo contiene valores
sintéticos. El export exige cola durable y no arranca sensor ni ingesta.

### Estado local

```bash
python3 -m runtime.cli status --spool /var/lib/dystopia/sensor/spool.db
python3 -m runtime.cli status --events /var/lib/dystopia/ingest/events.db
```

Abre SQLite en solo lectura y no crea una base ausente.

### Smoke tests

```bash
# Offline: fixtures y fakes, sin red
scripts/smoke_unified.sh --offline

# Laboratorio desechable, solo con autorización y marcador
DYSTOPIA_LAB_CONFIRM=DISPOSABLE-LAB-ONLY \
DYSTOPIA_LAB_MARKER=/ruta/marcador \
DYSTOPIA_LAB_TARGETS=10.20.30.40 \
DYSTOPIA_LAB_SCENARIO=/ruta/scenario.json \
  scripts/smoke_unified.sh --lab
```

---

## 9. Troubleshooting breve

### Elasticsearch no arranca

1. Comprobar `vm.max_map_count` en el host (Elasticsearch requiere al menos
   `262144`); es un ajuste del sistema, no del repo.
2. Revisar que `deploy/elastic/.env` existe y no conserva valores `CHANGEME_*`.
3. Verificar propietario de datos y certificados: los contenedores esperan UID
   `1000`; `chown -R 1000:1000` solo sobre los directorios indicados.
4. Revisar que los certificados existen en `ELASTIC_CERTS_DIR` y que la CA
   valida el nodo.
5. Consultar logs y salud:

```bash
docker compose -f deploy/elastic/docker-compose.elastic.yml \
  --profile deception-elastic --env-file deploy/elastic/.env ps
docker compose -f deploy/elastic/docker-compose.elastic.yml \
  --profile deception-elastic --env-file deploy/elastic/.env logs elasticsearch
curl --cacert deploy/elastic/certs/ca.crt -u elastic \
  https://127.0.0.1:9200/_cluster/health
```

No imprimir la password en el historial; usar un fichero privado o el gestor de
secretos.

### Kibana arranca pero no muestra datos

1. Confirmar que Elasticsearch está `green`/`yellow` y que Kibana usa
   `kibana_system` con TLS `full`.
2. Comprobar que los data streams existen:
   `GET _data_stream/deception-events` y `GET _data_stream/deception-alerts`.
3. Verificar que el bundle se importó con `overwrite=true` y que el data view
   por defecto sigue siendo `deception-events-dv`.
4. Si se regeneraron las claves de cifrado de Kibana, los saved objects previos
   pueden ser ilegibles; restaurar la clave original o reimportar el bundle.
5. Enviar un evento sintético y buscar su `event.id` en Discover. Un data view
   vacío no prueba que no haya ataques.

### 401 / 403

- **401**: falta el header `Authorization: Bearer`, el token expiró, la firma no
  coincide o el usuario/password cambió (`ver` inválido). Volver a hacer login.
- **403**: token válido con rol insuficiente, o esquema distinto de `Bearer`.
  Revisar el rol (`viewer`/`operator`/`admin`) y no confundirlo con los roles de
  Elasticsearch.
- En Elasticsearch, un `403` del writer al leer es correcto: el rol solo escribe.
  Un `401` suele indicar API key revocada, fichero equivocado o CA incorrecta.
- En la consola, las API keys `np_` se rechazan para eventos; se exige sesión de
  usuario real.

### Socket Unix de consulta

```bash
systemctl status dystopia-query.socket dystopia-query.service
stat -c '%U:%G %a %n' /run/dystopia-query/query.sock
journalctl -u dystopia-query.service --since today
```

- `503` con `X-Query-Error-ID`: socket deshabilitado, UID incorrecto, DB o
  índice ausente, permisos, bloqueo o timeout. Correlacionar el ID con
  `event_query_failure` en el control.
- `DENIED`: `SO_PEERCRED` no coincide con `dystopia-control`; revisar
  propietario/modo del socket y el UID efectivo del proceso.
- `422`: filtro inválido, periodo superior a 7 días o cursor caducado. Reiniciar
  la paginación.
- Habilitar **solo el socket**, no el servicio directamente. No dar al control
  acceso SQLite para “hacer funcionar” la gráfica.

Detalle: [QUERY-BRIDGE.md](QUERY-BRIDGE.md).

### Puerto ocupado

```bash
lsof -nP -iTCP:8082 -sTCP:LISTEN
lsof -nP -iTCP:9200 -sTCP:LISTEN
lsof -nP -iTCP:5601 -sTCP:LISTEN
```

- `8082` ocupado: localizar el proceso y detenerlo de forma autorizada; no
  cambiar el puerto de la unidad sin revisar el filtro `SocketBindAllow`.
- `9200`/`5601` ocupados: otro stack Elastic o un contenedor previo. Revisar
  `docker ps` antes de recrear; no borrar volúmenes para “liberar” el puerto.
- Si el socket existe pero nadie escucha, revisar `dystopia-query.socket` y
  `RemoveOnStop=yes`; no borrar el socket a mano con el servicio activo.

### Otros síntomas

| Síntoma | Causa probable | Acción |
|---|---|---|
| `RuntimeError: Provision a unique JWT secret` | `NETPULSE_JWT_SECRET` ausente o corto | Provisionar el secreto por el instalador; no usar valores de ejemplo |
| `409 ActivationBlocked` | Preparar/activar celdas | Es el comportamiento esperado; falta verificador Linux |
| `409 Legacy execution disabled` | Ruta heredada de engine/integrations/firewall | Usar el flujo de laboratorio autorizado; no hay flag `force` |
| `410` en `/api/deception/ingest` | Ingesta heredada retirada | Usar `runtime.ingest` y `/v1/events` |
| Ingesta devuelve `426` | La petición no llegó por TLS directo | Terminar TLS en el proceso, no en un proxy |
| `503 ingestion busy` | Límite de concurrencia | Reintentar con `Retry-After`; revisar carga |
| Spool lleno | Cuota de filas/bytes | Pausar el adaptador y revisar la cuota; no borrar la DB |

---

## 10. Documentos relacionados

- [README del proyecto](../README.md)
- [Instalación y operación endurecidas](HARDENING-OPERATIONS.md)
- [Arquitectura y diagnóstico de hardening](HARDENING.md)
- [Pruebas y pendientes de hardening](HARDENING-TESTS.md)
- [Consola operativa](CONSOLE-OPERATIONS.md)
- [Puente de consulta Unix](QUERY-BRIDGE.md)
- [Sistema unificado: arquitectura](UNIFIED-DECEPTION.md)
- [Operación del sistema unificado](UNIFIED-OPERATIONS.md)
- [Validación del sistema unificado](UNIFIED-VALIDATION.md)
- [Laboratorio de evaluación](EVALUATION-LAB.md)
- [Handoff al servidor Linux](LINUX-HANDOFF.md)
- [Validación de builds de honeypots](HONEYPOT-BUILDS.md)
- [Orquestador de honeypots por celda](HONEYPOT-ORCHESTRATION.md)
- [Bundle offline y locks](OFFLINE-BUNDLE.md)
- [SBOM](SBOM.md)
- [TLS y reverse proxy de Kibana](../deploy/tls-proxy/README.md)
- [Compatibilidad con T-Pot](TPOT-COMPATIBILITY.md)
- [Seguridad y operaciones](SEGURIDAD-Y-OPS.md)
- [Procedencia de dependencias](DEPENDENCY-PROVENANCE.md)
- [Roadmap](ROADMAP.md)
- [Elasticsearch/Kibana: despliegue y bootstrap](../deploy/elastic/README.md)
- [Dashboards de Kibana](../deploy/kibana-dashboards/README.md)
- [Aislamiento por celda](../deploy/isolation/README.md)
- [Honeypots y adaptadores](../deploy/honeypots/README.md)
- [Migración](../MIGRATION.md)

---

## Apéndice: datos no verificados en este documento

- No se ejecutó el despliegue real en Ubuntu 24.04, ni se arrancaron
  Elasticsearch/Kibana, systemd, KVM/libvirt o nftables.
- La suite completa no se ejecutó en este worktree; los comandos y la CI se
  transcriben del repositorio.
- Los permisos efectivos de UID/grupo y el soporte de cgroup/BPF/systemd solo
  pueden confirmarse en el laboratorio autorizado.
- La contención de red y el lifecycle de celdas siguen bloqueados y no se
  certifican en este documento.
