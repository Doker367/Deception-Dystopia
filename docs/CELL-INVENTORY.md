# Inventario de celdas y servicios — Dystopia

**Fuente de verdad:** `deploy/honeypots/inventory.yaml` (schema
`dystopia.honeypots/v1`, revisión `2026-10-29`, estado
`static-reference-only`). El compose de laboratorio
(`deploy/local/docker-compose.yml`) publica solo un subconjunto de los puertos
declarados. Este documento es el inventario operativo de handoff; si hay
conflicto, mandan el inventario y la política aprobada por el CPD.

## 1. Servicios de la celda de laboratorio

| Servicio | Imagen | Usuario | `read_only` | Caps | Mem | CPU | PIDs | Red | Volumen | Healthcheck |
|---|---|---|---:|---|---:|---:|---:|---|---|---|
| Cowrie | `dystopia/honeypot-cowrie:3.1.4` | 999:999 | sí | drop ALL | 512m | 0.50 | 256 | `cowrie_net` | `cowrie_var` | proceso `twistd` |
| OpenCanary | `dystopia/honeypot-opencanary:0.9.10` | 2000:2000 | sí | `NET_BIND_SERVICE` | 256m | 0.25 | 128 | `opencanary_net` | `opencanary_log` | proceso `opencanaryd` |
| Dionaea | `dystopia/honeypot-dionaea:0.12.5` | 2000:2000 | sí | `NET_BIND_SERVICE` | 768m | 1.00 | 512 | `dionaea_net` | `dionaea_var` | proceso `dionaea` |
| Heralding | `dystopia/honeypot-heralding:ac12724` | 2000:2000 | sí | `NET_BIND_SERVICE` | 512m | 0.50 | 256 | `heralding_net` | `heralding_log` | proceso `heralding` |
| RedisHoneyPot | `dystopia/honeypot-redishoneypot:45adc62` | 2000:2000 | sí | drop ALL | 192m | 0.25 | 128 | `redishoneypot_net` | `redishoneypot_log` | proceso `RedisHoneyPot` |
| Endlessh | `dystopia/honeypot-endlessh:dfe44eb` | 2000:2000 | sí | drop ALL | 64m | 0.10 | 64 | `endlessh_net` | `endlessh_log` | proceso `endlessh` |
| Colector | `dystopia/local-collector:lab` | 2000:2000 | sí | drop ALL | — | — | — | default | logs RO + `deception_db` | heartbeat SQLite |
| Control | `dystopia/local-control:lab` | 2000:2000 | sí | drop ALL | — | — | — | default | `deception_db`, `control_config`, `control_state` | `/api/health` |

Las imágenes `dystopia/local-*:lab` son **solo de laboratorio**. Para el CPD
se construyen con release y digest; no se deben usar tags mutables.

## 2. Puertos declarados y publicados

| Motor | device_id | Puertos contenedor (inventario) | Publicados en laboratorio | Publicados en remoto |
|---|---|---|---|---|
| Cowrie | `srv-files-01` | 2222/tcp ssh, 2223/tcp telnet | 12222→2222, 12223→2223 | 10.66.0.3:12222, 10.66.0.3:12223 |
| OpenCanary | `sw-access-01` | 21, 22, 23, 80, 3306/tcp | 13022→22, 13080→80 | 10.66.0.3:13022, 10.66.0.3:13080 |
| Dionaea | `srv-files-01` | 21, 69/udp, 81, 135, 443, 445, 1433, 1723, 1883, 3306, 27017 | 14021→21 | 10.66.0.3:14021 |
| Heralding | `srv-db-01` | 21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389, 5432, 5900 | 15021→21 | 10.66.0.3:15021 |
| RedisHoneyPot | `srv-db-01` | 6379/tcp | 16379→6379 | 10.66.0.3:16379 |
| Endlessh | `fw-edge-01` | 2222/tcp | 17222→2222 | 10.66.0.3:17222 |

El panel de control publica `8082` solo en loopback y en la IP de Tailscale
(`DYSTOPIA_TAILSCALE_IP`). No se publica en WireGuard.

## 3. Volúmenes y datos

| Volumen | Contenido | Montaje | Consumidor | Sensibilidad |
|---|---|---|---|---|
| `deception_db` | `deception.db` (WAL), eventos normalizados | `/srv/deception` | colector (writer), control (RO) | Alta: IPs, usuarios, detalle |
| `control_config` | `users.yaml` (hashes), configuración local | `/srv/local-config` | control | Alta: credenciales |
| `control_state` | `audit/audit.db`, `investigations.db` | `/srv/state` | control | Alta: auditoría/notas |
| `cowrie_var` | logs/estado Cowrie | `/cowrie/cowrie-git/var` | cowrie + colector RO | Media/alta |
| `opencanary_log` | `opencanary.log` (JSON + shim HTTP) | `/var/log/opencanary` | opencanary + colector RO | Media/alta |
| `dionaea_var` | logs/binarios capturados | `/opt/dionaea/var` | dionaea + colector RO | Alta: posible malware |
| `heralding_log` | `sessions.jsonl`, `auth.csv`, `sessions.csv` | `/var/log/heralding` | heralding + colector RO | Alta: credenciales |
| `redishoneypot_log` | `redishoneypot.log` | `/var/log/redishoneypot` | colector RO | Media |
| `endlessh_log` | `endlessh.log` | `/var/log/endlessh` | colector RO | Baja |

**Retención actual**

- Eventos analíticos: ventana máxima de **90 días**; límite por consulta
  `DYSTOPIA_ANALYTICS_MAX_ROWS` (20 000 por defecto).
- Auditoría de investigaciones: **10 000 filas** más recientes; presupuesto
  `investigations.db` **64 MiB**.
- Logs de honeypots: rotación diaria del laboratorio con `copytruncate`,
  7 rotaciones y corte a 50 MB (`deploy/server/lab/logrotate.d-dystopia`).
- Backups del laboratorio: timer diario 03:15, retención local de 14 días en
  `/var/backups/dystopia`, con `.backup` de SQLite, configuración y manifiesto
  SHA-256. **Debe copiarse fuera del host antes del CPD.**

## 4. Identidades y permisos del host

- `control`/`collector`: UID/GID **2000**.
- Cowrie: UID/GID **999**.
- OpenCanary, Dionaea, Heralding, RedisHoneyPot, Endlessh: **2000:2000**.
- Directorios persistentes del laboratorio: propiedad del UID del contenedor;
  nunca `chmod -R 777`.
- En el despliegue systemd del CPD: usuarios `dystopia-control`,
  `dystopia-ingest`, `dystopia-sensor`; `/etc/dystopia` 0711;
  `/var/lib/dystopia/{control,ingest,sensor}` con permisos privados.

## 5. Variables y configuración

| Variable | Ámbito | Uso |
|---|---|---|
| `NETPULSE_JWT_SECRET` | control | Firma de sesiones; mínimo 32 bytes; nunca en Git |
| `DYSTOPIA_CONTROL_STATE` | control | Estado privado (`audit`, investigaciones) |
| `DYSTOPIA_CONTROL_CONFIG` | control | `users.yaml` |
| `NETPULSE_DECEPTION_DATA_DIR` | colector/control | Ruta de `deception.db` |
| `DYSTOPIA_ANALYTICS_MAX_ROWS` | control | Tope por consulta |
| `NETPULSE_GEOIP_DB` | control | Ruta de `GeoLite2-City.mmdb` |
| `DYSTOPIA_TAILSCALE_IP` | laboratorio remoto | Bind del panel en Tailscale; no versionar |
| `NETPULSE_ENV` | control | Etiqueta de entorno |
| `NETPULSE_VMS_ENABLED`, `NETPULSE_FIREWALL_ENABLED`, `NETPULSE_SYSLOG_ENABLED`, `NETPULSE_METRICS_ENABLED`, `NETPULSE_AI_ENABLED` | control | Deshabilitados por defecto; no activar sin revisión |

## 6. Despliegue del CPD (systemd, no compose)

| Unidad | Rol | Usuario | Notas |
|---|---|---|---|
| `dystopia-control.service` | Panel/API | `dystopia-control` | `127.0.0.1:8082`, `IPAddressDeny=any`, allow localhost |
| `dystopia-ingest.service` | Ingesta TLS | `dystopia-ingest` | Certificado/clave en `/var/lib/dystopia/ingest` |
| `dystopia-processor.service` | Procesamiento | `dystopia-ingest` | Lee `events.db` |
| `dystopia-sensor.service` | Sensor | `dystopia-sensor` | No arranca por defecto |
| `dystopia-query.socket`/`.service` | Puente local | `dystopia-query` | Socket Unix, sin TCP |
| `dystopia-isolation-apply@.service` | Aplicar aislamiento | root | Requiere política y gate; hoy bloqueado |
| `dystopia-isolation-quarantine@.service` | Cuarentena | root | Requiere política y gate |

Rutas: `/opt/dystopia/current`, `/opt/dystopia/venv`,
`/etc/dystopia/{control.env,install.json}`, `/var/lib/dystopia/{control,ingest,sensor,cells}`.

## 7. Integridad y límites conocidos

- `runtime.cell_gate` inicia con trust store vacío: **siempre bloquea** hasta
  revisión del verificador Linux y fijación de clave pública.
- Docker Compose en un host compartido **no es contención**; `internal=true`
  reduce salida accidental pero no es evidencia.
- Las imágenes locales no están fijadas por digest; en CPD usar
  `image@sha256:...` y un registro aprobado.
- El host de laboratorio actual es Debian 13; el objetivo documentado es
  Ubuntu Server 24.04 LTS. Documentar la desviación o migrar.
- MariaDB `3306` del host de laboratorio pertenece a otros servicios y no debe
  publicarse en la celda Dystopia.
