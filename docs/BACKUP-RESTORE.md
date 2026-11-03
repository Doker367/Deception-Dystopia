# Backup y Restore offline — plano de control Dystopia y plano analítico

Estado del documento: contrato operativo (v1). El flujo es **offline por
diseño**: ninguna pieza de backup abre puertos, lanza daemons, ejecuta Docker
(en el host de control), habla con la red ni toca systemd, nftables, KVM o los
honeypots. Todo el trabajo lo realiza un contrato Python puro
(`runtime/backup.py`) expuesto por la CLI (`runtime.cli`) y validado por tests
deterministas (`tests/hardening/test_backup.py`).

## 1. Modelos de backup

### 1.1 Roles y artefactos (tabla fija, en `runtime/backup.py`)

La tabla de artefactos es **fija en código**: ni la CLI ni los scripts aceptan
rutas arbitrarias. Un backup solo puede contener artefactos declarados, y el
restore re-deriva cada destino de esa misma tabla (nunca de las rutas del
manifest). diseño fail-closed.

**Clasificación del backup: `secret-bearing`.** La tabla incluye por diseño
`sensors.db` (estado de autenticación de sensores) y `server.key` (clave
privada TLS del receptor). Por tanto **ningún backup de este contrato es una
copia “sin secretos”**: el manifest lo declara, la CLI lo imprime y el almacén
offline debe custodiarse como material secreto (root-only y cifrado en reposo
con una identidad de recuperación independiente). Lo que sí queda excluido por
la allowlist son los secretos de los ficheros `env` (contraseñas, tokens y
claves de cifrado de Elastic/Kibana y `NETPULSE_JWT_SECRET`).

| rol        | artefacto                                       | fuente en el host                       | tipo     | obligatorio |
|------------|-------------------------------------------------|------------------------------------------|----------|-------------|
| `control`  | `artifacts/control/config/users.yaml`           | `/var/lib/dystopia/control/config/users.yaml` | `file`   | sí |
| `manager`  | `artifacts/manager/install.json`                | `/etc/dystopia/install.json`             | `file`   | sí |
| `manager`  | `artifacts/manager/control.env.json`            | `/etc/dystopia/control.env`              | `env`    | no |
| `ingest`   | `artifacts/ingest/events.db`                    | `/var/lib/dystopia/ingest/events.db`     | `sqlite` | sí |
| `ingest`   | `artifacts/ingest/sensors.db`                   | `/var/lib/dystopia/ingest/sensors.db`    | `sqlite` | sí |
| `ingest`   | `artifacts/ingest/server.crt`                   | `/var/lib/dystopia/ingest/server.crt`    | `file`   | sí |
| `ingest`   | `artifacts/ingest/server.key`                   | `/var/lib/dystopia/ingest/server.key`    | `file`   | sí |
| `control`  | `artifacts/control/elastic-queue.db`            | `/var/lib/dystopia/control/elastic-queue.db` | `sqlite` | no |
| `control`  | `artifacts/control/export-cursor.db`            | `/var/lib/dystopia/control/export-cursor.db` | `sqlite` | no |
| `analytics`| `artifacts/analytics/elastic.env.json`          | `deploy/elastic/.env`                    | `env`    | no |

Tipos de artefacto:

- `file`: copia acotada de un fichero regular, sin symlinks, sin permisos
  grupo/mundo (`st_mode & 0o077 == 0`).
- `sqlite`: snapshot consistente vía la API `sqlite3.Connection.backup` sobre
  una conexión abierta en modo `?mode=ro`; la fuente se abre solo lectura, así
  que la ingesta activa nunca produce una copia rota y nunca se escribe sobre
  la base viva.
- `env`: **configuración filtrada**. El fichero de entorno se lee y solo se
  exportan las claves de una *allowlist revisada* de ajustes no secretos:
  `ANALYTICS_EXPORT_KEYS` + `ILM_*` para `deploy/elastic/.env`, y
  `CONTROL_EXPORT_KEYS` (`DYSTOPIA_CONTROL_STATE`, `DYSTOPIA_CONTROL_CONFIG`,
  `NETPULSE_ENV`) para `/etc/dystopia/control.env`. Las claves de
  contraseñas, tokens y claves de cifrado quedan fuera de estos artefactos
  `env` (`deny-by-default`), incluido `NETPULSE_JWT_SECRET`. El resultado es
  un JSON `dystopia.analytics.settings/v1`; esos secretos de entorno nunca se
  materializan. La clasificación global del backup sigue siendo
  `secret-bearing` por `server.key` y `sensors.db`.

El estado del sensor (`/var/lib/dystopia/sensor`) no se restaura desde el
plano de control: su spool es efímero y su identidad se re-emite con
`runtime.cli rotate-sensor` (ver `docs/HARDENING-OPERATIONS.md`).

### 1.2 El plano analítico (Elastic/Kibana)

Dos modelos complementarios, **nunca mezclados**:

1. **Configuración de plugins** (contrato Python, cualquier host): el fichero
   `deploy/elastic/.env` se exporta filtrado. Contenido esperado: versión de
   Elastic/Kibana, límites de memoria, ajustes `DYSTOPIA_ELASTIC_*` no
   secretos (URL/index/timeout/retries/backoff/batch/queue) y retenciones
   `ILM_*_DAYS`. El secret del superusuario, las claves de cifrado de saved
   objects y tokens de servicio **no se exportan**: se rotan tras un restore
   siguiendo `deploy/elastic/README.md` y `bootstrap-security.sh`.
2. **Datos / snapshots de índices** (solo Linux + Docker, contrato
   conservador): `scripts/backup-elasticsearch.sh` usa la API `_snapshot` vía
   `docker exec` contra un contenedor que **ya está** en ejecución. No crea ni
   arranca contenedores, no ejecuta compose, no monta nada. Las credenciales
   no viajan por argv: curl recibe su configuración (usuario, contraseña e
   incluso el cuerpo) por stdin. Restore solo produce índices renombrados
   (`restored-deception-*`); el cutover a índices vivos es un paso manual
   revisado.

### 1.3 Manifest (`dystopia.backup/v1`)

Cada backup queda cerrado por `manifest.json`:

- `schema`, `label`, `created_at` (UTC), `artifact_count`;
- `artifacts`: lista ordenada por `path`, cada entrada con `role`, `path`,
  `kind`, `required`, `secret`, `bytes`, `sha256` y `status`
  (`present`/`missing`). El conjunto debe ser **exactamente** la tabla fija;
  todos los `required` deben estar en `present`;
- `artifacts_sha256`: digest sellado sobre los `sha256` de los artefactos
  presentes, en orden; el restore lo recalcula y compara;
- `policy`: memoria del contrato (`classification: secret-bearing`,
  `secrets: secret-bearing`, `secret_artifacts`, `env_export: non-secret
  allowlist only`, `custody`, `restore_overwrite: refused`).

El identificador corto del backup es el SHA-256 de los bytes canónicos del
manifest (`backup_id()`, 16 caracteres hex).

### 1.4 Clasificación y custodia

- `server.key` y `sensors.db` son **obligatorios** y se copian: el backup es
  material secreto. Nunca se etiqueta, documenta ni entrega como “sin
  secretos”.
- El almacén offline debe ser root-only, fuera del repositorio y cifrado en
  reposo con una identidad de recuperación independiente del host. El código
  crea los artefactos `0600` y los directorios `0700` desde su nacimiento,
  pero **no implementa el cifrado del medio**: es una obligación del operador.
- Una copia filtrada por la allowlist de `env` no cambia la clasificación
  global: mientras existan `server.key` o `sensors.db`, el conjunto completo
  sigue siendo `secret-bearing`.

## 2. Rutas

- Estado en host (fuente en backup, destino en restore):
  - `/var/lib/dystopia/control` (usuarios, colas de export)
  - `/var/lib/dystopia/ingest` (bases de eventos y del registro de sensores, TLS del nodo de ingesta)
  - `/etc/dystopia/install.json`, `/etc/dystopia/control.env`
- Backup destino: **fuera del repositorio**, en almacenamiento revisado por el
  operador (p. ej. `/var/backups/dystopia` o soporte offline). El contrato
  rechaza escribir dentro del árbol del repo (`create_backup(repo_root=…)` y
  los scripts lo re-verifican) para que datos reales nunca se versionen.
- Configuración del plano analítico: `deploy/elastic/.env` en el repo (solo
  `.env.example` está versionado), snapshot repo de Elastic en un volumen
  propio del contenedor fuera del repo.

## 3. Control de versiones

- `schema: dystopia.backup/v1` — manifest versionado; un restore rechaza
  cualquier otro valor.
- Cada entrada registró la tabla fija (`role`/`kind`/`required`/`secret`); el
  restore exige el **conjunto exacto** de la tabla, `artifact_count`
  correcto, todos los `required` en `present` y un esquema exacto por
  entrada. Si el manifest no coincide con la tabla compilada del host de
  restore, se aborta antes de escribir.
- Los artefactos nunca se sobreescriben en el host: el restore hace preflight
  de todos los destinos y padres antes de la primera escritura. Después copia
  a un staging privado, re-verifica SHA-256/tamaño y publica con enlace duro
  sin overwrite; si una publicación falla, elimina los ficheros publicados y
  los directorios creados por ese restore. No se promete atomicidad entre
  filesystems distintos, pero no queda una mezcla parcial en el caso normal.
- Scripts de control de confirmación:
  - `restore-control.sh` exige `DYSTOPIA_RESTORE_CONFIRM=restore`;
  - `backup-elasticsearch.sh restore` exige `DYSTOPIA_ES_RESTORE_CONFIRM=restore`.

## 4. Cómo hacer backup

Los scripts aceptan overrides de entorno para apuntar a una raíz distinta a la
de producción (`DYSTOPIA_STATE_ROOT`, `DYSTOPIA_CONTROL_ENV_DIR`, `PYTHON`):
así el drill del restore se ejecuta contra una copia desechable sin tocar el
host vivo.

```bash
# plan read-only (falla si falta algún artefacto de estado requerido)
python3 -m runtime.cli backup-plan

# export offline, con timestamp determinista opcional
scripts/backup-control.sh /var/backups/dystopia/control-2026-11-02 \
    --created-at 2026-11-02T10:00:00Z
```

Equivalente directo por CLI:

```bash
python3 -m runtime.cli backup-export \
    --output /var/backups/dystopia/control-2026-11-02 \
    --created-at 2026-11-02T10:00:00Z
```

Salida:

```
backup_complete: /var/backups/dystopia/control-2026-11-02
created_at: 2026-11-02T10:00:00Z
backup_id: 404873221f145323
manifest_sha256: <sha256 del manifest.json>
classification: secret-bearing
```

> No etiquetar ni almacenar esta copia como “sin secretos”. El manifiesto,
> la CLI y este runbook declaran `secret-bearing`.

Snapshot de índices analíticos (solo Linux, contrato Docker):

```bash
DYSTOPIA_SNAPSHOT_REPO_PATH=/var/lib/dystopia/elastic/snapshots \
DYSTOPIA_ES_PASSWORD_FILE=/etc/dystopia/elastic/elastic-password \
scripts/backup-elasticsearch.sh register
scripts/backup-elasticsearch.sh verify
scripts/backup-elasticsearch.sh snapshot        # deception-<UTC-stamp>
scripts/backup-elasticsearch.sh list
```

## 5. Cómo restaurar

### 5.1 Plano de control

```bash
# 1) parar servicios que escriben el estado (systemd, consola del operador)
# 2) mover el estado existente a cuarentena (el restore NUNCA sobreescribe)
mv /var/lib/dystopia/ingest /var/lib/dystopia/ingest.pre-restore

# 3) restaurar (verificación SHA-256+tamaño completa ANTES de escribir)
DYSTOPIA_RESTORE_CONFIRM=restore \
scripts/restore-control.sh \
    --backup /var/backups/dystopia/control-2026-11-02
```

Pasos de la CLI equivalente:

```bash
python3 -m runtime.cli backup-restore --backup <backup-dir> \
    --state-root /var/lib/dystopia --control-env-dir /etc/dystopia
```

- Falla si falta el manifest, si alguna discrepancia de digest/tamaño, si el
  conjunto de artefactos no es exactamente la tabla fija, si `artifact_count`
  no cuadra, si falta un artefacto requerido (incluido `sensors.db` o
  `server.key`) o si un destino/padre no supera el preflight.
- Antes de escribir nada, comprueba todos los destinos y padres: no deben
  existir destinos, no se aceptan symlinks en la cadena de padres y no se
  permite que dos artefactos colisionen en el mismo destino. Después copia a
  staging privado y publica con rollback ante fallo.
- Los artefactos `env` son configuración derivada: **no** se escriben sobre la
  entrada viva; se listan en `not_restored_env_derived` para revisión manual.
- 4) reiniciar servicio por servicio y comparar `python3 -m runtime.cli
  status --events /var/lib/dystopia/ingest/events.db` con los valores del
  manifest (`artifact_count`, y para las bases el conteo de eventos esperado).

### 5.2 Plano analítico

```bash
# snapshot repo re-registrado contra la nueva ubicación de datos
DYSTOPIA_SNAPSHOT_REPO_PATH=/var/lib/dystopia/elastic/snapshots \
DYSTOPIA_ES_PASSWORD_FILE=/etc/dystopia/elastic/elastic-password \
DYSTOPIA_ES_RESTORE_CONFIRM=restore \
scripts/backup-elasticsearch.sh restore deception-20261102T101530Z
# produce índices restored-deception-*; el cutover se hace a mano tras
# verificar dashboards/ILM; NUNCA borra nada implícitamente
```

Después de un restore completo: rotar secretos de Elastic
(`bootstrap-security.sh`), re-importar dashboards certificados solo si el
manifest de `deploy/kibana-dashboards` cambió, y re-hacer el drill de restore.

## 6. Comprobar RPO/RTO

- **RPO del plano de control (objetivo: 24 h)**: el estado requerido es
  pequeño e idempotente (usuarios/plan/TLS). Ejecutar
  `scripts/backup-control.sh` con `--created-at` fija y almacenar el
  `backup_id`; la comprobación del RPO consiste en verificar que el intervalo
  entre dos export consecutivos es ≤ objetivo: registrar `created_at` de cada
  backup en la bitácora del operador y alertar con un cron sencillo si el hueco
  supera 24 h.
- **RTO del plano de control (objetivo: 30 min)**: el restore es
  `verify + copia local` (sin red). Cuantificarlo con un drill real:
  1. copiar el backup a un host desechable,
  2. `time scripts/restore-control.sh …`,
  3. registrar el tiempo y repetir si supera 30 min.
  Los tests deterministas garantizan que la fase de verificación y la de
  copia no dependen del orden de disco ni de relojes, por lo que la
  duración solo depende del tamaño (cota: MAX_FILE_BYTES/MAX_DB_BYTES).
- **RPO analítico (objetivo: 30 min)**: el lag real lo marca el cursor de
  export (`/var/lib/dystopia/control/export-cursor.db`) y la cola persistente
  (`elastic-queue.db`, artefactos opcionales incluidos en cada backup);
  comparar `python3 -m runtime.cli status` con el último snapshot Elastic.
- **RTO analítico**: preparar el `register` del snapshot repo de antemano y
  tabular el restore de indices grandes; el cutover manual es la parte
  dominante del RTO.

## 7. Pendientes Linux (no ejecutables aquí)

- [ ] Docker real en Linux: validar `scripts/backup-elasticsearch.sh` contra
  el compose certificado de `deploy/elastic/` (rutas del snapshot repo,
  permisos del volumen, TLS interno del nodo).
- [ ] Perfilar RTO real con bases `events.db` de tamaño productivo (el bound
  actual es `MAX_DB_BYTES = 8 GiB` por base).
- [ ] Integrar `backup-control.sh` en un timer systemd del host (diseño ya
  compatible) y definir la política de retención/cifrado del almacén offline.
- [ ] Curl `--config -` del contenedor: sustituir por un helper con lockfile
  si se necesitan restricciones de rate en la API de snapshots.
- [ ] Drill de restore completo contra un host desechable, métricas registradas
  en `audit/` (sin secretos).

## 8. Garantías y límites (resumen)

- El repo **nunca** contiene artefactos de backup reales ni secretos: los
  outputs rechazados si caen dentro del árbol versionado, `.gitignore` cubre
  `backups/` y los tests lo comprueban.
- El backup completo es **secret-bearing** por `server.key` y `sensors.db`;
  el manifest, la CLI y este runbook lo declaran. Un valor de la allowlist
  `env` (`CHANGEME_*`, `*PASSWORD*`, `*KEY*`…) jamás debe añadirse a
  `ANALYTICS_EXPORT_KEYS`/`CONTROL_EXPORT_KEYS` sin revisión.
- Los ficheros se crean `0600` y los directorios `0700` desde el nacimiento,
  con `umask 077` durante toda la exportación, antes de la primera escritura.
- El restore es fail-closed: exige el conjunto exacto y todos los requeridos,
  hace preflight de todos los destinos/padres, verifica SHA-256+tamaño y
  publica desde staging con rollback; no deja una mezcla parcial en el caso
  normal. No promete atomicidad entre filesystems distintos.
- El plano analítico Docker no modifica contenedores ni host y no corre fuera
  de Linux: `exit 3` en cualquier otro `uname -s`.
