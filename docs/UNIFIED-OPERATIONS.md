# Operación del sistema unificado — habilitación, salud y recuperación

**Estado: procedimiento para laboratorio autorizado. No se ha ejecutado nada.**
Este documento no sustituye la autorización, la consola de recuperación ni la
revisión de topología. La activación de celdas está bloqueada en código y no
existe opción `force`. No hay servicios reales arrancados, builds de honeypots,
import de dashboards ni pruebas de contención.

Alcance: Dystopia (control, sensor, ingestión, consulta), honeypots externos,
Elasticsearch/Kibana y el plano de observabilidad. Para la arquitectura y el
contrato, véase [UNIFIED-DECEPTION.md](UNIFIED-DECEPTION.md). Para el detalle de
endurecimiento, [HARDENING-OPERATIONS.md](HARDENING-OPERATIONS.md).

## 1. Principios que no se negocian

1. **Sin autorización no se ejecuta.** Host desechable, ventana, consola de
   recuperación y responsable identificados.
2. **Sin secretos en el repositorio ni en la línea de comandos.** Contraseñas
   por TTY o ficheros `0600`; tokens y API keys fuera del árbol.
3. **Sin autostart.** Ningún `systemctl enable` masivo, ningún
   `restart: always/unless-stopped` en celdas, ninguna unidad de aislamiento
   habilitada.
4. **Sin atajos destructivos.** Prohibido `nft flush ruleset`, `iptables -F`,
   `docker system prune`, borrado por prefijos o parada de procesos ajenos.
5. **Sin fallback heredado.** No se reactivan listeners, tailer, Compose
   deception ni QEMU para “hacer funcionar” algo.
6. **La ausencia de errores no es evidencia.** `plan`, `nft --check`, un JSON
   válido o un panel que carga no demuestran aislamiento ni integración.

## 2. Comprobaciones previas (todas obligatorias)

### 2.1 Autorización y entorno

- Laboratorio Ubuntu Server 24.04 LTS desechable, KVM/libvirt o runtime de
  contenedores aprobado, sin ruta a Internet, LAN real, producción, secretos
  compartidos ni sockets del host.
- Snapshot/restauración y consola fuera de banda probadas.
- Ventana de mantenimiento y responsable del ejercicio registrados.
- Autorización separada para: sistema operativo/paquetes, certificados,
  interfaces/rutas/nft, runtime de contenedores, Elasticsearch/Kibana y
  cualquier cambio de red.

### 2.2 Artefactos y versiones

- Release en `/opt/dystopia/current` root-owned, sin `.env`, bases, claves,
  logs, ISOs ni `.git`.
- Venv construido por el procedimiento aprobado, con `requirements.lock`
  completo y hashes SHA-256 reales; `release-hashes.json` en release y venv.
- Python 3.12 en Linux para el objetivo soportado. Las pruebas de esta sesión
  se hicieron en macOS/Python 3.14.7 y **no** certifican ese objetivo.
- Elasticsearch/Kibana fijados a `9.3.5`; imágenes de honeypot por digest
  revisado, nunca `latest`.
- Nada se descarga automáticamente durante la instalación o el arranque.

### 2.3 Identidades y secretos

- Cuatro usuarios de servicio: `dystopia-control`, `dystopia-ingest`,
  `dystopia-sensor`, `dystopia-query`; sin login ni grupos adicionales.
- Certificado de ingestión con SAN de la **IP exacta**, clave `0600`, CA
  confiable para sensores.
- Token bearer por sensor, transferido por canal administrativo seguro; nunca
  montar el registro central en un sensor.
- Credenciales de Elasticsearch únicas por instancia. `elastic` solo para
  bootstrap/emergencias; `deception_admin` para el día a día; `deception_writer`
  solo para ingesta; `deception_analyst` solo lectura.
- Ningún valor real en este repositorio ni en ejemplos.

### 2.4 Comprobaciones offline sin efectos

Ejecutar desde una copia revisada, sin privilegios y sin servicios:

```sh
# Plan de instalación: no escribe ni ejecuta comandos de host
python3 -m runtime.install --dry-run --config deploy/install.example.json

# Render de una celda KVM (solo validación/render)
python3 -m runtime.isolation plan --policy deploy/cell.example.json

# Render de una celda contenedor; image:null produce deployment_errors a propósito
python3 -m runtime.isolation plan-container \
  --policy deploy/isolation/cell-container.example.json

# Contratos, mappings, deduplicación, filtros y higiene de secretos
scripts/smoke_unified.sh

# Equivalente directo, sin red ni servicios
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s tests/integration_unified -p 'test_*.py' -v
```

Comprobaciones adicionales permitidas en un entorno de desarrollo aislado:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/hardening tests/deception -q
```

No ejecutar `docker compose config`, `nft`, `virsh`, `systemctl` ni el
instalador real como “comprobación” sin la autorización correspondiente.

### 2.5 Criterios de no-go

Abortar si cualquiera de estos puntos falla:

- redes o interfaces se solapan, o no coinciden con el inventario aprobado;
- falta un hash, un artefacto, un propietario o un permiso esperado;
- hay una tabla, bridge, tap, VM o contenedor preexistente que no se puede
  atribuir con certeza a una celda;
- el host tiene ruta a Internet/LAN/producción o sockets compartidos;
- el certificado no cubre la IP exacta o la CA no es la aprobada;
- el plan de instalación intenta escribir fuera de las rutas autorizadas;
- alguien propone `force`, `flush`, `prune`, un `enable` de arranque o volver a
  Compose/QEMU para desbloquear.

## 3. Habilitación por pasos

El orden importa: cada paso produce evidencia antes del siguiente. No se
habilita ingestión, honeypots ni analítica “para probar” en el mismo arranque.

### Paso A — Gestión (solo tras autorización)

1. Revisar release, venv, lock, hashes y configuración de instalación.
2. Aplicar únicamente gestión:

   ```sh
   /opt/dystopia/venv/bin/python -m runtime.install --apply \
     --config /ruta/revisada/install.json --bundle /srv/dystopia-bundle \
     --confirm APPLY-MANAGEMENT-ONLY
   ```

3. Crear el primer administrador por TTY (nunca por argumento o variable):

   ```sh
   cd /opt/dystopia/current
   runuser -u dystopia-control -- /opt/dystopia/venv/bin/python -m runtime.cli \
     bootstrap-admin \
     --users /var/lib/dystopia/control/config/users.yaml \
     --username NOMBRE_ELEGIDO
   ```

4. Repetir el mismo apply con los mismos artefactos; solo entonces se habilita
   e inicia control en `127.0.0.1:8082`.
5. Diagnosticar y revisar permisos/unidad/logs:

   ```sh
   /opt/dystopia/venv/bin/python -m runtime.install --diagnose \
     --config /ruta/revisada/install.json
   systemctl status dystopia-control.service
   curl --fail --silent http://127.0.0.1:8082/api/health
   ```

El bind remoto exige TLS y revisión explícita de la unidad y su filtro IP; no
se hace automáticamente. Para administración remota inicial, túnel SSH
autorizado.

### Paso B — Ingestión y sensores

1. Provisionar certificado con SAN de la IP de ingestión, clave `0600`,
   propietario del servicio y CA confiable para sensores.
2. Elegir un bind explícito en la red de telemetría; nunca en gestión ni en una
   red alcanzable desde producción.
3. Arrancar ingestión como proceso separado, solo tras revisar la unidad:

   ```sh
   systemctl start dystopia-ingest.service
   systemctl status dystopia-ingest.service
   ```

4. Dar de alta el primer sensor y transferir su token por canal seguro. La
   rotación y revocación son locales y no imprimen el token:

   ```sh
   python -m runtime.cli rotate-sensor \
     --registry /var/lib/dystopia/ingest/sensors.db \
     --sensor sensor-a --device srv-files-01 \
     --output /var/lib/dystopia/ingest/nueva-credencial

   python -m runtime.cli revoke-sensor \
     --registry /var/lib/dystopia/ingest/sensors.db --sensor sensor-a
   ```

5. Comprobar el spool y la base sin crear ni modificar nada:

   ```sh
   python -m runtime.cli status --spool /var/lib/dystopia/sensor/spool.db
   python -m runtime.cli status --events /var/lib/dystopia/ingest/events.db
   ```

**No iniciar sensores de honeypot todavía.** El sensor implementado transporta
el contrato v1, pero no incluye el colector de logs de los seis motores. El
tailer central está retirado y devuelve `blocked`. Sin un colector probado, un
sensor “arrancado” no produce eventos de honeypot.

El puente analítico central sí existe:
`scripts/run_elastic_export.py --events <events.db> --state <state.db> --once`
valida la configuración y permanece deshabilitado sin `--enable-elastic`. Con
el flag, necesita `DYSTOPIA_ELASTIC_*`, cola persistente y el fichero de API key
provisionado. No se ha ejecutado contra un clúster real ni tiene unidad systemd.

### Paso C — Celda de honeypot (laboratorio autorizado)

1. Revisar imagen, licencia, digest, dependencias y puertos; descargar en un
   paso offline aprobado. Nunca `latest` ni pull en el arranque.
2. Construir las imágenes en un entorno controlado y escanear CVEs/SBOM. Aquí
   no se construyó ni arrancó nada.
3. Crear los directorios de datos con el uid/gid del contenedor (Cowrie
   `999:999`; OpenCanary, Dionaea, Heralding, RedisHoneyPot y Endlessh
   `2000:2000`, según el inventario). No se crean rutas ni volúmenes desde este
   repositorio.
4. Provisionar bridge dedicado `dybrN` sin IP de host, veth `dytapN`, uplink
   `dyupN`, vecinos/rutas estáticos, cuota de disco y logs acotados.
5. Instalar la política root-owned en `/etc/dystopia/isolation/cell-N.json`,
   máximo 16 KiB, sin symlinks ni escritura de grupo/otros.
6. Revisar el render sin aplicar:

   ```sh
   python3 -m runtime.isolation plan-container \
     --policy deploy/isolation/cell-container.example.json
   ```

7. Solo con autorización de laboratorio, aplicar la tabla exclusiva:

   ```sh
   python3 -m runtime.isolation apply --cell N --confirm CELL-N-APPLY
   # o, tras revisar la plantilla:
   systemctl start dystopia-isolation-apply@N.service
   ```

   El éxito solo significa “nft aceptó la transacción”. **No arrancar el
   honeypot todavía.**

8. Verificación independiente. **Hoy está bloqueada:** `verify()` y
   `activate()` siempre fallan con `ActivationBlocked`. Se requiere un harness
   externo, separado del proceso web y del helper, con capturas en host/gateway/
   otra celda, contadores del kernel y la matriz de
   [LAB-TESTS.md](../deploy/isolation/LAB-TESTS.md).

9. Solo después de la verificación independiente y una autorización separada,
   arrancar el contenedor exacto con el runtime aprobado. Este repositorio no
   contiene ni ejecuta ese comando. No usar Compose ni el motor legacy.

### Paso D — Elasticsearch y Kibana (analítica)

1. Copiar `.env.example` a `deploy/elastic/.env` (excluido del repo) y rellenar
   todos los `CHANGEME_*` con valores únicos. El compose usa `:?` para obligar.
2. Generar certificados desde la raíz revisada del repositorio y ajustar
   propietario:

   ```sh
   cd /ruta/al/repo
   deploy/elastic/scripts/generate-certs.sh
   sudo chown -R 1000:1000 <ELASTIC_CERTS_DIR>
   ```

   `generate-certs.sh` exige `ELASTIC_CA_PASSPHRASE`, ya presente como
   `CHANGEME` en `.env.example`; sustituirla por una frase única de al menos 20
   caracteres. No usar el valor de ejemplo. El valor relativo de
   `ELASTIC_CERTS_DIR` se interpreta desde el directorio de ejecución.

3. Crear las rutas reales de `ELASTIC_DATA_DIR`/`KIBANA_DATA_DIR` y ajustar su
   propietario. Los valores relativos del `.env` deben revisarse contra el
   directorio que Compose resuelve para el compose file; no asumir que
   `./data/elastic` cae en la raíz del repositorio. Después, arrancar el profile
   explícito (no ejecutado ni probado):

   ```sh
   docker compose -f deploy/elastic/docker-compose.elastic.yml \
     --profile deception-elastic --env-file deploy/elastic/.env up -d
   ```

   Requiere `vm.max_map_count >= 262144`. Los healthchecks usan `curl`; no se
   verificó que la imagen oficial 9.3.5 lo incluya.

4. Aplicar roles, usuarios, ILM y plantillas:

   ```sh
   ./scripts/bootstrap-security.sh --all
   ```

   Es idempotente, pero los nombres de privilegios y el payload no se probaron
   contra la API real de 9.3.5. Si un privilege name se rechaza, corregir el
   role JSON y reintentar.

5. Importar dashboards **solo después** de validar data views y campos:

   ```sh
   curl -X POST -u deception_admin:"${DECEPTION_ADMIN_PASSWORD}" \
     http://127.0.0.1:5601/api/saved_objects/_import?overwrite=true \
     -H 'kbn-xsrf: true' \
     -F file=@deploy/kibana-dashboards/artifacts/deception-kibana-bundle.ndjson
   ```

   El bundle no se ha importado ni probado contra Kibana 9.3.5. Si el panel
   Maps falla, rehacerlo desde la UI y exportarlo; no bloquear el resto.

6. Configurar el publicador. Las API keys están habilitadas en
   `elasticsearch.yml`. `bootstrap-security.sh --create-api-key` (o `--all`)
   emite y rota la key del writer en `ELASTIC_API_KEY_DIR` con permisos `0600`.
   Exportar `DYSTOPIA_ELASTIC_API_KEY_FILE` apuntando a ese fichero, más
   `DYSTOPIA_ELASTIC_URL`, `_CA_FILE`, `_QUEUE` y `_ENABLED=true`. Después
   ejecutar `scripts/run_elastic_export.py` de forma explícita. La emisión y el
   uso contra un clúster real siguen pendientes de prueba de laboratorio.

### Paso E — Observabilidad operativa

El Compose de `docker-compose.monitoring.yml` es **heredado**: usa imágenes
`latest`, monta el socket Docker en Promtail y no tiene autenticación en
Prometheus/Loki. No forma parte del despliegue endurecido y no se ha validado.
Si se usa en laboratorio, solo en loopback y tras revisar versiones, permisos,
volúmenes y exposición. La salud de deception **no** debe depender de este
stack; Prometheus/Loki/Grafana es operación, no evidencia de contención.

## 4. Arranque y parada

| Componente | Arranque autorizado | Parada | Límite |
|---|---|---|---|
| Control | `systemctl start dystopia-control.service` | `systemctl stop …` | Loopback; sin listeners/QEMU |
| Ingestión | `systemctl start dystopia-ingest.service` | `systemctl stop …` | TLS directo; red de telemetría |
| Procesador | `systemctl start dystopia-processor.service` | `systemctl stop …` | Outbox/alertas; sin IA |
| Consulta | `systemctl start dystopia-query.socket` | `systemctl stop …` | Socket Unix; solo UID de control |
| Sensor | `systemctl start dystopia-sensor.service` | `systemctl stop …` | HTTPS exacto; sin base central |
| Elasticsearch/Kibana | `docker compose … --profile deception-elastic up -d` | `docker compose … stop` | Solo gestión; no probado |
| Celda KVM/contenedor | Fuera de este repositorio | Cuarentena y luego runtime autorizado | `verify/activate` bloqueados |

Reglas de arranque y parada:

- No habilitar todo a la vez. Un componente por paso, con su comprobación de
  salud y su evidencia.
- Las unidades de aislamiento (`apply@`, `quarantine@`) no tienen `[Install]`;
  `systemctl start` es una acción explícita del operador, nunca reconciliación
  automática.
- En una celda, **primero cuarentena de red** (`dy_quarantine_N`), confirmar con
  captura que no hay tráfico y solo entonces parar el contenedor exacto. No
  parar contenedores ajenos, no matar por PID/nombre, no reiniciar el host como
  atajo.
- Parar el controlador **no** retira reglas nft. La terminación abrupta tampoco.
  Un reinicio del host sí pierde las tablas; no hay persistencia automática.
- No usar `docker system prune`, `docker network prune`, `nft flush ruleset` ni
  borrado por prefijo en ninguna parada o rollback.

## 5. Salud y diagnóstico

### 5.1 Señales mínimas

| Señal | Comando/consulta | Interpretación |
|---|---|---|
| Control | `curl --fail http://127.0.0.1:8082/api/health` | `plane=control`, `sensors_started=false`; si `audit.storage_errors>0`, la auditoría falla cerrada |
| Spool | `python -m runtime.cli status --spool …` | Cola, bytes, cuarentena, antigüedad, descartes |
| Ingestión | `python -m runtime.cli status --events …` | Eventos, outbox pendiente, lag de notificación |
| Publicador | `ElasticPublisher.health()` | `queued`, `permanent`, `operator_action_required`, contadores |
| Elasticsearch | `GET /_cluster/health` (TLS + auth) | Estado del clúster; no prueba mappings ni dashboards |
| ILM | `GET /_ilm/explain` | Fase y retención; no prueba borrado real |
| Kibana | `GET /api/status` | Servicio y plugins; no prueba dashboards |
| Celda | Captura externa + contadores por celda | Única evidencia aceptable de filtrado |
| Observabilidad | Prometheus/Loki/Grafana | Salud operativa; no contención |

`/api/health` del control es deliberadamente simple: `status: healthy` no
significa que ingestión, Elasticsearch o una celda estén sanos. La salud del
stack analítico se sigue en su propio plano.

### 5.2 Diagnóstico por síntoma

| Síntoma | Causa probable | Acción |
|---|---|---|
| `401` en ingestión | Token revocado, rotado o mal transferido | Reparar/rotar credencial; no reutilizar la anterior |
| `403` en ingestión | Dispositivo no asignado al sensor | Corregir asignación en registro; no ampliar a ciegas |
| `409/410` en control | Ruta heredada retirada | Usar sensor/ingestión v1; no reactivar listeners |
| Lote en cuarentena | `403/409/413/422` | Revisar lote, corregir y reenviar; no borrar silenciosamente |
| Spool lleno | Saturación o receptor caído | Pausar productor, contabilizar descartes, ampliar solo con autorización |
| `storage_errors` de auditoría | Base `audit.db` con permisos heredados | Migrar permisos explícitamente; no relajar el almacén |
| Cola Elasticsearch con `permanent>0` | Rechazo permanente o conflicto | Revisar `event.id`, mapping, auth; no forzar overwrite |
| Data stream vacío | Exportador parado, cola pendiente o API key inválida | Verificar `run_elastic_export.py`, cola y API key; no crear documentos a mano |
| Dashboard sin datos | Data view desactualizado o rango temporal sin eventos | Verificar data view `deception-events*`, ingesta reciente y reimportar con `overwrite=true` |
| Celda sin tráfico | Precondición de red no configurada | Revisar política/vecinos estáticos; no abrir ARP/ND “para que conecte” |

## 6. Retención, capacidad y copias

### 6.1 Analítica

- `deception-events`: rollover a 50 GB o 30 días; borrado a los 30 días por
  defecto (`ILM_DECEPTION_EVENTS_DAYS`).
- `deception-alerts`: rollover a 10 GB o 90 días; borrado a los 90 días por
  defecto (`ILM_DECEPTION_ALERTS_DAYS`).
- Watermarks de disco: 85 % low, 90 % high, 95 % flood stage, con
  `enable_for_single_data_node: true`.
- ILM **no es una copia de seguridad**. El compose declara `path.repo`, pero no
  hay un repositorio de snapshots registrado en los artefactos; la copia de
  Elasticsearch sigue pendiente de diseño y prueba.

### 6.2 Dystopia

- Spool: 10.000 filas, 32 MiB de payload, 64 MiB de DB; el journal `DELETE`
  puede duplicar temporalmente el consumo.
- Receptor: 100.000 eventos, 10.000 por sensor, 256 MiB de DB y reserva de
  disco comprobada. Rechazo `503` antes de ACK si no puede persistir.
- No hay purga automática de eventos v1. La retención debe definirse y probarse
  antes de crecer; no se borra “para liberar espacio” sin autorización.
- Copias SQLite con la API de backup o con el servicio parado por el
  administrador; nunca copiar un journal incoherente. Cifrar y restringir;
  los logs/eventos contienen datos hostiles.
- Revisar `du`, `xfs_quota`/`repquota` y contadores del runtime como lectura;
  no cambiar cuotas del host desde este repositorio.

## 7. Recuperación

| Escenario | Procedimiento | Lo que no se hace |
|---|---|---|
| Apply interrumpido | Corregir prerrequisito y repetir el mismo apply | Borrar usuarios/directorios válidos o secretos |
| Archivo preexistente distinto | Reparación explícita desde backup confiable | Sobrescritura silenciosa |
| `nft` rechaza o tabla existe | Queda `degradado`; revisar y repetir con autorización | Adoptar/reemplazar la tabla o hacer `flush` |
| Pérdida del controlador | Las reglas permanecen; restaurar control y revisar | Retirar filtros al parar el control |
| Reinicio del host | Inventariar; las tablas nft se pierden; aplicar de nuevo con autorización fresca | Autostart, reconciliación implícita o `enable` de unidades |
| Sensor comprometido | Revocar de inmediato, conservar filtros y evidencia restringida | Seguir confiando en sus eventos o reutilizar su token |
| Base de auditoría ilegible | `chmod 600` y propietario correcto tras revisión; confirmar contadores a 0 | Relajar permisos o borrar la base |
| Base de eventos dañada | Restaurar copia consistente con servicios parados | Copiar `-wal`/`-shm` a ciegas o mezclar instantáneas |
| Elasticsearch/Kibana caídos | Parar, conservar volúmenes, restaurar configuración conocida y reiniciar | Borrar índices o volúmenes para “limpiar” |
| Dashboards rotos | Reimportar el bundle con `overwrite=true` tras corregir spec | Editar a mano objetos no versionados |

La recuperación de Elasticsearch por snapshot, la reconciliación de arranque de
celdas y la persistencia de tablas nft tras reboot **no están implementadas**.
No se debe presentar un reinicio exitoso como recuperación certificada.

## 8. Rollback

1. **Celda:** cuarentena aditiva primero; conservar tabla, logs, imagen, cuota y
   evidencia. Parar el contenedor exacto con el runtime autorizado. Restaurar la
   política revisada en frío. No borrar por prefijo ni retirar reglas ajenas.
2. **Control/ingestión:** restaurar release y venv anteriores verificados por
   hash; conservar datos y secretos válidos. Repetir el apply solo si la
   configuración coincide; si difiere, migración manual revisada.
3. **Elasticsearch/Kibana:** parar el profile, conservar volúmenes, restaurar
   configuración/certs conocidos. Los dashboards se pueden reimportar; los
   datos no se “recuperan” borrando índices.
4. **Prohibido como rollback:** reactivar Compose deception, listeners, tailer,
   QEMU o el motor legacy; ejecutar `flush ruleset`; borrar bridges/taps/
   volúmenes por patrón; deshabilitar la auditoría para que “pase” el health.

Criterio de rollback: cualquier duda de topología, cuota, separación de gestión
o autenticación deja el componente en `degradado` y la activación bloqueada.

## 9. Criterios para un laboratorio autorizado

El arnés opt-in de `tests/integration_unified` es la referencia de puertas
fail-closed. Solo se ejecuta si **todas** estas condiciones son explícitas:

- `DYSTOPIA_LAB_CONFIRM=DISPOSABLE-LAB-ONLY`;
- `DYSTOPIA_LAB_MARKER` es un fichero creado por el operador con
  `purpose=dystopia-disposable-lab` y `authorization_id=<id>`;
- `DYSTOPIA_LAB_TARGETS` es una allowlist explícita de literales RFC1918,
  loopback o ULA (o nombres `*.lab`/`*.lab.local`/`*.test`); se rechazan
  direcciones públicas, de documentación, carrier-grade, multicast y
  link-local/metadata;
- `DYSTOPIA_LAB_SCENARIO` apunta a un escenario sin credenciales inline; los
  tokens van en ficheros `0600/0400`;
- HTTP plano solo se acepta en loopback;
- el login SSH benigno lo realiza el operador y se confirma con
  `DYSTOPIA_LAB_SSH_PERFORMED`; el arnés nunca abre SSH, envía credenciales ni
  exploits.

```sh
# Preflight: solo salud/lectura y comprobaciones de topología
scripts/smoke_unified.sh --lab

# Flujo completo: además, persistencia, un documento por event.id, mapping,
# data view, filtros y reinicio del publicador. Requiere el paso SSH del operador.
scripts/smoke_unified.sh --lab --full
```

Un `skip` por falta de variables **no** es un resultado verde. Un fallo de
artefacto es un hallazgo del componente propietario, no algo que se silencie
revirtiendo el contrato.

Para la contención de celdas, la matriz obligatoria es
[LAB-TESTS.md](../deploy/isolation/LAB-TESTS.md): capturas en host/gateway/otra
celda, contadores por celda, IPv4 e IPv6, ARP/ND/VLAN/fragmentos, cuarentena,
pérdida de controlador, reboot y cuotas. `nft --check`, un XML o un contenedor
arrancado no sustituyen ninguna fila.

## 10. Estado de verificación actual

Ejecutado el 2026-10-29 en esta sesión, host macOS 26.6.2 / Python 3.14.7, sin
servicios ni red:

| Comprobación | Resultado | Alcance |
|---|---|---|
| `tests/integration_unified` | **82 OK, 3 skips** | Contratos, mappings, dedupe, filtros, artefactos; skips son lab y log externo |
| `tests/deception` | **50 passed** | Bindings, adaptadores, publicador con transporte falso |
| `tests/hardening` | **53 passed, 41 subtests** | Separación, identidad, cuotas, instalación, aislamiento con mocks |
| Suite completa `tests/` | **20 fallos, 4 errores** | 17+4 son contratos retirados; 3 son el puente de consulta con `AF_UNIX path too long` en macOS |
| Honeypots: builds | **No ejecutados** | No hay evidencia de compilación ni arranque |
| Digests/firmas/SBOM/CVE | **Pendientes** | Digests observados, sin verificar firma ni reproducibilidad |
| Elasticsearch/Kibana | **No arrancados** | Sin bootstrap, import ni consultas reales |
| `nft`/libvirt/contenedores | **No ejecutados** | Contención no demostrada |
| Observabilidad | **No ejecutada** | Compose heredado sin validar |

Estas cifras acreditan lógica de aplicación y coherencia de artefactos offline;
**no** certifican Ubuntu 24.04, Python 3.12, los pins de despliegue, TLS, red,
contención ni integración real.

## 11. Referencia rápida de comandos

| Comando | Efecto | ¿Seguro ahora? |
|---|---|---|
| `python3 -m runtime.install --dry-run …` | Plan sin escrituras | Sí, en copia revisada |
| `python3 -m runtime.isolation plan …` | Render sin efectos | Sí |
| `python3 -m runtime.isolation plan-container …` | Render sin efectos; `image:null` falla a propósito | Sí |
| `scripts/smoke_unified.sh` | Pruebas offline sin red | Sí |
| `python3 -m runtime.cli status …` | Lectura SQLite de solo lectura | Sí, si existe la DB |
| `curl http://127.0.0.1:8082/api/health` | Lectura local | Sí, con control arrancado |
| `python3 -m runtime.install --apply …` | Escribe usuarios/unidades/archivos | Solo autorizado |
| `systemctl start …` | Arranca un servicio | Solo autorizado |
| `python3 -m runtime.isolation apply …` | Aplica nft de una celda | Solo laboratorio autorizado |
| `nft`, `virsh`, `docker compose up`, builds | Cambian estado del host | Solo autorizado y con evidencia |
| `nft flush ruleset`, `docker system prune`, `iptables -F` | Destructivo/global | **Prohibido** |

## 12. Referencias

- [Arquitectura y contrato unificado](UNIFIED-DECEPTION.md)
- [Instalación y operación endurecida](HARDENING-OPERATIONS.md)
- [Diagnóstico de endurecimiento](HARDENING.md)
- [Aislamiento por celda](hardening-isolation.md)
- [Operación de celdas contenedor](../deploy/isolation/OPERATIONS.md)
- [Pruebas de laboratorio de celdas](../deploy/isolation/LAB-TESTS.md)
- [Honeypots: activación y límites](../deploy/honeypots/README.md)
- [Elasticsearch/Kibana](../deploy/elastic/README.md)
- [Dashboards Kibana](../deploy/kibana-dashboards/README.md)
- [Pruebas de integración unificadas](../tests/integration_unified/README.md)
- [Consola operativa](CONSOLE-OPERATIONS.md)
- [Puente de consulta](QUERY-BRIDGE.md)
