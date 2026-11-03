# Sistema unificado de deception — arquitectura y contrato

**Estado: artefactos en el árbol de trabajo, validación offline; NO desplegado.**
No se han arrancado Dystopia, Elasticsearch, Kibana, Prometheus/Loki/Grafana,
contenedores, VMs ni honeypots. No se han ejecutado `nft`, libvirt, QEMU,
`systemd`, instaladores ni cambios de red. La activación de celdas sigue
bloqueada en código y la contención real no está demostrada.

Esta página describe **cómo encajan** Dystopia, los honeypots externos y el
panel analítico. Para el detalle de cada pieza se enlazan los documentos
propietarios; no se duplican aquí sus procedimientos extensos.

| Capa | Implementado | Validado offline | Pendiente de laboratorio |
|---|---|---|---|
| Control FastAPI y topología | Sí: dispositivos, segmentos, personas, bindings | Sí: suite de topología y contratos | Instalación real, identidades Linux, TLS de gestión |
| Sensores y receptor v1 | Sí: spool, HTTPS, credencial por sensor, cuotas | Sí: unitarios de hardening e integración offline | Certificados, red de telemetría, carga real |
| Adaptadores de honeypots | Sí: seis `normalize` ECS/Dystopia | Sí: fixtures sintéticas | Colector de logs, ingesta operativa, builds |
| Publicador Elasticsearch | Sí: cola, idempotencia, reintentos | Sí: transporte falso en pruebas | Autenticación compatible, clúster real |
| Elasticsearch/Kibana 9.3.5 | Sí: compose, TLS, roles, plantillas, ILM, dashboards | Parcial: sintaxis y referencias | Arranque, bootstrap, import, consultas reales |
| Aislamiento por celda | Sí: validación y render KVM/contenedor | Sí: unitarios con mocks | `nft`/kernel, topología, capturas, cuotas |
| Observabilidad operativa | Compose heredado de Prometheus/Loki/Grafana | No | Endurecimiento, versiones fijadas, ejecución |

## 1. Vista de arquitectura y flujo

```text
                         PLANO DE GESTIÓN
  operador ──► control FastAPI (127.0.0.1:8082)
                 │  topología: dispositivos, segmentos, personas, bindings
                 │  consola de solo lectura ──► socket Unix ──► query
                 │  NO arranca listeners, QEMU, libvirt ni firewall
                 │
                 ├──► Elasticsearch 9.3.5 ◄── publicador ECS (opt-in, no cableado)
                 │        └──► Kibana 9.3.5 (analítica, solo gestión)
                 │
                 └──► Prometheus/Loki/Grafana (operación; Compose heredado)

                         PLANO DE DECEPTION
  atacante/cliente autorizado
        │ tráfico exacto autorizado
        ▼
  celda N: VM KVM  ─o─  contenedor de honeypot (nunca ambos)
        │  cowrie · opencanary · dionaea · heralding · redishoneypot · endlessh
        │  logs nativos hostiles
        ▼
  sensor independiente (spool acotado, sin configuración administrativa)
        │ HTTPS exacto a IP literal, bearer por sensor
        ▼
  receptor de ingestión (proceso separado) ──► events.db + outbox
        │                                      │
        │                                      └──► procesador/alertas (metadatos)
        └── contrato de transporte v1          └──► consulta de solo lectura

  normalización ECS/Dystopia (cowrie…endlessh) ──► documento analítico
        └── publicador Elasticsearch ──► deception-events* / deception-alerts*
```

La línea de normalización y publicación está **implementada y probada offline**.
`NativeExporter` (`app/services/deception/integrations/exporter_svc.py`) lee el
`EventStore` central en modo solo lectura, convierte los eventos runtime v1 a
ECS/Dystopia y los entrega al publicador Elasticsearch con cursor persistente,
cola durable e idempotencia por `event.id`. El runner
`scripts/run_elastic_export.py` está deshabilitado por defecto y aún no tiene
unidad systemd ni una ejecución real contra un clúster. El sensor independiente
sigue sin colector de logs de honeypot: el tailer central está retirado
(`blocked`), por lo que falta el proceso que alimente el spool desde los logs de
los seis motores. El puente central existe; el colector por sensor no.

### Flujo previsto, extremo a extremo

1. **Topología.** El operador declara segmentos, dispositivos, personas y
   servicios señuelo en `config/deception/network.yaml`. Cada servicio apunta a
   un motor (`engine`) y, si es externo, a una instancia (`instance`).
2. **Binding.** `topology_svc` publica la vista de bindings y resuelve
   `(instance_id) → device_id, segment_id, persona`. El honeypot no recibe la
   topología completa ni credenciales de gestión.
3. **Captura.** La celda aislada expone solo los puertos declarados. El
   honeypot escribe su log nativo en un volumen con cuota.
4. **Normalización.** Un adaptador traduce el registro nativo a un documento
   ECS/Dystopia. Metadatos ausentes no eliminan el evento; se marcan como
   desconocidos.
5. **Transporte.** El sensor envía lotes v1 por HTTPS autenticado al receptor
   independiente, con deduplicación y cuarentena de lotes rechazados.
6. **Persistencia.** El receptor confirma solo tras escribir en SQLite; el
   procesador deriva alertas y un outbox de metadatos.
7. **Analítica.** El publicador escribe el documento ECS en un data stream de
   Elasticsearch con `PUT …/_create/{event.id}`. Kibana consume los data views.
8. **Operación.** Prometheus/Loki/Grafana es el plano de salud y logs; no es el
   panel de analítica de ataques ni tiene ruta desde las celdas.

## 2. Planos y fronteras de confianza

Los valores son **sintéticos de laboratorio**. El inventario del operador es la
autoridad; ningún componente descubre topología ni adivina interfaces.

| Plano | Ejemplo | Componentes | Regla |
|---|---|---|---|
| Gestión | `mgmt0`, `198.51.100.0/24` | control, Kibana, Elasticsearch, SSH de operador | Solo gestión; sin ruta desde deception, telemetría ni simulación |
| Deception | `decoy0`, `192.0.2.0/24` | un bridge `dybrN` por celda; VM **o** contenedor | Solo flujos entrantes exactos y salida exacta a ingestión |
| Telemetría | `telemetry0`, `198.18.255.0/24` | receptor de ingestión | Solo el endpoint exacto; escritura a Elasticsearch con identidad propia |
| Simulación de ataque | `198.18.1.0/24` | clientes de laboratorio autorizados | Solo orígenes literales declarados por celda |
| Protegida | `203.0.113.0/24`, `fd42:d570:100::/64` | producción y otros | Sin ruta desde ninguna celda |

Fronteras que el diseño exige y que el código **no** puede demostrar por sí
solo:

- Un invitado o contenedor comprometido puede falsificar o perder la telemetría
  de su propia celda y robar su token. No debe obtener JWT, base central,
  credenciales de otros sensores, consola del hipervisor ni rutas a gestión.
- La identidad autenticada no hace veraz el contenido del sensor.
- Kernel, hipervisor, helper privilegiado, CA, configuración del operador y
  receptor siguen siendo confianza crítica.
- Una VLAN, una red Docker `internal: true`, un JSON válido o un `nft --check`
  correcto **no** son evidencia de contención.

Referencia completa: [diseño de aislamiento](hardening-isolation.md) y
[planos y celdas contenedor](../deploy/isolation/README.md).

## 3. Control Dystopia: topología, personas y NetBox

El control conserva la administración y la lectura, no la ejecución:

- **Dispositivos** (`DeceptionDevice`): `id`, `role`, `segment`, `ip`, `persona`,
  `services`, `enabled`, `tags`.
- **Segmentos** (`DeceptionSegment`): `id`, `vlan_id`, `cidr`, `gateway`,
  `isolated`.
- **Personas** (`DeceptionPersona`): identidad ficticia (vendor, OS, hostname,
  MAC, etc.). Es metadato de caracterización, no una prueba de identidad.
- **Servicios** (`DeceptionService`): `port`, `proto`, `engine`, `instance`,
  `banner`.

Motores internos (`native`, `go`) no exigen `instance`. Los seis motores
externos (`cowrie`, `opencanary`, `dionaea`, `heralding`, `redishoneypot`,
`endlessh`) sí la exigen al crear o actualizar dispositivos; los servicios
heredados sin `instance` se reportan como warning y no son consumibles por los
adaptadores.

Rutas de lectura relevantes:

```text
GET /api/deception/network
GET /api/deception/bindings
GET /api/deception/bindings/resolve/{instance_id}
```

**NetBox:** en este build autónomo no hay sincronización operativa.
`POST /api/deception/sync-netbox` devuelve `{"success": false, "disabled": true,
"reason": "standalone Dystopia"}` y no se importa ningún cliente NetBox. La
topología local revisada es la fuente de verdad; NetBox queda como referencia
histórica de inventario, no como dependencia del arranque.

Las rutas heredadas de ejecución (`engine/start`, `ingest`, `simulate`,
`firewall/*`, arranque de VMs) responden `409` o `410`; el control no abre
listeners, no lanza QEMU/libvirt y no aplica firewall. La consola es de solo
lectura para eventos y declarativa para celdas; `prepare`/`activate` devuelven
`409 ActivationBlocked`. Véase [consola operativa](CONSOLE-OPERATIONS.md) y
[puente de consulta](QUERY-BRIDGE.md).

> `docs/deception.md` describe la etapa anterior (listeners nativos, tailer
> dentro del control, Compose deception). Se conserva como histórico; no es la
> guía del build endurecido ni debe usarse para reactivar esas rutas.

## 4. Sensor independiente y receptor

- **Sensor:** `runtime.sensor.Spool` + `Transport`. No importa configuración
  administrativa ni listeners heredados. Entrega HTTPS a una IP literal, sin
  DNS, redirects, proxies ni hostnames.
- **Credencial:** bearer aleatoria por sensor, almacenada como digest en el
  registro del receptor. El sensor solo recibe su token y su asignación de
  dispositivos; no recibe JWT, CA privada ni credencial de otro sensor.
- **Receptor:** `runtime.ingest` es un proceso FastAPI separado, sin rutas de
  administración, que exige TLS directo y rechaza cabeceras de proxy como
  prueba de seguridad.
- **Cuotas:** 64 eventos/lote, 256 KiB/lote, 8 KiB/evento; spool de 10.000
  filas, 32 MiB de payload y 64 MiB de DB; receptor de 100.000 eventos,
  10.000 por sensor y 256 MiB de DB. El rechazo es visible, nunca un ACK falso.
- **Deduplicación:** clave `(sensor, event_id)`. El mismo ID con contenido
  distinto es conflicto; no se sobrescribe.
- **Cuarentena:** los lotes con `401` conservan eventos y exigen reparar o
  rotar la credencial; `403/409/413/422` van a cuarentena dentro de la misma
  cota y requieren revisión.

El sensor **no incluye** todavía un colector de logs de honeypot. Los
adaptadores existen y el exportador central ya convierte eventos runtime v1 a
ECS/Dystopia, pero no están importados por `runtime.sensor`; el tailer central
devuelve `blocked`. Por tanto, el proceso que lee los logs de los seis motores y
los convierte en eventos v1 dentro del sensor sigue siendo un pendiente de
integración. Una vez exista, el puente central
(`scripts/run_elastic_export.py`) ya está preparado para publicarlos en
Elasticsearch.

## 5. Contrato de evento

Hay dos capas que no deben confundirse.

### 5.1 Transporte v1 (sensor → receptor)

| Campo | Obligatorio | Regla |
|---|---|---|
| `event_id` | Sí | UUID4 canónico; deduplicación por `(sensor, event_id)` |
| `device_id` | Sí | Identificador validado contra el registro del sensor |
| `observed_at` | Sí | ISO-8601 con zona; se normaliza a UTC |
| `src_ip` | Sí | IP canónica, sin zona ni `%` |
| `type` | Sí | `connect`, `disconnect`, `login_attempt`, `login_success`, `command`, `file_download`, `port_scan`, `other` |
| `proto` | Sí | `tcp`, `udp`, `ssh`, `telnet`, `http`, `ftp`, `mysql`, `snmp` |
| `src_port` | No | Entero 1–65535 |
| `detail` | No | Máximo 16 claves, valores string ≤ 2 KiB; sin objetos anidados |

Los flags de simulación, supresión o identidad declarada por el sensor se
rechazan. `observed_at` es una declaración no confiable: las ventanas y cuotas
usan `received_at` del receptor.

### 5.2 Documento ECS/Dystopia (adaptador → Kibana)

| Bloque | Campos principales |
|---|---|
| `@timestamp` | Marca temporal UTC del evento |
| `event.*` | `id`, `kind`, `category`, `type`, `action`, `severity`, `outcome`, `dataset` |
| `observer.*` | `type=honeypot`, `name`, `product`, `vendor`, `version` |
| `network.*` | `transport`, `protocol` |
| `source.*` | `ip`, `port`, `geo.*`, `as.*` |
| `destination.*` | `ip`, `port` |
| `session.id` | Sesión nativa del honeypot, si existe |
| `dystopia.*` | `schema_version`, `device_id`, `segment_id`, `instance_id`, `persona`, `decoy_credentials`, `raw_reference`, `ingest_source` |
| `dystopia_restricted.payload` | Contenedor hostil **no indexado** (comando, URL, mensaje, hash, etc.) |

`dystopia` es `dynamic: strict`: un campo no declarado rechaza el documento.
El nivel superior es `dynamic: false`: lo no declarado —incluido
`dystopia_restricted`— se conserva en `_source` pero no se indexa ni agrega.

`dystopia.raw_reference` es un HMAC-SHA-256 con una clave provisionada fuera
del documento (`DYSTOPIA_EVENT_REFERENCE_KEY_FILE`), no un hash verificable del
registro crudo. Sin clave, el normalizador falla cerrado en vez de publicar un
oráculo de credenciales de baja entropía.

### 5.3 Identidad e idempotencia

- `event_id` del transporte es un **UUID4** generado por el sensor. Su
  deduplicación es `(sensor, event_id)`.
- `event.id` del documento analítico es un **UUID5 determinista** derivado de
  observador, instancia, dispositivo, ID nativo/sesión, tupla de red, acción,
  fingerprint del registro y secuencia. Releer la misma línea produce el mismo
  ID.
- El publicador usa `PUT /<índice>/_create/<event.id>`. Un `2xx` confirma; un
  `409` se interpreta como “ya existe” y se cuenta como duplicado (no se
  recupera ni compara el documento remoto). La cola rechaza el mismo `event.id`
  con bytes distintos; el clúster nunca sobrescribe porque la escritura es
  *create-only*.
- `event.id` no es el `event_id` del transporte: son capas distintas y no deben
  intercambiarse.

### 5.4 Metadatos ausentes y datos restringidos

- Si falta el dispositivo, el documento conserva el evento con
  `device_id = unknown-<observer>`; si falta el segmento, `segment_id` es
  `unknown`; si falta la instancia, `instance_id` es `unassigned`.
- El proveedor de metadatos (topología/GeoIP) no puede lanzar ni eliminar un
  evento; los fallos se degradan a ausencia de metadato.
- Las credenciales capturadas **no** se indexan: `dystopia.decoy_credentials`
  solo contiene el identificador (usuario o `password-present`). El valor queda
  accesible únicamente para manejadores en proceso y nunca se serializa en el
  documento publicado ni en logs.
- El payload hostil vive en `dystopia_restricted.payload`; no se envía a
  modelos de IA ni se usa en filtros de Kibana.
- Los logs del publicador y del sensor no incluyen comandos, contraseñas ni
  cuerpos completos.

Límites de lote y de evento: 64 eventos, 256 KiB y 8 KiB respectivamente. Los
detalles son cadenas hostiles acotadas, no estructuras ejecutables.

## 6. Bindings `engine` / `instance`

Reglas verificadas en código y pruebas:

- Un servicio externo sin `instance` no es consumible por adaptadores.
- `instance` debe cumplir `[a-z0-9][a-z0-9_-]*`, máximo 64 caracteres.
- La misma `(engine, instance)` no puede repartirse entre dispositivos
  distintos. Sí puede atender varios puertos del **mismo** dispositivo.
- `engine` es una etiqueta de enrutamiento; no concede confianza ni implica que
  el honeypot esté arrancado.
- Los bindings no contienen credenciales.

Ejemplo sintético, sin secretos (el archivo real es
`config/deception/network.yaml`):

```yaml
segments:
  - id: seg-lab-edge
    vlan_id: 110
    cidr: 192.0.2.0/24
    isolated: true

devices:
  - id: srv-files-01
    role: server
    segment: seg-lab-edge
    ip: 192.0.2.10
    persona:
      vendor: linux
      os: ubuntu
      hostname: srv-files-01
    services:
      - port: 2222
        proto: ssh
        engine: cowrie
        instance: cowrie-lab-01
      - port: 2223
        proto: telnet
        engine: cowrie
        instance: cowrie-lab-01
```

Vista de resolución, también sin secretos:

```json
{
  "instance_id": "cowrie-lab-01",
  "engine": "cowrie",
  "device_id": "srv-files-01",
  "segment_id": "seg-lab-edge",
  "device_ip": "192.0.2.10",
  "persona": {"vendor": "linux", "os": "ubuntu", "hostname": "srv-files-01"},
  "bindings": [
    {"proto": "ssh", "port": 2222},
    {"proto": "telnet", "port": 2223}
  ]
}
```

La validación de topología detecta segmento inexistente, IP fuera del CIDR,
`(puerto, proto)` duplicado, instancia con formato inválido y conflicto global
de `(engine, instance)`. No arranca ni comprueba honeypots.

## 7. Catálogo de honeypots

Los puertos son **internos al contenedor**; no se publican al host. Las rutas de
log se montan bajo `${DYSTOPIA_HONEYPOT_DATA:-/var/lib/dystopia/honeypots}`.
Fuente: [inventario](../deploy/honeypots/inventory.yaml) y
[matriz de motores](../deploy/honeypots/README.md).

| Motor | Puertos internos | Log canónico | Formato | RAM / CPU / PIDs / nofile | Licencia | Verificación |
|---|---|---|---|---|---|---|
| Cowrie | 2222/tcp SSH, 2223/tcp Telnet | `/cowrie/cowrie-git/var/log/cowrie/cowrie.json` | JSONL | 512 MiB / 0,50 / 256 / 4096 | BSD-3-Clause | Adaptador + fixture; build/runtime no |
| OpenCanary | 21, 22, 23, 80, 3306/tcp | `/var/log/opencanary/opencanary.log` | JSONL | 256 MiB / 0,25 / 128 / 2048 | BSD-3-Clause | Adaptador + fixture; build/runtime no |
| Dionaea | 21, 69/udp, 81, 135, 443, 445, 1433, 1723, 1883, 3306, 27017 | `/opt/dionaea/var/log/dionaea.json` | JSONL | 768 MiB / 1,00 / 512 / 4096 | GPL-2.0-or-later | Adaptador + fixture; build/runtime no |
| Heralding | 21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389, 5432, 5900/tcp | `/var/log/heralding/sessions.jsonl` | JSONL (+ CSV) | 512 MiB / 0,50 / 256 / 4096 | GPL-3.0 | Adaptador + fixture; build/runtime no |
| RedisHoneyPot | 6379/tcp | `/var/log/redishoneypot/redishoneypot.log` | JSONL | 192 MiB / 0,25 / 128 / 2048 | GPL-3.0 | Adaptador + fixture; build/runtime no |
| Endlessh | 2222/tcp | `/var/log/endlessh/endlessh.log` | texto con timestamp | 64 MiB / 0,10 / 64 / 8192 | Unlicense | Adaptador + fixture; build/runtime no |
| **Total** | — | — | — | **2304 MiB / 2,60 / 1344** | — | Reservar 4 vCPU / 4 GiB |

Versiones fijadas en el inventario: Cowrie `3.1.4`, OpenCanary `0.9.10`,
Dionaea `0.12.5`, Heralding `ac12724`, RedisHoneyPot `45adc62` y Endlessh
`dfe44eb`. Los digests de las imágenes base observados el 2026-10-29 están en
[PROVENANCE.md](../deploy/honeypots/PROVENANCE.md); no se verificó su firma.

Notas de operación y seguridad:

- Los límites son cotas de laboratorio, no una garantía bajo ataque. Ajustar
  tras medir en la celda autorizada.
- OpenCanary, Dionaea y Heralding escuchan en puertos < 1024 y usan la
  capability `NET_BIND_SERVICE`. Todos los servicios mantienen
  `no-new-privileges:true`: NNP bloquea la elevación por setuid/file
  capabilities de la imagen, no la capability concedida al contenedor. Falta
  verificar en Linux que sigue efectiva para el UID no-root; si no, remapear a
  puertos altos y hacer DNAT en la celda.
- Dionaea carga el módulo `curl` y puede intentar conexiones salientes al
  procesar URLs de atacantes. La celda debe denegar egress; no se probó.
- Cowrie usa `AuthRandom`: no produce `login_success` por defecto.
- Endlessh con `MaxClients 4096` consume descriptores; validar `nofile` contra
  `fs.file-max` de la celda.
- Los logs capturan credenciales, comandos y binarios: son datos hostiles.
  Restringir acceso, cifrar copias, definir retención y no enviarlos a IA ni a
  Kibana sin redacción y mapping aprobados.
- Las imágenes base y los digests se observaron el 2026-10-29, pero **no** se
  verificó firma, attestation ni reproducibilidad. Los builds no se ejecutaron.
- No existe `local_digest` de las imágenes construidas: el perfil de referencia
  declara `image_policy: tag-lab-only` (no productivo). El render por defecto
  exige digest y falla cerrado; para activar hay que construir, anotar el
  digest y cambiar el perfil a `digest-required`.

Procedencia y licencias completas: [PROVENANCE.md](../deploy/honeypots/PROVENANCE.md).
Estado de los adaptadores y diferencias nativo/fixture:
[adapters.md](../deploy/honeypots/adapters.md).

## 8. Adaptadores y normalización

Los seis adaptadores están registrados en
`app/services/deception/integrations/adapters.py` y producen el documento
descrito en la sección 5:

| Motor | Función | Parser heredado |
|---|---|---|
| Cowrie | `cowrie_svc.normalize` | `parse` se conserva para el tailer retirado |
| OpenCanary | `opencanary_svc.normalize` | `parse` se conserva |
| Dionaea | `dionaea_svc.normalize` | — |
| Heralding | `heralding_svc.normalize` | — |
| RedisHoneyPot | `redishoneypot_svc.normalize` | — |
| Endlessh | `endlessh_svc.normalize` | — |

Los adaptadores son puros: no abren logs, no ejecutan binarios descargados, no
expanden URLs ni renderizan HTML. La metadata se inyecta. Las fixtures son
muestras sintéticas con IPs RFC 5737 y contraseñas de demostración; no son
capturas reales ni evidencia de ingesta.

Limitaciones que deben revisarse antes de producción:

- Las fixtures añaden alias canónicos que el log nativo no siempre tiene
  (Dionaea anida `connection`/`credentials`; Heralding usa
  `source_ip`/`auth_attempts`; OpenCanary anida `logdata`). El colector real
  debe aplanar o el adaptador debe leer los objetos anidados.
- El parser heredado de Cowrie fija `proto="ssh"`; `normalize` ya distingue
  Telnet, pero el tailer antiguo no debe reactivarse.
- RedisHoneyPot mapea `Closed` a `disconnect` en el adaptador actual; la
  documentación antigua de `adapters.md` decía lo contrario. Verificar contra
  un log real antes de confiar en la clasificación.
- Endlessh mapea `TOTALS` a `other` sin origen; no debe contarse como ataque.

## 9. Elasticsearch/Kibana 9.3.5 — panel analítico

Artefactos: [deploy/elastic](../deploy/elastic/README.md),
[elasticsearch.yml](../config/elasticsearch/elasticsearch.yml),
[kibana.yml](../config/kibana/kibana.yml),
[plantillas](../config/elasticsearch/templates/),
[ILM](../config/elasticsearch/ilm/),
[roles](../deploy/elastic/roles/) y
[dashboards](../deploy/kibana-dashboards/README.md).

- **Versiones fijadas:** Elasticsearch y Kibana `9.3.5`, misma familia que el
  stack de tpotce 24.04.x. Nunca `latest`.
- **Compose no autoejecutable:** profile `deception-elastic`; puertos solo en
  `127.0.0.1` (o interfaz de gestión explícita); sin ruta desde deception.
- **TLS:** CA propia y certificados de nodo generados con `openssl`. HTTP y
  transport con TLS; Kibana valida el certificado con `verificationMode: full`.
  Las claves privadas del nodo no llevan passphrase y se protegen con `0600` y
  `umask 077`; el material no está en el repositorio.
- **Autenticación:** `xpack.security.enabled: true`; acceso anónimo
  deshabilitado, API keys habilitadas solo para el publicador y service tokens
  deshabilitados. `elastic` es superusuario solo para bootstrap/emergencias.
- **Roles:** `deception-ingest-writer` escribe únicamente en
  `deception-events*`/`deception-alerts*`, sin Kibana; `deception-analyst` es
  solo lectura y `minimal_read` en Kibana; `deception-admin` administra el
  espacio `deception-*` y `.kibana*` sin `manage_security`.
- **Data streams:** `deception-events` y `deception-alerts`, 1 shard, 0
  réplicas, `refresh_interval: 5s`, `best_compression`. Las plantillas aceptan
  el nombre exacto y `<nombre>-*`; los data views usan `deception-events*` /
  `deception-alerts*`.
- **ILM:** eventos con rollover a 50 GB o 30 días y borrado a los 30 días por
  defecto; alertas con rollover a 10 GB o 90 días y borrado a los 90 días. Los
  días de borrado se sobrescriben con `ILM_DECEPTION_EVENTS_DAYS` y
  `ILM_DECEPTION_ALERTS_DAYS` en el bootstrap. No hay purga automática de la
  base v1 de Dystopia: son retenciones distintas.
- **Dashboards:** 7 dashboards, 44 visualizaciones y 2 data views (53 objetos)
  en el bundle canónico, con manifiesto SHA-256. Importado y validado en
  Kibana `9.3.5`; los 7 dashboards renderizan con datos sintéticos. Existe una
  variante experimental con panel Maps.

Advertencias obligatorias:

- **Validado en macOS, no en la máquina objetivo.** Elasticsearch/Kibana
  `9.3.5`, roles, usuarios, API key, ILM, plantillas, data streams, ingesta
  real e import de dashboards se probaron en el laboratorio local. La
  contención KVM/nftables, el networking de segmentos y los builds reales de
  honeypots siguen sin certificarse en macOS.
- **Roles y API keys:** `bootstrap-security.sh --all` usa los privilegios
  reales de 9.3.5 (`manage_ilm`, metadata sin `_`, `active_only`,
  `role_descriptors`). El writer escribe con `201`, el duplicado devuelve `409`,
  el writer no puede leer (`403`) y el analyst lee (`200`) pero no escribe
  (`403`).
- **TLS:** CA y certificados incluyen AKI/SKI; Python/OpenSSL y `curl` los
  verifican. El frente TLS de Kibana (`server.ssl`) sigue comentado;
  `publicBaseUrl` apunta por defecto a HTTP en loopback. La exposición tras
  reverse proxy es un cambio de infraestructura separado.
- **Data streams:** se crean explícitamente con `PUT /_data_stream/<nombre>`.
  El antiguo doc de arranque creaba un índice plano y dejaba el data stream sin
  crear; corregido y verificado.
- **Dashboards:** el bundle usa el formato moderno de Kibana 9
  (`panelRefName`, `indexRefName`, `seriesParams[].data`, `histogram`,
  `format: "date"`). Un import con `createNewCopies=true` regenera IDs y rompe
  `defaultIndex: deception-events-dv`; usar `overwrite=true`.
- **Pendiente:** despliegue en la máquina objetivo, permisos definitivos de
  directorios, snapshots/restore de Elasticsearch y sustitución del panel Maps
  experimental si se adopta esa variante.

## 10. Aislamiento de celdas

Resumen; el procedimiento y la matriz de pruebas están en
[deploy/isolation](../deploy/isolation/README.md),
[CONTAINER-CELLS.md](../deploy/isolation/CONTAINER-CELLS.md),
[OPERATIONS.md](../deploy/isolation/OPERATIONS.md) y
[LAB-TESTS.md](../deploy/isolation/LAB-TESTS.md).

- Una celda `N` (`1..254`) es **una VM KVM o un contenedor de honeypot**, nunca
  ambas. Comparten de forma exclusiva `dybrN`, `dytapN`, `dyupN`, la tabla
  `dy_cell_N` y las direcciones `192.0.2.N` / `fd42:d570::N`.
- La política se valida y renderiza offline (`runtime.isolation`): XML KVM con
  NIC explícita y link down, o manifiesto de contenedor con rootfs read-only,
  usuario no root, `no-new-privileges`, `cap_drop=ALL`, sin socket Docker, sin
  puertos publicados, sin NAT y sin DNS.
- `container_nft_rules` delega en el mismo render que KVM; no hay una segunda
  implementación de firewall. Solo `create table` exclusivo; nunca
  `flush ruleset`, `delete`, `replace`, NAT ni adopción de tablas ajenas.
- La cuarentena es **aditiva** (`dy_quarantine_N`) y debe cortar también
  conexiones abiertas. La emergencia es cuarentena de red, no apagado del
  hipervisor.
- **Activación bloqueada:** `verify()` y `activate()` siempre fallan con
  `ActivationBlocked`; el estado `verificado` está reservado y nunca se produce.
  No existe `force`, `isolated` ni override.
- **Sin autostart:** las plantillas `dystopia-isolation-apply@.service` y
  `dystopia-isolation-quarantine@.service` no tienen `[Install]`; el perfil de
  honeypots usa `restart: "no"` y el profile `authorized-activation`. Las tablas
  nft se pierden al reiniciar el host y no hay reconciliación automática.
- **Límites declarativos, no aplicados por este repositorio:** memoria
  (`memory.max`/`MemoryMax`), pids (`pids.max`/`TasksMax`), CPU (`cpu.max`/
  `CPUQuota`), capa escribible (cuota XFS/ext4), logs, tmpfs y `LimitNOFILE`.
  El operador debe provisionarlos y verificarlos con evidencia externa.

El perfil Compose de honeypots es una **plantilla de referencia**. No publica
puertos, no usa red host y no monta el socket Docker, pero `internal: true` no
es contención. Los builds de las seis imágenes no se ejecutaron.

## 11. Límites actuales y afirmaciones que no deben hacerse

No está demostrado hoy:

- que los honeypots compilen, arranquen o resistan abuso;
- que la normalización funcione sobre logs reales (solo fixtures);
- que exista un colector sensor → normalizador → publicador en producción;
- que la contención KVM/nftables/cgroups/cuotas funcione en la máquina objetivo;
- que systemd, permisos, red de segmentos y recuperación estén certificados;
- que TLS/reverse proxy, snapshots y observabilidad de producción estén listos.

Sí está validado en el laboratorio: contrato ECS/Dystopia, publicador, roles,
data streams, ingesta real, import 53/53 de Kibana, 7 dashboards con datos
sintéticos, Discover, suite completa y ruff.

No deben usarse como evidencia: `nft --check`, un XML bien formado, un JSON
válido, una unidad systemd válida, `internal: true`, una VLAN, un contenedor
arrancado una vez o un panel sin errores.

## 12. Atribución, procedencia y licencias

- **T-Pot / Telekom Security:** se usó como referencia de catálogo y diseño.
  T-Pot es GPL-3.0. **No se copió el instalador de T-Pot, ni usuarios, tokens,
  claves, rutas `$HOME/tpotce`, configuración de red ni firewall.** Las
  configuraciones se reescribieron desde el upstream correspondiente y los
  artefactos ya presentes en Dystopia.
- **Cowrie** (BSD-3-Clause), **OpenCanary** (BSD-3-Clause), **Dionaea**
  (GPL-2.0-or-later), **Heralding** (GPL-3.0), **RedisHoneyPot** (GPL-3.0) y
  **Endlessh** (Unlicense) conservan sus licencias upstream.
- Los Dockerfiles de Dionaea, Heralding, RedisHoneyPot y Endlessh se
  reescribieron a partir del upstream y del patrón de build de T-Pot; no son
  copias literales. Si se consideran obra derivada de T-Pot, aplica GPL-3.0
  además de la licencia upstream.
- Distribuir imágenes GPL exige ofrecer el código fuente correspondiente. Este
  documento no es asesoramiento legal; revisar avisos y obligaciones antes de
  publicar imágenes o paquetes.

Detalle: [PROVENANCE.md](../deploy/honeypots/PROVENANCE.md).

## 13. Referencias

- [Endurecimiento: diagnóstico y plan](HARDENING.md)
- [Instalación y operación de la base endurecida](HARDENING-OPERATIONS.md)
- [Aislamiento por celda](hardening-isolation.md)
- [Consola operativa](CONSOLE-OPERATIONS.md)
- [Puente de consulta](QUERY-BRIDGE.md)
- [Honeypots: artefactos y límites](../deploy/honeypots/README.md)
- [Adaptadores y contrato](../deploy/honeypots/adapters.md)
- [Elasticsearch/Kibana](../deploy/elastic/README.md)
- [Dashboards Kibana](../deploy/kibana-dashboards/README.md)
- [Aislamiento de celdas contenedor](../deploy/isolation/README.md)
- [Pruebas de integración unificadas](../tests/integration_unified/README.md)
- [Operación del sistema unificado](UNIFIED-OPERATIONS.md)
