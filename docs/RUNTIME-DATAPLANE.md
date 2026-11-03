# Runtime data plane — colector offline de logs

Estado: **implementado y probado offline**. No arranca Docker, nftables, KVM,
SSH, contenedores, Elasticsearch ni Kibana. No publica puertos, no crea
sockets, no se ejecuta como daemon y no contiene secretos ni datos reales.

Este documento cubre la mitad "colector" del sensor:

```
deploy/honeypots/inventory.yaml
        |
        v
runtime.logreader.LogReader      lee solo fuentes declaradas, con cursor
        |                        (device, inode, offset) y límites
        v
runtime.normalize.normalize_raw  convierte el registro nativo en evento v1
        |                        (falla cerrado, redacta credenciales)
        v
runtime.sensor.Spool.submit      cola SQLite duradera e idempotente
        |
        v
runtime.sensor.Spool.flush_once  lote HTTPS autenticado al ingest existente
```

`runtime.dataplane.DataPlane` es el único punto que une las tres piezas. No es
importado por `runtime.ingest` ni por el plano de control.

## Ficheros

| Fichero | Responsabilidad |
|---|---|
| `runtime/logreader.py` | Fuentes declarativas, tail con rotación, lectura acotada y diagnóstico. |
| `runtime/normalize.py` | Registro nativo → evento v1 estricto, con redacción y `event_id` determinista. |
| `runtime/dataplane.py` | Bucle `leer → normalizar → spool → flush` de un solo paso, sin daemon. |
| `runtime/cli.py` | Subcomando `dataplane` de un solo uso (alternativa a `python -m runtime.dataplane`). |
| `tests/runtime-data-plane/` | Pruebas offline deterministas: fixtures, rotación, contrato, spool e ingesta. |

## Fuentes declarativas

Las rutas nunca se descubren recorriendo el sistema de ficheros.

### Modo laboratorio (fixtures)

Sin `--data-root` se usan las fixtures sintéticas declaradas por el inventario
(`deploy/honeypots/fixtures/*`). Es el modo de los tests y no toca el host.

```sh
python -m runtime.cli dataplane --spool /tmp/dystopia-spool.db --max-steps 2
```

### Modo celda Linux (solo cuando exista una celda autorizada)

El render de `runtime.honeypots` monta cada volumen declarado en
`<data_root>/cells/<N>/<source>`. El lector traduce la ruta interna del
contenedor usando la entrada `volumes` del propio motor; si la ruta no cae
dentro de un volumen declarado, falla y no adivina.

Ejemplo para la celda 1 con `storage.host_root: /var/lib/dystopia/honeypots`:

```sh
python -m runtime.cli dataplane \
  --spool /var/lib/dystopia/state/spool.db \
  --data-root /var/lib/dystopia/honeypots --cell 1
```

También se acepta la raíz de la celda ya resuelta, sin `--cell`:

```sh
python -m runtime.cli dataplane \
  --spool /var/lib/dystopia/state/spool.db \
  --data-root /var/lib/dystopia/honeypots/cells/1
```

Traducciones verificadas por los tests:

| Motor | Ruta en contenedor | Bind de host |
|---|---|---|
| Cowrie | `/cowrie/cowrie-git/var/log/cowrie/cowrie.json` | `<cell>/cowrie/var/log/cowrie/cowrie.json` |
| OpenCanary | `/var/log/opencanary/opencanary.log` | `<cell>/opencanary/log/opencanary.log` |
| Dionaea | `/opt/dionaea/var/log/dionaea.json` | `<cell>/dionaea/var/log/dionaea.json` |
| Heralding | `/var/log/heralding/sessions.jsonl` | `<cell>/heralding/log/sessions.jsonl` |
| RedisHoneyPot | `/var/log/redishoneypot/redishoneypot.log` | `<cell>/redishoneypot/log/redishoneypot.log` |
| Endlessh | `/var/log/endlessh/endlessh.log` | `<cell>/endlessh/log/endlessh.log` |

El `device_id` sale del inventario y debe coincidir con el asignado al sensor
en `runtime.identity.Registry`; el ingest rechaza dispositivos no asignados.

## Límites

| Límite | Valor | Dónde |
|---|---|---|
| Línea individual (incluida una línea sin `\n`) | 64 KiB | `DEFAULT_MAX_LINE_BYTES` |
| Tamaño de fichero aceptado | 64 MiB | `DEFAULT_MAX_FILE_BYTES` |
| Evento v1 serializado | 8 KiB | `runtime.contracts.MAX_EVENT_BYTES` |
| Lote de transporte | 64 eventos / 256 KiB | `MAX_BATCH_EVENTS` / `MAX_BATCH_BYTES` |
| `detail` | 16 claves, valores string ≤ 2048 bytes | `runtime.normalize._detail` |
| Spool | 10 000 eventos / 64 MiB (payload ≤ mitad) | `runtime.sensor.Spool` |
| Reintento de transporte | 5 s por petición, backoff exponencial ≤ 300 s | `runtime.sensor.Spool.flush_once` |

Reglas adicionales:

- Se lee como máximo el tamaño observado en el `fstat`; no se hace *slurp*.
- Un fichero mayor de 64 MiB se rechaza antes de leer. La rotación del host
  debe mantener los logs por debajo de esa cota; ver pendientes.
- Una línea incompleta al final se retiene en memoria (máximo 64 KiB) y no se
  emite hasta que llega el `\n`. Varios polls sin `\n` no mueven el cursor
  hacia atrás ni reemiten la línea anterior.
- Solo se abren ficheros regulares. Se rechazan symlinks (`O_NOFOLLOW`), rutas
  relativas, `..` y rutas fuera de los volúmenes declarados.
- El texto se decodifica como UTF-8 con reemplazo; el contenido hostil nunca se
  ejecuta, se interpreta como URL ni se renderiza.

## Errores y comportamiento

| Situación | Resultado |
|---|---|
| Fuente ausente, symlink, no regular o mayor de 64 MiB | `LogReaderError`; `collect()` lo cuenta por motor. |
| JSONL inválido, línea demasiado larga o ruta fuera de volumen | `LogReaderError`; la línea se consume, se cuenta y el resto de fuentes sigue. |
| `DataPlane.step()` con una fuente mala | `read_failed += 1`, `errors` en el resumen; los registros sanos se normalizan y se encolan. |
| `LogReader.step()` estricto | Lanza `LogReaderError` (API para quien prefiera parar). |
| Registro sin IP de origen canónica, motor desconocido o violación del contrato | `NormalizeError`/`ValueError`; `failed += 1` y se continúa. |
| Línea vacía o `TOTALS` de Endlessh | Se omite; `skipped += 1`. |
| `event_id` ya existe con contenido distinto | `ValueError` del spool; `failed += 1`, nunca se sobrescribe. |
| Spool lleno (`CapacityError`) | `paused = true`, `failed += 1`; el spool ya persistió su contador de descartes. No se reintenta en el mismo paso. |
| HTTP 403/409/413/422 del ingest | Lote a cuarentena en el spool; `operator_action_required`. |
| Fallo de red/TLS/5xx | Backoff exponencial; el lote permanece en el spool. |
| Respuesta de ingesta inválida | `ConnectionError`; no se borran eventos del spool. |

La cuarentena y el contador de descartes son la fuente de verdad operativa; no
se ocultan errores en `stats()`.

### Rotación

- **rename + recreate**: cambia el inode; el lector empieza desde el principio
  del fichero nuevo.
- **copytruncate**: si el tamaño es menor que el offset, se reinicia desde 0.
  Existe una carrera conocida si el fichero se trunca y vuelve a crecer por
  encima del offset anterior entre dos polls; ver pendientes.
- Un fichero que desaparece se reporta como error; el cursor se conserva y se
  reanuda si vuelve el mismo inode/tamaño.

## Determinismo, redacción e idempotencia

- `event_id` = UUID4 derivado de `sha256(canonical_json(raw))`, motor y
  `device_id`. Releer la misma línea produce el mismo id. El spool deduplica
  por `event_id`; el ingest deduplica por `(sensor, event_id)`.
- `observed_at` usa el timestamp nativo. Si falta o es inválido se usa la hora
  actual: es el único punto no determinista y está documentado.
- Nunca se copian `password`, `pass`, `pwd`, `token` ni `secret` a `detail`.
  Los mensajes nativos se redactan tanto por valor conocido como por patrón
  `password=…`.
- `detail` solo contiene strings acotados; no hay objetos anidados ni semántica
  de ejecución.

## Pruebas

Todas las pruebas son offline y deterministas. No requieren Docker, red ni
Linux. Usan las fixtures, SQLite temporal y `TestClient` (sin socket de
escucha).

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r deploy/requirements-test.lock
.venv/bin/python -m pytest tests/runtime-data-plane -q
.venv/bin/ruff check runtime tests/runtime-data-plane
.venv/bin/pyright runtime/logreader.py runtime/normalize.py runtime/dataplane.py
```

Cobertura actual:

- resolución de las seis fuentes y mapeo por volúmenes;
- lectura inicial y segunda pasada sin reemisión;
- línea parcial, varios polls y línea sin `\n` demasiado larga;
- rotación por truncado y por cambio de inode;
- JSONL inválido, symlink, fichero ausente, fuente duplicada;
- normalización de los seis motores, tipos/protocolos, timestamps, redacción y
  límites de `detail`;
- `event_id` determinista y UUID4 canónico;
- pipeline completo fixtures → spool → ingesta FastAPI → outbox;
- replay idempotente, dispositivos no asignados en cuarentena, deduplicación,
  conflicto de `event_id` y cohorte de fuerza bruta;
- frontera de dependencias: los módulos del sensor no importan `app.*` ni
  secretos.

## Pendientes para la ola Linux

Estos puntos **no** están resueltos y requieren una celda Linux autorizada; no
se han probado ni simulado con servicios reales:

1. **Persistencia de cursores.** Los cursores viven en memoria. Tras reiniciar,
   se relee el fichero desde el principio. El `event_id` determinista y la
   deduplicación del spool/ingest evitan duplicados mientras el evento siga
   retenido, pero un reinicio tras archival podría reingresar eventos. Falta
   persistir `(device, inode, offset)` en disco con escritura atómica.
2. **Rotación real.** Definir y validar `logrotate` por motor, la ventana de la
   carrera de `copytruncate`, la retención y la cuota de disco. El lector
   rechaza ficheros > 64 MiB; la rotación debe garantizar esa cota.
3. **Rutas y permisos reales.** Crear `<host_root>/cells/<N>/<motor>/…` con el
   uid/gid del contenedor, permisos mínimos y sin escritura para el usuario del
   colector más allá de lectura. El repo no crea directorios ni volúmenes.
4. **Supervisión.** No hay daemon, unidad systemd, reinicio automático ni
   métricas Prometheus para este bucle. Falta un servicio de un solo writer,
   con `UMask=0077`, `ProtectSystem`, `NoNewPrivileges`, límites de memoria y
   CPU, y política de reinicio.
5. **Transporte real.** El camino HTTPS autenticado (`runtime.sensor.Transport`)
   no se ha ejercitado contra un ingest real con TLS. Las pruebas usan un
   transporte falso que reenvía a `TestClient`. Falta rotación de token, CA,
   revocación y validación de reloj.
6. **Heralding secundario.** `sessions.jsonl` es la única fuente leída. Los
   `auth.csv`/`sessions.csv` declarados como `secondary_paths` no tienen parser
   CSV; los eventos de autenticación pueden llegar solo al cerrar la sesión.
7. **Diferencias nativo vs fixture.** Las fixtures añaden alias planos. En
   producción Dionaea puede traer solo objetos anidados, Heralding
   `source_ip`, RedisHoneyPot `action`/`addr` y Endlessh solo las líneas
   nativas. El normalizador cubre ambos cuando los campos están presentes, pero
   debe validarse contra capturas reales (ver `deploy/honeypots/adapters.md`).
8. **Enumeración de protocolos.** SMTP/IMAP/POP3/SMB/Redis/PostgreSQL/RDP/VNC
   se colapsan a `tcp` por el contrato v1. Ampliar el enum exige revisión del
   contrato y del ingest.
9. **Endurecimiento del host.** `O_NOFOLLOW` cubre symlinks, pero no hardlinks,
   ACLs, SELinux/AppArmor, inodos especiales ni un atacante con escritura en el
   directorio de logs. Falta validar la frontera de permisos y el montaje
   `nosuid,nodev,noexec` del volumen.
10. **Reloj y orden.** `observed_at` es controlado por el atacante; las
    ventanas del ingest ya usan `received_at`, pero falta verificar NTP y la
    deriva del host.
11. **Capacidad y pausa.** Si el spool se llena a mitad de un lote, los
    registros restantes de ese lote no se reencolan: el cursor ya avanzó. El
    contador de descartes lo hace visible, pero la ola Linux debe decidir entre
    pausar antes de leer, persistir un backlog o perder explícitamente.
12. **Multi-celda.** El lector acepta un `data_root`/`cell` por instancia. No
    hay coordinación entre varias celdas, límites por celda ni asignación
    dinámica de `device_id`.

## Referencias

- `deploy/honeypots/inventory.yaml` — rutas, formatos, dispositivos y volúmenes.
- `deploy/honeypots/adapters.md` — mapeo nativo y diferencias por motor.
- `docs/HONEYPOT-ORCHESTRATION.md` — render de la celda y binds de logs.
- `runtime/contracts.py` — contrato v1 de transporte.
- `runtime/sensor.py` — spool y transporte autenticado.
- `runtime/ingest.py` — recepción, cuotas y deduplicación.
