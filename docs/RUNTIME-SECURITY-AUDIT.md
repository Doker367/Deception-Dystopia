# Auditoría de seguridad e invariantes del plano runtime

**Fecha:** 2026-11-02  
**Revisión:** `263c2b99d42433800650a31aef5cdf8be4fefb09` (`main` al crear la rama; rama `wave/security-audit`)  
**Alcance:** diseño y fronteras de `runtime/honeypots.py`, `runtime/sensor.py`, `runtime/ingest.py`, `runtime/cell_gate.py`, `runtime/isolation/*`, `runtime/backup.py` y `app/services/deception/integrations/*`. Se consultaron como contexto `runtime/contracts.py`, `runtime/storage.py`, `runtime/identity.py`, `runtime/localfiles.py`, pruebas y documentación directamente relacionados.  
**Método:** revisión estática dirigida por fronteras de confianza, más ejecución offline de las suites puras y de reproducciones sintéticas en el host de trabajo.

## Resultado y límites de la evidencia

Se identifican **diez hallazgos confirmados (RT-01 a RT-10)** y **dos riesgos abiertos (RV-01, RV-02)**. Cuatro hallazgos son bloqueadores antes de una activación o antes de clasificar un backup como no secreto: RT-01, RT-02, RT-03 y RT-04. El resto son endurecimiento, disponibilidad o higiene de datos.

Cada afirmación lleva su grado de evidencia:

| Grado | Significado |
|---|---|
| **E1** | Confirmado por inspección estática del camino de código. |
| **E2** | Confirmado además por una prueba offline ejecutada en esta revisión: suites puras o reproducción sintética en directorios temporales, sin red, sin servicios y sin datos reales. |
| **E3** | Pendiente de validación en Linux; no se presenta como verificado. |

No se ejecutaron ataques, honeypots, contenedores, VMs, `nft`, el daemon de Docker, Elasticsearch, TLS real ni servicios reales. El único contacto con Docker fue un test de la suite que invocó el CLI `docker compose` y falló porque el host no tiene el plugin; no se contactó ningún daemon ni se creó ningún contenedor. No se usaron credenciales ni datos reales, no se cambiaron redes o permisos del host y no se desplegó nada. El host de trabajo es macOS (`Darwin 25.6.0 arm64`, Python 3.12.14), por lo que **ninguna conclusión E2 demuestra comportamiento del kernel Linux, de Docker, de systemd, de cgroups ni de un clúster Elasticsearch**. Las pruebas offline usaron fixtures sintéticos, transportes inyectados y bases SQLite temporales.

Esta es una revisión acotada, no una auditoría exhaustiva del repositorio ni una certificación de seguridad.

### Resumen de hallazgos

| ID | Tema | Prioridad | Evidencia |
|---|---|---|---|
| RT-01 | El backup declara `secrets: excluded` pero copia `server.key` y estado de credenciales | Alta | E1 + E2 |
| RT-02 | Un symlink de configuración saca el bind mount del contexto revisado | Alta | E1 + E2 |
| RT-03 | Restore no exige el conjunto completo ni es todo-o-nada | Alta | E1 + E2 |
| RT-04 | La evidencia del gate es rejugable y no tiene frescura ni identidad de host | Alta antes de activar | E1 + E2 (clave de prueba) |
| RT-05 | Los artefactos del backup nacen con permisos de umask y se endurecen después | Media (confidencialidad local) | E1 + E2 |
| RT-06 | La confianza en el directorio padre de bases y archivos privados no se verifica | Media condicionada al despliegue | E1 + E2 (tests de padres) |
| RT-07 | El spool del sensor puede quedar bloqueado por lotes en cuarentena | Media (disponibilidad) | E1 + E2 (suite) |
| RT-08 | Fallos permanentes de Elasticsearch consumen la cola y detienen el exportador | Media (disponibilidad) | E1 + E2 (suite) |
| RT-09 | El hash del registro crudo publicado es un oráculo de verificación de credenciales | Baja | E1 + E2 |
| RT-10 | El render de Compose fija imágenes por tag mutable, no por digest | Media (cadena de suministro) | E1 |
| RV-01 | SHA-256 del backup no autentica contra un escritor malicioso | Decisión de custodia | E1 |
| RV-02 | `no-new-privileges` no es una invariante universal de Compose | Endurecimiento | E1 + E2 (render) |

**Estado de remediación:** la rama integrada `feature/runtime-wave` reúne
`wave/security-fixes` (RT-01 a RT-05), `wave/runtime-hardening` (RT-06 a RT-08)
y `wave/compose-hardening` (RT-09, RT-10 y RV-02), todos a nivel de contrato
offline. RV-01 (autenticidad del backup) sigue abierto.

## 1. Fronteras de confianza y flujo de datos

```text
 Atacante externo
       |
       v
 [Honeypot / guest / container]  Frontera A: workload hostil
       |  logs/eventos falsificables; root del workload posible
       v
 [Adaptador + sensor de su celda]  Frontera A2: código del sensor
       |  validate_event + spool SQLite acotado
       |  token propio leído de archivo privado
       v
 HTTPS, IP literal, CA, sin proxy ni redirects
       |
       v
 [Ingest independiente]          Frontera B: autenticación != contenido confiable
       |  Bearer -> Registry -> sensor + devices asignados
       |  contrato estricto + segunda autorización transaccional
       v
 [events.db] --solo lectura--> [NativeExporter] --> [elastic-queue.db]
                                                         |
                                                         v
                                                HTTPS + API key de writer
                                                         |
                                                         v
                                              [Elasticsearch/Kibana]
                                                Frontera C: analítica

 Operador local root
       |
       +--> [política root-owned] --> [helper cerrado] --> /usr/sbin/nft
       |                            Frontera D: elevación local
       |
       +--> [backup.py] --> estado privado --> almacenamiento offline
       |                            Frontera E: copia con datos/secretos
       |
       +--> [cell_gate.py] <-- manifiesto firmado + artefactos
                                    Frontera F: evidencia de verificador

 Inventario revisado --> [honeypots.py] --> Compose YAML solamente
                                     Frontera G: repo/host -> runtime
```

### Propiedad de cada dominio

| Dominio | Puede hacer | No debe poder / supuesto necesario |
|---|---|---|
| Workload y sensor | Emitir telemetría de dispositivos asignados; conservar un spool acotado | No tiene autoridad administrativa ni acceso a otros sensores. Su identidad autenticada no vuelve verdadero el evento. |
| Ingest | Autenticar sensores, comprobar asignaciones y persistir eventos | No arranca workloads ni aplica firewall. Registry, CA, almacenamiento y servicio son críticos. |
| Exporter / integraciones | Leer eventos, enriquecerlos y escribir documentos en analítica | Debe usar una identidad Elastic limitada. La topología es confiable; el contenido capturado no. |
| Elasticsearch/Kibana | Conservar y mostrar telemetría | `dynamic=false` evita indexar campos desconocidos, pero no elimina datos de `_source`. |
| Helper de aislamiento | Ejecutar una transacción `nft` cerrada como root local | No acepta argv, URI ni política arbitraria del llamador. Aceptar la transacción no prueba aislamiento. |
| Backup/restore | Copiar artefactos declarados y restaurar en rutas derivadas de código | El almacenamiento de backup es una frontera de confianza propia, no un archivo inerte. |
| Directorios de estado | Guardar bases, tokens, colas y TLS | Deben ser propiedad del servicio/root y no escribibles por otros. Desde RT-06 el código lo verifica (padre inmediato estricto y cadena de ancestros en restore); la prueba E3 debe confirmar los UID/GID reales. |
| Verificador/gate | Validar un paquete de evidencia y su firma | En este commit el trust store está vacío. No observa el host ni activa nada. |

### Datos sensibles que realmente cruzan fronteras

- `sensor.py` lee el token en cada envío y lo coloca solo en `Authorization`; usa HTTPS con IP literal, CA, TLS >= 1.2, sin proxy y sin redirects (`runtime/sensor.py:24-53`).
- `events.db` contiene el evento completo, incluidos `detail` y posibles secretos capturados. El exporter no envía ese JSON directamente: lo normaliza antes de publicar (`app/services/deception/integrations/exporter_svc.py:246-269`).
- En la rama normal, `ecs.build_event` representa la contraseña como `CredentialReference`, cuya serialización JSON contiene solo el identificador (`ecs.py:368-431`, `632-637`). El comando/URL/mensaje se conserva en `dystopia_restricted`, no desaparece.
- **Derivado sensible (corregido en §9):** antes de esta rama, el documento publicado incluía `dystopia.raw_reference` con `sha256=<hash del registro crudo>`. Ese registro contiene la contraseña capturada; el hash era un oráculo de confirmación, no un redactor (RT-09). Ahora la referencia es `hmac-sha256=<digest>` con clave provisionada fuera del documento.
- El template tiene `dynamic=false` de nivel raíz, por lo que un campo restringido queda almacenado en `_source` pero no indexado (`config/elasticsearch/templates/deception-events-template.json:2,22-24`). **No indexado no significa redactado, cifrado ni ausente de backups/snapshots.**
- El backup incluye eventos, colas, registro de sensores y la clave TLS; por tanto debe tratarse como material sensible aunque los archivos `.env` se filtren.
- La cola persistente de Elasticsearch y el spool del sensor contienen payloads capturados; ambos son bases SQLite privadas, pero su contenido sigue siendo hostil y sensible.

## 2. Hallazgos confirmados

### RT-01 — El backup declara `secrets: excluded`, pero incluye la clave privada TLS y estado de credenciales

**Prioridad:** alta de corrección; impacto de confidencialidad **medio** con almacenamiento root-only, y mayor si el backup se exporta a un dominio menos confiable.  
**Estado:** confirmado estáticamente y reproducido offline (E1 + E2).

**Evidencia**

- La promesa global dice que secretos, tokens y claves quedan fuera de “every backup file” (`runtime/backup.py:18-21`).
- La tabla obligatoria copia `sensors.db` y `server.key` (`runtime/backup.py:139-146`). El restore vuelve a materializar ambos (`runtime/backup.py:490-511`).
- El manifiesto siempre publica `"secrets": "excluded"` (`runtime/backup.py:408-412`).
- El registry guarda los digest SHA-256 de los tokens y las asignaciones de sensores en `sensors.db` (`runtime/identity.py:18-20,44-50`). No son el token en claro, pero siguen siendo estado de autenticación sensible. `server.key` es directamente la clave privada del receptor.
- La prueba denominada `test_no_secret_lands_in_any_backup_file` solo concatena el manifiesto y los dos snapshots `env`; no examina `server.key`, las bases ni los demás artefactos (`tests/hardening/test_backup.py:133-155`).

**Reproducción offline (E2)**

Con un estado sintético que contiene un marcador de clave privada, `create_backup` produjo:

- `artifacts/ingest/server.key` contiene el marcador sintético de clave privada;
- `artifacts/ingest/server.crt` contiene el marcador sintético de certificado;
- el manifiesto sigue declarando `policy.secrets == "excluded"`.

El escaneo se hizo sobre **todos** los archivos del backup, no solo sobre los `.env`. No se usó ninguna clave real.

**Frontera y resultado**

Un operador puede clasificar el backup como libre de secretos y entregarlo a almacenamiento o personal con menos privilegios. Un lector de esa copia obtiene la clave TLS y estado de autenticación que la política decía excluir. Los modos `0600/0700` reducen exposición local, pero no cambian la clasificación ni protegen una copia posterior mal custodiada.

**Corrección mínima**

Elegir y hacer explícito un solo contrato:

1. Preferible para una copia “sin secretos”: excluir `server.key`, regenerarlo/rotarlo en restore y separar el registro de credenciales en un backup secreto; o
2. Si la continuidad exige conservarlos: declarar el backup completo como **secret-bearing**, cifrarlo con una identidad de recuperación independiente, exigir almacenamiento equivalente a root y cambiar manifiesto, CLI y runbooks.

Ampliar la prueba para recorrer **todos** los archivos y validar tanto valores plantados como la clasificación de artefactos. No basta con probar la allowlist de `.env`.

### RT-02 — Un symlink de configuración puede sacar el bind mount del contexto revisado

**Prioridad:** media; bloquear antes de habilitar Compose.  
**Estado:** confirmado en el documento renderizado y reproducido offline; el módulo actual no monta ni arranca nada (E1 + E2).

**Evidencia**

- El directorio de build se resuelve y se exige dentro del repositorio (`runtime/honeypots.py:527-533`).
- Para Dockerfile/config solo se comprueba `candidate.is_file()` (`runtime/honeypots.py:534-536`). Esa comprobación sigue symlinks y no exige que el archivo resuelto permanezca en el contexto/repositorio ni que el leaf sea regular sin symlink.
- Al renderizar la configuración se vuelve a llamar a `.resolve()` y el resultado se usa como `source` del bind (`runtime/honeypots.py:568-571`).
- `assert_safe` exige rutas absolutas y rechaza algunos prefijos, pero permite otras rutas de host, por ejemplo una ruta bajo `/etc`, y no exige que la fuente de configuración esté en el contexto (`runtime/honeypots.py:686-698`).
- La prueba actual codifica precisamente el `.resolve()` como resultado esperado y no incluye un symlink de escape (`tests/hardening/test_honeypots.py:84-93`).

**Reproducción offline (E2)**

Con un inventario sintético cuyo `config.file` es un symlink a un archivo fuera del contexto:

- `render_cell` produjo un bind `source` apuntando al archivo externo;
- `assert_safe` devolvió `True` para ese documento;
- el archivo de destino no estaba dentro del contexto de build resuelto.

**Frontera y resultado**

Quien pueda alterar el checkout/inventario puede colocar una configuración que apunte a un archivo legible fuera del árbol revisado. Si un operador posteriormente aplica ese Compose, el runtime montará ese archivo del host en el workload. Esto rompe la invariante “configuración revisada del contexto” y puede divulgar un archivo del host al honeypot. No hay explotación directa desde este módulo mientras `apply/up/down` permanezcan bloqueados.

**Corrección mínima**

Abrir/verificar el leaf sin seguir enlaces, exigir archivo regular y comprobar que el archivo resuelto es hijo del contexto resuelto. Repetir la misma invariante en `assert_safe` para que una deriva del renderer falle cerrada. Añadir fixtures con symlink absoluto, relativo y cadena de symlinks, todos dentro de scratch.

### RT-03 — Restore no exige un conjunto completo de artefactos ni es todo-o-nada

**Prioridad:** media.  
**Estado:** confirmado estáticamente y reproducido offline; son dos brechas de la misma invariante de recuperación (E1 + E2).

**Evidencia: artefactos requeridos ausentes**

- `_load_verified_manifest` comprueba que cada entrada conocida coincida con la tabla y que los presentes tengan hash/tamaño correctos (`runtime/backup.py:442-471`).
- No compara el conjunto con todos los `ArtifactSpec.required`, no exige `artifact_count` y no rechaza `status="missing"` en una entrada cuyo `spec.required` sea `True`. Tampoco exige claves exactas: admite entradas con campos adicionales (`runtime/backup.py:448-450`).
- Cualquier `status` distinto de `"present"` se trata como omitido en el restore (`runtime/backup.py:491-493`), no solo `"missing"`.
- Por tanto, un manifiesto incompleto pero internamente consistente puede pasar la verificación y restaurar solo un subconjunto.

**Evidencia: escritura parcial**

- La verificación del backup termina antes de escribir, pero no existe un preflight de **todos** los destinos (`runtime/backup.py:475-489`).
- El bucle crea/copia cada destino y solo entonces descubre si un destino posterior existe (`runtime/backup.py:490-511`). Un fallo tardío deja copiados los anteriores; no hay rollback ni staging.
- Esto contradice la expectativa documental de que si falta un artefacto requerido se aborta y de que “no toca nada si algo no encaja” (`docs/BACKUP-RESTORE.md:181-184,253-255`).

**Reproducción offline (E2)**

- **Conjunto incompleto:** se eliminó la entrada de `sensors.db` del manifiesto, se recalculó `artifacts_sha256` y el restore terminó correctamente **sin** `sensors.db`; no hubo error por required ausente.
- **Escritura parcial:** se puso una colisión en el último destino (`install.json`); el restore había escrito ya `control/config/users.yaml`, `events.db`, `sensors.db`, `server.crt` y `server.key` antes de lanzar `FileExistsError`.

**Frontera y resultado**

Una copia truncada o un destino parcialmente ocupado puede producir una mezcla de eventos, usuarios, registry y TLS de procedencias distintas. Además de disponibilidad, es una invariante de integridad de identidades y claves: un operador puede creer que recuperó un conjunto consistente cuando solo se escribió una parte.

**Corrección mínima**

Antes de cualquier escritura: exigir el conjunto exacto esperado, presencia de todos los requeridos, esquema exacto por entrada y preflight de todos los padres/destinos. Copiar a un árbol staging privado y publicar el conjunto mediante un procedimiento de recuperación explícito; si no se puede hacer atómico entre filesystems, informar el punto de compromiso y no afirmar todo-o-nada. Añadir pruebas de required omitido/missing y de colisión en el último destino verificando que ningún archivo quedó escrito.

### RT-04 — La evidencia del gate es rejugable entre hosts y no tiene frescura

**Prioridad:** **alta antes de cualquier activación futura**.  
**Estado:** limitación de diseño confirmada y reproducida offline con una clave de prueba; no explotable para activar este commit porque no hay claves fijadas ni camino de activación (E1 + E2).

**Evidencia**

- El contexto esperado contiene solo `cell` y `apply_succeeded` (`runtime/cell_gate.py:47-53`); no contiene identidad esperada del host, emisión, caducidad ni challenge.
- La plataforma validada es distribución, versión, kernel y formato de `boot_id` (`runtime/cell_gate.py:184-194`). No se compara con el host consumidor ni con una identidad única aprovisionada.
- `host_identity` es uno de los artefactos hasheados, pero el gate no interpreta su contenido (`runtime/cell_gate.py:202-233`).
- La decisión final depende de ausencia de blockers y firma válida (`runtime/cell_gate.py:235-295`). El esquema no incluye timestamp, expiry, host ID ni nonce (`runtime/cell_gate.py:163-169`).
- La documentación ya reconoce que no comprueba vigencia en el host (`docs/CELL-ACTIVATION-GATE.md:49-55`).

**Reproducción offline (E2)**

Se generó una clave Ed25519 efímera, se fijó su clave pública en `TRUSTED_VERIFIER_KEYS` **solo dentro del proceso de prueba**, se firmó un bundle sintético con los ocho artefactos y `boot_id` sintético, y se evaluó:

- el bundle fue aceptado (`activation_allowed == True`);
- el mismo bundle fue aceptado de nuevo sin ningún cambio (`replay`);
- `CellGateContext` solo expone `cell` y `apply_succeeded`: no hay entrada que pueda contradecir el `boot_id` del bundle ni representar “otro host”.

No se fijó ninguna clave de producción ni se modificó el repositorio.

**Frontera y resultado**

Una vez fijada una clave, cualquier persona que obtenga un bundle válido puede presentarlo de nuevo para la misma celda/política, en otro arranque o en otro host compatible. No necesita la clave privada para reutilizarlo. La firma prueba origen e integridad del paquete, no que la contención se haya observado **aquí y ahora**.

**Corrección mínima antes de fijar claves**

Añadir al manifiesto una identidad única del host aprovisionado, `issued_at`/`expires_at` o un challenge reciente, y vincularlos al contexto esperado. El verificador independiente debe firmar observaciones semánticas de ese host; el activador debe rechazar bundles fuera de ventana o de otro boot según el modelo elegido. Mantener separada la decisión operativa y no usar el gate actual como única autorización.

### RT-05 — Los artefactos del backup nacen con permisos de umask y se endurecen después de escribirlos

**Prioridad:** media (confidencialidad local; agrava RT-01).  
**Estado:** confirmado estáticamente y reproducido offline (E1 + E2).

**Evidencia**

- `_copy_regular` crea el destino con `destination.open("xb")` (`runtime/backup.py:301`), que aplica el modo por defecto del proceso (`0666 & ~umask`); el `chmod(0o600)` llega después de copiar (`runtime/backup.py:392`).
- `_write_env_snapshot` usa `destination.write_text(...)` (`runtime/backup.py:343`) y `_copy_sqlite` deja que SQLite cree el archivo (`runtime/backup.py:319`); ambos siguen el mismo patrón.
- `create_backup` solo endurece el directorio de salida al final (`runtime/backup.py:417-421`). Si el directorio ya existía vacío con modo `0755`, permanece así durante toda la exportación.
- Reproducción con `umask 022`: en el instante del `chmod`, `artifacts/ingest/server.key` tenía modo `0644`; al final quedó `0600`. El archivo contenía el marcador sintético de clave privada.

**Frontera y resultado**

Un usuario local con acceso de lectura al árbol de backup puede leer un artefacto secreto durante la ventana de escritura, especialmente en bases de hasta 8 GiB (`MAX_DB_BYTES`). El modo final correcto no protege lo que ya fue legible. En un backup que solo contiene configuración no secreta el impacto es bajo; combinado con RT-01, la ventana afecta a `server.key` y `sensors.db`.

**Corrección mínima**

Crear cada archivo con `os.open(..., O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)` (o fijar `umask 077` durante toda la exportación) y endurecer el directorio de salida a `0700` **antes** de la primera escritura. Añadir una prueba con `umask 022` y un directorio preexistente `0755` que compruebe que ningún archivo intermedio es legible por grupo/otros.

### RT-06 — La confianza en el directorio padre de bases y archivos privados es un supuesto no verificado

**Prioridad:** media, condicionada a que el despliegue no garantice los permisos del padre.  
**Estado:** confirmado estáticamente (E1); **remediado en contrato offline** en
`wave/runtime-hardening` (E2). La verificación de UID/GID reales del despliegue
sigue siendo E3.

**Evidencia**

- `runtime.storage.database` documenta “Parent must be provisioned, owned by the service and inaccessible to decoys” (`runtime/storage.py:26-27`), pero solo hace `fstat` del archivo: regular, single-link y modo privado (`runtime/storage.py:29-40`). No comprueba propietario/modo del directorio padre.
- En el camino privado (`read_group_gid is None`) tampoco compara `st_uid` con el effective UID; ese chequeo solo existe para la variante de lectura por grupo (`runtime/storage.py:35-38`).
- `runtime.localfiles._publish` abre el padre con `O_DIRECTORY | O_NOFOLLOW` (`runtime/localfiles.py:31`), pero no verifica su propietario ni que no sea escribible por grupo/otros. `read_private` valida solo el leaf (`runtime/localfiles.py:12-26`).
- `identity.Registry` y `EventStore` usan `database()` para `sensors.db` y `events.db` (`runtime/identity.py:14-21`, `runtime/storage.py:84-85`).

**Frontera y resultado**

Si el directorio padre es escribible por un usuario no confiable (despliegue incorrecto, directorio compartido sin sticky bit, restauración con permisos laxos), ese usuario puede desenlazar la base y crear otra con el mismo nombre y modo `0600`. `database()` la aceptará como regular, single-link y privada. En el registry esto permite controlar credenciales y asignaciones de sensores; en el event store permite inyectar o falsificar telemetría. El despliegue previsto (`/var/lib/dystopia/...` propiedad del servicio, `0700`) evita el ataque, pero hoy es una **asunción**, no una invariante comprobada.

El restore de backup tiene una variante del mismo supuesto: comprueba `target.parent.is_symlink()` y que sea directorio (`runtime/backup.py:499-504`), pero no recorre la cadena completa de ancestros ni valida propietario/modo. Un `--state-root` que sea symlink o un ancestro sustituido redirige la escritura.

**Corrección mínima**

Recorrer los ancestros con descriptores retenidos y `O_NOFOLLOW`, exigiendo propietario root/servicio y ausencia de escritura por grupo/otros (se puede reutilizar el patrón de `runtime/isolation/backend.py:51-74`). Alternativamente, `fstat` del padre y comparación explícita de UID/GID/modo antes de abrir la base. Añadir una prueba con un padre sintético `0777` y una base sustituida que deba fallar cerrada.

**Remediación offline (wave/runtime-hardening)**

- `runtime.localfiles.open_trusted_directory` abre el padre con `O_DIRECTORY |
  O_NOFOLLOW`, rechaza symlinks, exige propietario root/UID del servicio y
  prohíbe escritura por grupo/otros. `open_private_parent` lo aplica a
  `database()`, `read_private`, `create_private` y `replace_private`;
  `verify_ancestor_chain` añade la cadena de ancestros (con admisión acotada de
  raíces sticky como `/tmp`) y se invoca en el preflight de restore.
- `database()` verifica además que el propietario del leaf privado sea root o
  el UID efectivo, no solo en la variante de lectura por grupo.
- Pruebas: padre `0777/0770/0772`, padre symlink, padre de ficheros privados
  inseguro, UID esperado distinto y `--state-root` writable/symlink en restore.

### RT-07 — El spool del sensor puede quedar permanentemente bloqueado por lotes en cuarentena

**Prioridad:** media (disponibilidad; no confidencialidad).  
**Estado:** confirmado estáticamente y por las suites offline existentes (E1 + E2);
**remediado en contrato offline** en `wave/runtime-hardening` (E2).

**Evidencia**

- Ante `403/409/413/422`, `flush_once` marca los eventos como `quarantined=1` en lugar de borrarlos (`runtime/sensor.py:118-126`), deliberadamente para no perder evidencia.
- `submit` cuenta **todas** las filas, incluidas las cuarentenadas, para el límite `max_events` y para `max_bytes // 2` (`runtime/sensor.py:84-86`). Al alcanzar el límite rechaza todo evento nuevo con `CapacityError`.
- `health` incluye las cuarentenadas en `queued` y en `storage_exhausted` (`runtime/sensor.py:140-151`). No existe comando de drenaje o purga en este módulo.
- Las pruebas confirman que la cuarentena se conserva y no se borra silenciosamente (`tests/hardening/test_telemetry.py:139-160`).

**Frontera y resultado**

Un cambio de asignación de dispositivo, una rotación de credenciales o una revocación pueden hacer que lotes legítimos reciban 403 y se cuarentenen. Si el volumen de eventos es suficiente para llenar el spool, el sensor deja de aceptar eventos nuevos y la telemetría se detiene hasta que un operador intervenga manualmente en SQLite. La retención es una decisión de visibilidad razonable, pero falta un contrato de recuperación y un presupuesto separado.

**Corrección mínima**

Separar un presupuesto acotado para cuarentena (o un archivo de dead-letter) del presupuesto de eventos pendientes; exponer un comando de operador para drenar/exportar y borrar cuarentena; alertar con `operator_action_required`. Añadir una prueba que llene la cuarentena y verifique que los eventos válidos posteriores siguen teniendo un camino acotado, o que el sensor se detiene de forma explícita y documentada.

**Remediación offline (wave/runtime-hardening)**

- `Spool` cuenta para el presupuesto vivo solo `quarantined=0`. La cuarentena
  tiene su propio límite (`max_quarantine_events`/`max_quarantine_bytes`,
  por defecto 20 %/12,5 % del spool) y, al desbordarse, aplica dead-letter
  explícito del lote más antiguo con contador persistido `dead_lettered`.
- `health` separa `pending` (vivo) de `quarantined`, expone capacidades y
  mantiene `operator_action_required` cuando hay cuarentena.
- Operador: `sensor-quarantine --output` (export no destructivo), `--drain`
  (export durable y borrado de lo exportado) y `--purge`; también métodos
  `export_quarantine`, `drain_quarantine` y `purge_quarantine`.
- Pruebas de presión: cuarentena llena con el presupuesto vivo libre, nuevos
  eventos aceptados y entregados, dead-letter del más antiguo y migración de
  un spool con el esquema previo.

### RT-08 — Fallos permanentes de Elasticsearch consumen la cola acotada y detienen el exportador

**Prioridad:** media (disponibilidad analítica).  
**Estado:** confirmado estáticamente y por las suites offline existentes (E1 + E2);
**remediado en contrato offline** en `wave/runtime-hardening` (E2).

**Evidencia**

- `_deliver` marca como permanentes `400/401/403/404/405/413/422` (`app/services/deception/integrations/elastic_svc.py:50,489-494`) y `_mark_failure` conserva la fila con `permanent=1` (`elastic_svc.py:510-517`).
- `enqueue` cuenta todas las filas, incluidas las permanentes, contra `max_events` y `max_bytes` (`elastic_svc.py:316-325`). Al llenarse lanza `CapacityError`.
- El exporter detiene el avance del cursor ante `CapacityError` (`exporter_svc.py:288-295`); los eventos siguen en `events.db`, pero la analítica se queda atrás y requiere intervención.
- Las pruebas confirman que una fila permanente no se reintenta y permanece en la cola (`tests/deception/test_elasticsearch_publisher.py:130-144`).

**Frontera y resultado**

Tras suficientes rechazos permanentes, la cola se llena y el exportador deja de enqueuear; no hay pérdida en el event store, pero el lag crece sin cota y el operador debe drenar la cola a mano. Un `401/403` por rotación de API key es potencialmente transitorio, pero el código lo trata como permanente y no lo reintenta tras refrescar la credencial. Esto es fail-closed, no una fuga, pero es un riesgo operativo real.

**Corrección mínima**

Separar un área de dead-letter/permanentes que no consuma el presupuesto de eventos vivos; reintentar `401/403` tras una recarga controlada de credenciales; añadir un comando de drenaje/exportación y una alerta cuando `permanent > 0`. Añadir una prueba de cola llena por permanentes que demuestre que los eventos nuevos siguen fluyendo o que el sistema se detiene con una acción de operador explícita.

**Remediación offline (wave/runtime-hardening)**

- `enqueue` cuenta para el presupuesto vivo solo `permanent=0`: una cola llena
  de rechazos permanentes ya no detiene el exportador.
- Los permanentes tienen un presupuesto acotado propio
  (`dead_letter_events`/`dead_letter_bytes`); al desbordarse se descarta el más
  antiguo y se incrementa `dead_letter_evicted` con alerta explícita.
- `401/403` se clasifican como autenticación, no como defecto permanente:
  `_HttpTransport.reload_api_key()` relee el fichero privado y solo permite un
  reintento si el valor cambió. Una clave sin cambios marca `auth_blocked`,
  mantiene la fila reintentable y pausa el flush para no repetir el mismo
  error sobre cada fila.
- Operador: `export_dead_letter` y `purge_dead_letter`; `health` expone
  `live`, `permanent`, `auth_blocked`, `dead_letter_evicted_since_start` y
  `operator_action_required`.
- Pruebas: permanentes que no consumen el presupuesto vivo, dead-letter
  acotado, 401 que no se vuelve permanente, reintento tras rotación real del
  fichero de API key y exportador que sigue avanzando con la cola llena de
  permanentes.

### RT-09 — El hash del registro crudo publicado es un oráculo de verificación de credenciales

**Prioridad:** baja.  
**Estado:** confirmado estáticamente y reproducido offline (E1 + E2). **Cerrado en contrato offline en §9.**

**Evidencia (estado previo a §9)**

- `ecs.fingerprint(raw)` calculaba SHA-256 sobre el JSON canónico del registro **completo**, incluidas las claves de credenciales (`app/services/deception/integrations/ecs.py:277-286`).
- `build_event` publica ese digest en `dystopia.raw_reference` como `sha256=<hash>` (`ecs.py:596-599`) y, en adaptadores legacy, también alimenta `stable_event_id` (`ecs.py:555-568`).
- Todos los normalizadores pasan el registro crudo completo: `cowrie_svc.py:146`, `opencanary_svc.py:146`, `dionaea_svc.py:122`, `heralding_svc.py:87`, `redishoneypot_svc.py:95`, `native_svc.py:119`.
- `_payload` excluye `password` del contenedor restringido y `CredentialReference` lo excluye del JSON, pero el hash derivado permanece.

**Reproducción offline (E2)**

Con un evento sintético que contiene `detail.password`:

- la contraseña **no** aparece en el JSON publicado;
- `fingerprint(raw)` **sí** aparece en `dystopia.raw_reference`.

**Frontera y resultado**

Quien tenga acceso a `_source`, snapshots o backups puede confirmar offline una conjetura de contraseña calculando el mismo hash del registro candidato; para credenciales de baja entropía esto es un ataque de diccionario viable. El hash también correlaciona registros idénticos. No es reversible, pero contradice la intención de que solo se publique un identificador no secreto.

**Corrección mínima**

Calcular el fingerprint sobre una copia redactada (excluir `password`, `pass`, `pwd` y campos equivalentes) o usar un HMAC con clave fuera de Elasticsearch. Añadir una prueba que verifique que dos registros que solo difieren en la contraseña no comparten el hash publicado, o que el hash es keyed y no verificable sin la clave.

### RT-10 — El render de Compose fija la imagen por tag mutable, no por digest

**Prioridad:** media (integridad de cadena de suministro; requiere control del host/Docker para materializarse).  
**Estado:** confirmado estáticamente (E1). **Cerrado en contrato offline en §9; verificación Docker pendiente E3.**

**Evidencia**

- `Engine.base_digest` se valida como SHA-256 real (`runtime/honeypots.py:262-264`), pero el servicio renderizado usa `engine.image`, que es un tag (`runtime/honeypots.py:552`).
- `_IMAGE` exige un tag y no admite `@sha256` (`runtime/honeypots.py:34-37`); `assert_safe` solo rechaza `latest`, `stable`, `main` y `edge` (`runtime/honeypots.py:676-680`).
- No se comprueba que el ID de la imagen local coincida con `base_digest` ni con un digest de la imagen construida.

**Frontera y resultado**

Entre la revisión y el apply, un tag local puede ser recompilado o reemplazado por otra imagen con el mismo nombre; el Compose resultante no lo detecta. El atacante necesita capacidad de escritura sobre el daemon/almacén de imágenes, por lo que no es una escalada remota, pero rompe la reproducibilidad y la revisión de artefactos que el propio inventario declara.

**Corrección mínima**

Renderizar `image: <repo>@sha256:<digest>` o verificar el ID local contra un digest revisado antes de cualquier apply; el camino de activación debe rechazar tags mutables. Añadir una prueba que falle con un tag sin digest y acepte el digest revisado.

## 3. Riesgos que requieren validación / supuestos que deben hacerse explícitos

### RV-01 — SHA-256 del backup no autentica contra un escritor malicioso

**Estado:** necesita validación del modelo de custodia; no se asigna severidad.

El sellado es SHA-256 sin clave (`runtime/backup.py:396-407,445-471`). Quien pueda modificar el backup puede modificar también los hashes del manifiesto. Además, verificación y `shutil.copy2` vuelven a abrir rutas en operaciones separadas (`runtime/backup.py:462-469,509`), por lo que no hay una lectura retenida a prueba de sustitución concurrente.

La reproducción de RT-03 lo confirma de forma directa: se eliminó una entrada requerida del manifiesto y se recalculó `artifacts_sha256`; el restore aceptó el resultado. El sello detecta corrupción accidental, no manipulación deliberada.

Si el almacenamiento es root-only, íntegro y tan confiable como el host de restore, esto puede ser una comprobación de corrupción accidental suficiente. Si un operador de backup, soporte extraíble o sistema remoto tiene menos confianza, puede alterar usuarios/registry/datos que luego se restauran. Hay que decidir y documentar esa frontera. Para un dominio menos confiable se requiere firma/MAC con clave fuera del backup y lectura mediante descriptores retenidos; los hashes solos no aportan autenticidad.

### RV-02 — `no-new-privileges` no es una invariante universal de Compose

**Estado:** riesgo de endurecimiento confirmado en el render; impacto real depende de las imágenes y requiere Linux. **Cerrado en contrato offline en §9; privilegios efectivos pendientes E3.**

Con `NET_BIND_SERVICE`, `_service` elimina `security_opt` deliberadamente (`runtime/honeypots.py:603-606`). `assert_safe` exige `cap_drop` y limita `cap_add`, pero **nunca exige ni valida `security_opt`** (`runtime/honeypots.py:636-711`). La prueba acepta explícitamente una u otra alternativa (`tests/hardening/test_honeypots.py:69-71`). El camino de contenedores, en cambio, exige `no_new_privileges=True` (`runtime/isolation/containers.py:115`), lo que evidencia la inconsistencia entre ambos modelos.

Esto no demuestra escape del contenedor. Sí deja una posible vía de elevación **dentro** del workload mediante binarios setuid/file-capabilities presentes en una imagen. Antes de activación hay que inventariar esos binarios, usar una estrategia de capabilities compatible con NNP (por ejemplo bind de proxy no privilegiado o ambiente adecuadamente diseñado) y verificar los privilegios efectivos. La invariante del validador debe reflejar la excepción de forma estrecha, no omitir NNP globalmente, y `assert_safe` debe rechazar un servicio sin `security_opt` salvo excepción documentada.

## 4. Controles observados, parsing, logs y cuotas

### Comandos y elevación

- El único `subprocess.run` del helper privilegiado usa `/usr/sbin/nft`, argv fijo, stdin renderizado, entorno mínimo, `cwd=/`, timeout, sin shell y sin rutas controladas por la política (`runtime/isolation/backend.py:111-131`). Antes exige Linux root/Ubuntu y archivos root-owned no escribibles por otros (`backend.py:36-74,86-108`).
- `honeypots.py` solo valida/renderiza; `apply/up/down` lanzan siempre `HoneypotBlocked` (`runtime/honeypots.py:750-772`). El `CMD-SHELL` del healthcheck no recibe texto libre: el marker está limitado a `[A-Za-z0-9_.-]` (`honeypots.py:43,199-211,584-590`). No es ejecución realizada por el módulo. Detalle menor: el patrón permite un marker que empiece por `-`, que `grep` interpretaría como opción; no hay inyección de shell, pero conviene anclar el primer carácter a alfanumérico.
- `backup.py` no invoca shell, Docker ni red. Las rutas de restore se derivan de una tabla fija y se rechaza sobrescribir destinos (`runtime/backup.py:475-511`), con las brechas RT-01/RT-03/RT-05 ya señaladas.
- El gate comienza con `TRUSTED_VERIFIER_KEYS = {}` y siempre añade un blocker mientras permanezca vacío (`runtime/cell_gate.py:30-33,278-295`). `LocalCellBackend.activate()` también bloquea incondicionalmente (`runtime/isolation/backend.py:201-209`).
- Ingest exige HTTPS directo, limita concurrencia/cuerpo/tiempo, autentica antes de parsear el evento y repite autorización dentro de la transacción de persistencia (`runtime/ingest.py:23-32,34-88`). No confía en forwarding headers para afirmar TLS.
- El publicador está deshabilitado por defecto, exige IP literal y TLS fuera de loopback, no sigue redirects ni usa proxies y lee la API key con `read_private` (`app/services/deception/integrations/elastic_svc.py:127-170,173-227`).
- `sensor.py`, `ingest.py`, `backup.py`, `cell_gate.py` y el exporter no importan `subprocess`, `os.system`, `eval`, `exec`, `pickle` ni `marshal`. La única ejecución de proceso del alcance es el `nft` fijo del helper.

### Deserialización y parsing

| Superficie | Control observado | Límite |
|---|---|---|
| Inventario/perfil YAML | `yaml.SafeLoader` con aliases rechazados, claves duplicadas rechazadas y límites de 256/64 KiB (`runtime/honeypots.py:105-139`). | El contenido sigue siendo configuración revisada; no es una frontera contra un checkout comprometido (RT-02). |
| Contrato v1 de ingesta | JSON con `object_pairs_hook` que rechaza claves duplicadas, `parse_constant` que rechaza no finitos, límites de 256 KiB/64 eventos/8 KiB por evento (`runtime/contracts.py:34-106`). | Un evento válido sigue siendo contenido hostil; no se ejecuta ni se interpreta como plantilla. |
| Gate y política de aislamiento | JSON con claves duplicadas rechazadas, lecturas `O_NOFOLLOW`, tamaño máximo y doble `fstat` (`runtime/cell_gate.py:105-128`, `runtime/isolation/backend.py:86-108`). | La firma no se verifica si no hay clave fijada; el bundle no es confiable por sí mismo (RT-04). |
| Manifiesto de backup | `json.loads` simple, sin `object_pairs_hook`; no rechaza claves duplicadas (`runtime/backup.py:437`). | El manifiesto no está autenticado (RV-01), por lo que la ambigüedad no añade una escalada, pero rompe la consistencia de parsing del resto del runtime. Endurecerlo es barato. |
| Documentos en cola | `json.loads` sobre una base privada; un documento corrupto se marca permanente y no se publica (`elastic_svc.py:430-440`). | La base es local; si se corrompe, la cola se llena (RT-08). |

No se encontró `pickle`, `marshal`, `eval`, `exec` ni carga YAML insegura en el alcance. El único `yaml.load` usa el loader endurecido.

### Logs y datos derivados

- `sensor.py` registra contadores y estados (`discarded`, `retries`, `quarantined`), no payloads.
- `ingest.py` devuelve mensajes genéricos (`invalid sensor credential`, `invalid v1 event batch`, etc.) y no registra el cuerpo.
- `exporter_svc.py` registra `sensor` y `event_id` (asignados por el servidor), no `detail`, comandos ni contraseñas (`exporter_svc.py:262-306`).
- `elastic_svc.py` registra `event_id`, estado HTTP y contadores; no registra el documento (`elastic_svc.py:322-530`).
- `telemetry_svc` (camino legacy, fuera del pipeline nuevo) envía a Loki solo `event_type`, nunca credenciales/comandos (`app/services/deception/telemetry_svc.py:79,108`), pero **persiste `detail` en `store_svc`**; los parsers legacy `cowrie_svc.parse`/`opencanary_svc.parse` siguen incluyendo `password`/`msg` en `detail` (`cowrie_svc.py:52-68`, `opencanary_svc.py:49-68`). No se encontraron llamadas de producción a esos parsers; el tailer está bloqueado (`tailer_svc.py`). No deben reconectarse al pipeline restringido ni a un logger.
- RT-09 (corregido en §9): la referencia publicada ya no es un hash verificable del registro crudo; es un HMAC con clave fuera del documento.
- Los errores de backup/gate pueden incluir rutas locales del host; son visibles para el operador, no para el workload, pero conviene no exponerlas en respuestas de API.

### Cuotas y agotamiento

| Componente | Límite observado | Riesgo residual |
|---|---|---|
| Ingesta | 8 concurrentes, 5 s de cuerpo, 256 KiB, 64 eventos, 120 req/min por sensor, presupuesto de 1024 identidades (`runtime/ingest.py:20-55`). | El límite por sensor es por identidad autenticada; un sensor comprometido solo agota su propio presupuesto. |
| Spool del sensor | 10 000 eventos / 64 MiB, payload limitado a la mitad del presupuesto (`runtime/sensor.py`). | Presupuesto vivo separado de la cuarentena acotada y del dead-letter (RT-07). |
| Event store | 100 000 eventos, 10 000 por sensor, 256 MiB, chequeo de disco libre 2x (`runtime/storage.py:61-107`). | Sin borrado automático; el operador debe archivar. |
| Cola Elastic | 10 000 eventos / 64 MiB (`elastic_svc.py`), dead-letter 2 000 / 8 MiB por defecto. | Los permanentes no consumen el presupuesto vivo; el dead-letter está acotado (RT-08). |
| Backup | 64 MiB por archivo, 8 GiB por base (`runtime/backup.py:45-46`). | El backup completo puede ser grande; no hay cuota del directorio de salida. |
| Gate | 64 KiB manifiesto, 16 MiB por artefacto (`runtime/cell_gate.py:24-25`). | Correcto para evidencia; la frescura no está cubierta (RT-04). |
| Honeypots | Memoria, CPU, PIDs, nofile, tmpfs y rotación de logs de 10m x3 (`runtime/honeypots.py:548-610`). | No hay cuota de disco para los volúmenes de log escribibles; es una obligación del operador (E3). |

### Invariantes que dependen de la disciplina entre módulos

1. **`ElasticPublisher` no es un redactor de secretos.** `_serialize` solo exige objeto y `event.id`, y serializa cualquier otro campo (`elastic_svc.py:273-293`). La frontera segura es `ecs.build_event`; no deben inyectarse documentos crudos en el publisher.
2. **`CredentialReference` protege la serialización JSON, no toda API Python.** Sus valores permanecen accesibles por `.get`, item e `.items()` (`ecs.py:368-399`). Debe quedar dentro de consumidores confiables y no pasar a plantillas, logs ni serializadores que inspecten esos métodos. La referencia publicada es independiente: HMAC keyed, no verificable sin la clave (§9).
3. **Los parsers legacy no comparten la garantía del adaptador nuevo.** `cowrie_svc.parse` incluye `password` en `detail` (`cowrie_svc.py:52-68`) y `opencanary_svc.parse` conserva `msg` (`opencanary_svc.py:49-68`). No se encontraron llamadas de producción a esos parsers en esta revisión y el tailer está bloqueado; no se eleva a fuga activa, pero no deben reconectarse al pipeline restringido.
4. **El contenido restringido sigue siendo dato hostil.** No ejecutarlo en shell, no abrirlo como fórmula, no renderizarlo como CSV/terminal sin escape y no enviarlo a IA. `dynamic=false` reduce búsqueda/agregación accidental, no lectura de `_source` ni exportación.
5. **La contención no se hereda de un render, un hash o un `nft --check`.** `internal: true`, un Compose válido, una transacción aceptada y un test unitario no son evidencia de kernel. La única fuente válida es el verificador Linux independiente, y el gate actual no puede autorizar nada.

## 5. Qué se probó offline y qué queda para Linux

### Suites ejecutadas en esta revisión (E2)

Entorno: macOS (`Darwin 25.6.0 arm64`), Python 3.12.14, `HOME` en un directorio temporal, `PYTHONDONTWRITEBYTECODE=1`, sin caché de pytest. No se abrió ningún socket de escucha; los tests ASGI usan `TestClient` in-process y los transportes Elastic están inyectados.

```bash
python3.12 -m pytest -q -p no:cacheprovider \
  tests/hardening/test_backup.py tests/hardening/test_cell_gate.py \
  tests/hardening/test_honeypots.py tests/hardening/test_isolation.py \
  tests/deception/test_elastic_export.py \
  tests/deception/test_elasticsearch_publisher.py \
  tests/deception/test_external_adapters.py

python3.12 -m pytest -q -p no:cacheprovider \
  tests/hardening/test_telemetry.py tests/hardening/test_control.py \
  tests/hardening/test_install.py tests/hardening/test_supply_chain.py
```

Resultado: **189 passed, 1 failed, 41 subtests passed**. La única falla fue `tests/hardening/test_honeypots.py::test_docker_compose_accepts_the_rendered_document`, con `unknown shorthand flag: 'f' in -f`: el binario `docker` del host no tiene el plugin `compose`. **No es una falla del código ni una validación de sintaxis Compose**; esa comprobación queda pendiente en un entorno con Docker Compose.

### Reproducciones sintéticas (E2)

Scripts efímeros fuera del repositorio, con directorios temporales y fixtures inventados; no se conservaron secretos ni datos reales.

| Reproducción | Resultado observado | Hallazgo |
|---|---|---|
| Backup sintético con marcador de clave privada; escaneo de todos los archivos | `artifacts/ingest/server.key` contenía el marcador; el manifiesto decía `secrets: excluded` | RT-01 |
| Inventario con `config.file` symlink a un archivo fuera del contexto | El bind `source` apuntaba fuera del contexto y `assert_safe` devolvía `True` | RT-02 |
| Manifiesto sin `sensors.db`, sello recalculado | Restore completó sin `sensors.db` | RT-03 |
| Colisión en el último destino | 5 archivos ya escritos antes de `FileExistsError` | RT-03 |
| Clave Ed25519 efímera fijada solo en el proceso; bundle sintético | Aceptado y rejugable; el contexto solo tiene `cell`/`apply_succeeded` | RT-04 |
| `umask 022`, backup sintético | `server.key` estaba en `0644` antes del `chmod`; después `0600` | RT-05 |
| Evento sintético con `detail.password` (estado previo a §9) | La contraseña no aparecía en el JSON; `fingerprint(raw)` sí aparecía en `dystopia.raw_reference` | RT-09, corregido en §9 |

### Qué **no** demuestran estas pruebas

- No demuestran contención de kernel, red, cgroups, cuotas, namespaces, seccomp, capabilities ni Docker.
- No demuestran el comportamiento de TLS real, CA, revocación, systemd, permisos UID/GID ni del clúster Elasticsearch.
- No demuestran la independencia ni la calidad del verificador Linux del gate; solo el contrato del gate con una clave de prueba.
- No demuestran que un atacante externo pueda ejecutar algo: los hallazgos de path/backup requieren acceso al checkout, al almacenamiento o al host según el caso.
- No sustituyen un drill de restore ni una prueba de agotamiento de recursos.

### Cierre offline de RT-06/07/08 y frontera E3

- **RT-06 (E2 cerrado):** los tests usan padres sintéticos `0777/0770/0772`,
  symlinks, ficheros privados y un `--state-root` writable. **E3 pendiente:**
  comprobar propietario/modo reales de la cadena `/var/lib/dystopia`, de
  `/etc/dystopia`, de sockets/unidades systemd y de un `--state-root` en un
  filesystem real, no solo `tmp_path`.
- **RT-07 (E2 cerrado):** se llenó la cuarentena con el presupuesto vivo libre,
  se forzó dead-letter y se verificó que los eventos válidos posteriores se
  aceptan y entregan. **E3 pendiente:** presión sostenida bajo systemd,
  rotación/revocación real de credenciales del sensor y un `--drain` sobre el
  spool del servicio.
- **RT-08 (E2 cerrado):** transportes inyectados cubren 400/401/403, cola llena
  por permanentes, dead-letter y recarga de API key desde fichero. **E3
  pendiente:** Elasticsearch real, rol writer mínimo, `401/403` reales tras
  rotar la API key en el clúster y exportación del dead-letter por el operador.

### Validación obligatoriamente Linux, en laboratorio desechable y autorizado (E3)

1. **Red y kernel:** aplicar las reglas generadas en Ubuntu 24.04; comprobar ruleset cargado, hooks/prioridades, conntrack por celda y baseline positivo. Probar IPv4/IPv6, spoofing MAC/IP, host, gestión, otras celdas, Internet simulada, fragmentos, VLAN, ARP/ND/RA/DHCP, tráfico inverso nuevo y sesiones existentes durante cuarentena.
2. **Pérdida de control:** detener solo el controlador de laboratorio y verificar que los filtros persisten; probar fallo de apply, quarantine, reinicio y ausencia de autostart. Capturas y counters deben ser externos al workload.
3. **Workload real:** verificar KVM/QEMU o runtime de contenedor, interfaces/rutas extra, mounts, seccomp, UID, capabilities y NNP. Para RT-02, confirmar con archivos sintéticos que el fix impide cualquier bind fuera del contexto antes de usar Docker. Para RT-10, verificar el ID de imagen local contra el digest revisado.
4. **Recursos:** cgroup v2 efectivo, memoria/CPU/PIDs, cuotas de datos/logs, rotación y agotamiento controlado. Los valores de `container_spec()` y Compose son declaraciones hasta esta prueba.
5. **Gate independiente:** revisar el verificador y custodia de clave; generar evidencia real ligada a host/boot/política, probar replay, expiración, revocación y host incorrecto. No fijar una clave de producción mientras RT-04 no esté resuelto.
6. **Servicios y permisos:** TLS real con CA prevista, revocación/rotación, usuarios `control/ingest/sensor/query`, propietarios y modos, sockets y unidades systemd. Probar lecturas denegadas entre cuentas, no solo `stat`. Verificar la cadena completa de padres de `/var/lib/dystopia` (RT-06).
7. **Backup/restore:** drill completo en host desechable, SQLite bajo escritura, filesystem de destino real, almacenamiento offline y permisos de recuperación. Verificar conjunto consistente, comportamiento ante interrupción, ventana de permisos (RT-05) y procedimiento de rotación de secretos.
8. **Analítica real:** comprobar template instalado, rol writer mínimo, `_create`/409, `_source` de campos restringidos, permisos de lectura y snapshots. Confirmar que los datos restringidos no llegan a dashboards, logs ni destinos no autorizados.
9. **Compose real:** ejecutar `docker compose config` con el plugin instalado y el perfil de activación, y verificar que el documento renderizado no contiene binds fuera del contexto, imágenes mutables ni `security_opt` ausente.
10. **Cuotas y agotamiento:** llenar spool, cola Elastic y backup hasta los límites; verificar las acciones de operador de RT-07/RT-08 y que no hay pérdida silenciosa.

## 6. Recomendaciones priorizadas y criterios de aceptación

### P0 — antes de activar o de tratar un backup como no secreto

1. **RT-01: clasificación y custodia del backup.**
   - [ ] El manifiesto no puede declarar `secrets: excluded` si incluye `server.key`, `sensors.db` o equivalente.
   - [ ] Se elige y documenta: excluir/regenerar `server.key` o marcar el backup como `secret-bearing` y cifrarlo.
   - [ ] Una prueba recorre **todos** los archivos y falla si aparece un marcador sintético de clave/token.
   - [ ] CLI y runbook reflejan la clasificación real; el operador no puede exportar una copia “sin secretos” con material de clave.

2. **RT-02: confinamiento de la configuración al contexto.**
   - [ ] `load_inventory` abre el leaf con `O_NOFOLLOW`, exige archivo regular y comprueba que el resuelto es hijo del contexto resuelto.
   - [ ] `render_cell` y `assert_safe` repiten la invariante; un `source` fuera del contexto falla cerrado.
   - [ ] Pruebas con symlink absoluto, relativo, cadena de symlinks y un archivo tipo `/etc/passwd`.
   - [ ] No se habilita `apply/up/down` mientras esta prueba no pase.

3. **RT-03: restore completo y todo-o-nada.**
   - [ ] El conjunto de artefactos debe ser exactamente el de la tabla; todos los `required` deben estar presentes.
   - [ ] Se valida `artifact_count`, el esquema exacto por entrada y se rechaza cualquier `status` distinto de `present`/`missing` según la política.
   - [ ] Preflight de todos los padres/destinos antes de la primera escritura; staging privado y publicación controlada, o informe explícito de punto de compromiso.
   - [ ] Pruebas: required omitido, `missing`, `artifact_count` incorrecto, colisión en el último destino deja **cero** archivos escritos.

4. **RT-04: frescura e identidad de host en el gate.**
   - [ ] El manifiesto incluye identidad de host/boot, `issued_at`, `expires_at` o challenge, y el contexto esperado los exige.
   - [ ] El verificador firma observaciones semánticas de ese host; el gate rechaza replay, expiración y host distinto.
   - [ ] Pruebas con clave de test: mismo bundle dos veces en boots simulados distintos → rechazo; expirado → rechazo; host incorrecto → rechazo.
   - [ ] `TRUSTED_VERIFIER_KEYS` sigue vacío hasta que exista revisión independiente y custodia de clave.

### P1 — antes de habilitar Compose/analítica en un laboratorio

5. **RT-05: permisos de artefactos desde el nacimiento.**
   - [ ] Cada archivo se crea `0600` de forma atómica (`O_CREAT|O_EXCL|O_NOFOLLOW`) o con `umask 077` durante toda la exportación.
   - [ ] El directorio de salida se fija a `0700` antes de la primera escritura.
   - [ ] Prueba con `umask 022` y directorio preexistente `0755`: ningún archivo intermedio es legible por grupo/otros.

6. **RT-06: confianza explícita en padres.**
   - [x] Todo padre de base/archivo privado es propiedad del servicio/root y no escribible por grupo/otros; se verifica con descriptores retenidos.
   - [x] El restore valida la cadena completa de ancestros y rechaza `--state-root` symlink o ancestro sustituido.
   - [x] Prueba con padre `0777`/symlink que falla cerrada antes de crear la base (E2); la sustitución real entre UIDs se confirma en E3.

7. **RV-02: NNP y capabilities.**
   - [x] Todo servicio renderizado incluye `no-new-privileges:true`, sin excepción en el contrato offline.
   - [x] `assert_safe` valida `security_opt` exacto y no acepta `cap_add` como sustituto; `cap_add` sigue limitado a `NET_BIND_SERVICE`.
   - [ ] Inventario de binarios setuid/file-capabilities en cada imagen; verificación de privilegios efectivos en Linux.
   - [x] Pruebas que rechacen NNP ausente, opciones que lo desactivan y `cap_add` no permitido.

8. **RT-07/RT-08: presupuestos de cuarentena y dead-letter.**
   - [x] La cuarentena del spool y los permanentes de Elastic no consumen el presupuesto de eventos vivos, y existe drenaje/exportación de operador.
   - [x] `401/403` de Elastic se reintentan tras recarga controlada de credenciales; el resto va a dead-letter exportable.
   - [x] Alertas (`operator_action_required`, logs) cuando `quarantined > 0` o `permanent/auth_blocked > 0`.
   - [x] Pruebas de cola llena que demuestran flujo acotado o parada explícita con acción de operador.
   - [ ] Presión sostenida contra el servicio real y Elasticsearch real; queda para E3 (sección 5.10).

9. **RT-09: fingerprint sin secretos.**
   - [x] La referencia se calcula con HMAC-SHA-256 y clave provisionada fuera del documento (archivo privado).
   - [x] Prueba: dos registros que solo difieren en la contraseña no comparten la referencia publicada; sin clave el módulo falla cerrado.

10. **RT-10: imágenes inmutables.**
    - [x] El render con `image_policy: digest-required` exige `local_digest` y emite `repo@sha256:<digest>`; si falta, falla cerrado.
    - [x] Un perfil `tag-lab-only` es explícito, se marca en labels y en el informe, y nunca se presenta como productivo.

### P2 — endurecimiento y consistencia

- [ ] Añadir `object_pairs_hook` al manifiesto de backup para rechazar claves duplicadas, igual que en ingesta/gate/backend.
- [ ] Anclar el primer carácter del `healthcheck.marker` a alfanumérico para que `grep` no lo interprete como opción.
- [ ] Documentar que `CredentialReference` no es un límite de seguridad para código in-process y que su `_values` no debe pasar a plantillas/serializadores.
- [ ] Revisar si los errores de backup/gate deben ocultar rutas locales en salidas de API.
- [ ] Añadir a la documentación de backup que `_source`, snapshots y la cola persistente son datos sensibles aunque no estén indexados.
- [ ] Repetir la suite offline en CI Linux sin Docker y con el plugin Compose disponible; marcar el test de Compose como `skip` explícito si falta el plugin, no como fallo de código.

### Criterio de salida de esta auditoría

- [ ] Ningún camino devuelve `containment_verified=true` ni `activation_allowed=true` sin evidencia Linux independiente ligada a host/boot/política.
- [ ] `TRUSTED_VERIFIER_KEYS` permanece vacío hasta completar RT-04 y la revisión de custodia.
- [ ] `honeypots apply/up/down` y `LocalCellBackend.activate()` siguen bloqueados.
- [ ] Ningún backup se publica como “sin secretos” mientras contenga `server.key` o estado de credenciales.
- [ ] Todas las pruebas P0/P1 anteriores pasan offline; las E3 se ejecutan en un laboratorio Linux desechable y autorizado, con resultados registrados sin secretos.

## 7. Estado de remediación (ramas `wave/security-fixes` y `wave/runtime-hardening`)

**Fecha:** 2026-11-02. **Base:** `feature/runtime-wave`. **Entorno de prueba:**
macOS arm64, Python 3.12.14, sin red, sin Docker/KVM/systemd/nftables y sin
datos reales. Nada se activó: `TRUSTED_VERIFIER_KEYS` sigue vacío y
`honeypots apply/up/down` y `LocalCellBackend.activate()` siguen bloqueados.

| ID | Estado en contrato offline | Cambios principales | Evidencia offline | Límite / pendiente |
|---|---|---|---|---|
| RT-01 | **Cerrado** | El backup se declara `secret-bearing`; cada entrada lleva `secret`; `server.key` y `sensors.db` se clasifican como secretos; CLI, manifest y runbook dejan de afirmar “secrets excluded”. | `test_backup_is_declared_secret_bearing`, `test_environment_secrets_never_land_in_any_backup_file`, `test_plan_and_runtime_state_never_claim_a_secret_free_backup` recorren todos los archivos. | El cifrado en reposo del almacén offline es obligación operativa; el código no lo implementa. |
| RT-02 | **Cerrado** | `load_inventory`, `render_cell` y `assert_safe` resuelven el contexto, abren el leaf con `O_NOFOLLOW`, exigen archivo regular no symlink y comprueban que el resuelto queda dentro del contexto revisado. | Tests con symlink absoluto, relativo, cadena y `/etc/passwd`; `assert_safe` rechaza binds fuera del contexto y symlinks. | Validación Compose real y Docker quedan para E3. |
| RT-03 | **Cerrado** | Restore exige conjunto exacto, `artifact_count`, esquema por entrada, estados válidos y todos los `required`; preflight de destinos/padres; staging privado; publicación sin overwrite y rollback. | Tests de required `missing`, conjunto incompleto, `artifact_count` erróneo, estado inválido, colisión tardía y fallo de publicación con cero archivos finales. | No se promete atomicidad entre filesystems distintos; el caso normal queda todo-o-nada con rollback. |
| RT-04 | **Cerrado en contrato; E3 pendiente** | Manifiesto con `issued_at`, `expires_at`, `host_id`, `challenge`; contexto con host, boot, ahora, challenge y skew; ventana máxima de una hora; rechazo de replay en otro boot, expirado, futuro, host/challenge incorrectos. | Tests con clave Ed25519 efímera fijada solo en el proceso de prueba; el trust store real sigue vacío. | Falta el verificador Linux independiente y la custodia/fijación de su clave; no se ejecutó en Linux. |
| RT-05 | **Cerrado** | Archivos `0600` y directorios `0700` desde el nacimiento; `umask 077` durante toda la exportación; directorio de salida endurecido antes de la primera escritura. | Tests con `umask 022` y directorio preexistente `0755`: modos observados en el momento del digest y del primer copiado. | RT-06 cubre el contrato de padres/ancestros; los UID/GID reales se confirman en E3. |
| RT-06 | **Cerrado en contrato offline; E3 pendiente** | Helper único `open_trusted_directory`/`open_private_parent` (padre real, `O_NOFOLLOW`, propietario root/servicio, sin escritura grupo/otros) aplicado a `database()`, `read_private`, `create_private`, `replace_private` y al preflight de restore (`verify_ancestor_chain`). `database()` exige además propietario root/UID efectivo. | `tests/hardening/test_private_parents.py` (padres `0777/0770/0772`, symlink, ficheros privados, UID esperado, ancestros) y `test_restore_rejects_a_writable_or_symlinked_state_root`. | Los UID/GID y la cadena real de `/var/lib/dystopia` se confirman en Linux (E3, sección 5.6); raíces sticky como `/tmp` se admiten solo como ancestros. |
| RT-07 | **Cerrado** | Presupuesto vivo separado de cuarentena; cuarentena acotada con dead-letter del más antiguo y contador persistido; `health` separa `pending`/`quarantined`; operador `sensor-quarantine --output/--drain/--purge`. | `tests/hardening/test_spool_quarantine.py`: presión con presupuesto vivo libre, nuevos eventos aceptados/entregados, evicción dead-letter, export/drain/purge y migración de esquema previo. | El drenaje real del sensor systemd y la rotación de credenciales en laboratorio quedan para E3; no se probó un dispositivo físico. |
| RT-08 | **Cerrado** | Presupuesto vivo excluye `permanent=1`; dead-letter acotado con evicción contada; `401/403` son autenticación reintentable con recarga de API key solo si cambia; `flush` se pausa en auth en vez de repetir; `export_dead_letter`/`purge_dead_letter`. | `test_permanent_rows_do_not_consume_the_live_queue_budget`, `test_dead_letter_budget_evicts_oldest_and_counts_the_loss`, `test_auth_failure_retries_after_controlled_key_rotation`, `test_transport_reloads_a_rotated_api_key`, `test_dead_letter_can_be_exported_and_purged`, `test_permanent_rejections_do_not_stop_the_exporter`. | Elasticsearch real, rotación de API key en clúster y permisos del rol writer quedan para E3 (sección 5.8); el dead-letter no se reintenta automáticamente. |

RT-01 a RT-10 y RV-02 quedaron cerrados a nivel de contrato offline en las
ramas integradas. RV-01 (autenticidad del backup) sigue abierto. Las
dependencias de kernel, Docker, systemd, TLS y Elasticsearch siguen en E3.

**Suites offline ejecutadas para este cierre** (sin Docker, sin red, sin
servicios; el test de Compose se omite si falta el plugin):

```bash
python3.12 -m pytest -q -p no:cacheprovider \
  tests/hardening/test_backup.py tests/hardening/test_cell_gate.py \
  tests/hardening/test_honeypots.py tests/hardening/test_isolation.py \
  tests/hardening/test_telemetry.py tests/hardening/test_control.py \
  tests/hardening/test_install.py tests/hardening/test_supply_chain.py \
  tests/hardening/test_private_parents.py tests/hardening/test_spool_quarantine.py \
  tests/deception/test_elastic_export.py \
  tests/deception/test_elasticsearch_publisher.py \
  tests/deception/test_external_adapters.py
```

Resultado: **282 passed**. La suite completa del repositorio en este mismo
entorno terminó con **703 passed, 3 skipped, 0 failed**. Estas pruebas no
demuestran contención Linux, comportamiento de Docker/Compose, TLS real,
Elasticsearch real ni permisos de kernel; no sustituyen las validaciones E3 de
la sección 5.

## 8. Conclusión

El diseño tiene controles valiosos y bien delimitados: contrato v1 estricto, autenticación por sensor con doble autorización, transporte sin redirects/proxy, parser YAML endurecido, límites de tamaño, colas acotadas, bloqueo incondicional de activación y un helper `nft` de argv fijo. Esos controles **no** equivalen a contención demostrada.

Los riesgos que debían cerrarse primero eran de **clasificación y confianza**,
no de explotación remota: un backup que se declara sin secretos pero los contiene,
una configuración que puede escapar del contexto revisado, un restore que puede
quedar incompleto o parcial, y una evidencia de gate que no está ligada al host ni
al momento. En la rama `wave/security-fixes` esos cuatro bloques y RT-05 quedaron
cerrados **a nivel de contrato offline** (secciones 7 y 9). RT-06/07/08 se
cerraron en `wave/runtime-hardening`; RT-09/10 y RV-02 en
`wave/compose-hardening`. RV-01 sigue abierto y requiere una decisión de
custodia/autenticación del backup.

Nada de lo anterior autoriza a activar un workload. La regla sigue siendo: **un render, un hash, un mock, un `nft --check` o un test unitario no son evidencia de contención**. La evidencia válida es la del verificador Linux independiente, y todavía no existe en este commit.

## 9. Cierre de RT-09, RT-10 y RV-02 (rama `wave/compose-hardening`)

**Fecha:** 2026-11-02. **Base:** `feature/runtime-wave`. **Entorno:** macOS
arm64, Python 3.12.14, sin red, sin Docker/KVM/systemd/nftables y sin datos
reales. Nada se activó: `TRUSTED_VERIFIER_KEYS` sigue vacío,
`honeypots apply/up/down` y `LocalCellBackend.activate()` siguen bloqueados.

| ID | Estado en contrato offline | Cambios principales | Evidencia offline | Límite / pendiente |
|---|---|---|---|---|
| RT-09 | **Cerrado** | `ecs.reference_digest` sustituye a `fingerprint`: HMAC-SHA-256 sobre el registro crudo con una clave provisionada fuera del documento. La clave se carga de `DYSTOPIA_EVENT_REFERENCE_KEY_FILE` mediante `read_private` (archivo 0600, sin symlink); también se puede inyectar con `configure_reference_key`. Sin clave, el módulo lanza `ReferenceKeyUnavailable` en vez de publicar un digest verificable. `dystopia.raw_reference` pasa de `sha256=<hex>` a `hmac-sha256=<hex>`. La identidad de `event.id` usa el mismo HMAC, conservando idempotencia y correlación. | `test_raw_reference_is_not_an_unkeyed_password_oracle`, `test_raw_reference_depends_on_the_provisioned_key_only`, `test_raw_reference_fails_closed_without_a_provisioned_key`, `test_reference_key_is_loaded_from_a_private_file`; `test_external_adapters.py` verifica que la contraseña no aparece y que el SHA-256 sin clave no se publica. | El operador debe provisionar y custodiar la clave; el repo no contiene ninguna. La clave es estable por despliegue, por lo que rotarla cambia `event.id` de eventos futuros. `runtime/normalize` (camino v1) sigue derivando `event_id` del registro crudo antes de publicar; no es `dystopia.raw_reference`, pero mantiene una correlación verificable si se conocen todos los campos. |
| RT-10 | **Cerrado en contrato; E3 pendiente** | El inventario admite `local_digest` por motor. El perfil de celda añade `image_policy`: `digest-required` (por defecto, fail-closed) exige digest y renderiza `repo@sha256:<digest>`; `tag-lab-only` permite tags explícitos, pero es una elección declarada, marca cada servicio con `dystopia.image-policy` y se reporta como no apta para despliegue. `assert_safe` rechaza un tag bajo política de digest y un digest bajo una etiqueta de laboratorio inconsistente. | `test_digest_policy_renders_immutable_image_references`, `test_digest_policy_fails_closed_without_a_reviewed_local_digest`, `test_tag_lab_policy_is_explicitly_non_productive`, `test_assert_safe_rejects_a_mutable_tag_in_a_digest_cell`, `test_invalid_local_digest_is_rejected`. | No se inventaron digests: el inventario real no tiene `local_digest` y su perfil declara `tag-lab-only`. Falta construir las seis imágenes y anotar el digest observado antes de usar `digest-required`. La verificación del ID local contra el digest revisado es E3 (Docker). |
| RV-02 | **Cerrado** | `_service` ya no elimina `security_opt` cuando hay `cap_add`; todo servicio lleva exactamente `["no-new-privileges:true"]`. `assert_safe` exige esa lista exacta (rechaza ausencia, `false`, `seccomp=unconfined`, duplicados y opciones extra), valida `cap_add` como lista única y limitada a `NET_BIND_SERVICE`, y mantiene usuario no-root. La plantilla estática `profiles/honeypots.example.yaml` también incorpora NNP en los motores con capabilities. | `test_assert_safe_requires_exactly_no_new_privileges` (5 variantes), `test_capability_engines_keep_no_new_privileges`, `test_rendered_cell_is_safe_and_internal`. | Con NNP activo, las file capabilities de la imagen no pueden elevar privilegios en `exec`; los motores que escuchan por debajo de 1024 requieren verificar en Linux que `NET_BIND_SERVICE` sigue en el conjunto efectivo, o remapear a puertos altos con DNAT. Inventario de binarios setuid/file-capabilities por imagen: pendiente E3. |

**Suites offline ejecutadas para este cierre** (sin Docker, sin red, sin
servicios; el test de Compose se omite si falta el plugin):

```bash
python3.12 -m pytest -p no:cacheprovider
ruff check \
  runtime/honeypots.py app/services/deception/integrations/ecs.py \
  tests/hardening/test_honeypots.py tests/deception/test_external_adapters.py \
  tests/conftest.py
pyright \
  runtime/honeypots.py app/services/deception/integrations/ecs.py
```

Resultado: **521 passed, 4 skipped, 173 subtests passed**; `ruff` sin
hallazgos; `pyright` 0 errores (1 warning preexistente por `yaml` sin stubs).

**Decisiones**

1. **HMAC con clave, no hash de copia redactada.** Un hash sobre una copia
   redactada elimina la contraseña del oráculo, pero colapsa eventos que solo
   difieren en la credencial y rompe la idempotencia de `event.id`. El HMAC
   conserva ambas propiedades sin permitir verificación offline.
2. **La clave no vive en el repositorio ni en el documento.** Se provisiona en
   un archivo privado del servicio; el módulo falla cerrado si no existe. No se
   añadió ningún valor por defecto ni secreto de ejemplo.
3. **No se inventaron digests de imagen.** Sin imágenes construidas no hay
   digest revisado. El perfil de referencia declara `tag-lab-only` de forma
   explícita y el camino `digest-required` es el valor por defecto del perfil,
   de modo que una copia sin política falla cerrada.
4. **NNP no se negocia con capabilities.** Se mantiene `NET_BIND_SERVICE`
   únicamente donde el inventario lo declara, pero NNP queda siempre activo.
   La compatibilidad efectiva se valida en Linux, no en el render.
5. **`runtime/normalize` queda fuera de este cierre.** Su `event_id` derivado
   del registro crudo v1 no se publica como `dystopia.raw_reference`; se
   documenta como residual para una futura migración a identidad keyed.

**Pendientes Linux (E3) para estos tres cierres**

- Provisionar `DYSTOPIA_EVENT_REFERENCE_KEY_FILE` con un archivo 0600 propiedad
  del servicio y verificar que la referencia no es reproducible sin la clave.
- Construir las seis imágenes, registrar `local_digest`, cambiar el perfil a
  `image_policy: digest-required` y verificar que el ID local coincide con el
  digest renderizado antes de cualquier apply.
- Inventariar binarios setuid/file-capabilities en cada imagen y comprobar los
  privilegios efectivos con NNP activo; si `NET_BIND_SERVICE` no basta para los
  puertos <1024, remapear a puertos altos y DNAT en la celda.
- Ejecutar `docker compose config` con el perfil autorizado y confirmar que no
  hay tags sin digest, `security_opt` ausente ni binds fuera del contexto.
