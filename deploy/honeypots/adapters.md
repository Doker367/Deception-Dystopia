# Adaptadores de telemetría — estado y contrato

Dystopia mantiene **control/topología** y **Kibana** como analítica. Este
documento describe cómo se normalizan los seis motores al contrato de eventos.
Esta área no modifica `app/`, `runtime/` ni `tests/`.

## Estado actual

| Motor | Parser/adaptador en el árbol | Estado |
|---|---|---|
| Cowrie | `cowrie_svc.parse` y `cowrie_svc.normalize` | Existente; `normalize` emite el contrato ECS/Dystopia. |
| OpenCanary | `opencanary_svc.parse` y `opencanary_svc.normalize` | Existente. |
| Dionaea | `dionaea_svc.normalize` | Presente por integración paralela; se validó con la fixture sintética, no se editó `app/`. |
| Heralding | `heralding_svc.normalize` | Presente por integración paralela; validado con la fixture. |
| RedisHoneyPot | `redishoneypot_svc.normalize` | Presente por integración paralela; validado con la fixture. |
| Endlessh | `endlessh_svc.normalize` | Presente por integración paralela; validado con la fixture. |

El tailer central (`tailer_svc.py`) sigue retirado: devuelve `blocked` y no
procesa logs. La vía prevista es el sensor independiente (`runtime.sensor`),
que no importa automáticamente estos adaptadores. Por tanto, las fixtures son
material de prueba, **no** evidencia de ingesta operativa.

## Capas de contrato

Hay dos capas que no deben confundirse:

1. **Transporte v1 (sensor → ingestión)**: `event_id` UUID4, `device_id`,
   `observed_at`, `src_ip`, `type`, `proto`, `src_port`, `detail`. Es el
   contrato estricto de `runtime/contracts.py`, todavía sin adaptadores
   heredados portados.
2. **Documento ECS/Dystopia (adaptador → Kibana)**: `@timestamp`, `event.*`,
   `observer.*`, `network.*`, `source.*`, `destination.*`, `dystopia.*` y los
   contenedores restringidos `dystopia.decoy_credentials`/`payload`. Es lo que
   producen los `*_svc.normalize` actuales mediante `ecs.build_event`.

Los adaptadores no publican por sí mismos; el pipeline y el sensor deciden el
transporte. No se modificó `app/` desde esta área.

## Contrato de transporte v1 (resumen)

Campos obligatorios: `event_id` (UUID4 canónico), `device_id`, `observed_at`
(ISO-8601 con zona), `src_ip` (IP canónica), `type`, `proto`.
Opcionales: `src_port`, `detail` (máximo 16 claves, valores string ≤ 2 KiB).

`type` ∈ `connect`, `disconnect`, `login_attempt`, `login_success`, `command`,
`file_download`, `port_scan`, `other`.

`proto` ∈ `tcp`, `udp`, `ssh`, `telnet`, `http`, `ftp`, `mysql`, `snmp`.
Los protocolos sin valor propio (SMTP, IMAP, POP3, PostgreSQL, RDP, VNC, SMB,
Redis) se normalizan a `tcp` salvo que se amplíe el enum con revisión del
contrato.

## Mapeo propuesto por motor

### Cowrie

- `cowrie.session.connect` → `connect`, `proto=ssh` o `telnet` según listener.
- `cowrie.login.failed` → `login_attempt`; `cowrie.login.success` → `login_success`.
- `cowrie.command.input` → `command`.
- `cowrie.session.file_download` → `file_download`.
- `src_ip`, `src_port`, `timestamp`, `session` y `sensor` ya están en el JSONL.
- **Límite actual**: `cowrie_svc.parse` fija `proto="ssh"`, aunque el mismo
  parser se use para telnet. Corregir antes de habilitar el listener telnet en
  producción.
- **Privacidad**: el parser actual copia `password` a `detail`. Mantenerlo solo
  si la política lo autoriza; en Kibana no debe indexarse en claro.

### OpenCanary

- `src_host`/`src_ip`, `src_port`, `utc_time` o `local_time` (`utc_time` es UTC
  sin zona; añadir `Z` al normalizar).
- `dst_port` decide `proto`; `msg`/`logtype` deciden `login_attempt` si contiene
  login/password/credential; `161` → `snmp_query` (mapear a `other` o ampliar
  enum; hoy `snmp_query` no existe en el contrato v1).
- El parser actual usa `utc_time` como `ts`; validar que el sensor lo convierta
  a `observed_at` con zona.

### Dionaea

- `src_ip`, `src_port`, `dst_ip`, `dst_port`, `timestamp` (UTC sin zona).
- `connection.type`: `accept` → `connect`; `connect` → `disconnect`/`other`
  según el flujo.
- `credentials[]` → `login_attempt` (un evento por credencial o un evento con
  detalle acotado; no anidar arrays).
- `downloads[]` → `file_download` con hash y tamaño, no con el binario.
- `protocol` (`smbd`, `ftpd`, `mssqld`, `mysqld`, …) se mapea a `tcp` o al
  enum disponible.
- `flat_data: false` conserva listas anidadas; el adaptador debe aplanar y
  acotar antes de emitir.

### Heralding

- `sessions.jsonl` se escribe al cerrar la sesión; `auth.csv` permite eventos
  en tiempo casi real.
- `auth_attempts[]` → un `login_attempt` por intento; `num_auth_attempts` y
  `session_id` en `detail`.
- `protocol` mapea a `ssh`, `ftp`, `telnet`, `http`, `mysql` o `tcp`.
- `source_ip`/`source_port`/`destination_port` están en el JSON.
- No usar `public_ip_as_destination_ip` (deshabilitado) para evitar egress.

### RedisHoneyPot

- Logrus JSON: `time` (`YYYY-MM-DD HH:MM:SS`, UTC sin zona), `action`, `addr`,
  `level`, `msg`.
- `addr` = `ip:puerto`; separar con `rsplit(":", 1)` y validar IP.
- `action=NewConnect` → `connect`; los comandos → `command`/`other`.
  `Closed` debería ser `disconnect`; el adaptador actual lo clasifica como
  `connect` (pendiente).
- `proto=tcp`.
- **Riesgo**: `action` contiene la línea Redis completa, que puede incluir
  valores sensibles. Redactar antes de indexar.

### Endlessh

- Líneas `ACCEPT host=… port=… fd=… n=…` → `connect`, `proto=ssh`.
- `CLOSE host=… port=… fd=… time=… bytes=…` → `disconnect` con duración/bytes
  en `detail`.
- `TOTALS` es métrica agregada, no evento de atacante; descartar o enviar a
  métricas, no a `events`.
- El timestamp es RFC3339 con milisegundos y `Z`; válido para `observed_at`.

## Requisitos para un adaptador seguro

1. **Leer sin ejecutar**: nunca abrir binarios descargados, interpretar shell,
   expandir URLs ni renderizar HTML.
2. **Acotar**: máximo 64 eventos/lote, 256 KiB/lote, 8 KiB/evento; truncar
   `detail` y limitar el número de credenciales/comandos.
3. **Redactar**: contraseñas, tokens, claves y comandos con secretos no deben
   llegar a Kibana ni a un modelo. El payload completo no sale del sensor.
4. **Deduplicar**: `(sensor, event_id)`; conservar offset/inode para no
   reenviar líneas tras rotación. No reutilizar un `event_id` con contenido
   distinto.
5. **Tiempo**: `observed_at` es no confiable; usar `received_at` del receptor
   para ventanas y cuotas. Convertir timestamps sin zona a UTC explícito.
6. **Rotación**: manejar `copytruncate` (offset) o reapertura por inode; probar
   con las fixtures y con un archivo rotado.
7. **Fail closed**: si el spool/transporte falla, pausar y contabilizar
   descartes; no bloquear el honeypot ni perder silenciosamente.

## Formato nativo y fixtures híbridas

Las fixtures conservan los campos nativos de cada motor **y** añaden alias
canónicos (`src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `command`,
`username`, `password`) para que los adaptadores actuales puedan consumirlas
sin un preprocesador adicional. No son capturas literales: son muestras
sintéticas de contrato.

Diferencias conocidas entre el log nativo y lo que espera el adaptador actual:

- **Dionaea** anida `connection` y `credentials`; la fixture añade `event`,
  `protocol` y credenciales/URL planas. Un colector real debe aplanar o el
  adaptador debe leer los objetos anidados.
- **Heralding** usa `source_ip`/`destination_ip` y `auth_attempts[]`; la
  fixture añade `src_ip`/`dst_ip` y la primera credencial en el nivel superior.
- **RedisHoneyPot** usa `action` y `addr`; la fixture añade `src_ip`,
  `src_port`, `command` y `args`. La línea `Closed` no se mapea a
  `disconnect` por el adaptador actual (sale como `connect`).
- **Endlessh** nativo usa `ACCEPT host=… port=…`; la fixture incluye además
  `ip:puerto` para el regex actual. La línea `TOTALS` no es un evento de
  atacante y el adaptador la clasifica como `connect` sin origen.
- **OpenCanary** anida credenciales en `logdata`; la fixture añade
  `username`/`password` y `protocol` explícito para evitar que `logtype`
  ambiguo (p. ej. 4002/8001) cambie el protocolo.

Corregir estas diferencias en los adaptadores (fuera del área de este
artefacto) antes de considerar la ingesta lista para producción.

## Pruebas con fixtures

Las fixtures usan IPs de documentación (RFC 5737) y contraseñas literales
`demo-not-a-real-password`. No contienen malware, claves ni datos personales.
Se pueden usar para pruebas unitarias de los adaptadores, sin levantar
contenedores:

```sh
jq -c . deploy/honeypots/fixtures/cowrie.jsonl
jq -c . deploy/honeypots/fixtures/opencanary.jsonl
jq -c . deploy/honeypots/fixtures/dionaea.jsonl
jq -c . deploy/honeypots/fixtures/heralding.jsonl
jq -c . deploy/honeypots/fixtures/redishoneypot.jsonl
```

`endlessh.log` no es JSON; validar con el parser de texto propuesto.
