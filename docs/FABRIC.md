# NetPulse — Network Fabric (guía)

Fecha: 2026-11-16 · Estado: Fases 1-8 desplegadas en Debian trixie (OVS 3.5.0 + Docker)

## 1. Qué es

El **Network Fabric** convierte a Dystopia de gestor de honeypots en plataforma
de emulación de infraestructura: define una red señuelo completa (switches
virtuales OVS, VLANs, contenedores de dispositivo con sus servicios y
credenciales) en un único manifiesto YAML y la despliega de forma idempotente.

| Objetivo | Estado |
|---|---|
| Red señuelo completa en `network.yaml` (extensión compatible) | ✅ |
| Topología virtual con Mininet/OVS en el mismo host | ✅ (OVS directo; ver límites) |
| Contenedores de dispositivo (Docker) conectados a OVS por veth | ✅ |
| Bind de honeypots existentes a servicios del dispositivo | Parcial (listeners nativos; Cowrie/OpenCanary pendiente) |
| Telemetría del fabric en el pipeline de eventos | ✅ |
| Ciclo de vida vía API REST | ✅ |
| Visualización en el dashboard | ✅ |
| Compatibilidad 100%: sin `fabric:` todo funciona como antes | ✅ |

Especificación completa: [`docs/specs/DYSTOPIA_NETWORK_FABRIC_SPEC.md`](specs/DYSTOPIA_NETWORK_FABRIC_SPEC.md).
Runbook de operación: [`docs/FABRIC-OPERATIONS.md`](FABRIC-OPERATIONS.md).

## 2. Arquitectura

```text
┌──────────────────────────── HOST (Debian trixie) ────────────────────────────┐
│                                                                              │
│  ┌── Contenedor control (endurecido) ──┐      ┌── dystopia-fabric.service ─┐ │
│  │ app.main (FastAPI, :8082)           │      │ systemd, root CONFINADO     │ │
│  │  ├─ /api/fabric/*  (JWT admin/viewer)│ HTTP │  (CAP_NET_ADMIN NET_RAW     │ │
│  │  ├─ engine "remote" ─────────────────┼─────►│   SYS_ADMIN SYS_PTRACE      │ │
│  │  └─ POST /api/fabric/events ◄────────┼──────│   CAP_CHOWN) + token bearer│ │
│  │       ▲ X-Fabric-Token               │      │  ├─ OvsFabricEngine        │ │
│  └──────────────────────────────────────┘      │  ├─ DeviceRuntime (Docker) │ │
│                                                │  └─ EventForwarder (JSONL) │ │
│  ┌── Open vSwitch ──┐   ┌── Contenedores dispositivo (red none, agente) ──┐│
│  │ sw-core / sw-*   │◄──┤ dv00-… veth · eth0 IP/MAC · listeners nativos   ││
│  └──────────────────┘   └────────────── events.jsonl ────────────────────────┘│
└──────────────────────────────────────────────────────────────────────────────┘
```

Piezas:

| Pieza | Código | Responsabilidad |
|---|---|---|
| Parser | `app/services/fabric/parser.py` | Valida el manifiesto y cruza referencias (§3.3) |
| Topology Manager | `app/services/fabric/topology.py` | Planes puros: bridges, enlaces, dispositivos |
| Controller | `app/services/fabric/controller.py` | Máquina de estados, persistencia, auditoría |
| Engine OVS | `app/services/fabric/deploy.py` | `ovs-vsctl`/`ip` + `DeviceRuntime` |
| Device Runtime | `app/services/fabric/runtime.py` | Contenedores endurecidos, veth/netns, salud |
| Agente | `fabric/agent.py` | Sirve servicios y emite JSONL dentro del contenedor |
| Host service | `app/services/fabric/host_service.py` | API del host con token; corre el engine |
| Forwarder | `app/services/fabric/event_forwarder.py` | JSONL → control con offsets persistentes |
| Credenciales | `app/services/fabric/credential_store.py` | Fernet en reposo |
| Alertas | `app/services/fabric/fabric_alerts.py` | Primer contacto y movimiento lateral |

## 3. Manifiesto

El bloque `fabric:` extiende `config/deception/network.yaml` sin cambiar el
esquema existente (`segments`/`devices`). Ejemplo mínimo:

```yaml
segments:
  - id: vlan-oficina
    vlan_id: 10
    cidr: 10.10.0.0/24
    gateway: 10.10.0.1

devices:
  - id: pc-recepcion-01
    role: pc
    segment: vlan-oficina
    ip: 10.10.0.21
    services:
      - {port: 22, proto: ssh, engine: native, banner: "OpenSSH_8.9"}

fabric:
  enabled: true
  name: corporate-deception-net
  switches:
    - id: sw-core
      vlans: [10]
  links:                              # enlaces explícitos entre switches
    - from: sw-core
      to: sw-oficina
      trunk: true
      latency_ms: 50                  # emulación WAN (opcional, ver §3.1)
      jitter_ms: 5
  device_overrides:
    - id: pc-recepcion-01
      interfaces:
        - {segment: vlan-oficina, ip: 10.10.0.21/24, mac: "00:1c:42:10:10:21",
           gateway: 10.10.0.1, vlan_tag: 10, switch: sw-core}
      credentials:                      # se cifran en reposo, nunca en la API
        - {username: admin, password: admin123, service: ssh}
      routes: [{destination: 0.0.0.0/0, gateway: 10.10.0.1}]
      neighbors: [{ip: 10.10.0.1, mac: "00:1c:42:10:10:01", hostname: gateway}]
```

Ejemplo completo y válido: [`config/deception/network.fabric.example.yaml`](../config/deception/network.fabric.example.yaml).
Reglas de integridad (device/segment/switch/VLAN/IP, unicidad): spec §3.3.

### 3.1 Emulación WAN de los enlaces (Fase 10)

Cada entrada de `fabric.links` acepta cuatro parámetros opcionales que el
engine traduce a un qdisc `netem` de `tc` **en ambos extremos** del veth
(el enlace se degrada en los dos sentidos):

| Campo | Rango | Efecto (`tc netem`) |
|---|---|---|
| `latency_ms` | 0–5000 | `delay <n>ms` |
| `jitter_ms` | 0–1000, **≤ `latency_ms`** | `delay <lat>ms <jitter>ms` |
| `loss_pct` | 0–100 | `loss <n>%` |
| `bandwidth_mbps` | 0.1–100000 | `rate <n>mbit` |

```yaml
links:
  - {from: sw-core, to: sw-oficina, latency_ms: 50, jitter_ms: 5}
  - {from: sw-core, to: sw-servidores, loss_pct: 0.5, bandwidth_mbps: 20}
```

- Las cláusulas no declaradas se omiten: `latency_ms: 50` solo emite
  `delay 50ms`.
- `jitter_ms` exige `latency_ms` y no puede superarlo (netem no admite
  jitter sin delay ni retardos negativos); el parser lo rechaza.
- `bandwidth` (entero) queda como **alias deprecado** de `bandwidth_mbps`;
  si se declaran ambos deben coincidir y `bandwidth_mbps` prevalece.
- Los uplinks automáticos (`switches[].uplink`) no heredan parámetros WAN:
  declara un `links` explícito para ese par.
- Re-desplegar aplica `tc qdisc replace`: cambiar los parámetros recalcula
  el qdisc sin destruir el enlace. `destroy` borra el qdisc (tolerante a
  su ausencia). El resultado del deploy lo lista en `wan_links`.
- Requiere `tc` (iproute2) y el módulo `sch_netem`; si falta, el deploy
  falla en el preflight con un error accionable (no se ignora).

## 4. Cómo se habilita (doble gate)

1. **Manifiesto**: `fabric.enabled: true` y topología válida (botón *Validate*).
2. **Entorno**: `DYSTOPIA_FABRIC_ENABLED=true` en el entorno del control
   (en el lab, `.env` de `deploy/local`).
3. **Rol**: las mutaciones requieren JWT **admin**.

Con cualquiera de los tres cerrado, la API solo lee/valida.

Motor (`DYSTOPIA_FABRIC_ENGINE`): `stub` (simulado, default), `ovs` (local,
requiere privilegios) o `remote` (el control habla con el servicio del host;
es el modo de producción del lab).

## 5. API

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| GET | `/api/fabric/status` | viewer | Estado de la máquina, gate, forwarder, resumen de salud |
| GET | `/api/fabric/topology` | viewer | Topología validada, **sin credenciales** |
| GET | `/api/fabric/topology/graph` | viewer | Grafo `{nodes, edges, groups}` para D3/ECharts |
| POST | `/api/fabric/validate` | admin | Informe de errores/warnings sin desplegar |
| POST | `/api/fabric/deploy` | admin | Despliega (idempotente: destruye primero) |
| POST | `/api/fabric/destroy` | admin | Desmonta y vuelve a `ready` |
| POST | `/api/fabric/rebuild` | admin | Alias destroy+deploy |
| GET | `/api/fabric/devices` | viewer | Dispositivos con `runtime` (estado del contenedor) |
| GET | `/api/fabric/devices/{id}` | viewer | Detalle: runtime, interfaces, vecinos, servicios |
| GET | `/api/fabric/switches` | viewer | Switches declarados |
| GET | `/api/fabric/switches/{id}` | viewer | Detalle de switch |
| GET | `/api/fabric/health` | viewer | Salud: checks de bridges/enlaces/dispositivos |
| GET | `/api/fabric/events?device_id=&limit=` | viewer | Últimos eventos del fabric (store) |
| POST | `/api/fabric/events` | servicio | Ingesta del forwarder (`X-Fabric-Token`) |
| GET | `/api/fabric/config` | admin | YAML del bloque `fabric:` para el editor (credenciales enmascaradas `__REDACTED__`) |
| PUT | `/api/fabric/config` | admin | Guarda el YAML (valida antes; backup `.bak`; restaura `__REDACTED__` del manifiesto vigente) |
| POST | `/api/fabric/devices/{id}/console` | admin | Abre sesión de consola interactiva (Fase 11) |
| GET | `/api/fabric/console/sessions` | admin | Sesiones de consola activas (estado, transporte, actividad) |
| WS | `/api/fabric/devices/{id}/console/ws?token=` | admin | Puente WebSocket↔PTY de la consola |
| GET | `/api/fabric/console/sessions` | admin | Sesiones de consola vivas (id, device, actividad, estado) |

Errores: 401/403 auth · 409 transición inválida/ocupado · 413 lote grande ·
422 manifiesto/eventos inválidos · 429 cuota de consolas · 502 fallo del engine ·
503 manifiesto ilegible, ingesta sin token o consola deshabilitada.

### 5.1 Consola interactiva (Fase 11)

"Entrar en la máquina": terminal xterm.js en el drawer del dispositivo
(botón **Terminal**, solo admin y con el contenedor `running`). Gates
fail-closed:

- JWT admin (en el query del WS: los navegadores no pueden fijar headers).
- Fabric en estado `deployed` y el `device_id` en el manifiesto.
- `DYSTOPIA_FABRIC_CONSOLE_ENABLED=true` (independiente del gate de deploy).
- Cuota de sesiones (`DYSTOPIA_FABRIC_CONSOLE_MAX`, default 4), **cuota por
  dispositivo** (`DYSTOPIA_FABRIC_CONSOLE_PER_DEVICE_MAX`, default 1), idle
  timeout (`_CONSOLE_IDLE`, 600 s) y edad máxima (`_CONSOLE_MAX_AGE`, 3600 s).
- El idle/edad se aplica de verdad con un segador de fondo del control
  (loop de 30 s en el lifespan; antes `reap_idle()` era código muerto).

Transporte: el control **nunca** monta el socket de Docker. Con engine
`remote` (control en contenedor) el control abre un WebSocket contra el
servicio del host (`wss://…/console/ws`, bearer token + CA opcional) y
hace de puente; el servicio del host es quien ejecuta `docker exec`. Con
engine `ovs`/`stub` sobre el propio host, el control ejecuta `docker exec`
en local. En ambos casos el comando está fijado (sin shell del host, sin
argumentos libres): `docker exec -i -t -e COLUMNS=… -e LINES=…
-e TERM=xterm-256color <contenedor-del-manifiesto> /bin/sh -i`.

**Protocolo WS** (compatible con clientes previos):

| Frame | Dirección | Significado |
|---|---|---|
| Texto crudo | navegador → control | Entrada del teclado (onData del xterm) al stdin del PTY. Ctrl+C/Ctrl+L pasan crudos: los interpreta el shell del contenedor. |
| JSON `{"type":"resize","cols":n,"rows":n}` | navegador → control | Cambio de tamaño: `TIOCSWINSZ` + `SIGWINCH` al `docker exec` (local) o frame equivalente al host service (remote); nunca llega al stdin. |
| Bytes / texto | control → navegador | Salida del PTY (binario en el salto control↔host, texto UTF-8 hacia el navegador). |
| `\0ERR:<mensaje>` (texto) | control → navegador | Gate fallido (fail-closed): banner en la UI y cierre inmediato (códigos 4401/4404/1011). |

Experiencia del terminal (frontend, `web/src/components/FabricConsole.tsx`):

- **Reconexión automática** con backoff exponencial (600 ms → 6 s tope,
  5 intentos) y cuenta atrás visible; el chip se vuelve ámbar ("reconectando")
  y hay botón *Reintentar ahora*. Un fallo de gate no reintenta (el banner
  ya muestra el motivo en español).
- **Resize con debounce** (120 ms): el `fit()` del xterm se propaga al PTY
  con frame JSON; en remote el servicio del host lo aplica igual que en local.
- **Copiar/pegar**: Ctrl+Shift+C copia la selección; Ctrl+Shift+V pega el
  portapapeles; también ClipboardAddon para OSC 52.
- **Limpiar**: botón *Limpiar* (Ctrl+L del shell) en el strip de estado.
- **Sesiones**: chips con estado de las consolas abiertas en otros
  dispositivos (clic para cambiar) y `GET /api/fabric/console/sessions`
  (solo admin) con la lista real del control.
- **Accesibilidad**: drawer con `role="dialog"`/`aria-modal`, Escape
  cierra, `aria-live` en el estado y en los errores, y layout responsive
  (`width: 100vw` bajo 680 px, host del terminal con alto fluido).

Cerrar el drawer cierra la sesión (el backend mata el PTY al caer el
socket): cada terminal reconectado empieza un shell fresco en su
contenedor. El historial del xterm (scrollback 1000 líneas) vive solo
dentro de la sesión.

Activar en el laboratorio Docker (los dos lados):

```bash
# deploy/local/.env (control)
DYSTOPIA_FABRIC_CONSOLE_ENABLED=true
# /etc/dystopia/fabric.env (servicio del host)
DYSTOPIA_FABRIC_CONSOLE_ENABLED=true
```

y recrear el control (`docker compose up -d --force-recreate control`)
y el servicio (`systemctl restart dystopia-fabric`).

## 6. Dashboard

Página **Fabric** (sección Operación):

- **Estado**: badge de la máquina (`disabled/ready/deploying/deployed/destroying/error`),
  gate, switches/dispositivos/enlaces, hash del manifiesto.
- **Grafo interactivo**: switches (rectángulos) y dispositivos (círculos)
  agrupados por VLAN; troncales vs accesos; nodos con contenedor `running`
  y fabric `deployed` se marcan en verde. Clic en un dispositivo → drawer.
- **Topología**: toggle de layout **Fuerza** (grafo libre) y **Jerárquico**
  (switches en fila, dispositivos colgando de su switch); aristas con
  etiqueta de parámetros WAN (latencia/jitter/pérdida/ancho de banda).
- **Editor de manifiesto** (solo admin): textarea YAML del bloque
  `fabric:` con validación previa (POST `/validate`) y guardado con
  backup `.bak`; las credenciales se enmascaran como `__REDACTED__`.
- **Terminal** (solo admin): botón **Terminal** en el drawer del
  dispositivo con el contenedor `running`; abre una sesión interactiva
  WebSocket↔PTY hacia el señuelo.
- **Salud**: checks del host (bridges/enlaces/dispositivos), runtime
  disponible y estado del **forwarder** (enviados/pendientes/fallidos).
- **Tabla**: dispositivo, IP, MAC, switch, VLAN, contenedor, conectividad
  (ping a vecinos) y servicios.
- **Controles** (solo admin): Validate, Deploy, Rebuild, Destroy con
  confirmación y avisos (toast), más **Editar manifiesto** (editor YAML).

## 7. Modelo de seguridad

| Control | Implementación |
|---|---|
| Aislamiento de red | Bridges OVS internos, sin uplink del host; solo puertos del fabric (spec §9.1) |
| Hardening de contenedores | `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, pids/mem/cpus, uid 2000; sin socket Docker ni `--privileged` |
| Servicio del host | systemd root **confinado** (`CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_CHOWN`, `ProtectSystem=strict`, `SystemCallFilter`) |
| Credenciales | Cifradas con Fernet (`/etc/dystopia/fabric.key` 0600) en `/var/lib/dystopia/fabric/credentials/<device>.enc`; `device.json` **no** las contiene; nunca en respuestas (AC13) |
| Tokens | `DYSTOPIA_FABRIC_TOKEN` (operación control→host) y `DYSTOPIA_FABRIC_EVENTS_TOKEN` (ingesta host→control), distintos, 0600 |
| Auditoría | `fabric_validate/deploy/destroy/rebuild` en `audit_svc` (usuario, estado, hash, conteos) |
| Alertas | `fabric_new_device_probed` (media) y `fabric_lateral_movement` (alta; ventana 10 min) |

## 7b. Motores reales (Cowrie / OpenCanary)

Un servicio puede declarar `engine: cowrie` o `engine: opencanary`. Si el
contenedor usa la imagen con motores, el agente:

1. Genera la configuración del motor en `/var/log/fabric/engines/<engine>/`.
2. Arranca el proceso escuchando en el puerto declarado.
3. Taila su log nativo y normaliza cada registro con
   `runtime.normalize.normalize_raw(...)` hacia el mismo `events.jsonl`.

El forwarder, el control y las alertas no cambian: ven el mismo formato que
los listeners nativos. La configuración generada **no** contiene credenciales
del manifiesto (Cowrie usa `AuthRandom`; OpenCanary no recibe usuarios).

Imagen con motores (opcional, ~1 GB):

```bash
docker build -t dystopia/fabric-device:v1 -f fabric/Dockerfile .
docker build -t dystopia/fabric-device:engines -f fabric/Dockerfile.engines .
```

Para usarla, declara en el dispositivo:

```yaml
resources:
  image: "dystopia/fabric-device:engines"
```

Si el motor no está instalado o no arranca, el agente avisa y sirve ese
protocolo con el listener nativo (fallback). Motores sin binding real hoy:
`dionaea`, `heralding`, `redishoneypot`, `endlessh`.

## 8. Límites conocidos

- **Motores reales**: `engine: cowrie` y `engine: opencanary` se ejecutan de
  verdad si la imagen los incluye (`dystopia/fabric-device:engines`); el resto
  (`dionaea`, `heralding`, `redishoneypot`, `endlessh`) y los motores ausentes
  caen al **listener nativo** con warning. Ver §"Motores reales" arriba.
- **Rotación** de `events.jsonl`: logrotate diario (7 copias, `copytruncate`),
  instalado por `install-fabric-service.sh`.
- **TLS opcional** entre control y host service: el instalador genera un
  certificado autofirmado y el control puede verificar con
  `DYSTOPIA_FABRIC_REMOTE_CA` (ver runbook). Por defecto HTTP con token en la
  red privada del host.
- **Sin métricas OVS** (contadores de puertos) ni reachability programada: la
  salud se calcula al consultar.
- **WAN solo en enlaces entre switches**: los dispositivos no declaran
  latencia/pérdida propias (se aplicaría al veth de acceso, no al enlace).
- **Un deploy concurrente**: el segundo recibe 409.
- **Destroy usa el manifiesto actual**: si cambió desde el deploy, revisa
  huérfanos con el health/reconcile antes de asumir limpieza.
- `fabric/agent.py` no sirve honeypots de media interacción todavía (Fase 5b).
