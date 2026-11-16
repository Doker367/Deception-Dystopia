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

Errores: 401/403 auth · 409 transición inválida/ocupado · 413 lote grande ·
422 manifiesto/eventos inválidos · 502 fallo del engine · 503 manifiesto
ilegible o ingesta sin token configurado.

## 6. Dashboard

Página **Fabric** (sección Operación):

- **Estado**: badge de la máquina (`disabled/ready/deploying/deployed/destroying/error`),
  gate, switches/dispositivos/enlaces, hash del manifiesto.
- **Grafo interactivo**: switches (rectángulos) y dispositivos (círculos)
  agrupados por VLAN; troncales vs accesos; nodos con contenedor `running`
  y fabric `deployed` se marcan en verde. Clic en un dispositivo → drawer.
- **Salud**: checks del host (bridges/enlaces/dispositivos), runtime
  disponible y estado del **forwarder** (enviados/pendientes/fallidos).
- **Tabla**: dispositivo, IP, MAC, switch, VLAN, contenedor, conectividad
  (ping a vecinos) y servicios.
- **Controles** (solo admin): Validate, Deploy, Rebuild, Destroy con
  confirmación y avisos (toast).

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

## 8. Límites conocidos

- **Engines externos**: un servicio con `engine: cowrie/opencanary/...` usa el
  listener **nativo** por protocolo (con warning); el binding real de honeypots
  es trabajo pendiente.
- **Sin rotación** de `events.jsonl` (crecen hasta limpieza manual).
- **Sin TLS** entre control y host service: HTTP con token en la red local del
  host (docker0 ↔ contenedor); TLS/mTLS pendiente.
- **Sin métricas OVS** (contadores de puertos) ni reachability programada: la
  salud se calcula al consultar.
- **WAN solo en enlaces entre switches**: los dispositivos no declaran
  latencia/pérdida propias (se aplicaría al veth de acceso, no al enlace).
- **Un deploy concurrente**: el segundo recibe 409.
- **Destroy usa el manifiesto actual**: si cambió desde el deploy, revisa
  huérfanos con el health/reconcile antes de asumir limpieza.
- `fabric/agent.py` no sirve honeypots de media interacción todavía (Fase 5b).
