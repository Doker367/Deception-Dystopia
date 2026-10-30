# Aislamiento de celdas con honeypots contenedorizados

**Estado: diseño y renderizado offline. ACTIVACIÓN BLOQUEADA. No hay contención demostrada.**
No se ha ejecutado `nft`, ningún runtime de contenedores, `virsh`, QEMU, `systemd`,
cuotas de disco ni cambios de red para producir estos artefactos. Un JSON válido, una
unidad systemd bien formada, `nft --check` o una red Docker `internal=true` **no**
demuestran aislamiento.

Este directorio extiende el diseño de [aislamiento por celda](../../docs/hardening-isolation.md)
a honeypots contenedorizados (`cowrie`, `opencanary`, `dionaea`, `heralding`,
`redishoneypot`, `endlessh`) sin sustituir ni reactivar el despliegue Compose heredado.
Las celdas KVM siguen usando [deploy/cell.example.json](../cell.example.json) y
`runtime.isolation`; las celdas contenedor usan la misma política de tráfico y la misma
tabla exclusiva por celda.

## Planos y separación

Los valores son **sintéticos de laboratorio**. No se detectan interfaces ni se adivinan
redes; el operador debe sustituirlos por inventario aprobado. Véase
[networks.example.json](networks.example.json).

| Plano | Ejemplo | Componentes | Regla de diseño |
|---|---|---|---|
| Gestión | `mgmt0`, `198.51.100.0/24` | control, Kibana, Elasticsearch, SSH de operador | Solo gestión. Sin ruta desde deception, telemetría ni simulación de ataque. |
| Deception | `decoy0`, `192.0.2.0/24` | un bridge `dybrN` por celda; VM KVM **o** contenedor | Solo flujos entrantes exactos y salida exacta a ingestión. |
| Telemetría | `telemetry0`, `198.18.255.0/24` | servicio de ingestión | Recibe únicamente el endpoint exacto; escribe en Elasticsearch de gestión con identidad propia. |
| Simulación de ataque | `198.18.1.0/24` | clientes de laboratorio autorizados | Solo origen exacto declarado en la política de cada celda. |
| Protegida | `203.0.113.0/24`, `fd42:d570:100::/64` | producción/otros | Sin ruta desde ninguna celda. |

Una celda es **exclusivamente** una VM KVM o un contenedor de honeypot, nunca ambas.
El ID `1..254`, el bridge `dybrN`, el tap/veth `dytapN`, la tabla `dy_cell_N` y el
espacio de direcciones `192.0.2.N` / `fd42:d570::N` son exclusivos de esa celda. El
inventario del operador es la autoridad; la política no descubre topología.

## Matriz de flujos

| Origen → destino | Permitido |
|---|---|
| Cliente de ataque exacto → puerto exacto del honeypot | Sí, solo con IP/protocolo/puerto literales y respuestas conntrack |
| Honeypot → endpoint de ingestión exacto | Sí, TCP, con límite por regla y autenticación por sensor |
| Honeypot → gestión, Kibana, Elasticsearch, SSH | **No** |
| Honeypot → Internet, DNS, metadata, host, gateway IP | **No** |
| Honeypot → otra celda, otro tap o bridge ajeno | **No** |
| Gestión → honeypot | **No** por red; la operación usa consola/helper local autorizado |
| Ingestión → Elasticsearch de gestión | Solo identidad de escritura dedicada; nunca credenciales de Kibana/admin |
| Cualquier workload → socket del runtime | **No** |

ARP, ND, DAD, RA, DHCP, ICMP/ICMPv6, VLAN, multicast y EtherType distinto de IPv4/IPv6
se deniegan deliberadamente. La conectividad de laboratorio requiere vecinos y rutas
estáticas configuradas **offline** en ambos extremos, IPv6 sin DAD y MTU conservadora.
No se abre ARP/ND para “hacer que funcione”.

## Elasticsearch/Kibana e identidades

- Elasticsearch y Kibana viven **solo** en el plano de gestión. Su bind, TLS,
  autenticación y firewall son un cambio de infraestructura separado; no se editan
  aquí `config/kibana`, `app/` ni el despliegue legacy.
- El servicio de ingestión usa una identidad de escritura **independiente** para
  Elasticsearch, limitada a los índices de eventos. No es administrador, no es Kibana
  y no se comparte con el control ni con los honeypots.
- Cada honeypot recibe solo su token bearer de ingestión por sensor. No recibe JWT,
  credenciales de Elasticsearch/Kibana, CA privada, base central ni token de otro sensor.
- No hay secretos en este repositorio. Los ejemplos usan `null` o marcadores; las
  credenciales se provisionan fuera de banda, se rotan y se revocan por separado.

## Artefactos

| Archivo | Uso |
|---|---|
| [cell-container.example.json](cell-container.example.json) | Política de una celda contenedor; `image` debe sustituirse por un digest revisado antes de `apply`. |
| [networks.example.json](networks.example.json) | Planos, direcciones sintéticas y flujos denegados; no es configuración ejecutable. |
| [CONTAINER-CELLS.md](CONTAINER-CELLS.md) | Esquema de política, perfiles, reglas de tráfico, límites y cuotas. |
| [OPERATIONS.md](OPERATIONS.md) | Activación, verificación, parada, cuarentena, persistencia y limpieza acotada. |
| [LAB-TESTS.md](LAB-TESTS.md) | Matriz de pruebas de laboratorio aún requeridas. |
| [../systemd/dystopia-isolation-apply@.service](../systemd/dystopia-isolation-apply@.service) | Plantilla oneshot de `apply`; sin `[Install]`, nunca habilitar. |
| [../systemd/dystopia-isolation-quarantine@.service](../systemd/dystopia-isolation-quarantine@.service) | Plantilla oneshot de cuarentena aditiva; sin `[Install]`, nunca habilitar. |
| [../../runtime/isolation/containers.py](../../runtime/isolation/containers.py) | Validación/render puro de celdas contenedor. No arranca nada. |

## Instalador y ejemplos existentes

`deploy/install.example.json` y `deploy/cell.example.json` se conservan sin cambios:
el instalador tiene un esquema exacto, no crea redes y no provisiona contenedores. La
red de telemetría, el runtime, las imágenes y las cuotas de las celdas contenedor son
aprovisionamiento externo autorizado, descrito aquí y no una operación del instalador.

## Límites explícitos

- `plan-container` solo renderiza. `apply` solo puede afirmar que `nft` aceptó la
  transacción; no verifica interfaces, kernel, rutas, conntrack, cgroups, cuotas ni
  conectividad.
- `verify()` y `activate()` siguen fallando siempre con `ActivationBlocked`, también
  para celdas contenedor. El estado `verificado` está reservado y nunca se produce.
- No se inicia ni se para ningún contenedor desde este repositorio. El runtime, la
  imagen, la cuota de disco y el arranque son precondiciones externas del operador.
- No se usa Compose. `docker-compose.deception.yml` sigue retirado y `internal=true`
  no es evidencia de contención.
