# Aislamiento por celda: prototipo, ACTIVACIÓN BLOQUEADA

**No hay contención real demostrada.** Código stdlib nuevo e independiente del
runtime/VM/firewall legacy; no cambia sus rutas de ejecución. No se han ejecutado
pruebas, nft, libvirt, comandos privilegiados ni cambios de red durante esta
implementación. Este componente no convierte el backend legacy en seguro.

## Alcance implementado

- Política inmutable, esquema exacto sin campos desconocidos, claves JSON
  duplicadas, nombres/IP/comandos libres, booleanos como enteros ni CIDR abiertos.
- Ubuntu **24.04**, KVM/libvirt x86_64, una celda `1..254`, una NIC bridge explícita
  `dybrN`, tap `dytapN` y puerto de salida dedicado `dyupN`. El archivo local
  root-owned constituye la aprobación del bridge; no hay aprobación desde cliente.
- Direcciones de laboratorio fijas `192.0.2.N`, `fd42:d570::N` y
  `02:00:00:00:00:NN` (último byte hexadecimal). Los endpoints autorizados no
  pueden pertenecer a los rangos de señuelos. No hay soporte para IPs dinámicas.
- XML offline: disco RAW único `/var/lib/dystopia/cells/N/root.raw`, sin backing
  chain, ruta no controlable por cliente; sin VNC, serial, consola, canales,
  filesystem compartido, hostdev, red libvirt `default`, NAT ni sockets de red.
  NIC inicialmente **link down**. No se implementan define/start de libvirt.
- nftables familia bridge por celda: cadenas host input/output y forward,
  comprobaciones L2/MAC/IP/puerto, ruta tap ↔ uplink exclusiva, VLAN y todo EtherType
  distinto de IPv4/IPv6 bloqueados; fragmentos IPv4 y cabeceras de extensión IPv6
  bloqueados antes de conntrack; zona CT por celda y marca de flujos autorizados.
  Solo servicio entrante desde IP literal autorizada, protocolo/puerto exactos y
  respuestas CT. No `related` global, helpers autorizados, DNS o salida implícita.
- Telemetría desactivada con `null`; opcionalmente un destino TCP literal/puerto,
  con límite por regla de 10 paquetes/s y ráfaga 20, incluyendo respuestas.
  **No es un control de contenido ni un límite agregado de bytes**: un guest
  comprometido puede enviar datos arbitrarios al endpoint autorizado. Requiere
  colector dedicado no reenviador, autenticación y cuotas fuera de este módulo.
- Transacciones `create table` exclusivas: `dy_cell_N`, y cuarentena aditiva
  `dy_quarantine_N`. Nunca `flush ruleset`, flush/delete/replace de tablas ni
  adopción de una tabla preexistente. Colisión o fallo → degradado, no éxito falso.
  Las cadenas base usan política accept para no cortar interfaces ajenas; los
  drops explícitos se limitan al tap/uplink administrado. Los filtros tempranos
  afectan todo el uplink dedicado, que no se puede compartir con otros servicios.

### API y estados

`CellPolicy.from_mapping(...)`, `domain_xml(policy)` y `nft_rules(policy)` son
funciones de validación/render sin efectos. No validan que exista la topología.

`LocalCellBackend(N)` solo admite el ID entero. Carga una instantánea de
`/etc/dystopia/isolation/cell-N.json`, máximo 16 KiB, mediante descriptores
no-follow; directorios y archivo deben pertenecer a root y no ser escribibles
por grupo/otros. Rechaza symlinks, archivos especiales y archivos con varios
hardlinks. No acepta políticas, rutas ni objetos runner desde API/cliente.

- `configurado`: política local cargada, ningún hecho de kernel acreditado.
- `apply()` → `aplicado`: nft aceptó la transacción; **no significa aislado**.
  Ante fallo intenta cuarentena aditiva y queda `degradado`.
- `quarantine()` / `emergency()` → `degradado`: intenta instalar drops aditivos.
  Si falla, eleva error y declara cuarentena NO confirmada. No destruye la VM.
- `stop()` solicita cuarentena y detiene nuevas aplicaciones del controlador.
  No retira reglas. La terminación abrupta tampoco las retira: las tablas no
  llevan flag de ownership ligado al proceso. Un reinicio del host sí las pierde.
- `verify()` siempre falla con `ActivationBlocked` y estado degradado.
- `activate()` **siempre** eleva `ActivationBlocked`, incluso si se manipula el
  estado a `verificado`. Ese estado está reservado y nunca es producido aquí.
  No existe parámetro `isolated`, `verified`, `force` ni override de activación.

El runner exige Linux root local y Ubuntu 24.04, verifica ownership/permisos del
binario fijo `/usr/sbin/nft`, usa argv fijo, `shell=False` implícito, stdin generado,
ambiente allowlist y timeout. Solo ejecuta check y apply nft; no sudo, SSH, shell,
ip, virsh, qemu ni comandos arbitrarios. No es una frontera frente a código Python
hostil dentro del mismo proceso root. Debe vivir fuera del proceso web sin privilegios.

Controlador one-shot: no recarga, reconciliación ni recuperación automática de
reglas preexistentes después de restart. Repetir cuarentena puede fallar por tabla
existente: se informa degradado, nunca se infiere integridad de esa tabla. La
recuperación debe ser una tarea administrativa posterior con celda apagada,
verificación independiente y sin borrar reglas de otros propietarios.

## Ejemplo declarativo para laboratorio (no desplegado)

```json
{
  "version": 1,
  "cell": 7,
  "bridge": "dybr7",
  "gateway_mac": "02:10:20:30:40:50",
  "services": [
    {"address": "198.51.100.20", "protocol": "tcp", "port": 22},
    {"address": "2001:db8:20::1", "protocol": "tcp", "port": 22}
  ],
  "telemetry": null,
  "memory_mib": 512,
  "vcpus": 1
}
```

ARP, ND, DAD, RA, DHCP, ICMP/ICMPv6 y multicast están cerrados deliberadamente.
Requiere configurar **offline** direcciones, rutas y vecinos estáticos en ambos
extremos; IPv6 sin DAD sobre estas direcciones; MTU conservadora. No abrir ARP/ND
ampliamente para que una prueba conecte. Las IPs de documentación son exclusivamente
para laboratorio. El gateway no puede ser la máquina host en el mismo bridge.

## Verificación pendiente — laboratorio desechable, nunca producción

No quitar el bloqueo de activación para ejecutar estas pruebas. Un administrador
puede construir un harness de integración independiente, solo en hosts/VMs
Ubuntu 24.04 desechables sin ruta a Internet, LAN, secretos ni sockets compartidos.
No se incluyen comandos de despliegue automático para infraestructura real.

### Precondiciones que este código NO comprueba

1. KVM, libvirt local, AppArmor/seccomp/sVirt efectivos y QEMU no privilegiado;
   XML normalizado por libvirt sin dispositivos/consolas/socket añadidos.
2. Imagen RAW administrada sin enlaces, permisos/ownership/identidad seguros,
   host sin montaje guest-writable de esa ruta; sistema guest provisionado offline.
   El renderer solo fija la ruta: **no inspecciona ni abre el disco**.
3. Un bridge dedicado sin IP host y exactamente dos puertos previstos; sin
   interfaz adicional, túnel, hairpin, proxy ARP/ND, VLAN trunk, NAT o puerto físico
   ajeno. Todo señuelo pertenece a los rangos fijos y no puede acceder al host.
4. Interfaces y nombres reservados, no renombrables/reutilizables por tenants;
   sin bypass por hardware/software offload, tc/XDP, OVS o hooks externos;
   VLAN filtering y offloads inspeccionados, no asumidos. Ningún daemon elimina
   o reescribe tablas, zonas o marcas CT. Inventario por celda exclusivo.
5. Sintaxis nft y soporte real de conntrack bridge, prioridad -310/-300 y zonas,
   orden de hooks, defragmentación y filtros L2. CT helpers deshabilitados,
   rangos de zonas/marcas reservados y sin flujos antiguos. Rollback nft atómico.
6. Política/kernel/disco/topología ligados a evidencia fresca, identidad de host
   y boot, revisada de forma independiente; un booleano de cliente jamás basta.
7. Barrera de arranque root que aplique/verifique antes de levantar NIC o iniciar
   guest; autostart deshabilitado, watchdog y cuarentena al perder observación,
   política persistente tras reboot. No implementados en este prototipo.

### Matriz mínima desde guest root, IPv4 E IPv6

Registrar captura en gateway/host/otra celda (no solo salida del comando guest),
contadores scoped, reglas leídas del kernel y resultado positivo/negativo:

| Prueba | Resultado exigido |
|---|---|
| Cliente autorizado → servicio exacto | Conexión y respuesta CT permitidas |
| Origen o puerto no autorizado, dirección inversa nueva | Sin paquetes entregados |
| Guest → Internet/LAN/host/metadata/DNS/otra celda | Sin paquetes entregados |
| Guest → otro tap, incluso usando gateway o MAC/IP autorizada | Sin paquetes entregados |
| Spoof MAC/IP, IPv4 mapped IPv6, UDP/TCP malformado/fragmentado | Sin paquetes entregados |
| ARP poisoning, ND/RA/DHCP, broadcast/multicast, STP/LLDP/EAPOL | Sin efecto host/L2 ni entrega |
| VLAN 802.1Q/QinQ y tags ocultos por offload | Sin paquetes entregados |
| IPv6 extensiones/fragmentos/túneles y IPv4 opciones/fragmentos | Sin bypass del allowlist |
| Telemetría null; luego destino/puerto correcto e incorrecto | Cerrada; solo excepción exacta con cuotas |
| Flujo previamente establecido no autorizado, CT related/helper | Sin paquetes entregados |
| Cuarentena con conexiones ya abiertas | Todo tráfico de la celda detenido |
| Fallo nft, tabla preexistente, doble controlador, reinicio controlador | Degradado, no activación ni reglas ajenas modificadas |
| SIGKILL/controlador stop, pérdida de observación y reboot host | Sin fail-open; documentar el gap de reboot actual |
| Reglas/contadores de otras celdas y tablas antes/después | Sin mutación de reglas ajenas |

Un resultado positivo de `nft --check`, tests con mocks o XML bien formado no
satisface esta matriz. La verificación real y su vínculo de evidencia al arranque
son trabajo pendiente; hasta entonces ACTIVACIÓN sigue bloqueada.

## Tests unitarios: no ejecutados

Los tests cubren validación negativa, XML, scope/allowlist del render y estados,
fallos y argv fijo mediante mocks; no importan la app legacy ni ejecutan nft real.
No confundir búsquedas de texto en reglas con un modelo de semántica del kernel.

Solo ejecutarlos con **todos** los controles de `security-audit`: sandbox de SO
con red externa denegada (loopback aislado solo si hace falta), entorno inicialmente
vacío con allowlist, HOME/TMP/cachés en scratch, repo y toolchain RO, escritura
únicamente en scratch y límites explícitos de CPU, RAM, procesos, tamaño de
archivo, disco y tiempo. No instalar dependencias. Invocación orientativa dentro
del sandbox ya preparado: `python -B -m unittest discover -s tests/hardening -p test_isolation.py`.
Límites sugeridos para unit tests: 1 CPU, 256 MiB RAM, 16 procesos, 8 MiB por archivo,
32 MiB scratch, 15 s CPU y 30 s wall. El laboratorio KVM requiere un harness de
hipervisor separado y recursos mayores explícitamente acotados, no acceso al host
real del agente. Este entorno no acredita esos controles: pruebas NO ejecutadas.
