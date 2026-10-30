# Pruebas de laboratorio requeridas para celdas contenedor

**Estado: no ejecutadas. Esta tabla define evidencia mínima; no es un resultado.**
Ninguna prueba se ha corrido en este host. Un JSON válido, un XML, una unidad
systemd, `nft --check`, una red Docker `internal=true` o la salida de un comando
dentro del contenedor no sustituyen estas pruebas.

## Precondiciones

- Ubuntu 24.04 desechable, snapshot/restauración y consola fuera de banda probada.
- Sin ruta a Internet, LAN real, producción, secretos ni sockets compartidos.
- Una celda contenedor y, al menos, otra celda/VM y un destino de gestión de prueba.
- Imagen por digest, runtime aprobado, cuota de proyecto provisionada y logs acotados.
- Captura independiente en host, gateway y otra celda; contadores y reglas leídos del
  kernel con alcance por celda.

## Matriz

| # | Prueba | Resultado exigido | Evidencia |
|---|---|---|---|
| 1 | Cliente autorizado → puerto exacto del honeypot | Conexión y respuestas conntrack permitidas | Captura en host y contador de la celda |
| 2 | Origen no autorizado, puerto no autorizado, dirección inversa nueva | Sin paquetes entregados | Captura y contadores de drop |
| 3 | Honeypot → control, Kibana, Elasticsearch, SSH de gestión | Sin paquetes entregados | Captura en gestión y host |
| 4 | Gestión → honeypot | Sin paquetes entregados | Captura bidireccional |
| 5 | Honeypot → Internet, DNS, metadata `169.254.169.254`, host, gateway IP | Sin paquetes entregados | Captura en uplink/host |
| 6 | Honeypot → otra celda, otro tap, otro bridge o VM KVM | Sin paquetes entregados | Captura en ambas celdas |
| 7 | Honeypot → endpoint de ingestión exacto | Solo TCP al puerto exacto; autenticación por sensor | Captura y log de ingestión |
| 8 | Honeypot → ingestión con puerto/host/IP distinto o sin token | Rechazo, sin entrega | Captura y 401/403 del receptor |
| 9 | MAC/IP spoofing, IPv4-mapped IPv6, fragmentos IPv4, extensiones IPv6 | Sin bypass del allowlist | Captura y contadores |
| 10 | ARP/ND/RA/DAD/DHCP/ICMP/multicast/broadcast/STP/LLDP/EAPOL | Sin efecto L2 ni entrega | Captura en bridge y host |
| 11 | VLAN 802.1Q/QinQ y tags ocultos por offload | Sin paquetes entregados | Captura y revisión de offloads |
| 12 | Flujo previamente establecido no autorizado y `ct related`/helpers | Sin paquetes entregados | Tabla conntrack y captura |
| 13 | Cuarentena con conexiones ya abiertas | Todo tráfico de la celda detenido | Captura antes/después y contadores |
| 14 | Fallo de `nft`, tabla preexistente, doble controlador | `degradado`; no se adoptan ni modifican reglas ajenas | Estado del helper y tablas antes/después |
| 15 | `SIGKILL`/stop del controlador, pérdida de observación | Sin fail-open; reglas conservadas | Tablas del kernel y captura |
| 16 | Reinicio del host | Sin autostart de contenedor ni reconciliación implícita; documentar pérdida de tablas | Inventario, unidades, runtime y tablas |
| 17 | Reinicio del runtime/contenedor | No vuelve a conectar la NIC ni arranca solo | Inspección del runtime y captura |
| 18 | Rootfs read-only, usuario no root, `no-new-privileges`, caps vacías, seccomp | Configuración efectiva, no solo declarada | Inspección del runtime y pruebas de escritura/privilegio |
| 19 | Socket Docker, PID/IPC/UTS del host, dispositivos y puertos publicados | Ausentes o inaccesibles | Inspección del runtime y del contenedor |
| 20 | Imagen `latest`, tag sin digest, digest no revisado o pull en arranque | Rechazo antes de aplicar/arrancar | Política, manifiesto y logs |
| 21 | Memoria, pids y CPU bajo carga | Contenido dentro del cgroup; host, gestión y otras celdas estables | `memory.events`, `pids.events`, `cpu.stat`, host |
| 22 | Cuota de capa escribible y logs llenos | Fallo controlado; no se llena el disco del host | `xfs_quota`/`repquota`, `du`, logs |
| 23 | `/tmp` lleno | Fallo controlado, sin `exec`/`suid`/device | tmpfs y pruebas dentro del contenedor |
| 24 | Rotación/revocación del token de sensor | Token anterior rechazado; no afecta a otros sensores | Registro de ingestión y receptor |
| 25 | Credencial de escritura de Elasticsearch comprometida/rotada | Sin acceso de administrador ni Kibana; rotación independiente | Roles de Elasticsearch y auditoría |
| 26 | Contenedor comprometido intenta leer credenciales de gestión/otros | Sin secretos accesibles | Inspección de mounts/env/files y pruebas |
| 27 | Reglas/contadores de otras celdas antes/después | Sin mutación | Volcado comparado por celda |
| 28 | Limpieza/rollback por operador | Solo artefactos exactos de la celda; sin prefijos ni global | Inventario, diff de tablas/interfaces/volúmenes |

## Evidencia que no vale

- `nft --check` correcto, `systemd-analyze verify` correcto o JSON parseado.
- Una red `internal=true`, una VLAN, un bridge “privado” o un contenedor “sin puertos”.
- La salida de `curl`/`ping` dentro del contenedor como única prueba; se necesita
  captura externa y contadores por celda.
- Un estado `aplicado` o un log sin errores. `verificado` no lo produce el prototipo.
- Haber arrancado el honeypot una vez sin observar tráfico de fuga.

## Criterio de salida

Todas las filas aplicables deben tener evidencia independiente, revisada y ligada a
la identidad del host/boot/política/imagen. Cualquier duda de topología, cuota o
separación de gestión deja la celda en `degradado` y la activación bloqueada. La
decisión de habilitar producción es externa a este repositorio y no se deriva de
estos artefactos.
