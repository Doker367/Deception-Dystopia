# Celdas de honeypot contenedorizado: diseño y límites

**No es un despliegue.** Esta página describe el contrato declarativo, la separación
de redes y los límites de recursos. `runtime.isolation` valida y renderiza, pero no
crea bridges, veths, contenedores, cgroups ni cuotas. La activación sigue bloqueada.

## Modelo de celda exclusiva

Una celda `N` (`1..254`) es **una** de estas dos cosas:

- una VM KVM definida por [deploy/cell.example.json](../cell.example.json), o
- un honeypot contenedorizado definido por [cell-container.example.json](cell-container.example.json).

Nunca ambas. Por eso comparten, de forma exclusiva, `dybrN`, `dytapN`, la tabla
`dy_cell_N` y las direcciones `192.0.2.N` / `fd42:d570::N`. Si el inventario no
puede demostrar la exclusividad, no se aplica ninguna política. No hay descubrimiento
automático de topología ni asignación de IDs desde un cliente.

## Esquema de `ContainerCellPolicy`

Claves exactas; una clave desconocida, ausente, duplicada o con tipo booleano donde
se espera entero se rechaza. El archivo gestionado tiene un máximo de 16 KiB y debe
ser root-owned, sin symlinks, sin escritura de grupo/otros y con un solo hardlink.

| Campo | Tipo | Regla |
|---|---|---|
| `version` | entero | Exactamente `1`. |
| `cell` | entero | `1..254`; debe coincidir con `cell-N.json`. |
| `workload` | cadena | Exactamente `container`. |
| `bridge` | cadena | Exactamente `dybrN`; bridge dedicado, sin IP de host. |
| `gateway_mac` | cadena | MAC unicast, fuera del rango señuelo `02:00:00:00:00:*`. |
| `profile` | objeto | `name`, `image`, `services`; ver abajo. |
| `ingest` | objeto | Un único endpoint TCP con IP literal y puerto exacto. |
| `mgmt_networks` | lista | CIDR canónicos; no pueden solaparse con deception ni contener la IP de la celda, sus servicios o ingestión. |
| `memory_mib` | entero | `256..4096`. |
| `vcpus` | entero | `1..4`; se traduce a `CPUQuota=100%..400%`. |
| `pids` | entero | `16..1024`; límite de procesos del contenedor. |
| `run_as_uid` | entero | `1..65535`; nunca UID 0. |
| `writable_mib` | entero | `16..10240`; cuota de la capa/escribible por celda. |
| `log_mib` | entero | `8..1024`; tamaño máximo de logs por celda. |
| `tmpfs_mib` | entero | `8..256`; `nosuid,nodev,noexec`. |
| `read_only_root` | booleano | Debe ser `true`. |
| `no_new_privileges` | booleano | Debe ser `true`. |
| `drop_all_capabilities` | booleano | Debe ser `true`. |
| `docker_socket` | booleano | Debe ser `false`; no se admite socket del runtime. |

`profile`:

| Campo | Regla |
|---|---|
| `name` | Uno de `cowrie`, `opencanary`, `dionaea`, `heralding`, `redishoneypot`, `endlessh`. |
| `image` | `null` en diseño, o `referencia@sha256:<64 hex>` revisada. Se rechazan tags sin digest, `latest` y el digest todo ceros. |
| `services` | `1..16` endpoints inmutables `{address, protocol, port}`; IP literal, solo TCP/UDP, sin duplicados. Son los **únicos** flujos entrantes autorizados. |

`deployment_errors()` exige un digest de imagen revisado antes de `apply`. Un ejemplo
con `image: null` sirve para revisar el render, no para desplegar. `apply` rechaza una
política contenedor que no esté lista y queda `degradado`, sin instalar tabla.

## Perfiles y puertos

El nombre del perfil es una etiqueta de inventario, no una decisión de confianza ni
una lista implícita de puertos. Los puertos se declaran siempre de forma explícita en
`services`. Recomendaciones de laboratorio, sujetas a revisión del operador:

| Perfil | Puertos habituales (solo los declarados) |
|---|---|
| `cowrie` | `2222/tcp` SSH; opcional `2223/tcp` telnet. |
| `opencanary` | Subconjunto revisado de `21, 22, 23, 80, 443, 3306, 3389, 5900, 6379, 9418/tcp` y `123, 161, 5060/udp`. |
| `dionaea` | Subconjunto revisado de `21, 42, 80, 135, 443, 445, 1433, 3306, 5060, 5061/tcp` y `69/udp`. |
| `heralding` | Subconjunto revisado de protocolos soportados por la imagen (FTP, SSH, telnet, HTTP/S, SMTP, POP3, IMAP, VNC, RDP, MySQL, PostgreSQL, etc.). |
| `redishoneypot` | `6379/tcp`. |
| `endlessh` | `2222/tcp` o el puerto configurado y declarado. |

No se publican puertos al host, no se usa NAT, no se usa `host` networking y no se
añade un rango amplio “por comodidad”. Cada puerto extra amplía la superficie y debe
justificarse.

## Tráfico y tabla por celda

`container_nft_rules(policy)` construye una `CellPolicy` interna y delega en el mismo
render que las VM. No hay una segunda implementación de firewall que pueda divergir.

- Tabla exclusiva `bridge dy_cell_N`; cuarentena aditiva `bridge dy_quarantine_N`.
- `create table` exclusivo. Nunca `flush ruleset`, `delete`, `destroy`, `replace`,
  `masquerade`, `snat`, `dnat`, `table ip` ni `table inet`.
- Cadenas host `input`/`output` y `forward`; drops explícitos solo en `dytapN`/`dyupN`.
- Filtro temprano L2: bridge correcto, EtherType IPv4/IPv6, sin VLAN, sin fragmentos
  IPv4, sin extensiones IPv6 distintas de TCP/UDP y sin ARP/ND/RA/DHCP/ICMP.
- Forward únicamente `dytapN ↔ dyupN`, con MAC/IP de origen y destino exactas, zona
  conntrack por celda y marca de flujo.
- Entrada solo desde la IP literal del cliente al puerto/protocolo exacto; respuestas
  solo `ct state established` con la marca de esa celda. Sin `related` global, sin
  helpers, sin DNS y sin salida implícita.
- Salida solo al endpoint de ingestión exacto, TCP, con límite por regla de 10 paquetes/s
  y ráfaga 20, incluidas respuestas. No es un límite agregado de bytes ni un control de
  contenido: un honeypot comprometido puede enviar datos arbitrarios a ese endpoint.
  El colector debe ser dedicado, autenticado y con cuotas propias.

La política no verifica que el bridge, el tap, el uplink o el contenedor existan. Esa
comprobación y la captura de tráfico son pruebas de laboratorio externas.

## Contenedor y runtime

El manifiesto declarativo (`container_manifest`) exige o recomienda:

- rootfs de solo lectura, usuario no root, `no-new-privileges`, `cap_drop=ALL`,
  seccomp revisado, sin dispositivos, sin PID/IPC/UTS del host y sin socket Docker.
- rootless cuando la imagen y el runtime lo permitan; si no, un usuario de servicio
  dedicado y una revisión explícita.
- imagen por digest, descargada y revisada **fuera de línea**; nunca `latest` ni pull
  en el arranque del honeypot.
- sin puertos publicados, sin NAT, sin red de host, sin DNS y sin ruta por defecto.
  Solo la ruta estática al endpoint de ingestión y los vecinos estáticos del bridge.
- link down al definir la interfaz; el operador la conecta solo después de la
  verificación independiente y la autorización. No hay arranque automático.

No se incluye un `docker run`, un unit de arranque de contenedor ni un Compose. El
runtime es una dependencia externa y su configuración debe revisarse por separado.

## Límites de recursos y cuotas de disco

Los campos son declarativos; **este módulo no aplica ni comprueba ninguno**. El
operador debe provisionarlos y verificar su vigencia en el laboratorio.

| Recurso | Campo | Límite de ejemplo | Aplicación externa exigida |
|---|---|---|---|
| Memoria | `memory_mib` | `512` | cgroup v2 `memory.max` (`MemoryMax`). |
| Procesos | `pids` | `128` | cgroup v2 `pids.max` (`TasksMax`). |
| CPU | `vcpus` | `1` | cgroup v2 `cpu.max` (`CPUQuota=100%`). |
| Capa escribible | `writable_mib` | `256` | Cuota de proyecto XFS/ext4, `project_id=10000+N`. |
| Logs | `log_mib` | `64` | Volumen/cuota separada y rotación; nunca logs ilimitados. |
| `/tmp` | `tmpfs_mib` | `32` | tmpfs con `nosuid,nodev,noexec`. |
| FDs | fijo | `1024` | `LimitNOFILE`. |
| Core dump | fijo | `0` | `LimitCORE=0`. |
| Tamaño de archivo | `log_mib` | `64 MiB` | `LimitFSIZE`. |

Requisitos:

- La cuota de disco se provisiona por celda y se comprueba antes de arrancar. Un
  disco lleno debe hacer fallar el honeypot de forma controlada, no llenar el host.
- La capa de imagen y los logs no comparten un volumen sin cuota con el host.
- `du`, `xfs_quota`/`repquota` y los contadores del runtime se revisan como evidencia;
  no se cambian cuotas del host desde este repositorio.
- No se usa `docker system prune`, `docker network prune` ni borrado por prefijos.
- La saturación de memoria/procesos/CPU se prueba con el contenedor aislado y límites
  del host explícitos; no se acepta “el cgroup existe” como prueba de contención.

## Gestión, Elasticsearch y credenciales

- Elasticsearch y Kibana solo escuchan en el plano de gestión; no hay ruta desde una
  celda contenedor. Su configuración (bind, TLS, usuarios, índices) es un cambio de
  infraestructura separado y no se modifica en `deploy/isolation/`.
- El servicio de ingestión corre en el plano de telemetría y usa una identidad de
  escritura dedicada para Elasticsearch. Esa identidad no administra el clúster, no
  accede a Kibana y no se comparte con el control.
- Cada honeypot recibe únicamente su token de ingestión por sensor. No recibe
  credenciales de Elasticsearch/Kibana, JWT de administración, CA privada, base central
  ni credencial de otra celda.
- La rotación/revocación del token de sensor y la de la identidad de escritura de
  ingestión son independientes. No hay periodo de gracia implícito ni secreto común.
- Los ejemplos no contienen secretos. Cualquier credencial se provisiona fuera de
  banda, con propietario/permisos exclusivos, y nunca se imprime en logs.

## Secuencia de provisión (offline, no ejecutada aquí)

1. Revisar imagen, licencia, digest, dependencias y puertos; descargarla en un paso
   offline aprobado. No usar `latest`.
2. Crear directorio de estado root-owned, usuario de servicio no root y cuota de
   proyecto por celda. No montar el socket del runtime ni directorios del host.
3. Configurar bridge dedicado `dybrN` sin IP de host, veth `dytapN`, uplink `dyupN`,
   vecinos/rutas estáticos y link down.
4. Instalar la política root-owned `/etc/dystopia/isolation/cell-N.json` con el digest
   revisado; sin symlinks ni escritura ajena.
5. Ejecutar `plan-container` y revisar manifiesto, reglas nft y errores de despliegue.
   Esto no aplica nada.
6. Solo con autorización de laboratorio, aplicar la tabla exclusiva y ejecutar el
   verificador externo. La activación del honeypot sigue bloqueada hasta que exista
   evidencia independiente.
7. Si se autoriza el arranque del contenedor, hacerlo con el runtime revisado, sin
   autostart, con la NIC en el bridge de la celda y sin publicar puertos. No usar
   Compose ni el motor legacy.

## No afirmaciones

Un JSON parseado, un XML bien formado, una unidad systemd válida, un `nft --check`
correcto, una red `internal=true`, una VLAN o un contenedor “arrancado” no prueban
aislamiento. La matriz de [LAB-TESTS.md](LAB-TESTS.md) y la evidencia externa siguen
pendientes; hasta entonces la activación permanece bloqueada.
