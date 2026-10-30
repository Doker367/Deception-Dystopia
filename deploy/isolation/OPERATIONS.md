# Operación de celdas contenedor: activar, verificar, parar, aislar

**Documento de procedimiento para laboratorio autorizado. No se ha ejecutado nada.**
La activación está bloqueada en código y no existe opción `force`. Este documento no
sustituye la autorización, la consola de recuperación ni la revisión de la topología.

## Estados y significado

| Estado | Significado | Lo que **no** significa |
|---|---|---|
| `configurado` | Política local cargada; nada se ha aplicado. | No hay filtros ni contención. |
| `aplicado` | `nft` aceptó la transacción exclusiva de la celda. | No verifica kernel, interfaces, rutas, conntrack, cgroups ni conectividad. |
| `degradado` | Fallo, cuarentena o verificador ausente; se requiere operador. | No es un aislamiento parcial “suficiente”. |
| `verificado` | Reservado; **nunca** lo produce este prototipo. | No se puede fabricar desde un cliente ni con un booleano. |
| detenido / parado | El controlador dejó de aceptar operaciones; las reglas no se retiran. | No implica que el honeypot esté apagado. |

## 0. Puertas previas (todas obligatorias)

1. Laboratorio Ubuntu 24.04 desechable, KVM/contenedores, red sin salida a Internet,
   LAN real, secretos ni sockets compartidos; consola de recuperación probada.
2. Inventario que demuestre que la celda `N` es contenedor y no VM, y que `dybrN`,
   `dytapN`, `dyupN`, `dy_cell_N` y las direcciones no se comparten.
3. Imagen revisada por digest, runtime aprobado, usuario no root, cuota de disco
   provisionada y logs acotados. Sin `latest`, sin pull en arranque.
4. Política root-owned en `/etc/dystopia/isolation/cell-N.json`, máximo 16 KiB, sin
   symlinks, sin escritura de grupo/otros y con un solo hardlink.
5. Separación confirmada: la celda no tiene ruta a gestión (control, Kibana,
   Elasticsearch, SSH), Internet, DNS, metadata, host ni otras celdas. Solo el
   endpoint de ingestión exacto.
6. Ningún Compose, motor legacy, autostart de contenedor, socket Docker montado ni
   `restart: always/unless-stopped`. Si algo de esto existe, abortar.

## 1. Revisión sin efectos

Desde una copia revisada, sin privilegios:

```sh
python3 -m runtime.isolation plan-container --policy deploy/isolation/cell-container.example.json
```

Salida esperada: `state: configurado`, `containment_verified: false`,
`activation_allowed: false`, un manifiesto con `deployment_errors` y reglas nft.
Sustituir `image: null` por el digest revisado antes de cualquier `apply`. Revisar:

- tabla `bridge dy_cell_N` y ausencia de `flush`, `delete`, `replace`, NAT o `table ip`;
- un único bridge/tap/uplink y una sola celda;
- `mgmt_networks` sin solapamiento con `192.0.2.0/24` ni con la IP de la celda;
- servicios exactos y endpoint de ingestión exacto;
- límites de memoria, pids, CPU, capa escribible, logs y tmpfs;
- `docker_socket: false`, rootfs de solo lectura, usuario no root y caps vacías.

Este paso no aplica nada y no es una verificación.

## 2. Activación de filtros (solo laboratorio autorizado)

Copiar la política revisada a la ruta fija root-owned. Después, con autorización
explícita y consola de recuperación:

```sh
python3 -m runtime.isolation apply --cell N --confirm CELL-N-APPLY
# o, si se revisó la plantilla systemd:
systemctl start dystopia-isolation-apply@N.service
```

`apply` es one-shot y exige un controlador nuevo. Para una celda contenedor:

- si `deployment_errors()` no está vacío, **no instala** la tabla, queda `degradado`
  y eleva error; no se continúa al arranque del honeypot;
- si `nft` rechaza la transacción, intenta cuarentena aditiva y queda `degradado`;
- si la tabla `dy_cell_N` ya existe, no se adopta ni se reemplaza; el fallo es visible.

El éxito solo significa “transacción aceptada”. **No arrancar el contenedor todavía.**

## 3. Verificación independiente (bloqueada en el prototipo)

`verify()` y `activate()` siempre fallan con `ActivationBlocked`, para VM y para
contenedor. No hay verificador de kernel/topología/workload. Para levantar el bloqueo
se requiere un harness externo, separado del proceso web y del propio helper, que
produzca evidencia fresca y ligada al arranque:

- captura en host/gateway/otra celda, no solo la salida de un comando dentro del
  contenedor;
- reglas y contadores leídos del kernel, con alcance por celda;
- pruebas positivas y negativas de la matriz de [LAB-TESTS.md](LAB-TESTS.md);
- identidad del host, boot, imagen, política y cuota verificadas de forma independiente;
- revisión humana y registro de evidencia; un booleano de cliente no basta.

Hasta entonces, no se inicia el honeypot contenedor. La mera ausencia de errores en
`plan-container`, `nft --check` o `systemd-analyze` no cambia el estado.

## 4. Arranque del honeypot (fuera de este repositorio)

Solo después de la verificación independiente y de una autorización separada. El
runtime debe aplicar el manifiesto revisado: rootfs read-only, usuario no root,
`no-new-privileges`, `cap_drop=ALL`, seccomp, sin socket Docker, sin PID/IPC/UTS del
host, sin puertos publicados, sin NAT, sin DNS, sin ruta por defecto, NIC en `dybrN`
y link down hasta el attach explícito. No se usa Compose ni el motor legacy. Este
repositorio no contiene el comando de arranque ni lo ejecuta.

## 5. Parada

1. Cuarentena de red primero: tabla aditiva `dy_quarantine_N`, sin tocar `dy_cell_N`.
2. Confirmar que no hay tráfico de la celda (captura y contadores).
3. Solo entonces, con la herramienta del runtime autorizada, parar **el contenedor
   exacto** de esa celda. No parar contenedores ajenos, no usar `docker system prune`,
   no matar por nombre/PID ni reiniciar el host como atajo.
4. Conservar tabla, logs, imagen, cuota y evidencia. La parada del controlador no
   retira reglas.

Si la cuarentena no se confirma, el estado es `degradado` y se eleva error. No se
destruye el contenedor ni se “limpia” el host para ocultar el fallo.

## 6. Cuarentena y emergencia

```sh
python3 -m runtime.isolation quarantine --cell N --confirm CELL-N-QUARANTINE
python3 -m runtime.isolation emergency --cell N --confirm CELL-N-EMERGENCY
# o:
systemctl start dystopia-isolation-quarantine@N.service
```

- La cuarentena es **aditiva**: crea/usa `dy_quarantine_N` con drops tempranos y no
  borra ni reemplaza la tabla de la celda. Si la tabla ya existe o `nft` falla, se
  informa `degradado` y “cuarentena NO confirmada”; no se infiere integridad.
- Debe cortar también conexiones ya abiertas. Verificarlo con captura, no con la
  salida del comando.
- La emergencia es cuarentena de red, **no** apagado del hipervisor ni del host. Si
  hay VMs o contenedores heredados, un administrador debe identificarlos y pararlos
  con la herramienta autorizada; no se acepta matar por PID ni por prefijo.
- No se ejecuta `flush ruleset`, `iptables -F`, `nft delete table` global, borrado de
  bridges por prefijo ni limpieza de volúmenes compartidos.

## 7. Persistencia y reconciliación sin autostart

- Las tablas nft no tienen propietario persistente ligado al proceso y se pierden al
  reiniciar el host. Un reinicio del controlador no las retira; una tabla existente no
  se adopta a ciegas.
- Las plantillas `dystopia-isolation-apply@.service` y
  `dystopia-isolation-quarantine@.service` **no tienen `[Install]`**. No se habilitan,
  no se añaden `Wants=`/`Requires=` de arranque y no se usan como reconciliación
  automática. `systemctl start` es una acción explícita del operador.
- El contenedor no debe tener política de reinicio automático. No hay `restart: always`
  ni `unless-stopped`; no hay Compose. Un reinicio del runtime no debe volver a
  conectar la NIC ni arrancar el honeypot sin una nueva revisión.
- Tras un reboot: inventariar celdas, comprobar que no hay autostart, revisar política,
  imagen, cuota y estado del contenedor; aplicar de nuevo solo con autorización fresca
  y volver a verificar. No se reconstruye el estado a partir de “la unidad existe” ni
  de un `systemctl is-enabled` inesperado.
- No hay script de reconciliación automática. Si se crea uno en el futuro, debe ser
  read-only por defecto, por celda, sin `flush`, sin adopción de tablas y con
  confirmación explícita.

## 8. Limpieza acotada (nunca global)

Prohibido por diseño:

- `nft flush ruleset`, `iptables -F`, `nft delete table` por prefijo o por “todas”;
- `docker system prune`, `docker network prune`, `docker volume prune`;
- borrar `/var/lib/dystopia/cells/*`, bridges `dybr*`, taps `dytap*` o cuotas por patrón;
- parar unidades o matar procesos ajenos para “dejar limpio” el host;
- reinstalar/restaurar el motor legacy o Compose para recuperar conectividad.

La retirada de una tabla, bridge, veth, contenedor, volumen o cuota concretos es una
operación manual posterior, con la celda parada/cuarentenada, inventario exacto,
autorización separada y evidencia conservada. Se inspecciona el nombre/owner/UUID
exacto; nunca se borra por prefijo. No se retiran reglas de otras celdas.

## 9. Disco, cuotas y saturación

- Comprobar la cuota de proyecto y el uso antes de arrancar; `du` y
  `xfs_quota`/`repquota` son lectura, no cambios.
- Si la cuota se llena, el honeypot debe fallar de forma controlada y conservar
  evidencia; no se amplía la cuota ni se borra el volumen sin autorización.
- Los logs tienen tope y rotación; no se envían a un volumen sin cuota ni se copian
  fuera sin revisar contenido hostil.
- Memoria/pids/CPU se limitan por cgroup v2; una saturación no debe afectar al host,
  a gestión ni a otras celdas. Verificarlo en laboratorio.

## 10. Rollback

Mantener la celda en cuarentena, conservar tabla/logs/imagen/cuota y restaurar la
política revisada en frío. No se hace `flush`, no se borra por prefijo, no se vuelve
al arranque heredado y no se reintroduce Compose. Cualquier retirada de artefactos
exige inventario y autorización separada.
