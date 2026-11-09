# Migración a DNAT sin pérdida de la IP de origen (Ola 4A)

**Estado: configuración versionada, NO evidencia de despliegue.** Ningún cambio de este
repositorio prueba que la VPS, el firewall del proveedor, WireGuard, UFW o los
contenedores ya estén configurados. Ejecutar los pasos solo con autorización,
consola fuera de banda y plan de reversión. El laboratorio de
[Compose local](../local/README.md) **no** acredita aislamiento Linux ni autoriza
activar celdas: verificar previamente aislamiento, permisos de volúmenes y
política de egreso para contenedores. Esto no modifica el gate ni habilita `apply`
(sigue en 409); no reescribir eventos históricos.

```text
cliente externo (IP pública) → VPS:puerto TCP → DNAT (sin SNAT)
→ wg0 10.66.0.1 → servidor wg0 10.66.0.3:puerto
→ DNAT de Docker → señuelo → respuesta marcada → tabla 100 → wg0 → VPS → cliente
```

| TCP en VPS y servidor WG | Señuelo |
|---|---|
| 12222, 12223 | Cowrie SSH, Telnet |
| 13022, 13080 | OpenCanary SSH, HTTP |
| 14021 | Dionaea FTP |
| 15021 | Heralding FTP |
| 16379 | RedisHoneyPot |
| 17222 | Endlessh SSH |

**Solo esos ocho puertos TCP.** Nada de rangos `13000:15999`, puertos adicionales,
UDP nuevo, `8082`, SNAT/MASQUERADE ni reglas IPv6 implícitas. Confirmar que el
proveedor NO publica IPv6 para estos servicios o documentar y revisar su ruta
independientemente antes de activar la exposición.

## Antes del cambio (ambos hosts)

- Confirmar acceso a consola de recuperación del proveedor y a consola del
  servidor fuera de WireGuard; identificar servicios nginx **stream** de esos
  ocho puertos sin tocar otros vhosts ni el acceso administrativo. Guardar en
  el host (fuera de Git) la configuración previa de nginx, UFW, sysctl,
  WireGuard, `iptables-save`, `ip -4 rule` y `ip -4 route show table 100`.
- Auditar FORWARD y DOCKER-USER y exigir que la política de egreso del
  contenedor impida conexiones **NEW** no autorizadas hacia Internet/LAN; las
  respuestas **ESTABLISHED** al cliente deben poder salir por wg0. Publicar
  un puerto Docker no lo protege mediante reglas UFW INPUT. No usar este
  runbook para poner públicamente en marcha las imágenes del lab si falta
  aislamiento Linux aprobado; no ejecutar `apply` ni saltarse el gate.
- Reservar exclusivamente la tabla 100, prioridad 10010 y bits de marca
  `0x0000ff00` para este servicio. Comprobar que el firewall de la VPS tiene
  política routed denegada por defecto y que las reglas de administración
  existentes no dependen de nginx stream. Mantener el acceso SSH/Tailscale.
- Validar la versión de Compose que entiende `ports: !override`; si no es
  compatible, detener la migración: nunca sustituirlo por un merge de puertos
  que vuelva a publicar el panel en otra interfaz.

## Servidor Linux (antes de habilitar DNAT en la VPS)

1. En la configuración **local no versionada** de `wg0`, mantener la dirección
   `10.66.0.3/24`; en el peer de la VPS establecer `AllowedIPs = 10.66.0.0/24,
   0.0.0.0/0` y en `[Interface]` `Table = off`. Usar como referencia
   [wg0-peer.example.conf](../server/wg0-peer.example.conf); **nunca** copiar
   claves ni Endpoint reales al repositorio. En la VPS, el peer de este servidor
   debe permitir `10.66.0.3/32`. Planificar el reinicio de `wg-quick@wg0` con
   consola fuera de banda, comprobar el handshake y que la ruta por defecto de
   la tabla principal del servidor no cambió.
2. Instalar [dystopia-wg-return.sh](../server/dystopia-wg-return.sh) en
   `/usr/local/sbin/` con modo `0750` y
   [dystopia-wg-return.service](../server/dystopia-wg-return.service) en
   `/etc/systemd/system/`. `systemctl daemon-reload`; ejecutar primero
   `dystopia-wg-return.sh check` y solo después `systemctl start
   dystopia-wg-return.service`. Habilitar en arranque **solo tras** validar la
   topología real. El preflight exige `ip_forward=1` también en el servidor
    para el trayecto wg0→bridge, sin cambiar ese valor. El servicio ajusta
    `wg0.rp_filter=2` (modo loose: necesario
   cuando la ruta inversa principal a Internet va por WAN), instala una ruta
   `default dev wg0` **solo en tabla 100** y una regla para fwmark
   `0x6600/0x0000ff00`. Marca el conntrack de los ocho destinos que entran por
   wg0 y marca el paquete **solo en dirección REPLY al entrar por un bridge
   Docker `br-*`**. Confirmar con `ip -o link show type bridge` que los bridges
   efectivos de Compose tienen ese prefijo; si no, detenerse y revisar el
   filtro antes de abrir los puertos. No marca los paquetes de entrada:
   eso podría reenviarlos erróneamente a wg0.
   No afecta a la ruta principal, al tráfico normal del panel ni a los
   paquetes NEW salientes de los contenedores.
3. Preparar la [variante remota](../local/docker-compose.remote.yml) solo en
   un entorno Linux con contención autorizada. Asignar
   `DYSTOPIA_TAILSCALE_IP` a la IPv4 de **este servidor** en `.env` privada;
   no versionar `.env`, JWT, `.token` ni la base GeoLite2. Instalar la base
   `GeoLite2-City.mmdb` actualizada en `deploy/local/geoip/` del servidor,
   legible por el usuario del control. El compose base mantiene los ocho
   puertos de señuelo en loopback; el override añade exactamente esos ocho
   bindings en `10.66.0.3`, y reemplaza los puertos del panel por
   `127.0.0.1:8082` y la IPv4 Tailscale `:8082` exclusivamente. Verificar
   la configuración efectiva **antes de arrancar** con
   [check-compose-bindings.py](../server/check-compose-bindings.py). Ejecutar
   desde `deploy/local/` en una terminal privada (el pipe contiene un JWT
   interpolado; no imprimirlo ni guardarlo):

   ```bash
   set -o pipefail
   docker compose --env-file .env -f docker-compose.yml -f docker-compose.remote.yml \
     config --format json | DYSTOPIA_TAILSCALE_IP="$(tailscale ip -4)" \
     python3 ../server/check-compose-bindings.py
   ```

   Un FAIL impide publicar. Tras arrancar, inspeccionar `ss -lntp` y
   `docker inspect` fuera de Git. La política FORWARD/DOCKER-USER efectiva debe
   restringir el panel a `tailscale0` y loopback: **UFW INPUT no basta** para
   un puerto publicado por Docker. No permitir `8082` por WAN ni wg0; probar
   denegación externa de `8082` antes y después del cambio, y revisar que
   Docker no habilite direct routing público a la red del contenedor.

## VPS (después de validar el servidor)

1. Instalar [90-dystopia-forward.conf](90-dystopia-forward.conf) en
   `/etc/sysctl.d/`, aplicar `sysctl -p /etc/sysctl.d/90-dystopia-forward.conf`
   y comprobar `net.ipv4.ip_forward=1`. En UFW **routed/FORWARD**, autorizar
   exclusivamente los ocho TCP con origen en la interfaz WAN y salida por
   wg0 a `10.66.0.3`; el tráfico de retorno debe ser ESTABLISHED. Por ejemplo,
   sustituyendo la interfaz **en la VPS** (no versionar el valor):

   ```bash
   read -r -p 'Interfaz WAN de la VPS: ' WAN_IF
   for p in 12222 12223 13022 13080 14021 15021 16379 17222; do
     sudo ufw route allow in on "$WAN_IF" out on wg0 to 10.66.0.3 port "$p" proto tcp
   done
   sudo ufw status verbose
   ```

   No basta con `ufw allow PORT/tcp` (INPUT no es FORWARD). No abrir un rango
   completo. En el firewall **del proveedor**, crear o confirmar exactamente
   las mismas ocho entradas TCP IPv4; es un paso manual externo al repositorio.
2. Instalar [dystopia-dnat.sh](dystopia-dnat.sh) con modo `0750`, la
   [unidad](dystopia-dnat.service) en `/etc/systemd/system/`, y copiar
   [dnat.env.example](dnat.env.example) a `/etc/dystopia/dnat.env` con modo
   `0600`. Sustituir los placeholders **solo en la VPS**: `WAN_IF` es la
   interfaz de llegada e `VPS_INGRESS_IP` es la IPv4 **asignada localmente**
   que recibe la conexión tras cualquier NAT del proveedor. La comprobación
   previa rechaza una IP no asignada a esa interfaz, una tabla sin ruta por
   wg0 o `ip_forward=0`. Ejecutar `systemctl daemon-reload`,
   `dystopia-dnat.sh check` y luego `systemctl start dystopia-dnat.service`;
   comprobar contadores en la cadena `DYSTOPIA_DNAT`. Esta regla solo hace
   DNAT de los ocho TCP; no usa SNAT ni altera la administración de nginx.
3. Mantener inicialmente el stream anterior como rollback. Tras comprobar el
   resultado extremo a extremo, eliminar **solo** las directivas `stream`
   de estos ocho listeners y recargar nginx con `nginx -t` seguido de reload;
   no deshabilitar nginx completo si gestiona otros servicios. Reaplicar y
   verificar el servicio DNAT tras cualquier `ufw reload` que afecte reglas.
   Habilitar las dos unidades en arranque solo tras prueba positiva y
   verificación de recuperación ante reinicio en una ventana aprobada.

## Verificación obligatoria de aceptación (por operador autorizado)

1. Desde una **máquina externa real**, no desde la VPS, servidor, WG ni
   Tailscale, anotar privadamente su IP pública de egreso y estado/provincia
   esperado por la base GeoIP; no publicar ninguno de los dos junto con los
   tokens. Anotar hora UTC anterior al estímulo. Conectar **una vez** a uno
   de los ocho puertos mediante un cliente benigno (Cowrie SSH: enviar banner
   `SSH-2.0-check` al puerto `12222`). Anotar hora UTC posterior, esperar el
   poll del colector (~10 s). No usar pruebas de penetración ni escaneos
   masivos contra infraestructura ajena.
2. Desde el servidor, con JWT de una **sesión humana** autorizada y ventana
   UTC de máximo 10 minutos, ejecutar
   [verify-source-ip.py](../server/verify-source-ip.py), alimentando por
   variables locales `DYSTOPIA_API_TOKEN`, `EXPECTED_SOURCE_IP`,
   `EXPECTED_COUNTRY_CODE`, `EXPECTED_REGION_CODE`, `PROBE_FROM_UTC` y
   `PROBE_TO_UTC`. El verificador consulta **solo el loopback del servidor**:
   `/api/analytics/events` (busca `source` igual a la IP pública externa,
   `countryCode` y `regionCode`) y `/api/analytics/origins` (país/estado,
   coordenadas y eventos). Devuelve PASS/FAIL sin imprimir direcciones, JWT ni
   respuesta cruda. El campo `ip` de un grupo de orígenes es representativo,
   no la lista completa de IPs; por ello se compara `source` en **events**.
   Una IP privada `10.66.0.1` o la IP de la VPS **no** satisface el resultado.
3. Validar en captura controlada (fuera de Git) que la dirección origen del
   paquete no cambió al cruzar VPS→wg0→Docker, y que las respuestas vuelven
   por wg0, no por el WAN del servidor. Comprobar región GeoIP y mapa para
   una IP externa estadounidense con subdivisión conocida; la cobertura de
   provincias de México/Canadá corresponde a una fase distinta. Comprobar
   que `8082` **no** es accesible desde Internet ni desde wg0 y **sí** desde
   loopback y Tailscale. Sin esta evidencia externa la migración permanece
   **pendiente**, aunque pasen las pruebas unitarias.

## Rollback dirigido

1. VPS: `systemctl stop dystopia-dnat.service` (elimina únicamente su salto
   PREROUTING y su cadena NAT). Restaurar el stream previo de esos ocho
   listeners y recargar nginx. Si se habilitó en arranque, deshabilitar la
   unidad. Revocar en el proveedor **solo** las ocho aperturas añadidas por
   este cambio y borrar **solo** las reglas UFW routed propias, contrastando
   con la captura de configuración inicial; no borrar la política SSH/WG.
2. Servidor: `systemctl stop dystopia-wg-return.service` (elimina solo marca,
   regla de prioridad 10010 y ruta por wg0 de tabla 100). Retirar el override
   remoto y volver a las publicaciones de loopback anteriores cuando proceda,
   sin detener el colector ni borrar su SQLite. Restaurar la configuración
   WireGuard y el valor anterior de `wg0.rp_filter` desde el snapshot; no
   vaciar tablas ni cadenas de Docker ni reescribir eventos antiguos.
3. VPS: retirar **solo** `/etc/sysctl.d/90-dystopia-forward.conf` si fue
   instalado por este cambio, o restaurar su contenido anterior guardado.
   Volver a aplicar el valor **anterior** de `net.ipv4.ip_forward` en vivo
   únicamente si ningún otro servicio necesita forwarding; verificar también
   el valor **persistente** tras `sysctl --system` en ventana aprobada y tras
   reinicio. Comprobar acceso de administración y conectividad normal antes
   de cerrar el incidente. Los eventos capturados antes del cambio conservan
   su `source` original y no se corrigen.
