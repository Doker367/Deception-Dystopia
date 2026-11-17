# Migración de puertos: SSH, web y señuelos

Estado: **casi completo** (2026-11-16). Solo queda el corte de `80/443`, que
depende de la Origin Rule de `ferreteriashector.com` en Cloudflare (pendiente
para el 2026-11-17).

## Hosts

- VPS `srv1083856`: `193.203.167.121`, WireGuard `10.66.0.1`, Tailscale
  `100.114.190.104`.
- Laboratorio `greencode2`: `100.100.229.7`, WireGuard `10.66.0.3`.

## Mapa final

| Puerto público (VPS) | Destino interno | Servicio | Estado |
|---|---|---|---|
| `22022` | sshd de la VPS | SSH administrativo | ✅ |
| `8080` | nginx :8080 | Web HTTP | ✅ |
| `8443` | nginx :8443 | Web HTTPS | ✅ |
| `22` | `10.66.0.3:12222` | Cowrie SSH | ✅ |
| `23` | `10.66.0.3:12223` | Cowrie Telnet | ✅ |
| `21` | `10.66.0.3:14021` | Dionaea FTP | ✅ |
| `80` | `10.66.0.3:13080` | OpenCanary HTTP | ⏳ al liberar nginx |
| `2222` | `10.66.0.3:17222` | Endlessh | ✅ |
| `2223` | `10.66.0.3:13022` | OpenCanary SSH | ✅ |
| `6379` | `10.66.0.3:16379` | RedisHoneyPot | ✅ |
| `443` | — | sin señuelo TLS | se cerrará |

Los puertos altos `12xxx`/`15xxx`/`16379`/`17222` ya no se publican en la VPS;
solo existen como puertos internos en el laboratorio.

## Firewall de Hostinger

13 reglas: `443`, `22`, `80`, `4443/udp`, `22022`, `8080`, `8443`, `21`, `23`,
`2222`, `2223`, `6379` y el `Drop` final. Al cerrar `443` se elimina esa regla
y quedan 12.

## Causa del fallo de `6379`

El DNAT llegaba al laboratorio, pero la cadena `DOCKER-USER` bloquea el puerto
`6379` para orígenes no privados:

```text
-A DOCKER-USER -p tcp --dport 6379 -j DROP
```

El DNAT interno apunta a `172.23.0.2:6379`, así que la política descartaba el
paquete antes de llegar al contenedor. La excepción se aplica antes del DROP:

```bash
iptables -I DOCKER-USER 1 -d 172.23.0.2/32 -p tcp --dport 6379 -j RETURN
```

Se dejó permanente en `/usr/local/sbin/dystopia-routing.sh`, que ahora también
añade el SNAT dinámico por subred de cada señuelo y resuelve la IP del
contenedor Redis con `docker inspect` (la IP puede cambiar al recrear el
stack). El Redis real del host sigue protegido; la excepción es solo para la IP
del contenedor honeypot.

## Pendiente para el 2026-11-17

1. **Cloudflare — ferreteriashector.com**: Origin Rule con Destination Port
   `8443` y condición `Scheme equals https`; activar **Always Use HTTPS**;
   SSL/TLS en **Full (strict)**.
2. **Cloudflare — manyboxenviox.com**: activar **Always Use HTTPS**. Ahora
   `http://manyboxenviox.com` devuelve `400 The plain HTTP request was sent to
   HTTPS port` porque la Origin Rule manda HTTP al `8443`.
3. **Corte de `80/443`** (lo ejecuta el operador):
   - quitar `listen 80`, `listen [::]:80`, `listen 443 ssl`,
     `listen [::]:443 ssl` de `/etc/nginx/sites-enabled/*`;
   - `nginx -t && systemctl reload nginx`;
   - descomentar `80 13080` en `/etc/dystopia/dnat.map` y reiniciar
     `dystopia-dnat`;
   - borrar la regla `443` del firewall de Hostinger.
4. **Certificados**: al liberar el 80, HTTP-01 deja de funcionar. Opciones:
   - Cloudflare Origin CA para los dominios proxied;
   - DNS-01 con token de Cloudflare;
   - bypass temporal del DNAT del 80 para los dominios directos
     (`greenalgorithm.com.mx`, `tarea1...`) durante la renovación.

## Verificación rápida

```bash
# SSH admin
ssh -p 22022 root@193.203.167.121

# Señuelos
printf 'PING\r\n' | nc -w3 193.203.167.121 6379       # +PONG
nc -w3 193.203.167.121 21                            # 220 FTP server ready
nc -w3 193.203.167.121 22                            # banner Cowrie
nc -w3 193.203.167.121 23                            # login: Cowrie
nc -w3 193.203.167.121 2223                          # banner OpenCanary

# Web
curl -sk -H 'Host: greenalgorithm.com.mx' https://193.203.167.121:8443/ -o /dev/null -w '%{http_code}\n'
```

## Rollback

- SSH: restaurar `/root/dystopia-backup-20261116-014711/` y
  `/etc/systemd/system/ssh.socket.d/10-dystopia-ports.conf`; reiniciar
  `ssh.socket`.
- DNAT: `systemctl stop dystopia-dnat.service` y restaurar
  `iptables-save.before`.
- Nginx: restaurar `/root/dystopia-backup-20261116-014711/nginx-sites/` y
  recargar.
- Laboratorio: revertir `/usr/local/sbin/dystopia-routing.sh` al respaldo y
  reiniciar `dystopia.service`.
