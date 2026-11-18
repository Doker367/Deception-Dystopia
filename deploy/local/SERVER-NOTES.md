# Dystopia en greencode2 (100.100.229.7 / Tailscale)

## Operación

- Arranque:   sudo systemctl start dystopia.service
- Parada:     sudo systemctl stop dystopia.service
- Estado:     sudo systemctl status dystopia.service
- Logs:       sudo journalctl -u dystopia.service -f
- Panel:      http://100.100.229.7:8082/app  (SOLO Tailscale)
- Local:      http://127.0.0.1:8082/app
- Usuario:    lab (admin). Contraseña en .admin-password (0600).

### Puertos públicos (migración 2026-11-16, casi completa)

Ver `docs/MIGRACION-PUERTOS.md`. Resumen:

- SSH administrativo VPS: `22022` (el `22` ya es Cowrie).
- Web real: `8080`/`8443` (los sitios siguen también en `80`/`443` hasta la
  Origin Rule de `ferreteriashector.com`, pendiente el 2026-11-17).
- Señuelos activos: `22`, `23`, `21`, `2222`, `2223`, `6379` en la VPS →
  puertos internos `12222`, `12223`, `14021`, `17222`, `13022`, `16379` en
  `10.66.0.3`. `80` → trampa HTTP de OpenCanary se activa al liberar nginx.
- Trampa HTTP: publicada en `10.66.0.3:8080` (`DYSTOPIA_HTTP_TRAP_PORT` /
  `DYSTOPIA_HTTP_TRAP_BIND` en `deploy/local/.env`); único puerto HTTP
  publicado. Requiere la regla ufw de `docs/MIGRACION-PUERTOS.md`. Diagnóstico
  completo en `docs/DIAGNOSTICO-TRAMPA-HTTP.md`.
- `443` queda cerrado (sin señuelo TLS desplegado).
- Firewall de Hostinger: 13 reglas (`443`, `22`, `80`, `4443/udp`, `22022`,
  `8080`, `8443`, `21`, `23`, `2222`, `2223`, `6379`, `Drop`). Al cerrar
  `443` quedan 12.

### Redis `6379` y `DOCKER-USER`

`/usr/local/sbin/dystopia-routing.sh` añade, después de levantar el stack:

- SNAT dinámico por subred de cada señuelo hacia `10.66.0.3` por `wg0`.
- Excepción en `DOCKER-USER` para la IP del contenedor Redis honeypot, porque
  la política del host bloquea el puerto `6379` para orígenes no privados:

```bash
iptables -I DOCKER-USER 1 -d <redis_honeypot_ip>/32 -p tcp --dport 6379 -j RETURN
```

El Redis real del host sigue protegido; la excepción es solo para la IP del
contenedor.

`dystopia.service` ejecuta Compose con `docker-compose.yml` +
`docker-compose.remote.yml` + `docker-compose.ai.yml` y luego aplica el routing
de retorno por wg0. Los modelos de IA escuchan en `0.0.0.0:8081/8091`; el
firewall solo permite loopback y la subred del control.
Los contenedores tienen `restart: unless-stopped`.

### Nunca levantes `control` sin el override remoto

`docker compose -f docker-compose.yml up -d` (o `make up` sin la variable en
`.env`) recrea `control` solo en `127.0.0.1:8082`: el panel deja de responder
en `100.100.229.7:8082` aunque el contenedor esté *healthy*.

Red de seguridad instalada: `dystopia-control-guard.timer` revisa cada minuto
que exista el listener en la IP de Tailscale y, si falta, reaplica el override
remoto solo al servicio `control` (no toca el resto ni arranca el stack si
está parado). Logs: `journalctl -t dystopia-control-guard`.

## Señuelos y VPS

- Publicados en 10.66.0.3 (wg0); la VPS hace DNAT y conserva la IP real.
- El panel NO está en wg0 ni en internet.
- VPS: `dystopia-dnat.service` aplica el DNAT desde `/etc/dystopia/dnat.map`.
- Firewall Hostinger: reglas para los puertos públicos nuevos; ver
  `docs/MIGRACION-PUERTOS.md`.

## Notas

- Dionaea se reconstruyó desde Dockerfile.2404 (Ubuntu 24.04/Python 3.12);
  el binario actual instala en bin/dionaea y el módulo emu va desactivado.
- Routing: tabla 100, reglas desde las subredes de honeypots, `wg0` con
  `Table = off` y `AllowedIPs = 10.66.0.0/24, 0.0.0.0/0`.
