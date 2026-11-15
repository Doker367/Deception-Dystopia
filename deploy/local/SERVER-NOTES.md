# Dystopia en greencode2 (100.100.229.7 / Tailscale)

## Operación

- Arranque:   sudo systemctl start dystopia.service
- Parada:     sudo systemctl stop dystopia.service
- Estado:     sudo systemctl status dystopia.service
- Logs:       sudo journalctl -u dystopia.service -f
- Panel:      http://100.100.229.7:8082/app  (SOLO Tailscale)
- Local:      http://127.0.0.1:8082/app
- Usuario:    lab (admin). Contraseña en .admin-password (0600).

`dystopia.service` ejecuta Compose con `docker-compose.yml` +
`docker-compose.remote.yml` y luego aplica el routing de retorno por wg0.
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
- VPS: `dystopia-dnat.service` (habilitada) aplica el DNAT.
- Firewall Hostinger: falta abrir TCP 13000-15999 para los señuelos nuevos.
- Ver deploy/vps/README.md para el mapa completo de puertos.

## Notas

- Dionaea se reconstruyó desde Dockerfile.2404 (Ubuntu 24.04/Python 3.12);
  el binario actual instala en bin/dionaea y el módulo emu va desactivado.
- Routing: tabla 100, reglas desde las subredes de honeypots, `wg0` con
  `Table = off` y `AllowedIPs = 10.66.0.0/24, 0.0.0.0/0`.
