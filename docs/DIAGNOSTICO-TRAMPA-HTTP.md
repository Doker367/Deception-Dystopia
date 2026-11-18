# Diagnóstico: la trampa no recibía ataques HTTP (2026-11-16)

## Causa raíz

Los honeypots se publican con Docker Compose y **ningún puerto HTTP estaba
publicado de forma alcanzable**:

1. `deploy/local/docker-compose.yml` publicaba todo en `127.0.0.1`
   (`…:13080:80` incluido): nada accesible desde otra máquina.
2. El override del servidor (`docker-compose.remote.yml`) publicaba los
   señuelos en la IP WireGuard `10.66.0.3`, pero el HTTP de OpenCanary quedaba
   en `13080` (y un intento previo sin commit lo ponía en el `80`),
   **sin regla de firewall que lo permitiera** y con nginx ocupando aún el
   `80/443` públicos.
3. Resultado (comprobado en el host con `ss -tlnp` sobre `10.66.0.3`): solo
   escuchaban los señuelos no-HTTP ya publicados — `17222` (Endlessh),
   `16379` (RedisHoneyPot) y `15021` (Heralding FTP) — más los de Cowrie en
   loopback. `ufw status` solo tenía permitidos `22` y `5005/5006`: ningún
   puerto HTTP publicado ni permitido ⇒ **cero ataques HTTP**.

Los comandos de diagnóstico (en el host; el repositorio no ejecuta firewall):

```bash
docker ps --format '{{.Names}}\t{{.Ports}}' | grep -E "opencanary|cowrie|heralding"
ss -tlnp | grep -E "10\.66\.0\.3|13080|8080"
ufw status numbered
```

## Solución aplicada (repo)

* Único puerto HTTP publicado: el módulo HTTP del contenedor `opencanary`
  (80 en el contenedor) hacia `${DYSTOPIA_HTTP_TRAP_BIND}:${DYSTOPIA_HTTP_TRAP_PORT}`
  (defectos: `8080` y, con el override remoto, `10.66.0.3`; loopback sin él).
  No se publican `80/443` ni otros puertos de honeypots.
* Variables documentadas en `deploy/local/.env.example` y
  `docs/MIGRACION-PUERTOS.md`.
* Captura de datos del atacante por petición: `src_ip`, `src_port`, método,
  path, user-agent, `Referer`, estado y credenciales Basic (ver
  `docker/deception/opencanary/patch_http_capture.py`,
  `docker/deception/opencanary/access_shim.py` y `runtime/normalize.py`).

## Pendiente del operador (no lo ejecuta el repo)

```bash
# 1) Variables en deploy/local/.env del servidor:
#    DYSTOPIA_HTTP_TRAP_PORT=8080
#    DYSTOPIA_HTTP_TRAP_BIND=10.66.0.3
# 2) Firewall del host (ajusta el puerto al valor real):
ufw allow from any to 10.66.0.3 port 8080 proto tcp
# 3) Recrear la pila para aplicar el binding nuevo:
cd /home/doker/Dystopia/deploy/local && docker compose --env-file .env \
  -f docker-compose.yml -f docker-compose.remote.yml up -d opencanary
# 4) Verificar llegada de ataques: docs/MIGRACION-PUERTOS.md, apartado
#    «Cómo verificar que llegan ataques HTTP».
```

Nota: un puerto publicado por Docker se filtra en `DOCKER-USER`/FORWARD, no
en el INPUT de ufw; si `dystopia-routing.sh` añade políticas restrictivas,
añade la excepción equivalente para la IP del contenedor (como ya se hace
para Redis, ver `docs/MIGRACION-PUERTOS.md`).
