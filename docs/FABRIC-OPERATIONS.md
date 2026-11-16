# NetPulse — Network Fabric: runbook de operación

Fecha: 2026-11-16 · Entorno de referencia: **Debian trixie**, OVS 3.5.0,
Docker, control en contenedor con engine `remote`.

Guía de usuario y arquitectura: [`docs/FABRIC.md`](FABRIC.md).

================================================================
1) REQUISITOS
================================================================

| Requisito | Detalle |
|---|---|
| SO | Debian trixie o Ubuntu 24.04 LTS |
| Open vSwitch | 3.1+ (verificado con 3.5.0); `openvswitch-switch` activo |
| Docker | Demonio activo; grupo `docker` |
| Python | venv del control en `/opt/dystopia/venv` (con `cryptography`) |
| Código | `/opt/dystopia/current` (release del repo) |
| Privilegios | root (el socket OVSDB `/run/openvswitch/db.sock` es root:root 0660) |
| Red | El BIND del servicio debe ser alcanzable por el contenedor del control |

================================================================
2) INSTALACIÓN DEL SERVICIO
================================================================

```bash
cd /opt/dystopia/current
sudo deploy/server/install-fabric-service.sh
```

El instalador es **idempotente** y hace:

1. Verifica SO (Debian/Ubuntu), herramientas y venv.
2. Crea grupo/usuario `dystopia-fabric` (sin login; dueño del estado).
3. Crea `/var/lib/dystopia/fabric` (0700) y `/var/lib/dystopia/fabric/credentials` (0700).
4. Genera y conserva **dos tokens** en `/etc/dystopia/fabric.env` (0600):
   `DYSTOPIA_FABRIC_TOKEN` (operación) y `DYSTOPIA_FABRIC_EVENTS_TOKEN` (ingesta).
5. Genera la clave Fernet `/etc/dystopia/fabric.key` (0600) si falta.
6. Instala la unit `deploy/systemd/dystopia-fabric.service` →
   `/etc/systemd/system/dystopia-fabric.service`, `daemon-reload`, `enable`, `restart`.
7. Verifica `GET /health` con el token (reintentos 15 s).

Verificación tras instalar:

```bash
systemctl status dystopia-fabric.service --no-pager
journalctl -u dystopia-fabric -n 50 --no-pager
TOKEN=$(sed -n 's/^DYSTOPIA_FABRIC_TOKEN=//p' /etc/dystopia/fabric.env)
curl -s -H "Authorization: Bearer $TOKEN" http://172.17.0.1:18100/health | python3 -m json.tool
```

================================================================
3) CONFIGURACIÓN — /etc/dystopia/fabric.env
================================================================

| Variable | Valor recomendado (despliegue real) | Descripción |
|---|---|---|
| `DYSTOPIA_FABRIC_TOKEN` | generado (64 hex) | Token de **operación** (control→host). |
| `DYSTOPIA_FABRIC_EVENTS_TOKEN` | generado (64 hex), **distinto** | Token de **ingesta** (forwarder→control). |
| `DYSTOPIA_FABRIC_BIND` | `172.17.0.1` | **Gateway de docker0**: estable; `host.docker.internal` lo resuelve. NO usar la IP de la red compose (cambia al recrearla). |
| `DYSTOPIA_FABRIC_PORT` | `18100` | Puerto del host service (8090/8091 suelen estar ocupados; el default del código es 8090). |
| `DYSTOPIA_FABRIC_MANIFEST` | `/opt/dystopia/current/config/deception/network.yaml` | Manifiesto que despliega el host. |
| `DYSTOPIA_FABRIC_EVENTS_URL` | `http://127.0.0.1:8082/api/fabric/events` | Control (publicado en 127.0.0.1:8082). |
| `DYSTOPIA_FABRIC_EVENTS_INTERVAL` | `5` | Segundos entre ciclos del forwarder. |
| `DYSTOPIA_FABRIC_EVENTS_ENABLED` | `true` | `false` desactiva el forwarder. |
| `DYSTOPIA_FABRIC_DEVICES_DIR` | `/var/lib/dystopia/fabric/logs` | Raíz de los JSONL del agente. |
| `DYSTOPIA_FABRIC_DEVICE_CONFIG_DIR` | `/var/lib/dystopia/fabric/devices` | device.json por dispositivo. |
| `DYSTOPIA_FABRIC_DEVICE_LOG_DIR` | `/var/lib/dystopia/fabric/logs` | Montaje `/var/log/fabric` del contenedor. |
| `DYSTOPIA_FABRIC_KEY` | (no usar; usar el fichero) | Clave Fernet alternativa. |
| `DYSTOPIA_FABRIC_KEY_FILE` | `/etc/dystopia/fabric.key` | Fichero de clave 0600. |
| `DYSTOPIA_FABRIC_CREDENTIALS_DIR` | `/var/lib/dystopia/fabric/credentials` | Credenciales cifradas. |
| `DYSTOPIA_FABRIC_LATERAL_WINDOW` | `600` | Ventana (s) de la alerta de movimiento lateral. |

En el **control** (Docker, `deploy/local/docker-compose.yml` + `.env`):

| Variable | Valor |
|---|---|
| `DYSTOPIA_FABRIC_ENABLED` | `true` para activar (doble gate). |
| `DYSTOPIA_FABRIC_ENGINE` | `remote`. |
| `DYSTOPIA_FABRIC_REMOTE_URL` | `http://host.docker.internal:18100` |
| `DYSTOPIA_FABRIC_REMOTE_TOKEN` | **el mismo** que `DYSTOPIA_FABRIC_TOKEN` del host. |
| `DYSTOPIA_FABRIC_EVENTS_TOKEN` | **el mismo** que `DYSTOPIA_FABRIC_EVENTS_TOKEN` del host. |
| `DYSTOPIA_FABRIC_REMOTE_TIMEOUT` | `120` |

================================================================
4) FIREWALL
================================================================

Con INPUT DROP por defecto (ufw), solo la red Docker local puede hablar
con el host service:

```bash
sudo ufw allow from 172.16.0.0/12 to 172.17.0.1 port 18100 proto tcp
sudo ufw status numbered | grep 18100
```

No abrir el puerto a Internet: el token viaja en claro (HTTP local).

================================================================
5) ACTUALIZACIÓN
================================================================

```bash
cd /opt/dystopia/current
sudo -u dystopia-fabric git pull        # o el mecanismo de release habitual

# Rebuild de la imagen de dispositivo (contexto = raíz del repo):
sudo docker build -t dystopia/fabric-device:v1 -f fabric/Dockerfile .

# Rebuild/restart del control (carga app/ nueva):
cd deploy/local && docker compose build control && docker compose up -d control

# Restart del host service (carga código nuevo):
sudo systemctl restart dystopia-fabric.service
curl -s -H "Authorization: Bearer $TOKEN" http://172.17.0.1:18100/health
```

Tras actualizar, el fabric queda `ready` (el runtime sobrevive al reinicio
del control; el host service reconstruye el estado de OVS/Docker al vuelo).
Rebuild desde la UI/API si hace falta.

================================================================
6) VERIFICACIÓN
================================================================

```bash
# Estado del servicio y del control
systemctl status dystopia-fabric.service --no-pager
curl -s -H "Authorization: Bearer $TOKEN" http://172.17.0.1:18100/status

# Bridges y puertos OVS (tags de VLAN)
sudo ovs-vsctl show
sudo ovs-vsctl list-ports sw-core
sudo ovs-vsctl get port dv00-pcrecepc tag

# Contenedores del fabric
sudo docker ps --filter label=dystopia.fabric=true --format '{{.Names}} {{.Status}}'

# Config del netns de un dispositivo
PID=$(sudo docker inspect -f '{{.State.Pid}}' dystopia-fabric-pc-recepcion-01)
sudo nsenter -t $PID -n -- ip addr show eth0
sudo nsenter -t $PID -n -- ip route
sudo nsenter -t $PID -n -- ip neigh

# Eventos del agente (JSONL) y forwarder
sudo tail -n 5 /var/lib/dystopia/fabric/logs/pc-recepcion-01/events.jsonl
curl -s -H "Authorization: Bearer $TOKEN" http://172.17.0.1:18100/status | python3 -c 'import json,sys; print(json.load(sys.stdin)["forwarder"])'
```

### Emulación WAN (`tc netem`, Fase 10)

Si algún enlace de `fabric.links` declara `latency_ms`, `jitter_ms`,
`loss_pct` o `bandwidth_mbps`, el deploy deja un qdisc `netem` en los
**dos** extremos del veth (`lk<NN>a-*` y `lk<NN>b-*`):

```bash
# ¿Qué qdisc hay en cada extremo del enlace?
sudo tc qdisc show dev lk00a-swcore
sudo tc qdisc show dev lk00b-swofici
#   qdisc netem 8001: root refcnt 2 limit 1000 delay 50ms 5ms

# RTT real entre dos dispositivos de switches distintos
PID=$(sudo docker inspect -f '{{.State.Pid}}' dystopia-fabric-pc-recepcion-01)
sudo nsenter -t $PID -n -- ping -c 5 10.20.0.10

# Parámetros aplicados según el último deploy (JSON del host service)
curl -s -H "Authorization: Bearer $TOKEN" http://172.17.0.1:18100/status \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["last_deploy"]["wan_links"])'

# Limpieza manual (el destroy ya lo hace)
sudo tc qdisc del dev lk00a-swcore root
sudo tc qdisc del dev lk00b-swofici root
```

Sin qdisc netem, `tc qdisc show` responde `qdisc noqueue 0: root refcnt 2`
(o `pfifo_fast`). El destroy borra el qdisc y es idempotente.

================================================================
7) OPERACIÓN DIARIA
================================================================

Desde la **UI** (página Fabric, rol admin): Validate → Deploy → (Destroy /
Rebuild). Estado y salud se refrescan con Actualizar.

Por API (control, JWT admin):

```bash
CONTROL=http://127.0.0.1:8082
JWT=<token admin>
curl -s -X POST -H "Authorization: Bearer $JWT" $CONTROL/api/fabric/validate
curl -s -X POST -H "Authorization: Bearer $JWT" $CONTROL/api/fabric/deploy
curl -s -H "Authorization: Bearer $JWT" $CONTROL/api/fabric/health
curl -s -X POST -H "Authorization: Bearer $JWT" $CONTROL/api/fabric/destroy
```

Directo al host service (token de operación):

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" http://172.17.0.1:18100/deploy
curl -s -X POST -H "Authorization: Bearer $TOKEN" http://172.17.0.1:18100/destroy
```

 =================================================================
8) TROUBLESHOOTING (errores reales)
================================================================

| Síntoma | Causa | Solución |
|---|---|---|
| `ovs-vsctl: database connection failed (Permission denied)` | El socket `/run/openvswitch/db.sock` es `root:root 0660` y el servicio no corre como root | El servicio debe correr como **root** (confinado por `CapabilityBoundingSet`); verifica `systemctl show -p User dystopia-fabric` y `ls -l /run/openvswitch/db.sock` |
| `ip link set … netns <pid>: Invalid netns value` | Falta `CAP_SYS_PTRACE`: los contenedores corren como uid 2000 y el kernel aplica el chequeo ptrace al resolver `/proc/<pid>/ns/net` | Añade `CAP_SYS_PTRACE` a `CapabilityBoundingSet`/`AmbientCapabilities` |
| `nsenter: Operación no permitida` | `RestrictNamespaces=user` bloquea `setns(fd,0)` | **Retira** la directiva `RestrictNamespaces` de la unit (ya retirada) |
| `device.json: Permission denied` (en el contenedor) | Directorios 0700 de uid 2000 + servicio root sin `CAP_DAC_OVERRIDE` | Directorios de config **root 0700** y fichero **root:2000 0640** (implementado en `runtime.py`) |
| `chmod: Operation not permitted` | Root sin `CAP_FOWNER` al chmodear ficheros ajenos | Orden **chown → chmod → chown** (implementado); mantén `CAP_CHOWN` en la unit |
| Forwarder con `files: []` | Root sin `CAP_DAC_OVERRIDE` no entra en dirs 0700 de uid 2000 | Logs **0750 owner 2000 group root** (implementado); verifica `ls -la /var/lib/dystopia/fabric/logs/<device>/` |
| Control colgado ~120 s al hablar con el host | `DYSTOPIA_FABRIC_BIND` apuntaba a la IP de la **red compose**, que cambia al recrear la red (172.25.0.1 → 172.22.0.1) | BIND = **172.17.0.1** (gateway de docker0, estable); `host.docker.internal` resuelve siempre ahí |
| `Address already in use` en 8090/8091 | Puertos ocupados en el host | Usa **18100** (`ss -ltnp | grep 18100`) y alinea `DYSTOPIA_FABRIC_REMOTE_URL` del control |
| `503 Ingesta de eventos deshabilitada` | `DYSTOPIA_FABRIC_EVENTS_TOKEN` sin configurar en el control | Define el token de eventos en el `.env` del control y recrea el contenedor |
| `401 token inválido` en operaciones | Tokens desalineados entre control y host | Compara `DYSTOPIA_FABRIC_REMOTE_TOKEN` (control) con `DYSTOPIA_FABRIC_TOKEN` (host) |
| `El manifiesto declara emulación WAN … pero 'tc' no está disponible` | Falta `tc` (iproute2) o el módulo `sch_netem` | `sudo apt install iproute2`; verifica `tc -V` y `sudo modprobe sch_netem`; el preflight falla a propósito (no se ignora) |
| `jitter_ms sin latency_ms` / `no puede superar la latencia` | Manifiesto con jitter sin delay o mayor que la latencia | Declara `latency_ms` y deja `jitter_ms ≤ latency_ms` |
| `tc qdisc replace` devuelve `Operation not permitted` | El servicio no tiene `CAP_NET_ADMIN` | La unit ya lo incluye; comprueba `systemctl show -p CapabilityBoundingSet dystopia-fabric` |
| El RTT no cambia tras editar la latencia | El manifiesto del host difiere del local (el engine remote aborta) o no se re-desplegó | Sincroniza `network.yaml` y ejecuta **Deploy** (usa `replace`, no hace falta destroy) |
| `422 Manifiesto inválido` al desplegar | El manifiesto del host difiere del del control o tiene errores | Ejecuta Validate en la UI; sincroniza `config/deception/network.yaml` (el engine remote compara hashes) |
| Contenedor `Restarting`/exits | El agente no encuentra `/etc/fabric/device.json` o ningún listener arranca | `sudo docker logs dystopia-fabric-<device>`; verifica que hubo clave del fabric y servicios en el manifiesto |

================================================================
9) ROTACIÓN DE SECRETOS
================================================================

**Tokens** (ventana de mantenimiento):

```bash
# 1. Nuevos tokens en el host
sudo sed -i "s|^DYSTOPIA_FABRIC_TOKEN=.*|DYSTOPIA_FABRIC_TOKEN=$(openssl rand -hex 32)|" /etc/dystopia/fabric.env
sudo sed -i "s|^DYSTOPIA_FABRIC_EVENTS_TOKEN=.*|DYSTOPIA_FABRIC_EVENTS_TOKEN=$(openssl rand -hex 32)|" /etc/dystopia/fabric.env
# 2. Mismos valores en el .env del control (REMOTE_TOKEN = operación; EVENTS_TOKEN = ingesta)
# 3. Reiniciar ambos lados
sudo systemctl restart dystopia-fabric.service
cd deploy/local && docker compose up -d control
```

**Clave Fernet**: NO regenerar sin migrar (los `.enc` quedarían ilegibles).
Procedimiento: rotar = reemplazar `/etc/dystopia/fabric.key` por una clave
nueva y re-ejecutar **Deploy** (el engine re-cifra todas las credenciales
del manifiesto con la clave actual). Ante compromiso, destruye el fabric,
rota la clave, vuelve a desplegar.

================================================================
10) BACKUP / RESTORE
================================================================

Backup (con el servicio parado para consistencia):

```bash
sudo systemctl stop dystopia-fabric.service
sudo tar -czf /backup/fabric-$(date +%F).tgz \
  /etc/dystopia/fabric.env /etc/dystopia/fabric.key /var/lib/dystopia/fabric \
  /opt/dystopia/current/config/deception/network.yaml
sudo systemctl start dystopia-fabric.service
```

Restore: detener servicio, restaurar ficheros (permos 0600/0700),
`daemon-reload`, arrancar y verificar `/health`. El estado del runtime
(bridges/contenedores) NO se respalda: tras restaurar, ejecuta **Deploy**
(idempotente) para reconstruir la topología.

================================================================
11) CHECKLIST DE SEGURIDAD
================================================================

- [ ] `/etc/dystopia/fabric.env` 0600 con **dos tokens distintos**.
- [ ] `/etc/dystopia/fabric.key` 0600 (Fernet).
- [ ] `DYSTOPIA_FABRIC_BIND=172.17.0.1` (no 0.0.0.0, no IP de red compose).
- [ ] Ufw: solo `172.16.0.0/12 → 172.17.0.1:18100/tcp`.
- [ ] Doble gate activo: `fabric.enabled` + `DYSTOPIA_FABRIC_ENABLED` + JWT admin.
- [ ] Unit: `CapabilityBoundingSet` mínimo (NET_ADMIN, NET_RAW, SYS_ADMIN, SYS_PTRACE, CHOWN), `ProtectSystem=strict`, sin `RestrictNamespaces`.
- [ ] Control sin socket Docker ni red host; dispositivos `--network none`, `--cap-drop ALL`, uid 2000.
- [ ] `device.json` sin credenciales; `.enc` 0600; ninguna credencial en respuestas de la API.
- [ ] Auditoría `fabric_*` visible: `sudo journalctl -u dystopia-fabric | grep ALERTA` y tabla `audit` del control.
- [ ] Alertas del fabric activas (primer contacto / movimiento lateral) y cooldown operativo.
