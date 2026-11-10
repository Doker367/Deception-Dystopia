# Matriz de red y flujos — Dystopia en centro de datos

**Estado:** plantilla de handoff para el ingeniero de redes. No contiene IPs
reales, credenciales ni reglas listas para producción. El servidor actual es de
laboratorio; la segmentación definitiva la define el CPD.

## 1. Zonas propuestas

| Zona | Contenido | Acceso permitido |
|---|---|---|
| `MGMT` | Panel `:8082`, SSH, consola de administración, monitorización | Solo operadores/VPN; nunca Internet |
| `INGRESS` | VPS, balanceador L4 o DNAT del CPD | Solo publica los puertos de señuelos hacia `SENSOR` |
| `SENSOR` | Cowrie, OpenCanary, Dionaea, Heralding, RedisHoneyPot, Endlessh | Entrada desde `INGRESS`; sin salida a `MGMT`/Internet |
| `OPS` | Colector, control, backups, SIEM | Salida allowlist a repos, backup y SIEM |
| `BACKUP` | Almacenamiento externo | Recibe copias; no inicia conexiones a `SENSOR` |

Si se usan celdas KVM, aplicar **una VLAN interna por celda** y una interfaz de
gestión separada. Un bridge Docker en un host compartido **no es contención**.

## 2. Flujos que debe aprobar el ingeniero de redes

Las direcciones se escriben como placeholders: `<SENSOR_VLAN>`,
`<MGMT_VLAN>`, `<VPS_PUBLIC_IP>`, `<WG_SERVER_IP>`, `<BACKUP_TARGET>`,
`<SIEM_TARGET>`.

| ID | Origen | Destino | Protocolo/puerto | Propósito | Política |
|---|---|---|---|---|---|
| F1 | `<VPS_PUBLIC_IP>` / ingress | `<WG_SERVER_IP>` | UDP 4443 (o el que se acuerde) | Túnel WireGuard | Permitir solo peer acordado |
| F2 | `<VPS_PUBLIC_IP>` / ingress | `<SENSOR_VLAN>` | TCP 12222, 12223 | Cowrie SSH/Telnet | DNAT; preservar IP origen |
| F3 | `<VPS_PUBLIC_IP>` / ingress | `<SENSOR_VLAN>` | TCP 13022, 13080 | OpenCanary SSH/HTTP | DNAT; preservar IP origen |
| F4 | `<VPS_PUBLIC_IP>` / ingress | `<SENSOR_VLAN>` | TCP 14021 | Dionaea FTP | DNAT; preservar IP origen |
| F5 | `<VPS_PUBLIC_IP>` / ingress | `<SENSOR_VLAN>` | TCP 15021 | Heralding FTP | DNAT; preservar IP origen |
| F6 | `<VPS_PUBLIC_IP>` / ingress | `<SENSOR_VLAN>` | TCP 16379 | RedisHoneyPot | DNAT; preservar IP origen |
| F7 | `<VPS_PUBLIC_IP>` / ingress | `<SENSOR_VLAN>` | TCP 17222 | Endlessh SSH | DNAT; preservar IP origen |
| F8 | `<MGMT_VLAN>` | control `:8082` | TCP 8082 | Panel/API | Solo MGMT/VPN; denegar Internet |
| F9 | `<MGMT_VLAN>` | host | TCP 22 | SSH administración | Solo MGMT/VPN |
| F10 | Colector/control | `<BACKUP_TARGET>` | TCP 443 / 22 / NFS acordado | Backups | Allowlist; salida |
| F11 | Colector/control | `<SIEM_TARGET>` | TCP 443 / 6514 | SIEM/observabilidad | Allowlist; salida |
| F12 | Host | repositorios aprobados | TCP 443 | Actualizaciones | Allowlist; ventana |
| F13 | Host | DNS interno | UDP/TCP 53 | Resolución | Solo DNS interno |
| F14 | Host | NTP interno | UDP 123 | Hora | Solo NTP interno |
| F15 | Operadores | DNS/NTP/backup/SIEM | — | Soporte | Según política corporativa |

**Reglas clave**

- No publicar `8082` en Internet ni en la VLAN de sensores.
- No permitir que `SENSOR` inicie conexiones hacia `MGMT`, backup, SIEM,
  Internet ni otras celdas. Solo responde a las conexiones entrantes permitidas.
- No aplicar SNAT en el ingress: se necesita la IP pública real del atacante
  para GeoIP, atribución y fichas por IP.
- Denegar en `SENSOR` cualquier tráfico saliente salvo el estrictamente
  aprobado (idealmente ninguno).
- Si se usa WireGuard, el retorno de las respuestas debe salir por `wg0`
  (tabla de rutas dedicada); documentar y probar el rollback.
- IPv6: si se habilita, replicar exactamente las mismas políticas.

## 3. Matriz de puertos publicados (laboratorio actual)

Estos son los **8 puertos publicados** por `docker-compose.remote.yml` y los
puertos internos de cada contenedor. El inventario completo de puertos
declarados está en `CELL-INVENTORY.md`.

| Servicio | Puerto host | Puerto contenedor | Protocolo | Uso | Notas |
|---|---:|---:|---|---|---|
| Cowrie | 12222 | 2222 | TCP | SSH | Conservar IP origen |
| Cowrie | 12223 | 2223 | TCP | Telnet | Conservar IP origen |
| OpenCanary | 13022 | 22 | TCP | SSH | Conservar IP origen |
| OpenCanary | 13080 | 80 | TCP | HTTP | Panel falso + beacon `/__fp` |
| Dionaea | 14021 | 21 | TCP | FTP | Solo FTP publicado hoy |
| Heralding | 15021 | 21 | TCP | FTP | Solo FTP publicado hoy |
| RedisHoneyPot | 16379 | 6379 | TCP | Redis | Conservar IP origen |
| Endlessh | 17222 | 2222 | TCP | SSH tarpit | Conservar IP origen |

Puertos declarados en el inventario pero **no publicados** en el laboratorio:
Dionaea 69/udp, 81, 135, 443, 445, 1433, 1723, 1883, 3306, 27017; OpenCanary
21, 23, 3306; Heralding 22, 23, 25, 80, 110, 143, 443, 3306, 3389, 5432, 5900.
Si el CPD quiere exponer más, debe aprobarse individualmente y actualizar la
matriz y el preflight de bindings.

## 4. Matriz de administración y datos

| Flujo | Origen | Destino | Puerto | Datos | Control |
|---|---|---|---|---|---|
| Panel/API | MGMT/VPN | control | 8082 | Sesión, analítica, fichas | TLS/VPN, RBAC, sin caché |
| SSH | MGMT | host | 22 | Administración | Claves, sin password, allowlist |
| Colector | host local | volúmenes de logs | local | Logs de señuelos | Solo lectura |
| Colector | host local | `deception.db` | local | Eventos normalizados | WAL, único writer |
| Control | host local | `deception.db` | local | Lectura BFF | Solo lectura |
| Control | host local | `audit/audit.db` | local | Auditoría | Append-only |
| Backup | host | `<BACKUP_TARGET>` | acordado | DB, config, logs | Cifrado, retención |
| SIEM | host | `<SIEM_TARGET>` | 443/6514 | Eventos/alertas | Allowlist |

## 5. Requisitos que debe entregar el CPD

- VLANs, subredes, gateways y direcciones de gestión.
- Matriz de firewall aprobada (entrada, salida, forwarding) y ventana de cambio.
- Ingress: IP pública, DNAT/balanceador, preservación de IP origen, TLS si aplica.
- DNS/NTP internos y salida a repositorios/backup/SIEM.
- Consola fuera de banda o acceso de recuperación.
- Plan de backups y ubicación externa.
- Responsable de red, responsable de seguridad y procedimiento de rollback.
- Confirmación de que el host será **Ubuntu Server 24.04 LTS** (o documentar la
  desviación) y de que los sensores no compartirán host con servicios ajenos.

## 6. Pruebas de aceptación de red

1. Desde una IP externa aprobada, conectar a cada puerto publicado y confirmar
   que el evento llega con la **IP pública real** y `regionCode` correcto.
2. Confirmar que `SENSOR` no puede alcanzar `MGMT`, backup, SIEM, Internet ni
   otra celda.
3. Confirmar que el panel `8082` **no** responde desde Internet ni desde
   `SENSOR`.
4. Confirmar que el retorno de las conexiones DNAT sale por el camino aprobado.
5. Repetir tras reinicio del host y tras reinicio del ingress.
6. Guardar PASS/FAIL, fecha, ventana y hashes de configuración; sin IPs, JWT ni
   capturas crudas en el ticket.

> El estado actual del laboratorio no demuestra contención. La evidencia Linux
> del verificador y el gate siguen siendo obligatorios antes de afirmar
> aislamiento.
