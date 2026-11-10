# Runbook — cutover y rollback al centro de datos

**Alcance:** mover Dystopia del servidor de laboratorio al CPD, conservar los
datos y dejar evidencia de aceptación. No incluye aplicar reglas de red: las
aprueba y ejecuta el ingeniero de redes del CPD.

**Roles**

| Rol | Responsabilidad |
|---|---|
| Operador Dystopia | Exportar/importar datos, arrancar servicios, validar panel y colector |
| Ingeniero de redes | VLANs, firewall, DNAT/ingress, retorno, DNS/NTP |
| Responsable de seguridad | Revisar aislamiento, gate, secretos y rollback |
| Aprobador del cambio | Autorizar ventana y aceptar PASS/FAIL |

## 0. Reglas de oro

- No ejecutar este runbook sobre el servidor de prueba como si fuera producción.
- No usar `docker compose down -v` ni borrar volúmenes.
- No publicar `8082` en Internet ni en la VLAN de sensores.
- No declarar contención hasta que el verificador Linux y el gate lo permitan.
- No pegar IPs reales, JWT, contraseñas ni capturas crudas en tickets.

## 1. Preflight (antes de la ventana)

- [ ] Host `Ubuntu Server 24.04 LTS`, hora/NTP y DNS internos correctos.
- [ ] VLANs y matriz de firewall aprobadas (`NETWORK-MATRIX.md`).
- [ ] IPs de gestión, ingress y backup definidas; consola fuera de banda probada.
- [ ] Certificados/TLS y secretos provisionados fuera de Git.
- [ ] `runtime.install --plan --config <config>` revisado y aprobado.
- [ ] Backup externo disponible y **restore probado** en un entorno desechable.
- [ ] Monitorización/SIEM y alertas de colector configurados.
- [ ] Ventana, contactos y rollback acordados.

## 2. Snapshot del origen (servidor de prueba)

1. Registrar versión y hashes:
   ```bash
   cd ~/Dystopia
   git rev-parse HEAD
   sha256sum deploy/local/docker-compose.yml deploy/local/docker-compose.remote.yml
   ```
2. Detener la celda de laboratorio (sin borrar volúmenes):
   ```bash
   cd deploy/local
   docker compose --env-file .env -f docker-compose.yml -f docker-compose.remote.yml stop
   ```
3. Exportar SQLite con `.backup` (consistente con WAL) y copiar configuración:
   ```bash
   B=/backup/dystopia-$(date -u +%Y%m%dT%H%M%SZ)
   mkdir -p "$B"
   # Ejemplo con un contenedor temporal; ajustar nombres de volúmenes.
   docker run --rm --user 2000:2000 \
     -v dystopia-local_deception_db:/srv/deception:ro \
     -v dystopia-local_control_state:/srv/state:ro \
     -v dystopia-local_control_config:/srv/local-config:ro \
     -v "$B":/backup \
     --entrypoint python3 dystopia/local-control:lab - <<'PY'
   import os, shutil, sqlite3
   for name, path in [("deception", "/srv/deception/deception.db"),
                      ("audit", "/srv/state/audit/audit.db"),
                      ("investigations", "/srv/state/investigations.db")]:
       if os.path.exists(path):
           src = sqlite3.connect(path); dst = sqlite3.connect(f"/backup/{name}.db")
           src.backup(dst); dst.close(); src.close()
   if os.path.exists("/srv/local-config/users.yaml"):
       shutil.copy2("/srv/local-config/users.yaml", "/backup/users.yaml")
   PY
   ```
4. Guardar hashes del backup y copiarlo al almacenamiento externo aprobado.

## 3. Importación en el CPD

1. Instalar release y dependencias:
   ```bash
   /opt/dystopia/venv/bin/python -m runtime.install --plan --config /etc/dystopia/install.json
   /opt/dystopia/venv/bin/python -m runtime.install --apply --config /etc/dystopia/install.json
   ```
2. Restaurar datos con permisos del servicio (`dystopia-control:dystopia-control`,
   `dystopia-ingest:dystopia-ingest`):
   - `deception.db` en `/var/lib/dystopia/control/deception/`.
   - `audit/audit.db` y `investigations.db` en el estado de control.
   - `users.yaml` en `/var/lib/dystopia/control/config/`.
   - No copiar `.env`, JWT, claves privadas ni sockets desde el laboratorio.
3. Bootstrap del primer administrador **por TTY** (nunca por variable/argumento).
4. Arrancar solo control e ingesta:
   ```bash
   systemctl enable --now dystopia-control.service dystopia-ingest.service dystopia-processor.service
   systemctl status dystopia-control.service dystopia-ingest.service
   ```
5. No habilitar sensores ni activación de celdas hasta aprobación del gate.

## 4. Validación (pegar PASS/FAIL, sin secretos)

| # | Prueba | Criterio | Resultado |
|---|---|---|---|
| V1 | Panel | `http://127.0.0.1:8082/app` responde y solo escucha loopback/MGMT | |
| V2 | Bindings | `ss -lntp` no muestra 8082 en 0.0.0.0/Internet | |
| V3 | Salud | `/api/health` y `/api/analytics/health` OK | |
| V4 | Colector | heartbeat reciente, `ingested` aumenta | |
| V5 | Evento sintético | aparece con sensor, src/dst y `regionCode` | |
| V6 | Ficha | perfil por IP, campañas y fingerprint (si aplica) | |
| V7 | Permisos | login viewer/operator/admin y rechazo de API keys donde aplique | |
| V8 | Export | CSV/JSON y auditoría append-only | |
| V9 | Backup | copia nueva + restore en entorno desechable | |
| V10 | Red | sensores sin salida; ingress solo a los 8 puertos; IP real preservada | |
| V11 | Gate | `apply` sigue bloqueado sin verificador firmado | |
| V12 | Reinicio | servicios vuelven y los datos siguen | |

Para el laboratorio Docker, el preflight de bindings es:

```bash
docker compose --env-file .env -f docker-compose.yml -f docker-compose.remote.yml config --format json \
  | DYSTOPIA_TAILSCALE_IP='<IP_TAILSCALE>' python3 deploy/server/check-compose-bindings.py
```

Para la prueba de IP real, usar `deploy/server/verify-source-ip.py` con un
probe externo autorizado y una ventana UTC de ≤10 minutos. Solo se comparte
`PASS/FAIL` y `regionCode`.

## 5. Rollback

1. Declarar rollback si falla V1–V4, V9 o V10.
2. Detener unidades nuevas:
   ```bash
   systemctl stop dystopia-control.service dystopia-ingest.service dystopia-processor.service
   ```
3. Restaurar el snapshot anterior y los permisos originales.
4. Revertir cambios de red **solo** con el ingeniero de redes y la ventana
   acordada; no borrar reglas ajenas.
5. Arrancar la versión anterior y repetir V1–V4.
6. Registrar causa, hora, responsable y evidencia.

## 6. Post-cutover

- Activar timer de backup y probar restauración programada.
- Rotación de logs y retención/WORM.
- Alertas de colector caído, disco, ingesta y errores.
- Revisión de accesos, claves y RBAC.
- Actualizar `NETWORK-MATRIX.md` y `CELL-INVENTORY.md` con los valores reales
  (sin secretos).
- Cerrar la aceptación con hashes de release, ventana y PASS/FAIL.

## 7. Pendientes conocidos del laboratorio

- Proxy Docker que dejó inaccesible `127.0.0.1:13080` desde el host tras
  recrear OpenCanary; verificar antes de migrar.
- MariaDB `3306` del host de laboratorio no forma parte de Dystopia; cerrar.
- Debian 13 vs Ubuntu 24.04.
- Backups programados y restauración aún no automatizados.
- Verificador Linux/gate sin evidencia firmada: la contención sigue sin
  declararse.
