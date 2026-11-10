# Operación del laboratorio (servidor de prueba)

Artefactos para el host de laboratorio. No son el despliegue del CPD; sirven
para que el entorno de pruebas tenga backups, rotación y recuperación
reproducibles.

## Instalación

```bash
install -d -m 700 /usr/local/lib/dystopia
install -m 600 dystopia-backup.py /usr/local/lib/dystopia/backup.py
install -m 700 dystopia-backup.sh /usr/local/sbin/dystopia-backup.sh
install -m 644 dystopia-backup.service /etc/systemd/system/dystopia-backup.service
install -m 644 dystopia-backup.timer /etc/systemd/system/dystopia-backup.timer
install -m 644 logrotate.d-dystopia /etc/logrotate.d/dystopia
systemctl daemon-reload
systemctl enable --now dystopia-backup.timer
systemctl start dystopia-backup.service
```

El backup queda en `/var/backups/dystopia/<UTC>/` con permisos 0700. Incluye
`deception.db`, `audit.db`, `investigations.db` (si existe), `users.yaml`,
`.env`, los compose y un `MANIFEST.sha256`. Retención local: 14 días.

**Importante:** el backup vive en el mismo host. Antes del CPD hay que copiarlo
a un destino externo aprobado; el runbook de cutover explica el restore.

## Restore de prueba

```bash
B=$(ls -1d /var/backups/dystopia/* | tail -1)
T=$(mktemp -d /var/tmp/dystopia-restore.XXXXXX)
cp "$B"/*.db "$T"/
python3 - "$T" <<'PY'
import sqlite3, sys, os
base = sys.argv[1]
for name in ("deception.db", "audit.db", "investigations.db"):
    path = os.path.join(base, name)
    if not os.path.exists(path):
        continue
    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    print(name, c.execute("PRAGMA integrity_check").fetchone()[0])
    c.close()
PY
rm -rf "$T"
```

## Rotación de logs

`logrotate.d-dystopia` rota los logs de los volúmenes Docker con
`copytruncate` (el colector detecta el truncado y reinicia el offset), conserva
7 rotaciones y fuerza rotación a los 50 MB. El log de backup se rota semanal.

## Nota de enrutamiento del laboratorio

El script local `/usr/local/sbin/dystopia-routing.sh` añade reglas
`from <subred Docker> lookup 100` para devolver el tráfico de las respuestas por
WireGuard. Eso también desviaba el tráfico **del host hacia los contenedores**
por `wg0` y rompía `127.0.0.1:13080`. La corrección persistente es añadir, antes
del default de la tabla 100:

```bash
ip rule add to 172.16.0.0/12 lookup main priority 999
```

`dystopia-routing.sh` y `dystopia-down.sh` ya la añaden/eliminan. En el CPD se
debe usar el diseño de marca de conntrack de `deploy/server/dystopia-wg-return.sh`
o la política aprobada por el ingeniero de redes, no copiar este script tal cual.
