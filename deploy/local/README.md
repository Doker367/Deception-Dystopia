# Laboratorio local — Dystopia

Pila completa en Docker Desktop (macOS): 6 honeypots + colector + control plane,
todo publicado únicamente en `127.0.0.1`. No es una celda Linux ni autoriza
exposición a una red real.

## Arranque

```bash
cd deploy/local
make up                     # crea .env, construye y levanta todo
make bootstrap-user         # usuario `lab` (admin) en el volumen de config
make health                 # /api/health
make analytics-health       # requiere `make token` antes
```

Abre `http://127.0.0.1:8082/app` y entra con el usuario `lab`.

## Flujo de prueba

```bash
make attack                 # 8 estímulos benignos, uno por puerto
sleep 12                    # poll del colector (10 s)
make token                  # guarda .token (0600)
make analytics-health       # debe incluir collector.status=ok
```

Contraste directo en SQLite (eventos, offsets y duplicados):

```bash
docker compose -f docker-compose.yml exec -T collector python - <<'PY'
import sqlite3
c = sqlite3.connect('file:/srv/deception/deception.db?mode=ro', uri=True)
print('eventos  ', c.execute('SELECT COUNT(*) FROM deception_events').fetchone()[0])
print('offsets  ', c.execute('SELECT engine, offset FROM collector_offsets').fetchall())
print('dupes    ', c.execute(
    "SELECT COUNT(*) FROM (SELECT 1 FROM deception_events "
    "WHERE json_extract(detail,'$.source_event_id') IS NOT NULL "
    "GROUP BY json_extract(detail,'$.engine'), "
    "json_extract(detail,'$.source_event_id') HAVING COUNT(*) > 1)").fetchone()[0])
print('collector', c.execute(
    'SELECT status, polls, ingested FROM collector_heartbeat').fetchall())
PY
```

## Reinicio / replay

```bash
make reset-ledger           # borra offsets (no eventos) y reinicia el colector
sleep 12
# el colector relee los logs desde 0: el índice único debe dejar 0 duplicados
```

## Parada

```bash
make down                   # conserva volúmenes (DB, offsets y logs)
```

Para borrar todo (incluida la DB de laboratorio): `docker compose down -v`.

## Puertos

| Host (loopback) | Servicio |
|---|---|
| 12222 / 12223 | Cowrie SSH / Telnet |
| 13022 / 13080 | OpenCanary SSH / HTTP |
| 14021 | Dionaea FTP |
| 15021 | Heralding FTP |
| 16379 | RedisHoneyPot |
| 17222 | Endlessh |
| 8082 | Control plane + web |

## Límites conocidos

- Dionaea usa una imagen **prebuilt** (`dystopia/honeypot-dionaea:0.12.5`):
  el master upstream ya no compila con Python 3.14 (módulo Python/Cython) y
  el commit antes fijado desapareció del repo. La imagen existe en el
  servidor; para reconstruirla cuando upstream lo arregle:
  `docker build -t dystopia/honeypot-dionaea:0.12.5 docker/deception/dionaea`.

- En macOS los volúmenes nombrados viven en la VM Linux de Docker Desktop:
  no reproducen los UID/GID del servidor, pero sí mantienen permisos
  coherentes entre contenedores y WAL funcional.
- El único escritor de eventos es el colector. No arranques dos.
- En Linux habrá que preparar bind mounts por celda (`cells/<N>`) con los GID
  reales (Cowrie 999, resto 2000) y dar lectura al servicio colector.
- Si el log nativo de un motor no trae `src_ip`, el normalizador descarta la
  línea: se cuenta en `collector_dead_letters`, no se inventa un evento.
