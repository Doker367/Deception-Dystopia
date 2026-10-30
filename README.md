# Dystopia

Plataforma Python/FastAPI de deception, en endurecimiento para **Ubuntu Server
24.04 LTS con KVM/libvirt**.

**Base inicial, no despliegue certificado.** El plano de control está separado
de sensores e hipervisor. El arranque heredado de listeners/QEMU está retirado
y la activación de celdas queda bloqueada hasta verificar la contención real. No
hay contraseñas por defecto ni bootstrap público.

![Resumen del panel de deception](docs/images/overview.png)

## Qué incluye

- Runtime de control, sensor, ingesta, procesador y consulta.
- Topología de máquinas, segmentos, dispositivos y personas en Dystopia.
- Consola operativa de solo lectura con transporte Unix.
- Honeypots compatibles con T-Pot: Cowrie, OpenCanary, Dionaea, Heralding,
  RedisHoneyPot y Endlessh.
- Contrato ECS + `dystopia.*` e idempotencia por `event.id`.
- Elasticsearch/Kibana 9.3.5 como plano analítico.
- 7 dashboards, 44 visualizaciones y 2 data views.
- Roles separados para ingesta, análisis y administración.
- Documentación de operación, validación, seguridad y roadmap.

## Qué usa

| Área | Componentes |
|---|---|
| Control | Python 3.12+, FastAPI, Uvicorn, Pydantic, slowapi, JWT, bcrypt, PyYAML |
| Estado local | SQLite y ficheros de configuración |
| Analítica | Elasticsearch 9.3.5, Kibana 9.3.5, Docker/Colima |
| Honeypots | Cowrie, OpenCanary, Dionaea, Heralding, RedisHoneyPot, Endlessh |
| Red real | KVM/libvirt, systemd, nftables, VLANs/segmentos |
| Calidad | pytest, ruff, pyright informativo, GitHub Actions |

Las dependencias de control y su procedencia están en
[`requirements.txt`](requirements.txt),
[`deploy/requirements-control.in`](deploy/requirements-control.in) y
[`docs/DEPENDENCY-PROVENANCE.md`](docs/DEPENDENCY-PROVENANCE.md).

## Probar en tu Mac

No necesitas el servidor Linux para ver el panel. La guía completa está en
[`docs/LOCAL-LAB.md`](docs/LOCAL-LAB.md); resumen:

```bash
export LAB="$HOME/dystopia-lab"
mkdir -p "$LAB"/{data/elastic,data/kibana,certs,api-keys}
cp deploy/elastic/.env.example "$LAB/.env"

# Rellena los CHANGEME_* y las rutas absolutas de "$LAB" en $LAB/.env
chmod 600 "$LAB/.env"

ENV_FILE="$LAB/.env" ELASTIC_CERTS_DIR="$LAB/certs" \
  ./deploy/elastic/scripts/generate-certs.sh

docker compose --env-file "$LAB/.env" \
  -f deploy/elastic/docker-compose.elastic.yml \
  --profile deception-elastic up -d

ENV_FILE="$LAB/.env" ELASTIC_CERTS_DIR="$LAB/certs" \
  ./deploy/elastic/scripts/bootstrap-security.sh --all
```

Después importa el bundle y abre Kibana:

```bash
set -a; . "$LAB/.env"; set +a
curl -sS -u "deception_admin:$DECEPTION_ADMIN_PASSWORD" \
  -H 'kbn-xsrf: true' \
  -F 'file=@deploy/kibana-dashboards/artifacts/deception-kibana-bundle.ndjson' \
  'http://127.0.0.1:5601/api/saved_objects/_import?overwrite=true'
```

```text
http://127.0.0.1:5601/app/dashboards#/view/deception-overview
```

Para generar un evento sintético:

```bash
python3 scripts/seed_demo_event.py \
  --url https://127.0.0.1:9200 \
  --api-key-file "$LAB/api-keys/dystopia-ingest-writer.api-key" \
  --ca-cert "$LAB/certs/ca.crt"
```

## Cómo se usa

- **Operador:** dashboards de Kibana, Discover y consola de solo lectura.
- **Ingesta:** honeypots o sensores envían eventos normalizados al publicador;
  `event.id` evita duplicados.
- **Analista:** lee data streams y dashboards, sin permisos de escritura.
- **Administrador:** gestiona topología y espacio `deception-*`; el
  superusuario `elastic` queda para bootstrap/emergencias.
- **Consulta:** el control usa el puente Unix, nunca SQLite del sensor.

## Documentación

- [Laboratorio local en macOS](docs/LOCAL-LAB.md) — qué se puede probar antes del servidor.
- [Arquitectura y diagnóstico](docs/HARDENING.md)
- [Instalación, operación y recuperación](docs/HARDENING-OPERATIONS.md)
- [Pruebas y pendientes](docs/HARDENING-TESTS.md)
- [Sistema unificado: arquitectura](docs/UNIFIED-DECEPTION.md)
- [Operación del sistema unificado](docs/UNIFIED-OPERATIONS.md)
- [Informe de validación](docs/UNIFIED-VALIDATION.md)
- [Roadmap hacia el primer PR y el despliegue Linux](docs/ROADMAP.md)
- [Consola operativa](docs/CONSOLE-OPERATIONS.md)
- [Puente de consulta Unix](docs/QUERY-BRIDGE.md)
- [Migración](MIGRATION.md) y [procedencia de dependencias](docs/DEPENDENCY-PROVENANCE.md)

## Límites actuales

- KVM/libvirt, nftables, networking de segmentos y builds reales de honeypots
  se validan en Linux, no en macOS.
- El despliegue en la máquina objetivo sigue pendiente.
- Kibana no debe exponerse directamente; falta TLS/reverse proxy.
- Snapshots/restore y observabilidad de producción están pendientes.
- El panel Maps experimental no forma parte del bundle canónico.

Plan de instalación sin efectos:

```bash
python3 -m runtime.install --dry-run --config deploy/install.example.json
```

No ejecutes instalación, servicios o laboratorio sin autorización y
prerrequisitos. `.env` no se carga automáticamente.
