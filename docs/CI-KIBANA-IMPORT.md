# Validación CI del import de Kibana

`.github/workflows/kibana-import.yml` valida de extremo a extremo el bundle
canónico `deploy/kibana-dashboards/artifacts/deception-kibana-bundle.ndjson`
contra un stack **efímero** de Elasticsearch + Kibana **9.3.5**.

Se ejecuta solo con `workflow_dispatch` y con `schedule` semanal (lunes 04:00
UTC). **No** corre en cada PR: el stack consume memoria y minutos de runner.

## Qué hace

`scripts/validate_kibana_import.sh`:

1. Crea un directorio temporal (`mktemp -d`) con `data/`, `kibana/`, `certs/`
   y `api-keys/`.
2. Deriva un `.env` de `deploy/elastic/.env.example` con secretos aleatorios
   (`openssl rand -hex`) y rutas absolutas al temporal. Nunca los imprime.
3. Usa puertos alternativos para no chocar con un laboratorio local:
   `ELASTIC_HTTP_PORT=19201`, `KIBANA_HTTP_PORT=15602`.
4. Genera la PKI con `deploy/elastic/scripts/generate-certs.sh`.
5. Levanta el stack con
   `docker compose -f deploy/elastic/docker-compose.elastic.yml --profile deception-elastic`.
   Usa un nombre de proyecto Compose único y un override temporal de
   `container_name`, así que no colisiona con un stack local ya arrancado.
6. Espera Elasticsearch (`/_cluster/health`) y Kibana (`/api/status`) con
   `curl` y un límite de 240 s. Kibana se arranca antes de que exista
   `kibana_system`, así que el bootstrap del punto 7 corre mientras Kibana
   termina de arrancar y la espera de `/api/status` valida el estado final.
7. Ejecuta `bootstrap-security.sh --all` (roles, usuarios, API key, ILM,
   plantillas y data streams).
8. Importa el bundle como `deception_admin` con `?overwrite=true`.
9. Comprueba `success: true`, `successCount == 53` y `errors` vacío; además
   valida `GET /_data_stream/deception-events` y `/api/status` de Kibana.
10. En el `trap` de salida apaga el stack (`down` sin `-v`) y borra el
    temporal. Solo publica `ci-artifacts/kibana-import-summary.txt` y, si
    falla, un diagnóstico con los secretos enmascarados.

## Ejecución local

```bash
# Docker Desktop o Colima arrancados; vm.max_map_count no aplica en macOS.
bash scripts/validate_kibana_import.sh

# Puertos alternativos si 19201/15602 están ocupados:
ELASTIC_HTTP_PORT=29201 KIBANA_HTTP_PORT=25602 \
  bash scripts/validate_kibana_import.sh
```

El script termina con `exit 0` si el import es 53/53 y con `exit 1` (más el
motivo) en cualquier otro caso. No requiere secretos de GitHub.

## Requisitos

- Docker con Compose v2 (probado con Docker Desktop/Colima en macOS; en el
  runner Ubuntu el workflow aplica `vm.max_map_count=262144`).
- `curl`, `openssl`, `python3` (solo stdlib).
- ~4,5 GB de RAM disponibles para los contenedores y espacio para las
  imágenes de Elasticsearch y Kibana.

En macOS el temporal se crea bajo `~/.cache` (`KIBANA_CI_TMP_BASE` permite
cambiarlo): Docker Desktop/Colima solo comparte rutas del HOME por defecto.

## Limitaciones

- No certifica KVM/nftables, honeypots reales ni TLS de Kibana tras reverse
  proxy: solo el contrato de seguridad, los data streams y el import del
  panel.
- En Linux sin `sudo` passwordless el bind mount de `data/` y `certs/` puede
  quedar con ownership incorrecto para el uid 1000 de los contenedores.
