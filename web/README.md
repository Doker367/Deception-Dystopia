# Dystopia Web

Interfaz de operaciones de Dystopia. Está inspirada en los flujos de Kibana
(Dashboards, Discover, time picker y mapa), pero usa marca, navegación y
componentes propios. No copia código, assets ni marcas de Elastic.

## Estado

Prototipo funcional de la interfaz con datos de demostración:

- Resumen operativo con métricas, timeline, protocolos, ranking y actividad.
- Mapa global 3D con globo terráqueo, arcos animados y selección de origen.
- Explorador de eventos tipo Discover con filtros, paginación, detalle y CSV.
- Estado de los seis honeypots del MVP.
- Topología declarativa de dispositivos y segmentos.
- Salud del pipeline de ingesta.
- Administración de usuarios, claves y configuración.

La UI tiene dos modos:

- **Demo**: sin token JWT, usa datos sintéticos para poder revisar el diseño.
- **Live**: tras iniciar sesión, consulta el BFF `/api/analytics/*`, que habla
  con Elasticsearch usando una identidad de solo lectura.

La UI nunca recibe credenciales de Elasticsearch.

## Stack

- React 19 + TypeScript + Vite
- Apache ECharts para series y distribuciones
- `react-globe.gl` / Three.js para el globo 3D
- Lucide para iconografía
- CSS propio con tokens de diseño

## Desarrollo

```bash
cd web
npm install
npm run dev
```

Abre `http://127.0.0.1:5173`. El proxy de Vite envía `/api` a
`http://127.0.0.1:8082`.

## Build

```bash
cd web
npm run build
```

El build queda en `web/dist` con base `/static/web/` para servirlo desde
FastAPI. La integración de servidor se hará en una fase posterior.

## Contrato de datos previsto

La UI consumirá un BFF de Dystopia, no Elasticsearch directamente:

```text
GET /api/analytics/overview?from=...&to=...
GET /api/analytics/timeline?from=...&to=...&interval=...
GET /api/analytics/origins?from=...&to=...
GET /api/analytics/events?from=...&to=...&page=...
GET /api/analytics/health
```

El BFF usa un rol de solo lectura y aplica la autorización JWT de Dystopia.
Variables de entorno del control plane:

```bash
DYSTOPIA_ANALYTICS_ENABLED=true
DYSTOPIA_ANALYTICS_URL=https://127.0.0.1:9200
DYSTOPIA_ANALYTICS_INDEX=deception-events*
DYSTOPIA_ANALYTICS_ALERTS_INDEX=deception-alerts*
DYSTOPIA_ANALYTICS_API_KEY_FILE=/ruta/privada/dystopia-analytics-reader.api-key
DYSTOPIA_ANALYTICS_CA_FILE=/ruta/privada/ca.crt
DYSTOPIA_ANALYTICS_TIMEOUT=5
```

La API key debe tener el rol `deception-analyst` (solo lectura). No reutilizar
la clave del writer de ingesta.

## Servir el build desde FastAPI

`npm run build` genera `web/dist`. FastAPI lo detecta y sirve la SPA en `/`
(la consola histórica queda en `/console`). Si `web/dist` no existe, `/`
sigue sirviendo la consola anterior.

## Diseño

- Tema oscuro con acentos cian, azul, ámbar y violeta.
- Estructura de panel densa, orientada a operaciones.
- Tipografía Inter para interfaz y JetBrains Mono para datos.
- El globo es la pieza visual principal del mapa de amenazas.
- Los estados de activación de infraestructura siguen representados como
  bloqueados; la UI es de observación y control declarativo.


## Capturas

![Dystopia Web · resumen](../docs/images/dystopia-web-overview.jpg)

![Dystopia Web · mapa global](../docs/images/dystopia-web-map.jpg)
