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

El siguiente paso es conectar los endpoints reales del BFF de Dystopia y
Elasticsearch. La UI no debe recibir credenciales de Elasticsearch.

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

El BFF usará un rol de solo lectura y aplicará la autorización JWT de Dystopia.

## Diseño

- Tema oscuro con acentos cian, azul, ámbar y violeta.
- Estructura de panel densa, orientada a operaciones.
- Tipografía Inter para interfaz y JetBrains Mono para datos.
- El globo es la pieza visual principal del mapa de amenazas.
- Los estados de activación de infraestructura siguen representados como
  bloqueados; la UI es de observación y control declarativo.
