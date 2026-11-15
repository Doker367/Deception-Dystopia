import { useMemo } from "react";
import type { EChartsOption } from "echarts";
import {
  Activity,
  ArrowRight,
  Crosshair,
  Download,
  Globe2,
  ShieldAlert,
  Sparkles,
  Users,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { MetricCard } from "../components/MetricCard";
import { Panel } from "../components/Panel";
import { EChart } from "../components/EChart";
import { AnimatedNumber } from "../components/AnimatedNumber";
import { AttackGlobe } from "../components/AttackGlobe";
import { EventTable } from "../components/EventTable";
import { DATACENTER, HONEYPOTS } from "../data/mock";
import type { AnalyticsSnapshot, TimelinePoint } from "../data/useAnalytics";
import type { PageId } from "../types";
import { formatNumber } from "../lib/format";
import { ambientPulse, chartAxis, chartGrid, chartTooltip, horizontalBarOption } from "../lib/charts";
import { inkAccent, panelBg, useTheme } from "../lib/theme";
import { PROTOCOLS as PALETTE_PROTOCOLS, SERIES } from "../lib/palette";
import { useToast } from "../components/Toast";
import { downloadJson } from "../lib/download";

const PROTOCOL_COLORS: Record<string, string> = PALETTE_PROTOCOLS;

function volumeOption(points: TimelinePoint[]): EChartsOption {
  const data = points.length ? points : Array.from({ length: 24 }, (_, index) => ({ label: `${String(index).padStart(2, "0")}:00`, count: 0 }));
  const accent = inkAccent("#e2601f");
  const tip = chartTooltip();
  const lastPoint = data[data.length - 1];
  return {
    backgroundColor: "transparent",
    animation: true,
    animationDuration: 1400,
    animationDurationUpdate: 700,
    animationEasing: "quarticOut",
    animationEasingUpdate: "cubicOut",
    grid: { top: 18, right: 12, bottom: 26, left: 38 },
    tooltip: {
      trigger: "axis",
      ...tip,
      textStyle: { ...tip.textStyle, fontSize: 13.5 },
      axisPointer: { lineStyle: { color: `${accent}59` } },
      formatter: (params: unknown) => {
        const items = params as Array<{ axisValue: string; value: number }>;
        const item = items[0];
        return item ? `<b>${item.axisValue}</b><br/><span style="color:${accent}">●</span> ${formatNumber(item.value)} eventos` : "";
      },
    },
    xAxis: {
      type: "category",
      boundaryGap: false,
      data: data.map((point) => point.label),
      axisLine: { lineStyle: { color: chartGrid().color } },
      axisTick: { show: false },
      axisLabel: { ...chartAxis(), interval: data.length > 20 ? 3 : 1 },
    },
    yAxis: {
      type: "value",
      splitLine: { lineStyle: chartGrid() },
      axisLabel: { ...chartAxis(), formatter: (value: number) => (value >= 1000 ? `${(value / 1000).toFixed(1)}k` : `${value}`) },
    },
    series: [
      {
        type: "line",
        id: "volume",
        data: data.map((point) => point.count),
        smooth: 0.34,
        symbol: "none",
        animationDuration: 1400,
        animationEasing: "quarticOut",
        emphasis: { focus: "series" },
        lineStyle: { color: accent, width: 2, shadowBlur: 10, shadowColor: `${accent}40` },
        itemStyle: { color: accent },
        areaStyle: {
          color: {
            type: "linear",
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: `${accent}47` },
              { offset: 1, color: `${accent}03` },
            ],
          },
        },
        markLine: {
          silent: true,
          symbol: "none",
          label: { show: false },
          lineStyle: { color: "rgba(240, 173, 78, 0.35)", type: "dashed" },
          data: [{ yAxis: data[Math.floor(data.length * 0.7)]?.count ?? 0 }],
        },
      },
      ...(lastPoint && lastPoint.count > 0 ? [ambientPulse(lastPoint.label, lastPoint.count, accent)] : []),
    ],
  };
}

function protocolOption(protocols: Array<{ name: string; value: number }>): EChartsOption {
  const total = protocols.reduce((sum, item) => sum + item.value, 0) || 1;
  const tip = chartTooltip();
  return {
    backgroundColor: "transparent",
    animation: true,
    animationDuration: 900,
    animationDurationUpdate: 550,
    animationEasing: "cubicOut",
    animationEasingUpdate: "cubicOut",
    tooltip: {
      trigger: "item",
      ...tip,
      textStyle: { ...tip.textStyle, fontSize: 13.5 },
      formatter: "{b}: {c} ({d}%)",
    },
    series: [
      {
        type: "pie",
        id: "protocols",
        radius: ["62%", "82%"],
        center: ["50%", "50%"],
        avoidLabelOverlap: true,
        universalTransition: true,
        animationType: "scale",
        animationDuration: 900,
        animationEasing: "cubicOut",
        animationDelay: (index: number) => index * 45,
        itemStyle: { borderColor: panelBg(), borderWidth: 3, borderRadius: 3 },
        label: { show: false },
        emphasis: { focus: "self", scale: true, scaleSize: 6 },
        blur: { itemStyle: { opacity: 0.35 } },
        data: protocols.map((item, index) => ({
          value: item.value,
          name: item.name,
          itemStyle: { color: inkAccent(PROTOCOL_COLORS[item.name] ?? SERIES[index % SERIES.length]) },
        })).map((item) => ({ ...item, value: Math.round((item.value / total) * 100) })),
      },
    ],
  };
}

interface OverviewPageProps {
  search: string;
  range: string;
  data: AnalyticsSnapshot;
  onNavigate: (page: PageId) => void;
}

export function OverviewPage({ search, range, data, onNavigate }: OverviewPageProps) {
  const { notify } = useToast();
  const { mode, overview, timeline, origins, events } = data;
  const filteredEvents = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return events.slice(0, 7);
    return events.filter((event) =>
      [event.source, event.country, event.sensor, event.device, event.kind, event.action, event.proto]
        .join(" ")
        .toLowerCase()
        .includes(query),
    ).slice(0, 7);
  }, [events, search]);

  const [theme] = useTheme();
  const volume = useMemo(() => volumeOption(timeline), [timeline, theme]);
  const protocols = useMemo(() => protocolOption(overview.protocols), [overview.protocols, theme]);
  const maxOriginEvents = Math.max(...origins.map((origin) => origin.events), 1);
  const total = overview.totalEvents;
  const live = mode === "live";

  return (
    <div className="page">
      <PageHeader
        eyebrow="Security operations / Overview"
        title="Dystopia overview"
        description="Actividad agregada de la red señuelo, sensores y pipeline de ingesta en una sola vista."
        actions={
          <>
            <button className="button ghost" onClick={() => {
              downloadJson("dystopia-overview.json", { generatedAt: new Date().toISOString(), mode, overview, timeline, origins: origins.length, events });
              notify("Resumen exportado como JSON.", "success");
            }}><Download size={15} /> Exportar</button>
            <button className="button primary" onClick={() => onNavigate("map")}><Globe2 size={15} /> Abrir mapa global</button>
          </>
        }
        meta={
          <>
            <span><i className="status-dot live" /> {live ? "Datos en vivo" : "Datos de demostración"}</span>
            <span className="mono">c1 · 172.28.1.6</span>
            <span>{data.loading ? "Sincronizando BFF…" : live ? "Consultado ahora" : "Actualizado hace 12 s"}</span>
          </>
        }
      />

      {mode === "error" && (
        <div className="data-notice error">
          <ShieldAlert size={15} />
          <span>El BFF analítico no está disponible. La interfaz sigue mostrando datos de demostración.</span>
          <span className="mono">{data.error}</span>
        </div>
      )}

      {live && total === 0 && (
        <div className="data-notice">
          <Activity size={15} />
          <span>El almacén SQLite local está vacío. Los honeypots aparecerán aquí cuando la ingesta escriba eventos.</span>
          <span className="mono">deception_events / events</span>
        </div>
      )}

      <div className="metrics-grid">
        <MetricCard
          label="Eventos totales"
          value={formatNumber(total)}
          detail={live ? "en la ventana consultada" : "vs. 10,854 en el periodo anterior"}
          delta={live ? undefined : "+18.4 %"}
          icon={<Activity size={17} />}
          tone="cyan"
          spark={timeline.slice(-12).map((point) => point.count)}
        />
        <MetricCard
          label="Orígenes únicos"
          value={formatNumber(overview.uniqueSources)}
          detail={live ? "direcciones únicas en la ventana" : "214 nuevos en las últimas 24 h"}
          delta={live ? undefined : "+9.1 %"}
          icon={<Users size={17} />}
          tone="blue"
          spark={[12, 18, 16, 21, 18, 28, 25, 31, 29, 38, 35, 42]}
        />
        <MetricCard
          label="Alertas abiertas"
          value={formatNumber(overview.alerts)}
          detail={overview.alerts ? "requieren revisión" : "sin alertas en la ventana"}
          delta={live ? undefined : "-4.2 %"}
          trend="down"
          icon={<ShieldAlert size={17} />}
          tone="red"
          spark={[42, 38, 46, 39, 35, 38, 31, 34, 29, 26, 24, 21]}
        />
        <MetricCard
          label="Latencia de ingesta"
          value={live ? "n/d" : "1.2 s"}
          detail={live ? "pendiente de métrica de lag" : "6/6 sensores reportando"}
          delta={live ? undefined : "estable"}
          trend="flat"
          icon={<Sparkles size={17} />}
          tone="amber"
          spark={[16, 18, 15, 19, 17, 18, 16, 17, 15, 16, 17, 16]}
        />
      </div>

      <div className="dashboard-grid">
        <Panel
          className="span-7"
          eyebrow="Telemetría"
          title="Volumen de ataques"
          description="Eventos normalizados y deduplicados en SQLite local."
          actions={
            <div className="panel-tabs">
              {["24h", "7d", "30d"].map((item) => (
                <button key={item} className={range === item ? "active" : ""}>{item}</button>
              ))}
            </div>
          }
        >
          <div className="chart-summary">
            <div><strong><AnimatedNumber value={formatNumber(total)} /></strong><span>eventos en ventana</span></div>
            <div><strong className="up">{live ? "live" : "+18.4 %"}</strong><span>{live ? "BFF conectado" : "vs. ayer"}</span></div>
            <div><strong><AnimatedNumber value={origins.length} /></strong><span>países activos</span></div>
          </div>
          <EChart option={volume} height={252} />
        </Panel>

        <Panel
          className="span-5 panel-globe"
          eyebrow="Geolocalización"
          title="Origen global"
          description="Arcos de ataque hacia UNACH · FCFM."
          actions={
            <button className="link-button" onClick={() => onNavigate("map")}>
              Ver mapa <ArrowRight size={14} />
            </button>
          }
          flush
        >
          <AttackGlobe points={origins} minimal height={330} />
          <div className="globe-summary-row">
            <div><span>Top origen</span><strong>{origins[0]?.country ?? "—"} <small>{origins[0] ? formatNumber(origins[0].events) : "0"}</small></strong></div>
            <div><span>Core</span><strong>{DATACENTER.city} <small>{DATACENTER.country}</small></strong></div>
            <div><span>Países</span><strong>{origins.length} <small>activos</small></strong></div>
          </div>
        </Panel>

        <Panel
          className="span-4"
          eyebrow="Protocolos"
          title="Distribución por servicio"
          description="Porcentaje del total de eventos."
        >
          <div className="protocol-panel">
            <div className="donut-wrap">
              <EChart option={protocols} height={190} />
              <div className="donut-center"><strong>{overview.protocols.length}</strong><span>protocolos</span></div>
            </div>
            <div className="legend-list">
              {overview.protocols.map((item, index) => (
                <div className="legend-row" key={item.name}>
                  <span><i style={{ background: inkAccent(PROTOCOL_COLORS[item.name] ?? SERIES[index % SERIES.length]) }} />{item.name}</span>
                  <strong>{Math.round((item.value / Math.max(overview.protocols.reduce((sum, protocol) => sum + protocol.value, 0), 1)) * 100)}%</strong>
                </div>
              ))}
            </div>
          </div>
        </Panel>

        <Panel
          className="span-4"
          eyebrow="Origen"
          title="Top países"
          description="Volumen de eventos por país de origen."
          actions={<button className="link-button" onClick={() => onNavigate("map")}>Detalle <ArrowRight size={14} /></button>}
        >
          <div className="rank-list">
            {origins.slice(0, 6).map((origin, index) => (
              <button className="rank-row" key={origin.id} onClick={() => onNavigate("map")}>
                <span className="rank-number">{String(index + 1).padStart(2, "0")}</span>
                <span className="rank-flag">{origin.countryCode}</span>
                <span className="rank-country"><strong>{origin.country}</strong><small>{origin.city}</small></span>
                <span className="rank-bar"><i style={{ width: `${(origin.events / maxOriginEvents) * 100}%` }} /></span>
                <span className="rank-value mono">{formatNumber(origin.events)}</span>
              </button>
            ))}
          </div>
        </Panel>

        <Panel
          className="span-4"
          eyebrow="Sensores"
          title="Estado de honeypots"
          description="Contenedores activos en la celda c1."
          actions={<button className="link-button" onClick={() => onNavigate("honeypots")}>Gestionar <ArrowRight size={14} /></button>}
        >
          <div className="honeypot-mini-grid">
            {HONEYPOTS.map((honeypot) => (
              <button className="honeypot-mini" key={honeypot.id} onClick={() => onNavigate("honeypots")}>
                <span className="honeypot-mini-head">
                  <i className="status-dot live" />
                  <strong>{honeypot.name}</strong>
                  <span className="mono">{formatNumber(honeypot.events)}</span>
                </span>
                <span className="honeypot-mini-meta">{honeypot.service} · :{honeypot.port}</span>
                <span className="honeypot-mini-bar"><i style={{ width: `${Math.min((honeypot.events / 5000) * 100, 100)}%`, background: honeypot.color }} /></span>
              </button>
            ))}
          </div>
        </Panel>

        <Panel
          className="span-12"
          eyebrow="Comparativa"
          title="Actividad por honeypot"
          description="Volumen capturado por cada sensor del MVP."
          actions={<span className="signal-pill"><Activity size={13} /> 6 sensores</span>}
        >
          <EChart
            option={horizontalBarOption(
              HONEYPOTS.map((honeypot) => honeypot.name),
              HONEYPOTS.map((honeypot) => honeypot.events),
              HONEYPOTS.map((honeypot) => honeypot.color),
              " eventos",
            )}
            height={250}
          />
        </Panel>

        <Panel
          className="span-12"
          eyebrow="Actividad reciente"
          title="Últimos eventos"
          description="Vista compacta del flujo del almacén local."
          actions={
            <button className="link-button" onClick={() => onNavigate("events")}>
              Abrir explorador <ArrowRight size={14} />
            </button>
          }
          flush
        >
          <EventTable events={filteredEvents} compact />
        </Panel>

        <Panel
          className="span-12 insight-panel"
          eyebrow="Dystopia signal"
          title="Lo que está cambiando"
          description="Resumen operativo generado a partir de la ventana activa."
          actions={<span className="signal-pill"><Crosshair size={13} /> 3 señales</span>}
        >
          <div className="insight-grid">
            <div className="insight">
              <span className="insight-icon red"><ShieldAlert size={16} /></span>
              <div><strong>SSH sigue siendo el vector dominante</strong><p>38 % de los eventos y el mayor volumen de fuerza bruta desde tres regiones.</p></div>
            </div>
            <div className="insight">
              <span className="insight-icon amber"><Activity size={16} /></span>
              <div><strong>La ingesta se mantiene estable</strong><p>1.2 s de latencia media y 0 descartes en los últimos 30 minutos.</p></div>
            </div>
            <div className="insight">
              <span className="insight-icon cyan"><Globe2 size={16} /></span>
              <div><strong>Nuevo origen en el mapa</strong><p>Fráncfort apareció por primera vez en la ventana de 24 horas.</p></div>
            </div>
          </div>
        </Panel>
      </div>
    </div>
  );
}
