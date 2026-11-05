import { useMemo } from "react";
import type { EChartsOption } from "echarts";
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  Clock3,
  Database,
  Gauge,
  HardDrive,
  Inbox,
  Radio,
  Server,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Panel } from "../components/Panel";
import { EChart } from "../components/EChart";
import { INGEST_SERIES, HONEYPOTS } from "../data/mock";
import { formatNumber } from "../lib/format";

const AXIS_LABEL = { color: "#71849b", fontSize: 10, fontFamily: "JetBrains Mono, monospace" };

function ingestOption(): EChartsOption {
  return {
    backgroundColor: "transparent",
    animationDuration: 800,
    grid: { top: 18, right: 16, bottom: 28, left: 42 },
    tooltip: {
      trigger: "axis",
      backgroundColor: "#0b1520",
      borderColor: "rgba(93, 170, 196, 0.3)",
      textStyle: { color: "#dbe7f3", fontSize: 12 },
    },
    legend: { right: 0, top: 0, textStyle: { color: "#8c9fb3", fontSize: 11 }, icon: "roundRect", itemWidth: 8, itemHeight: 8 },
    xAxis: {
      type: "category",
      data: Array.from({ length: INGEST_SERIES.length }, (_, index) => `${index * 5}m`),
      axisTick: { show: false },
      axisLine: { lineStyle: { color: "rgba(108, 150, 177, 0.16)" } },
      axisLabel: AXIS_LABEL,
    },
    yAxis: {
      type: "value",
      splitLine: { lineStyle: { color: "rgba(108, 150, 177, 0.12)", type: "dashed" } },
      axisLabel: AXIS_LABEL,
    },
    series: [
      {
        name: "Documentos / min",
        type: "line",
        smooth: 0.35,
        symbol: "none",
        data: INGEST_SERIES,
        lineStyle: { color: "#35e6c4", width: 2 },
        areaStyle: { color: "rgba(53, 230, 196, 0.13)" },
      },
      {
        name: "Descartes",
        type: "line",
        smooth: true,
        symbol: "none",
        data: INGEST_SERIES.map((value) => Math.max(0, Math.round(value * 0.012))),
        lineStyle: { color: "#ff7a9e", width: 1.4, type: "dashed" },
      },
    ],
  };
}

export function IngestPage() {
  const option = useMemo(() => ingestOption(), []);

  return (
    <div className="page">
      <PageHeader
        eyebrow="Operación / Data plane"
        title="Ingesta y pipeline"
        description="Salud del colector, normalización ECS, deduplicación y publicación en Elasticsearch. Todo en solo lectura."
        actions={
          <>
            <button className="button ghost"><Gauge size={15} /> Ver métricas</button>
            <button className="button primary"><Zap size={15} /> Probar pipeline</button>
          </>
        }
        meta={
          <>
            <span><i className="status-dot live" /> Pipeline operativo</span>
            <span>latencia 1.2 s</span>
            <span className="mono">deception-events</span>
          </>
        }
      />

      <div className="metrics-grid">
        <div className="metric-card tone-cyan"><div className="metric-top"><span className="metric-icon"><Activity size={17} /></span><span className="metric-label">Eventos / min</span><span className="metric-delta up">+8.2 %</span></div><div className="metric-main"><div><strong className="metric-value">234</strong><p className="metric-detail">pico de 318 en la ventana</p></div></div></div>
        <div className="metric-card tone-blue"><div className="metric-top"><span className="metric-icon"><Clock3 size={17} /></span><span className="metric-label">Lag de ingesta</span><span className="metric-delta flat">estable</span></div><div className="metric-main"><div><strong className="metric-value">1.2 s</strong><p className="metric-detail">p95: 2.8 s</p></div></div></div>
        <div className="metric-card tone-amber"><div className="metric-top"><span className="metric-icon"><Inbox size={17} /></span><span className="metric-label">Cola pendiente</span><span className="metric-delta down">-12</span></div><div className="metric-main"><div><strong className="metric-value">38</strong><p className="metric-detail">0 descartes en 30 min</p></div></div></div>
        <div className="metric-card tone-violet"><div className="metric-top"><span className="metric-icon"><HardDrive size={17} /></span><span className="metric-label">Almacenamiento</span><span className="metric-delta up">ok</span></div><div className="metric-main"><div><strong className="metric-value">4.2 GB</strong><p className="metric-detail">retención 30 días</p></div></div></div>
      </div>

      <div className="dashboard-grid">
        <Panel className="span-8" eyebrow="Throughput" title="Documentos por minuto" description="Ingesta normalizada vs. descartes en las últimas dos horas.">
          <EChart option={option} height={286} />
        </Panel>

        <Panel className="span-4" eyebrow="Pipeline" title="Salud por etapa">
          <div className="pipeline-list">
            {[
              { name: "Colector", value: "healthy", detail: "tailer activo", icon: Inbox },
              { name: "Normalizador", value: "healthy", detail: "ECS + dystopia.*", icon: ShieldCheck },
              { name: "Deduplicador", value: "healthy", detail: "event.id idempotente", icon: CheckCircle2 },
              { name: "Publicador", value: "healthy", detail: "batch 200", icon: Database },
              { name: "Elasticsearch", value: "healthy", detail: "9.3.5 · 3 shards", icon: Server },
            ].map((stage) => {
              const Icon = stage.icon;
              return (
                <div className="pipeline-stage" key={stage.name}>
                  <span className="pipeline-icon"><Icon size={15} /></span>
                  <div><strong>{stage.name}</strong><span>{stage.detail}</span></div>
                  <span className="health-pill healthy"><i />{stage.value}</span>
                </div>
              );
            })}
          </div>
        </Panel>

        <Panel className="span-12 pipeline-diagram-panel" eyebrow="Flujo" title="De honeypot a Dystopia" description="Cada etapa mantiene sus propios límites y credenciales." flush>
          <div className="pipeline-diagram">
            <div className="pipeline-node"><span className="pipeline-node-icon"><Radio size={18} /></span><strong>Honeypots</strong><span>6 sensores</span><small className="mono">loopback</small></div>
            <ArrowRight className="pipeline-arrow" size={17} />
            <div className="pipeline-node"><span className="pipeline-node-icon"><Inbox size={18} /></span><strong>Colector</strong><span>logs reales</span><small className="mono">spool</small></div>
            <ArrowRight className="pipeline-arrow" size={17} />
            <div className="pipeline-node"><span className="pipeline-node-icon"><ShieldCheck size={18} /></span><strong>Normalizador</strong><span>ECS + Dystopia</span><small className="mono">schema</small></div>
            <ArrowRight className="pipeline-arrow" size={17} />
            <div className="pipeline-node"><span className="pipeline-node-icon"><CheckCircle2 size={18} /></span><strong>Deduplicador</strong><span>event.id</span><small className="mono">idempotente</small></div>
            <ArrowRight className="pipeline-arrow" size={17} />
            <div className="pipeline-node accent"><span className="pipeline-node-icon"><Database size={18} /></span><strong>Elasticsearch</strong><span>deception-events</span><small className="mono">9.3.5</small></div>
          </div>
        </Panel>

        <Panel className="span-7" eyebrow="Data streams" title="Destinos" description="Índices y data streams utilizados por la analítica." flush>
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Destino</th><th>Tipo</th><th>Documentos</th><th>Retención</th><th>Estado</th></tr></thead>
              <tbody>
                <tr><td className="mono">deception-events</td><td>data stream</td><td>{formatNumber(12847)}</td><td>30 d</td><td><span className="health-pill healthy"><i />healthy</span></td></tr>
                <tr><td className="mono">deception-alerts</td><td>data stream</td><td>{formatNumber(342)}</td><td>90 d</td><td><span className="health-pill healthy"><i />healthy</span></td></tr>
                <tr><td className="mono">.kibana</td><td>system index</td><td>53 objetos</td><td>—</td><td><span className="health-pill healthy"><i />healthy</span></td></tr>
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel className="span-5" eyebrow="Sensores" title="Aportación por honeypot">
          <div className="sensor-contribution">
            {HONEYPOTS.map((honeypot) => (
              <div key={honeypot.id}>
                <span><i style={{ background: honeypot.color }} />{honeypot.name}</span>
                <span className="contribution-bar"><i style={{ width: `${(honeypot.events / 4821) * 100}%`, background: honeypot.color }} /></span>
                <strong className="mono">{formatNumber(honeypot.events)}</strong>
              </div>
            ))}
          </div>
          <div className="ingest-footnote"><Clock3 size={14} /> El colector no se inicia desde la interfaz. El gate de activación sigue cerrado.</div>
        </Panel>
      </div>
    </div>
  );
}
