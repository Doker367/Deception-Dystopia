import { useMemo, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  Boxes,
  CircleCheck,
  Clock3,
  Container,
  Network,
  RefreshCw,
  ShieldCheck,
  TerminalSquare,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Panel } from "../components/Panel";
import { Sparkline } from "../components/Sparkline";
import { HONEYPOTS, EVENTS } from "../data/mock";
import type { Honeypot } from "../types";
import { formatNumber } from "../lib/format";

const STATUS_LABEL = {
  healthy: "Healthy",
  degraded: "Degraded",
  offline: "Offline",
};

function HoneypotCard({ honeypot, active, onSelect }: { honeypot: Honeypot; active: boolean; onSelect: () => void }) {
  return (
    <button className={`honeypot-card ${active ? "active" : ""}`} onClick={onSelect}>
      <div className="honeypot-card-head">
        <span className="honeypot-icon" style={{ color: honeypot.color, borderColor: `${honeypot.color}44`, background: `${honeypot.color}12` }}>
          <Container size={18} />
        </span>
        <div className="honeypot-card-title">
          <strong>{honeypot.name}</strong>
          <span>{honeypot.service}</span>
        </div>
        <span className={`health-pill ${honeypot.status}`}><i />{STATUS_LABEL[honeypot.status]}</span>
      </div>
      <div className="honeypot-card-stats">
        <div><span>Eventos</span><strong>{formatNumber(honeypot.events)}</strong></div>
        <div><span>Fuentes</span><strong>{formatNumber(honeypot.uniqueSources)}</strong></div>
        <div><span>Puerto</span><strong className="mono">:{honeypot.port}</strong></div>
      </div>
      <div className="honeypot-card-chart">
        <Sparkline data={honeypot.trend} color={honeypot.color} width={250} height={48} />
      </div>
      <div className="honeypot-card-foot">
        <span><Clock3 size={13} /> {honeypot.lastSeen}</span>
        <span className="mono">{honeypot.uptime} uptime</span>
      </div>
    </button>
  );
}

export function HoneypotsPage() {
  const [selected, setSelected] = useState(HONEYPOTS[0].id);
  const active = HONEYPOTS.find((item) => item.id === selected) ?? HONEYPOTS[0];
  const related = useMemo(() => EVENTS.filter((event) => event.sensor === active.id).slice(0, 5), [active.id]);

  return (
    <div className="page">
      <PageHeader
        eyebrow="Operación / Sensors"
        title="Honeypots"
        description="Estado de los seis sensores del MVP, volumen capturado y salud del contenedor. La activación real sigue protegida por el gate de Dystopia."
        actions={
          <>
            <button className="button ghost"><RefreshCw size={15} /> Refrescar estado</button>
            <button className="button primary"><TerminalSquare size={15} /> Ver logs</button>
          </>
        }
        meta={
          <>
            <span><i className="status-dot live" /> 6/6 healthy</span>
            <span>celda c1</span>
            <span className="mono">contenedores Docker</span>
          </>
        }
      />

      <div className="sensor-summary">
        <div><span className="eyebrow">Eventos capturados</span><strong>12,847</strong><small>en la ventana activa</small></div>
        <div><span className="eyebrow">Fuentes únicas</span><strong>1,204</strong><small>+214 nuevas</small></div>
        <div><span className="eyebrow">Uptime medio</span><strong>99.93 %</strong><small>últimas 24 h</small></div>
        <div><span className="eyebrow">Contenedores</span><strong>6/6</strong><small>sin reinicios</small></div>
      </div>

      <div className="honeypot-grid">
        {HONEYPOTS.map((honeypot) => (
          <HoneypotCard key={honeypot.id} honeypot={honeypot} active={selected === honeypot.id} onSelect={() => setSelected(honeypot.id)} />
        ))}
      </div>

      <div className="dashboard-grid">
        <Panel
          className="span-7"
          eyebrow="Detalle del sensor"
          title={`${active.name} · ${active.service}`}
          description={`Contenedor dystopia-hp-c1-${active.id} en la celda c1.`}
          actions={<span className={`health-pill ${active.status}`}><i />{STATUS_LABEL[active.status]}</span>}
        >
          <div className="sensor-detail-grid">
            <div className="sensor-detail-stat"><span>Estado</span><strong><CircleCheck size={15} /> Operativo</strong></div>
            <div className="sensor-detail-stat"><span>Eventos</span><strong>{formatNumber(active.events)}</strong></div>
            <div className="sensor-detail-stat"><span>Fuentes únicas</span><strong>{formatNumber(active.uniqueSources)}</strong></div>
            <div className="sensor-detail-stat"><span>Último evento</span><strong>{active.lastSeen}</strong></div>
            <div className="sensor-detail-stat"><span>Puerto</span><strong className="mono">127.0.0.1:{active.port}</strong></div>
            <div className="sensor-detail-stat"><span>Uptime</span><strong>{active.uptime}</strong></div>
          </div>
          <div className="sensor-chart-head"><span>Actividad reciente</span><span className="mono">eventos / hora</span></div>
          <div className="sensor-big-chart">
            <Sparkline data={[...active.trend, ...active.trend].slice(0, 24)} color={active.color} width={680} height={120} />
          </div>
        </Panel>

        <Panel
          className="span-5"
          eyebrow="Últimos eventos"
          title={`Actividad de ${active.name}`}
          description="Muestra de documentos atribuidos al sensor."
          flush
        >
          <div className="sensor-event-list">
            {related.length === 0 && <div className="empty-state small"><Boxes size={18} /><strong>Sin eventos recientes</strong></div>}
            {related.map((event) => (
              <div className="sensor-event" key={event.id}>
                <span className="sensor-event-dot" style={{ background: active.color }} />
                <div><strong>{event.action}</strong><span className="mono">{event.source} · {event.proto}</span></div>
                <span className="mono muted">{event.kind}</span>
              </div>
            ))}
          </div>
          <div className="panel-footer-link"><button className="link-button">Abrir en explorador <ArrowUpRight size={14} /></button></div>
        </Panel>

        <Panel
          className="span-12"
          eyebrow="Infraestructura"
          title="Contenedores y red"
          description="Puertos publicados en loopback y estado del runtime."
          flush
        >
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Sensor</th><th>Contenedor</th><th>Servicio</th><th>Puerto host</th><th>Red</th><th>Estado</th><th>Uptime</th></tr></thead>
              <tbody>
                {HONEYPOTS.map((honeypot) => (
                  <tr key={honeypot.id}>
                    <td><strong>{honeypot.name}</strong></td>
                    <td className="mono muted">dystopia-hp-c1-{honeypot.id}</td>
                    <td>{honeypot.service}</td>
                    <td className="mono">127.0.0.1:{honeypot.port}</td>
                    <td><span className="sensor-chip"><Network size={12} /> c1</span></td>
                    <td><span className={`health-pill ${honeypot.status}`}><i />{STATUS_LABEL[honeypot.status]}</span></td>
                    <td className="mono">{honeypot.uptime}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel className="span-12 note-panel" eyebrow="Gate de activación" title="La interfaz no activa infraestructura">
          <div className="note-grid">
            <div><ShieldCheck size={17} /><p><strong>Fail-closed</strong><span>Las acciones de preparación y activación siguen bloqueadas sin verificador Linux y claves de confianza.</span></p></div>
            <div><Activity size={17} /><p><strong>Observabilidad primero</strong><span>Esta vista es de solo lectura sobre la telemetría y el estado del runtime.</span></p></div>
            <div><Boxes size={17} /><p><strong>Control en Dystopia</strong><span>La topología y los dispositivos se gestionan en el control plane de Dystopia.</span></p></div>
          </div>
        </Panel>
      </div>
    </div>
  );
}
