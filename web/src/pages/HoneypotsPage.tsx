import { useEffect, useMemo, useState } from "react";
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
import { EChart } from "../components/EChart";
import { HoneypotConfigDrawer } from "../components/HoneypotConfigDrawer";
import { useToast } from "../components/Toast";
import { HONEYPOTS, HONEYPOT_CONFIGS, DEMO_EVENTS } from "../data/mock";
import type { EventRow, Honeypot } from "../types";
import { DEMO_OVERVIEW, type DataMode } from "../data/useAnalytics";
import { AttackerDrawer } from "../components/AttackerDrawer";
import { formatNumber } from "../lib/format";
import { apiGet } from "../lib/api";
import { horizontalBarOption } from "../lib/charts";

const STATUS_LABEL = {
  healthy: "Healthy",
  degraded: "Sin verificar",
  offline: "Offline",
};

function HoneypotCard({ honeypot, active, onSelect, onConfigure }: { honeypot: Honeypot; active: boolean; onSelect: () => void; onConfigure: () => void }) {
  return (
    <article
      className={`honeypot-card ${active ? "active" : ""}`}
      onClick={onSelect}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onSelect();
        }
      }}
      role="button"
      tabIndex={0}
    >
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
        <button
          className="card-config-link"
          onClick={(event) => {
            event.stopPropagation();
            onConfigure();
          }}
        >
          Configurar
        </button>
      </div>
    </article>
  );
}

interface HoneypotsPageProps {
  onRefresh: () => void;
  onOpenEvents: (query: string) => void;
  events: EventRow[];
  mode: DataMode;
}

export function HoneypotsPage({ onRefresh, onOpenEvents, events, mode }: HoneypotsPageProps) {
  const { notify } = useToast();
  const [selected, setSelected] = useState(HONEYPOTS[0].id);
  const [configId, setConfigId] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [attackerIp, setAttackerIp] = useState<string | null>(null);
  const [attackerQuery, setAttackerQuery] = useState("");
  const [matches, setMatches] = useState<Array<{ source: string; events: number; last_seen: string }>>([]);
  const [searchOpen, setSearchOpen] = useState(false);
  const [activeMatch, setActiveMatch] = useState(-1);
  const [searchError, setSearchError] = useState("");
  const [searching, setSearching] = useState(false);
  const sourceEvents = mode === "live" ? events : mode === "demo" ? DEMO_EVENTS : [];
  const demo = mode === "demo";
  const honeypots = useMemo(() => mode === "demo" ? HONEYPOTS : HONEYPOTS.map((sensor) => {
    const activity = sourceEvents.filter((event) => event.sensor === sensor.id);
    const trend = Array.from({ length: 24 }, (_, index) => activity.filter((event) => {
      const age = Date.now() - new Date(event.timestamp).getTime();
      return age >= index * 3600000 && age < (index + 1) * 3600000;
    }).length).reverse();
    return { ...sensor, status: "degraded" as const, events: activity.length,
      uniqueSources: new Set(activity.map((event) => event.source)).size,
      lastSeen: activity[0]?.timestamp ? new Date(activity[0].timestamp).toLocaleString("es-MX") : "sin eventos",
      uptime: "sin datos", trend };
  }), [mode, sourceEvents]);
  const active = honeypots.find((item) => item.id === selected) ?? honeypots[0];
  const configHoneypot = honeypots.find((item) => item.id === configId) ?? null;
  const config = configId ? HONEYPOT_CONFIGS[configId] ?? null : null;
  const related = sourceEvents.filter((event) => event.sensor === active.id).slice(0, 5);
  const attackers = Array.from(new Set(sourceEvents.filter((event) => event.sensor === active.id).map((event) => event.source)))
    .filter(Boolean).slice(0, 20);

  useEffect(() => {
    const query = attackerQuery.trim();
    const controller = new AbortController();
    if (!searchOpen || query.length < 2 || query.length > 45 || !/^[0-9.:]+$/.test(query)) {
      setMatches([]);
      setSearching(false);
      return () => controller.abort();
    }
    if (mode === "demo") {
      const counts = new Map<string, { source: string; events: number; last_seen: string }>();
      for (const event of DEMO_EVENTS) {
        if (!event.source.startsWith(query)) continue;
        const old = counts.get(event.source);
        counts.set(event.source, { source: event.source, events: (old?.events ?? 0) + 1,
          last_seen: event.timestamp > (old?.last_seen ?? "") ? event.timestamp : old!.last_seen });
      }
      setMatches(Array.from(counts.values()).sort((a, b) => b.last_seen.localeCompare(a.last_seen)).slice(0, 20));
      setSearching(false);
      return () => controller.abort();
    }
    if (mode !== "live") { setMatches([]); setSearching(false); return () => controller.abort(); }
    setSearching(true);
    setSearchError("");
    const timer = window.setTimeout(() => {
      apiGet<{ items: Array<{ source: string; events: number; last_seen: string }> }>(
        `/api/investigations/attackers?query=${encodeURIComponent(query)}&limit=20`, controller.signal,
      ).then((data) => { if (!controller.signal.aborted) setMatches(data.items); })
        .catch(() => { if (!controller.signal.aborted) { setMatches([]); setSearchError("No se pudieron buscar orígenes. Inténtalo de nuevo."); } })
        .finally(() => { if (!controller.signal.aborted) setSearching(false); });
    }, 350);
    return () => { window.clearTimeout(timer); controller.abort(); };
  }, [attackerQuery, mode, searchOpen]);

  function openSource(ip: string) {
    setAttackerIp(ip);
    setAttackerQuery(ip);
    setSearchOpen(false);
    setActiveMatch(-1);
  }

  function refresh() {
    setRefreshing(true);
    onRefresh();
    window.setTimeout(() => setRefreshing(false), 800);
    notify("Muestra de telemetría actualizada; la salud del contenedor no está verificada.", "success");
  }

  return (
    <div className="page">
      <PageHeader
        eyebrow="Operación / Sensors"
        title="Honeypots"
        description="Inventario declarado, actividad observada y borradores de configuración. La telemetría no verifica la salud del contenedor ni habilita su activación."
        actions={
          <>
            <button className={`button ghost ${refreshing ? "spinning" : ""}`} onClick={refresh}><RefreshCw size={15} /> Actualizar telemetría</button>
            <button className="button primary" onClick={() => onOpenEvents(active.id)}><TerminalSquare size={15} /> Explorar eventos</button>
          </>
        }
        meta={
          <>
            <span><i className={`status-dot ${mode === "live" ? "live" : ""}`} /> {mode === "live" ? "ingesta conectada · salud no verificada" : mode === "error" ? "sin conexión" : "inventario de demostración"}</span>
            <span>celda c1</span>
            <span className="mono">contenedores Docker</span>
          </>
        }
      />

      <div className="sensor-summary">
        <div><span className="eyebrow">{demo ? "Eventos de demostración" : "Eventos visibles"}</span><strong>{formatNumber(demo ? DEMO_OVERVIEW.totalEvents : sourceEvents.length)}</strong><small>{mode === "live" ? "muestra de hasta 100 eventos · no total histórico" : demo ? "cifra ilustrativa del panel" : "sin datos"}</small></div>
        <div><span className="eyebrow">{demo ? "Fuentes de demostración" : "Fuentes visibles"}</span><strong>{formatNumber(demo ? DEMO_OVERVIEW.uniqueSources : new Set(sourceEvents.map((event) => event.source)).size)}</strong><small>{demo ? "cifra ilustrativa del panel" : "en la muestra actual"}</small></div>
        <div><span className="eyebrow">Sensores declarados</span><strong>{honeypots.length}</strong><small>inventario estático</small></div>
        <div><span className="eyebrow">Estado del runtime</span><strong>—</strong><small>no verificado por esta interfaz</small></div>
      </div>

      <div className="honeypot-grid">
        {honeypots.map((honeypot) => (
          <HoneypotCard
            key={honeypot.id}
            honeypot={honeypot}
            active={selected === honeypot.id}
            onSelect={() => setSelected(honeypot.id)}
            onConfigure={() => setConfigId(honeypot.id)}
          />
        ))}
      </div>

      <div className="dashboard-grid">
        <Panel
          className="span-7"
          eyebrow="Comparativa"
          title="Eventos por honeypot"
          description={mode === "demo" ? "Volumen ilustrativo de demostración." : "Eventos presentes en la muestra actual de hasta 100 documentos."}
          actions={<span className="signal-pill"><Activity size={13} /> 6 sensores</span>}
        >
          <EChart
            option={horizontalBarOption(
              honeypots.map((honeypot) => honeypot.name),
              honeypots.map((honeypot) => honeypot.events),
              honeypots.map((honeypot) => honeypot.color),
              " eventos",
            )}
            height={250}
          />
        </Panel>

        <Panel
          className="span-5"
          eyebrow="Capacidad"
          title="Memoria asignada"
          description="Límite declarado por contenedor en la celda c1."
        >
          <EChart
            option={horizontalBarOption(
              honeypots.map((honeypot) => honeypot.name),
              honeypots.map((honeypot) => Number.parseInt(HONEYPOT_CONFIGS[honeypot.id]?.resources.memLimit ?? "0", 10)),
              honeypots.map((honeypot) => honeypot.color),
              " MiB",
            )}
            height={250}
          />
        </Panel>

        <Panel
          className="span-7"
          eyebrow="Detalle del sensor"
          title={`${active.name} · ${active.service}`}
          description={`Contenedor dystopia-hp-c1-${active.id} en la celda c1.`}
          actions={
            <>
              <button className="button small" onClick={() => setConfigId(active.id)}>Ver configuración</button>
              <span className={`health-pill ${active.status}`}><i />{STATUS_LABEL[active.status]}</span>
            </>
          }
        >
          <div className="sensor-detail-grid">
            <div className="sensor-detail-stat"><span>Estado</span><strong><CircleCheck size={15} /> {mode === "demo" ? "Demostración" : "No verificado"}</strong></div>
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
                <div><strong>{event.action}</strong><button className="link-button mono" onClick={() => setAttackerIp(event.source)}>Ficha {event.source}</button><span className="mono">{event.proto}</span></div>
                <span className="mono muted">{event.kind}</span>
              </div>
            ))}
          </div>
          <div className="panel-footer-link"><button className="link-button" onClick={() => onOpenEvents(active.id)}>Abrir en explorador <ArrowUpRight size={14} /></button></div>
        </Panel>

        <Panel className="span-12" eyebrow="Investigación" title={`Orígenes de ${active.name}`} description="IPs visibles en la muestra de eventos. Abre una ficha para consultar la actividad y anotar hallazgos.">
          {(mode === "live" || mode === "demo") && <form className="attacker-search" onSubmit={(event) => {
            event.preventDefault();
            const ip = (activeMatch >= 0 ? matches[activeMatch] : matches.find((item) => item.source === attackerQuery.trim()) ?? matches[0])?.source ?? attackerQuery.trim();
            if (ip) openSource(ip);
          }} onBlur={(event) => { if (!event.currentTarget.contains(event.relatedTarget)) setSearchOpen(false); }}>
            <label htmlFor="attacker-ip">Consultar otra IP {mode === "demo" ? "de demostración" : "del almacén"}</label>
            <div className="attacker-search-field">
              <input id="attacker-ip" role="combobox" aria-autocomplete="list" aria-expanded={searchOpen && matches.length > 0}
                aria-controls="attacker-matches" aria-activedescendant={searchOpen && activeMatch >= 0 ? `attacker-match-${activeMatch}` : undefined}
                value={attackerQuery} onFocus={() => setSearchOpen(true)}
                onChange={(event) => { setAttackerQuery(event.target.value); setMatches([]); setActiveMatch(-1); setSearchOpen(true); }}
                onKeyDown={(event) => {
                  if (event.key === "Escape") { setSearchOpen(false); setActiveMatch(-1); }
                  if (searchOpen && matches.length && (event.key === "ArrowDown" || event.key === "ArrowUp")) {
                    event.preventDefault();
                    setActiveMatch((current) => event.key === "ArrowDown" ? (current + 1) % matches.length : (current + matches.length - 1) % matches.length);
                  }
                }} placeholder="Ej. 203.0.113.7" maxLength={45} />
              {searchOpen && matches.length > 0 && <div id="attacker-matches" className="attacker-matches" role="listbox" aria-label="IPs observadas">
                {matches.map((item, index) => <button key={item.source} type="button" role="option" id={`attacker-match-${index}`}
                  aria-selected={index === activeMatch} className="attacker-match" onMouseDown={(event) => event.preventDefault()}
                  onClick={() => openSource(item.source)}><span className="mono">{item.source}</span><span>{item.events} eventos</span></button>)}
              </div>}
              {searchOpen && (searching || searchError || (attackerQuery.length >= 2 && !matches.length && /^[0-9.:]+$/.test(attackerQuery) && !searching)) &&
                <span className="attacker-search-status" role="status">{searching ? "Buscando…" : searchError || "Sin coincidencias en la muestra consultada."}</span>}
            </div>
            <button className="button small" type="submit" disabled={!attackerQuery.trim()}>Abrir ficha</button>
          </form>}
          <div className="attacker-source-list">
            {attackers.length ? attackers.map((ip) => <button className="attacker-source" key={ip} onClick={() => setAttackerIp(ip)}>
              <span className="mono">{ip}</span><span>{sourceEvents.filter((event) => event.source === ip && event.sensor === active.id).length} eventos visibles</span><ArrowUpRight size={15} />
            </button>) : <p className="muted">No se observaron orígenes para este sensor en la muestra actual.</p>}
          </div>
        </Panel>

        <Panel
          className="span-12"
          eyebrow="Infraestructura"
          title="Contenedores y red"
          description="Puertos del inventario de referencia; no se confirma su publicación ni el estado del runtime."
          flush
        >
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Sensor</th><th>Contenedor</th><th>Servicio</th><th>Puerto host</th><th>Red</th><th>Estado</th><th>Uptime</th></tr></thead>
              <tbody>
                {honeypots.map((honeypot) => (
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
            <div><Activity size={17} /><p><strong>Observabilidad primero</strong><span>La evidencia es de solo lectura; las fichas y los borradores se guardan por separado.</span></p></div>
            <div><Boxes size={17} /><p><strong>Control en Dystopia</strong><span>La topología y los dispositivos se gestionan en el control plane de Dystopia.</span></p></div>
          </div>
        </Panel>
      </div>

      <HoneypotConfigDrawer honeypot={configHoneypot} config={config} mode={mode} onClose={() => setConfigId(null)} />
      <AttackerDrawer source={attackerIp} mode={mode} sample={sourceEvents} onClose={() => setAttackerIp(null)} />
    </div>
  );
}
