import { useMemo, useState } from "react";
import {
  ChevronLeft,
  ChevronRight,
  Columns3,
  Copy,
  Download,
  Filter,
  Search,
  SlidersHorizontal,
  X,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { EventTable, type EventColumn } from "../components/EventTable";
import { ActionDialog } from "../components/ActionDialog";
import { SeverityBadge } from "../components/SeverityBadge";
import { HONEYPOTS } from "../data/mock";
import type { EventRow, Severity } from "../types";
import type { DataMode } from "../data/useAnalytics";
import { formatDateTime, formatNumber } from "../lib/format";

const PAGE_SIZE = 12;

const SEVERITY_OPTIONS: Array<{ value: "all" | Severity; label: string }> = [
  { value: "all", label: "Todas" },
  { value: "critical", label: "Crítico" },
  { value: "high", label: "Alto" },
  { value: "medium", label: "Medio" },
  { value: "low", label: "Bajo" },
  { value: "info", label: "Info" },
];

interface EventsPageProps {
  search: string;
  range: string;
  events: EventRow[];
  total: number;
  mode: DataMode;
}

export function EventsPage({ search, range, events, total, mode }: EventsPageProps) {
  const [localQuery, setLocalQuery] = useState("");
  const [severity, setSeverity] = useState<"all" | Severity>("all");
  const [sensor, setSensor] = useState("all");
  const [protocol, setProtocol] = useState("all");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<EventRow | null>(null);
  const [showFilters, setShowFilters] = useState(true);
  const [columnsOpen, setColumnsOpen] = useState(false);
  const [visibleColumns, setVisibleColumns] = useState<EventColumn[]>(["time", "severity", "event", "source", "sensor", "device", "proto"]);

  const filtered = useMemo(() => {
    const query = `${search} ${localQuery}`.trim().toLowerCase();
    return events.filter((event) => {
      if (severity !== "all" && event.severity !== severity) return false;
      if (sensor !== "all" && event.sensor !== sensor) return false;
      if (protocol !== "all" && event.proto !== protocol) return false;
      if (!query) return true;
      return [event.id, event.source, event.country, event.sensor, event.device, event.kind, event.action, event.proto, event.message]
        .join(" ")
        .toLowerCase()
        .includes(query);
    });
  }, [events, localQuery, protocol, search, sensor, severity]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const pageEvents = filtered.slice(safePage * PAGE_SIZE, safePage * PAGE_SIZE + PAGE_SIZE);

  const protocols = useMemo(() => Array.from(new Set(events.map((event) => event.proto))).sort(), [events]);

  function resetFilters() {
    setSeverity("all");
    setSensor("all");
    setProtocol("all");
    setLocalQuery("");
    setPage(0);
  }

  function exportCsv() {
    const headers = ["id", "timestamp", "severity", "sensor", "device", "source", "country", "kind", "proto", "action"];
    const rows = filtered.map((event) => [event.id, event.timestamp, event.severity, event.sensor, event.device, event.source, event.country, event.kind, event.proto, event.action]);
    const csv = [headers, ...rows].map((row) => row.map((value) => `"${String(value).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "dystopia-events.csv";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="page page-events">
      <PageHeader
        eyebrow="Monitorización / Event explorer"
        title="Eventos"
        description="Explora el flujo normalizado del almacén local con filtros, búsqueda y detalle por evento."
        actions={
          <>
            <button className="button ghost" onClick={() => setShowFilters((value) => !value)}><SlidersHorizontal size={15} /> Filtros</button>
            <button className="button ghost" onClick={() => setColumnsOpen(true)}><Columns3 size={15} /> Columnas</button>
            <button className="button primary" onClick={exportCsv}><Download size={15} /> Exportar CSV</button>
          </>
        }
        meta={
          <>
            <span><i className={`status-dot ${mode === "live" ? "live" : ""}`} /> {mode === "live" ? "datos en vivo" : mode === "error" ? "BFF sin conexión" : "datos de demostración"}</span>
            <span>{formatNumber(total)} documentos</span>
            <span>ventana {range}</span>
          </>
        }
      />

      <div className="discover-bar">
        <Search size={16} />
        <input
          value={localQuery}
          onChange={(event) => { setLocalQuery(event.target.value); setPage(0); }}
          placeholder='Filtra eventos. Ejemplo: source.ip:"45.155.205.233" or event.severity:"critical"'
          aria-label="Filtrar eventos"
        />
        <span className="discover-kbd mono">KQL</span>
        <button className="button small" onClick={() => setLocalQuery("")}>Limpiar</button>
      </div>

      {showFilters && (
        <div className="filter-bar">
          <span className="filter-bar-label"><Filter size={14} /> Filtros activos</span>
          <label className="filter-select">
            <span>Severidad</span>
            <select value={severity} onChange={(event) => { setSeverity(event.target.value as "all" | Severity); setPage(0); }}>
              {SEVERITY_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
            </select>
          </label>
          <label className="filter-select">
            <span>Sensor</span>
            <select value={sensor} onChange={(event) => { setSensor(event.target.value); setPage(0); }}>
              <option value="all">Todos</option>
              {HONEYPOTS.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
            </select>
          </label>
          <label className="filter-select">
            <span>Protocolo</span>
            <select value={protocol} onChange={(event) => { setProtocol(event.target.value); setPage(0); }}>
              <option value="all">Todos</option>
              {protocols.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
          </label>
          <button className="link-button" onClick={resetFilters}>Restablecer</button>
          <span className="filter-count">{formatNumber(filtered.length)} resultados</span>
        </div>
      )}

      <div className="discover-layout">
        <section className="panel discover-panel">
          <div className="discover-toolbar">
            <div className="save-search">
              <span className="eyebrow">Vista guardada</span>
              <strong>Security events · all honeypots</strong>
            </div>
            <div className="discover-toolbar-right">
              <span className="mono">1–{Math.min((safePage + 1) * PAGE_SIZE, filtered.length)} de {formatNumber(filtered.length)}</span>
              <button className="icon-button small" onClick={() => setPage(Math.max(0, safePage - 1))} disabled={safePage === 0} aria-label="Página anterior"><ChevronLeft size={15} /></button>
              <button className="icon-button small" onClick={() => setPage(Math.min(pageCount - 1, safePage + 1))} disabled={safePage >= pageCount - 1} aria-label="Página siguiente"><ChevronRight size={15} /></button>
            </div>
          </div>
          <EventTable events={pageEvents} onOpen={setSelected} visibleColumns={visibleColumns} />
          <div className="discover-pagination">
            <span className="muted">Mostrando {PAGE_SIZE} por página</span>
            <div className="pagination-buttons">
              <button className="icon-button small" onClick={() => setPage(0)} disabled={safePage === 0}><ChevronLeft size={13} /><ChevronLeft size={13} /></button>
              {Array.from({ length: Math.min(pageCount, 5) }, (_, index) => {
                const pageIndex = Math.max(0, Math.min(index, pageCount - 1));
                return <button key={pageIndex} className={`page-number ${safePage === pageIndex ? "active" : ""}`} onClick={() => setPage(pageIndex)}>{pageIndex + 1}</button>;
              })}
              <button className="icon-button small" onClick={() => setPage(pageCount - 1)} disabled={safePage >= pageCount - 1}><ChevronRight size={13} /><ChevronRight size={13} /></button>
            </div>
          </div>
        </section>

        <aside className="discover-side">
          <div className="side-card">
            <span className="eyebrow">Distribución</span>
            <h3>Severidad en la vista</h3>
            <div className="severity-stack">
              {SEVERITY_OPTIONS.filter((option) => option.value !== "all").map((option) => {
                const count = filtered.filter((event) => event.severity === option.value).length;
                const percentage = filtered.length ? Math.round((count / filtered.length) * 100) : 0;
                return (
                  <button key={option.value} onClick={() => { setSeverity(option.value); setPage(0); }} className={severity === option.value ? "active" : ""}>
                    <span><SeverityBadge severity={option.value as Severity} /> <b>{count}</b></span>
                    <span className="severity-bar"><i className={`bar-${option.value}`} style={{ width: `${percentage}%` }} /></span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="side-card">
            <span className="eyebrow">Campos</span>
            <h3>Schema ECS + Dystopia</h3>
            <div className="field-list">
              {[
                ["@timestamp", "date"],
                ["event.id", "keyword"],
                ["source.ip", "ip"],
                ["source.geo.country_iso_code", "keyword"],
                ["dystopia.sensor", "keyword"],
                ["dystopia.device", "keyword"],
                ["event.kind", "keyword"],
                ["network.protocol", "keyword"],
              ].map(([field, type]) => (
                <div key={field}><span className="mono">{field}</span><small>{type}</small></div>
              ))}
            </div>
          </div>

          <div className="side-card side-card-note">
            <span className="eyebrow">Privacidad</span>
            <p>La vista usa datos de demostración. En producción, el navegador consulta el BFF de Dystopia y nunca recibe la ruta de SQLite.</p>
          </div>
        </aside>
      </div>

      <ActionDialog
        open={columnsOpen}
        title="Columnas visibles"
        description="Elige qué campos quieres mostrar en el explorador de eventos."
        confirmLabel="Aplicar"
        onConfirm={() => setColumnsOpen(false)}
        onClose={() => setColumnsOpen(false)}
      >
        <div className="column-picker">
          {([
            ["time", "Hora"],
            ["severity", "Severidad"],
            ["event", "Evento"],
            ["source", "Origen"],
            ["sensor", "Sensor"],
            ["device", "Dispositivo"],
            ["proto", "Protocolo"],
          ] as Array<[EventColumn, string]>).map(([key, label]) => (
            <label key={key} className="column-option">
              <input
                type="checkbox"
                checked={visibleColumns.includes(key)}
                onChange={() => setVisibleColumns((current) => current.includes(key) ? current.filter((item) => item !== key) : [...current, key])}
              />
              <span>{label}</span>
            </label>
          ))}
        </div>
      </ActionDialog>

      {selected && (
        <div className="drawer-backdrop" onClick={() => setSelected(null)}>
          <aside className="event-drawer" onClick={(event) => event.stopPropagation()}>
            <div className="drawer-head">
              <div>
                <span className="eyebrow">Event detail</span>
                <h2>{selected.action}</h2>
                <span className="mono muted">{selected.id}</span>
              </div>
              <button className="icon-button" onClick={() => setSelected(null)} aria-label="Cerrar detalle"><X size={18} /></button>
            </div>
            <div className="drawer-badges">
              <SeverityBadge severity={selected.severity} />
              <span className="sensor-chip">{selected.sensor}</span>
              <span className="proto-chip">{selected.proto}</span>
            </div>
            <div className="drawer-summary">
              <div><span>Origen</span><strong className="mono">{selected.source}</strong></div>
              <div><span>País</span><strong>{selected.country}</strong></div>
              <div><span>Dispositivo</span><strong className="mono">{selected.device}</strong></div>
              <div><span>Destino</span><strong className="mono">{selected.dst_ip || "—"}:{selected.dst_port ?? "—"}</strong></div>
              <div><span>Timestamp</span><strong>{formatDateTime(selected.timestamp)}</strong></div>
            </div>
            <div className="drawer-message">
              <span className="eyebrow">Mensaje normalizado</span>
              <p>{selected.message}</p>
            </div>
            <div className="drawer-json">
              <div className="drawer-json-head"><span className="eyebrow">Documento</span><button className="link-button" onClick={() => navigator.clipboard?.writeText(JSON.stringify(selected, null, 2))}><Copy size={13} /> Copiar</button></div>
              <pre>{JSON.stringify(selected, null, 2)}</pre>
            </div>
          </aside>
        </div>
      )}
    </div>
  );
}
