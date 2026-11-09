import { useEffect, useState } from "react";
import { X } from "lucide-react";
import { apiGet, apiPut, getToken } from "../lib/api";
import { EChart } from "./EChart";
import { attackerTimelineOption } from "../lib/charts";
import type { EventRow } from "../types";
import type { DataMode } from "../data/useAnalytics";

interface Annotation {
  revision: number;
  alias: string;
  classification: string;
  tags: string[];
  notes: string;
  updated_at?: string;
  updated_by?: string;
}
interface Evidence {
  id: string;
  timestamp: string;
  sensor: string;
  device: string;
  kind: string;
  action: string;
  proto: string;
  port: number | null;
  severity: string;
  message: string;
  country?: string;
  detail: Record<string, unknown>;
}
interface Profile {
  source: string;
  total: number;
  first_seen?: string;
  last_seen?: string;
  country?: string;
  city?: string;
  protocols?: Record<string, number>;
  sensors?: Record<string, number>;
  kinds?: Record<string, number>;
  devices?: Record<string, number>;
  items: Evidence[];
  scanned_limit?: number;
  window?: { from: string; to: string };
  annotation: Annotation;
}
interface SourceTimeline {
  interval: "1h" | "1d";
  buckets: Array<{ at: string; count: number }>;
  total: number;
  scanned_limit: number;
}
interface AuditChange { field: string; from: unknown; to: unknown }
interface AuditEntry { id: number; at: string; actor: string; revision: number; changes: AuditChange[] }
const EMPTY: Annotation = { revision: 0, alias: "", classification: "unclassified", tags: [], notes: "" };
const showValue = (value: unknown) => Array.isArray(value) ? value.join(", ") : value && typeof value === "object" ? JSON.stringify(value) : String(value ?? "—");
const CLASSIFICATIONS = [
  ["unclassified", "Sin clasificar"], ["scanner", "Escaneo"],
  ["brute_force", "Fuerza bruta"], ["targeted", "Dirigido"],
  ["benign", "Benigno"], ["other", "Otro"],
];
const formatTime = (value?: string) => value ? new Date(value).toLocaleString("es-MX") : "Sin dato";

export function AttackerDrawer({ source, mode, sample, onClose }: {
  source: string | null; mode: DataMode; sample: EventRow[]; onClose: () => void;
}) {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [draft, setDraft] = useState<Annotation>(EMPTY);
  const [tags, setTags] = useState("");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [exporting, setExporting] = useState<"csv" | "json" | null>(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [canEdit, setCanEdit] = useState(false);
  const [history, setHistory] = useState<AuditEntry[]>([]);
  const [timeline, setTimeline] = useState<SourceTimeline | null>(null);
  const [timelineError, setTimelineError] = useState("");

  async function loadHistory() {
    if (!source || mode === "demo" || !getToken()) return;
    try {
      const data = await apiGet<{ items: AuditEntry[] }>(`/api/investigations/attackers/${encodeURIComponent(source)}/history?limit=20`);
      setHistory(data.items);
    } catch { /* El historial no bloquea la ficha. */ }
  }

  useEffect(() => { void loadHistory(); }, [source, mode]);

  useEffect(() => {
    if (!source || mode === "demo" || !getToken()) return;
    const controller = new AbortController();
    apiGet<{ role: string }>("/api/console/capabilities", controller.signal)
      .then((data) => { if (!controller.signal.aborted) setCanEdit(["admin", "operator"].includes(data.role)); })
      .catch(() => { if (!controller.signal.aborted) setCanEdit(false); });
    return () => controller.abort();
  }, [source, mode]);

  useEffect(() => {
    if (!source || mode === "demo" || !getToken()) return;
    const controller = new AbortController();
    setLoading(true);
    setError("");
    setMessage("");
    setProfile(null);
    apiGet<Profile>(`/api/investigations/attackers/${encodeURIComponent(source)}?offset=0&limit=50`, controller.signal)
      .then((data) => {
        if (controller.signal.aborted) return;
        setProfile(data);
        setDraft(data.annotation);
        setTags(data.annotation.tags.join(", "));
        setOffset(data.items.length);
      })
      .catch((cause: unknown) => { if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "No se pudo cargar la ficha"); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [source, mode]);

  useEffect(() => {
    setTimeline(null);
    setTimelineError("");
    if (!source || mode === "demo" || !getToken()) return;
    const controller = new AbortController();
    apiGet<SourceTimeline>(`/api/investigations/attackers/${encodeURIComponent(source)}/timeline?interval=1h`, controller.signal)
      .then((data) => { if (!controller.signal.aborted) setTimeline(data); })
      .catch(() => { if (!controller.signal.aborted) setTimelineError("No se pudo cargar la línea de tiempo."); });
    return () => controller.abort();
  }, [source, mode]);

  if (!source) return null;
  const demo = mode === "demo" || !getToken();
  const demoEvents: Evidence[] = sample.filter((item) => item.source === source).map((item) => ({
    ...item, detail: {}, port: item.port,
  }));
  const evidence = demo ? demoEvents : profile?.items ?? [];
  const demoFirst = demoEvents.length ? demoEvents.map((item) => item.timestamp).sort()[0] : undefined;
  const demoLast = demoEvents.length ? demoEvents.map((item) => item.timestamp).sort().at(-1) : undefined;
  const demoCountry = demoEvents[0]?.country;
  const demoCounts = new Map<string, number>();
  for (const item of demoEvents) {
    const stamp = Date.parse(item.timestamp);
    if (Number.isNaN(stamp)) continue;
    const at = new Date(Math.floor(stamp / 3600000) * 3600000).toISOString();
    demoCounts.set(at, (demoCounts.get(at) ?? 0) + 1);
  }
  const shownTimeline = demo ? {
    interval: "1h" as const,
    buckets: Array.from(demoCounts, ([at, count]) => ({ at, count })).sort((a, b) => a.at.localeCompare(b.at)),
    total: demoEvents.length,
    scanned_limit: demoEvents.length,
  } : timeline;

  async function save() {
    if (!source || !profile) return;
    setSaving(true);
    setError("");
    setMessage("");
    try {
      const updated = await apiPut<Annotation>(`/api/investigations/attackers/${encodeURIComponent(source)}/annotation`, {
        ...draft, tags: tags.split(",").map((tag) => tag.trim()).filter(Boolean),
      });
      setProfile({ ...profile, annotation: updated });
      setDraft(updated);
      setTags(updated.tags.join(", "));
      setMessage("Ficha guardada. Los eventos originales no se modificaron.");
      void loadHistory();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "No se pudo guardar");
    } finally { setSaving(false); }
  }

  async function downloadEvidence(format: "csv" | "json") {
    if (!source) return;
    const token = getToken();
    if (!token) { setError("Inicia sesión para exportar evidencia real."); return; }
    setExporting(format);
    setError("");
    try {
      const response = await fetch(`/api/investigations/attackers/${encodeURIComponent(source)}/export?format=${format}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) {
        throw new Error(response.status === 401 ? "Sesión expirada: inicia sesión de nuevo para exportar." :
          response.status === 403 ? "Tu sesión no permite exportar: usa una cuenta de usuario con rol viewer o superior." :
          "No se pudo exportar la evidencia. Verifica la conexión y vuelve a intentarlo.");
      }
      const disposition = response.headers.get("Content-Disposition") ?? "";
      const filename = /filename="([a-zA-Z0-9._:-]+)"/.exec(disposition)?.[1] ?? `dystopia-export.${format}`;
      const url = URL.createObjectURL(await response.blob());
      try {
        const link = document.createElement("a");
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
      } finally { URL.revokeObjectURL(url); }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "No se pudo descargar la evidencia; vuelve a intentarlo.");
    } finally { setExporting(null); }
  }

  async function loadMore() {
    if (!source || !profile) return;
    setLoading(true);
    setError("");
    try {
      const next = await apiGet<Pick<Profile, "items" | "total">>(`/api/investigations/attackers/${encodeURIComponent(source)}?offset=${offset}&limit=50&summary=false`);
      setProfile({ ...profile, items: [...profile.items, ...next.items] });
      setOffset(offset + next.items.length);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "No se pudieron cargar más eventos"); }
    finally { setLoading(false); }
  }

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="event-drawer investigation-drawer" role="dialog" aria-modal="true" aria-label={`Ficha del origen ${source}`} onClick={(event) => event.stopPropagation()}>
        <div className="drawer-head">
          <div><span className="eyebrow">Ficha de origen · IP observada</span><h2 className="mono">{source}</h2><span className="muted">Una IP no identifica por sí sola a una persona.</span></div>
          <button className="icon-button" onClick={onClose} aria-label="Cerrar ficha" autoFocus><X size={18} /></button>
        </div>
        {demo && <p className="investigation-notice">Datos de demostración. Inicia sesión y conecta la ingesta para consultar evidencia real y guardar anotaciones.</p>}
        {loading && !profile && !demo && <p role="status">Cargando evidencia…</p>}
        {error && <p className="investigation-error" role="alert">{error}</p>}
        {message && <p className="investigation-success" role="status">{message}</p>}
        {(profile || demo) && <>
          <div className="investigation-facts">
            <div><span>Eventos en la consulta</span><strong>{demo ? demoEvents.length : profile?.total}</strong></div>
            <div><span>Primera actividad</span><strong>{formatTime(demo ? demoFirst : profile?.first_seen)}</strong></div>
            <div><span>Última actividad</span><strong>{formatTime(demo ? demoLast : profile?.last_seen)}</strong></div>
            <div><span>Geolocalización aproximada</span><strong>{demo ? demoCountry : profile?.city || profile?.country || "Sin dato"}</strong></div>
          </div>
          {!demo && <p className="muted investigation-scope">Consulta de los últimos 90 días, limitada a {profile?.scanned_limit?.toLocaleString("es-MX")} eventos recientes del almacén. El total mostrado no es histórico exhaustivo.</p>}
          <section className="investigation-section" aria-label="Actividad por intervalo UTC">
             <h3>Línea de tiempo · actividad por {shownTimeline?.interval === "1d" ? "día" : "hora"} UTC</h3>
             {timelineError && <p className="investigation-error" role="status">{timelineError}</p>}
             {shownTimeline?.buckets.length ? <div role="img" aria-label={`${shownTimeline.total} eventos en ${shownTimeline.buckets.length} intervalos UTC`}>
               <EChart option={attackerTimelineOption(shownTimeline.buckets, shownTimeline.interval)} height={180} />
             </div> : <p className="muted">{shownTimeline ? "Sin eventos en la ventana consultada." : "Cargando línea de tiempo…"}</p>}
             {shownTimeline && !demo && <p className="muted">Hasta {shownTimeline.scanned_limit.toLocaleString("es-MX")} eventos por origen · últimos 90 días.</p>}
           </section>
           {!demo && <section className="investigation-section"><h3>Actividad observada</h3>
            {([ ["Sensores", profile?.sensors], ["Protocolos", profile?.protocols], ["Acciones", profile?.kinds], ["Dispositivos", profile?.devices] ] as Array<[string, Record<string, number> | undefined]>).map(([label, values]) => (
              <div className="investigation-breakdown" key={label}><span>{label}</span><div>{Object.entries(values ?? {}).map(([name, count]) => <span className="sensor-chip" key={name}>{name} · {count}</span>)}{!Object.keys(values ?? {}).length && "Sin dato"}</div></div>
            ))}
          </section>}
          <section className="investigation-section"><h3>Análisis del operador</h3>
            <p className="muted">Solo se editan las anotaciones; la evidencia capturada permanece intacta.</p>
            <div className="investigation-form">
              <label>Alias<input value={draft.alias} maxLength={80} disabled={!canEdit || demo} onChange={(event) => setDraft({ ...draft, alias: event.target.value })} placeholder="Nombre para identificar este origen" /></label>
              <label>Clasificación<select value={draft.classification} disabled={!canEdit || demo} onChange={(event) => setDraft({ ...draft, classification: event.target.value })}>{CLASSIFICATIONS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
              <label>Etiquetas · separadas por coma<input value={tags} disabled={!canEdit || demo} onChange={(event) => setTags(event.target.value)} placeholder="ssh, revisión" /></label>
              <label>Notas<textarea value={draft.notes} maxLength={4000} rows={4} disabled={!canEdit || demo} onChange={(event) => setDraft({ ...draft, notes: event.target.value })} placeholder="Hallazgos y contexto del análisis" /></label>
              {canEdit && !demo && <button className="button primary" onClick={save} disabled={saving}>{saving ? "Guardando…" : "Guardar ficha"}</button>}
              {!canEdit && !demo && <span className="muted">Necesitas rol de operador o administrador para editar.</span>}
            </div>
          </section>
          <section className="investigation-section">
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <h3>Evidencia · {evidence.length} de {demo ? demoEvents.length : profile?.total}</h3>
              {!demo && <>
                <button className="button ghost" disabled={exporting !== null} onClick={() => void downloadEvidence("csv")}>{exporting === "csv" ? "Exportando…" : "Exportar CSV"}</button>
                <button className="button ghost" disabled={exporting !== null} onClick={() => void downloadEvidence("json")}>{exporting === "json" ? "Exportando…" : "Exportar JSON"}</button>
              </>}
            </div>
            <p className="muted">Exporta solo la muestra consultada; no es un historial exhaustivo</p>
            {!evidence.length && <p className="muted">No hay eventos de este origen en la ventana consultada.</p>}
            {evidence.map((item, index) => <details className="investigation-event" key={`${item.sensor}-${item.id}-${index}`}>
              <summary><time>{formatTime(item.timestamp)}</time><strong>{item.action}</strong><span className="mono">{item.sensor} · {item.proto}</span></summary>
              <div className="investigation-event-body"><p>{item.message}</p><p className="muted">ID {item.id} · Dispositivo {item.device || "Sin dato"} · Puerto origen {item.port ?? "Sin dato"} · Severidad {item.severity}</p><span className="eyebrow">Detalle capturado</span><pre>{JSON.stringify(item.detail, null, 2)}</pre></div>
            </details>)}
            {!demo && offset < (profile?.total ?? 0) && <button className="button ghost" disabled={loading} onClick={loadMore}>{loading ? "Cargando…" : "Cargar otros 50 eventos"}</button>}
          </section>
          {!demo && <section className="investigation-section"><h3>Historial de anotaciones</h3>
            <p className="muted">Registro append-only de quién cambió qué. No modifica la evidencia capturada.</p>
            {!history.length ? <p className="muted">Sin cambios registrados.</p> : <ol className="audit-list">{history.map((entry) => (
              <li className="audit-entry" key={entry.id}>
                <div className="audit-meta"><strong>revisión {entry.revision}</strong><time>{formatTime(entry.at)}</time><span className="mono">{entry.actor}</span></div>
                <div className="audit-changes">{entry.changes.length ? entry.changes.map((change) => (
                  <span className="audit-change" key={change.field}><b>{change.field}</b>: {showValue(change.from)} → {showValue(change.to)}</span>
                )) : <span className="muted">Sin cambios de contenido</span>}</div>
              </li>
            ))}</ol>}
          </section>}
        </>}
      </aside>
    </div>
  );
}
