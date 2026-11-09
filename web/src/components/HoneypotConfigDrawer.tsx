import { useEffect, useState } from "react";
import { X } from "lucide-react";
import { apiGet, apiPut, getToken } from "../lib/api";
import type { Honeypot, HoneypotConfig } from "../types";
import type { DataMode } from "../data/useAnalytics";

interface HoneypotConfigDrawerProps {
  honeypot: Honeypot | null;
  config: HoneypotConfig | null;
  onClose: () => void;
  mode: DataMode;
}

type Draft = { revision: number; display_name: string; description: string; memory_mib: number; cpus: number; pids_limit: number; updated_at?: string };
type PlanChange = { field: string; from: unknown; to: unknown };
type Plan = { sensor: string; baseline: Draft; draft: Draft | null; changes: PlanChange[]; changed: boolean; plan_sha256: string; activation: string; blocking_reasons: string[] };
type AuditEntry = { id: number; at: string; actor: string; revision: number; changes: PlanChange[] };
type SensorResponse = { sensor: string; draft: Draft | null; plan: Plan; application: string; reason: string };
const showValue = (value: unknown) => Array.isArray(value) ? value.join(", ") : value && typeof value === "object" ? JSON.stringify(value) : String(value ?? "—");

export function HoneypotConfigDrawer({ honeypot, config, onClose, mode }: HoneypotConfigDrawerProps) {
  const [draft, setDraft] = useState<Draft | null>(null);
  const [canEdit, setCanEdit] = useState(false);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [plan, setPlan] = useState<Plan | null>(null);
  const [history, setHistory] = useState<AuditEntry[]>([]);

  async function loadHistory(sensor: string) {
    if (!getToken()) return;
    try {
      const data = await apiGet<{ items: AuditEntry[] }>(`/api/investigations/honeypots/${encodeURIComponent(sensor)}/history?limit=20`);
      setHistory(data.items);
    } catch { /* El historial no bloquea la configuración. */ }
  }

  useEffect(() => {
    if (!honeypot || !config || !getToken()) return;
    const controller = new AbortController();
    setLoading(true);
    setError("");
    setMessage("");
    setDraft(null);
    setPlan(null);
    setHistory([]);
    void loadHistory(honeypot.id);
    Promise.all([
      apiGet<SensorResponse>(`/api/investigations/honeypots/${encodeURIComponent(honeypot.id)}`, controller.signal),
      apiGet<{ role: string }>("/api/console/capabilities", controller.signal),
    ]).then(([data, capabilities]) => {
      if (controller.signal.aborted) return;
      setCanEdit(capabilities.role === "admin");
      setPlan(data.plan);
      setDraft(data.draft ?? {
        revision: 0, display_name: honeypot.name, description: config.description,
        memory_mib: Number.parseInt(config.resources.memLimit, 10),
        cpus: Number.parseFloat(config.resources.cpus), pids_limit: config.resources.pidsLimit,
      });
    }).catch((cause: unknown) => { if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "No se pudo cargar la configuración"); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [honeypot?.id, mode]);

  async function save() {
    if (!honeypot || !draft) return;
    setSaving(true);
    setError("");
    setMessage("");
    try {
      const result = await apiPut<SensorResponse>(`/api/investigations/honeypots/${encodeURIComponent(honeypot.id)}`, draft);
      setDraft(result.draft);
      setPlan(result.plan);
      void loadHistory(honeypot.id);
      setMessage("Borrador guardado. Aún no se aplicó al contenedor.");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "No se pudo guardar"); }
    finally { setSaving(false); }
  }

  if (!honeypot || !config) return null;

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="event-drawer config-drawer" onClick={(event) => event.stopPropagation()}>
        <div className="drawer-head">
          <div>
            <span className="eyebrow">Honeypot / configuration</span>
            <h2>{honeypot.name}</h2>
            <span className="mono muted">{config.container}</span>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Cerrar configuración"><X size={18} /></button>
        </div>

        <div className="drawer-badges">
          <span className={`health-pill ${honeypot.status}`}><i />{honeypot.status === "degraded" ? "Sin verificar" : honeypot.status}</span>
          <span className="sensor-chip">{honeypot.service}</span>
          <span className="proto-chip">{config.logFormat}</span>
        </div>

        <p className="config-description">{config.description}</p>
        <section className="config-block investigation-section">
          <h3>Configuración editable</h3>
          <p className="muted">Los cambios se guardan como borrador. No modifican el inventario ni el contenedor hasta que exista una aplicación segura y verificada.</p>
          {!getToken() && <p className="investigation-notice">Vista de demostración. Inicia sesión para guardar una configuración.</p>}
          {loading && <p role="status">Cargando borrador…</p>}
          {error && <p className="investigation-error" role="alert">{error}</p>}
          {message && <p className="investigation-success" role="status">{message}</p>}
          {draft && getToken() && <div className="investigation-form">
            <label>Nombre visible<input value={draft.display_name} maxLength={80} disabled={!canEdit} onChange={(event) => setDraft({ ...draft, display_name: event.target.value })} /></label>
            <label>Descripción<textarea value={draft.description} maxLength={500} rows={3} disabled={!canEdit} onChange={(event) => setDraft({ ...draft, description: event.target.value })} /></label>
            <div className="investigation-fields">
              <label>Memoria · MiB<input type="number" min={128} max={4096} value={draft.memory_mib} disabled={!canEdit} onChange={(event) => setDraft({ ...draft, memory_mib: Number(event.target.value) })} /></label>
              <label>CPU<input type="number" min={0.1} max={4} step={0.05} value={draft.cpus} disabled={!canEdit} onChange={(event) => setDraft({ ...draft, cpus: Number(event.target.value) })} /></label>
              <label>PID máximos<input type="number" min={32} max={1024} value={draft.pids_limit} disabled={!canEdit} onChange={(event) => setDraft({ ...draft, pids_limit: Number(event.target.value) })} /></label>
            </div>
            {canEdit ? <button className="button primary" disabled={saving || !draft.display_name.trim()} onClick={save}>{saving ? "Guardando…" : "Guardar borrador"}</button> : <span className="muted">Necesitas rol de administrador para editar.</span>}
            <span className="muted">Aplicación a contenedores: bloqueada hasta disponer de verificación independiente del aislamiento y un ciclo de vida de sensores autorizado.</span>
          </div>}
        </section>

        {plan && getToken() && <section className="config-block investigation-section">
          <h3>Plan de cambios</h3>
          <p className="muted">Diferencia declarativa frente a <code>deploy/honeypots/inventory.yaml</code>. No es una autorización de ejecución.</p>
          {plan.changes.length ? <ul className="plan-list">{plan.changes.map((change) => (
            <li className="plan-change" key={change.field}><b>{change.field}</b><span>{showValue(change.from)} → {showValue(change.to)}</span></li>
          ))}</ul> : <p className="muted">El borrador coincide con el inventario declarado.</p>}
          <div className="plan-meta"><span className="mono">sha256 {plan.plan_sha256.slice(0, 16)}…</span><span className="health-pill degraded"><i />aplicación bloqueada</span></div>
          <ul className="plan-blockers">{plan.blocking_reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
        </section>}

        {history.length > 0 && <section className="config-block investigation-section">
          <h3>Historial de borradores</h3>
          <ol className="audit-list">{history.map((entry) => (
            <li className="audit-entry" key={entry.id}>
              <div className="audit-meta"><strong>revisión {entry.revision}</strong><time>{new Date(entry.at).toLocaleString("es-MX")}</time><span className="mono">{entry.actor}</span></div>
              <div className="audit-changes">{entry.changes.length ? entry.changes.map((change) => (
                <span className="audit-change" key={change.field}><b>{change.field}</b>: {showValue(change.from)} → {showValue(change.to)}</span>
              )) : <span className="muted">Sin cambios de contenido</span>}</div>
            </li>
          ))}</ol>
        </section>}

        <div className="honeypot-config-grid">
          <div><span>Imagen</span><strong className="mono">{config.image}</strong></div>
          <div><span>Dispositivo</span><strong className="mono">{config.device}</strong></div>
          <div><span>Usuario</span><strong className="mono">{config.user}</strong></div>
          <div><span>Puerto host</span><strong className="mono">127.0.0.1:{honeypot.port}</strong></div>
        </div>

        <section className="config-block">
          <span className="eyebrow">Archivo de configuración</span>
          <div className="config-code-row"><span className="mono">{config.configTarget}</span><span>{config.configFile}</span></div>
        </section>

        <section className="config-block">
          <span className="eyebrow">Puertos declarados</span>
          <div className="config-port-list">
            {config.ports.map((port) => (
              <div key={`${port.container}-${port.proto}`}>
                <span className="mono">{port.container}/{port.proto}</span>
                <span>{port.purpose}</span>
                <span className="mono muted">{port.host ? `host :${port.host}` : "interno"}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="config-block">
          <span className="eyebrow">Volúmenes</span>
          <div className="config-list">
            {config.volumes.map((volume) => <span className="mono" key={volume}>{volume}</span>)}
          </div>
        </section>

        <section className="config-block">
          <span className="eyebrow">Log y salud</span>
          <div className="config-kv">
            <div><span>Log</span><strong className="mono">{config.logPath}</strong></div>
            <div><span>Formato</span><strong className="mono">{config.logFormat}</strong></div>
            <div><span>Healthcheck</span><strong>{config.healthcheck.type} · {config.healthcheck.marker}</strong></div>
            <div><span>Intervalo</span><strong>{config.healthcheck.interval} · start {config.healthcheck.startPeriod}</strong></div>
          </div>
        </section>

        <section className="config-block">
          <span className="eyebrow">Recursos asignados</span>
          <div className="honeypot-config-grid compact">
            <div><span>Memoria</span><strong>{config.resources.memLimit}</strong></div>
            <div><span>CPU</span><strong>{config.resources.cpus}</strong></div>
            <div><span>PIDs</span><strong>{config.resources.pidsLimit}</strong></div>
            <div><span>Nofile</span><strong>{config.resources.nofile}</strong></div>
            <div><span>Tmpfs</span><strong>{config.resources.tmpfsMib} MiB</strong></div>
          </div>
        </section>

        <div className="config-footnote">
          Configuración declarada en <code>deploy/honeypots/inventory.yaml</code>. La interfaz no inicia, detiene ni modifica contenedores.
        </div>
      </aside>
    </div>
  );
}
