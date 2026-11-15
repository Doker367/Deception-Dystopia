import { useEffect, useMemo, useState } from "react";
import { Ban, Check, Copy, Radio, RefreshCw, ShieldAlert, Terminal, X } from "lucide-react";
import { apiDelete, apiGet, apiPost, apiPut, getToken } from "../lib/api";
import { HONEYPOTS } from "../data/mock";
import { EChart } from "./EChart";
import { attackerTimelineOption } from "../lib/charts";
import { bestFingerprint, formatBattery, formatStorage } from "../lib/fingerprint";
import { scopeLabel } from "../lib/format";
import type { EventRow } from "../types";
import type { DataMode } from "../data/useAnalytics";

interface Annotation {
  revision: number;
  alias: string;
  classification: string;
  handling: "none" | "monitor" | "lock" | "redirect";
  handling_target: string;
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
  dst_ip?: string;
  dst_port?: number | null;
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
  countryCode?: string;
  region?: string;
  regionCode?: string;
  city?: string;
  scope?: string;
  /** Última huella de navegador encontrada fuera de la página de evidencia. */
  fingerprint?: string | null;
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
interface BlockEntry { ip: string; reason?: string; hits?: number; blocked_at?: string; last_blocked?: string }
const EMPTY: Annotation = { revision: 0, alias: "", classification: "unclassified", handling: "none", handling_target: "", tags: [], notes: "" };
const HANDLING_LABEL: Record<Annotation["handling"], string> = {
  none: "Sin acción", monitor: "En vigilancia", lock: "Bloqueo registrado", redirect: "Redirigir a otra trampa",
};
const HANDLING_ORDER = ["useragent", "path", "method", "username", "session", "command"] as const;

function summarize(items: Evidence[]) {
  const counters = new Map<string, Map<string, number>>();
  for (const item of items) {
    const detail = item.detail ?? {};
    for (const field of HANDLING_ORDER) {
      const value = detail[field];
      if (typeof value !== "string" || !value) continue;
      const bucket = counters.get(field) ?? new Map<string, number>();
      bucket.set(value, (bucket.get(value) ?? 0) + 1);
      counters.set(field, bucket);
    }
    if (item.dst_port) {
      const bucket = counters.get("dst_port") ?? new Map<string, number>();
      const key = String(item.dst_port);
      bucket.set(key, (bucket.get(key) ?? 0) + 1);
      counters.set("dst_port", bucket);
    }
  }
  return Array.from(counters, ([field, values]) => [field, Array.from(values).sort((a, b) => b[1] - a[1]).slice(0, 8)] as const);
}
const showValue = (value: unknown) => Array.isArray(value) ? value.join(", ") : value && typeof value === "object" ? JSON.stringify(value) : String(value ?? "—");
const CLASSIFICATIONS = [
  ["unclassified", "Sin clasificar"], ["scanner", "Escaneo"],
  ["brute_force", "Fuerza bruta"], ["targeted", "Dirigido"],
  ["benign", "Benigno"], ["other", "Otro"],
];
const formatTime = (value?: string) => value ? new Date(value).toLocaleString("es-MX") : "Sin dato";
function locationLabel(profile: Profile | null): string {
  if (!profile) return "Sin dato";
  if (profile.scope && profile.scope !== "public") return scopeLabel(profile.scope);
  const place = [profile.city, profile.region, profile.country].filter(Boolean).join(", ");
  return place || "Sin dato";
}

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
  const [canAdmin, setCanAdmin] = useState(false);
  const [history, setHistory] = useState<AuditEntry[]>([]);
  const [timeline, setTimeline] = useState<SourceTimeline | null>(null);
  const [timelineError, setTimelineError] = useState("");
  const [blockEntry, setBlockEntry] = useState<BlockEntry | null>(null);
  const [blockReason, setBlockReason] = useState("manual desde ficha de atacante");
  const [blocking, setBlocking] = useState(false);
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [following, setFollowing] = useState(false);

  const firewall = useMemo(() => {
    if (!source) return { nft: "", iptables: "" };
    const ipv6 = source.includes(":");
    const family = ipv6 ? "ip6" : "ip";
    const binary = ipv6 ? "ip6tables" : "iptables";
    return {
      nft: [
        `nft add rule inet filter input ${family} saddr ${source} counter drop`,
        `nft add rule inet filter input ${family} daddr ${source} counter drop`,
      ].join("\n"),
      iptables: [
        `${binary} -I INPUT -s ${source} -j DROP`,
        `${binary} -I OUTPUT -d ${source} -j DROP`,
      ].join("\n"),
    };
  }, [source]);

  async function loadHistory() {
    if (!source || mode === "demo" || !getToken()) return;
    try {
      const data = await apiGet<{ items: AuditEntry[] }>(`/api/investigations/attackers/${encodeURIComponent(source)}/history?limit=20`);
      setHistory(data.items);
    } catch { /* El historial no bloquea la ficha. */ }
  }

  useEffect(() => { void loadHistory(); }, [source, mode, reloadKey]);

  useEffect(() => {
    if (!source || mode === "demo" || !getToken()) {
      setCanEdit(false);
      setCanAdmin(false);
      return;
    }
    const controller = new AbortController();
    apiGet<{ role: string }>("/api/console/capabilities", controller.signal)
      .then((data) => {
        if (controller.signal.aborted) return;
        setCanEdit(["admin", "operator"].includes(data.role));
        setCanAdmin(data.role === "admin");
      })
      .catch(() => { if (!controller.signal.aborted) { setCanEdit(false); setCanAdmin(false); } });
    return () => controller.abort();
  }, [source, mode]);

  useEffect(() => {
    setBlockEntry(null);
    if (!source || mode === "demo" || !getToken()) return;
    const controller = new AbortController();
    apiGet<BlockEntry[]>("/api/deception/blocklist", controller.signal)
      .then((entries) => {
        if (!controller.signal.aborted) setBlockEntry(entries.find((entry) => entry.ip === source) ?? null);
      })
      .catch(() => { if (!controller.signal.aborted) setBlockEntry(null); });
    return () => controller.abort();
  }, [source, mode, reloadKey]);

  useEffect(() => {
    setMessage("");
    setError("");
    setFollowing(false);
  }, [source, mode]);

  useEffect(() => {
    if (!following || !source) return;
    const timer = window.setInterval(() => setReloadKey((value) => value + 1), 30_000);
    return () => window.clearInterval(timer);
  }, [following, source]);

  useEffect(() => {
    if (!source || mode === "demo" || !getToken()) return;
    const controller = new AbortController();
    setLoading(true);
    setError("");
    setProfile(null);
    apiGet<Profile>(`/api/investigations/attackers/${encodeURIComponent(source)}?offset=0&limit=50`, controller.signal)
      .then((data) => {
        if (controller.signal.aborted) return;
        setProfile(data);
        setDraft({ ...EMPTY, ...data.annotation });
        setTags((data.annotation.tags ?? []).join(", "));
        setOffset(data.items.length);
      })
      .catch((cause: unknown) => { if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "No se pudo cargar la ficha"); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [source, mode, reloadKey]);

  useEffect(() => {
    setTimeline(null);
    setTimelineError("");
    if (!source || mode === "demo" || !getToken()) return;
    const controller = new AbortController();
    apiGet<SourceTimeline>(`/api/investigations/attackers/${encodeURIComponent(source)}/timeline?interval=1h`, controller.signal)
      .then((data) => { if (!controller.signal.aborted) setTimeline(data); })
      .catch(() => { if (!controller.signal.aborted) setTimelineError("No se pudo cargar la línea de tiempo."); });
    return () => controller.abort();
  }, [source, mode, reloadKey]);

  useEffect(() => {
    if (!source) return;
    const onKey = (keyboardEvent: KeyboardEvent) => {
      if (keyboardEvent.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [source, onClose]);

  if (!source) return null;
  const demo = mode === "demo" || !getToken();
  const demoEvents: Evidence[] = sample.filter((item) => item.source === source).map((item) => ({
    ...item, detail: {}, port: item.port,
  }));
  const evidence = demo ? demoEvents : profile?.items ?? [];
  const fingerprint = demo ? null : bestFingerprint(evidence, profile?.fingerprint);
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
      setDraft({ ...EMPTY, ...updated });
      setTags(updated.tags.join(", "));
      setMessage("Ficha guardada. Los eventos originales no se modificaron.");
      void loadHistory();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "No se pudo guardar");
    } finally { setSaving(false); }
  }

  async function blockSource() {
    if (!source) return;
    setBlocking(true);
    setError("");
    setMessage("");
    try {
      const entry = await apiPost<BlockEntry>("/api/deception/blocklist", {
        ip: source,
        reason: blockReason.trim() || "manual desde ficha de atacante",
      });
      setBlockEntry(entry);
      setMessage("IP registrada en la blocklist. El control no modifica el firewall: aplica la regla en el perímetro autorizado.");
      setReloadKey((value) => value + 1);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "No se pudo registrar en la blocklist");
    } finally {
      setBlocking(false);
    }
  }

  async function unblockSource() {
    if (!source) return;
    setBlocking(true);
    setError("");
    setMessage("");
    try {
      await apiDelete(`/api/deception/blocklist/${encodeURIComponent(source)}`);
      setBlockEntry(null);
      setMessage("IP retirada de la blocklist. Revisa también la regla del firewall perimetral.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "No se pudo retirar de la blocklist");
    } finally {
      setBlocking(false);
    }
  }

  async function copyCommand(key: string, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedCommand(key);
      window.setTimeout(() => setCopiedCommand(null), 1600);
    } catch { /* clipboard may be blocked; the command remains visible */ }
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
            <div><span>Geolocalización aproximada</span><strong>{demo ? (demoCountry || "Sin dato") : locationLabel(profile)}</strong></div>
          </div>
          {!demo && draft.handling !== "none" && <p className="investigation-notice">Resguardo: {HANDLING_LABEL[draft.handling]}{draft.handling === "redirect" && draft.handling_target ? ` → ${draft.handling_target}` : ""}</p>}
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
          {!demo && <section className="investigation-section"><h3>Huella observada</h3>
            <p className="muted">Campos normalizados de la evidencia; las contraseñas nunca se muestran.</p>
            {summarize(profile?.items ?? []).map(([field, values]) => (
              <div className="investigation-breakdown" key={field}>
                <span>{field}</span>
                <div>{values.map(([name, count]) => <span className="sensor-chip" key={name}>{name} · {count}</span>)}</div>
              </div>
            ))}
          </section>}
          {!demo && <section className="investigation-section"><h3>Dispositivo / navegador</h3>
            <p className="muted">Huella del navegador que abrió el panel falso: sistema operativo, CPU, RAM, táctil, batería, GPU y pantalla. SSH/Telnet no pueden exponer estos datos; solo se obtienen si el atacante ejecutó JavaScript en un señuelo HTTP.</p>
            {fingerprint ? <>
              <div className="investigation-facts">
                <div><span>Sistema operativo</span><strong>{String(fingerprint.client.os || fingerprint.client.platform || "—")}{fingerprint.client.osVersion ? ` · ${String(fingerprint.client.osVersion)}` : ""}</strong></div>
                <div><span>Arquitectura</span><strong>{[fingerprint.client.arch, fingerprint.client.bitness ? `${String(fingerprint.client.bitness)} bits` : ""].filter(Boolean).join(" · ") || "—"}</strong></div>
                <div><span>Modelo / móvil</span><strong>{String(fingerprint.client.model || "—")} · {fingerprint.client.mobile ? "móvil" : "escritorio"}</strong></div>
                <div><span>CPU</span><strong>{fingerprint.client.cores != null ? `${String(fingerprint.client.cores)} hilos` : "—"}</strong></div>
                <div><span>RAM</span><strong>{fingerprint.client.ram_gb != null || fingerprint.client.memory != null ? `${String(fingerprint.client.ram_gb ?? fingerprint.client.memory)} GB (estimada)` : "—"}</strong></div>
                <div><span>Táctil</span><strong>{fingerprint.client.touchscreen ? `Sí · ${String(fingerprint.client.touch ?? 0)} puntos simultáneos` : "No"}</strong></div>
                <div><span>Batería</span><strong>{formatBattery(fingerprint.client.battery)}</strong></div>
                <div><span>Pantalla</span><strong>{String(fingerprint.client.screen ?? "—")} · viewport {String(fingerprint.client.viewport ?? "—")} · DPR {String(fingerprint.client.dpr ?? "—")}</strong></div>
                <div><span>GPU / WebGL</span><strong>{[fingerprint.client.gpuVendor, fingerprint.client.webgl].filter(Boolean).join(" · ") || "—"}</strong></div>
                <div><span>Almacenamiento</span><strong>{formatStorage(fingerprint.client.storage)}</strong></div>
                <div><span>Zona / idioma</span><strong>{String(fingerprint.client.tz ?? "—")} · {String(fingerprint.client.languages || fingerprint.client.lang || "—")}</strong></div>
                <div><span>Automatización</span><strong>webdriver: {String(fingerprint.client.webdriver ?? "—")} · cookies: {String(fingerprint.client.cookie ?? "—")}</strong></div>
                <div><span>Client hints</span><strong>{String(fingerprint.headers["sec-ch-ua"] ?? fingerprint.client.brands ?? "—")} · móvil {String(fingerprint.headers["sec-ch-ua-mobile"] ?? fingerprint.client.mobile ?? "—")}</strong></div>
                <div><span>Conexión</span><strong>{fingerprint.client.connection ? `${String((fingerprint.client.connection as { type?: string }).type ?? "—")}${(fingerprint.client.connection as { down?: number }).down ? ` · ${(fingerprint.client.connection as { down?: number }).down} Mbps` : ""}${(fingerprint.client.connection as { rtt?: number }).rtt ? ` · ${(fingerprint.client.connection as { rtt?: number }).rtt} ms` : ""}` : "—"}</strong></div>
                <div><span>User-Agent</span><strong>{String(fingerprint.client.ua ?? "—")}</strong></div>
              </div>
              <details className="investigation-event">
                <summary><strong>Huella completa</strong><span className="mono">JSON capturado</span></summary>
                <div className="investigation-event-body"><pre>{JSON.stringify(fingerprint.client, null, 2)}</pre></div>
              </details>
            </> : <p className="muted">Sin telemetría de navegador: el cliente no ejecutó JavaScript, lo bloqueó o es una herramienta de terminal/automatizada. Las conexiones SSH, Telnet, FTP o Redis no exponen batería, RAM ni núcleos.</p>}
          </section>}
          <section className="investigation-section">
            <h3>Respuesta al atacante</h3>
            <p className="muted">El control plane registra y documenta la respuesta, pero no ejecuta firewall ni aísla la máquina del atacante. La contención real se aplica en el perímetro o en el helper de aislamiento autorizado.</p>
            <div className="response-grid">
              <div className="response-card">
                <div className="response-head">
                  <span className="eyebrow">Blocklist</span>
                  <span className={`response-state ${blockEntry ? "on" : ""}`}>{blockEntry ? "Registrada" : "No registrada"}</span>
                </div>
                {blockEntry ? <>
                  <strong>{blockEntry.reason || "Sin motivo"}</strong>
                  <span className="muted">{blockEntry.hits ?? 1} registro(s) · {formatTime(blockEntry.last_blocked || blockEntry.blocked_at)}</span>
                  <button className="button ghost" onClick={() => void unblockSource()} disabled={!canAdmin || blocking}>
                    {blocking ? "Procesando…" : "Quitar de blocklist"}
                  </button>
                  {!canAdmin && <span className="muted">Requiere rol admin.</span>}
                </> : <>
                  <label className="response-field">Motivo
                    <input value={blockReason} maxLength={120} disabled={!canAdmin || blocking}
                      onChange={(event) => setBlockReason(event.target.value)} />
                  </label>
                  <button className="button primary" onClick={() => void blockSource()} disabled={!canAdmin || blocking}>
                    {blocking ? "Registrando…" : <><Ban size={14} /> Añadir a blocklist</>}
                  </button>
                  {!canAdmin && <span className="muted">Requiere rol admin para modificar la blocklist.</span>}
                </>}
              </div>
              <div className="response-card">
                <div className="response-head">
                  <span className="eyebrow"><Terminal size={12} /> Firewall perimetral</span>
                  <span className="response-state">Dry-run</span>
                </div>
                <p className="muted">Copia la regla al firewall autorizado. El control no la ejecuta.</p>
                <div className="response-command">
                  <div>
                    <span className="mono">nftables</span>
                    <button className="link-button" onClick={() => void copyCommand("nft", firewall.nft)}>
                      {copiedCommand === "nft" ? <Check size={12} /> : <Copy size={12} />}
                      {copiedCommand === "nft" ? "Copiado" : "Copiar"}
                    </button>
                  </div>
                  <pre>{firewall.nft}</pre>
                </div>
                <details className="response-details">
                  <summary>Ver regla iptables / ip6tables</summary>
                  <div className="response-command">
                    <div>
                      <span className="mono">iptables</span>
                      <button className="link-button" onClick={() => void copyCommand("iptables", firewall.iptables)}>
                        {copiedCommand === "iptables" ? <Check size={12} /> : <Copy size={12} />}
                        {copiedCommand === "iptables" ? "Copiado" : "Copiar"}
                      </button>
                    </div>
                    <pre>{firewall.iptables}</pre>
                  </div>
                </details>
              </div>
            </div>
            <div className="response-note">
              <strong><ShieldAlert size={14} /> Cuarentena y observación</strong>
              <p>No puedes aislar la máquina del atacante desde el señuelo. Puedes contener su tráfico en el perímetro, redirigirlo a otra trampa y conservar/exportar la evidencia. Si quieres seguir viendo qué hace, no lo bloquees todavía: el bloqueo corta la colección desde esa IP.</p>
              <div className="response-actions">
                <button className="button ghost" onClick={() => setReloadKey((value) => value + 1)}>
                  <RefreshCw size={14} /> Actualizar ficha y evidencia
                </button>
                <button className={`button ${following ? "primary" : "ghost"}`} onClick={() => setFollowing((value) => !value)}>
                  <Radio size={14} /> {following ? "Seguimiento activo · 30 s" : "Seguir actividad"}
                </button>
              </div>
              {following && <p className="muted">El seguimiento recarga la primera página de evidencia y la línea de tiempo cada 30 segundos.</p>}
            </div>
          </section>
          <section className="investigation-section"><h3>Análisis del operador</h3>
            <p className="muted">Solo se editan las anotaciones; la evidencia capturada permanece intacta.</p>
            <div className="investigation-form">
              <label>Alias<input value={draft.alias} maxLength={80} disabled={!canEdit || demo} onChange={(event) => setDraft({ ...draft, alias: event.target.value })} placeholder="Nombre para identificar este origen" /></label>
              <label>Clasificación<select value={draft.classification} disabled={!canEdit || demo} onChange={(event) => setDraft({ ...draft, classification: event.target.value })}>{CLASSIFICATIONS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
              <label>Resguardo<select value={draft.handling} disabled={!canEdit || demo} onChange={(event) => setDraft({ ...draft, handling: event.target.value as Annotation["handling"], handling_target: event.target.value === "redirect" ? draft.handling_target : "" })}>
                <option value="none">Sin acción</option>
                <option value="monitor">Monitorear</option>
                <option value="lock">Bloquear (registrado)</option>
                <option value="redirect">Enviar a otra trampa</option>
              </select></label>
              {draft.handling === "redirect" && <label>Trampa destino<select value={draft.handling_target} disabled={!canEdit || demo} onChange={(event) => setDraft({ ...draft, handling_target: event.target.value })}>
                <option value="">Selecciona un sensor</option>
                {HONEYPOTS.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
              </select></label>}
              <span className="muted">El resguardo queda registrado y auditado; el bloqueo o redirección real requiere el gate de red autorizado.</span>
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
              <div className="investigation-event-body"><p>{item.message}</p><p className="muted">ID {item.id} · Dispositivo {item.device || "Sin dato"} · Origen {item.port ?? "Sin dato"} · Destino {item.dst_ip || "Sin dato"}:{item.dst_port ?? "Sin dato"} · Severidad {item.severity}</p><span className="eyebrow">Detalle capturado</span><pre>{JSON.stringify(item.detail, null, 2)}</pre></div>
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
