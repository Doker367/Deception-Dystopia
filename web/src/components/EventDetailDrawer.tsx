import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  ArrowUpRight,
  Ban,
  Check,
  Clock3,
  Copy,
  Download,
  Fingerprint,
  MapPin,
  Network,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";
import { SeverityBadge } from "./SeverityBadge";
import { apiDelete, apiGet, apiPost, getToken } from "../lib/api";
import {
  countryFlag,
  formatFullDateTime,
  relativeTime,
  scopeLabel,
} from "../lib/format";
import { fingerprintFacts, parseFingerprintValue } from "../lib/fingerprint";
import { downloadJson } from "../lib/download";
import type { EventRow } from "../types";

const DETAIL_LABELS: Record<string, string> = {
  engine: "Motor",
  eventid: "ID en el motor",
  message: "Mensaje del sensor",
  path: "Ruta",
  method: "Método HTTP",
  useragent: "User-Agent",
  username: "Usuario",
  command: "Comando",
  url: "URL",
  file: "Archivo",
  md5_hash: "MD5",
  sha256_hash: "SHA-256",
  shasum: "Hash",
  session: "Sesión",
  host: "Host",
  source_event_id: "Huella del registro",
  success: "Resultado",
  mitre: "MITRE ATT&CK",
  password: "Contraseña",
  pass: "Contraseña",
  pwd: "Contraseña",
  service: "Servicio",
  dst_port: "Puerto destino",
};

const SENSITIVE_KEYS = new Set(["password", "pass", "pwd", "token", "secret", "api_key", "apikey"]);

interface BlockEntry { ip: string; reason?: string; hits?: number; blocked_at?: string }

function humanValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return value ? "Sí" : "No";
  if (typeof value === "object") return JSON.stringify(value, null, 2);
  return String(value);
}

function endpoint(ip?: string | null, port?: number | null): string {
  if (!ip && port == null) return "";
  return `${ip || "—"}:${port ?? "—"}`;
}

function locationFor(event: EventRow): string {
  if (event.scope && event.scope !== "public") return scopeLabel(event.scope);
  const place = [event.city, event.region, event.country].filter(Boolean).join(", ");
  return place || event.country || "Sin dato";
}

function Fact({ label, children, value, mono }: {
  label: string;
  children?: ReactNode;
  value?: string;
  mono?: boolean;
}) {
  return (
    <div className="event-detail-fact">
      <span>{label}</span>
      {children ?? <strong className={mono ? "mono" : undefined}>{value || "—"}</strong>}
    </div>
  );
}

export function EventDetailDrawer({ event, onClose, onOpenAttacker }: {
  event: EventRow;
  onClose: () => void;
  onOpenAttacker?: (source: string) => void;
}) {
  const [copied, setCopied] = useState<string | null>(null);
  const [blockEntry, setBlockEntry] = useState<BlockEntry | null>(null);
  const [canAdmin, setCanAdmin] = useState(false);
  const [blockBusy, setBlockBusy] = useState(false);
  const [blockNotice, setBlockNotice] = useState("");
  const [blockError, setBlockError] = useState("");
  const detail = event.detail ?? {};
  const fingerprint = useMemo(
    () => typeof detail.fingerprint === "string" ? parseFingerprintValue(detail.fingerprint) : null,
    [detail.fingerprint],
  );

  useEffect(() => {
    if (!getToken()) return;
    const controller = new AbortController();
    apiGet<{ role: string }>("/api/console/capabilities", controller.signal)
      .then((data) => { if (!controller.signal.aborted) setCanAdmin(data.role === "admin"); })
      .catch(() => { if (!controller.signal.aborted) setCanAdmin(false); });
    return () => controller.abort();
  }, [event.id]);

  useEffect(() => {
    setBlockNotice("");
    setBlockError("");
    if (!event.source || !getToken()) {
      setBlockEntry(null);
      return;
    }
    const controller = new AbortController();
    apiGet<BlockEntry[]>("/api/deception/blocklist", controller.signal)
      .then((entries) => {
        if (!controller.signal.aborted) setBlockEntry(entries.find((entry) => entry.ip === event.source) ?? null);
      })
      .catch(() => { if (!controller.signal.aborted) setBlockEntry(null); });
    return () => controller.abort();
  }, [event.id, event.source]);

  async function blockSource() {
    if (!event.source) return;
    setBlockBusy(true);
    setBlockError("");
    setBlockNotice("");
    try {
      const entry = await apiPost<BlockEntry>("/api/deception/blocklist", {
        ip: event.source,
        reason: "desde detalle de evento",
      });
      setBlockEntry(entry);
      setBlockNotice("IP registrada en blocklist. No aplica firewall por sí sola.");
    } catch (cause) {
      setBlockError(cause instanceof Error ? cause.message : "No se pudo registrar la IP");
    } finally {
      setBlockBusy(false);
    }
  }

  async function unblockSource() {
    if (!event.source) return;
    setBlockBusy(true);
    setBlockError("");
    setBlockNotice("");
    try {
      await apiDelete(`/api/deception/blocklist/${encodeURIComponent(event.source)}`);
      setBlockEntry(null);
      setBlockNotice("IP retirada de la blocklist.");
    } catch (cause) {
      setBlockError(cause instanceof Error ? cause.message : "No se pudo retirar la IP");
    } finally {
      setBlockBusy(false);
    }
  }

  useEffect(() => {
    const onKey = (keyboardEvent: KeyboardEvent) => {
      if (keyboardEvent.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  useEffect(() => setCopied(null), [event.id]);

  const location = locationFor(event);
  const destination = endpoint(event.dst_ip, event.dst_port);
  const mitre = typeof detail.mitre === "string" ? detail.mitre : "";
  const mitreUrl = /^T\d{4}(\.\d{3})?$/.test(mitre)
    ? `https://attack.mitre.org/techniques/${mitre.split(".")[0]}/`
    : null;
  const resultApplies = ["login_attempt", "login_success", "command", "file_download", "port_scan"].includes(event.kind);
  const resultLabel = resultApplies ? humanValue(detail.success) : "No aplica";
  const hasSensorMessage = Boolean(event.message && event.message !== event.action);
  const entries = Object.entries(detail).filter(([key]) => key !== "fingerprint" && key !== "mitre" && key !== "message" && key !== "success");

  async function copyValue(key: string, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(key);
      window.setTimeout(() => setCopied(null), 1600);
    } catch { /* clipboard may be blocked; the value remains visible */ }
  }

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside
        className="event-drawer event-detail"
        role="dialog"
        aria-modal="true"
        aria-label={`Detalle del evento ${event.id}`}
        onClick={(clickEvent) => clickEvent.stopPropagation()}
      >
        <div className="drawer-head event-detail-head">
          <div>
            <span className="eyebrow">Investigación / Detalle de evento</span>
            <h2>{event.action}</h2>
            <div className="event-detail-idline">
              <span className="mono muted">{event.id}</span>
              <button className="link-button" onClick={() => void copyValue("id", event.id)}>
                {copied === "id" ? <Check size={13} /> : <Copy size={13} />}
                {copied === "id" ? "Copiado" : "Copiar ID"}
              </button>
            </div>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Cerrar detalle" autoFocus><X size={18} /></button>
        </div>

        <div className="event-detail-badges">
          <SeverityBadge severity={event.severity} />
          <span className="sensor-chip">{event.sensor || "Sensor sin dato"}</span>
          <span className="proto-chip">{event.proto || "protocolo sin dato"}</span>
          <span className={`event-detail-kind ${event.scope && event.scope !== "public" ? "private" : ""}`}>
            {event.scope && event.scope !== "public" ? scopeLabel(event.scope) : event.kind}
          </span>
        </div>

        <div className="event-detail-time">
          <Clock3 size={14} />
          <strong>{formatFullDateTime(event.timestamp)}</strong>
          <span className="mono muted">{event.timestamp}</span>
          <span className="muted">{relativeTime(event.timestamp)}</span>
        </div>

        <section className="event-detail-section">
          <h3><Network size={16} /> Flujo observado</h3>
          <div className="event-flow">
            <div className="event-flow-card">
              <span className="eyebrow">Origen</span>
              <strong className="mono">{event.source || "—"}</strong>
              <span>{event.port != null ? `Puerto ${event.port}` : "Puerto no registrado"}</span>
              <span className="event-flow-location">
                <MapPin size={12} />
                {event.countryCode && <span className="flag">{countryFlag(event.countryCode)}</span>}
                {location}
              </span>
              <button className="link-button" onClick={() => void copyValue("source", event.source)}>
                {copied === "source" ? <Check size={12} /> : <Copy size={12} />}
                {copied === "source" ? "Copiada" : "Copiar IP"}
              </button>
              {onOpenAttacker && event.source && (
                <button className="link-button" onClick={() => { onOpenAttacker(event.source); onClose(); }}>
                  <ArrowUpRight size={12} /> Abrir ficha del atacante
                </button>
              )}
              {event.source && (blockEntry ? (
                <button className="link-button" onClick={() => void unblockSource()} disabled={!canAdmin || blockBusy}
                  title={canAdmin ? "Retirar de la blocklist" : "Requiere rol admin"}>
                  <ShieldCheck size={12} /> En blocklist · Quitar
                </button>
              ) : (
                <button className="link-button" onClick={() => void blockSource()} disabled={!canAdmin || blockBusy}
                  title={canAdmin ? "Registrar en la blocklist" : "Requiere rol admin"}>
                  <Ban size={12} /> {blockBusy ? "Registrando…" : "Bloquear IP"}
                </button>
              ))}
              {blockNotice && <span className="event-flow-note success">{blockNotice}</span>}
              {blockError && <span className="event-flow-note error">{blockError}</span>}
            </div>
            <div className="event-flow-arrow" aria-hidden="true">
              <span>{event.proto || "tcp"}</span>
              <i />
              <small>{event.kind}</small>
            </div>
            <div className={`event-flow-card ${destination ? "" : "empty"}`}>
              <span className="eyebrow">Destino</span>
              <strong className="mono">{destination || "No registrado"}</strong>
              <span>{destination ? "Sensor señuelo" : "El motor no adjuntó IP/puerto destino"}</span>
              {event.dst_port != null && <span className="event-flow-location">Puerto destino {event.dst_port}</span>}
            </div>
          </div>
        </section>

        <section className="event-detail-section">
          <h3><ShieldAlert size={16} /> Clasificación y contexto</h3>
          <div className="event-detail-grid">
            <Fact label="Sensor" value={event.sensor} />
            <Fact label="Dispositivo" value={event.device} mono />
            <Fact label="Tipo de evento" value={event.action} />
            <Fact label="Identificador interno" value={event.kind} mono />
            <Fact label="Ubicación">
              <strong>
                {event.countryCode && <span className="flag">{countryFlag(event.countryCode)}</span>}
                {location}
              </strong>
            </Fact>
            <Fact label="Código de país" value={event.countryCode || (event.scope === "public" ? "Sin dato" : "No aplica")} mono />
            <Fact label="MITRE ATT&CK">
              {mitreUrl ? <a className="event-detail-link mono" href={mitreUrl} target="_blank" rel="noreferrer">{mitre}</a> : <strong className="mono">{mitre || "—"}</strong>}
            </Fact>
            <Fact label="Resultado" value={resultLabel} />
            <Fact label="Motor" value={typeof detail.engine === "string" ? detail.engine : "—"} />
            <Fact label="ID en el motor" value={typeof detail.eventid === "string" ? detail.eventid : "—"} mono />
          </div>
        </section>

        <section className="event-detail-section">
          <h3>Mensaje normalizado</h3>
          <p className="event-detail-message">{hasSensorMessage ? event.message : "El sensor no adjuntó un mensaje adicional para este evento."}</p>
        </section>

        {fingerprint && (
          <section className="event-detail-section">
            <h3><Fingerprint size={16} /> Huella del navegador</h3>
            <p className="muted">Datos que el atacante expuso al ejecutar JavaScript en el panel falso. Son declarados por su navegador y pueden estar falseados.</p>
            <div className="event-detail-fingerprint">
              {fingerprintFacts(fingerprint).map((fact) => (
                <div key={fact.label}>
                  <span>{fact.label}</span>
                  <strong className={fact.mono ? "mono" : undefined}>{fact.value}</strong>
                </div>
              ))}
            </div>
            <details className="event-detail-raw">
              <summary>Payload completo de la baliza <span className="mono">/__fp</span></summary>
              <pre>{JSON.stringify(fingerprint.client, null, 2)}</pre>
            </details>
          </section>
        )}

        <section className="event-detail-section">
          <div className="event-detail-section-head">
            <h3>Detalles capturados</h3>
            <span className="muted">{entries.length} campo{entries.length === 1 ? "" : "s"}</span>
          </div>
          {entries.length ? (
            <div className="event-detail-kv">
              {entries.map(([key, value]) => (
                <div className="event-detail-kv-row" key={key}>
                  <span>{DETAIL_LABELS[key] ?? key}</span>
                  <strong className={key === "command" || key === "path" || key === "url" ? "mono" : undefined}>
                    {SENSITIVE_KEYS.has(key) ? "[REDACTADO]" : humanValue(value)}
                  </strong>
                </div>
              ))}
            </div>
          ) : (
            <p className="muted">El sensor no adjuntó campos adicionales para este evento.</p>
          )}
        </section>

        <section className="event-detail-section">
          <div className="event-detail-section-head">
            <h3>Documento normalizado</h3>
            <div className="event-detail-actions">
              <button className="button ghost small" onClick={() => void copyValue("json", JSON.stringify(event, null, 2))}>
                {copied === "json" ? <Check size={13} /> : <Copy size={13} />}
                {copied === "json" ? "Copiado" : "Copiar JSON"}
              </button>
              <button className="button ghost small" onClick={() => downloadJson(`dystopia-${event.id}.json`, event)}>
                <Download size={13} /> Descargar
              </button>
            </div>
          </div>
          <details className="event-detail-raw">
            <summary>Ver JSON completo <span className="mono">{event.id}</span></summary>
            <pre>{JSON.stringify(event, null, 2)}</pre>
          </details>
          <p className="muted event-detail-footnote">El mensaje del sensor y los campos capturados pueden contener texto controlado por el atacante; se muestran como texto, nunca como HTML.</p>
        </section>
      </aside>
    </div>
  );
}
