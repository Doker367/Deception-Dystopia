import { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BellRing,
  BrainCircuit,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Database,
  Eye,
  Gauge,
  MessageSquareText,
  RefreshCw,
  Search,
  Send,
  ShieldAlert,
  Sparkles,
  UserCheck,
  XCircle,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Panel } from "../components/Panel";
import { MetricCard } from "../components/MetricCard";
import { SeverityBadge } from "../components/SeverityBadge";
import { useToast } from "../components/Toast";
import { apiGet, apiPost, getRole } from "../lib/api";
import { formatDateTime, formatNumber } from "../lib/format";
import type { Severity } from "../types";

type AiTab = "findings" | "ask" | "memory" | "eval";
type MemoryKind = "all" | "event" | "note" | "knowledge";

interface AiEvidence {
  n: number;
  chunk_id: number;
  doc_key: string;
  kind: string;
  source: string;
  src_ip?: string | null;
  ts?: string | null;
  heading?: string;
  text: string;
  score?: number;
  similarity?: number | null;
  matched_by?: string[];
}

interface AiStructured {
  verdict: string;
  confidence: number;
  mitre: string[];
  observed: string[];
  inferred: string[];
  missing: string[];
  recommended_actions: string[];
}

interface AiAsk {
  mode: string;
  question: string;
  answer: string;
  abstained: boolean;
  grounded: boolean;
  citations: number[];
  evidence: AiEvidence[];
  structured?: AiStructured | null;
  model?: string | null;
  retrieval: { mode: string; degraded: boolean; error?: string | null; count: number };
}

interface AiFinding {
  id: number;
  ts: string;
  src_ip?: string | null;
  verdict: string;
  confidence?: number | null;
  severity: Severity;
  title: string;
  summary: string;
  evidence: AiEvidence[];
  model?: string | null;
  source: string;
  notified: boolean;
  ack: boolean;
  ack_by?: string | null;
  ack_at?: string | null;
}

interface AiMetrics {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  precision?: number | null;
  recall?: number | null;
  f1?: number | null;
  labeled: number;
  note: string;
}

interface AiStatus {
  enabled: boolean;
  indexed: boolean;
  db: string;
  docs?: number;
  chunks?: number;
  findings?: number;
  unacked_findings?: number;
  embedding_match?: boolean | null;
  embed: { url: string; model: string; dim: number };
  llm: { url: string; model: string; disable_thinking?: boolean };
  limits: { top_k: number; min_score: number; context_chars: number; max_vectors: number; event_days: number };
  monitor: { enabled: boolean; window_min: number; min_events: number; min_confidence: number; cooldown_min: number; last_scan?: string | null };
  privacy: { include_payload: boolean };
  error?: string;
}

interface AiFindingsResponse {
  items: AiFinding[];
  unacked: number;
}

const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

const VERDICT_LABEL: Record<string, string> = {
  malicious: "Ataque probable",
  suspicious: "Sospechoso",
  benign: "Benigno",
  unknown: "Sin clasificar",
};

const KIND_LABEL: Record<string, string> = {
  event: "evento",
  note: "nota",
  knowledge: "documento",
};

const RETRIEVAL_LABEL: Record<string, string> = {
  hybrid: "palabras + significado",
  fts: "coincidencia de palabras",
  vector: "significado parecido",
};

function kindLabel(kind: string) {
  return KIND_LABEL[kind] ?? kind;
}

function retrievalLabel(mode: string) {
  return RETRIEVAL_LABEL[mode] ?? mode;
}

function percent(value?: number | null) {
  return value != null ? `${Math.round(value * 100)}%` : "—";
}

const TECHNIQUE_LABEL: Record<string, string> = {
  T1046: "escaneo de red",
  T1110: "fuerza bruta de contraseñas",
  T1078: "uso de cuentas válidas",
  T1190: "explotación de una aplicación expuesta",
  T1059: "ejecución de comandos",
  T1105: "descarga de herramientas",
};

const PROTOCOL_LABEL: Record<string, string> = {
  ssh: "SSH",
  telnet: "Telnet",
  http: "HTTP",
  https: "HTTPS",
  ftp: "FTP",
  smb: "SMB",
  tcp: "TCP",
  udp: "UDP",
  redis: "Redis",
};

function protocolLabel(value: string) {
  const key = value.trim().toLowerCase();
  return PROTOCOL_LABEL[key] ?? value.trim();
}

function cleanText(value: string) {
  return value.replace(/[`*_>#|]/g, " ").replace(/\s+/g, " ").trim();
}

function plainPreview(text: string, max = 280) {
  const clean = text
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/^\s*[-*+]\s+/gm, "")
    .replace(/\s+/g, " ")
    .trim();
  const readable = cleanText(clean);
  return readable.length > max ? `${readable.slice(0, max).trimEnd()}…` : readable;
}

interface EventFacts {
  count: number;
  devices: string;
  protocols: string[];
  targets: string[];
  successes: number;
  techniques: string[];
  summary: string;
}

function eventFacts(text: string): EventFacts | null {
  const lines = text.split(/\r?\n/);
  const field = (prefix: string) => {
    const found = lines.find((line) => line.startsWith(prefix));
    if (!found) return "";
    return found.slice(found.indexOf(":") + 1).trim();
  };
  const count = Number(field("Eventos observados")) || 0;
  if (!count) return null;

  const devices = field("Dispositivos señuelo").replace(/\(\d+\)/g, "").trim();
  const protocols = field("Protocolos")
    .split(",")
    .map((item) => item.split("=")[0].trim())
    .filter(Boolean);
  const targets = field("Destinos")
    .split(",")
    .map((item) => item.split("=")[0].trim())
    .filter(Boolean);
  const successes = Number(field("Accesos aceptados en señuelo")) || 0;
  const techniques = Array.from(new Set(text.match(/\bT\d{4}\b/g) ?? []));

  const protocolText = protocols.map(protocolLabel).join(", ");
  const targetText = targets
    .map((target) => {
      const [port, proto] = target.split("/");
      const protoName = proto ? protocolLabel(proto) : "";
      return protoName && !protocolText.toLowerCase().includes(protoName.toLowerCase())
        ? `${port} (${protoName})`
        : port;
    })
    .join(", ");

  const intro = [
    `Se registraron ${count} eventos desde esta IP`,
    devices ? `contra ${devices}` : "",
    protocolText ? `usando ${protocolText}` : "",
    targetText ? `en el puerto ${targetText}` : "",
  ].filter(Boolean).join(" ").replace(/\.$/, "");

  const outcome = successes > 0
    ? ` Hubo ${successes} acceso(s) aceptado(s): revísalo cuanto antes.`
    : " No hubo accesos aceptados.";

  return {
    count,
    devices,
    protocols,
    targets,
    successes,
    techniques,
    summary: `${intro}.${outcome}`,
  };
}

function cleanAnswer(result: AiAsk) {
  if (!result.abstained) return result.answer;
  return result.answer.replace(/EVIDENCIA INSUFICIENTE:?\s*/i, "").trim()
    || "No hay datos suficientes para responder con seguridad. Prueba con otra pregunta, añade la IP o prepara más documentos en la memoria.";
}

async function safeGet<T>(path: string): Promise<T | null> {
  try {
    return await apiGet<T>(path);
  } catch {
    return null;
  }
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : "No se pudo completar la acción";
}

export function AiPage({ onOpenEvents }: { onOpenEvents: (query: string) => void }) {
  const { notify } = useToast();
  const role = getRole();
  const canOperate = role === "operator" || role === "admin";
  const canAdmin = role === "admin";

  const [tab, setTab] = useState<AiTab>("findings");
  const [status, setStatus] = useState<AiStatus | null>(null);
  const [findings, setFindings] = useState<AiFinding[]>([]);
  const [metrics, setMetrics] = useState<AiMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  const [question, setQuestion] = useState("¿Qué está pasando con esta IP y qué evidencia lo respalda?");
  const [ipFilter, setIpFilter] = useState("");
  const [mode, setMode] = useState<"analysis" | "triage">("analysis");
  const [result, setResult] = useState<AiAsk | null>(null);

  const [query, setQuery] = useState("fuerza bruta SSH");
  const [results, setResults] = useState<AiEvidence[]>([]);
  const [searched, setSearched] = useState(false);
  const [memoryKind, setMemoryKind] = useState<MemoryKind>("event");

  const [pushOn, setPushOn] = useState(() => {
    try {
      return localStorage.getItem("dystopia.ai.push") === "1"
        && "Notification" in window && Notification.permission === "granted";
    } catch {
      return false;
    }
  });
  const seenRef = useRef<number | null>(null);
  const newest = findings.length ? findings[0].id : 0;

  const load = useCallback(async () => {
    const [nextStatus, nextFindings, nextMetrics] = await Promise.all([
      safeGet<AiStatus>("/api/ai/rag/status"),
      safeGet<AiFindingsResponse>("/api/ai/rag/findings?limit=30"),
      safeGet<AiMetrics>("/api/ai/rag/metrics"),
    ]);
    if (nextStatus) setStatus(nextStatus);
    if (nextFindings) setFindings(nextFindings.items);
    if (nextMetrics) setMetrics(nextMetrics);
    setLoading(false);
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => { void load(); }, 30000);
    return () => window.clearInterval(timer);
  }, [load]);

  useEffect(() => {
    if (seenRef.current === null) {
      seenRef.current = newest;
      return;
    }
    if (!pushOn) {
      seenRef.current = Math.max(seenRef.current, newest);
      return;
    }
    const fresh = findings.filter(
      (finding) => finding.id > (seenRef.current ?? 0) && !finding.ack && SEVERITY_RANK[finding.severity] >= 2,
    );
    if (fresh.length) {
      notify(`${fresh.length} hallazgo(s) nuevo(s) de la IA`, "info");
      if ("Notification" in window && Notification.permission === "granted") {
        for (const finding of fresh.slice(0, 3)) {
          new Notification(finding.title, { body: finding.summary.slice(0, 180), tag: `dystopia-ai-${finding.id}` });
        }
      }
    }
    seenRef.current = Math.max(seenRef.current, newest);
  }, [findings, newest, notify, pushOn]);

  async function togglePush() {
    if (pushOn) {
      setPushOn(false);
      localStorage.setItem("dystopia.ai.push", "0");
      notify("Avisos del navegador desactivados", "info");
      return;
    }
    if (!("Notification" in window)) {
      notify("Este navegador no soporta notificaciones", "error");
      return;
    }
    const permission = await Notification.requestPermission();
    if (permission !== "granted") {
      notify("El navegador denegó el permiso de notificaciones", "error");
      return;
    }
    seenRef.current = newest;
    localStorage.setItem("dystopia.ai.push", "1");
    setPushOn(true);
    notify("Avisos del navegador activados", "success");
  }

  async function runScan() {
    setBusy("scan");
    try {
      const response = await apiPost<{ findings: number; notified: number; candidates: number }>(
        "/api/ai/rag/scan", { notify: true },
      );
      notify(`Revisión completada: ${response.findings} alerta(s) nueva(s), ${response.notified} aviso(s) enviado(s).`, "success");
      await load();
    } catch (error) {
      notify(errorText(error), "error");
    } finally {
      setBusy(null);
    }
  }

  async function indexMemory() {
    setBusy("index");
    try {
      const response = await apiPost<{ docs: number; chunks: number; skipped: number }>(
        "/api/ai/rag/index", { scope: "all", force: false },
      );
      notify(`Memoria actualizada: ${response.docs} documento(s) y ${response.chunks} trozo(s) de texto.`, "success");
      await load();
    } catch (error) {
      notify(errorText(error), "error");
    } finally {
      setBusy(null);
    }
  }

  async function ask() {
    if (!question.trim()) {
      notify("Escribe una pregunta para la IA", "error");
      return;
    }
    setBusy("ask");
    setResult(null);
    try {
      const payload = {
        question: question.trim(),
        src_ip: ipFilter.trim() || undefined,
        mode,
      };
      const response = mode === "triage"
        ? await apiPost<AiAsk>("/api/ai/rag/triage", payload)
        : await apiPost<AiAsk>("/api/ai/rag/ask", payload);
      setResult(response);
    } catch (error) {
      notify(errorText(error), "error");
    } finally {
      setBusy(null);
    }
  }

  async function searchMemory(kind: MemoryKind = memoryKind) {
    if (!query.trim()) {
      notify("Escribe un término para buscar en la memoria", "error");
      return;
    }
    setBusy("search");
    try {
      const params = new URLSearchParams({ q: query.trim(), k: "8" });
      if (ipFilter.trim()) params.set("src_ip", ipFilter.trim());
      if (kind !== "all") params.set("kinds", kind);
      const response = await apiGet<{ results: AiEvidence[]; mode: string; degraded: boolean }>(
        `/api/ai/rag/search?${params.toString()}`,
      );
      setResults(response.results);
      setSearched(true);
    } catch (error) {
      notify(errorText(error), "error");
    } finally {
      setBusy(null);
    }
  }

  function pickMemoryKind(kind: MemoryKind) {
    setMemoryKind(kind);
    if (searched) void searchMemory(kind);
  }

  function askAbout(item: AiEvidence) {
    const title = item.heading || item.doc_key;
    setQuestion(
      item.kind === "event"
        ? `Explícame en palabras sencillas qué pasó con ${item.src_ip || "esta actividad"} y qué debería revisar.`
        : `Explícame en palabras sencillas qué dice "${title}" y por qué importa para entender un ataque.`,
    );
    setIpFilter(item.src_ip ?? "");
    setMode("analysis");
    setResult(null);
    setTab("ask");
  }

  async function ack(finding: AiFinding) {
    setBusy(`ack-${finding.id}`);
    try {
      await apiPost(`/api/ai/rag/findings/${finding.id}/ack`, {});
      notify(`Alerta ${finding.id} marcada como revisada`, "success");
      await load();
    } catch (error) {
      notify(errorText(error), "error");
    } finally {
      setBusy(null);
    }
  }

  async function label(finding: AiFinding, kind: "true_positive" | "false_positive") {
    setBusy(`fb-${finding.id}`);
    const allowed = ["malicious", "suspicious", "benign", "unknown"];
    const predicted = allowed.includes(finding.verdict) ? finding.verdict : "unknown";
    try {
      await apiPost("/api/ai/rag/feedback", {
        question: `${finding.title}: ${finding.summary}`.slice(0, 1800),
        predicted,
        label: kind,
        src_ip: finding.src_ip ?? "",
        notes: `hallazgo #${finding.id}`,
      });
      notify("Tu respuesta se guardó para medir la calidad de la IA", "success");
      await load();
    } catch (error) {
      notify(errorText(error), "error");
    } finally {
      setBusy(null);
    }
  }

  function analyzeIp(ip: string) {
    setIpFilter(ip);
    setQuestion(`¿Qué hizo ${ip} contra los señuelos y qué evidencia lo respalda?`);
    setMode("triage");
    setResult(null);
    setTab("ask");
  }

  const openFindings = findings.filter((finding) => !finding.ack).length;
  const precision = metrics?.precision != null ? percent(metrics.precision) : "Sin datos";
  const recall = metrics?.recall != null ? percent(metrics.recall) : "Sin datos";
  const labeled = metrics?.labeled ?? 0;
  const realAlerts = (metrics?.tp ?? 0) + (metrics?.fp ?? 0);
  const realAttacks = (metrics?.tp ?? 0) + (metrics?.fn ?? 0);

  return (
    <div className="page page-ai">
      <PageHeader
        eyebrow="Inteligencia / Memoria de ataques"
        title="IA de análisis"
        description="Lee los eventos de los señuelos y tu documentación, y te explica en lenguaje sencillo qué puede estar pasando. Te enseña las pruebas y lo que aún no sabe; tú decides qué hacer."
        actions={
          <>
            <button className={`button ghost ${pushOn ? "active" : ""}`} onClick={() => void togglePush()}>
              <BellRing size={15} /> {pushOn ? "Avisos activos" : "Avisarme de alertas"}
            </button>
            <button className="button ghost" onClick={() => void load()} disabled={loading}>
              <RefreshCw size={15} /> Actualizar datos
            </button>
            {canAdmin && (
              <button className="button ghost" onClick={() => void runScan()} disabled={busy === "scan"}>
                <Sparkles size={15} /> {busy === "scan" ? "Revisando…" : "Buscar amenazas ahora"}
              </button>
            )}
            {canAdmin && (
              <button className="button primary" onClick={() => void indexMemory()} disabled={busy === "index"}>
                <Database size={15} /> {busy === "index" ? "Actualizando…" : "Actualizar memoria"}
              </button>
            )}
          </>
        }
        meta={
          <>
            <span><i className={`status-dot ${status?.indexed ? "live" : "missing"}`} /> {status?.indexed ? "memoria lista" : "memoria sin preparar"}</span>
            <span>modelo local: {status?.llm.model ?? "sin configurar"}</span>
            <span>solo aconseja · nunca bloquea</span>
            {status?.monitor.last_scan && <span>último análisis: {formatDateTime(status.monitor.last_scan)}</span>}
          </>
        }
      />

      <section className="ai-guide" aria-label="Cómo funciona la IA">
        <article>
          <Eye size={18} className="ai-guide-icon" />
          <strong>1. Lee lo que pasó</strong>
          <p>Revisa los eventos de los señuelos (sistemas trampa), tus notas y la documentación que tengas preparada.</p>
        </article>
        <article>
          <MessageSquareText size={18} className="ai-guide-icon" />
          <strong>2. Te lo explica claro</strong>
          <p>Dice qué vio, qué cree que significa y qué le falta comprobar. Cada frase debe citar su fuente.</p>
        </article>
        <article>
          <UserCheck size={18} className="ai-guide-icon" />
          <strong>3. Tú decides</strong>
          <p>Confirma o descarta cada alerta. La IA nunca bloquea, borra ni silencia nada por su cuenta.</p>
        </article>
      </section>

      {status && !status.enabled && (
        <div className="ai-banner warning">
          <AlertTriangle size={17} />
          <div>
            <strong>La IA está desactivada</strong>
            <p>Para usarla, activa <code>NETPULSE_RAG_ENABLED=true</code>, arranca los modelos locales y reinicia el servicio. Mientras tanto, esta sección solo muestra el diagnóstico.</p>
          </div>
        </div>
      )}
      {status?.enabled && !status.indexed && (
        <div className="ai-banner info">
          <BrainCircuit size={17} />
          <div>
            <strong>La IA todavía no tiene documentos que consultar</strong>
            <p>Pulsa “Actualizar memoria” para que lea los eventos y la documentación disponibles. Sin ese paso no puede responder con pruebas.</p>
          </div>
        </div>
      )}
      {status?.indexed && status.embedding_match === false && (
        <div className="ai-banner warning">
          <AlertTriangle size={17} />
          <div>
            <strong>Cambió el buscador interno de la IA</strong>
            <p>Vuelve a preparar la memoria para que las búsquedas sigan siendo comparables. Es un paso técnico: <code>force=true</code> al reindexar.</p>
          </div>
        </div>
      )}

      <div className="metrics-grid">
        <MetricCard
          label="Documentos en memoria"
          value={formatNumber(status?.docs ?? 0)}
          detail={`${formatNumber(status?.chunks ?? 0)} trozos de texto consultables · ${status?.limits.event_days ?? 90} días de eventos`}
          icon={<Database size={16} />}
          tone="cyan"
        />
        <MetricCard
          label="Alertas por revisar"
          value={`${formatNumber(status?.unacked_findings ?? 0)}`}
          detail={`${formatNumber(findings.length)} en la lista · no repite la misma alerta en ${status?.monitor.cooldown_min ?? 180} min`}
          icon={<ShieldAlert size={16} />}
          tone={openFindings ? "amber" : "blue"}
        />
        <MetricCard
          label="Aciertos al alertar"
          value={precision}
          detail={realAlerts ? `${formatNumber(metrics?.tp ?? 0)} de ${formatNumber(realAlerts)} alertas revisadas eran ataques reales` : "Aún no hay alertas revisadas por una persona"}
          icon={<Gauge size={16} />}
          tone="blue"
        />
        <MetricCard
          label="Ataques detectados"
          value={recall}
          detail={realAttacks ? `${formatNumber(metrics?.tp ?? 0)} de ${formatNumber(realAttacks)} ataques etiquetados fueron detectados` : "Aún no hay ataques etiquetados para medir"}
          icon={<Activity size={16} />}
          tone="violet"
        />
      </div>

      <div className="ai-tabs" role="tablist" aria-label="Secciones de IA">
        {([
          ["findings", `Alertas${openFindings ? ` (${openFindings})` : ""}`],
          ["ask", "Preguntar"],
          ["memory", "Buscar"],
          ["eval", "Calidad"],
        ] as Array<[AiTab, string]>).map(([id, labelText]) => (
          <button
            key={id}
            role="tab"
            aria-selected={tab === id}
            className={tab === id ? "active" : ""}
            onClick={() => setTab(id)}
          >
            {labelText}
          </button>
        ))}
      </div>

      {tab === "findings" && (
        <Panel
          eyebrow="Revisión automática"
          title="Sospechas que la IA detectó"
          description="Cada tarjeta es una pista, no una sentencia. Ábrela, revisa de dónde sale y decide tú si era un ataque."
          actions={<span className="ai-count">{openFindings} sin revisar</span>}
        >
          {loading && <div className="empty-state small"><RefreshCw size={20} /><strong>Cargando alertas</strong></div>}
          {!loading && !findings.length && (
            <div className="empty-state small">
              <Sparkles size={22} />
              <strong>Todavía no hay nada que revisar</strong>
              <span>Cuando la IA vea actividad sospechosa, aparecerá aquí con su evidencia. Que no haya alertas no confirma que no haya ataques.</span>
            </div>
          )}
          <div className="ai-findings">
            {findings.map((finding) => (
              <FindingCard
                key={finding.id}
                finding={finding}
                expanded={expanded === finding.id}
                canOperate={canOperate}
                busy={busy === `ack-${finding.id}` || busy === `fb-${finding.id}`}
                onToggle={() => setExpanded(expanded === finding.id ? null : finding.id)}
                onAsk={() => analyzeIp(finding.src_ip ?? "")}
                onAck={() => void ack(finding)}
                onFeedback={(kind) => void label(finding, kind)}
                onOpenEvents={onOpenEvents}
              />
            ))}
          </div>
        </Panel>
      )}

      {tab === "ask" && (
        <div className="dashboard-grid">
          <Panel className="span-7" eyebrow="Explicación con fuentes" title="Pregunta con tus palabras" description="La IA responde solo con lo que hay en tu memoria y te enseña las fuentes. Si no encuentra pruebas, lo dice.">
            <div className="ai-console">
              <label>
                ¿Qué quieres saber?
                <textarea
                  rows={3}
                  value={question}
                  maxLength={2000}
                  onChange={(event) => setQuestion(event.target.value)}
                  placeholder="¿Qué hizo 203.0.113.9? ¿Es un ataque real o un escáner autorizado?"
                />
              </label>
              <div className="ai-console-row">
                <label>
                  IP (opcional)
                  <input value={ipFilter} maxLength={64} onChange={(event) => setIpFilter(event.target.value)} placeholder="203.0.113.9" />
                </label>
                <label>
                  Tipo de respuesta
                  <select value={mode} onChange={(event) => setMode(event.target.value as "analysis" | "triage")}>
                    <option value="analysis">Explicación sencilla</option>
                    <option value="triage">Ficha ordenada</option>
                  </select>
                </label>
                <button className="button primary" onClick={() => void ask()} disabled={busy === "ask"}>
                  <Send size={15} /> {busy === "ask" ? "Pensando…" : "Preguntar"}
                </button>
              </div>
              <p className="ai-hint">Explicación sencilla: texto claro con lo esencial. Ficha ordenada: los mismos puntos separados en qué se vio, qué se supone, qué falta y qué conviene revisar. Los números entre corchetes <code>[1]</code> indican la fuente de cada frase.</p>
            </div>
            {result && (
              <div className="ai-result">
                <div className="ai-result-badges">
                  {result.grounded ? (
                    <span className="ai-pill ok"><CheckCircle2 size={13} /> respuesta basada en fuentes</span>
                  ) : (
                    <span className="ai-pill bad"><XCircle size={13} /> sin fuentes verificables: no confíes</span>
                  )}
                  {result.abstained && <span className="ai-pill warn"><AlertTriangle size={13} /> prefirió no responder</span>}
                  <span className="ai-pill neutral">búsqueda: {retrievalLabel(result.retrieval.mode)}</span>
                  <span className="ai-pill neutral">{result.evidence.length} fuente(s)</span>
                  {result.model && <span className="ai-pill neutral mono">modelo {result.model}</span>}
                </div>
                {result.structured && <StructuredResult structured={result.structured} />}
                <p className="ai-hint">Respuesta de la IA. Compruébala con las fuentes antes de tomar una decisión.</p>
                <div className={`ai-answer ${result.grounded ? "grounded" : "warning"}`}>
                  <AnswerBody text={cleanAnswer(result)} />
                </div>
                <EvidenceList items={result.evidence} onOpenEvents={onOpenEvents} />
              </div>
            )}
          </Panel>

          <Panel className="span-5" eyebrow="Configuración" title="Qué puede y qué no puede hacer" description="Resumen en lenguaje claro. Los detalles técnicos quedan al final, por si los necesitas.">
            <div className="ai-status-list">
              <div><span>Redacta las respuestas</span><strong className="mono">{status?.llm.model ?? "sin configurar"}</strong></div>
              <div><span>Busca textos parecidos</span><strong className="mono">{status?.embed.model ?? "sin configurar"}</strong></div>
              <div><span>Fuentes por consulta</span><strong>{status?.limits.top_k ?? "sin dato"}</strong></div>
              <div><span>Máximo de texto que lee</span><strong>{formatNumber(status?.limits.context_chars ?? 0)} caracteres</strong></div>
              <div><span>Comandos y URLs de atacantes</span><strong>{status?.privacy.include_payload ? "se guardan redactados" : "no se guardan en la memoria"}</strong></div>
              <div><span>Revisión automática</span><strong>{status?.monitor.enabled ? `cada ${status.monitor.window_min} min` : "desactivada"}</strong></div>
              <div><span>¿Bloquea o borra sola?</span><strong className="ok-text">Nunca</strong></div>
            </div>
            <details className="ai-advanced">
              <summary>Ver detalles técnicos</summary>
              <div className="ai-status-list">
                <div><span>Dimensión de los vectores</span><strong>{status?.embed.dim ?? "sin dato"}</strong></div>
                <div><span>Umbral mínimo de similitud</span><strong>{status?.limits.min_score ?? "sin dato"}</strong></div>
                <div><span>Vectores máximos</span><strong>{formatNumber(status?.limits.max_vectors ?? 0)}</strong></div>
                <div><span>URL del buscador</span><strong className="mono">{status?.embed.url ?? "sin configurar"}</strong></div>
                <div><span>URL del redactor</span><strong className="mono">{status?.llm.url ?? "sin configurar"}</strong></div>
              </div>
            </details>
            <div className="ai-note">
              <AlertTriangle size={15} />
              <p>Una IP solo indica un origen, no quién es la persona. Confirma siempre con la evidencia y el contexto del señuelo.</p>
            </div>
          </Panel>
        </div>
      )}

      {tab === "memory" && (
        <div className="dashboard-grid">
          <Panel className="span-12" eyebrow="Buscador de la memoria" title="Busca en lo que la IA sabe" description="Encuentra eventos, notas y documentación por palabras o por significado. No hace falta escribir los términos exactos.">
            <p className="ai-hint">La búsqueda combina coincidencia de palabras con significado parecido. Cada resultado indica de dónde sale y qué tan parecido es a lo que buscas.</p>
            <div className="ai-filter" role="group" aria-label="Filtrar la memoria por tipo">
              {([
                ["event", "Ataques"],
                ["note", "Notas"],
                ["knowledge", "Documentación"],
                ["all", "Todo"],
              ] as Array<[MemoryKind, string]>).map(([kind, label]) => (
                <button
                  key={kind}
                  className={memoryKind === kind ? "active" : ""}
                  aria-pressed={memoryKind === kind}
                  onClick={() => pickMemoryKind(kind)}
                >
                  {label}
                </button>
              ))}
            </div>
            <div className="ai-searchbar">
              <Search size={16} />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={(event) => { if (event.key === "Enter") void searchMemory(); }}
                placeholder="Ej.: accesos SSH fallidos, T1110, 203.0.113.9"
                aria-label="Buscar en la memoria"
              />
              <input
                className="ai-search-ip"
                value={ipFilter}
                onChange={(event) => setIpFilter(event.target.value)}
                placeholder="IP (opcional)"
                aria-label="Filtrar por IP"
              />
              <button className="button primary" onClick={() => void searchMemory()} disabled={busy === "search"}>
                <Search size={15} /> Buscar
              </button>
            </div>
            {!searched && <div className="empty-state small"><Database size={20} /><strong>Busca en la memoria</strong><span>Por defecto buscamos en ataques reales. Cambia el filtro para consultar notas o documentación. Los resultados muestran de dónde salen para que puedas verificarlos.</span></div>}
            {searched && !results.length && (
              <div className="empty-state small">
                <Search size={20} />
                <strong>Sin coincidencias en {memoryKind === "all" ? "la memoria" : memoryKind === "event" ? "ataques" : memoryKind === "note" ? "notas" : "documentación"}</strong>
                <span>Prueba con otras palabras o cambia el filtro. La IA no inventa resultados que no existen.</span>
              </div>
            )}
            {results.length > 0 && (
              <div className="ai-evidence">
                {results.map((item, index) => (
                  <MemoryResultCard
                    key={`${item.chunk_id}-${index}`}
                    item={item}
                    index={index}
                    onAsk={() => askAbout(item)}
                    onOpenEvents={onOpenEvents}
                  />
                ))}
              </div>
            )}
          </Panel>
        </div>
      )}

      {tab === "eval" && (
        <div className="dashboard-grid">
          <Panel className="span-8" eyebrow="Calidad de las alertas" title="¿Qué tan bien está funcionando?" description="Solo mide los casos que una persona ha revisado. Al principio no hay datos, y eso es normal.">
            <p className="ai-hint">Casos revisados por una persona: {formatNumber(labeled)}. Con menos de 30, los porcentajes todavía no son fiables.</p>
            <div className="ai-metric-grid">
              <div><span>Aciertos (era ataque)</span><strong>{formatNumber(metrics?.tp ?? 0)}</strong></div>
              <div><span>Falsas alarmas</span><strong className="warn-text">{formatNumber(metrics?.fp ?? 0)}</strong></div>
              <div><span>Ataques que se escaparon</span><strong className="bad-text">{formatNumber(metrics?.fn ?? 0)}</strong></div>
              <div><span>Descartes correctos</span><strong>{formatNumber(metrics?.tn ?? 0)}</strong></div>
            </div>
            <div className="ai-eval-bars">
              <div><span title="De las alertas que marcó, cuántas eran ataques reales.">Precisión</span><div className="ai-bar"><i style={{ width: `${Math.round((metrics?.precision ?? 0) * 100)}%` }} /></div><strong>{precision}</strong></div>
              <div><span title="De los ataques etiquetados, cuántos detectó.">Cobertura</span><div className="ai-bar"><i style={{ width: `${Math.round((metrics?.recall ?? 0) * 100)}%` }} /></div><strong>{recall}</strong></div>
              <div><span title="Equilibrio entre precisión y cobertura (F1).">Equilibrio</span><div className="ai-bar"><i style={{ width: `${Math.round((metrics?.f1 ?? 0) * 100)}%` }} /></div><strong>{metrics?.f1 != null ? metrics.f1.toFixed(3) : "Sin datos"}</strong></div>
            </div>
            <p className="ai-hint"><strong>Precisión:</strong> de cada 10 alertas que marcó, cuántas eran reales. <strong>Cobertura:</strong> de cada 10 ataques etiquetados, cuántos detectó. Mejorar una suele empeorar la otra: decide qué priorizas.</p>
            <div className="ai-note">
              <Gauge size={15} />
              <p>{metrics?.note ?? "Revisa y etiqueta alertas para construir la muestra."} Ninguna IA detecta todo sin generar alguna falsa alarma; estos números te ayudan a decidir cuánto confiar en ella.</p>
            </div>
          </Panel>
          <Panel className="span-4" eyebrow="Cómo medirla" title="Revisa y etiqueta" description="Sin casos revisados, los porcentajes no significan nada.">
            <ol className="ai-steps">
              <li>Reúne al menos 30 casos reales o de laboratorio.</li>
              <li>Revisa cada alerta y pulsa “Sí era un ataque” o “Fue una falsa alarma”.</li>
              <li>Vuelve aquí: Precisión mide el ruido; Cobertura mide los ataques perdidos.</li>
              <li>Repite la medición si cambias el modelo o la configuración.</li>
            </ol>
            <div className="ai-note">
              <ShieldAlert size={15} />
              <p>La IA solo aconseja. Confirmar, descartar, bloquear o silenciar sigue siendo una decisión humana.</p>
            </div>
          </Panel>
        </div>
      )}
    </div>
  );
}

function FindingCard({
  finding,
  expanded,
  canOperate,
  busy,
  onToggle,
  onAsk,
  onAck,
  onFeedback,
  onOpenEvents,
}: {
  finding: AiFinding;
  expanded: boolean;
  canOperate: boolean;
  busy: boolean;
  onToggle: () => void;
  onAsk: () => void;
  onAck: () => void;
  onFeedback: (kind: "true_positive" | "false_positive") => void;
  onOpenEvents: (query: string) => void;
}) {
  const confidence = finding.confidence != null ? `${Math.round(finding.confidence * 100)}%` : "n/d";
  return (
    <article className={`ai-finding ${finding.ack ? "acked" : ""}`}>
      <div className="ai-finding-head">
        <SeverityBadge severity={finding.severity} />
        <strong>{finding.title}</strong>
        <span className={`ai-verdict v-${finding.verdict}`}>{VERDICT_LABEL[finding.verdict] ?? finding.verdict}</span>
        <span className="ai-confidence" title="Seguridad de la IA en esta clasificación. No es una probabilidad matemática ni una prueba.">confianza {confidence}</span>
        <time className="muted">{formatDateTime(finding.ts)}</time>
      </div>
      <p className="ai-finding-summary">{finding.summary}</p>
      <div className="ai-finding-meta">
        {finding.src_ip && <button className="link-button mono" onClick={() => onOpenEvents(finding.src_ip ?? "")}>{finding.src_ip}</button>}
        <span className={`ai-pill ${finding.source === "ai" ? "ok" : "neutral"}`}>{finding.source === "ai" ? "generada por IA" : finding.source}</span>
        {finding.model && <span className="mono">modelo {finding.model}</span>}
        {finding.notified && <span className="ai-pill neutral">avisada</span>}
        {finding.ack ? <span className="ai-pill ok"><CheckCircle2 size={12} /> revisada</span> : <span className="ai-pill warn">sin revisar</span>}
      </div>
      {expanded && <EvidenceList items={finding.evidence} onOpenEvents={onOpenEvents} />}
      <div className="ai-finding-actions">
        <button className="button small ghost" onClick={onToggle}>
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />} {expanded ? "Ocultar de dónde sale" : `Ver de dónde sale (${finding.evidence.length})`}
        </button>
        <button className="button small ghost" onClick={onAsk}><BrainCircuit size={14} /> Preguntar por esta IP</button>
        {canOperate && !finding.ack && (
          <button className="button small ghost" onClick={onAck} disabled={busy}><CheckCircle2 size={14} /> Marcar como revisada</button>
        )}
        {canOperate && (
          <>
            <button className="button small ghost" onClick={() => onFeedback("true_positive")} disabled={busy}><ShieldAlert size={14} /> Sí era un ataque</button>
            <button className="button small ghost" onClick={() => onFeedback("false_positive")} disabled={busy}><XCircle size={14} /> Fue una falsa alarma</button>
          </>
        )}
      </div>
    </article>
  );
}

function EvidenceList({ items, onOpenEvents }: { items: AiEvidence[]; onOpenEvents: (query: string) => void }) {
  if (!items.length) return <p className="ai-hint">Sin fragmentos de evidencia asociados.</p>;
  return (
    <div className="ai-evidence">
      {items.map((item, index) => (
        <div className="ai-evidence-item" key={`${item.chunk_id}-${item.n}-${index}`}>
          <div className="ai-evidence-head">
            <span className="ai-cite">[{item.n || index + 1}]</span>
            <strong>{item.heading || item.doc_key}</strong>
            <span className="muted">{kindLabel(item.kind)} · fuente: {item.source}</span>
            {typeof item.similarity === "number" && (
              <span className="mono muted" title="1.00 = texto idéntico; 0.00 = nada que ver. No es una probabilidad de ataque.">
                parecido {Math.round(item.similarity * 100)}%
              </span>
            )}
            {item.src_ip && <button className="link-button mono" onClick={() => onOpenEvents(item.src_ip ?? "")}>{item.src_ip}</button>}
          </div>
          <EvidenceContent item={item} />
        </div>
      ))}
    </div>
  );
}

function EvidenceContent({ item }: { item: AiEvidence }) {
  const facts = item.kind === "event" ? eventFacts(item.text) : null;
  if (facts) {
    return (
      <>
        <p className="ai-evidence-summary">{facts.summary}</p>
        <div className="ai-memory-facts">
          <span className="ai-pill neutral">{facts.count} evento(s)</span>
          {facts.devices && <span className="ai-pill neutral">{facts.devices}</span>}
          {facts.protocols.map((protocol) => <span key={protocol} className="ai-pill neutral">{protocolLabel(protocol)}</span>)}
          <span className={`ai-pill ${facts.successes ? "warn" : "ok"}`}>
            {facts.successes ? `${facts.successes} acceso(s) aceptado(s)` : "sin accesos aceptados"}
          </span>
          {facts.techniques.map((code) => (
            <span key={code} className="ai-pill neutral" title="Técnica MITRE ATT&CK. Es una inferencia, no una confirmación.">
              {code} · {TECHNIQUE_LABEL[code] ?? "técnica detectada"}
            </span>
          ))}
        </div>
        <details className="ai-memory-raw">
          <summary>Ver detalle técnico</summary>
          <pre>{item.text}</pre>
        </details>
      </>
    );
  }
  return (
    <>
      <p className="ai-evidence-summary">{plainPreview(item.text)}</p>
      <details className="ai-memory-raw">
        <summary>Ver texto completo</summary>
        <pre>{item.text}</pre>
      </details>
    </>
  );
}

function MemoryResultCard({
  item,
  index,
  onAsk,
  onOpenEvents,
}: {
  item: AiEvidence;
  index: number;
  onAsk: () => void;
  onOpenEvents: (query: string) => void;
}) {
  return (
    <article className="ai-memory-card">
      <div className="ai-memory-head">
        <span className="ai-cite">[{index + 1}]</span>
        <strong>{item.heading || item.doc_key}</strong>
        <span className={`ai-kind kind-${item.kind}`}>{kindLabel(item.kind)}</span>
        <span className="muted">fuente: {item.source}</span>
        {typeof item.similarity === "number" && (
          <span className="mono muted" title="1.00 = texto idéntico; 0.00 = nada que ver. No es una probabilidad de ataque.">
            parecido {Math.round(item.similarity * 100)}%
          </span>
        )}
      </div>
      <EvidenceContent item={item} />
      <div className="ai-memory-actions">
        <button className="button small ghost" onClick={onAsk}><BrainCircuit size={14} /> Explicar en simple</button>
        {item.src_ip && (
          <button className="link-button mono" onClick={() => onOpenEvents(item.src_ip ?? "")}>
            Abrir eventos de {item.src_ip}
          </button>
        )}
      </div>
    </article>
  );
}

function AnswerBody({ text }: { text: string }) {
  const sections: Array<{ title: string | null; lines: string[] }> = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const normalized = line.replace(/^[*#>\s]+/, "").replace(/[*\s]+$/, "");
    const heading = /^(EN UNA FRASE|RESUMEN|QUÉ SE OBSERVÓ|QUÉ SE VIO|QUÉ SIGNIFICA|QUÉ PODRÍA SIGNIFICAR|QUÉ HACER|QUÉ CONVIENE REVISAR)\s*(?:[:–—-]\s*)?(.*)$/i.exec(normalized);
    if (heading) {
      sections.push({ title: heading[1].toUpperCase(), lines: heading[2] ? [heading[2].trim()] : [] });
    } else if (sections.length) {
      sections[sections.length - 1].lines.push(line);
    } else {
      sections.push({ title: null, lines: [line] });
    }
  }
  if (!sections.length) return <p>Sin respuesta.</p>;
  return (
    <div className="ai-answer-body">
      {sections.map((section, index) => {
        const lead = !!section.title && /EN UNA FRASE|RESUMEN/.test(section.title);
        return (
          <section key={index} className={`ai-answer-section ${section.title ? "titled" : ""} ${lead ? "lead" : ""}`}>
            {section.title && <span className="ai-answer-label">{section.title}</span>}
            {section.lines.map((line, lineIndex) => {
              const bullet = /^[-*•]\s+/.test(line);
              const content = bullet ? line.replace(/^[-*•]\s+/, "") : line;
              const nodes = content.split(/(\[\d{1,2}\])/g).map((part, partIndex) =>
                /^\[\d{1,2}\]$/.test(part) ? <span key={partIndex} className="ai-cite">{part}</span> : part
              );
              return bullet
                ? <p key={lineIndex} className="ai-answer-bullet">{nodes}</p>
                : <p key={lineIndex}>{nodes}</p>;
            })}
          </section>
        );
      })}
    </div>
  );
}

function StructuredResult({ structured }: { structured: AiStructured }) {
  return (
    <div className={`ai-structured v-${structured.verdict}`}>
      <div className="ai-structured-head">
        <strong>{VERDICT_LABEL[structured.verdict] ?? structured.verdict}</strong>
        <span>confianza {Math.round(structured.confidence * 100)}%</span>
        {structured.mitre.map((item) => <span key={item} className="ai-pill neutral mono" title="Técnica de ataque catalogada en MITRE ATT&CK">{item}</span>)}
      </div>
      <div className="ai-structured-grid">
        <div><span>Lo que se vio</span><ul>{structured.observed.map((item) => <li key={item}>{item}</li>)}</ul></div>
        <div><span>Lo que la IA supone</span><ul>{structured.inferred.map((item) => <li key={item}>{item}</li>)}</ul></div>
        <div><span>Lo que aún no se sabe</span><ul>{structured.missing.length ? structured.missing.map((item) => <li key={item}>{item}</li>) : <li>nada relevante</li>}</ul></div>
        <div><span>Qué conviene revisar</span><ul>{structured.recommended_actions.map((item) => <li key={item}>{item}</li>)}</ul></div>
      </div>
    </div>
  );
}
