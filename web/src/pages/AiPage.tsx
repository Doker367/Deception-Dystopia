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
  Gauge,
  RefreshCw,
  Search,
  Send,
  ShieldAlert,
  Sparkles,
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
      notify(`Análisis completado: ${response.findings} hallazgo(s), ${response.notified} notificado(s).`, "success");
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
      notify(`Memoria actualizada: ${response.docs} documento(s), ${response.chunks} fragmento(s).`, "success");
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

  async function searchMemory() {
    if (!query.trim()) {
      notify("Escribe un término para buscar en la memoria", "error");
      return;
    }
    setBusy("search");
    try {
      const params = new URLSearchParams({ q: query.trim(), k: "8" });
      if (ipFilter.trim()) params.set("src_ip", ipFilter.trim());
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

  async function ack(finding: AiFinding) {
    setBusy(`ack-${finding.id}`);
    try {
      await apiPost(`/api/ai/rag/findings/${finding.id}/ack`, {});
      notify(`Hallazgo ${finding.id} marcado como revisado`, "success");
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
      notify("Etiqueta guardada para las métricas", "success");
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
    setTab("ask");
  }

  const openFindings = findings.filter((finding) => !finding.ack).length;
  const precision = metrics?.precision != null ? `${Math.round(metrics.precision * 100)}%` : "n/d";
  const recall = metrics?.recall != null ? `${Math.round(metrics.recall * 100)}%` : "n/d";

  return (
    <div className="page page-ai">
      <PageHeader
        eyebrow="Inteligencia / Memoria de ataques"
        title="IA de análisis"
        description="Memoria local de eventos, notas y documentación. La IA explica qué ve, cita la evidencia y propone revisión humana; nunca bloquea ni suprime por su cuenta."
        actions={
          <>
            <button className={`button ghost ${pushOn ? "active" : ""}`} onClick={() => void togglePush()}>
              <BellRing size={15} /> {pushOn ? "Avisos activos" : "Activar avisos"}
            </button>
            <button className="button ghost" onClick={() => void load()} disabled={loading}>
              <RefreshCw size={15} /> Actualizar
            </button>
            {canAdmin && (
              <button className="button ghost" onClick={() => void runScan()} disabled={busy === "scan"}>
                <Sparkles size={15} /> {busy === "scan" ? "Analizando…" : "Escanear ahora"}
              </button>
            )}
            {canAdmin && (
              <button className="button primary" onClick={() => void indexMemory()} disabled={busy === "index"}>
                <Database size={15} /> {busy === "index" ? "Indexando…" : "Indexar memoria"}
              </button>
            )}
          </>
        }
        meta={
          <>
            <span><i className={`status-dot ${status?.indexed ? "live" : "missing"}`} /> {status?.indexed ? "memoria activa" : "sin memoria"}</span>
            <span>{status?.llm.model ?? "modelo sin configurar"}</span>
            <span>asesor · sin bloqueo automático</span>
            {status?.monitor.last_scan && <span>último análisis {formatDateTime(status.monitor.last_scan)}</span>}
          </>
        }
      />

      {status && !status.enabled && (
        <div className="ai-banner warning">
          <AlertTriangle size={17} />
          <div>
            <strong>El RAG está desactivado</strong>
            <p>Exporta <code>NETPULSE_RAG_ENABLED=true</code>, arranca los modelos locales y reinicia el servicio. Sin eso, esta sección solo muestra el diagnóstico.</p>
          </div>
        </div>
      )}
      {status?.enabled && !status.indexed && (
        <div className="ai-banner info">
          <BrainCircuit size={17} />
          <div>
            <strong>Todavía no hay memoria indexada</strong>
            <p>Usa “Indexar memoria” o <code>python3 scripts/rag_cli.py index --scope all</code>. La IA no responde sin fragmentos recuperados.</p>
          </div>
        </div>
      )}
      {status?.indexed && status.embedding_match === false && (
        <div className="ai-banner warning">
          <AlertTriangle size={17} />
          <div>
            <strong>El modelo de embeddings cambió</strong>
            <p>Reindexa con <code>force=true</code> para que los vectores sean comparables.</p>
          </div>
        </div>
      )}

      <div className="metrics-grid">
        <MetricCard
          label="Memoria indexada"
          value={formatNumber(status?.docs ?? 0)}
          detail={`${formatNumber(status?.chunks ?? 0)} fragmentos · ${status?.limits.event_days ?? 90} días`}
          icon={<Database size={16} />}
          tone="cyan"
        />
        <MetricCard
          label="Hallazgos sin revisar"
          value={`${formatNumber(status?.unacked_findings ?? 0)}`}
          detail={`${formatNumber(findings.length)} recientes · cooldown ${status?.monitor.cooldown_min ?? 180} min`}
          icon={<ShieldAlert size={16} />}
          tone={openFindings ? "amber" : "blue"}
        />
        <MetricCard
          label="Precisión"
          value={precision}
          detail={`${formatNumber(metrics?.labeled ?? 0)} casos etiquetados · FP ${metrics?.fp ?? 0}`}
          icon={<Gauge size={16} />}
          tone="blue"
        />
        <MetricCard
          label="Recall"
          value={recall}
          detail={`FN ${metrics?.fn ?? 0} · ataques que se escaparon`}
          icon={<Activity size={16} />}
          tone="violet"
        />
      </div>

      <div className="ai-tabs" role="tablist" aria-label="Secciones de IA">
        {([
          ["findings", `Hallazgos${openFindings ? ` (${openFindings})` : ""}`],
          ["ask", "Consultar"],
          ["memory", "Memoria"],
          ["eval", "Evaluación"],
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
          eyebrow="Monitor proactivo"
          title="Lo que la IA considera que está mal"
          description="Hallazgos generados al evaluar eventos nuevos. Se notifican a los canales configurados y quedan aquí hasta que un humano los revisa."
          actions={<span className="ai-count">{openFindings} sin revisar</span>}
        >
          {loading && <div className="empty-state small"><RefreshCw size={20} /><strong>Cargando hallazgos</strong></div>}
          {!loading && !findings.length && (
            <div className="empty-state small">
              <Sparkles size={22} />
              <strong>Sin hallazgos todavía</strong>
              <span>El monitor evalúa eventos nuevos cada pocos minutos. También puedes lanzar “Escanear ahora”.</span>
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
          <Panel className="span-7" eyebrow="Consulta fundamentada" title="Preguntar a la memoria" description="La respuesta solo usa fragmentos recuperados. Sin evidencia, se abstiene.">
            <div className="ai-console">
              <label>
                Pregunta
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
                  Modo
                  <select value={mode} onChange={(event) => setMode(event.target.value as "analysis" | "triage")}>
                    <option value="analysis">Análisis explicado</option>
                    <option value="triage">Triage estructurado</option>
                  </select>
                </label>
                <button className="button primary" onClick={() => void ask()} disabled={busy === "ask"}>
                  <Send size={15} /> {busy === "ask" ? "Consultando…" : "Preguntar"}
                </button>
              </div>
              <p className="ai-hint">La IA no bloquea, no aísla y no modifica eventos. Cada afirmación debe citar <code>[n]</code>.</p>
            </div>
            {result && (
              <div className="ai-result">
                <div className="ai-result-badges">
                  {result.grounded ? (
                    <span className="ai-pill ok"><CheckCircle2 size={13} /> evidencia citada</span>
                  ) : (
                    <span className="ai-pill bad"><XCircle size={13} /> sin citas verificables</span>
                  )}
                  {result.abstained && <span className="ai-pill warn"><AlertTriangle size={13} /> abstención</span>}
                  <span className="ai-pill neutral">{result.retrieval.mode}</span>
                  <span className="ai-pill neutral">{result.evidence.length} fragmentos</span>
                  {result.model && <span className="ai-pill neutral mono">{result.model}</span>}
                </div>
                {result.structured && <StructuredResult structured={result.structured} />}
                <div className={`ai-answer ${result.grounded ? "grounded" : "warning"}`}>{result.answer}</div>
                {result.citations.length > 0 && (
                  <div className="ai-citations">
                    {result.citations.map((citation) => <span key={citation} className="ai-cite">[{citation}]</span>)}
                  </div>
                )}
                <EvidenceList items={result.evidence} onOpenEvents={onOpenEvents} />
              </div>
            )}
          </Panel>

          <Panel className="span-5" eyebrow="Estado" title="Modelo y límites" description="Lo que la IA puede y no puede hacer en este despliegue.">
            <div className="ai-status-list">
              <div><span>Generación</span><strong className="mono">{status?.llm.model ?? "n/d"}</strong></div>
              <div><span>Embeddings</span><strong className="mono">{status?.embed.model ?? "n/d"}</strong></div>
              <div><span>Dimensión</span><strong>{status?.embed.dim ?? "n/d"}</strong></div>
              <div><span>Top-K</span><strong>{status?.limits.top_k ?? "n/d"}</strong></div>
              <div><span>Contexto</span><strong>{formatNumber(status?.limits.context_chars ?? 0)} caracteres</strong></div>
              <div><span>Payload capturado</span><strong>{status?.privacy.include_payload ? "indexado y redactado" : "no indexado"}</strong></div>
              <div><span>Monitor</span><strong>{status?.monitor.enabled ? `cada ${status.monitor.window_min} min` : "desactivado"}</strong></div>
              <div><span>Bloqueo automático</span><strong className="ok-text">nunca</strong></div>
            </div>
            <div className="ai-note">
              <AlertTriangle size={15} />
              <p>Una IP observada no prueba la identidad del atacante. Confirma siempre con la evidencia y el contexto del señuelo.</p>
            </div>
          </Panel>
        </div>
      )}

      {tab === "memory" && (
        <div className="dashboard-grid">
          <Panel className="span-12" eyebrow="Búsqueda híbrida" title="Explorar la memoria" description="FTS5 + similitud semántica sobre eventos agregados, notas y documentación.">
            <div className="ai-searchbar">
              <Search size={16} />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={(event) => { if (event.key === "Enter") void searchMemory(); }}
                placeholder="Ejemplo: fuerza bruta SSH, T1110, 203.0.113.9"
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
            {!searched && <div className="empty-state small"><Database size={20} /><strong>Busca en la memoria</strong><span>Los resultados muestran procedencia y similitud para que puedas verificar.</span></div>}
            {searched && !results.length && <div className="empty-state small"><Search size={20} /><strong>Sin coincidencias</strong><span>Prueba con un término más específico o indexa más fuentes.</span></div>}
            {results.length > 0 && (
              <div className="ai-evidence">
                {results.map((item) => (
                  <div className="ai-evidence-item" key={`${item.chunk_id}-${item.n}`}>
                    <div className="ai-evidence-head">
                      <span className="ai-cite">[{item.n}]</span>
                      <strong>{item.heading || item.doc_key}</strong>
                      <span className="muted">{item.kind} · {item.source}</span>
                      {typeof item.similarity === "number" && <span className="mono muted">sim {item.similarity.toFixed(2)}</span>}
                      {item.src_ip && <button className="link-button" onClick={() => onOpenEvents(item.src_ip ?? "")}>{item.src_ip}</button>}
                    </div>
                    <p>{item.text}</p>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>
      )}

      {tab === "eval" && (
        <div className="dashboard-grid">
          <Panel className="span-8" eyebrow="Calidad" title="Precisión y recall por separado" description="Las métricas salen solo de casos que un analista etiquetó. Así se mide el ruido y lo que se escapa sin mezclarlos.">
            <div className="ai-metric-grid">
              <div><span>Verdaderos positivos</span><strong>{formatNumber(metrics?.tp ?? 0)}</strong></div>
              <div><span>Falsos positivos</span><strong className="warn-text">{formatNumber(metrics?.fp ?? 0)}</strong></div>
              <div><span>Falsos negativos</span><strong className="bad-text">{formatNumber(metrics?.fn ?? 0)}</strong></div>
              <div><span>Verdaderos negativos</span><strong>{formatNumber(metrics?.tn ?? 0)}</strong></div>
            </div>
            <div className="ai-eval-bars">
              <div><span>Precisión</span><div className="ai-bar"><i style={{ width: `${Math.round((metrics?.precision ?? 0) * 100)}%` }} /></div><strong>{precision}</strong></div>
              <div><span>Recall</span><div className="ai-bar"><i style={{ width: `${Math.round((metrics?.recall ?? 0) * 100)}%` }} /></div><strong>{recall}</strong></div>
              <div><span>F1</span><div className="ai-bar"><i style={{ width: `${Math.round((metrics?.f1 ?? 0) * 100)}%` }} /></div><strong>{metrics?.f1 != null ? metrics.f1.toFixed(3) : "n/d"}</strong></div>
            </div>
            <div className="ai-note">
              <Gauge size={15} />
              <p>{metrics?.note ?? "Etiqueta hallazgos como TP o FP para construir la muestra."} No se puede garantizar cero falsos positivos y cero falsos negativos a la vez: decide qué priorizas con estos números.</p>
            </div>
          </Panel>
          <Panel className="span-4" eyebrow="Protocolo" title="Cómo evaluar" description="Sin muestra etiquetada, las métricas no significan nada.">
            <ol className="ai-steps">
              <li>Reúne al menos 30 casos reales o de laboratorio.</li>
              <li>Revisa cada hallazgo y usa “Confirmar ataque” o “Falso positivo”.</li>
              <li>Vuelve aquí: precisión mide ruido; recall mide ataques perdidos.</li>
              <li>Repite tras cambiar modelo, embeddings o prompt.</li>
            </ol>
            <div className="ai-note">
              <ShieldAlert size={15} />
              <p>La IA es asesora. La supresión de alertas y el bloqueo siguen siendo decisiones humanas.</p>
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
        <span className="ai-confidence">conf. {confidence}</span>
        <time className="muted">{formatDateTime(finding.ts)}</time>
      </div>
      <p className="ai-finding-summary">{finding.summary}</p>
      <div className="ai-finding-meta">
        {finding.src_ip && <button className="link-button mono" onClick={() => onOpenEvents(finding.src_ip ?? "")}>{finding.src_ip}</button>}
        <span className={`ai-pill ${finding.source === "ai" ? "ok" : "neutral"}`}>{finding.source === "ai" ? "IA" : finding.source}</span>
        {finding.model && <span className="mono">{finding.model}</span>}
        {finding.notified && <span className="ai-pill neutral">notificado</span>}
        {finding.ack ? <span className="ai-pill ok"><CheckCircle2 size={12} /> revisado</span> : <span className="ai-pill warn">pendiente</span>}
      </div>
      {expanded && <EvidenceList items={finding.evidence} onOpenEvents={onOpenEvents} />}
      <div className="ai-finding-actions">
        <button className="button small ghost" onClick={onToggle}>
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />} {expanded ? "Ocultar evidencia" : `Ver evidencia (${finding.evidence.length})`}
        </button>
        <button className="button small ghost" onClick={onAsk}><BrainCircuit size={14} /> Analizar con IA</button>
        {canOperate && !finding.ack && (
          <button className="button small ghost" onClick={onAck} disabled={busy}><CheckCircle2 size={14} /> Marcar revisado</button>
        )}
        {canOperate && (
          <>
            <button className="button small ghost" onClick={() => onFeedback("true_positive")} disabled={busy}><XCircle size={14} /> Confirmar ataque</button>
            <button className="button small ghost" onClick={() => onFeedback("false_positive")} disabled={busy}><CheckCircle2 size={14} /> Falso positivo</button>
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
            <span className="muted">{item.kind} · {item.source}</span>
            {item.src_ip && <button className="link-button mono" onClick={() => onOpenEvents(item.src_ip ?? "")}>{item.src_ip}</button>}
          </div>
          <p>{item.text}</p>
        </div>
      ))}
    </div>
  );
}

function StructuredResult({ structured }: { structured: AiStructured }) {
  return (
    <div className={`ai-structured v-${structured.verdict}`}>
      <div className="ai-structured-head">
        <strong>{VERDICT_LABEL[structured.verdict] ?? structured.verdict}</strong>
        <span>conf. {Math.round(structured.confidence * 100)}%</span>
        {structured.mitre.map((item) => <span key={item} className="ai-pill neutral mono">{item}</span>)}
      </div>
      <div className="ai-structured-grid">
        <div><span>Observado</span><ul>{structured.observed.map((item) => <li key={item}>{item}</li>)}</ul></div>
        <div><span>Inferido</span><ul>{structured.inferred.map((item) => <li key={item}>{item}</li>)}</ul></div>
        <div><span>Falta</span><ul>{structured.missing.length ? structured.missing.map((item) => <li key={item}>{item}</li>) : <li>nada relevante</li>}</ul></div>
        <div><span>Acciones sugeridas</span><ul>{structured.recommended_actions.map((item) => <li key={item}>{item}</li>)}</ul></div>
      </div>
    </div>
  );
}
