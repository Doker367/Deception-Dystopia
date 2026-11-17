import { useState } from "react";
import {
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  Sparkles,
  XCircle,
} from "lucide-react";
import { apiPost, getToken } from "../lib/api";

interface AiEvidence {
  n?: number;
  chunk_id?: number;
  doc_key?: string;
  kind?: string;
  source?: string;
  src_ip?: string | null;
  ts?: string | null;
  heading?: string;
  text?: string;
  similarity?: number | null;
}

interface AiAsk {
  answer: string;
  abstained: boolean;
  grounded: boolean;
  citations?: number[];
  evidence: AiEvidence[];
  model?: string | null;
  retrieval?: { mode?: string; degraded?: boolean; error?: string | null; count?: number };
}

interface AskAiPanelProps {
  /** IP del origen; limita la recuperación a su evidencia. */
  srcIp?: string;
  /** Texto breve que sitúa la pregunta (evento, sesión, etc.). */
  context?: string;
  defaultQuestion?: string;
  suggestions?: string[];
  /** Adjunta los movimientos y respuestas del señuelo de esa IP al prompt. */
  includeMovements?: boolean;
  /** Modo demostración: no hay sesión real contra la que preguntar. */
  demo?: boolean;
}

const DEFAULT_SUGGESTIONS = [
  "¿Qué hizo esta IP después de entrar?",
  "¿Qué comandos ejecutó y qué intentaba lograr?",
  "¿Hubo un acceso exitoso? ¿Qué riesgo implica?",
  "¿Qué debo revisar o contener primero?",
];

const EVENT_SUGGESTIONS = [
  "¿Qué significa este evento exactamente?",
  "¿Se relaciona con un acceso exitoso?",
  "¿Qué movimientos se observaron antes y después?",
];

function errorText(cause: unknown): string {
  if (cause instanceof Error) return cause.message;
  return "No se pudo consultar a la IA";
}

export function AskAiPanel({
  srcIp, context, defaultQuestion = "", suggestions, includeMovements = false, demo = false,
}: AskAiPanelProps) {
  const [question, setQuestion] = useState(defaultQuestion);
  const [result, setResult] = useState<AiAsk | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const logged = Boolean(getToken());
  const disabled = demo || !logged;
  const choices = suggestions ?? (context ? EVENT_SUGGESTIONS : DEFAULT_SUGGESTIONS);

  async function ask() {
    const text = question.trim();
    if (text.length < 3) {
      setError("Escribe una pregunta de al menos 3 caracteres.");
      return;
    }
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const response = await apiPost<AiAsk>("/api/ai/rag/ask", {
        question: text,
        ...(srcIp ? { src_ip: srcIp } : {}),
        ...(includeMovements && srcIp ? { include_movements: true } : {}),
        mode: "analysis",
      });
      setResult(response);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="drawer-ai">
      <div className="drawer-ai-head">
        <span><Sparkles size={15} /> Preguntar a la IA</span>
        <small>Responde con la memoria local y cita sus fuentes. Verifica siempre la evidencia.</small>
      </div>
      {context && <p className="drawer-ai-context">{context}</p>}
      {disabled ? (
        <p className="investigation-notice">
          {demo ? "Inicia sesión para preguntar a la IA sobre la evidencia real." : "Necesitas una sesión activa para usar la IA."}
        </p>
      ) : (
        <>
          <label className="drawer-ai-field">
            ¿Qué quieres saber?
            <textarea
              rows={3}
              value={question}
              maxLength={2000}
              onChange={(event) => setQuestion(event.target.value)}
              placeholder={srcIp ? `¿Qué hizo ${srcIp} y qué comandos ejecutó?` : "Escribe tu pregunta sobre este evento"}
            />
          </label>
          <div className="drawer-ai-suggestions">
            {choices.map((choice) => (
              <button key={choice} type="button" className="sensor-chip drawer-ai-chip" onClick={() => setQuestion(choice)}>
                {choice}
              </button>
            ))}
          </div>
          <div className="drawer-ai-actions">
            <button className="button primary" onClick={() => void ask()} disabled={busy}>
              <BrainCircuit size={14} /> {busy ? "Pensando…" : "Preguntar"}
            </button>
            {(result || error) && (
              <button className="button ghost" onClick={() => { setResult(null); setError(""); }}>
                Limpiar
              </button>
            )}
          </div>
          {error && <p className="investigation-error" role="alert">{error}</p>}
          {result && (
            <div className="ai-result">
              <div className="ai-result-badges">
                {result.grounded ? (
                  <span className="ai-pill ok"><CheckCircle2 size={12} /> basada en fuentes</span>
                ) : (
                  <span className="ai-pill bad"><XCircle size={12} /> sin fuentes verificables</span>
                )}
                {result.abstained && <span className="ai-pill warn"><AlertTriangle size={12} /> prefirió no responder</span>}
                {result.retrieval?.mode && <span className="ai-pill neutral">búsqueda: {result.retrieval.mode}</span>}
                <span className="ai-pill neutral">{result.evidence.length} fuente(s)</span>
                {result.model && <span className="ai-pill neutral mono">{result.model}</span>}
              </div>
              <div className={`ai-answer ${result.grounded ? "grounded" : "warning"}`}>{result.answer}</div>
              {result.evidence.length > 0 && (
                <div className="ai-evidence">
                  {result.evidence.slice(0, 4).map((item, index) => (
                    <details className="ai-evidence-item" key={`${item.chunk_id ?? item.doc_key ?? index}-${index}`}>
                      <summary className="drawer-ai-source">
                        <span className="ai-cite">[{item.n ?? index + 1}]</span>
                        <strong>{item.heading || item.doc_key || "Fuente"}</strong>
                        <span className="muted">{item.kind || "documento"} · {item.source || "memoria local"}</span>
                        {typeof item.similarity === "number" && (
                          <span className="mono muted">parecido {Math.round(item.similarity * 100)}%</span>
                        )}
                      </summary>
                      <p>{item.text}</p>
                    </details>
                  ))}
                </div>
              )}
              <p className="ai-hint">Respuesta generada por la IA. Compruébala con las fuentes y el evento original antes de decidir.</p>
            </div>
          )}
        </>
      )}
    </div>
  );
}
