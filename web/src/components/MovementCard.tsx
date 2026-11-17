import { formatTime } from "../lib/format";

export interface MovementStep {
  at: string;
  last_at: string;
  command: string;
  count: number;
  /** Texto que devolvió la shell emulada del señuelo. */
  response?: string;
}

export interface Movement {
  session: string;
  login_at: string;
  username: string | null;
  proto: string;
  device: string;
  sensor?: string;
  commands: number;
  total_commands?: number;
  truncated?: boolean;
  /** Comandos con respuesta registrada en el TTY del señuelo. */
  answered?: number;
  steps: MovementStep[];
}

/** Resumen de lo que hizo un atacante después de un acceso aceptado. */
export function MovementCard({ movement }: { movement: Movement }) {
  const answered = movement.answered ?? movement.steps.filter((step) => Boolean(step.response)).length;
  return (
    <article className="movement-card">
      <header className="movement-head">
        <span className="movement-badge">Acceso aceptado</span>
        <strong>{movement.username || "usuario no registrado"}</strong>
        <span className="mono muted">{movement.session}</span>
        <time>{formatTime(movement.login_at)}</time>
        <span className="muted">{movement.proto || "tcp"} · {movement.device || "señuelo"}</span>
        <span className="sensor-chip">{movement.commands} {movement.commands === 1 ? "comando" : "comandos"}</span>
        <span className="sensor-chip">{answered} con respuesta</span>
      </header>
      <p className="movement-narrative">
        <strong>{movement.username || "Acceso aceptado"}</strong>
        {movement.proto ? ` por ${movement.proto}` : ""}
        {movement.device ? ` en ${movement.device}` : ""}
        {movement.commands
          ? ` · ejecutó ${movement.commands} ${movement.commands === 1 ? "comando" : "comandos"} y el señuelo respondió a ${answered}.`
          : " · no ejecutó comandos registrados."}
      </p>
      {movement.steps.length ? (
        <ol className="movement-steps">
          {movement.steps.map((step, index) => (
            <li key={`${movement.session}-${step.at}-${index}`}>
              <time>{formatTime(step.at)}</time>
              <div className="movement-step-body">
                <div className="movement-command">
                  <span className="movement-prompt" aria-hidden="true">$</span>
                  <code className="mono">{step.command}</code>
                  {step.count > 1 && <span className="movement-count">×{step.count}</span>}
                </div>
                {step.response
                  ? <pre className="movement-response" aria-label="Respuesta del señuelo">{step.response}</pre>
                  : <span className="movement-no-response">Sin salida registrada del señuelo</span>}
              </div>
            </li>
          ))}
        </ol>
      ) : <p className="muted">El acceso fue aceptado, pero no se capturaron comandos posteriores.</p>}
      {movement.truncated && (
        <p className="movement-truncated">
          Sesión extensa: se muestran los primeros {movement.steps.length} pasos de {movement.total_commands ?? movement.commands}.
        </p>
      )}
    </article>
  );
}
