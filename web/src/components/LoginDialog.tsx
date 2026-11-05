import { useState } from "react";
import { KeyRound, LockKeyhole, ShieldCheck, X } from "lucide-react";
import { BrandMark } from "./Brand";
import { ApiError, login } from "../lib/api";

interface LoginDialogProps {
  open: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export function LoginDialog({ open, onClose, onSuccess }: LoginDialogProps) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (!open) return null;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username.trim(), password);
      setPassword("");
      onSuccess();
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : "No se pudo conectar con el control plane");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-backdrop" onMouseDown={onClose}>
      <div className="auth-dialog" role="dialog" aria-modal="true" aria-labelledby="login-title" onMouseDown={(event) => event.stopPropagation()}>
        <button className="icon-button auth-close" onClick={onClose} aria-label="Cerrar"><X size={18} /></button>
        <div className="auth-brand"><BrandMark className="auth-mark" /><span>DYSTOPIA</span></div>
        <span className="eyebrow">Control plane / session</span>
        <h2 id="login-title">Conectar datos en vivo</h2>
        <p>Inicia sesión con una cuenta local de Dystopia para consultar Elasticsearch a través del BFF analítico. La API key del writer nunca se envía al navegador.</p>
        <form className="auth-form" onSubmit={submit}>
          <label>
            <span>Usuario</span>
            <div className="auth-input"><KeyRound size={15} /><input autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required maxLength={64} /></div>
          </label>
          <label>
            <span>Contraseña</span>
            <div className="auth-input"><LockKeyhole size={15} /><input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /></div>
          </label>
          {error && <p className="auth-error" role="alert">{error}</p>}
          <button className="button primary wide" type="submit" disabled={busy}>{busy ? "Conectando…" : "Iniciar sesión"}</button>
        </form>
        <div className="auth-foot"><ShieldCheck size={14} /> JWT local · el BFF aplica rol viewer como mínimo</div>
      </div>
    </div>
  );
}
