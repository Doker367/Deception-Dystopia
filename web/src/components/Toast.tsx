import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { CheckCircle2, Info, X, XCircle } from "lucide-react";

type Tone = "success" | "info" | "error";
interface ToastItem {
  id: number;
  message: string;
  tone: Tone;
}

interface ToastContextValue {
  notify: (message: string, tone?: Tone) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export function useToast() {
  const value = useContext(ToastContext);
  if (!value) throw new Error("useToast must be used within ToastProvider");
  return value;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);

  const dismiss = useCallback((id: number) => {
    setItems((current) => current.filter((item) => item.id !== id));
  }, []);

  const notify = useCallback((message: string, tone: Tone = "info") => {
    const id = Date.now() + Math.random();
    setItems((current) => [...current.slice(-2), { id, message, tone }]);
    window.setTimeout(() => dismiss(id), 4200);
  }, [dismiss]);

  const value = useMemo(() => ({ notify }), [notify]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toast-stack" aria-live="polite" aria-atomic="false">
        {items.map((item) => (
          <div className={`app-toast ${item.tone}`} key={item.id} role="status">
            <span className="toast-icon">
              {item.tone === "success" ? <CheckCircle2 size={16} /> : item.tone === "error" ? <XCircle size={16} /> : <Info size={16} />}
            </span>
            <span>{item.message}</span>
            <button onClick={() => dismiss(item.id)} aria-label="Cerrar aviso"><X size={13} /></button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
