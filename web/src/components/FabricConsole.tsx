/* Terminal interactivo del fabric (drawer, Fase 11).

   Conecta con el control por WebSocket (JWT admin en el query) y puentea
   un xterm.js hacia ``docker exec -i -t`` del contenedor señuelo.

   Experiencia:
   - reconexión automática con backoff exponencial visible (chip + banner).
   - resize propagado al PTY (fit del xterm al contenedor con debounce).
   - copiar (Ctrl+Shift+C) y pegar (Ctrl+Shift+V) por teclado.
   - limpiar pantalla (botón Clear + Ctrl+L lo maneja el shell del PTY).
   - Ctrl+C lo pasa el shell del backend como SIGINT (terminal real).
   - lista de sesiones activas con estado (chips) y accesibilidad
     (foco atrapado, Escape para cerrar, aria-labels). */
import { useEffect, useRef } from "react";
import { AlertTriangle, RefreshCw, X } from "lucide-react";
import "@xterm/xterm/css/xterm.css";
import { Portal } from "./Portal";
import type { ConsoleStatus, DeviceConsoleState } from "../types";
import { useConsoleSession } from "../hooks/useConsoleSession";
import { STATUS_LABEL } from "../hooks/consoleProtocol";

interface FabricConsoleProps {
  deviceId: string;
  /** Reporta el estado de la sesión al panel del padre (chips). */
  onState?: (deviceId: string, state: DeviceConsoleState) => void;
  /** Otras consolas abiertas (para el strip de sesiones). */
  otherSessions?: Array<{ deviceId: string; status: ConsoleStatus }>;
  /** Cambia a la consola de otro dispositivo (chip). */
  onOpenDevice?: (deviceId: string) => void;
  /** Cierra el drawer (y la sesión). */
  onClose: () => void;
}

/** Color del chip de estado (paleta Dystopia). */
const STATUS_COLOR: Record<ConsoleStatus, string> = {
  connecting: "#66afe9",
  open: "#9bd275",
  reconnecting: "#f0ad4e",
  error: "#f05050",
  closed: "#8b959c",
};

export function FabricConsole({
  deviceId, onState, otherSessions = [], onOpenDevice, onClose,
}: FabricConsoleProps) {
  const asideRef = useRef<HTMLElement | null>(null);

  const session = useConsoleSession({
    deviceId,
    onState: onState ?? (() => {}),
    onClose,
  });

  /* Escape cierra el drawer y el terminal coge el foco al abrir. */
  useEffect(() => {
    const node = asideRef.current;
    if (node !== null && session.status === "open") session.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, session]);

  const status = session.status;
  const statusColor = STATUS_COLOR[status];
  const statusLabel = STATUS_LABEL[status];

  return (
    <Portal>
      <div className="drawer-backdrop" style={{ zIndex: 95 }} onClick={onClose}>
        <aside
          ref={asideRef}
          className="event-drawer console-drawer"
          role="dialog"
          aria-modal="true"
          aria-label={"Terminal interactivo del dispositivo " + deviceId}
          tabIndex={-1}
          onClick={(event) => event.stopPropagation()}
        >
          <div className="drawer-head">
            <div>
              <span className="eyebrow">Fabric / consola</span>
              <h2>Terminal · {deviceId}</h2>
              <span className="mono muted">Sesión interactiva sobre WebSocket</span>
            </div>
            <button className="icon-button" onClick={onClose} aria-label="Cerrar consola">
              <X size={18} />
            </button>
          </div>

          <div className="drawer-badges console-status-strip">
            <span
              className="health-pill"
              style={{ color: statusColor, background: statusColor + "1f" }}
              role="status"
              aria-live="polite"
            >
              <i />{statusLabel}
            </span>
            {session.attempt > 0 && (
              <span className="proto-chip">intento {session.attempt}/{5}</span>
            )}
            {session.retryIn !== null && (
              <span className="proto-chip" aria-live="polite">
                reintento en {session.retryIn}s
              </span>
            )}
            <span className="mono muted">Ctrl+L limpia · Ctrl+Shift+C copia · Ctrl+Shift+V pega</span>
            <button
              type="button"
              className="button ghost console-clear"
              onClick={session.clearScreen}
              title="Limpiar la pantalla (Ctrl+L)"
              disabled={status !== "open"}
            >
              Limpiar
            </button>
          </div>

          {otherSessions.length > 0 && (
            <div className="console-sessions" role="list" aria-label="Otras sesiones abiertas">
              {otherSessions.map((item) => (
                <button
                  key={item.deviceId}
                  type="button"
                  className="network-chip"
                  style={{ color: STATUS_COLOR[item.status], borderColor: STATUS_COLOR[item.status] + "73" }}
                  onClick={() => { onOpenDevice?.(item.deviceId); }}
                  aria-label={"Cambiar a la consola de " + item.deviceId}
                >
                  <i style={{ background: STATUS_COLOR[item.status] }} />
                  {item.deviceId}
                </button>
              ))}
            </div>
          )}

          {session.error !== null && (
            <div className="segment-note console-error" role="alert">
              <AlertTriangle size={15} />
              <p>{session.error}</p>
            </div>
          )}
          {(status === "reconnecting" || status === "error") && (
            <button
              type="button"
              className="button ghost console-retry"
              onClick={session.reconnect}
              title="Reconectar ahora"
            >
              <RefreshCw size={14} /> Reintentar ahora
            </button>
          )}

          <div className="console-host" ref={session.hostRef} />
        </aside>
      </div>
    </Portal>
  );
}
