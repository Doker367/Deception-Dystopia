import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { X } from "lucide-react";
import { Portal } from "./Portal";

interface FabricConsoleProps {
  deviceId: string;
  onClose: () => void;
}

/**
 * Terminal interactivo (xterm.js) conectado por WebSocket al backend.
 * El backend hace el puente hacia `docker exec -i -t` del contenedor
 * señuelo; la sesión se autentica con el JWT en el query del WS.
 */
export function FabricConsole({ deviceId, onClose }: FabricConsoleProps) {
  const hostRef = useRef<HTMLDivElement>(null);
  const [status, setStatus] = useState<"connecting" | "open" | "error" | "closed">("connecting");
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: "'JetBrains Mono', ui-monospace, monospace",
      theme: {
        background: "#101418",
        foreground: "#d8e0ea",
        cursor: "#7ad7be",
      },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(hostRef.current ?? document.body);
    fit.fit();

    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const token = window.localStorage.getItem("dystopia.access_token") ?? "";
    const ws = new WebSocket(
      `${proto}://${window.location.host}/api/fabric/devices/${encodeURIComponent(deviceId)}/console/ws?token=${encodeURIComponent(token)}`,
    );
    wsRef.current = ws;
    ws.onopen = () => {
      setStatus("open");
      term.writeln("\x1b[38;5;114m── consola del fabric conectada ──\x1b[0m");
    };
    ws.onmessage = (event) => term.write(event.data);
    ws.onerror = () => {
      setStatus("error");
      setError("No se pudo abrir la consola (verifica rol admin y que la sesión sea válida)");
    };
    ws.onclose = () => setStatus((prev) => (prev === "open" ? "closed" : prev));

    return () => {
      ws.close();
      term.dispose();
    };
  }, [deviceId]);

  return (
    <Portal>
      <div className="drawer-backdrop" style={{ zIndex: 95 }} onClick={onClose}>
        <aside
          className="event-drawer config-drawer"
          onClick={(event) => event.stopPropagation()}
          style={{ maxWidth: 860, display: "flex", flexDirection: "column" }}
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
          {status === "connecting" && (
            <div className="empty-state small">
              <strong>Conectando…</strong>
            </div>
          )}
          {status === "error" && (
            <div className="segment-note">
              <p>{error}</p>
            </div>
          )}
          <div ref={hostRef} style={{ flex: 1, minHeight: 420 }} />
        </aside>
      </div>
    </Portal>
  );
}
