import { Copy, TerminalSquare, X } from "lucide-react";
import type { Honeypot, HoneypotConfig } from "../types";
import { useToast } from "./Toast";

const LOG_SAMPLES: Record<string, string[]> = {
  cowrie: [
    '{"eventid":"cowrie.session.connect","src_ip":"203.0.113.7","src_port":55555,"session":"c1","timestamp":"2026-11-05T12:00:00Z"}',
    '{"eventid":"cowrie.login.failed","src_ip":"203.0.113.7","username":"root","password":"[redacted]","timestamp":"2026-11-05T12:00:03Z"}',
    '{"eventid":"cowrie.command.input","src_ip":"203.0.113.7","input":"uname -a","timestamp":"2026-11-05T12:00:08Z"}',
  ],
  opencanary: [
    '{"src_host":"203.0.113.7","src_port":55555,"dst_host":"10.20.2.20","dst_port":80,"logtype":3000,"msg":"HTTP request"}',
    '{"src_host":"203.0.113.7","dst_port":22,"logtype":4004,"msg":"SSH login attempt"}',
  ],
  dionaea: [
    '{"connection":{"protocol":"smb","remote_ip":"203.0.113.7"},"event":"connection"}',
    '{"connection":{"protocol":"smb"},"event":"smb_negotiation"}',
  ],
  heralding: [
    '{"protocol":"ssh","src_ip":"203.0.113.7","username":"admin","password":"[redacted]"}',
    '{"protocol":"rdp","src_ip":"203.0.113.7","username":"administrator"}',
  ],
  redishoneypot: [
    '{"src_ip":"203.0.113.7","command":"PING","timestamp":"2026-11-05T12:00:00Z"}',
    '{"src_ip":"203.0.113.7","command":"INFO","timestamp":"2026-11-05T12:00:02Z"}',
  ],
  endlessh: [
    "2026-11-05T12:00:00Z CONNECT 203.0.113.7:55555",
    "2026-11-05T12:00:31Z CLOSE 203.0.113.7:55555 duration=31s bytes=0",
  ],
};

interface HoneypotLogDrawerProps {
  honeypot: Honeypot | null;
  config: HoneypotConfig | null;
  onClose: () => void;
}

export function HoneypotLogDrawer({ honeypot, config, onClose }: HoneypotLogDrawerProps) {
  const { notify } = useToast();
  if (!honeypot || !config) return null;
  const lines = LOG_SAMPLES[honeypot.id] ?? [];

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="event-drawer config-drawer log-drawer" onClick={(event) => event.stopPropagation()}>
        <div className="drawer-head">
          <div>
            <span className="eyebrow">Honeypot / log preview</span>
            <h2>{honeypot.name} · logs</h2>
            <span className="mono muted">{config.logPath}</span>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Cerrar logs"><X size={18} /></button>
        </div>

        <div className="drawer-badges">
          <span className="sensor-chip">{config.logFormat}</span>
          <span className="health-pill healthy"><i />lectura local</span>
        </div>

        <div className="log-path-bar">
          <TerminalSquare size={14} />
          <span className="mono">{config.logPath}</span>
          <button className="icon-button small" onClick={() => { navigator.clipboard?.writeText(config.logPath); notify("Ruta de log copiada.", "success"); }} aria-label="Copiar ruta"><Copy size={13} /></button>
        </div>

        <div className="log-viewer">
          {lines.map((line, index) => (
            <div key={index}><span className="log-line-number">{String(index + 1).padStart(2, "0")}</span><code>{line}</code></div>
          ))}
        </div>

        <div className="config-footnote">
          Vista de ejemplo del formato declarado. El visor en vivo se habilitará cuando el colector local de los honeypots esté conectado al almacén SQLite.
        </div>
      </aside>
    </div>
  );
}
