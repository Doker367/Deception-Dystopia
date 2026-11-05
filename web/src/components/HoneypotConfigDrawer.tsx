import { X } from "lucide-react";
import type { Honeypot, HoneypotConfig } from "../types";

interface HoneypotConfigDrawerProps {
  honeypot: Honeypot | null;
  config: HoneypotConfig | null;
  onClose: () => void;
}

export function HoneypotConfigDrawer({ honeypot, config, onClose }: HoneypotConfigDrawerProps) {
  if (!honeypot || !config) return null;

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="event-drawer config-drawer" onClick={(event) => event.stopPropagation()}>
        <div className="drawer-head">
          <div>
            <span className="eyebrow">Honeypot / configuration</span>
            <h2>{honeypot.name}</h2>
            <span className="mono muted">{config.container}</span>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Cerrar configuración"><X size={18} /></button>
        </div>

        <div className="drawer-badges">
          <span className="health-pill healthy"><i />{honeypot.status}</span>
          <span className="sensor-chip">{honeypot.service}</span>
          <span className="proto-chip">{config.logFormat}</span>
        </div>

        <p className="config-description">{config.description}</p>

        <div className="honeypot-config-grid">
          <div><span>Imagen</span><strong className="mono">{config.image}</strong></div>
          <div><span>Dispositivo</span><strong className="mono">{config.device}</strong></div>
          <div><span>Usuario</span><strong className="mono">{config.user}</strong></div>
          <div><span>Puerto host</span><strong className="mono">127.0.0.1:{honeypot.port}</strong></div>
        </div>

        <section className="config-block">
          <span className="eyebrow">Archivo de configuración</span>
          <div className="config-code-row"><span className="mono">{config.configTarget}</span><span>{config.configFile}</span></div>
        </section>

        <section className="config-block">
          <span className="eyebrow">Puertos declarados</span>
          <div className="config-port-list">
            {config.ports.map((port) => (
              <div key={`${port.container}-${port.proto}`}>
                <span className="mono">{port.container}/{port.proto}</span>
                <span>{port.purpose}</span>
                <span className="mono muted">{port.host ? `host :${port.host}` : "interno"}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="config-block">
          <span className="eyebrow">Volúmenes</span>
          <div className="config-list">
            {config.volumes.map((volume) => <span className="mono" key={volume}>{volume}</span>)}
          </div>
        </section>

        <section className="config-block">
          <span className="eyebrow">Log y salud</span>
          <div className="config-kv">
            <div><span>Log</span><strong className="mono">{config.logPath}</strong></div>
            <div><span>Formato</span><strong className="mono">{config.logFormat}</strong></div>
            <div><span>Healthcheck</span><strong>{config.healthcheck.type} · {config.healthcheck.marker}</strong></div>
            <div><span>Intervalo</span><strong>{config.healthcheck.interval} · start {config.healthcheck.startPeriod}</strong></div>
          </div>
        </section>

        <section className="config-block">
          <span className="eyebrow">Recursos asignados</span>
          <div className="honeypot-config-grid compact">
            <div><span>Memoria</span><strong>{config.resources.memLimit}</strong></div>
            <div><span>CPU</span><strong>{config.resources.cpus}</strong></div>
            <div><span>PIDs</span><strong>{config.resources.pidsLimit}</strong></div>
            <div><span>Nofile</span><strong>{config.resources.nofile}</strong></div>
            <div><span>Tmpfs</span><strong>{config.resources.tmpfsMib} MiB</strong></div>
          </div>
        </section>

        <div className="config-footnote">
          Configuración declarada en <code>deploy/honeypots/inventory.yaml</code>. La interfaz no inicia, detiene ni modifica contenedores.
        </div>
      </aside>
    </div>
  );
}
