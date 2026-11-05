import { Copy, Network, Server, ShieldCheck, X } from "lucide-react";
import { useToast } from "./Toast";

interface DeviceLike {
  name: string;
  segment: string;
  ip: string;
  profile: string;
  services: number;
  status: string;
}

interface DeviceDrawerProps {
  device: DeviceLike | null;
  onClose: () => void;
}

const SERVICE_HINTS: Record<string, string[]> = {
  server: ["ssh/tcp", "http/tcp", "smb/tcp"],
  switch: ["ssh/tcp", "snmp/udp", "http/tcp", "telnet/tcp"],
  router: ["ssh/tcp", "https/tcp", "snmp/udp", "dhcp/udp", "dns/udp"],
  printer: ["http/tcp", "ipp/tcp"],
  camera: ["rtsp/tcp"],
  firewall: ["https/tcp", "ssh/tcp"],
  pc: ["http/tcp", "smb/tcp"],
};

export function DeviceDrawer({ device, onClose }: DeviceDrawerProps) {
  const { notify } = useToast();
  if (!device) return null;
  const services = SERVICE_HINTS[device.profile] ?? ["tcp"];
  const yaml = [
    "device:",
    `  id: ${device.name}`,
    `  segment: ${device.segment}`,
    `  address: ${device.ip}`,
    `  profile: ${device.profile}`,
    "  services:",
    ...services.map((service) => `    - ${service}`),
  ].join("\n");

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="event-drawer config-drawer" onClick={(event) => event.stopPropagation()}>
        <div className="drawer-head">
          <div>
            <span className="eyebrow">Topology / device</span>
            <h2>{device.name}</h2>
            <span className="mono muted">{device.ip}</span>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Cerrar dispositivo"><X size={18} /></button>
        </div>

        <div className="drawer-badges">
          <span className={`health-pill ${device.status === "online" ? "healthy" : "degraded"}`}><i />{device.status}</span>
          <span className="sensor-chip">{device.segment}</span>
          <span className="proto-chip">{device.profile}</span>
        </div>

        <div className="honeypot-config-grid">
          <div><span>Perfil</span><strong>{device.profile}</strong></div>
          <div><span>Segmento</span><strong>{device.segment}</strong></div>
          <div><span>Servicios</span><strong>{device.services} declarados</strong></div>
          <div><span>Dirección</span><strong className="mono">{device.ip}</strong></div>
        </div>

        <section className="config-block">
          <span className="eyebrow">Configuración declarativa</span>
          <pre className="device-yaml">{yaml}</pre>
          <button className="button ghost wide" onClick={() => { navigator.clipboard?.writeText(yaml); notify("Configuración YAML copiada.", "success"); }}><Copy size={14} /> Copiar YAML</button>
        </section>

        <section className="config-block">
          <span className="eyebrow">Servicios observados</span>
          <div className="service-chip-list">
            {services.map((service) => <span key={service} className="proto-chip">{service}</span>)}
          </div>
        </section>

        <div className="segment-note">
          <ShieldCheck size={15} />
          <p>La topología es declarativa. La UI no aplica cambios de red, VLANs ni reglas nftables.</p>
        </div>
        <div className="config-footnote">
          <Network size={13} /> Segmento en <code>config/deception/network.yaml</code>. <Server size={13} /> Materialización sujeta al gate de activación.
        </div>
      </aside>
    </div>
  );
}
