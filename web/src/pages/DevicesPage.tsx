import { useMemo, useState } from "react";
import {
  ArrowRight,
  Boxes,
  Camera,
  CheckCircle2,
  HardDrive,
  Monitor,
  Network,
  Printer,
  Router,
  Server,
  Shield,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Panel } from "../components/Panel";
import { DEVICES, SEGMENTS } from "../data/mock";

const PROFILE_ICON = {
  server: Server,
  switch: Network,
  router: Router,
  printer: Printer,
  camera: Camera,
  firewall: Shield,
  pc: Monitor,
} as const;

const PROFILE_LABEL: Record<string, string> = {
  server: "Servidor",
  switch: "Switch",
  router: "Router",
  printer: "Impresora",
  camera: "Cámara",
  firewall: "Firewall",
  pc: "Estación",
};

export function DevicesPage() {
  const [selected, setSelected] = useState("all");
  const devices = useMemo(() => (selected === "all" ? DEVICES : DEVICES.filter((device) => device.segment === selected)), [selected]);

  return (
    <div className="page">
      <PageHeader
        eyebrow="Operación / Topology"
        title="Dispositivos y segmentos"
        description="Topología declarativa de la red señuelo. Dystopia es la fuente de verdad; la analítica solo observa el resultado."
        actions={
          <>
            <button className="button ghost"><HardDrive size={15} /> Exportar topología</button>
            <button className="button primary"><Network size={15} /> Editar segmentos</button>
          </>
        }
        meta={
          <>
            <span><i className="status-dot live" /> 6 dispositivos</span>
            <span>3 segmentos</span>
            <span className="mono">config/deception/network.yaml</span>
          </>
        }
      />

      <div className="topology-layout">
        <Panel
          className="topology-panel"
          eyebrow="Topología lógica"
          title="Celda c1 · red señuelo"
          description="Segmentos declarados y dispositivos asociados. Las conexiones son lógicas, no implican cambios reales de red."
          actions={
            <div className="segmented-control">
              <button className={selected === "all" ? "active" : ""} onClick={() => setSelected("all")}>Todos</button>
              {SEGMENTS.map((segment) => (
                <button key={segment.name} className={selected === segment.name ? "active" : ""} onClick={() => setSelected(segment.name)}>{segment.name}</button>
              ))}
            </div>
          }
          flush
        >
          <div className="topology-canvas">
            <div className="topology-core">
              <span className="core-orbit" />
              <span className="core-orbit orbit-two" />
              <div className="core-node">
                <Shield size={21} />
                <strong>Dystopia Core</strong>
                <span className="mono">c1</span>
              </div>
            </div>
            <div className="topology-segments">
              {SEGMENTS.map((segment) => (
                <div className={`segment-column ${selected !== "all" && selected !== segment.name ? "dimmed" : ""}`} key={segment.name}>
                  <div className="segment-head">
                    <span className="segment-dot" style={{ background: segment.color }} />
                    <div><strong>{segment.name}</strong><span className="mono">{segment.cidr}</span></div>
                    <span className="segment-count">{segment.devices}</span>
                  </div>
                  <div className="segment-devices">
                    {DEVICES.filter((device) => device.segment === segment.name).map((device) => {
                      const Icon = PROFILE_ICON[device.profile as keyof typeof PROFILE_ICON] ?? Boxes;
                      return (
                        <div className="device-node" key={device.name}>
                          <span className="device-icon"><Icon size={16} /></span>
                          <div><strong>{device.name}</strong><span className="mono">{device.ip}</span></div>
                          <span className={`device-status ${device.status}`} />
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </Panel>

        <Panel className="segment-panel" eyebrow="Segmentos" title="Resumen de red">
          <div className="segment-list">
            {SEGMENTS.map((segment) => (
              <button key={segment.name} className={selected === segment.name ? "active" : ""} onClick={() => setSelected(segment.name)}>
                <span className="segment-dot" style={{ background: segment.color }} />
                <span><strong>{segment.name}</strong><small className="mono">{segment.cidr}</small></span>
                <span className="segment-meta"><b>{segment.devices}</b><small>{segment.exposure}</small></span>
                <ArrowRight size={14} />
              </button>
            ))}
          </div>
          <div className="segment-note">
            <CheckCircle2 size={15} />
            <p>Los segmentos son declarativos. La interfaz no aplica VLANs, bridges ni reglas nftables.</p>
          </div>
        </Panel>
      </div>

      <div className="dashboard-grid">
        <Panel className="span-8" eyebrow="Inventario" title="Dispositivos" description="Perfiles y servicios observados en la topología." flush>
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Dispositivo</th><th>Perfil</th><th>Segmento</th><th>Dirección</th><th>Servicios</th><th>Estado</th></tr></thead>
              <tbody>
                {devices.map((device) => {
                  const Icon = PROFILE_ICON[device.profile as keyof typeof PROFILE_ICON] ?? Boxes;
                  return (
                    <tr key={device.name}>
                      <td><span className="device-name"><Icon size={14} />{device.name}</span></td>
                      <td>{PROFILE_LABEL[device.profile] ?? device.profile}</td>
                      <td><span className="sensor-chip">{device.segment}</span></td>
                      <td className="mono">{device.ip}</td>
                      <td>{device.services}</td>
                      <td><span className={`health-pill ${device.status === "online" ? "healthy" : "degraded"}`}><i />{device.status}</span></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel className="span-4" eyebrow="Modelo" title="Cómo se emulan dispositivos">
          <div className="model-list">
            <div><span className="model-number">01</span><p><strong>Declaración</strong><span>Segmentos, perfiles, IPs y servicios viven en <code>network.yaml</code>.</span></p></div>
            <div><span className="model-number">02</span><p><strong>Materialización</strong><span>El motor crea la celda y publica los servicios señuelo.</span></p></div>
            <div><span className="model-number">03</span><p><strong>Observación</strong><span>Los honeypots y VMs reportan eventos al pipeline de Dystopia.</span></p></div>
            <div><span className="model-number">04</span><p><strong>Gate</strong><span>La activación real requiere verificador Linux y claves de confianza.</span></p></div>
          </div>
        </Panel>

        <Panel className="span-12" eyebrow="Capacidad" title="Estado de la celda" description="Límites operativos de la celda de laboratorio.">
          <div className="capacity-grid">
            <div><span>Dispositivos</span><strong>6 / 12</strong><div className="capacity-bar"><i style={{ width: "50%" }} /></div></div>
            <div><span>Segmentos</span><strong>3 / 6</strong><div className="capacity-bar"><i style={{ width: "50%" }} /></div></div>
            <div><span>Servicios publicados</span><strong>17 / 40</strong><div className="capacity-bar"><i style={{ width: "42%" }} /></div></div>
            <div><span>RAM del host</span><strong>3.8 GB</strong><div className="capacity-bar warning"><i style={{ width: "78%" }} /></div></div>
          </div>
        </Panel>
      </div>
    </div>
  );
}
