import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type CSSProperties } from "react";
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
import { EChart } from "../components/EChart";
import { ActionDialog } from "../components/ActionDialog";
import { DeviceDrawer } from "../components/DeviceDrawer";
import { useToast } from "../components/Toast";
import { DEVICES, SEGMENTS } from "../data/mock";
import { horizontalBarOption } from "../lib/charts";
import { downloadJson } from "../lib/download";
import { profileColor } from "../lib/profiles";

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

/** Curvas que conectan el núcleo con cada columna de segmento. */
interface LinkPath {
  key: string;
  color: string;
  dimmed: boolean;
  path: string;
  coreDot: { x: number; y: number };
  segmentDot: { x: number; y: number };
}

export function DevicesPage() {
  const { notify } = useToast();
  const [selected, setSelected] = useState("all");
  const [deviceName, setDeviceName] = useState<string | null>(null);
  const [editOpen, setEditOpen] = useState(false);
  const canvasRef = useRef<HTMLDivElement | null>(null);
  const coreRef = useRef<HTMLDivElement | null>(null);
  const segmentRefs = useRef<Map<string, HTMLDivElement>>(new Map());
  const [links, setLinks] = useState<LinkPath[]>([]);

  const devices = useMemo(() => (selected === "all" ? DEVICES : DEVICES.filter((device) => device.segment === selected)), [selected]);
  const selectedDevice = DEVICES.find((device) => device.name === deviceName) ?? null;
  const topologyYaml = [
    "cell: c1",
    "segments:",
    ...SEGMENTS.map((segment) => `  - id: ${segment.name}\n    cidr: ${segment.cidr}\n    exposure: ${segment.exposure}`),
    "devices:",
    ...DEVICES.map((device) => `  - id: ${device.name}\n    segment: ${device.segment}\n    address: ${device.ip}\n    profile: ${device.profile}`),
  ].join("\n");

  const measureLinks = useCallback(() => {
    const canvas = canvasRef.current;
    const core = coreRef.current;
    if (!canvas || !core) return;
    // En móvil el núcleo se apila sobre los segmentos: no hay líneas.
    if (window.matchMedia("(max-width: 900px)").matches) {
      setLinks([]);
      return;
    }
    const canvasBox = canvas.getBoundingClientRect();
    const coreBox = core.getBoundingClientRect();
    const origin = {
      x: coreBox.right - canvasBox.left - 6,
      y: coreBox.top - canvasBox.top + coreBox.height / 2,
    };
    const next: LinkPath[] = [];
    for (const segment of SEGMENTS) {
      const node = segmentRefs.current.get(segment.name);
      if (!node) continue;
      const box = node.getBoundingClientRect();
      const target = {
        x: box.left - canvasBox.left - 4,
        y: box.top - canvasBox.top + box.height / 2,
      };
      const bend = (target.x - origin.x) / 2;
      next.push({
        key: segment.name,
        color: segment.color,
        dimmed: selected !== "all" && selected !== segment.name,
        path: `M ${origin.x} ${origin.y} C ${origin.x + bend} ${origin.y}, ${target.x - bend} ${target.y}, ${target.x} ${target.y}`,
        coreDot: origin,
        segmentDot: target,
      });
    }
    setLinks(next);
  }, [selected]);

  useLayoutEffect(() => {
    measureLinks();
  }, [measureLinks]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(() => measureLinks());
    observer.observe(canvas);
    window.addEventListener("resize", measureLinks);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", measureLinks);
    };
  }, [measureLinks]);

  return (
    <div className="page">
      <PageHeader
        eyebrow="Operación / Topology"
        title="Dispositivos y segmentos"
        description="Topología declarativa de la red señuelo. Dystopia es la fuente de verdad; la analítica solo observa el resultado."
        actions={
          <>
            <button className="button ghost" onClick={() => {
              downloadJson("dystopia-topology.json", { segments: SEGMENTS, devices: DEVICES });
              notify("Topología exportada como JSON.", "success");
            }}><HardDrive size={15} /> Exportar topología</button>
            <button className="button primary" onClick={() => setEditOpen(true)}><Network size={15} /> Editar segmentos</button>
          </>
        }
        meta={
          <>
            <span><i className="status-dot live" /> {DEVICES.length} dispositivos</span>
            <span>{SEGMENTS.length} segmentos</span>
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
          <div className="topology-canvas" ref={canvasRef}>
            <svg className={`topology-links ${links.length ? "" : "hidden"}`} aria-hidden="true">
              {links.map((link) => (
                <g key={link.key} className={link.dimmed ? "dimmed" : ""}>
                  <path className="topology-link-base" d={link.path} style={{ stroke: link.color }} />
                  <path className="topology-link-flow" d={link.path} style={{ stroke: link.color }} />
                  <circle className="topology-link-dot" cx={link.segmentDot.x} cy={link.segmentDot.y} r={2.4} style={{ fill: link.color }} />
                </g>
              ))}
            </svg>
            <div className="topology-core">
              <span className="core-orbit" />
              <span className="core-orbit orbit-two" />
              <div className="core-node" ref={coreRef}>
                <span className="core-hex" aria-hidden="true" />
                <Shield size={21} />
                <strong>Dystopia Core</strong>
                <span className="mono">c1</span>
              </div>
            </div>
            <div className="topology-segments">
              {SEGMENTS.map((segment) => (
                <div
                  className={`segment-column ${selected !== "all" && selected !== segment.name ? "dimmed" : ""}`}
                  key={segment.name}
                  style={{ "--segment": segment.color, "--segment-soft": `${segment.color}24` } as CSSProperties}
                  ref={(node) => { if (node) segmentRefs.current.set(segment.name, node); }}
                >
                  <div className="segment-head">
                    <span className="segment-dot" style={{ background: segment.color }} />
                    <div><strong>{segment.name}</strong><span className="mono">{segment.cidr}</span></div>
                    <span className="exposure-chip" data-exposure={segment.exposure}>{segment.exposure}</span>
                    <span className="segment-count" style={{ color: segment.color, background: `${segment.color}1c` }}>{segment.devices}</span>
                  </div>
                  <div className="segment-devices">
                    {DEVICES.filter((device) => device.segment === segment.name).map((device) => {
                      const Icon = PROFILE_ICON[device.profile as keyof typeof PROFILE_ICON] ?? Boxes;
                      const color = profileColor(device.profile);
                      return (
                        <button
                          type="button"
                          className={`device-node ${deviceName === device.name ? "selected" : ""}`}
                          key={device.name}
                          onClick={() => setDeviceName(device.name)}
                        >
                          <span className="device-icon" style={{ color, background: `${color}14` }}><Icon size={16} /></span>
                          <div>
                            <strong>{device.name}</strong>
                            <span className="mono">{device.ip}</span>
                          </div>
                          <div className="device-node-side">
                            <span className="device-svc mono">{device.services} svc</span>
                            <span className={`device-status ${device.status}`} />
                          </div>
                        </button>
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
                <span className="segment-meta"><b>{segment.devices}</b><small data-exposure={segment.exposure}>{segment.exposure}</small></span>
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
                  const color = profileColor(device.profile);
                  return (
                    <tr key={device.name} onClick={() => setDeviceName(device.name)} className="clickable-row">
                      <td><span className="device-name"><Icon size={14} style={{ color }} />{device.name}</span></td>
                      <td><span className="profile-chip" style={{ color, borderColor: `${color}33`, background: `${color}12` }}><Icon size={10} />{PROFILE_LABEL[device.profile] ?? device.profile}</span></td>
                      <td><span className="sensor-chip">{device.segment}</span></td>
                      <td className="mono">{device.ip}</td>
                      <td><span className="svc-count mono">{device.services}</span></td>
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

        <Panel className="span-12" eyebrow="Distribución" title="Servicios por segmento" description="Servicios declarados agrupados por segmento de red.">
          <EChart
            option={horizontalBarOption(
              SEGMENTS.map((segment) => segment.name),
              SEGMENTS.map((segment) => DEVICES.filter((device) => device.segment === segment.name).reduce((sum, device) => sum + device.services, 0)),
              SEGMENTS.map((segment) => segment.color),
              " servicios",
            )}
            height={190}
          />
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

      <DeviceDrawer device={selectedDevice} onClose={() => setDeviceName(null)} />
      <ActionDialog
        open={editOpen}
        title="Topología declarativa"
        description="La edición real se hace en config/deception/network.yaml y requiere el gate de activación. Esta vista permite revisar y copiar el bloque actual."
        confirmLabel="Copiar YAML"
        cancelLabel="Cerrar"
        onConfirm={() => { navigator.clipboard?.writeText(topologyYaml); notify("Topología copiada al portapapeles.", "success"); setEditOpen(false); }}
        onClose={() => setEditOpen(false)}
      >
        <pre className="device-yaml">{topologyYaml}</pre>
      </ActionDialog>
    </div>
  );
}
