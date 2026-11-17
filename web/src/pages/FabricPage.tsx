import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Container,
  Power,
  RefreshCw,
  Rocket,
  Settings,
  ShieldCheck,
  TerminalSquare,
  Trash2,
  X,
} from "lucide-react";
import type { ECElementEvent, EChartsOption } from "echarts";
import { PageHeader } from "../components/PageHeader";
import { FabricConsole } from "../components/FabricConsole";
import { FabricConfigEditor } from "../components/FabricConfigEditor";
import { Portal } from "../components/Portal";
import { Panel } from "../components/Panel";
import { EChart } from "../components/EChart";
import { ActionDialog } from "../components/ActionDialog";
import { useToast } from "../components/Toast";
import { apiGet, apiPost, getRole } from "../lib/api";
import { formatDateTime } from "../lib/format";
import { ACCENTS, withAlpha } from "../lib/palette";
import { isLight } from "../lib/theme";

// ── Contrato de /api/fabric/* ───────────────────────────────

type FabricState = "disabled" | "ready" | "deploying" | "deployed" | "destroying" | "error";

interface FabricStatus {
  state: FabricState;
  enabled: boolean;
  gate_open: boolean;
  name: string | null;
  manifest_hash: string;
  error: string | null;
  warnings: string[];
  deployed_at: string | null;
  destroyed_at: string | null;
  switches: number;
  links: number;
  devices: number;
  forwarder: ForwarderStatus | null;
  health_summary: HealthSummary | null;
}

interface ForwarderStatus {
  enabled: boolean;
  pending: number;
  sent: number;
  failed: number;
  last_error: string | null;
}

interface HealthSummary {
  healthy: boolean;
  runtime_available: boolean;
}

interface HealthCheck {
  name: string;
  ok: boolean;
  detail: string;
}

interface DeviceHealth {
  device_id: string;
  healthy: boolean;
  runtime_available: boolean;
  container: { exists: boolean; running: boolean; pid: number; state: string };
  interfaces: Array<{
    name: string;
    host_veth?: string;
    switch: string;
    vlan_tag: number | null;
    port_present: boolean;
  }>;
  neighbors: Array<{ ip: string; reachable: boolean }>;
  checks: HealthCheck[];
}

interface FabricHealth {
  healthy: boolean;
  state: FabricState;
  runtime_available: boolean;
  checks: HealthCheck[];
  devices_health: DeviceHealth[];
  runtime?: {
    bridges?: { expected: string[]; present: string[]; missing: string[] };
    links?: { expected: string[]; present: string[]; missing: string[] };
    extra_ports?: string[];
  } | null;
}

interface FabricValidateReport {
  valid: boolean;
  state: FabricState;
  errors: string[];
  warnings: string[];
  manifest_hash: string;
}

interface GraphNode {
  id: string;
  label: string;
  kind: "switch" | "device";
  group: string;
  switch_id?: string;
  stp?: boolean;
  vlans?: number[];
  device_id?: string;
  container_name?: string;
  role?: string | null;
  segment?: string;
  switch?: string;
  vlan_tag?: number | null;
  ip?: string;
  mac?: string;
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: "trunk" | "access";
  label: string;
  state: "up" | "down";
  trunk?: boolean;
  bandwidth?: number | null;
  vlan_tag?: number | null;
  port?: string;
  /** Parámetros WAN declarados para el enlace (emulación tc netem). */
  wan?: {
    latency_ms?: number | null;
    jitter_ms?: number | null;
    loss_pct?: number | null;
    bandwidth_mbps?: number | null;
  } | null;
}

interface GraphGroup {
  id: string;
  label: string;
  vlan_id: number | null;
  segment: string | null;
}

interface FabricGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  groups: GraphGroup[];
  state: FabricState;
}

interface FabricService {
  port: number;
  proto: string;
  engine?: string;
  instance?: string | null;
  banner?: string | null;
}

interface ManifestDevice {
  id: string;
  role: string;
  segment: string;
  ip: string;
  persona?: { vendor?: string; os?: string; hostname?: string; mac?: string | null };
  services?: FabricService[];
}

interface OverrideInterface {
  name?: string;
  segment: string;
}

interface DeviceOverride {
  id: string;
  interfaces?: OverrideInterface[];
}

interface FabricSegment {
  id: string;
  vlan_id: number | null;
  cidr: string;
  gateway: string | null;
}

interface FabricTopology {
  config?: { name?: string; enabled?: boolean; device_overrides?: DeviceOverride[] };
  segments?: FabricSegment[];
  devices?: ManifestDevice[];
  switch_port_map?: Record<string, string[]>;
  device_switch_map?: Record<string, string>;
}

interface FabricInterfaceSpec {
  name: string;
  container_veth: string;
  host_veth: string;
  peer_veth: string;
  switch: string;
  vlan_tag: number | null;
  ip: string;
  mac: string;
  gateway: string | null;
}

interface FabricRouteSpec {
  destination: string;
  gateway: string;
}

interface FabricNeighborSpec {
  ip: string;
  mac: string;
  hostname: string;
}

interface FabricDeviceSpec {
  device_id: string;
  container_name: string;
  labels: Record<string, string>;
  image: string;
  mem_limit: string;
  cpus: number;
  interfaces: FabricInterfaceSpec[];
  routes: FabricRouteSpec[];
  neighbors: FabricNeighborSpec[];
  arp_entries: Array<{ ip: string; mac: string }>;
  runtime?: DeviceRuntimeDetail;
}

interface DeviceRuntimeDetail {
  state: string;
  container_id: string;
  last_health: string | null;
  error: string | null;
  healthy?: boolean;
  pid?: number;
  container_state?: string;
  interfaces?: Array<{
    name: string;
    host_veth?: string;
    switch: string;
    vlan_tag: number | null;
    port_present: boolean;
  }>;
  neighbors?: Array<{ ip: string; reachable: boolean }>;
  checks?: HealthCheck[];
}

interface FabricDeviceDetail extends FabricDeviceSpec {
  runtime: DeviceRuntimeDetail;
  role?: string | null;
  services?: FabricService[];
}

interface FabricEvent {
  id: number;
  timestamp: string;
  device_id: string;
  src_ip: string;
  src_port: number | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  proto: string;
  type: string;
  username: string | null;
  success: boolean;
  detail: Record<string, unknown>;
}

interface DeviceRow {
  spec: FabricDeviceSpec;
  manifest: ManifestDevice | undefined;
  iface: FabricInterfaceSpec | undefined;
  segmentId: string;
}

type ActionKind = "deploy" | "destroy" | "rebuild";

// ── Presentación ────────────────────────────────────────────

const STATE_META: Record<FabricState, { label: string; color: string; hint: string }> = {
  disabled: { label: "Deshabilitado", color: ACCENTS.slate, hint: "fabric.enabled = false" },
  ready: { label: "Listo", color: ACCENTS.blue, hint: "Manifiesto validado" },
  deploying: { label: "Desplegando", color: ACCENTS.amber, hint: "Operación en curso" },
  deployed: { label: "Desplegado", color: ACCENTS.green, hint: "Topología activa" },
  destroying: { label: "Destruyendo", color: ACCENTS.amber, hint: "Operación en curso" },
  error: { label: "Error", color: ACCENTS.red, hint: "Revisa el informe de validación" },
};

const RUNTIME_META: Record<string, { label: string; color: string }> = {
  running: { label: "running", color: ACCENTS.green },
  stopped: { label: "stopped", color: ACCENTS.slate },
  error: { label: "error", color: ACCENTS.red },
  pending: { label: "pending", color: ACCENTS.amber },
};

const GROUP_COLORS = [
  ACCENTS.cyan,
  ACCENTS.blue,
  ACCENTS.amber,
  ACCENTS.violet,
  ACCENTS.pink,
  ACCENTS.green,
];

const ACTION_COPY: Record<ActionKind, { title: string; description: string; confirmLabel: string }> = {
  deploy: {
    title: "Desplegar fabric",
    description:
      "Se crearán bridges OVS, enlaces y contenedores según la topología validada. "
      + "La operación es idempotente: si ya hay un despliegue, se destruye primero.",
    confirmLabel: "Desplegar",
  },
  destroy: {
    title: "Destruir fabric",
    description:
      "Se detendrán los contenedores y se eliminarán los bridges y enlaces del fabric. "
      + "El manifiesto network.yaml no se modifica.",
    confirmLabel: "Destruir",
  },
  rebuild: {
    title: "Reconstruir fabric",
    description:
      "Alias destroy+deploy: se desmonta la topología actual y se vuelve a crear "
      + "desde el mismo manifiesto validado.",
    confirmLabel: "Reconstruir",
  },
};

function shortHash(hash?: string | null): string {
  return hash ? `${hash.slice(0, 10)}…` : "—";
}

function StatePill({ state }: { state: FabricState }) {
  const meta = STATE_META[state];
  return (
    <span className="health-pill" style={{ color: meta.color, background: withAlpha(meta.color, 0.12) }}>
      <i />
      {meta.label}
    </span>
  );
}

type GraphLayout = "force" | "hierarchical";

function buildGraphOption(
  graph: FabricGraph,
  runtimeByDevice: Map<string, string>,
  deployed: boolean,
  layout: GraphLayout = "force",
): EChartsOption {
  const groupIndex = new Map(graph.groups.map((group, index) => [group.id, index + 1]));
  const categories = [
    { name: "Switches", itemStyle: { color: ACCENTS.slate } },
    ...graph.groups.map((group, index) => ({
      name: group.label,
      itemStyle: { color: GROUP_COLORS[index % GROUP_COLORS.length] },
    })),
  ];
  const ink = isLight() ? "#3d4f60" : "#c9d6e4";

  // Layout jerárquico: switches en la fila superior, dispositivos colgando
  // de su switch. ECharts encaja el bounding box de coordenadas en el panel
  // escalando X e Y por separado, así que el espacio de coordenadas es fijo
  // (no depende del nº de dispositivos) y mantiene el aspecto del panel
  // (~1.9) para que los símbolos no salgan deformados.
  const positions = new Map<string, { x: number; y: number }>();
  if (layout === "hierarchical") {
    const switches = graph.nodes.filter((node) => node.kind === "switch");
    const devices = graph.nodes.filter((node) => node.kind === "device");
    const bySwitch = new Map<string, string[]>();
    devices.forEach((device) => {
      const swKey = `switch:${device.switch ?? "—"}`;
      const list = bySwitch.get(swKey) ?? [];
      list.push(device.id);
      bySwitch.set(swKey, list);
    });
    const maxDevices = Math.max(1, ...[...bySwitch.values()].map((ids) => ids.length));
    const xSpan = 1420; // ~2.03 * 700, el aspecto del área de dibujo
    const yBase = 100;
    const ySpan = 700;
    const stepX = switches.length > 1 ? xSpan / (switches.length - 1) : 0;
    const switchX = new Map<string, number>();
    switches.forEach((node, index) => {
      const x = index * stepX;
      switchX.set(node.id, x);
      positions.set(node.id, { x, y: yBase });
    });
    bySwitch.forEach((ids, swKey) => {
      const anchorX = switchX.get(swKey);
      ids.forEach((id, index) => {
        positions.set(id, {
          x: anchorX ?? index * stepX,
          // Reparte los dispositivos entre yBase+ySpan/maxDevices y yBase+ySpan
          // (con 1 dispositivo queda al fondo, manteniendo el aspecto).
          y: yBase + ((index + 1) * ySpan) / maxDevices,
        });
      });
    });
  }

  const spanX = Math.max(...[...positions.values()].map((pos) => pos.x), 1);

  return {
    animationDuration: 450,
    tooltip: {
      trigger: "item",
      renderMode: "richText",
      backgroundColor: isLight() ? "#ffffff" : "#232322",
      borderColor: isLight() ? "rgba(0, 0, 0, 0.18)" : "rgba(255, 255, 255, 0.18)",
      textStyle: { color: isLight() ? "#333333" : "#f2f0ec", fontSize: 12 },
      formatter: (params: unknown) => {
        const item = params as { dataIndex?: number; dataType?: string; name?: string };
        if (item.dataType === "edge") return item.name ?? "Enlace";
        const node = typeof item.dataIndex === "number" ? graph.nodes[item.dataIndex] : undefined;
        if (!node) return item.name ?? "";
        if (node.kind === "switch") {
          const vlans = (node.vlans ?? []).join(", ") || "—";
          return `Switch ${node.label}\nVLANs troncales: ${vlans}\nSTP: ${node.stp ? "on" : "off"}`;
        }
        const runtime = node.device_id ? runtimeByDevice.get(node.device_id) : undefined;
        return [
          `Dispositivo ${node.label}`,
          `IP ${node.ip ?? "—"} · VLAN ${node.vlan_tag ?? "sin etiqueta"}`,
          `Switch ${node.switch ?? "—"} · Segmento ${node.segment ?? "—"}`,
          `Runtime: ${runtime ?? "sin datos"}`,
        ].join("\n");
      },
    },
    legend: [{
      data: categories.map((category) => category.name),
      bottom: 0,
      icon: "circle",
      itemWidth: 8,
      itemHeight: 8,
      textStyle: { color: ink, fontSize: 11 },
    }],
    series: [{
      type: "graph",
      layout: layout === "hierarchical" ? "none" : "force",
      roam: true,
      draggable: layout === "force",
      ...(layout === "force"
        ? { force: { repulsion: 280, edgeLength: [85, 160], gravity: 0.08 } }
        : { left: 34, right: 34, top: 46, bottom: 48 }),
      categories,
      data: graph.nodes.map((node) => {
        const runtime = node.device_id ? runtimeByDevice.get(node.device_id) : undefined;
        const running = deployed && runtime === "running";
        const pos = positions.get(node.id);
        // Los nodos del borde derecho llevan la etiqueta a la izquierda para
        // que no se corte contra el borde del panel.
        const nearRight = (pos?.x ?? 0) > spanX * 0.72;
        return {
          id: node.id,
          name: node.label,
          value: node.kind === "device" ? node.ip ?? "" : node.switch_id ?? "",
          category: node.kind === "switch" ? 0 : groupIndex.get(node.group) ?? 1,
          ...(pos ? { x: pos.x, y: pos.y, fixed: true } : {}),
          symbol: node.kind === "switch" ? "roundRect" : "circle",
          symbolSize: node.kind === "switch" ? 46 : 32,
          itemStyle: node.kind === "switch"
            ? { color: ACCENTS.slate, borderColor: withAlpha(ACCENTS.slate, 0.7), borderWidth: 1 }
            : {
                borderColor: running ? ACCENTS.green : withAlpha(ink, 0.35),
                borderWidth: running ? 2.5 : 1,
                shadowBlur: running ? 10 : 0,
                shadowColor: running ? withAlpha(ACCENTS.green, 0.6) : "transparent",
              },
          label: {
            show: true,
            position: node.kind === "switch" ? "top" : nearRight ? "left" : "right",
            color: ink,
            fontSize: 10.5,
            backgroundColor: isLight() ? "rgba(247, 245, 240, 0.88)" : "rgba(30, 30, 29, 0.88)",
            borderRadius: 3,
            padding: [1, 3],
          },
        };
      }),
      links: graph.edges.map((edge) => {
        const wanParts: string[] = [];
        if (edge.wan) {
          if (edge.wan.latency_ms) wanParts.push(`${edge.wan.latency_ms}ms`);
          if (edge.wan.loss_pct) wanParts.push(`${edge.wan.loss_pct}% loss`);
          if (edge.wan.bandwidth_mbps) wanParts.push(`${edge.wan.bandwidth_mbps}Mbps`);
        }
        return {
          ...edge,
          label: {
            show: wanParts.length > 0,
            formatter: wanParts.join(" · "),
            fontSize: 10,
            color: ink,
          },
        };
      }),
      edgeLabel: {
        show: true,
        fontSize: 10,
        color: ink,
      },
      edgeSymbol: ["none", "none"],
      emphasis: { focus: "adjacency", lineStyle: { width: 3 } },
      lineStyle: { opacity: 0.85 },
    }],
  };
}

// ── Drawer de dispositivo ───────────────────────────────────

function FabricDeviceDrawer({
  row,
  onClose,
  onOpenConsole,
}: {
  row: DeviceRow;
  onClose: () => void;
  onOpenConsole: (deviceId: string) => void;
}) {
  const canAdmin = getRole() === "admin";
  const { spec, manifest, iface, segmentId } = row;
  const [detail, setDetail] = useState<FabricDeviceDetail | null>(null);
  const [events, setEvents] = useState<FabricEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const deviceId = spec.device_id;

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    Promise.all([
      apiGet<FabricDeviceDetail>(`/api/fabric/devices/${encodeURIComponent(deviceId)}`),
      apiGet<FabricEvent[]>(`/api/fabric/events?device_id=${encodeURIComponent(deviceId)}&limit=10`),
    ])
      .then(([nextDetail, nextEvents]) => {
        if (cancelled) return;
        setDetail(nextDetail);
        setEvents(nextEvents);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "No se pudo cargar el dispositivo");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [deviceId]);

  const runtime = detail?.runtime ?? null;
  const services = detail?.services ?? manifest?.services ?? [];
  const vlan = iface?.vlan_tag;
  const runtimeMeta = RUNTIME_META[runtime?.state ?? "pending"] ?? RUNTIME_META.pending;

  return (
    <Portal>
      <div className="drawer-backdrop" onClick={onClose}>
        <aside className="event-drawer config-drawer" onClick={(event) => event.stopPropagation()}>
          <div className="drawer-head">
          <div>
            <span className="eyebrow">Fabric / device</span>
            <h2>{spec.device_id}</h2>
            <span className="mono muted">{iface?.ip ?? "sin IP"}</span>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            {canAdmin && (
              <button
                className="button ghost"
                onClick={() => onOpenConsole(spec.device_id)}
                disabled={runtime?.state !== "running"}
                title={
                  runtime?.state === "running"
                    ? "Abrir terminal interactivo hacia el contenedor"
                    : "La consola requiere el dispositivo desplegado y en ejecución"
                }
              >
                <TerminalSquare size={15} /> Terminal
              </button>
            )}
            <button className="icon-button" onClick={onClose} aria-label="Cerrar dispositivo">
              <X size={18} />
            </button>
          </div>
        </div>

        <div className="drawer-badges">
          <span className="proto-chip">{detail?.role ?? manifest?.role ?? "device"}</span>
          <span className="sensor-chip">{segmentId || "sin segmento"}</span>
          <span className="health-pill"><i />{vlan === null || vlan === undefined ? "sin etiqueta" : `VLAN ${vlan}`}</span>
          <span className="health-pill" style={{ color: runtimeMeta.color, background: withAlpha(runtimeMeta.color, 0.12) }}>
            <i />{runtimeMeta.label}
          </span>
        </div>

        {loading && (
          <div className="empty-state small">
            <RefreshCw size={18} />
            <strong>Cargando dispositivo</strong>
            <span>Leyendo runtime y últimos eventos.</span>
          </div>
        )}
        {error && (
          <div className="segment-note">
            <AlertTriangle size={15} />
            <p>{error}</p>
          </div>
        )}

        <div className="honeypot-config-grid">
          <div><span>IP</span><strong className="mono">{iface?.ip ?? "—"}</strong></div>
          <div><span>MAC</span><strong className="mono">{iface?.mac ?? "—"}</strong></div>
          <div><span>Switch</span><strong className="mono">{iface?.switch ?? "—"}</strong></div>
          <div><span>VLAN</span><strong className="mono">{vlan ?? "sin etiqueta"}</strong></div>
          <div><span>Segmento</span><strong>{segmentId || "—"}</strong></div>
          <div><span>Gateway</span><strong className="mono">{iface?.gateway ?? "—"}</strong></div>
          <div><span>Contenedor</span><strong className="mono">{spec.container_name}</strong></div>
          <div><span>Recursos</span><strong>{spec.cpus} CPU · {spec.mem_limit}</strong></div>
          <div><span>Estado runtime</span><strong>{runtimeMeta.label}</strong></div>
          <div><span>PID</span><strong className="mono">{runtime?.pid ?? "—"}</strong></div>
          <div><span>Estado contenedor</span><strong>{runtime?.container_state ?? "—"}</strong></div>
          <div><span>Salud</span><strong>{runtime?.healthy === undefined ? "—" : runtime.healthy ? "sano" : "con errores"}</strong></div>
        </div>

        {runtime?.error && (
          <div className="segment-note">
            <AlertTriangle size={15} />
            <p>{runtime.error}</p>
          </div>
        )}

        <section className="config-block">
          <span className="eyebrow">Servicios declarados</span>
          <div className="service-chip-list">
            {services.length === 0 && <span className="muted">Sin servicios declarados.</span>}
            {services.map((service) => (
              <span className="proto-chip" key={`${service.proto}-${service.port}`}>
                {service.proto}/{service.port}{service.engine ? ` · ${service.engine}` : ""}
              </span>
            ))}
          </div>
        </section>

        {runtime?.interfaces && runtime.interfaces.length > 0 && (
          <section className="config-block">
            <span className="eyebrow">Interfaces (runtime)</span>
            <div className="service-chip-list">
              {runtime.interfaces.map((item) => (
                <span
                  className="proto-chip"
                  key={item.name}
                  style={{
                    color: item.port_present ? ACCENTS.green : ACCENTS.red,
                    borderColor: withAlpha(item.port_present ? ACCENTS.green : ACCENTS.red, 0.45),
                  }}
                >
                  {item.name} · {item.switch} · VLAN {item.vlan_tag ?? "—"} · {item.port_present ? "puerto OK" : "puerto ausente"}
                </span>
              ))}
            </div>
          </section>
        )}

        {runtime?.neighbors && runtime.neighbors.length > 0 && (
          <section className="config-block">
            <span className="eyebrow">Conectividad (ping)</span>
            <div className="service-chip-list">
              {runtime.neighbors.map((neighbor) => (
                <span
                  className="proto-chip"
                  key={neighbor.ip}
                  style={{
                    color: neighbor.reachable ? ACCENTS.green : ACCENTS.red,
                    borderColor: withAlpha(neighbor.reachable ? ACCENTS.green : ACCENTS.red, 0.45),
                  }}
                >
                  {neighbor.ip} · {neighbor.reachable ? "reachable" : "sin respuesta"}
                </span>
              ))}
            </div>
          </section>
        )}

        <section className="config-block">
          <span className="eyebrow">Últimos eventos</span>
          {events.length === 0 ? (
            <div className="empty-state small">
              <AlertTriangle size={18} />
              <strong>Sin eventos</strong>
              <span>El agente aún no ha registrado interacciones.</span>
            </div>
          ) : (
            <div className="service-chip-list" style={{ flexDirection: "column", alignItems: "stretch" }}>
              {events.map((event) => (
                <div
                  key={event.id}
                  style={{
                    display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center",
                    justifyContent: "space-between", padding: "6px 8px",
                    border: "1px solid var(--line)", borderRadius: 3,
                  }}
                >
                  <span className="mono" style={{ fontSize: 11 }}>{formatDateTime(event.timestamp)}</span>
                  <span className="proto-chip">{event.type}</span>
                  <span className="mono" style={{ fontSize: 11 }}>
                    {event.src_ip}{event.src_port ? `:${event.src_port}` : ""}
                  </span>
                  <span className="muted" style={{ fontSize: 11 }}>
                    {event.proto}{event.username ? ` · ${event.username}` : ""}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>

        {spec.routes.length > 0 && (
          <section className="config-block">
            <span className="eyebrow">Rutas estáticas</span>
            <pre className="device-yaml">
              {spec.routes.map((route) => `${route.destination} via ${route.gateway}`).join("\n")}
            </pre>
          </section>
        )}

        {spec.neighbors.length > 0 && (
          <section className="config-block">
            <span className="eyebrow">Vecinos / ARP estático</span>
            <pre className="device-yaml">
              {spec.neighbors.map((neighbor) => `${neighbor.ip} → ${neighbor.mac}${neighbor.hostname ? ` (${neighbor.hostname})` : ""}`).join("\n")}
            </pre>
          </section>
        )}

        <div className="config-footnote">
          <ShieldCheck size={13} /> Las credenciales del manifiesto nunca llegan al dashboard.
          {" "}Imagen <code>{spec.image}</code>.
        </div>
        </aside>
      </div>
    </Portal>
  );
}

// ── Página ──────────────────────────────────────────────────

export function FabricPage() {
  const { notify } = useToast();
  const canAdmin = getRole() === "admin";
  const [layout, setLayout] = useState<GraphLayout>("force");
  const [consoleDevice, setConsoleDevice] = useState<string | null>(null);
  const [configOpen, setConfigOpen] = useState(false);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<FabricStatus | null>(null);
  const [topology, setTopology] = useState<FabricTopology>({});
  const [graph, setGraph] = useState<FabricGraph>({ nodes: [], edges: [], groups: [], state: "disabled" });
  const [specs, setSpecs] = useState<FabricDeviceSpec[]>([]);
  const [health, setHealth] = useState<FabricHealth | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<string | null>(null);
  const [report, setReport] = useState<FabricValidateReport | null>(null);
  const [validating, setValidating] = useState(false);
  const [pending, setPending] = useState<ActionKind | null>(null);
  const [busy, setBusy] = useState<ActionKind | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [nextStatus, nextTopology, nextGraph, nextSpecs, nextHealth] = await Promise.all([
        apiGet<FabricStatus>("/api/fabric/status"),
        apiGet<FabricTopology>("/api/fabric/topology"),
        apiGet<FabricGraph>("/api/fabric/topology/graph"),
        apiGet<FabricDeviceSpec[]>("/api/fabric/devices"),
        apiGet<FabricHealth>("/api/fabric/health"),
      ]);
      setStatus(nextStatus);
      setTopology(nextTopology ?? {});
      setGraph(nextGraph);
      setSpecs(nextSpecs ?? []);
      setHealth(nextHealth);
    } catch (err) {
      setError(err instanceof Error ? err.message : "No se pudo cargar el fabric");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const manifestById = useMemo(
    () => new Map((topology.devices ?? []).map((device) => [device.id, device])),
    [topology.devices],
  );
  const overrideById = useMemo(
    () => new Map((topology.config?.device_overrides ?? []).map((override) => [override.id, override])),
    [topology.config?.device_overrides],
  );

  const rows = useMemo<DeviceRow[]>(() => specs.map((spec) => {
    const manifest = manifestById.get(spec.device_id);
    const iface = spec.interfaces[0];
    const override = overrideById.get(spec.device_id);
    return {
      spec,
      manifest,
      iface,
      segmentId: override?.interfaces?.[0]?.segment ?? manifest?.segment ?? "",
    };
  }), [specs, manifestById, overrideById]);

  const selectedRow = rows.find((row) => row.spec.device_id === selectedDevice) ?? null;
  const state = status?.state ?? "disabled";
  const meta = STATE_META[state];
  const runtimeByDevice = useMemo(
    () => new Map(specs.map((spec) => [spec.device_id, spec.runtime?.state ?? "pending"])),
    [specs],
  );
  const graphOption = buildGraphOption(graph, runtimeByDevice, state === "deployed", layout);

  function handleGraphClick(params: ECElementEvent) {
    if (params.dataType !== "node") return;
    const node = graph.nodes[params.dataIndex];
    if (node?.kind === "device" && node.device_id) setSelectedDevice(node.device_id);
  }

  async function runValidate() {
    setValidating(true);
    try {
      const next = await apiPost<FabricValidateReport>("/api/fabric/validate");
      setReport(next);
      if (next.valid) {
        notify("Manifiesto válido: la topología puede desplegarse.", "success");
      } else {
        notify("El manifiesto tiene errores; revisa el informe.", "error");
      }
      await load();
    } catch (err) {
      notify(err instanceof Error ? err.message : "No se pudo validar el manifiesto", "error");
    } finally {
      setValidating(false);
    }
  }

  async function confirmAction() {
    const kind = pending;
    if (!kind || busy) return;
    setPending(null);
    setBusy(kind);
    try {
      await apiPost<{ success: boolean; state: FabricState }>(`/api/fabric/${kind}`);
      notify(`${ACTION_COPY[kind].title} completado.`, "success");
    } catch (err) {
      notify(err instanceof Error ? err.message : "La operación no se pudo completar", "error");
    } finally {
      setBusy(null);
      await load();
    }
  }

  const actionsDisabled = busy !== null || validating;

  return (
    <div className="page">
      <PageHeader
        eyebrow="Operación / Fabric"
        title="Network Fabric"
        description="Red virtual del manifiesto: switches OVS, enlaces, VLANs y dispositivos con sus servicios. El despliegue real vive detrás del motor y del doble gate."
        actions={
          <>
            <button className="button ghost" onClick={() => void load()} disabled={loading}>
              <RefreshCw size={15} className={loading ? "spinning" : ""} /> Actualizar
            </button>
            {canAdmin ? (
              <>
                <button className="button ghost" onClick={() => void runValidate()} disabled={actionsDisabled}>
                  <ShieldCheck size={15} /> {validating ? "Validando…" : "Validate"}
                </button>
                <button className="button ghost" onClick={() => setConfigOpen(true)}>
                  <Settings size={15} /> Editar manifiesto
                </button>                <button
                  className={`button primary ${busy === "deploy" ? "spinning" : ""}`}
                  onClick={() => setPending("deploy")}
                  disabled={actionsDisabled || state !== "ready" || !status?.gate_open}
                  title={state === "ready" ? "Desplegar el fabric" : "Deploy solo está disponible en estado ready"}
                >
                  <Rocket size={15} /> Deploy
                </button>
                <button
                  className={`button ghost ${busy === "rebuild" ? "spinning" : ""}`}
                  onClick={() => setPending("rebuild")}
                  disabled={actionsDisabled || (state !== "deployed" && state !== "ready") || !status?.gate_open}
                  title="Destruir y volver a desplegar"
                >
                  <RefreshCw size={15} /> Rebuild
                </button>
                <button
                  className={`button danger ${busy === "destroy" ? "spinning" : ""}`}
                  onClick={() => setPending("destroy")}
                  disabled={actionsDisabled || state !== "deployed"}
                  title={state === "deployed" ? "Destruir el fabric" : "Destroy solo está disponible en estado deployed"}
                >
                  <Trash2 size={15} /> Destroy
                </button>
              </>
            ) : (
              <span className="muted" style={{ fontSize: 12 }}>
                Los controles de ciclo de vida requieren rol admin.
              </span>
            )}
          </>
        }
        meta={
          <>
            <StatePill state={state} />
            <span><i className={`status-dot ${status?.gate_open ? "live" : "missing"}`} /> Gate {status?.gate_open ? "abierto" : "cerrado"}</span>
            <span>{status?.switches ?? 0} switches</span>
            <span>{status?.devices ?? 0} dispositivos</span>
            <span className="mono">{shortHash(status?.manifest_hash)}</span>
          </>
        }
      />

      {loading && !status ? (
        <Panel>
          <div className="empty-state">
            <RefreshCw size={20} />
            <strong>Cargando fabric</strong>
            <span>Leyendo estado, topología y plan de despliegue.</span>
          </div>
        </Panel>
      ) : error && !status ? (
        <Panel>
          <div className="empty-state">
            <AlertTriangle size={20} />
            <strong>No se pudo cargar el fabric</strong>
            <span>{error}</span>
            <button className="button ghost" onClick={() => void load()}>Reintentar</button>
          </div>
        </Panel>
      ) : (
        <>
          {error && (
            <div className="segment-note">
              <AlertTriangle size={15} />
              <p>{error}</p>
            </div>
          )}

          <div className="dashboard-grid">
            <Panel
              className="span-8"
              eyebrow="Topología"
              title="Red virtual"
              description="Troncales entre switches y accesos por VLAN. Haz clic en un dispositivo para ver su detalle."
              actions={
                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <span className="mono muted">{meta.hint}</span>
                  <button
                    className={`button ghost ${layout === "force" ? "active" : ""}`}
                    onClick={() => setLayout("force")}
                    title="Layout de fuerza (grafo libre)"
                  >
                    Fuerza
                  </button>
                  <button
                    className={`button ghost ${layout === "hierarchical" ? "active" : ""}`}
                    onClick={() => setLayout("hierarchical")}
                    title="Layout jerárquico: switches arriba, dispositivos debajo"
                  >
                    Jerárquico
                  </button>
                </div>
              }
              flush
            >
              {state === "disabled" || graph.nodes.length === 0 ? (
                <div className="empty-state">
                  <Power size={20} />
                  <strong>{state === "disabled" ? "Fabric deshabilitado" : "Sin topología válida"}</strong>
                  <span>
                    {state === "disabled"
                      ? "Activa fabric.enabled: true en network.yaml y exporta DYSTOPIA_FABRIC_ENABLED=true en el host."
                      : "Corrige el manifiesto y ejecuta Validate para reconstruir la topología."}
                  </span>
                </div>
              ) : (
                <EChart option={graphOption} height={430} onElementClick={handleGraphClick} />
              )}
            </Panel>

            <Panel
              className="span-4"
              eyebrow="State machine"
              title="Estado del fabric"
              actions={<StatePill state={state} />}
            >
              <div className="honeypot-config-grid">
                <div><span>Switches</span><strong>{status?.switches ?? 0}</strong></div>
                <div><span>Dispositivos</span><strong>{status?.devices ?? 0}</strong></div>
                <div><span>Enlaces</span><strong>{status?.links ?? 0}</strong></div>
                <div><span>Gate de activación</span><strong>{status?.gate_open ? "abierto" : "cerrado"}</strong></div>
                <div><span>Último deploy</span><strong>{status?.deployed_at ? formatDateTime(status.deployed_at) : "—"}</strong></div>
                <div><span>Último destroy</span><strong>{status?.destroyed_at ? formatDateTime(status.destroyed_at) : "—"}</strong></div>
                <div style={{ gridColumn: "1 / -1" }}>
                  <span>Manifiesto</span>
                  <strong className="mono" title={status?.manifest_hash}>{status?.name ?? "sin nombre"} · {shortHash(status?.manifest_hash)}</strong>
                </div>
              </div>

              {status && !status.gate_open && (
                <div className="segment-note">
                  <AlertTriangle size={15} />
                  <p>El deploy está bloqueado: exporta <code>DYSTOPIA_FABRIC_ENABLED=true</code> en el host.</p>
                </div>
              )}
              {status?.error && (
                <div className="segment-note">
                  <AlertTriangle size={15} />
                  <p>{status.error}</p>
                </div>
              )}
              {status?.warnings?.length ? (
                <div className="segment-note">
                  <AlertTriangle size={15} />
                  <p>{status.warnings.join(" · ")}</p>
                </div>
              ) : null}
            </Panel>
          </div>

          <Panel
            className="span-12"
            eyebrow="Salud"
            title="Runtime y forwarder"
            description="Chequeos del host (bridges, enlaces y dispositivos) y estado del forwarder de eventos."
            actions={
              <span
                className="health-pill"
                style={{
                  color: health?.healthy ? ACCENTS.green : ACCENTS.red,
                  background: withAlpha(health?.healthy ? ACCENTS.green : ACCENTS.red, 0.12),
                }}
              >
                <i />{health ? (health.healthy ? "sano" : "con errores") : "sin datos"}
              </span>
            }
          >
            {!health ? (
              <div className="empty-state small">
                <AlertTriangle size={18} />
                <strong>Sin datos de salud</strong>
                <span>El control no pudo consultar el runtime del fabric.</span>
              </div>
            ) : (
              <>
                <div className="honeypot-config-grid">
                  <div><span>Runtime</span><strong>{health.runtime_available ? "disponible" : "no disponible"}</strong></div>
                  <div><span>Checks</span><strong>{health.checks.filter((check) => check.ok).length}/{health.checks.length} OK</strong></div>
                  <div><span>Bridges</span><strong>{health.runtime?.bridges ? `${health.runtime.bridges.present.length}/${health.runtime.bridges.expected.length}` : "—"}</strong></div>
                  <div><span>Enlaces</span><strong>{health.runtime?.links ? `${health.runtime.links.present.length}/${health.runtime.links.expected.length}` : "—"}</strong></div>
                  <div><span>Forwarder</span><strong>{status?.forwarder ? (status.forwarder.enabled ? "activo" : "desactivado") : "sin datos"}</strong></div>
                  <div><span>Eventos enviados</span><strong>{status?.forwarder?.sent ?? "—"}</strong></div>
                  <div><span>Pendientes</span><strong>{status?.forwarder?.pending ?? "—"}</strong></div>
                  <div><span>Fallidos</span><strong>{status?.forwarder?.failed ?? "—"}</strong></div>
                </div>

                <div className="config-block">
                  <span className="eyebrow">Checks</span>
                  <div className="service-chip-list">
                    {health.checks.map((check) => (
                      <span
                        key={check.name}
                        className="proto-chip"
                        title={check.detail}
                        style={{
                          color: check.ok ? ACCENTS.green : ACCENTS.red,
                          borderColor: withAlpha(check.ok ? ACCENTS.green : ACCENTS.red, 0.45),
                        }}
                      >
                        {check.name}: {check.ok ? "ok" : "falla"}
                      </span>
                    ))}
                  </div>
                </div>

                {status?.forwarder?.last_error && (
                  <div className="segment-note">
                    <AlertTriangle size={15} />
                    <p>Forwarder: {status.forwarder.last_error}</p>
                  </div>
                )}
                {status?.forwarder && !status.forwarder.enabled && (
                  <div className="segment-note">
                    <AlertTriangle size={15} />
                    <p>Forwarder desactivado: exporta <code>DYSTOPIA_FABRIC_EVENTS_ENABLED=true</code> en el host.</p>
                  </div>
                )}
              </>
            )}
          </Panel>

          {report && (
            <Panel
              className="span-12"
              eyebrow="Validación"
              title={report.valid ? "Manifiesto válido" : "Manifiesto con errores"}
              description={`Estado tras validar: ${report.state} · hash ${shortHash(report.manifest_hash)}`}
              actions={<button className="icon-button" onClick={() => setReport(null)} aria-label="Cerrar informe"><X size={16} /></button>}
            >
              {report.errors.length > 0 && (
                <div className="config-block" style={{ marginTop: 0, paddingTop: 0, borderTop: "none" }}>
                  <span className="eyebrow">Errores</span>
                  <pre className="device-yaml">{report.errors.map((item) => `✗ ${item}`).join("\n")}</pre>
                </div>
              )}
              {report.warnings.length > 0 && (
                <div className="config-block">
                  <span className="eyebrow">Warnings</span>
                  <pre className="device-yaml">{report.warnings.map((item) => `! ${item}`).join("\n")}</pre>
                </div>
              )}
              {report.valid && report.warnings.length === 0 && (
                <div className="empty-state small">
                  <CheckCircle2 size={20} />
                  <strong>Sin errores ni warnings</strong>
                  <span>El manifiesto cumple el esquema y las referencias cruzadas.</span>
                </div>
              )}
            </Panel>
          )}

          <Panel
            className="span-12"
            eyebrow="Inventario"
            title="Dispositivos del fabric"
            description="Solo los dispositivos con interfaces declaradas participan en el fabric runtime."
            flush
          >
            {rows.length === 0 ? (
              <div className="empty-state">
                <Container size={20} />
                <strong>Sin dispositivos desplegables</strong>
                <span>Añade device_overrides con interfaces para planificar contenedores.</span>
              </div>
            ) : (
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Dispositivo</th>
                      <th>IP</th>
                      <th>MAC</th>
                      <th>Switch</th>
                      <th>VLAN</th>
                      <th>Contenedor</th>
                      <th>Conectividad</th>
                      <th>Servicios</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => {
                      const services = row.manifest?.services ?? [];
                      const visible = services.slice(0, 2);
                      const extra = services.length - visible.length;
                      return (
                        <tr
                          key={row.spec.device_id}
                          className="clickable-row"
                          onClick={() => setSelectedDevice(row.spec.device_id)}
                        >
                          <td>
                            <strong>{row.spec.device_id}</strong>
                            <br />
                            <span className="mono muted">{row.manifest?.role ?? row.spec.container_name}</span>
                          </td>
                          <td className="mono">{row.iface?.ip ?? "—"}</td>
                          <td className="mono">{row.iface?.mac ?? "—"}</td>
                          <td><span className="sensor-chip">{row.iface?.switch ?? "—"}</span></td>
                          <td className="mono">
                            {row.iface?.vlan_tag ?? "sin etiqueta"}
                            <br />
                            <span className="muted">{row.segmentId || "—"}</span>
                          </td>
                          <td>
                            {(() => {
                              const runtime = row.spec.runtime?.state ?? "pending";
                              const runtimeMeta = RUNTIME_META[runtime] ?? RUNTIME_META.pending;
                              return (
                                <span className="health-pill" style={{ color: runtimeMeta.color, background: withAlpha(runtimeMeta.color, 0.12) }}>
                                  <i />{runtimeMeta.label}
                                </span>
                              );
                            })()}
                          </td>
                          <td>
                            {(() => {
                              const deviceHealth = health?.devices_health.find(
                                (item) => item.device_id === row.spec.device_id,
                              );
                              if (!deviceHealth) return <span className="muted">—</span>;
                              const neighbors = deviceHealth.neighbors ?? [];
                              if (neighbors.length === 0) return <span className="muted">sin vecinos</span>;
                              const reachable = neighbors.filter((neighbor) => neighbor.reachable).length;
                              const allOk = reachable === neighbors.length;
                              const color = allOk ? ACCENTS.green : (reachable === 0 ? ACCENTS.red : ACCENTS.amber);
                              return (
                                <span className="health-pill" style={{ color, background: withAlpha(color, 0.12) }}>
                                  <i />{reachable}/{neighbors.length} vecinos
                                </span>
                              );
                            })()}
                          </td>
                          <td>
                            {services.length === 0 ? (
                              <span className="muted">—</span>
                            ) : (
                              <span className="service-chip-list">
                                {visible.map((service) => (
                                  <span className="proto-chip" key={`${row.spec.device_id}-${service.proto}-${service.port}`}>
                                    {service.proto}/{service.port}
                                  </span>
                                ))}
                                {extra > 0 && <span className="proto-chip">+{extra}</span>}
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </>
      )}

      <ActionDialog
        open={pending !== null}
        title={pending ? ACTION_COPY[pending].title : ""}
        description={pending ? ACTION_COPY[pending].description : undefined}
        confirmLabel={pending ? ACTION_COPY[pending].confirmLabel : "Confirmar"}
        tone={pending === "destroy" ? "danger" : "primary"}
        onConfirm={() => void confirmAction()}
        onClose={() => setPending(null)}
      >
        <div className="honeypot-config-grid">
          <div><span>Estado actual</span><strong>{STATE_META[state].label}</strong></div>
          <div><span>Switches</span><strong>{status?.switches ?? 0}</strong></div>
          <div><span>Dispositivos</span><strong>{status?.devices ?? 0}</strong></div>
          <div><span>Enlaces</span><strong>{status?.links ?? 0}</strong></div>
        </div>
      </ActionDialog>

      {consoleDevice && <FabricConsole deviceId={consoleDevice} onClose={() => setConsoleDevice(null)} />}
      {configOpen && (
        <FabricConfigEditor
          onClose={() => setConfigOpen(false)}
          onSaved={() => void load()}
        />
      )}

      {selectedRow && !consoleDevice && !configOpen && (
        <FabricDeviceDrawer
          row={selectedRow}
          onClose={() => setSelectedDevice(null)}
          onOpenConsole={(deviceId) => {
            setSelectedDevice(null);
            setConsoleDevice(deviceId);
          }}
        />
      )}
    </div>
  );
}
