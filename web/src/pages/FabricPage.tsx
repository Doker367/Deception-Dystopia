import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Container,
  Power,
  RefreshCw,
  Rocket,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";
import type { ECElementEvent, EChartsOption } from "echarts";
import { PageHeader } from "../components/PageHeader";
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

function buildGraphOption(graph: FabricGraph): EChartsOption {
  const groupIndex = new Map(graph.groups.map((group, index) => [group.id, index + 1]));
  const categories = [
    { name: "Switches", itemStyle: { color: ACCENTS.slate } },
    ...graph.groups.map((group, index) => ({
      name: group.label,
      itemStyle: { color: GROUP_COLORS[index % GROUP_COLORS.length] },
    })),
  ];
  const ink = isLight() ? "#3d4f60" : "#c9d6e4";

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
        return [
          `Dispositivo ${node.label}`,
          `IP ${node.ip ?? "—"} · VLAN ${node.vlan_tag ?? "sin etiqueta"}`,
          `Switch ${node.switch ?? "—"} · Segmento ${node.segment ?? "—"}`,
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
      layout: "force",
      roam: true,
      draggable: true,
      top: 20,
      bottom: 46,
      left: 18,
      right: 18,
      force: { repulsion: 280, edgeLength: [85, 160], gravity: 0.08 },
      categories,
      data: graph.nodes.map((node) => ({
        id: node.id,
        name: node.label,
        value: node.kind === "device" ? node.ip ?? "" : node.switch_id ?? "",
        category: node.kind === "switch" ? 0 : groupIndex.get(node.group) ?? 1,
        symbol: node.kind === "switch" ? "roundRect" : "circle",
        symbolSize: node.kind === "switch" ? 46 : 32,
        itemStyle: node.kind === "switch"
          ? { color: ACCENTS.slate, borderColor: withAlpha(ACCENTS.slate, 0.7), borderWidth: 1 }
          : { borderColor: withAlpha(ink, 0.35), borderWidth: 1 },
        label: {
          show: true,
          position: node.kind === "switch" ? "inside" : "right",
          color: node.kind === "switch" ? "#f2f0ec" : ink,
          fontSize: 10.5,
          overflow: "truncate",
          width: 110,
        },
      })),
      links: graph.edges.map((edge) => ({
        source: edge.source,
        target: edge.target,
        lineStyle: {
          color: edge.state === "up" ? ACCENTS.green : ACCENTS.slate,
          width: edge.kind === "trunk" ? 2.2 : 1.2,
          type: edge.state === "up" ? "solid" : "dashed",
          opacity: 0.85,
          curveness: 0.08,
        },
      })),
      edgeSymbol: ["none", "none"],
      emphasis: { focus: "adjacency", lineStyle: { width: 3 } },
      lineStyle: { opacity: 0.85 },
    }],
  };
}

// ── Drawer de dispositivo ───────────────────────────────────

function FabricDeviceDrawer({ row, onClose }: { row: DeviceRow; onClose: () => void }) {
  const { spec, manifest, iface, segmentId } = row;
  const services = manifest?.services ?? [];
  const vlan = iface?.vlan_tag;
  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="event-drawer config-drawer" onClick={(event) => event.stopPropagation()}>
        <div className="drawer-head">
          <div>
            <span className="eyebrow">Fabric / device</span>
            <h2>{spec.device_id}</h2>
            <span className="mono muted">{iface?.ip ?? "sin IP"}</span>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Cerrar dispositivo"><X size={18} /></button>
        </div>

        <div className="drawer-badges">
          <span className="proto-chip">{manifest?.role ?? "device"}</span>
          <span className="sensor-chip">{segmentId || "sin segmento"}</span>
          <span className="health-pill"><i />{vlan === null || vlan === undefined ? "sin etiqueta" : `VLAN ${vlan}`}</span>
        </div>

        <div className="honeypot-config-grid">
          <div><span>IP</span><strong className="mono">{iface?.ip ?? "—"}</strong></div>
          <div><span>MAC</span><strong className="mono">{iface?.mac ?? "—"}</strong></div>
          <div><span>Switch</span><strong className="mono">{iface?.switch ?? "—"}</strong></div>
          <div><span>VLAN</span><strong className="mono">{vlan ?? "sin etiqueta"}</strong></div>
          <div><span>Segmento</span><strong>{segmentId || "—"}</strong></div>
          <div><span>Gateway</span><strong className="mono">{iface?.gateway ?? "—"}</strong></div>
          <div><span>Contenedor</span><strong className="mono">{spec.container_name}</strong></div>
          <div><span>Recursos</span><strong>{spec.cpus} CPU · {spec.mem_limit}</strong></div>
        </div>

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
  );
}

// ── Página ──────────────────────────────────────────────────

export function FabricPage() {
  const { notify } = useToast();
  const canAdmin = getRole() === "admin";

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<FabricStatus | null>(null);
  const [topology, setTopology] = useState<FabricTopology>({});
  const [graph, setGraph] = useState<FabricGraph>({ nodes: [], edges: [], groups: [], state: "disabled" });
  const [specs, setSpecs] = useState<FabricDeviceSpec[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<string | null>(null);
  const [report, setReport] = useState<FabricValidateReport | null>(null);
  const [validating, setValidating] = useState(false);
  const [pending, setPending] = useState<ActionKind | null>(null);
  const [busy, setBusy] = useState<ActionKind | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [nextStatus, nextTopology, nextGraph, nextSpecs] = await Promise.all([
        apiGet<FabricStatus>("/api/fabric/status"),
        apiGet<FabricTopology>("/api/fabric/topology"),
        apiGet<FabricGraph>("/api/fabric/topology/graph"),
        apiGet<FabricDeviceSpec[]>("/api/fabric/devices"),
      ]);
      setStatus(nextStatus);
      setTopology(nextTopology ?? {});
      setGraph(nextGraph);
      setSpecs(nextSpecs ?? []);
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
  const graphOption = buildGraphOption(graph);

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
                <button
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
              actions={<span className="mono muted">{meta.hint}</span>}
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

      {selectedRow && <FabricDeviceDrawer row={selectedRow} onClose={() => setSelectedDevice(null)} />}
    </div>
  );
}
