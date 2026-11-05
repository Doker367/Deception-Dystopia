import {
  Activity,
  Boxes,
  ChevronRight,
  Database,
  Globe2,
  LayoutDashboard,
  ScrollText,
  Settings2,
  ShieldCheck,
  X,
} from "lucide-react";
import { Brand } from "./Brand";
import type { PageId } from "../types";

interface NavItem {
  id: PageId;
  label: string;
  hint: string;
  icon: typeof LayoutDashboard;
  group: "monitor" | "operate" | "manage";
}

const NAV: NavItem[] = [
  { id: "overview", label: "Resumen", hint: "Vista general", icon: LayoutDashboard, group: "monitor" },
  { id: "map", label: "Mapa global", hint: "Origen de ataques", icon: Globe2, group: "monitor" },
  { id: "events", label: "Eventos", hint: "Explorador", icon: ScrollText, group: "monitor" },
  { id: "honeypots", label: "Honeypots", hint: "Sensores activos", icon: Boxes, group: "operate" },
  { id: "devices", label: "Dispositivos", hint: "Topología", icon: Database, group: "operate" },
  { id: "ingest", label: "Ingesta", hint: "Pipeline", icon: Activity, group: "operate" },
  { id: "admin", label: "Administración", hint: "Acceso y claves", icon: Settings2, group: "manage" },
];

const GROUP_LABEL: Record<NavItem["group"], string> = {
  monitor: "Monitorización",
  operate: "Operación",
  manage: "Gobierno",
};

interface SidebarProps {
  active: PageId;
  onNavigate: (page: PageId) => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

export function Sidebar({ active, onNavigate, mobileOpen, onCloseMobile }: SidebarProps) {
  let lastGroup: NavItem["group"] | null = null;
  return (
    <>
      {mobileOpen && <button className="sidebar-backdrop" aria-label="Cerrar navegación" onClick={onCloseMobile} />}
      <aside className={`sidebar ${mobileOpen ? "sidebar-open" : ""}`} aria-label="Navegación principal">
        <div className="sidebar-head">
          <Brand />
          <button className="icon-button sidebar-close" onClick={onCloseMobile} aria-label="Cerrar navegación">
            <X size={18} />
          </button>
        </div>

        <nav className="nav">
          {NAV.map((item) => {
            const Icon = item.icon;
            const showGroup = item.group !== lastGroup;
            lastGroup = item.group;
            return (
              <div key={item.id}>
                {showGroup && <span className="nav-group">{GROUP_LABEL[item.group]}</span>}
                <button
                  type="button"
                  className={`nav-item ${active === item.id ? "active" : ""}`}
                  onClick={() => {
                    onNavigate(item.id);
                    onCloseMobile();
                  }}
                >
                  <span className="nav-icon"><Icon size={17} strokeWidth={1.8} /></span>
                  <span className="nav-text">
                    <strong>{item.label}</strong>
                    <small>{item.hint}</small>
                  </span>
                  {active === item.id && <ChevronRight className="nav-chevron" size={14} />}
                </button>
              </div>
            );
          })}
        </nav>

        <div className="sidebar-foot">
          <div className="system-card">
            <div className="system-card-head">
              <span className="status-dot live" />
              <strong>Entorno de laboratorio</strong>
            </div>
            <p>SQLite local · datos de demostración</p>
            <div className="system-meta">
              <span><ShieldCheck size={13} /> Sin cambios de red</span>
              <span className="mono">c1</span>
            </div>
          </div>
          <div className="sidebar-version">
            <span>DYSTOPIA</span>
            <span className="mono">v0.1.0-web</span>
          </div>
        </div>
      </aside>
    </>
  );
}
