import { useEffect, useRef, useState } from "react";
import {
  Activity,
  ChevronDown,
  Clock3,
  Command,
  Database,
  HelpCircle,
  Menu,
  RefreshCw,
  Search,
  ShieldCheck,
  UserRound,
  Wifi,
  WifiOff,
} from "lucide-react";
import { TIME_RANGES } from "../data/mock";
import type { PageId } from "../types";
import type { DataMode } from "../data/useAnalytics";
import { useToast } from "./Toast";

const PAGE_LABEL: Record<PageId, { section: string; title: string }> = {
  overview: { section: "Monitorización", title: "Resumen" },
  map: { section: "Monitorización", title: "Mapa global" },
  events: { section: "Monitorización", title: "Eventos" },
  honeypots: { section: "Operación", title: "Honeypots" },
  devices: { section: "Operación", title: "Dispositivos" },
  ingest: { section: "Operación", title: "Ingesta" },
  admin: { section: "Gobierno", title: "Administración" },
};

interface TopbarProps {
  page: PageId;
  range: string;
  dataMode: DataMode;
  loading: boolean;
  sessionActive: boolean;
  onLogin: () => void;
  onLogout: () => void;
  onRangeChange: (range: string) => void;
  search: string;
  onSearchChange: (value: string) => void;
  onRefresh: () => void;
  refreshing: boolean;
  onOpenMobile: () => void;
}

export function Topbar({
  page,
  range,
  dataMode,
  loading,
  sessionActive,
  onLogin,
  onLogout,
  onRangeChange,
  search,
  onSearchChange,
  onRefresh,
  refreshing,
  onOpenMobile,
}: TopbarProps) {
  const [rangeOpen, setRangeOpen] = useState(false);
  const [userOpen, setUserOpen] = useState(false);
  const [commandFocused, setCommandFocused] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const rangeRef = useRef<HTMLDivElement>(null);
  const userRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const label = PAGE_LABEL[page];
  const { notify } = useToast();

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    const onPointer = (event: MouseEvent) => {
      if (rangeRef.current && !rangeRef.current.contains(event.target as Node)) setRangeOpen(false);
      if (userRef.current && !userRef.current.contains(event.target as Node)) setUserOpen(false);
    };
    document.addEventListener("mousedown", onPointer);
    return () => document.removeEventListener("mousedown", onPointer);
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const activeRange = TIME_RANGES.find((item) => item.id === range) ?? TIME_RANGES[0];
  const relative = dataMode === "live" ? "datos en vivo" : dataMode === "error" ? "sin conexión al BFF" : "datos de demostración";

  return (
    <header className="topbar">
      <div className="topbar-left">
        <button className="icon-button mobile-menu" onClick={onOpenMobile} aria-label="Abrir navegación">
          <Menu size={19} />
        </button>
        <div className="breadcrumb">
          <span>{label.section}</span>
          <span className="breadcrumb-sep">/</span>
          <strong>{label.title}</strong>
        </div>
      </div>

      <div className={`global-search ${commandFocused ? "focused" : ""}`}>
        <Search size={16} />
        <input
          ref={inputRef}
          value={search}
          onChange={(event) => onSearchChange(event.target.value)}
          onFocus={() => setCommandFocused(true)}
          onBlur={() => setCommandFocused(false)}
          placeholder="Buscar IP, país, sensor o evento…"
          aria-label="Buscar en Dystopia"
        />
        <span className="search-shortcut"><Command size={12} />K</span>
      </div>

      <div className="topbar-actions">
        <span className={`mode-pill ${dataMode}`} title={relative}>
          {dataMode === "live" ? <Wifi size={12} /> : dataMode === "error" ? <WifiOff size={12} /> : <Clock3 size={12} />}
          {loading ? "sync" : dataMode === "live" ? "Live" : dataMode === "error" ? "Offline" : "Demo"}
        </span>
        <div className="range-control" ref={rangeRef}>
          <button className="range-button" onClick={() => setRangeOpen((open) => !open)} aria-expanded={rangeOpen}>
            <span className="status-dot live" />
            <span>{activeRange.label}</span>
            <ChevronDown size={14} />
          </button>
          {rangeOpen && (
            <div className="dropdown range-dropdown" role="menu">
              <span className="dropdown-label">Rango de tiempo</span>
              {TIME_RANGES.map((item) => (
                <button
                  key={item.id}
                  className={item.id === range ? "active" : ""}
                  onClick={() => {
                    onRangeChange(item.id);
                    setRangeOpen(false);
                  }}
                >
                  <span>{item.label}</span>
                  <span className="mono">{item.short}</span>
                </button>
              ))}
              <div className="dropdown-foot">El dashboard guarda la ventana seleccionada.</div>
            </div>
          )}
        </div>

        <button className={`icon-button ${refreshing ? "spinning" : ""}`} onClick={onRefresh} aria-label="Actualizar datos" title="Actualizar">
          <RefreshCw size={17} />
        </button>
        <button className="icon-button badge-button" aria-label="Avisos" title="Avisos" onClick={() => notify("3 avisos operativos: 2 críticos y 1 de ingesta. El centro de alertas se conectará al backend en la siguiente fase.", "info")}>
          <Activity size={17} />
          <span className="badge">3</span>
        </button>
        <button className="icon-button help-button" aria-label="Ayuda" title="Ayuda" onClick={() => notify("Dystopia Web: usa el menú lateral para navegar. El modo Demo no requiere sesión; Live consulta SQLite a través del BFF.", "info")}>
          <HelpCircle size={17} />
        </button>

        <div className="user-control" ref={userRef}>
          <button className="user-button" onClick={() => setUserOpen((open) => !open)} aria-expanded={userOpen}>
            <span className="avatar"><UserRound size={16} /></span>
            <span className="user-copy">
              <strong>{dataMode === "live" ? "sesión activa" : "deception_admin"}</strong>
              <small>{dataMode === "live" ? "datos reales" : "modo demostración"}</small>
            </span>
            <ChevronDown size={14} />
          </button>
          {userOpen && (
            <div className="dropdown user-dropdown" role="menu">
              <div className="user-dropdown-head">
                <span className="avatar large"><UserRound size={18} /></span>
                <div>
                  <strong>{dataMode === "live" ? "sesión activa" : "deception_admin"}</strong>
                  <span>{dataMode === "live" ? "datos de SQLite local" : "modo demostración · sin token"}</span>
                </div>
              </div>
              <div className="user-dropdown-status">
                <ShieldCheck size={14} />
                <span>{dataMode === "live" ? "BFF analítico autorizado" : "La UI nunca recibe la ruta de SQLite"}</span>
              </div>
              <div className="user-dropdown-time"><Database size={13} /> actualizado {new Date(now).toLocaleTimeString("es-MX", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false })}</div>
              <button
                onClick={() => {
                  setUserOpen(false);
                  if (sessionActive) onLogout();
                  else onLogin();
                }}
              >
                {sessionActive ? "Cerrar sesión" : "Iniciar sesión"}
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
