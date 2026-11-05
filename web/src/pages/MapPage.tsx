import { useEffect, useMemo, useState } from "react";
import {
  ArrowUpRight,
  Crosshair,
  Download,
  Filter,
  Globe2,
  MapPin,
  Radio,
  RotateCcw,
  ScanLine,
  ShieldAlert,
  Check,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Panel } from "../components/Panel";
import { AttackGlobe } from "../components/AttackGlobe";
import { DATACENTER } from "../data/mock";
import type { AttackOrigin } from "../types";
import type { DataMode } from "../data/useAnalytics";
import { formatNumber } from "../lib/format";
import { SeverityBadge } from "../components/SeverityBadge";
import { useToast } from "../components/Toast";
import { downloadJson } from "../lib/download";

interface MapPageProps {
  search: string;
  origins: AttackOrigin[];
  mode: DataMode;
  onRefresh: () => void;
  onOpenEvents: (origin: AttackOrigin) => void;
}

const REGION_BY_COUNTRY: Record<string, string> = {
  US: "AMER", CA: "AMER", MX: "AMER", BR: "AMER", AR: "AMER", CL: "AMER", CO: "AMER", PE: "AMER", VE: "AMER", EC: "AMER", BO: "AMER", PY: "AMER", UY: "AMER", CR: "AMER", PA: "AMER", GT: "AMER", HN: "AMER", SV: "AMER", NI: "AMER", DO: "AMER", CU: "AMER", PR: "AMER",
  GB: "EMEA", DE: "EMEA", FR: "EMEA", NL: "EMEA", BE: "EMEA", ES: "EMEA", IT: "EMEA", PT: "EMEA", CH: "EMEA", AT: "EMEA", SE: "EMEA", NO: "EMEA", DK: "EMEA", FI: "EMEA", IE: "EMEA", PL: "EMEA", CZ: "EMEA", SK: "EMEA", HU: "EMEA", RO: "EMEA", BG: "EMEA", GR: "EMEA", TR: "EMEA", RU: "EMEA", UA: "EMEA", BY: "EMEA", RS: "EMEA", HR: "EMEA", SI: "EMEA", BA: "EMEA", AL: "EMEA", MK: "EMEA", ME: "EMEA", XK: "EMEA", IL: "EMEA", SA: "EMEA", AE: "EMEA", QA: "EMEA", KW: "EMEA", BH: "EMEA", OM: "EMEA", JO: "EMEA", LB: "EMEA", EG: "EMEA", ZA: "EMEA", NG: "EMEA", KE: "EMEA", MA: "EMEA", DZ: "EMEA", TN: "EMEA", LY: "EMEA", ET: "EMEA", GH: "EMEA", CI: "EMEA", SN: "EMEA", CM: "EMEA", UG: "EMEA", TZ: "EMEA",
  CN: "APAC", JP: "APAC", KR: "APAC", IN: "APAC", ID: "APAC", VN: "APAC", TH: "APAC", MY: "APAC", SG: "APAC", PH: "APAC", AU: "APAC", NZ: "APAC", PK: "APAC", BD: "APAC", LK: "APAC", NP: "APAC", TW: "APAC", HK: "APAC", MO: "APAC", KZ: "APAC", UZ: "APAC", IR: "APAC", IQ: "APAC", AF: "APAC", MM: "APAC", KH: "APAC", LA: "APAC", MN: "APAC", BN: "APAC", FJ: "APAC",
};

const REGION_LABEL: Record<string, string> = { AMER: "América", EMEA: "Europa / África / Oriente Medio", APAC: "Asia-Pacífico", OTROS: "Otros" };

function regionFor(code: string) {
  return REGION_BY_COUNTRY[code] ?? "OTROS";
}

export function MapPage({ search, origins, mode, onRefresh, onOpenEvents }: MapPageProps) {
  const { notify } = useToast();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [country, setCountry] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [sensor, setSensor] = useState("all");
  const [protocol, setProtocol] = useState("all");
  const [region, setRegion] = useState("all");
  const [following, setFollowing] = useState(false);

  const countryOptions = useMemo(() => Array.from(new Set(origins.map((origin) => origin.country))).sort(), [origins]);
  const sensorOptions = useMemo(() => Array.from(new Set(origins.map((origin) => origin.sensor))).sort(), [origins]);
  const protocolOptions = useMemo(() => Array.from(new Set(origins.map((origin) => origin.protocol))).sort(), [origins]);

  const points = useMemo(() => {
    const query = search.trim().toLowerCase();
    return origins.filter((origin) => {
      if (country !== "all" && origin.country !== country) return false;
      if (region !== "all" && regionFor(origin.countryCode) !== region) return false;
      if (severity !== "all" && origin.severity !== severity) return false;
      if (sensor !== "all" && origin.sensor !== sensor) return false;
      if (protocol !== "all" && origin.protocol !== protocol) return false;
      if (!query) return true;
      return [origin.country, origin.city, origin.ip, origin.protocol, origin.sensor].join(" ").toLowerCase().includes(query);
    });
  }, [country, origins, protocol, region, search, sensor, severity]);

  const filtersActive = country !== "all" || severity !== "all" || sensor !== "all" || protocol !== "all" || region !== "all";
  const regionCounts = useMemo(() => {
    const counts: Record<string, number> = { AMER: 0, EMEA: 0, APAC: 0, OTROS: 0 };
    for (const origin of origins) counts[regionFor(origin.countryCode)] += 1;
    return counts;
  }, [origins]);

  useEffect(() => {
    if (!following) return;
    const timer = window.setInterval(onRefresh, 30_000);
    return () => window.clearInterval(timer);
  }, [following, onRefresh]);

  function resetFilters() {
    setCountry("all");
    setSeverity("all");
    setSensor("all");
    setProtocol("all");
    setRegion("all");
  }

  const selected = points.find((origin) => origin.id === selectedId) ?? points[0] ?? null;
  const totalEvents = points.reduce((total, origin) => total + origin.events, 0);
  const maxEvents = Math.max(...points.map((origin) => origin.events), 1);

  return (
    <div className="page page-map">
      <PageHeader
        eyebrow="Monitorización / Threat geography"
        title="Mapa global de ataques"
        description="Geolocalización de los orígenes que están tocando la red señuelo. Arcos animados, actividad por país y detalle del origen seleccionado."
        actions={
          <>
            <button className="button ghost" onClick={() => {
              const geojson = {
                type: "FeatureCollection",
                features: points.map((origin) => ({
                  type: "Feature",
                  geometry: { type: "Point", coordinates: [origin.lng, origin.lat] },
                  properties: { country: origin.country, countryCode: origin.countryCode, city: origin.city, ip: origin.ip, events: origin.events, severity: origin.severity, protocol: origin.protocol, sensor: origin.sensor },
                })),
              };
              downloadJson("dystopia-origins.geojson", geojson);
              notify(`GeoJSON exportado con ${points.length} orígenes.`, "success");
            }}><Download size={15} /> Exportar GeoJSON</button>
            <button className={`button ${following ? "ghost" : "primary"}`} onClick={() => {
              setFollowing((value) => !value);
              notify(following ? "Seguimiento pausado." : "Seguimiento activo: refresco cada 30 s.", following ? "info" : "success");
              if (!following) onRefresh();
            }}>{following ? <Check size={15} /> : <Radio size={15} />} {following ? "Seguimiento activo" : "Iniciar seguimiento"}</button>
          </>
        }
        meta={
          <>
            <span><i className={`status-dot ${mode === "live" ? "live" : ""}`} /> {mode === "live" ? "Telemetría en vivo" : mode === "error" ? "BFF sin conexión" : "Datos de demostración"}</span>
            <span>{points.length} orígenes activos</span>
            <span className="mono">ventana 24 h</span>
          </>
        }
      />

      <div className="map-region-bar" aria-label="Filtro por región">
        <span className="filter-bar-label"><Globe2 size={14} /> Regiones</span>
        {(["AMER", "EMEA", "APAC", "OTROS"] as const).filter((item) => regionCounts[item] > 0).map((item) => (
          <button key={item} className={`region-chip ${region === item ? "active" : ""}`} onClick={() => { setRegion(region === item ? "all" : item); setSelectedId(null); }}>
            <b>{item}</b><span>{regionCounts[item]}</span>
          </button>
        ))}
        <span className="region-legend">{region === "all" ? "Todas las regiones" : REGION_LABEL[region]}</span>
      </div>

      <div className="filter-bar map-filter-bar">
        <span className="filter-bar-label"><Filter size={14} /> Filtros del mapa</span>
        <label className="filter-select">
          <span>País</span>
          <select value={country} onChange={(event) => { setCountry(event.target.value); setSelectedId(null); }}>
            <option value="all">Todos</option>
            {countryOptions.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </label>
        <label className="filter-select">
          <span>Severidad</span>
          <select value={severity} onChange={(event) => { setSeverity(event.target.value); setSelectedId(null); }}>
            <option value="all">Todas</option>
            <option value="critical">Crítico</option>
            <option value="high">Alto</option>
            <option value="medium">Medio</option>
            <option value="low">Bajo</option>
            <option value="info">Info</option>
          </select>
        </label>
        <label className="filter-select">
          <span>Sensor</span>
          <select value={sensor} onChange={(event) => { setSensor(event.target.value); setSelectedId(null); }}>
            <option value="all">Todos</option>
            {sensorOptions.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </label>
        <label className="filter-select">
          <span>Protocolo</span>
          <select value={protocol} onChange={(event) => { setProtocol(event.target.value); setSelectedId(null); }}>
            <option value="all">Todos</option>
            {protocolOptions.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </label>
        {filtersActive && <button className="link-button" onClick={resetFilters}><RotateCcw size={13} /> Limpiar</button>}
        <span className="filter-count">{points.length} de {origins.length} orígenes</span>
      </div>

      <div className="map-layout">
        <Panel className="map-main" flush>
          <AttackGlobe points={points} height={660} onSelect={(origin) => setSelectedId(origin.id)} />
          <div className="map-bottom-strip">
            <div><span className="eyebrow">Eventos geolocalizados</span><strong>{formatNumber(totalEvents)}</strong></div>
            <div><span className="eyebrow">Países</span><strong>{points.length}</strong></div>
            <div><span className="eyebrow">Core</span><strong>{DATACENTER.city}</strong></div>
            <div><span className="eyebrow">Precisión</span><strong>ciudad</strong></div>
            <div><span className="eyebrow">Fuente</span><strong>SQLite local</strong></div>
          </div>
        </Panel>

        <div className="map-side">
          <Panel className="map-focus" eyebrow="Origen seleccionado" title={selected ? `${selected.city}, ${selected.country}` : "Selecciona un origen"}>
            {selected ? (
              <div className="origin-detail">
                <div className="origin-detail-head">
                  <span className="origin-code">{selected.countryCode}</span>
                  <div>
                    <strong className="mono">{selected.ip}</strong>
                    <span>Último evento {selected.lastSeen}</span>
                  </div>
                  <SeverityBadge severity={selected.severity} />
                </div>
                <div className="origin-stats">
                  <div><span>Eventos</span><strong>{formatNumber(selected.events)}</strong></div>
                  <div><span>Fuentes</span><strong>{formatNumber(selected.uniqueSources)}</strong></div>
                  <div><span>Protocolo</span><strong>{selected.protocol}</strong></div>
                  <div><span>Sensor</span><strong>{selected.sensor}</strong></div>
                </div>
                <div className="origin-route">
                  <MapPin size={14} />
                  <span>{selected.city}</span>
                  <span className="route-line" />
                  <ScanLine size={14} />
                  <span>{DATACENTER.city}</span>
                </div>
                <button className="button ghost wide" onClick={() => onOpenEvents(selected)}>Ver eventos de este origen <ArrowUpRight size={14} /></button>
              </div>
            ) : (
              <p className="muted">Haz clic en un punto del globo para inspeccionar el origen. No hay orígenes en la ventana actual.</p>
            )}
          </Panel>

          <Panel className="map-region-panel" eyebrow="Cobertura" title="Regiones activas">
            <div className="region-list">
              {(["AMER", "EMEA", "APAC", "OTROS"] as const).filter((item) => regionCounts[item] > 0).map((item) => (
                <button key={item} className={region === item ? "active" : ""} onClick={() => setRegion(region === item ? "all" : item)}>
                  <span className="region-abbr">{item}</span>
                  <span className="region-name">{REGION_LABEL[item]}</span>
                  <span className="region-bar"><i style={{ width: `${(regionCounts[item] / Math.max(origins.length, 1)) * 100}%` }} /></span>
                  <b>{regionCounts[item]}</b>
                </button>
              ))}
            </div>
          </Panel>

          <Panel
            className="map-rank"
            eyebrow="Ranking"
            title="Top orígenes"
            description="Ordenado por eventos en la ventana."
            actions={<span className="signal-pill"><Globe2 size={13} /> {points.length}</span>}
          >
            <div className="rank-list compact-rank">
              {points.slice(0, 10).map((origin, index) => (
                <button
                  className={`rank-row ${selected?.id === origin.id ? "selected" : ""}`}
                  key={origin.id}
                  onClick={() => setSelectedId(origin.id)}
                >
                  <span className="rank-number">{String(index + 1).padStart(2, "0")}</span>
                  <span className="rank-flag">{origin.countryCode}</span>
                  <span className="rank-country"><strong>{origin.country}</strong><small>{origin.city}</small></span>
                  <span className="rank-bar"><i style={{ width: `${(origin.events / maxEvents) * 100}%` }} /></span>
                  <span className="rank-value mono">{formatNumber(origin.events)}</span>
                </button>
              ))}
            </div>
          </Panel>

          <Panel className="map-signal" eyebrow="Detección" title="Señales del mapa">
            <div className="map-signal-list">
              <div><span className="insight-icon red"><ShieldAlert size={15} /></span><p><strong>Concentración inusual</strong><span>China + Rusia representan 32 % del volumen.</span></p></div>
              <div><span className="insight-icon cyan"><Crosshair size={15} /></span><p><strong>Core observado</strong><span>{DATACENTER.city} recibe arcos de {points.length} regiones distintas.</span></p></div>
              <div><span className="insight-icon amber"><Radio size={15} /></span><p><strong>Nuevo origen</strong><span>Fráncfort entró en la ventana hace 38 minutos.</span></p></div>
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
