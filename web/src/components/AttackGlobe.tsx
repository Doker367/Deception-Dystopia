import { useEffect, useMemo, useRef, useState } from "react";
import Globe from "react-globe.gl";
import type { GlobeMethods } from "react-globe.gl";
import { MeshPhongMaterial } from "three";
import { Crosshair, Maximize2, RotateCcw } from "lucide-react";
import { ATTACK_ORIGINS, DATACENTER } from "../data/mock";
import type { AttackOrigin, Severity } from "../types";

interface CountryFeature {
  type: "Feature";
  properties: Record<string, string | number | null>;
  geometry: unknown;
}

interface AreaTotal {
  events: number;
  severity: Severity;
}

interface AreaTotals {
  byCountry: Map<string, AreaTotal>;
  byRegion: Map<string, AreaTotal>;
}

// Shared promises cache in-flight requests, successful GeoJSONs and missing files.
const regionCache = new Map<string, Promise<CountryFeature[]>>();

function loadRegions(countryCode: string): Promise<CountryFeature[]> {
  const cached = regionCache.get(countryCode);
  if (cached) return cached;
  const path = countryCode === "US" ? "us-states.geo.json" : `regions/${countryCode.toLowerCase()}.geo.json`;
  const request = fetch(`${import.meta.env.BASE_URL}${path}`)
    .then(async (response) => {
      if (response.status === 404) return [];
      if (!response.ok) throw new Error(`No se pudo cargar ${path}`);
      // Some SPA servers serve index.html (HTTP 200) for absent static assets.
      const collection = await response.json().catch(() => null);
      const features: CountryFeature[] = collection?.features;
      if (!Array.isArray(features) || !features.length || !features.every((feature) =>
        feature?.type === "Feature" && typeof feature.properties?.code === "string"
        && typeof feature.properties?.name === "string" && feature.geometry)) return [];
      return features.map((feature) => ({
        ...feature,
        properties: { ...feature.properties, __layer: "region", __country: countryCode },
      }));
    })
    .catch(() => {
      // A transient network error can be retried when the origins change.
      regionCache.delete(countryCode);
      return [];
    });
  regionCache.set(countryCode, request);
  return request;
}

function totalForPolygon(feature: CountryFeature, totals: AreaTotals): AreaTotal | undefined {
  const properties = feature.properties ?? {};
  return properties.__layer === "region"
    ? totals.byRegion.get(`${properties.__country}|${properties.code}`)
    : totals.byCountry.get(String(properties.ISO_A2 ?? ""));
}

interface GlobePoint {
  lat: number;
  lng: number;
  kind: "origin" | "core";
  origin?: AttackOrigin;
  color: string;
  altitude: number;
  radius: number;
}

interface GlobeArc {
  startLat: number;
  startLng: number;
  endLat: number;
  endLng: number;
  color: string[];
  origin: AttackOrigin;
}

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#ff5f7a",
  high: "#ff9f5b",
  medium: "#f5d06b",
  low: "#35e6c4",
  info: "#5aa9ff",
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Crítico",
  high: "Alto",
  medium: "Medio",
  low: "Bajo",
  info: "Info",
};

function withAlpha(hex: string, alpha: number) {
  const value = hex.replace("#", "");
  const bigint = Number.parseInt(value, 16);
  const r = (bigint >> 16) & 255;
  const g = (bigint >> 8) & 255;
  const b = bigint & 255;
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

function tooltipFor(origin: AttackOrigin) {
  return `
    <div class="globe-tooltip">
      <div class="globe-tooltip-head">
        <span class="globe-tooltip-dot" style="background:${SEVERITY_COLOR[origin.severity]}"></span>
        <strong>${[origin.city, origin.region, origin.country].filter(Boolean).join(", ")}</strong>
        <span class="globe-tooltip-badge">${SEVERITY_LABEL[origin.severity]}</span>
      </div>
      <div class="globe-tooltip-row"><span>Origen</span><b class="mono">${origin.ip}</b></div>
      <div class="globe-tooltip-row"><span>Eventos</span><b>${origin.events.toLocaleString("es-MX")}</b></div>
      <div class="globe-tooltip-row"><span>Protocolo</span><b>${origin.protocol}</b></div>
      <div class="globe-tooltip-row"><span>Sensor</span><b>${origin.sensor}</b></div>
      <div class="globe-tooltip-foot"><span>Último evento</span><b>${origin.lastSeen}</b></div>
    </div>
  `;
}

interface AttackGlobeProps {
  points?: AttackOrigin[];
  autoRotate?: boolean;
  showArcs?: boolean;
  height?: number;
  minimal?: boolean;
  onSelect?: (origin: AttackOrigin) => void;
}

export function AttackGlobe({
  points = ATTACK_ORIGINS,
  autoRotate = true,
  showArcs = true,
  height = 480,
  minimal = false,
  onSelect,
}: AttackGlobeProps) {
  const globeRef = useRef<GlobeMethods | undefined>(undefined);
  const containerRef = useRef<HTMLDivElement>(null);
  const [countries, setCountries] = useState<CountryFeature[]>([]);
  const [regions, setRegions] = useState<Record<string, CountryFeature[]>>({});
  const [size, setSize] = useState({ width: 640, height });
  const [rotating, setRotating] = useState(autoRotate);
  const [interactionPaused, setInteractionPaused] = useState(false);
  const resumeTimer = useRef<number | null>(null);
  const initialized = useRef(false);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const observer = new ResizeObserver((entries) => {
      const rect = entries[0]?.contentRect;
      if (rect) setSize({ width: Math.max(rect.width, 260), height: Math.max(rect.height, 280) });
    });
    observer.observe(container);
    return () => observer.disconnect();
  }, []);

  const regionCountries = useMemo(() => Array.from(new Set(points
    .filter((origin) => origin.regionCode && /^[A-Z]{2}$/.test(origin.countryCode))
    .map((origin) => origin.countryCode))).sort(), [points]);

  useEffect(() => {
    let cancelled = false;
    fetch(`${import.meta.env.BASE_URL}world.geo.json`)
      .then((response) => {
        if (!response.ok) throw new Error("No se pudo cargar world.geo.json");
        return response.json();
      })
      .then((world) => {
        if (!cancelled) setCountries(Array.isArray(world?.features) ? world.features as CountryFeature[] : []);
      })
      .catch(() => { /* Points and any available regional polygons still render. */ });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    let cancelled = false;
    for (const countryCode of regionCountries) {
      loadRegions(countryCode).then((features) => {
        if (!cancelled) setRegions((current) => current[countryCode] === features
          ? current : { ...current, [countryCode]: features });
      });
    }
    return () => { cancelled = true; };
  }, [regionCountries]);

  useEffect(() => {
    const globe = globeRef.current;
    if (!globe) return;
    const controls = globe.controls();
    controls.autoRotate = rotating && !interactionPaused;
    controls.autoRotateSpeed = 0.42;
    controls.enablePan = false;
    controls.minDistance = 210;
    controls.maxDistance = 620;
    if (!initialized.current) {
      globe.pointOfView({ lat: DATACENTER.lat, lng: DATACENTER.lng, altitude: 1.9 }, 0);
      initialized.current = true;
    }
  }, [rotating, interactionPaused, size.width]);

  useEffect(() => {
    const globe = globeRef.current;
    if (!globe) return;
    const controls = globe.controls();
    const clearResumeTimer = () => {
      if (resumeTimer.current !== null) {
        window.clearTimeout(resumeTimer.current);
        resumeTimer.current = null;
      }
    };
    const pause = () => {
      clearResumeTimer();
      setInteractionPaused(true);
    };
    const scheduleResume = () => {
      clearResumeTimer();
      resumeTimer.current = window.setTimeout(() => {
        setInteractionPaused(false);
        resumeTimer.current = null;
      }, 15_000);
    };
    const onStart = () => pause();
    const onEnd = () => scheduleResume();
    const container = containerRef.current;
    const onPointerDown = () => pause();
    const onPointerUp = () => scheduleResume();
    const onWheel = () => {
      pause();
      scheduleResume();
    };
    controls.addEventListener("start", onStart);
    controls.addEventListener("end", onEnd);
    container?.addEventListener("pointerdown", onPointerDown);
    container?.addEventListener("touchstart", onPointerDown, { passive: true });
    container?.addEventListener("wheel", onWheel, { passive: true });
    window.addEventListener("pointerup", onPointerUp);
    window.addEventListener("touchend", onPointerUp);
    return () => {
      clearResumeTimer();
      controls.removeEventListener("start", onStart);
      controls.removeEventListener("end", onEnd);
      container?.removeEventListener("pointerdown", onPointerDown);
      container?.removeEventListener("touchstart", onPointerDown);
      container?.removeEventListener("wheel", onWheel);
      window.removeEventListener("pointerup", onPointerUp);
      window.removeEventListener("touchend", onPointerUp);
    };
  }, []);

  const availableRegions = useMemo(() => {
    const available = new Map<string, CountryFeature[]>();
    for (const countryCode of regionCountries) {
      if (regions[countryCode]?.length) available.set(countryCode, regions[countryCode]);
    }
    return available;
  }, [regionCountries, regions]);
  const polygons = useMemo(() => [
    ...countries.filter((feature) => !availableRegions.has(String(feature.properties?.ISO_A2 ?? ""))),
    ...Array.from(availableRegions.values()).flat(),
  ], [countries, availableRegions]);
  const areaTotals = useMemo<AreaTotals>(() => {
    const byCountry = new Map<string, AreaTotal>();
    const byRegion = new Map<string, AreaTotal>();
    const regionCodes = new Map<string, Set<string>>();
    for (const [country, features] of availableRegions) {
      regionCodes.set(country, new Set(features.map((feature) => String(feature.properties.code))));
    }
    const rank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    for (const origin of points) {
      const code = origin.regionCode?.toUpperCase();
      const hasRegion = Boolean(code && regionCodes.get(origin.countryCode)?.has(code));
      const target = hasRegion ? byRegion : byCountry;
      const key = hasRegion ? `${origin.countryCode}|${code}` : origin.countryCode;
      const current = target.get(key);
      if (!current) {
        target.set(key, { events: origin.events, severity: origin.severity });
      } else {
        current.events += origin.events;
        if (rank[origin.severity] > rank[current.severity]) current.severity = origin.severity;
      }
    }
    return { byCountry, byRegion };
  }, [points, availableRegions]);
  const pointData = useMemo<GlobePoint[]>(
    () => [
      ...points.map((origin) => ({
        lat: origin.lat,
        lng: origin.lng,
        kind: "origin" as const,
        origin,
        color: SEVERITY_COLOR[origin.severity],
        altitude: 0.018 + Math.min(origin.events / 1800, 1) * 0.08,
        radius: 0.22 + Math.min(origin.events / 1800, 1) * 0.34,
      })),
      {
        lat: DATACENTER.lat,
        lng: DATACENTER.lng,
        kind: "core",
        color: "#35e6c4",
        altitude: 0.02,
        radius: 0.42,
      },
    ],
    [points],
  );

  const arcData = useMemo<GlobeArc[]>(
    () =>
      points.map((origin) => ({
        startLat: origin.lat,
        startLng: origin.lng,
        endLat: DATACENTER.lat,
        endLng: DATACENTER.lng,
        color: [withAlpha(SEVERITY_COLOR[origin.severity], 0.08), SEVERITY_COLOR[origin.severity]],
        origin,
      })),
    [points],
  );

  const maxEvents = Math.max(...points.map((origin) => origin.events), 1);
  const globeMaterial = useMemo(
    () =>
      new MeshPhongMaterial({
        color: "#07121c",
        emissive: "#010509",
        emissiveIntensity: 0.8,
        shininess: 12,
        specular: "#0d2f3d",
      }),
    [],
  );

  return (
    <div className={`globe-shell ${minimal ? "globe-minimal" : ""}`} ref={containerRef} style={{ height }}>
      <div className="globe-canvas">
        <Globe
          ref={globeRef}
          width={size.width}
          height={size.height}
          backgroundColor="rgba(0,0,0,0)"
          globeMaterial={globeMaterial}
          showAtmosphere
          atmosphereColor="#35e6c4"
          atmosphereAltitude={0.16}
          showGraticules
          polygonsData={polygons}
          polygonAltitude={(feature: object) => totalForPolygon(feature as CountryFeature, areaTotals) ? 0.012 : 0.004}
          polygonCapColor={(feature: object) => {
            const total = totalForPolygon(feature as CountryFeature, areaTotals);
            if (!total) return "rgba(17, 34, 46, 0.82)";
            return withAlpha(SEVERITY_COLOR[total.severity], 0.34 + (total.events / maxEvents) * 0.42);
          }}
          polygonSideColor={() => "rgba(0, 0, 0, 0)"}
          polygonStrokeColor={(feature: object) => String((feature as CountryFeature).properties?.__layer ?? "") === "region"
            ? "rgba(91, 184, 190, 0.3)"
            : "rgba(91, 184, 190, 0.18)"}
          polygonLabel={(feature: object) => {
            const properties = (feature as CountryFeature).properties ?? {};
            const total = totalForPolygon(feature as CountryFeature, areaTotals);
            const name = properties.__layer === "region"
              ? String(properties.name ?? properties.code ?? "Estado / región")
              : String(properties.NAME_ES ?? properties.ADMIN ?? properties.NAME ?? "País");
            return `<div class="globe-tooltip globe-tooltip-small"><strong>${name}</strong><span>${total ? `${total.events.toLocaleString("es-MX")} eventos` : "Sin actividad en la ventana"}</span></div>`;
          }}
          pointsData={pointData}
          pointLat="lat"
          pointLng="lng"
          pointColor="color"
          pointAltitude="altitude"
          pointRadius="radius"
          pointLabel={(point: object) => {
            const item = point as GlobePoint;
            return item.kind === "core"
              ? `<div class="globe-tooltip"><div class="globe-tooltip-head"><span class="globe-tooltip-dot" style="background:#35e6c4"></span><strong>${DATACENTER.name}</strong><span class="globe-tooltip-badge core">Core</span></div><div class="globe-tooltip-row"><span>Ubicación</span><b>${DATACENTER.city}, ${DATACENTER.country}</b></div><div class="globe-tooltip-foot"><span>Rol</span><b>Red señuelo</b></div></div>`
              : tooltipFor(item.origin as AttackOrigin);
          }}
          onPointClick={(point: object) => {
            const item = point as GlobePoint;
            if (item.origin) onSelect?.(item.origin);
          }}
          arcsData={showArcs ? arcData : []}
          arcStartLat="startLat"
          arcStartLng="startLng"
          arcEndLat="endLat"
          arcEndLng="endLng"
          arcColor="color"
          arcAltitudeAutoScale={0.38}
          arcStroke={0.38}
          arcDashLength={0.48}
          arcDashGap={0.2}
          arcDashAnimateTime={2600}
          arcsTransitionDuration={0}
          arcLabel={(arc: object) => tooltipFor((arc as GlobeArc).origin)}
          ringsData={[{ lat: DATACENTER.lat, lng: DATACENTER.lng }]}
          ringColor={() => "rgba(53, 230, 196, 0.32)"}
          ringMaxRadius={4.2}
          ringPropagationSpeed={1.4}
          ringRepeatPeriod={1800}
          onGlobeReady={() => {
            const globe = globeRef.current;
            if (!globe) return;
            const controls = globe.controls();
            controls.autoRotate = rotating && !interactionPaused;
            controls.autoRotateSpeed = 0.42;
            controls.enablePan = false;
          }}
        />
      </div>

      {!minimal && (
        <>
          <div className="globe-overlay-top">
            <div className="globe-live">
              <span className="status-dot live" />
              <span>Live attack telemetry</span>
            </div>
            <div className="globe-overlay-actions">
              <button
                className="icon-button small"
                onClick={() => {
                  const next = !rotating;
                  setRotating(next);
                  if (next) {
                    if (resumeTimer.current !== null) {
                      window.clearTimeout(resumeTimer.current);
                      resumeTimer.current = null;
                    }
                    setInteractionPaused(false);
                  }
                }}
                title={rotating ? "Pausar rotación" : "Reanudar rotación"}
                aria-label={rotating ? "Pausar rotación" : "Reanudar rotación"}
              >
                <RotateCcw size={14} />
              </button>
              <button className="icon-button small" title="Centrar en el core" aria-label="Centrar en el core"
                onClick={() => globeRef.current?.pointOfView({ lat: DATACENTER.lat, lng: DATACENTER.lng, altitude: 1.85 }, 800)}>
                <Crosshair size={14} />
              </button>
              <button className="icon-button small" title="Pantalla completa" aria-label="Pantalla completa"
                onClick={() => containerRef.current?.requestFullscreen?.()}>
                <Maximize2 size={14} />
              </button>
            </div>
          </div>

          <div className="globe-overlay-left">
            <span className="eyebrow">Origen de ataques</span>
            <strong>{points.length} regiones activas</strong>
            <span className="globe-overlay-muted">Arcos animados hacia {DATACENTER.city}</span>
            <span className="globe-overlay-muted">{interactionPaused ? "Rotación en pausa · reanuda tras 15 s" : "Rotación automática · 0.42×"}</span>
          </div>

          <div className="globe-legend">
            <span><i style={{ background: "#ff5f7a" }} /> Crítico</span>
            <span><i style={{ background: "#ff9f5b" }} /> Alto</span>
            <span><i style={{ background: "#f5d06b" }} /> Medio</span>
            <span><i style={{ background: "#35e6c4" }} /> Bajo / core</span>
          </div>
        </>
      )}
    </div>
  );
}
