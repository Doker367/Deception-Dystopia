import { useEffect, useMemo, useRef, useState } from "react";
import Globe from "react-globe.gl";
import type { GlobeMethods } from "react-globe.gl";
import { MeshPhongMaterial } from "three";
import { Crosshair, Maximize2, Minus, Plus, RotateCcw } from "lucide-react";
import { ATTACK_ORIGINS, DATACENTER } from "../data/mock";
import type { AttackOrigin, Severity } from "../types";
import { ACCENTS, SEVERITY as SEVERITY_COLORS } from "../lib/palette";

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

// A zero-area ring breaks three-globe's triangulation: the generated buffer
// comes out corrupted and a single feature can cover the whole globe with its
// cap color (a country-sized overlay painted over everything). Degenerate
// rings are dropped before handing data to the globe.
function ringArea(ring: number[][]): number {
  if (ring.length < 4) return 0;
  let area = 0;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    area += ring[j][0] * ring[i][1] - ring[i][0] * ring[j][1];
  }
  return Math.abs(area / 2);
}

function sanitizeGeometry(geometry: unknown): unknown {
  if (!geometry || typeof geometry !== "object") return null;
  const geo = geometry as { type?: string; coordinates?: unknown };
  if (geo.type === "Polygon") {
    const rings = geo.coordinates as number[][][];
    if (!Array.isArray(rings) || !Array.isArray(rings[0]) || ringArea(rings[0]) < 1e-9) return null;
    const holes = rings.slice(1).filter((ring) => Array.isArray(ring) && ringArea(ring) >= 1e-9);
    return { ...geo, coordinates: [rings[0], ...holes] };
  }
  if (geo.type === "MultiPolygon") {
    const polygons = geo.coordinates as number[][][][];
    if (!Array.isArray(polygons)) return null;
    const kept = polygons.filter((poly) =>
      Array.isArray(poly) && Array.isArray(poly[0]) && ringArea(poly[0]) >= 1e-9);
    if (!kept.length) return null;
    return { ...geo, coordinates: kept };
  }
  return geometry;
}

function sanitizeFeature(feature: CountryFeature): CountryFeature | null {
  const geometry = sanitizeGeometry(feature.geometry);
  return geometry ? { ...feature, geometry } : null;
}

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
      }))
        .map(sanitizeFeature)
        .filter((feature): feature is CountryFeature => feature !== null);
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
  critical: SEVERITY_COLORS.critical,
  high: SEVERITY_COLORS.high,
  medium: SEVERITY_COLORS.medium,
  low: SEVERITY_COLORS.low,
  info: SEVERITY_COLORS.info,
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Crítico",
  high: "Alto",
  medium: "Medio",
  low: "Bajo",
  info: "Info",
};

// Arcos por país: mismo color para el mismo país, distinto entre países. La
// severidad se mantiene en los puntos y en la tabla para no perder esa señal.
const COUNTRY_ARC_COLORS = [
  "#e2601f", "#66afe9", "#f0ad4e", "#b39ddb", "#e982a8", "#9bd275",
  "#4dd0c4", "#f3d35b", "#ff8a65", "#7e9cf5", "#ce93d8", "#aed581",
  "#ffd54f", "#4fc3f7", "#ba68c8", "#81c784", "#ffb74d", "#9575cd",
  "#4db6ac", "#f06292",
];

function countryArcColor(countryCode: string): string {
  const key = (countryCode || "??").toUpperCase();
  let hash = 0;
  for (let index = 0; index < key.length; index += 1) {
    hash = (hash * 31 + key.charCodeAt(index)) >>> 0;
  }
  return COUNTRY_ARC_COLORS[hash % COUNTRY_ARC_COLORS.length];
}

function tooltipFor(origin: AttackOrigin, color?: string) {
  const dotColor = color ?? SEVERITY_COLOR[origin.severity];
  return `
    <div class="globe-tooltip">
      <div class="globe-tooltip-head">
        <span class="globe-tooltip-dot" style="background:${dotColor}"></span>
        <strong>${[origin.city, origin.region, origin.country].filter(Boolean).join(", ")}</strong>
        <span class="globe-tooltip-badge">${SEVERITY_LABEL[origin.severity]}</span>
        ${origin.approximate ? '<span class="globe-tooltip-badge core">Aprox.</span>' : ""}
      </div>
      <div class="globe-tooltip-row"><span>Origen</span><b class="mono">${origin.ip}</b></div>
      <div class="globe-tooltip-row"><span>Eventos</span><b>${origin.events.toLocaleString("es-MX")}</b></div>
      <div class="globe-tooltip-row"><span>Protocolo</span><b>${origin.protocol}</b></div>
      <div class="globe-tooltip-row"><span>Sensor</span><b>${origin.sensor}</b></div>
      <div class="globe-tooltip-foot"><span>Último evento</span><b>${origin.lastSeen}</b></div>
    </div>
  `;
}

function withAlpha(hex: string, alpha: number) {
  const value = hex.replace("#", "");
  const bigint = Number.parseInt(value, 16);
  const r = (bigint >> 16) & 255;
  const g = (bigint >> 8) & 255;
  const b = bigint & 255;
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
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
  const [zoomAltitude, setZoomAltitude] = useState(2.5);
  const resumeTimer = useRef<number | null>(null);
  const lastZoomAltitude = useRef(0);
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
        if (!cancelled) {
          const features = Array.isArray(world?.features) ? world.features as CountryFeature[] : [];
          setCountries(features
            .map(sanitizeFeature)
            .filter((feature): feature is CountryFeature => feature !== null));
        }
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
    // Permite acercarse hasta ~0.15 radios sobre la superficie (mucho más zoom
    // que antes) sin atravesar el globo, y alejarse para ver el mundo completo.
    controls.minDistance = 115;
    controls.maxDistance = 900;
    controls.enableDamping = true;
    controls.dampingFactor = 0.08;
    controls.zoomSpeed = 1.15;
    controls.rotateSpeed = 0.5;
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
  const activeRegions = new Set(points.filter((origin) => origin.regionCode)
    .map((origin) => `${origin.countryCode}|${origin.regionCode}`)).size;
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
  const countryColors = useMemo(() => {
    const codes = Array.from(new Set(points
      .filter((origin) => !origin.approximate)
      .map((origin) => origin.countryCode || "??"))).sort();
    return new Map(codes.map((code, index) => [
      code,
      COUNTRY_ARC_COLORS[index % COUNTRY_ARC_COLORS.length],
    ]));
  }, [points]);
  const colorFor = (origin: AttackOrigin) => origin.approximate
    ? ACCENTS.slate
    : countryColors.get(origin.countryCode) ?? countryArcColor(origin.countryCode);

  const pointData = useMemo<GlobePoint[]>(
    () => [
      ...points.map((origin) => ({
        lat: origin.lat,
        lng: origin.lng,
        kind: "origin" as const,
        origin,
        color: colorFor(origin),
        altitude: 0.018 + Math.min(origin.events / 1800, 1) * 0.08,
        radius: 0.22 + Math.min(origin.events / 1800, 1) * 0.34,
      })),
      {
        lat: DATACENTER.lat,
        lng: DATACENTER.lng,
        kind: "core",
        color: ACCENTS.cyan,
        altitude: 0.02,
        radius: 0.42,
      },
    ],
    [points, countryColors],
  );

  const arcData = useMemo<GlobeArc[]>(
    () =>
      points.map((origin) => {
        const color = colorFor(origin);
        return {
          startLat: origin.lat,
          startLng: origin.lng,
          endLat: DATACENTER.lat,
          endLng: DATACENTER.lng,
          color: [withAlpha(color, 0.05), withAlpha(color, 0.55), color],
          origin,
        };
      }),
    [points, countryColors],
  );

  const maxEvents = Math.max(...points.map((origin) => origin.events), 1);
  // Etiquetas de ciudad/estado solo al acercarse, para no saturar la vista global.
  const labelData = useMemo(() => {
    if (zoomAltitude > 0.8) return [];
    const seen = new Set<string>();
    return [...points]
      .sort((a, b) => b.events - a.events)
      .filter((origin) => {
        const text = origin.region || origin.city || origin.country;
        if (!text || seen.has(text)) return false;
        seen.add(text);
        return true;
      })
      .slice(0, 12)
      .map((origin) => ({ lat: origin.lat, lng: origin.lng, text: origin.region || origin.city || origin.country }));
  }, [points, zoomAltitude]);

  function zoomBy(factor: number) {
    const globe = globeRef.current;
    if (!globe) return;
    const pov = globe.pointOfView();
    const altitude = Math.max(0.16, Math.min(pov.altitude * factor, 8));
    globe.pointOfView({ lat: pov.lat, lng: pov.lng, altitude }, 300);
  }

  // Globo neutro cálido: el naranja OPNsense queda solo en la atmósfera, los
  // anillos y los arcos para que la actividad destaque.
  const globeMaterial = useMemo(
    () =>
      new MeshPhongMaterial({
        color: "#171412",
        emissive: "#0b0806",
        emissiveIntensity: 0.6,
        shininess: 12,
        specular: "#4a3220",
      }),
    [],
  );

  return (
    <div className={`globe-shell ${minimal ? "globe-minimal" : ""}`} ref={containerRef} style={{ height }}>
      <div className="globe-canvas" role="img"
        data-zoom={zoomAltitude.toFixed(2)}
        data-labels={labelData.length}
        aria-label={`Globo de ataques: ${points.length} ${points.length === 1 ? "origen" : "orígenes"} y ${activeRegions} ${activeRegions === 1 ? "región activa" : "regiones activas"}.`}>
        <Globe
          ref={globeRef}
          width={size.width}
          height={size.height}
          backgroundColor="#000000"
          globeMaterial={globeMaterial}
          showAtmosphere
          atmosphereColor={ACCENTS.cyan}
          atmosphereAltitude={0.16}
          showGraticules
          polygonsData={polygons}
          polygonAltitude={(feature: object) => totalForPolygon(feature as CountryFeature, areaTotals) ? 0.012 : 0.004}
          polygonCapColor={(feature: object) => {
            const total = totalForPolygon(feature as CountryFeature, areaTotals);
            if (!total) return "rgba(74, 69, 63, 0.96)";
            return withAlpha(SEVERITY_COLOR[total.severity], 0.34 + (total.events / maxEvents) * 0.42);
          }}
          polygonSideColor={() => "rgba(0, 0, 0, 0)"}
          polygonStrokeColor={(feature: object) => String((feature as CountryFeature).properties?.__layer ?? "") === "region"
            ? "rgba(255, 255, 255, 0.22)"
            : "rgba(255, 255, 255, 0.12)"}
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
              ? `<div class="globe-tooltip"><div class="globe-tooltip-head"><span class="globe-tooltip-dot" style="background:${ACCENTS.cyan}"></span><strong>${DATACENTER.name}</strong><span class="globe-tooltip-badge core">Core</span></div><div class="globe-tooltip-row"><span>Ubicación</span><b>${DATACENTER.city}, ${DATACENTER.country}</b></div><div class="globe-tooltip-foot"><span>Rol</span><b>Red señuelo</b></div></div>`
              : tooltipFor(item.origin as AttackOrigin, item.color);
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
          arcAltitudeAutoScale={0.32}
          arcStroke={0.6}
          arcDashLength={0.55}
          arcDashGap={0.12}
          arcDashAnimateTime={2200}
          arcsTransitionDuration={0}
          arcLabel={(arc: object) => {
            const item = arc as GlobeArc;
            return tooltipFor(item.origin, item.color[item.color.length - 1]);
          }}
          labelsData={labelData}
          labelLat="lat"
          labelLng="lng"
          labelText="text"
          labelSize={0.42}
          labelColor={() => "#e9e5df"}
          labelAltitude={0.02}
          labelIncludeDot={false}
          labelResolution={2}
          ringsData={[{ lat: DATACENTER.lat, lng: DATACENTER.lng }]}
          ringColor={() => "rgba(226, 96, 31, 0.38)"}
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
            controls.minDistance = 115;
            controls.maxDistance = 900;
            controls.enableDamping = true;
            controls.dampingFactor = 0.08;
            controls.zoomSpeed = 1.15;
            controls.rotateSpeed = 0.5;
          }}
          onZoom={(pov: { altitude: number }) => {
            if (Math.abs(pov.altitude - lastZoomAltitude.current) > 0.08) {
              lastZoomAltitude.current = pov.altitude;
              setZoomAltitude(pov.altitude);
            }
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
              <button className="icon-button small" title="Acercar" aria-label="Acercar mapa"
                onClick={() => zoomBy(0.62)}>
                <Plus size={14} />
              </button>
              <button className="icon-button small" title="Alejar" aria-label="Alejar mapa"
                onClick={() => zoomBy(1.6)}>
                <Minus size={14} />
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
            <span className="globe-overlay-muted">{interactionPaused ? "Rotación en pausa · reanuda tras 15 s" : "Rotación automática · rueda o botones para zoom"}</span>
          </div>

          <div className="globe-legend">
            <span><i style={{ background: `linear-gradient(90deg, ${COUNTRY_ARC_COLORS.join(", ")})` }} /> País (punto/arco)</span>
            <span><i style={{ background: SEVERITY_COLORS.critical }} /> Crítico</span>
            <span><i style={{ background: SEVERITY_COLORS.high }} /> Alto</span>
            <span><i style={{ background: SEVERITY_COLORS.medium }} /> Medio</span>
            <span><i style={{ background: SEVERITY_COLORS.low }} /> Bajo / core</span>
          </div>
        </>
      )}
    </div>
  );
}
