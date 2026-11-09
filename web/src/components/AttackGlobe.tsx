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
  const [states, setStates] = useState<CountryFeature[]>([]);
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

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      fetch(`${import.meta.env.BASE_URL}world.geo.json`).then((response) => response.json()),
      // Si falta el GeoJSON de estados, se conserva el polígono de EE. UU.
      fetch(`${import.meta.env.BASE_URL}us-states.geo.json`).then((response) => response.json()).catch(() => ({ features: [] })),
    ])
      .then(([world, us]) => {
        if (cancelled) return;
        const stateFeatures = Array.isArray(us?.features) ? (us.features as CountryFeature[]) : [];
        setStates(stateFeatures.map((feature) => ({
          ...feature,
          properties: { ...feature.properties, __layer: "state" },
        })));
        const countryFeatures = Array.isArray(world?.features) ? (world.features as CountryFeature[]) : [];
        setCountries(stateFeatures.length
          ? countryFeatures.filter((feature) => String(feature.properties?.ISO_A2 ?? "") !== "US")
          : countryFeatures);
      })
      .catch(() => {
        if (!cancelled) { setCountries([]); setStates([]); }
      });
    return () => {
      cancelled = true;
    };
  }, []);

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

  const polygons = useMemo(() => [...countries, ...states], [countries, states]);
  const activeStates = new Set(points.filter((origin) => origin.countryCode === "US" && origin.regionCode)
    .map((origin) => origin.regionCode)).size;
  const areaTotals = useMemo(() => {
    const byCountry = new Map<string, { events: number; severity: Severity }>();
    const byState = new Map<string, { events: number; severity: Severity }>();
    const rank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    for (const origin of points) {
      const isState = origin.countryCode === "US" && Boolean(origin.regionCode);
      const target = isState ? byState : byCountry;
      const key = isState ? String(origin.regionCode) : origin.countryCode;
      const current = target.get(key);
      if (!current) {
        target.set(key, { events: origin.events, severity: origin.severity });
      } else {
        current.events += origin.events;
        if (rank[origin.severity] > rank[current.severity]) current.severity = origin.severity;
      }
    }
    return { byCountry, byState };
  }, [points]);
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
      <div className="globe-canvas" role="img"
        aria-label={`Globo de ataques: ${points.length} ${points.length === 1 ? "origen" : "orígenes"} y ${activeStates} ${activeStates === 1 ? "estado activo" : "estados activos"} de Estados Unidos.`}>
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
          polygonAltitude={(feature: object) => {
            const properties = (feature as CountryFeature).properties ?? {};
            const active = properties.__layer === "state"
              ? areaTotals.byState.has(String(properties.code ?? ""))
              : areaTotals.byCountry.has(String(properties.ISO_A2 ?? ""));
            return active ? 0.012 : 0.004;
          }}
          polygonCapColor={(feature: object) => {
            const properties = (feature as CountryFeature).properties ?? {};
            const isState = properties.__layer === "state";
            const total = isState
              ? areaTotals.byState.get(String(properties.code ?? ""))
              : areaTotals.byCountry.get(String(properties.ISO_A2 ?? ""));
            if (!total) return "rgba(17, 34, 46, 0.82)";
            return withAlpha(SEVERITY_COLOR[total.severity], 0.34 + (total.events / maxEvents) * 0.42);
          }}
          polygonSideColor={() => "rgba(0, 0, 0, 0)"}
          polygonStrokeColor={(feature: object) => String((feature as CountryFeature).properties?.__layer ?? "") === "state"
            ? "rgba(91, 184, 190, 0.3)"
            : "rgba(91, 184, 190, 0.18)"}
          polygonLabel={(feature: object) => {
            const properties = (feature as CountryFeature).properties ?? {};
            const isState = properties.__layer === "state";
            const total = isState
              ? areaTotals.byState.get(String(properties.code ?? ""))
              : areaTotals.byCountry.get(String(properties.ISO_A2 ?? ""));
            const name = isState
              ? String(properties.name ?? properties.code ?? "Estado")
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
