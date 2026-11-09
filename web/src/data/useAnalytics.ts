import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ATTACK_ORIGINS,
  EVENTS,
  HONEYPOTS,
  PROTOCOLS,
  TIME_RANGES,
  VOLUME_SERIES,
} from "../data/mock";
import type { AttackOrigin, EventRow, Severity } from "../types";
import { apiGet, getToken } from "../lib/api";
import { relativeTime } from "../lib/format";

const HOURS: Record<string, number> = { "24h": 24, "7d": 168, "30d": 720, "90d": 2160 };
const INTERVAL: Record<string, string> = { "24h": "1h", "7d": "6h", "30d": "1d", "90d": "1d" };

interface ApiOverview {
  total_events: number;
  unique_sources: number;
  alerts: number;
  max_severity: Severity;
  latest_event: string | null;
  protocols: Array<{ name: string; value: number }>;
  datasets: Array<{ name: string; value: number }>;
}

interface ApiTimeline {
  interval: string;
  buckets: Array<{ at: string; count: number }>;
}

interface ApiOrigin {
  countryCode: string;
  country: string;
  region?: string;
  regionCode?: string;
  city: string;
  ip: string;
  lat: number | null;
  lng: number | null;
  events: number;
  uniqueSources: number;
  severity: Severity;
  protocol: string;
  sensor: string;
  lastEvent: string | null;
}

interface ApiOrigins {
  origins: ApiOrigin[];
}

interface ApiEvents {
  total: number;
  items: Array<{
    id: string;
    timestamp: string;
    sensor: string;
    device: string;
    source: string;
    country: string;
    countryCode: string;
    kind: string;
    proto: string;
    port: number | null;
    dst_ip?: string;
    dst_port?: number | null;
    action: string;
    severity: Severity;
    message: string;
  }>;
}

export interface AnalyticsOverview {
  totalEvents: number;
  uniqueSources: number;
  alerts: number;
  protocols: Array<{ name: string; value: number }>;
  datasets: Array<{ name: string; value: number }>;
  latestEvent: string | null;
}

export interface TimelinePoint {
  label: string;
  count: number;
}

export type DataMode = "demo" | "live" | "error";

export interface AnalyticsSnapshot {
  mode: DataMode;
  loading: boolean;
  error: string | null;
  overview: AnalyticsOverview;
  timeline: TimelinePoint[];
  origins: AttackOrigin[];
  events: EventRow[];
  totalEvents: number;
  collectorHealth: CollectorHealth | null;
  refresh: () => void;
}

export type CollectorStatus = "ok" | "stale" | "missing";

export interface CollectorHealth {
  status: CollectorStatus;
  lastPollAt: string | null;
  ageSeconds: number | null;
  polls: number | null;
}

interface ApiAnalyticsHealth {
  collector?: {
    status?: string;
    last_poll_at?: string | null;
    age_seconds?: number | null;
    polls?: number | null;
  };
}

export const DEMO_OVERVIEW: AnalyticsOverview = {
  totalEvents: 12_847,
  uniqueSources: 1_204,
  alerts: 17,
  protocols: PROTOCOLS.map((item) => ({ name: item.name, value: item.value })),
  datasets: HONEYPOTS.map((item) => ({ name: item.id, value: item.events })),
  latestEvent: null,
};

const EMPTY_OVERVIEW: AnalyticsOverview = {
  totalEvents: 0,
  uniqueSources: 0,
  alerts: 0,
  protocols: [],
  datasets: [],
  latestEvent: null,
};

function windowFor(range: string) {
  const to = new Date();
  const hours = HOURS[range] ?? 24;
  const from = new Date(to.getTime() - hours * 60 * 60 * 1000);
  return { from: from.toISOString(), to: to.toISOString(), interval: INTERVAL[range] ?? "1h" };
}

function labelFor(iso: string, range: string) {
  const date = new Date(iso);
  if (range === "24h") {
    return new Intl.DateTimeFormat("es-MX", { hour: "2-digit", minute: "2-digit", hour12: false }).format(date);
  }
  if (range === "7d") {
    return new Intl.DateTimeFormat("es-MX", { weekday: "short", hour: "2-digit", hour12: false }).format(date);
  }
  return new Intl.DateTimeFormat("es-MX", { day: "2-digit", month: "short" }).format(date);
}

function demoOrigins(): AttackOrigin[] {
  return ATTACK_ORIGINS;
}

function demoEvents(): EventRow[] {
  return EVENTS;
}

function demoTimeline(range: string): TimelinePoint[] {
  const series = (VOLUME_SERIES as Record<string, number[]>)[range] ?? VOLUME_SERIES["24h"];
  return series.map((count, index) => ({
    label: range === "24h" ? `${String(index).padStart(2, "0")}:00` : `P-${index + 1}`,
    count,
  }));
}

function normalizeOrigins(payload: ApiOrigins): AttackOrigin[] {
  return payload.origins.flatMap((origin, index) => {
    const fallback = ATTACK_ORIGINS.find((item) => item.countryCode === origin.countryCode);
    const lat = typeof origin.lat === "number" ? origin.lat : fallback?.lat;
    const lng = typeof origin.lng === "number" ? origin.lng : fallback?.lng;
    if (typeof lat !== "number" || typeof lng !== "number") return [];
    return [{
      id: `${origin.countryCode}-${origin.regionCode || index}`,
      country: origin.country || fallback?.country || origin.countryCode,
      countryCode: origin.countryCode || fallback?.countryCode || "??",
      region: origin.region || "",
      regionCode: origin.regionCode || "",
      city: origin.city || fallback?.city || "",
      ip: origin.ip || fallback?.ip || "—",
      lat,
      lng,
      events: origin.events,
      uniqueSources: origin.uniqueSources,
      severity: origin.severity,
      protocol: origin.protocol || fallback?.protocol || "—",
      sensor: origin.sensor || fallback?.sensor || "—",
      lastSeen: origin.lastEvent ? relativeTime(origin.lastEvent) : "sin dato",
    }];
  });
}

function normalizeEvents(payload: ApiEvents): EventRow[] {
  return payload.items.map((event) => ({
    ...event,
    port: event.port ?? 0,
    message: event.message || "Evento normalizado del almacén local",
  }));
}

export function useAnalytics(range: string): AnalyticsSnapshot {
  const [nonce, setNonce] = useState(0);
  const [mode, setMode] = useState<DataMode>(() => (getToken() ? "live" : "demo"));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Arrancamos vacío: los datos de demostración solo se usan sin sesión,
  // nunca como relleno mientras se carga la sesión real.
  const [overview, setOverview] = useState<AnalyticsOverview>(EMPTY_OVERVIEW);
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [origins, setOrigins] = useState<AttackOrigin[]>([]);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [totalEvents, setTotalEvents] = useState(0);
  const [collectorHealth, setCollectorHealth] = useState<CollectorHealth | null>(null);

  const refresh = useCallback(() => setNonce((value) => value + 1), []);

  // Refresco automático: sin esto la vista solo cambia al pulsar el botón.
  useEffect(() => {
    const timer = window.setInterval(() => setNonce((value) => value + 1), 15_000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (mode !== "live") {
      setCollectorHealth(null);
      return;
    }
    let cancelled = false;
    const controller = new AbortController();
    const load = () => {
      apiGet<ApiAnalyticsHealth>("/api/analytics/health", controller.signal)
        .then((payload) => {
          if (cancelled) return;
          const collector = payload.collector;
          const status: CollectorStatus =
            collector?.status === "ok" || collector?.status === "stale" ? collector.status : "missing";
          setCollectorHealth({
            status,
            lastPollAt: collector?.last_poll_at ?? null,
            ageSeconds: collector?.age_seconds ?? null,
            polls: collector?.polls ?? null,
          });
        })
        .catch(() => {
          if (!cancelled) {
            setCollectorHealth({ status: "missing", lastPollAt: null, ageSeconds: null, polls: null });
          }
        });
    };
    load();
    const timer = window.setInterval(load, 30_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
      controller.abort();
    };
  }, [mode, nonce]);

  useEffect(() => {
    const token = getToken();
    if (!token) {
      setMode("demo");
      setLoading(false);
      setError(null);
      setOverview(DEMO_OVERVIEW);
      setOrigins(demoOrigins());
      setEvents(demoEvents());
      setTotalEvents(DEMO_OVERVIEW.totalEvents);
      setTimeline(demoTimeline(range));
      return;
    }

    const controller = new AbortController();
    const { from, to, interval } = windowFor(range);
    const query = `from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`;
    setLoading(true);
    setError(null);

    Promise.all([
      apiGet<ApiOverview>(`/api/analytics/overview?${query}`, controller.signal),
      apiGet<ApiTimeline>(`/api/analytics/timeline?${query}&interval=${interval}`, controller.signal),
      apiGet<ApiOrigins>(`/api/analytics/origins?${query}&limit=50`, controller.signal),
      apiGet<ApiEvents>(`/api/analytics/events?${query}&limit=100`, controller.signal),
    ])
      .then(([overviewPayload, timelinePayload, originsPayload, eventsPayload]) => {
        if (controller.signal.aborted) return;
        setMode("live");
        setOverview({
          totalEvents: overviewPayload.total_events,
          uniqueSources: overviewPayload.unique_sources,
          alerts: overviewPayload.alerts,
          protocols: overviewPayload.protocols,
          datasets: overviewPayload.datasets,
          latestEvent: overviewPayload.latest_event,
        });
        setTimeline(
          timelinePayload.buckets.map((bucket) => ({ label: labelFor(bucket.at, range), count: bucket.count })),
        );
        setOrigins(normalizeOrigins(originsPayload));
        setEvents(normalizeEvents(eventsPayload));
        setTotalEvents(eventsPayload.total || overviewPayload.total_events);
      })
      .catch((cause: unknown) => {
        if (controller.signal.aborted) return;
        setMode("error");
        setError(cause instanceof Error ? cause.message : "No se pudo consultar el BFF analítico");
        setOverview(DEMO_OVERVIEW);
        setOrigins(demoOrigins());
        setEvents(demoEvents());
        setTotalEvents(DEMO_OVERVIEW.totalEvents);
        setTimeline(demoTimeline(range));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });

    return () => controller.abort();
  }, [nonce, range]);

  return useMemo(
    () => ({ mode, loading, error, overview, timeline, origins, events, totalEvents, collectorHealth, refresh }),
    [mode, loading, error, overview, timeline, origins, events, totalEvents, collectorHealth, refresh],
  );
}

export const RANGE_OPTIONS = TIME_RANGES;
