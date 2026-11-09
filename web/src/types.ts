export type PageId =
  | "overview"
  | "map"
  | "events"
  | "honeypots"
  | "devices"
  | "ingest"
  | "admin";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface AttackOrigin {
  id: string;
  country: string;
  countryCode: string;
  /** Estado/provincia cuando GeoIP lo conoce (p. ej. California). */
  region?: string;
  /** Código ISO 3166-2 sin prefijo de país (p. ej. CA). */
  regionCode?: string;
  city: string;
  ip: string;
  lat: number;
  lng: number;
  events: number;
  uniqueSources: number;
  severity: Severity;
  protocol: string;
  sensor: string;
  lastSeen: string;
}

export interface EventRow {
  id: string;
  timestamp: string;
  sensor: string;
  device: string;
  source: string;
  country: string;
  countryCode: string;
  kind: string;
  proto: string;
  port: number;
  action: string;
  severity: Severity;
  message: string;
}

export interface Honeypot {
  id: string;
  name: string;
  service: string;
  status: "healthy" | "degraded" | "offline";
  port: number;
  events: number;
  uniqueSources: number;
  lastSeen: string;
  uptime: string;
  trend: number[];
  color: string;
}

export interface TimeRangeOption {
  id: string;
  label: string;
  short: string;
  from: string;
}

export interface HoneypotConfig {
  id: string;
  container: string;
  image: string;
  device: string;
  description: string;
  user: string;
  configFile: string;
  configTarget: string;
  logPath: string;
  logFormat: string;
  ports: Array<{ container: number; proto: string; purpose: string; host?: number }>;
  volumes: string[];
  healthcheck: { type: string; marker: string; interval: string; startPeriod: string };
  resources: { memLimit: string; cpus: string; pidsLimit: number; nofile: number; tmpfsMib: number };
}
