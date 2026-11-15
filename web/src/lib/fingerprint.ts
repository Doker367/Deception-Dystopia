/** Utilidades compartidas para interpretar la huella del navegador. */

export interface BrowserFingerprint {
  client: Record<string, unknown>;
  headers: Record<string, string>;
  raw: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function text(value: unknown): string {
  return value === null || value === undefined || value === "" ? "" : String(value);
}

export function parseFingerprintValue(raw: string): BrowserFingerprint | null {
  try {
    const parsed = JSON.parse(raw) as { client?: unknown; headers?: unknown };
    const client = typeof parsed.client === "string" ? JSON.parse(parsed.client) as unknown : parsed.client;
    if (!isRecord(client)) return null;
    const headers: Record<string, string> = {};
    if (isRecord(parsed.headers)) {
      for (const [key, value] of Object.entries(parsed.headers)) {
        if (typeof value === "string") headers[key] = value;
      }
    }
    return { client, headers, raw };
  } catch {
    return null;
  }
}

export function fingerprintScore(fingerprint: BrowserFingerprint): number {
  return Object.values(fingerprint.client).filter((value) =>
    value !== null && value !== undefined && value !== "" &&
    !(typeof value === "object" && !Object.keys(value as object).length)
  ).length;
}

export function bestFingerprint(
  items: Array<{ detail?: Record<string, unknown> }>,
  preferred?: string | null,
): BrowserFingerprint | null {
  // El backend entrega la mejor baliza de la IP aunque ya no esté en la
  // página de 50 eventos; así la huella no desaparece con la actividad.
  const candidates: BrowserFingerprint[] = [];
  if (preferred) {
    const parsed = parseFingerprintValue(preferred);
    if (parsed) candidates.push(parsed);
  }
  for (const item of items) {
    const raw = item.detail?.fingerprint;
    if (typeof raw !== "string") continue;
    const parsed = parseFingerprintValue(raw);
    if (parsed) candidates.push(parsed);
  }
  if (!candidates.length) return null;
  return candidates.reduce((best, candidate) =>
    fingerprintScore(candidate) > fingerprintScore(best) ? candidate : best
  );
}

export function formatBattery(value: unknown): string {
  if (!isRecord(value)) return "No disponible";
  const level = typeof value.level === "number" ? `${value.level}%` : null;
  const charging = typeof value.charging === "boolean" ? value.charging : null;
  const parts: Array<string | null> = [
    level,
    charging === null ? null : charging ? "cargando" : "descargando",
  ];
  if (charging === true && typeof value.chargingTime === "number" && value.chargingTime > 0) {
    parts.push(`llena en ${Math.round(value.chargingTime / 60)} min`);
  }
  if (charging === false && typeof value.dischargingTime === "number" && value.dischargingTime > 0) {
    parts.push(`autonomía ${Math.round(value.dischargingTime / 60)} min`);
  }
  return parts.filter(Boolean).join(" · ") || "No disponible";
}

export function formatStorage(value: unknown): string {
  if (!isRecord(value)) return "—";
  const quota = typeof value.quota_mb === "number" ? `${value.quota_mb} MB disponibles` : "";
  const usage = typeof value.usage_mb === "number" ? `${value.usage_mb} MB usados` : "";
  return [quota, usage].filter(Boolean).join(" · ") || "—";
}

export interface FingerprintFact {
  label: string;
  value: string;
  mono?: boolean;
}

export function fingerprintFacts(fingerprint: BrowserFingerprint): FingerprintFact[] {
  const client = fingerprint.client;
  const flags = fingerprint.headers;
  const arch = [text(client.arch), text(client.bitness) ? `${text(client.bitness)} bits` : ""]
    .filter(Boolean).join(" · ");
  const gpu = [text(client.gpuVendor), text(client.webgl)].filter(Boolean).join(" · ");
  const connection = isRecord(client.connection)
    ? [
        text(client.connection.type),
        typeof client.connection.down === "number" ? `${client.connection.down} Mbps` : "",
        typeof client.connection.rtt === "number" ? `${client.connection.rtt} ms` : "",
      ].filter(Boolean).join(" · ")
    : "";
  const mobile = typeof client.mobile === "boolean" ? (client.mobile ? "móvil" : "escritorio") : "";
  const model = [text(client.model), mobile].filter(Boolean).join(" · ");

  return [
    { label: "Sistema operativo", value: [text(client.os || client.platform), text(client.osVersion)].filter(Boolean).join(" · ") || "—" },
    { label: "Arquitectura", value: arch || "—" },
    { label: "Modelo / tipo", value: model || "—" },
    { label: "CPU", value: client.cores != null ? `${text(client.cores)} hilos` : "—" },
    { label: "RAM estimada", value: client.ram_gb != null || client.memory != null ? `${text(client.ram_gb ?? client.memory)} GB` : "—" },
    { label: "Táctil", value: client.touchscreen ? `Sí · ${text(client.touch ?? 0)} puntos simultáneos` : "No" },
    { label: "Batería", value: formatBattery(client.battery) },
    { label: "Pantalla", value: [text(client.screen), text(client.viewport) ? `viewport ${text(client.viewport)}` : "", text(client.dpr) ? `DPR ${text(client.dpr)}` : ""].filter(Boolean).join(" · ") || "—" },
    { label: "GPU / WebGL", value: gpu || "—" },
    { label: "Almacenamiento", value: formatStorage(client.storage) },
    { label: "Zona / idioma", value: [text(client.tz), text(client.languages || client.lang)].filter(Boolean).join(" · ") || "—" },
    { label: "Automatización", value: `webdriver: ${text(client.webdriver) || "—"} · cookies: ${text(client.cookie) || "—"}` },
    { label: "Client hints", value: [text(flags["sec-ch-ua"] || client.brands), text(flags["sec-ch-ua-mobile"] ?? client.mobile)].filter(Boolean).join(" · ") || "—" },
    { label: "Conexión", value: connection || "—" },
    { label: "User-Agent", value: text(client.ua) || "—", mono: true },
  ];
}
