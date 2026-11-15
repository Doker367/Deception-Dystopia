// ─────────────────────────────────────────────────────────────────────────────
// Paleta Dystopia — única fuente de verdad de color en TypeScript.
// Los equivalentes CSS viven en `web/src/styles.css` (bloques :root y
// [data-theme="light"]). Si cambias un valor aquí, cambia su gemelo allí.
//
// Los acentos se usan tal cual sobre lienzos oscuros (globo, canvas). Para
// superficies blancas, `inkAccent()` de `theme.ts` devuelve su variante de
// tinta con más contraste.
// ─────────────────────────────────────────────────────────────────────────────

/** Acentos por rol. Cada rol tiene UNA tonalidad en todo el proyecto. */
export const ACCENTS = {
  /** Marca, positivo y datos principales: naranja OPNsense. */
  cyan: "#e2601f",
  /** Información, geografía y opencanary. */
  blue: "#66afe9",
  /** Advertencia, perimetral, dionaea. */
  amber: "#f0ad4e",
  /** Datos secundarios, heralding, impresora. */
  violet: "#b39ddb",
  /** Descartes, redishoneypot. */
  pink: "#e982a8",
  /** Peligro de la interfaz (botones/estados destructivos). */
  red: "#f05050",
  /** Éxito, cámara. */
  green: "#9bd275",
  /** Neutro de series ("Otros"). */
  slate: "#8b959c",
} as const;

/** Rampa de severidad de eventos (crítico → info). */
export const SEVERITY = {
  critical: "#f05050",
  high: "#f0ad4e",
  medium: "#f3d35b",
  low: ACCENTS.cyan,
  info: ACCENTS.blue,
} as const;

/** Color por sensor (orden de series en las gráficas). */
export const SENSORS = {
  cowrie: ACCENTS.cyan,
  opencanary: ACCENTS.blue,
  dionaea: ACCENTS.amber,
  heralding: ACCENTS.violet,
  redishoneypot: ACCENTS.pink,
  endlessh: ACCENTS.green,
} as const;

/** Colores por protocolo; las claves en minúscula cubren los datos reales. */
export const PROTOCOLS: Record<string, string> = {
  SSH: ACCENTS.cyan,
  HTTP: ACCENTS.blue,
  SMB: ACCENTS.amber,
  RDP: ACCENTS.violet,
  Redis: ACCENTS.pink,
  Otros: ACCENTS.slate,
  Telnet: ACCENTS.amber,
  HTTPS: ACCENTS.blue,
  ssh: ACCENTS.cyan,
  http: ACCENTS.blue,
  telnet: ACCENTS.amber,
  smb: ACCENTS.amber,
  rdp: ACCENTS.violet,
  redis: ACCENTS.pink,
};

/** Serie alternativa cuando no hay un mapeo semántico. */
export const SERIES = [
  ACCENTS.cyan,
  ACCENTS.blue,
  ACCENTS.amber,
  ACCENTS.violet,
  ACCENTS.pink,
  ACCENTS.slate,
] as const;

/** Tono del perfil de dispositivo (nodos de topología y fichas). */
export const PROFILES = {
  server: ACCENTS.cyan,
  switch: ACCENTS.blue,
  router: ACCENTS.amber,
  printer: ACCENTS.violet,
  camera: ACCENTS.green,
  firewall: ACCENTS.red,
  pc: "#cfccc6",
} as const;

/** Aplica alfa a un color hex (#rrggbb) devolviendo rgba(). */
export function withAlpha(hex: string, alpha: number): string {
  const value = hex.replace("#", "");
  if (value.length !== 6) return hex;
  const r = Number.parseInt(value.slice(0, 2), 16);
  const g = Number.parseInt(value.slice(2, 4), 16);
  const b = Number.parseInt(value.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}
