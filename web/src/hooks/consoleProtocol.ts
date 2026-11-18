/* Protocolo y constantes del puente WebSocket de la consola (Fase 11).

   Frame types (unidad: texto del WebSocket control):
     - Entrada del usuario:     "ls\r\n"                 → stdin del PTY
     - Frame de control:        {"type":"resize",...}    → ioctl TIOCSWINSZ
     - Frame de error (server): "\0ERR:<mensaje>"        → banner + cierre

   Los limites de tamaño del PTY y el gate de admin los refuerza
   app/services/fabric/console_svc.py. */

/** Prefijo de los frames de control del backend (gate fallido). */
export const ERROR_PREFIX = "\u0000ERR:";

/** Retardo base del backoff exponencial de reconexión (ms). */
export const BACKOFF_BASE_MS = 600;
/** Tope del backoff (ms). */
export const BACKOFF_MAX_MS = 6000;
/** Máximo de intentos automáticos antes de rendirse. */
export const MAX_ATTEMPTS = 5;
/** Debounce del resize del terminal (ms). */
export const RESIZE_DEBOUNCE_MS = 120;

/** Límites de tamaño del PTY (clamp en el servidor y en el cliente). */
export const PTY_MIN_COLS = 20;
export const PTY_MAX_COLS = 500;
export const PTY_MIN_ROWS = 5;
export const PTY_MAX_ROWS = 200;

/** Estado de una sesión de consola. */
export type ConsoleStatus =
  | "connecting"
  | "open"
  | "reconnecting"
  | "error"
  | "closed";

/** Estado completo imperativo de la sesión. */
export interface ConsoleState {
  status: ConsoleStatus;
  /** Último mensaje de error (en español); null cuando no lo hay. */
  error: string | null;
  /** Intento de reconexión en curso (0 = conexión inicial). */
  attempt: number;
  /** Epoch (ms) del próximo intento automático; null si no hay. */
  nextRetryAt: number | null;
}

/** Mensajes de error predefinidos en español. */
export const CONSOLE_ERRORS = {
  generic: "No se pudo abrir la consola (verifica el rol admin y que la sesión sea válida)",
  network: "Se perdió la conexión con la consola",
  disabled: "Consola deshabilitada: exporta DYSTOPIA_FABRIC_CONSOLE_ENABLED=true (fail-closed)",
  notDeployed: "El fabric no está desplegado; no hay consola disponible",
  unknownDevice: "Dispositivo de fabric no encontrado",
  noContainer: "El dispositivo no tiene contenedor asociado",
  maxSessions: "Máximo de consolas concurrentes alcanzado",
  perDevice: "Ya hay una consola activa para este dispositivo; ciérrala antes de abrir otra",
  reconnectFailed: "No se pudo reconectar con la consola",
} as const;

/** Etiquetas visibles para el chip de estado. */
export const STATUS_LABEL: Record<ConsoleStatus, string> = {
  connecting: "conectando…",
  open: "abierta",
  reconnecting: "reconectando",
  error: "con errores",
  closed: "cerrada",
};

/** Construye la URL del WebSocket de consola (token en el query). */
export function buildConsoleWsUrl(deviceId: string, cols: number, rows: number): string {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const token = window.localStorage.getItem("dystopia.access_token") ?? "";
  const base = proto + "://" + window.location.host;
  const path = "/api/fabric/devices/" + encodeURIComponent(deviceId) + "/console/ws";
  const query = [
    "token=" + encodeURIComponent(token),
    "cols=" + String(Math.max(PTY_MIN_COLS, Math.min(cols, PTY_MAX_COLS))),
    "rows=" + String(Math.max(PTY_MIN_ROWS, Math.min(rows, PTY_MAX_ROWS))),
  ].join("&");
  return base + path + "?" + query;
}
