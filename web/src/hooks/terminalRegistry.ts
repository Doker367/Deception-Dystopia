/* Registro de terminales xterm activos (uno por dispositivo señaluelo).

   El xterm de la consola del fabric se crea UNA vez por (dispositivo, pestaña)
   y se guarda aquí para que el hook de sesión pueda escribir en él sin
   seguir de re-renders de React. Al desmontar el drawer se destruye. */
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { ClipboardAddon } from "@xterm/addon-clipboard";

const terminals = new Map<string, Terminal>();
const addons = new Map<string, FitAddon>();

/** Tema del terminal (paleta Dystopia, fondo de la consola). */
const TERM_THEME = {
  background: "#101418",
  foreground: "#d8e0ea",
  cursor: "#7ad7be",
} as const;

/** Crea (o devuelve) el terminal del dispositivo. */
export function mountTerminal(deviceId: string, host: HTMLElement, cols: number, rows: number): Terminal | null {
  const existing = terminals.get(deviceId);
  if (existing !== undefined) return existing;

  const term = new Terminal({
    cursorBlink: true,
    fontSize: 13,
    fontFamily: "'JetBrains Mono', ui-monospace, monospace",
    scrollback: 10000,
    theme: TERM_THEME,
    allowProposedApi: true,
  });
  const fit = new FitAddon();
  const clipboard = new ClipboardAddon();
  term.loadAddon(fit);
  term.loadAddon(clipboard);
  try { term.open(host); } catch { return null; }
  try { term.resize(cols, rows); } catch { /* el host aún no tiene tamaño */ }
  terminals.set(deviceId, term);
  addons.set(deviceId, fit);
  return term;
}

/** Devuelve el terminal del dispositivo (o undefined si no está montado). */
export function getTerminal(deviceId: string): Terminal | undefined {
  return terminals.get(deviceId);
}

/** Devuelve el FitAddon del terminal. */
export function getAddon(deviceId: string): FitAddon | undefined {
  return addons.get(deviceId);
}

/** Libera el terminal del dispositivo (y sus addons). */
export function unmountTerminal(deviceId: string): void {
  const term = terminals.get(deviceId);
  if (term === undefined) return;
  try { term.dispose(); } catch { /* ya dispuesto */ }
  terminals.delete(deviceId);
  addons.delete(deviceId);
}

/** Libera todos los terminales (en unload de la página). */
export function disposeAll (): void {
  terminals.forEach((term) => {
    try { term.dispose(); } catch { /* ya dispuesto */ }
  });
  terminals.clear();
  addons.clear();
}
