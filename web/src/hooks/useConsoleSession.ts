/* Hook de sesión de consola interactiva del fabric (Fase 11).

   Encapsula el ciclo de vida completo de un terminal interactivo:

       navegador ── ws ── control ── docker exec ── contenedor señuelo

   - Conexión con token JWT en el query (los navegadores no fijan headers
     en el handshake WS); el router autentica y aplica los gates.
   - Reconexión automática con backoff exponencial y cuenta atrás.
   - Resize del xterm propagado al PTY (``TIOCSWINSZ``) con debounce.
   - Copiar/pegar (selección nativa) y limpiar pantalla (Ctrl+L en el
     shell; Ctrl+C lo maneja el propio PTY como SIGINT).
   - Los frames ``\0ERR:<mensaje>`` del backend se muestran como banner
     en español y corresponden a un cierre del control (fail-closed).

   Los límites del backend (cuota de sesiones, per-device, idle y edad
   máxima) los refuerza ``app/services/fabric/console_svc.py``. */
import { useCallback, useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import type { DeviceConsoleState } from "../types";

import {
  BACKOFF_BASE_MS,
  BACKOFF_MAX_MS,
  buildConsoleWsUrl,
  CONSOLE_ERRORS,
  ERROR_PREFIX,
  MAX_ATTEMPTS,
  RESIZE_DEBOUNCE_MS,
} from "./consoleProtocol";
import { getAddon, mountTerminal, unmountTerminal } from "./terminalRegistry";

/** Estado semilla de una sesión nueva. */
export const BLANK_STATE: DeviceConsoleState = {
  status: "connecting", error: null, attempt: 0, nextRetryAt: null,
};

/** Parámetros del hook de sesión. */
export interface UseConsoleSessionProps {
  deviceId: string;
  /** Notifica el estado fresco de la sesión al panel de chips del padre. */
  onState: (deviceId: string, state: DeviceConsoleState) => void;
  /** El padre cierra el drawer (o el servidor terminó la sesión). */
  onClose: () => void;
}

/** Lo que expone el hook; lo consume el componente de presentación. */
export interface ConsoleSessionApi {
  /** ref del nodo DOM donde se monta el xterm. */
  hostRef: React.RefObject<HTMLDivElement | null>;
  /** Estado completo de la sesión (copia inmutable). */
  state: DeviceConsoleState;
  /** Cierra la consola (y libera recursos). */
  close: () => void;
  /** Reintento manual del usuario. */
  reconnect: () => void;
  /** Escribe texto en el shell. */
  sendInput: (data: string) => void;
  /** Redimensiona el PTY tras un cambio del xterm. */
  sendResize: (cols: number, rows: number) => void;
  /** Limpia el terminal (Ctrl+L). */
  clearScreen: () => void;
  /** Copia la selección al portapapeles. */
  copySelection: () => void;
  /** Pega el portapapeles en el terminal. */
  paste: () => void;
  /** Enfoca el terminal (teclado listo). */
  focus: () => void;
  /** Estado actual (espejo para render). */
  status: DeviceConsoleState["status"];
  /** Último error legible (banner); null si no hay. */
  error: string | null;
  /** Intento de reconexión (0 = conexión inicial). */
  attempt: number;
  /** Segundos hasta el próximo intento; null si no hay pendiente. */
  retryIn: number | null;
}

const RETRY_TICK_MS = 100;

export function useConsoleSession(props: UseConsoleSessionProps): ConsoleSessionApi {
  const { deviceId, onState, onClose } = props;

  /* ── Estado imperativo (la única fuente de verdad) ──────── */
  const stateRef = useRef<DeviceConsoleState>({ ...BLANK_STATE });
  const [state, setState] = useState<DeviceConsoleState>(stateRef.current);
  const [retryIn, setRetryIn] = useState<number | null>(null);

  /* ── Objetos vivos de la sesión ─────────────────────────── */
  const hostRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const observerRef = useRef<ResizeObserver | null>(null);
  const retryTimerRef = useRef<number | null>(null);
  const tickTimerRef = useRef<number | null>(null);
  const fitTimerRef = useRef<number | null>(null);
  const attemptRef = useRef(0);
  const nextRetryAtRef = useRef<number | null>(null);
  const mountedRef = useRef(true);

  /* ── Callbacks frescos del padre, envueltos en refs estables ── */
  const onStateRef = useRef(onState);
  const onCloseRef = useRef(onClose);
  onStateRef.current = onState;
  onCloseRef.current = onClose;

  /* ── Único punto de mutación del estado ─────────────────── */
  const update = useCallback((patch: Partial<DeviceConsoleState>) => {
    const next = { ...stateRef.current, ...patch };
    stateRef.current = next;
    onStateRef.current(deviceId, next);
    setState(next);
  }, [deviceId]);

  /* ── Corta el WS y cancela los temporizadores ───────────── */
  const disconnect = useCallback(() => {
    if (retryTimerRef.current !== null) {
      window.clearTimeout(retryTimerRef.current);
      retryTimerRef.current = null;
    }
    if (tickTimerRef.current !== null) {
      window.clearInterval(tickTimerRef.current);
      tickTimerRef.current = null;
    }
    if (fitTimerRef.current !== null) {
      window.clearTimeout(fitTimerRef.current);
      fitTimerRef.current = null;
    }
    if (observerRef.current !== null) {
      observerRef.current.disconnect();
      observerRef.current = null;
    }
    if (wsRef.current !== null) {
      wsRef.current.onclose = null;
      wsRef.current.onerror = null;
      try { wsRef.current.close(); } catch { /* ya cerrado */ }
      wsRef.current = null;
    }
  }, []);

  /* ── Fit + resize propagado (con debounce) ──────────────── */
  const scheduleFit = useCallback(() => {
    if (fitTimerRef.current !== null) window.clearTimeout(fitTimerRef.current);
    fitTimerRef.current = window.setTimeout(() => {
      fitTimerRef.current = null;
      const term = termRef.current;
      const fit = fitRef.current;
      if (term === null || fit === null) return;
      try { fit.fit(); } catch { /* contenedor sin tamaño aún */ }
      const ws = wsRef.current;
      if (ws !== null && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      }
    }, RESIZE_DEBOUNCE_MS);
  }, []);

  /* ── Reconexión con backoff exponencial visible ─────────── */
  const scheduleReconnect = useCallback(() => {
    if (!mountedRef.current) return;
    const next = attemptRef.current + 1;
    if (next > MAX_ATTEMPTS) {
      setRetryIn(null);
      update({ status: "error", error: CONSOLE_ERRORS.reconnectFailed });
      return;
    }
    const delay = Math.min(BACKOFF_BASE_MS * (2 ** (next - 1)), BACKOFF_MAX_MS);
    nextRetryAtRef.current = Date.now() + delay;
    update({ status: "reconnecting", attempt: next, nextRetryAt: nextRetryAtRef.current });
    retryTimerRef.current = window.setTimeout(() => {
      retryTimerRef.current = null;
      connectRef.current();
    }, delay);
    /* Cuenta atrás visible (segundos enteros hacia 0). */
    if (tickTimerRef.current !== null) window.clearInterval(tickTimerRef.current);
    tickTimerRef.current = window.setInterval(() => {
      const at = nextRetryAtRef.current;
      if (at === null) return;
      const left = Math.ceil((at - Date.now()) / 1000);
      setRetryIn(left > 0 ? left : 0);
    }, RETRY_TICK_MS);
  }, []);

  /* ── Conexión del WS al control ─────────────────────────── */
  const connect = useCallback(() => {
    if (!mountedRef.current) return;
    disconnect();
    const term = termRef.current;
    const cols = term?.cols ?? 80;
    const rows = term?.rows ?? 24;
    update({ status: "connecting", error: null, nextRetryAt: null });
    const socket = new WebSocket(buildConsoleWsUrl(deviceId, cols, rows));
    wsRef.current = socket;
    socket.onopen = () => {
      if (!mountedRef.current) return;
      attemptRef.current = 0;
      nextRetryAtRef.current = null;
      setRetryIn(null);
      update({ status: "open", error: null, attempt: 0, nextRetryAt: null });
      const sync = () => {
        if (wsRef.current === socket && socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ type: "resize", cols, rows }));
        }
      };
      if (typeof requestAnimationFrame === "function") requestAnimationFrame(sync);
      else sync();
      term?.focus();
    };
    socket.onmessage = (event) => {
      if (typeof event.data === "string" && event.data.startsWith(ERROR_PREFIX)) {
        update({ status: "error", error: event.data.slice(ERROR_PREFIX.length) });
        try { socket.close(); } catch { /* ya cerrado */ }
        return;
      }
      if (typeof event.data === "string") {
        term?.write(event.data);
      } else if (event.data instanceof ArrayBuffer) {
        try { term?.write(new TextDecoder().decode(new Uint8Array(event.data))); } catch { /* frame no texto */ }
      }
    };
    socket.onerror = () => {
      if (!mountedRef.current) return;
      update({ status: "reconnecting", error: CONSOLE_ERRORS.network });
    };
    socket.onclose = (event: CloseEvent) => {
      wsRef.current = null;
      if (!mountedRef.current) return;
      if (event.code === 1000) {
        /* Cierre limpio: shell exit o reap por timeout/inactividad. */
        if (tickTimerRef.current !== null) { window.clearInterval(tickTimerRef.current); tickTimerRef.current = null; }
        setRetryIn(null);
        update({ status: "closed", error: null, nextRetryAt: null });
        onCloseRef.current();
        return;
      }
      if (stateRef.current.error !== null) {
        /* Gate fallido (consola deshabilitada, device no encontrado…): el
           banner ya muestra el motivo; reintentar no cambiaría nada. */
        if (tickTimerRef.current !== null) { window.clearInterval(tickTimerRef.current); tickTimerRef.current = null; }
        onCloseRef.current();
        return;
      }
      scheduleReconnect();
    };
  }, [deviceId, scheduleReconnect, update]);

  /* ── Montado del terminal + arranque de la conexión ─────── */
  const connectRef = useRef(() => {});
  connectRef.current = connect;    // el rAF/observer siempre ven la última

  const mountAndConnect = useCallback(() => {
    const host = hostRef.current;
    if (host === null || termRef.current !== null) return;
    const term = mountTerminal(deviceId, host, 80, 24);
    if (term === null) {
      update({ status: "error", error: CONSOLE_ERRORS.generic });
      return;
    }
    termRef.current = term;
    fitRef.current = getAddon(deviceId) ?? null;
    /* Teclado → shell. Los atajos (Ctrl+C/L) pasan crudos: los interpreta
       el PTY del backend (SIGINT / clear), como en un terminal real. */
    term.onData(sendInputRef.current);
    try {
      term.attachCustomKeyEventHandler((event: KeyboardEvent) => {
        if (event.type !== "keydown") return true;
        if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "c") {
          copySelectionRef.current();
          return false;
        }
        if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "v") {
          pasteRef.current();
          return false;
        }
        return true;
      });
    } catch { /* xterm sin el handler (versión antigua) */ }
    /* El drawer anima su apertura: re-fit cuando cambie el layout. */
    observerRef.current = new ResizeObserver(() => { scheduleFit(); });
    observerRef.current.observe(host);
    scheduleFit();
    connectRef.current();
  }, [deviceId, scheduleFit, update]);

  /* ── Ciclo de vida del componente ───────────────────────── */
  useEffect(() => {
    mountedRef.current = true;
    const raf = requestAnimationFrame(() => { mountAndConnect(); });
    return () => {
      mountedRef.current = false;
      cancelAnimationFrame(raf);
      disconnect();
      unmountTerminal(deviceId);
      termRef.current = null;
      fitRef.current = null;
    };
  }, [deviceId, disconnect, mountAndConnect]);

  /* ── API para el componente ────────────────────────────── */
  const sendInputRef = useRef<(data: string) => void>(() => {});
  const copySelectionRef = useRef<() => void>(() => {});
  const pasteRef = useRef<() => void>(() => {});
  sendInputRef.current = (data: string) => {
    const ws = wsRef.current;
    if (ws === null || ws.readyState !== WebSocket.OPEN) return;
    ws.send(data);
  };
  copySelectionRef.current = () => {
    const selection = termRef.current?.getSelection() ?? "";
    if (selection !== "" && typeof navigator !== "undefined" && navigator.clipboard) {
      void navigator.clipboard.writeText(selection);
    }
  };
  pasteRef.current = () => {
    if (typeof navigator === "undefined" || !navigator.clipboard) return;
    void navigator.clipboard.readText().then((text) => {
      if (text !== "") sendInputRef.current(text);
    }).catch(() => { /* permiso del portapapeles denegado */ });
  };

  const sendInput = useCallback((data: string) => { sendInputRef.current(data); }, []);
  const sendResize = useCallback((cols: number, rows: number) => {
    const ws = wsRef.current;
    if (ws === null || ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify({ type: "resize", cols, rows }));
  }, []);
  const copySelection = useCallback(() => { copySelectionRef.current(); }, []);
  const paste = useCallback(() => { pasteRef.current(); }, []);
  const clearScreen = useCallback(() => {
    /* Limpiar la pantalla del xterm; el shell decide el prompt nuevo. */
    termRef.current?.clear();
  }, []);
  const focus = useCallback(() => { termRef.current?.focus(); }, []);
  const close = useCallback(() => {
    disconnect();
    if (termRef.current !== null) {
      unmountTerminal(deviceId);
      termRef.current = null;
      fitRef.current = null;
    }
    update({ status: "closed", error: null });
    onCloseRef.current();
  }, [deviceId, disconnect, update]);
  const reconnect = useCallback(() => {
    attemptRef.current = 0;
    nextRetryAtRef.current = null;
    setRetryIn(null);
    connect();
  }, [connect]);

  return {
    hostRef, state, close, reconnect, sendInput, sendResize,
    clearScreen, copySelection, paste, focus,
    status: state.status, error: state.error, attempt: state.attempt, retryIn,
  };
}
