// ─────────────────────────────────────────────────────────────────────────────
// Tema de la UI — "dark" (por defecto) y "light" (blanco sólido).
// El tema activo se expone como atributo `data-theme` en <html>; los estilos
// viven en `web/src/styles.css` (bloques :root y [data-theme="light"]).
// ─────────────────────────────────────────────────────────────────────────────

import { useSyncExternalStore } from "react";

export type Theme = "dark" | "light";

const STORAGE_KEY = "dystopia.theme";

const listeners = new Set<() => void>();

function emit(): void {
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Lee el tema guardado; si no hay preferencia, cae a oscuro. */
export function getTheme(): Theme {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    return stored === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

/** Aplica el tema al documento (atributo + color-scheme del navegador). */
export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
}

/** Cambia el tema, lo persiste y lo aplica al documento. */
export function setTheme(theme: Theme): void {
  applyTheme(theme);
  try {
    window.localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // localStorage puede estar bloqueado (modo privado): el tema solo vive en memoria.
  }
  emit();
}

/** Aplica el tema guardado antes del primer render para evitar el destello. */
export function initTheme(): Theme {
  const theme = getTheme();
  applyTheme(theme);
  // Sincroniza el tema entre pestañas abiertas del dashboard.
  window.addEventListener("storage", (event) => {
    if (event.key !== STORAGE_KEY) return;
    const next: Theme = event.newValue === "light" ? "light" : "dark";
    applyTheme(next);
    emit();
  });
  return theme;
}

/** Devuelve true cuando las gráficas y lienzos deben usar tinta clara. */
export function isLight(): boolean {
  return document.documentElement.dataset.theme === "light";
}

/** Respeta la preferencia del sistema para animaciones ambientales. */
export function prefersReducedMotion(): boolean {
  return typeof window !== "undefined"
    && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * Versión legible sobre fondo claro de un acento hex del proyecto.
 * En tema oscuro devuelve el color intacto; en claro usa el mismo matiz
 * con más profundidad para conservar el contraste sobre blanco.
 */
const ACCENT_INK: Record<string, string> = {
  "#e2601f": "#b8440f",
  "#a8460f": "#96300f",
  "#66afe9": "#31708f",
  "#f0ad4e": "#a56b0e",
  "#b39ddb": "#6f5b95",
  "#e982a8": "#b94f74",
  "#f05050": "#d13a3a",
  "#9bd275": "#4f8a2f",
  "#8b959c": "#6b767d",
  "#f3d35b": "#8f7008",
  "#cfccc6": "#5f5f5f",
  // Valores heredados por si alguna serie los conserva.
  "#35e6c4": "#b8440f",
  "#218f85": "#96300f",
  "#5aa9ff": "#31708f",
  "#f5b75b": "#a56b0e",
  "#b58cff": "#6f5b95",
  "#ff7a9e": "#b94f74",
  "#ed687b": "#d13a3a",
  "#71df9a": "#4f8a2f",
  "#58718f": "#6b767d",
  "#ff5f7a": "#d13a3a",
  "#ff9f5b": "#a56b0e",
  "#f5d06b": "#8f7008",
  "#a9c3c9": "#5f5f5f",
  "#42c6d5": "#b8440f",
};

export function inkAccent(hex: string): string {
  if (!isLight()) return hex;
  return ACCENT_INK[hex.toLowerCase()] ?? hex;
}

/** Fondo de panel para separar sectores de un gráfico (dona, pie). */
export function panelBg(): string {
  return isLight() ? "#ffffff" : "#0a111b";
}

/**
 * Hook de tema: devuelve el tema activo y una función para alternarlo.
 * Los componentes que pintan en canvas (ECharts, sparklines) lo usan para
 * reconstruir sus colores cuando cambia el tema.
 */
export function useTheme(): [Theme, () => void] {
  const theme = useSyncExternalStore(subscribe, getTheme, getTheme);
  const toggle = () => setTheme(theme === "dark" ? "light" : "dark");
  return [theme, toggle];
}
