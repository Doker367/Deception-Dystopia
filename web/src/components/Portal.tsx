import { type ReactNode } from "react";
import { createPortal } from "react-dom";

/**
 * Monta sus hijos directamente en `document.body`.
 *
 * Los drawers usan `position: fixed` con z-index alto; si algún ancestro
 * crea un stacking context (transform, filter, backdrop-filter, animación
 * de opacity con fill-mode `both`, contain…), el `fixed` queda atrapado
 * dentro de ese contexto y el topbar/sidebar pueden pintarse encima.
 * El portal los saca de la jerarquía para que el overlay siempre cubra el
 * viewport completo.
 */
export function Portal({ children }: { children: ReactNode }) {
  if (typeof document === "undefined") return null;
  return createPortal(children, document.body);
}
