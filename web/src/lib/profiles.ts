// Colores por perfil de dispositivo. Sirven para teñir iconos, chips y
// nodos de la topología; derivan de la paleta central (lib/palette.ts).
import { PROFILES } from "./palette";

export const PROFILE_COLOR: Record<string, string> = { ...PROFILES };

export function profileColor(profile: string): string {
  return PROFILE_COLOR[profile] ?? "#78959f";
}
