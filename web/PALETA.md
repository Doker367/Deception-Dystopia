# Paleta de colores — Dystopia web

Única referencia de color del proyecto. Si necesitas un color, tómalo de
aquí; no definas hexágonos sueltos en componentes.

## Fuente de verdad (dos gemelos, siempre sincronizados)

| Lugar | Contenido |
|---|---|
| `web/src/styles.css` → bloque `:root` | Tokens CSS (`--cyan`, `--sev-critical`, tripletes `--*-rgb`, …) |
| `web/src/lib/palette.ts` | Tokens TS (`ACCENTS`, `SEVERITY`, `SENSORS`, `PROTOCOLS`, `PROFILES`, `SERIES`, `withAlpha()`) |

## Acentos — un rol, una tonalidad

| Token | Hex | Uso |
|---|---|---|
| `cyan` | `#35e6c4` | Marca, datos principales, Cowrie, severidad baja |
| `blue` | `#5aa9ff` | Información, geografía, OpenCanary, severidad info |
| `amber` | `#f5b75b` | Advertencia, perimetral, Dionaea, Telnet |
| `violet` | `#b58cff` | Datos secundarios, Heralding, impresora, RDP |
| `pink` | `#ff7a9e` | Descartes, redis-honeypot, Redis |
| `red` | `#ed687b` | Peligro de la interfaz (destructivo) |
| `green` | `#71df9a` | Éxito, cámara |
| `slate` | `#58718f` | Neutro de series ("Otros") |

## Severidad

| Token | Hex |
|---|---|
| `--sev-critical` | `#ff5f7a` |
| `--sev-high` | `#ff9f5b` |
| `--sev-medium` | `#f5d06b` |
| `--sev-low` | `= cyan` |
| `--sev-info` | `= blue` |

## Superficies y tinta

`--bg #081016`, `--bg-soft #0b151d`, `--bg-panel #101d27`, `--bg-raised #152832`,
`--line rgba(105,178,190,.16)`, texto `--text #eaf8f7` → `--faint #506d79`
(escala de 4 pasos: text → text-soft → muted → faint).

## Reglas

1. **Nada de hexágonos en componentes TSX/CSS**: usa `import { … } from "../lib/palette"`
   o `var(--…)`. Las excepciones son los fondos decorativos del canvas/globo.
2. Para transparencias usa `withAlpha(color, 0.15)` en TS o
   `rgba(var(--cyan-rgb), 0.15)` en CSS; no repitas el RGB a mano.
3. Series de gráficas: `SERIES` (o `SENSORS`/`PROTOCOLS` si hay mapeo semántico).
4. Cambiar un valor: edítalo en **ambos** archivos (palette.ts y :root) en el
   mismo commit; los nombres coinciden 1:1.
