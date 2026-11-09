# Licencias de terceros

Dystopia se distribuye bajo la licencia **MIT** (ver [`LICENSE`](LICENSE)).
Esa licencia cubre únicamente el código propio del proyecto.

Los honeypots, imágenes base y demás componentes de terceros que Dystopia
compila, descarga o ejecuta conservan **sus propias licencias**. Al distribuir
imágenes o paquetes derivados hay que respetar esas licencias, que se detallan
en [`deploy/honeypots/PROVENANCE.md`](deploy/honeypots/PROVENANCE.md). Resumen:

| Componente | Licencia |
|---|---|
| Cowrie | BSD-3-Clause |
| OpenCanary | BSD-3-Clause |
| Dionaea | GPL-2.0-or-later |
| Heralding | GPL-3.0 |
| RedisHoneyPot | GPL-3.0 |
| Endlessh | Unlicense (dominio público) |
| T-Pot (solo referencia de diseño) | GPL-3.0 |

Las licencias GPL de los componentes upstream no se ven alteradas por la
licencia MIT del código propio de Dystopia. Las fuentes y licencias de los mapas
admin-1 se documentan en [`LICENSES-THIRD-PARTY.md`](LICENSES-THIRD-PARTY.md).
Este documento no es asesoramiento legal.
