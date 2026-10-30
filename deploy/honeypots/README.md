# Honeypots T-Pot — artefactos estáticos para Dystopia

Esta carpeta contiene el inventario, los perfiles de referencia, las fixtures
y las notas de procedencia de los honeypots incorporados desde el catálogo de
T-Pot: **Cowrie, OpenCanary, Dionaea, Heralding, RedisHoneyPot y Endlessh**.

> **No es un despliegue ejecutable.** No hay puertos publicados, no se usa red
> host, no se monta el socket Docker y no se modifican systemd, nft, interfaces
> ni rutas del host. La activación requiere autorización separada, una celda
> de sensor aislada y validada, y revisión de aislamiento.

## Contenido

| Ruta | Uso |
|---|---|
| `inventory.yaml` | Inventario legible por máquina: build, imagen, puertos internos, log, fixture, volúmenes y recursos. |
| `profiles/honeypots.example.yaml` | Plantilla Compose de referencia, sin puertos publicados y bloqueada tras el profile `authorized-activation`. |
| `fixtures/` | Una muestra sintética por motor para probar el adaptador sin tráfico real. Incluye campos nativos y alias canónicos; ver `adapters.md`. |
| `PROVENANCE.md` | Origen, revisión fijada, licencia y cambios respecto al upstream. |
| `adapters.md` | Contrato de normalización, estado de los adaptadores y límites de seguridad. |

## Matriz de motores

| Motor | Puerto(s) interno(s) | Log canónico | Formato | Fixture |
|---|---|---|---|---|
| Cowrie | 2222/tcp, 2223/tcp | `/cowrie/cowrie-git/var/log/cowrie/cowrie.json` | JSONL | `fixtures/cowrie.jsonl` |
| OpenCanary | 21, 22, 23, 80, 3306/tcp | `/var/log/opencanary/opencanary.log` | JSONL | `fixtures/opencanary.jsonl` |
| Dionaea | 21, 69/udp, 81, 135, 443, 445, 1433, 1723, 1883, 3306, 27017 | `/opt/dionaea/var/log/dionaea.json` | JSONL | `fixtures/dionaea.jsonl` |
| Heralding | 21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389, 5432, 5900/tcp | `/var/log/heralding/sessions.jsonl` | JSONL (+ CSV) | `fixtures/heralding.jsonl` |
| RedisHoneyPot | 6379/tcp | `/var/log/redishoneypot/redishoneypot.log` | JSONL | `fixtures/redishoneypot.jsonl` |
| Endlessh | 2222/tcp | `/var/log/endlessh/endlessh.log` | texto con timestamp | `fixtures/endlessh.log` |

Las rutas son **internas al contenedor**. En el host se montan bajo
`${DYSTOPIA_HONEYPOT_DATA:-/var/lib/dystopia/honeypots}/<motor>/...`, según el
perfil. Ninguna ruta de T-Pot (`$HOME/tpotce/...`) se reutiliza.

## Límites recomendados

| Motor | RAM | CPU | PIDs | nofile | Notas |
|---|---:|---:|---:|---:|---|
| Cowrie | 512 MiB | 0,50 | 256 | 4096 | Sesiones interactivas y filesystem emulado. |
| OpenCanary | 256 MiB | 0,25 | 128 | 2048 | Cinco listeners ligeros. |
| Dionaea | 768 MiB | 1,00 | 512 | 4096 | Emulación y captura de binarios; vigilar CPU. |
| Heralding | 512 MiB | 0,50 | 256 | 4096 | Muchos listeners; sin hash cracking. |
| RedisHoneyPot | 192 MiB | 0,25 | 128 | 2048 | Un proceso, mapa en memoria. |
| Endlessh | 64 MiB | 0,10 | 64 | 8192 | `MaxClients 4096`; el límite es de FDs, no de PIDs. |
| **Total** | **2304 MiB** | **2,60** | **1344** | — | Reservar 4 vCPU / 4 GiB para SO, agente y picos. |

Los valores están en `inventory.yaml` y en el perfil de referencia. Son cotas
de laboratorio, no una garantía de comportamiento bajo ataque; ajustar tras
medir en la celda autorizada.

## Activación (solo tras autorización)

1. Revisar y fijar los digests de las imágenes base; verificar firmas/attestations
   si la política lo exige. Los digests de este inventario se observaron el
   2026-10-29 y deben revalidarse.
2. Construir las imágenes en un entorno controlado y escanear CVEs/SBOM. Aquí
   no se construyó ni arrancó nada.
3. Crear los directorios de datos con el uid/gid correcto:
   - Cowrie `999:999`: `<root>/cowrie/var/log/cowrie`,
     `<root>/cowrie/var/lib/cowrie/downloads`, `<root>/cowrie/var/lib/cowrie/tty`
   - OpenCanary `2000:2000`: `<root>/opencanary/log`
   - Dionaea `2000:2000`: `<root>/dionaea/var/log` y
     `<root>/dionaea/var/dionaea/{binaries,bistreams,roots/ftp,roots/tftp,roots/www}`
   - Heralding `2000:2000`: `<root>/heralding/log`
   - RedisHoneyPot `2000:2000`: `<root>/redishoneypot/log`
   - Endlessh `2000:2000`: `<root>/endlessh/log`
4. Validar la celda de sensor aislada y la política nft. `internal: true` en Docker
   **no** es evidencia de contención.
5. Exponer el tráfico mediante la política de la celda (DNAT/forwarding
   autorizado), nunca publicando puertos de gestión en el host.
6. Configurar rotación externa de logs. El adaptador debe tolerar rotación por
   inode o reapertura; no se incluye logrotate en este repositorio.
7. Arrancar únicamente el profile autorizado y registrar la ventana.

## Validación local reproducible

```sh
cd deploy/honeypots

# JSON: una línea = un objeto
while IFS= read -r line; do printf '%s' "$line" | jq -e . >/dev/null; done < fixtures/cowrie.jsonl

# YAML (Ruby/psych está disponible en este host; no requiere instalar nada)
ruby -e 'require "yaml"; YAML.load_file("inventory.yaml", aliases: true); YAML.load_file("profiles/honeypots.example.yaml", aliases: true)'

# Compose: solo resolución/validación, no arranca contenedores
docker compose -f profiles/honeypots.example.yaml config --quiet
```

## Pendientes de seguridad

- Los builds **no se ejecutaron** en este entorno. No hay evidencia de que las
  imágenes compilen, arranquen o resistan abuso.
- Los digests se consultaron en el registro, pero no se verificó firma,
  procedencia SLSA ni reproducible build.
- Dependencias Python transitivas de OpenCanary y Heralding no están lockeadas
  con hashes; hacerlo antes de una activación real.
- Heralding (GPL-3.0), Dionaea (GPL-2.0-or-later) y RedisHoneyPot (GPL-3.0)
  imponen obligaciones de código fuente si se distribuyen imágenes.
- Los logs capturan credenciales, comandos y binarios. Son datos hostiles:
  restringir acceso, cifrar backups, definir retención y no enviarlos a IA ni
  a Kibana sin redacción/mapping aprobados.
- Dionaea carga el módulo `curl` y puede intentar conexiones salientes al
  procesar URLs de atacantes. La celda debe denegar egress; no se probó.
- Cowrie usa `AuthRandom`: no produce `login_success` por defecto. Si se
  necesita, añadir un usuario sintético en un paso autorizado, nunca
  credenciales reales.
- Endlessh con `MaxClients 4096` consume descriptores; el límite `nofile` del
  perfil debe validarse contra el `fs.file-max` de la celda.
- OpenCanary, Dionaea y Heralding escuchan en puertos < 1024. Corren como UID
  2000 con la file capability `NET_BIND_SERVICE`; por eso **no** llevan
  `no-new-privileges` (esa opción anula las file capabilities). Si la política
  exige NNP, remapear a puertos altos y hacer DNAT en la celda.
