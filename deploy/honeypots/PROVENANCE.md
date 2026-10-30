# Procedencia y licencias — honeypots

Referencia consultada: `tpotce/` (T-Pot, GPL-3.0).
No se copiaron secretos, usuarios, tokens, claves, rutas `$HOME/tpotce` ni
configuración de red/firewall de T-Pot. Las configuraciones se reescribieron a
partir del upstream correspondiente y de los artefactos ya presentes en
Dystopia.

## Componentes

| Componente | Upstream y revisión fijada | Licencia upstream | Imagen base fijada | Cambios en Dystopia |
|---|---|---|---|---|
| Cowrie | `cowrie/cowrie` v3.1.4, commit `085ed091a84ae1cee7f15b6e8aa549d11826a0f7` | BSD-3-Clause | `cowrie/cowrie:3.1.4` @ `sha256:4e2d4067…54e55` | Config reducida y adaptada a la topología (`srv-files-01`), JSONL en volumen `var/`, sin claves ni usuarios reales; healthcheck de proceso. |
| OpenCanary | `thinkst/opencanary` v0.9.10, commit `fb12e4fefbdb1b9acd1e5561a2614f827ab639ff` | BSD-3-Clause | `python:3.12.8-slim-bookworm` @ `sha256:2199a628…2a2f0` | Paquete PyPI fijado (`opencanary==0.9.10`), usuario 2000, `CAP_NET_BIND_SERVICE`, logger JSONL; persona ya existente en Dystopia revisada. |
| Dionaea | `telekom-security/dionaea` v0.12.5, commit `78af2ff2a0f1b62ac7cc5858bac2ab46898c9cc0` | GPL-2.0-or-later | `ubuntu:26.04` @ `sha256:6a06111c…f4d3c` | Build multi-stage desde commit; configs `dionaea.cfg`, handlers y servicios adaptados de `conf/` (CC0-1.0). Sin paquetes Debian archivados ni scripts de T-Pot. |
| Heralding | `johnnykv/heralding`, commit `ac12724ab38c4e2fe78f07d1bc35e6e586ba69c0` | GPL-3.0 (declarada en `setup.py`; no hay fichero LICENSE) | `alpine:3.23.7` @ `sha256:ff7f0c72…03d63` | Build desde commit, dependencias del `requirements.txt` upstream; config reducida, sin ipify, HPFeeds, syslog ni hash cracking; usuario 2000. |
| RedisHoneyPot | `cypwnpwnsocute/RedisHoneyPot`, commit `45adc622a423d12d76392c3a54274f6cff111d58` | GPL-3.0 | `golang:1.26.10-alpine3.23` + `alpine:3.23.7` | Build estático (`CGO_ENABLED=0`), usuario 2000, log JSONL a archivo; `redis.conf` con valores sintéticos. |
| Endlessh | `skeeto/endlessh`, commit `dfe44eb2c5b6fc3c48a39ed826fe0e4459cdf6ef` | Unlicense (dominio público) | `alpine:3.23.7` @ `sha256:ff7f0c72…03d63` | Build desde commit, usuario 2000, `LogLevel 1`, `stdbuf` para línea a línea; `MaxClients 4096`. |

## Imágenes base

| Imagen | Digest observado | Fecha |
|---|---|---|
| `cowrie/cowrie:3.1.4` | `sha256:4e2d40671691ab7a4af19840918556c62316939e905bfc9ab3fc1f9e1db54e55` | 2026-10-29 |
| `python:3.12.8-slim-bookworm` | `sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0` | 2026-10-29 |
| `ubuntu:26.04` | `sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c` | 2026-10-29 |
| `alpine:3.23.7` | `sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63` | 2026-10-29 |
| `golang:1.26.10-alpine3.23` | `sha256:34414731924cf2263160f0021f5cf6e1807382d85248f7cb419d4187b96d5e43` | 2026-10-29 |

Los digests se obtuvieron de la API del registro; **no** se verificó firma,
attestation ni reproducibilidad. Revalidar antes de activar.

Los Dockerfiles de Dionaea, Heralding, RedisHoneyPot y Endlessh se reescribieron
a partir de los upstream y del patrón de build de T-Pot (GPL-3.0); no son
copias literales. Si se consideran obra derivada de T-Pot, se aplica GPL-3.0
además de la licencia upstream correspondiente.

## Licencias y distribución

- **Cowrie, OpenCanary**: BSD-3-Clause; conservar avisos de copyright.
- **Endlessh**: Unlicense; sin obligaciones de atribución, se mantiene el aviso
  por cortesía.
- **Dionaea**: GPL-2.0-or-later. Distribuir la imagen implica ofrecer el código
  fuente correspondiente y respetar la licencia del conjunto.
- **Heralding**: GPL-3.0. Igual obligación; el proyecto upstream no incluye un
  fichero LICENSE, pero `setup.py` y las cabeceras lo declaran.
- **RedisHoneyPot**: GPL-3.0. Igual obligación.
- **T-Pot**: GPL-3.0. Se usó solo como referencia de catálogo/diseño; no se
  incorporaron sus scripts ni su configuración de red. Las configuraciones de
  Dionaea se basan en el `conf/` upstream, marcado CC0-1.0.

Este documento no es asesoramiento legal. Antes de publicar imágenes o
paquetes, revisar las obligaciones de código fuente y los avisos de terceros.
