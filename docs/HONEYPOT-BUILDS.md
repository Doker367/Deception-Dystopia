# Validación local de builds de honeypots

Este documento registra la **construcción local de las seis imágenes de
deception** de Dystopia. Es una ola de evidencia: se validó que los Dockerfiles
compilan, **sin ejecutar ningún honeypot**, sin publicar puertos, sin crear redes
señuelo y sin montar el socket de Docker.

Fecha de la validación: **2026-10-29**
Rama: `feature/local-validation`
Base: `main` de Dystopia

## 1. Entorno

| Elemento | Valor |
|---|---|
| Docker Engine | 29.5.2 |
| Arquitectura del host | `aarch64` (Apple Silicon) |
| SO del host | macOS |
| Builder disponible | legacy builder (`docker build`); **sin** `buildx` ni BuildKit |
| Plataforma de las imágenes | `linux/arm64` salvo Cowrie (`linux/amd64`, ver §5) |

Nota: el host **no** tiene el componente `buildx`, por lo que
`docker build --progress=plain` falla con `unknown flag: --progress`. Los builds
se ejecutaron con el builder legacy, equivalente funcional para esta validación.
En un host Linux con BuildKit los mismos comandos aceptan `--progress=plain`.

## 2. Resultado

| Imagen | Resultado | Tiempo aprox. | Tamaño | ID de imagen | Arquitectura |
|---|---|---|---|---|---|
| `dystopia-validation/cowrie:local` | OK | 10 s | 403 MB | `sha256:6531018612fd…` | amd64 |
| `dystopia-validation/dionaea:local` | OK | 107 s | 444 MB | `sha256:73381b76522c…` | arm64 |
| `dystopia-validation/endlessh:local` | OK | 21 s | 16.5 MB | `sha256:6ee2732fe5c9…` | arm64 |
| `dystopia-validation/heralding:local` | OK | 39 s | 195 MB | `sha256:e7f3fcc7507c…` | arm64 |
| `dystopia-validation/redishoneypot:local` | OK | 34 s | 17.8 MB | `sha256:6565b7fa5eef…` | arm64 |
| `dystopia-validation/opencanary:local` | OK | 29 s | 289 MB | `sha256:02e89c83f526…` | arm64 |

Los tiempos incluyen la descarga de capas base. Ningún build se acercó al
límite de 15 minutos; no hubo timeouts.

IDs completos:

```text
cowrie         6531018612fda18f5821f614e4cb8c8e43199ab42822f53d80e6f424b1d75fc1
dionaea        73381b76522c0e78ee27069ae5e7d168640a67e5487449db538da2f3db721a5f
endlessh       6ee2732fe5c9a11177624a8296c8469f7d0d918ff3878b4f10432807e48e087b
heralding      e7f3fcc7507c17e5358475cc868a900bbe266dcd64cbb8b01f25dd1d7fa1b075
redishoneypot  6565b7fa5eefb9d20d4d92fcfc8fe6386b1fe07af3011333d8aa95f1fed2c68c
opencanary     02e89c83f5267ba75029b728a6e01ce53e3d407408135c1c6189dba53ce72f3c
```

## 3. Comandos reproducibles

Cada contexto es el propio directorio del honeypot (el `Dockerfile` vive dentro
y no se necesitan ficheros fuera de él):

```bash
docker build -t dystopia-validation/cowrie:local \
  -f docker/deception/cowrie/Dockerfile docker/deception/cowrie

docker build -t dystopia-validation/dionaea:local \
  -f docker/deception/dionaea/Dockerfile docker/deception/dionaea

docker build -t dystopia-validation/endlessh:local \
  -f docker/deception/endlessh/Dockerfile docker/deception/endlessh

docker build -t dystopia-validation/heralding:local \
  -f docker/deception/heralding/Dockerfile docker/deception/heralding

docker build -t dystopia-validation/redishoneypot:local \
  -f docker/deception/redishoneypot/Dockerfile docker/deception/redishoneypot

docker build -t dystopia-validation/opencanary:local \
  -f docker/deception/opencanary/Dockerfile docker/deception/opencanary
```

Con BuildKit (host Linux) se puede añadir `--progress=plain`; con el builder
legacy del host de validación hay que omitirlo.

Comprobación de resultados sin arrancar contenedores:

```bash
docker images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.Size}}' \
  | grep dystopia-validation
```

## 4. Qué valida (y qué no) esta ola

**Validado**

- Todos los `FROM` resuelven y los digests fijados existen en el registro.
- Los commits fijados de dionaea, endlessh, heralding y redishoneypot clonan y
  pasan su `git rev-parse` de verificación.
- La compilación nativa funciona: dionaea (CMake/C), endlessh (make),
  redishoneypot (Go estático), heralding (pip + extensiones), opencanary (pip),
  cowrie (overlay de configuración sobre la imagen upstream).
- Los `COPY` de configuración y los `--chown` resuelven correctamente.
- Los usuarios no privilegiados (uid 2000 / 999) y los `HEALTHCHECK` se aplican.

**No validado (fuera de alcance por diseño)**

- Arranque de los procesos, binds de puertos y comportamiento señuelo.
- `HEALTHCHECK` en ejecución, generación de logs y adaptadores.
- Capacidades reales (`CAP_NET_BIND_SERVICE`), nftables y aislamiento de red.
- Funcionamiento en amd64: solo Cowrie se construyó como amd64 (por su pin);
  el resto se construyó nativamente en arm64.

No se ejecutó `docker run`, no se publicaron puertos, no se montó el socket de
Docker y no se levantó ninguna red señuelo.

## 5. Fallos y pendientes

No hubo fallos de build. Los únicos puntos que requieren decisión humana:

1. **Pin de Cowrie limitado a amd64.** El digest fijado
   (`sha256:4e2d4067…`) es el manifiesto **amd64** de `cowrie/cowrie:3.1.4`, no
   el índice multiarquitectura. En el host arm64 el build emite:
   `requested image's platform (linux/amd64) does not match the detected host
   platform (linux/arm64/v8)` y la imagen resultante es amd64. En un destino
   Linux **amd64** es correcto y reproducible; en un destino **arm64** exigiría
   emulación (qemu) o cambiar el pin al digest del índice/arm64. No se modificó
   porque el pin es una decisión de seguridad/procedencia.
2. **Builder legacy.** El host de validación no tiene `buildx`. No afecta al
   resultado, pero conviene validar en Linux con BuildKit antes de fijar
   instrucciones de CI.
3. **Dependencias transitivas de OpenCanary.** El Dockerfile ya documenta que
   solo fija `opencanary==0.9.10` y sus dependencias directas; el conjunto
   transitivo no está bloqueado por hash. El build es reproducible en el momento
   de la prueba, no necesariamente a largo plazo.
4. **Avisos no bloqueantes observados:** `pip` como root (heralding, opencanary),
   deprecaciones de OpenSSL 3 en dionaea y `useradd` con uid 2000 en dionaea.
   Ninguno altera el artefacto.

No se necesitó corregir ningún Dockerfile.

## 6. Conclusión

Las seis imágenes de honeypots **construyen correctamente** con los Dockerfiles
y pines actuales. El artefacto está listo para un destino **Linux amd64** en
cuanto a build: cinco de seis también compilan nativamente en **arm64**, y
Cowrie funciona en arm64 solo con emulación mientras se mantenga el digest
amd64.

Queda pendiente, y no forma parte de esta ola, validar el arranque real, los
puertos señuelo, las capacidades y el aislamiento en un host Linux.
