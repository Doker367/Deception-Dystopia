# Orquestación declarativa de una celda de honeypots

**Estado: solo plan/render/validate. La activación está bloqueada.** Esta ola
no arranca contenedores, no crea redes, no publica puertos y no modifica
nftables, KVM ni el socket de Docker. Un YAML de Compose bien formado —o una
red Docker con `internal: true`— **no es evidencia de contención**.

## 1. Qué se ha construido

| Pieza | Ruta | Función |
|---|---|---|
| Módulo de orquestación | `runtime/honeypots.py` | Carga inventario y perfil, valida, renderiza el Compose de una celda y verifica invariantes sobre su propia salida. |
| Inventario | `deploy/honeypots/inventory.yaml` | Fuente de verdad por motor: build, imagen, config revisada, puertos internos, logs, volúmenes, healthcheck y recursos. |
| Perfil de celda MVP | `deploy/honeypots/profiles/cell-mvp.example.yaml` | Una celda (`cell: 1`) con los seis motores, sin puertos publicados. |
| CLI de solo lectura | `runtime/cli.py` → `honeypots` | `plan`, `render`, `validate`; `apply`/`up`/`down` devuelven error explícito. |
| Tests | `tests/hardening/test_honeypots.py` | Contrato de seguridad, validación negativa, CLI, bloqueo y `docker compose config` opcional. |

No se han modificado dashboards, Elastic, Kibana, `requirements*`, supply-chain
ni el README. No hay arranque real, ni publicación de puertos, ni cambios de
firewall.

## 2. Modelo

```
inventario (global, revisado)      perfil de celda (por celda)
        │                                   │
        └──────────────┬────────────────────┘
                       ▼
             runtime.honeypots
        validación estricta (fail closed)
                       │
                       ▼
        Compose de UNA celda + assert_safe()
```

- **Inventario**: describe motores, no celdas. No contiene rutas de host
  absolutas salvo `storage.host_root`; los binds se derivan del contexto de
  build revisado.
- **Perfil de celda**: elige celda `1..254`, modo de red (`internal` o
  `loopback-lab`), `data_root` y subconjunto de motores (por defecto los seis
  del MVP).
- **Render**: produce un documento Compose determinista. Las rutas de build y
  de configuración se emiten **absolutas** y resueltas, para que el fichero
  generado no dependa del directorio desde el que se ejecute Compose.

### Invariantes del Compose generado

| Invariante | Cómo se garantiza |
|---|---|
| Nombres únicos por celda | `name: dystopia-honeypot-cell-<N>`, `container_name: dystopia-hp-c<N>-<motor>`, red `dyhp<N>-<motor>`. |
| Sin `latest` | El motor exige tag explícito en el namespace `dystopia/honeypot-*`; `latest`/`stable`/`main`/`edge` se rechazan. |
| Sin red host ni privilegios | El esquema no admite `network_mode`, `privileged`, `pid/ipc/uts: host`, `devices`, `sysctls` ni socket Docker; `assert_safe()` re-verifica la salida. |
| Sin puertos por defecto | Modo `internal`: solo `expose`. Publicar exige `mode: loopback-lab` y `127.0.0.1:<host alto>:<contenedor>`. |
| Red interna | Un bridge `internal: true` por motor y celda, sin IPv6, sin `external`. |
| Configuración read-only | Bind del fichero de configuración revisado del contexto de build, siempre `read_only: true`. |
| Logs declarados | Bind escribible únicamente en `<data_root>/cells/<N>/<motor>/…`; el path del log debe caer dentro del volumen declarado. |
| Límites de recursos | `mem_limit`, `cpus`, `pids_limit`, `ulimits` (`nofile`, `core=0`), `tmpfs` con `noexec,nosuid` y tamaño acotado. |
| Reinicio responsable | `restart: "no"`; un honeypot no debe entrar en bucles de reinicio. |
| Doble seguro de arranque | Todos los servicios quedan tras el profile `authorized-activation`; `docker compose up` sin ese profile no arranca nada. |
| Healthcheck | Derivado del marcador de proceso del inventario (`grep -q <marker> /proc/1/cmdline`), intervalo y `start_period` acotados. |

`assert_safe()` se ejecuta dentro de `render_cell()`: si el documento se
desvía de estas reglas, el render falla en vez de producir un artefacto
peligroso.

Capacidades: solo `NET_BIND_SERVICE`, y únicamente cuando el motor escucha por
debajo de 1024. En ese caso se omite `no-new-privileges` porque anula las file
capabilities; es una decisión heredada del perfil de referencia y debe
revisarse en la ola Linux (ver §6).

## 3. Uso

```sh
# Informe estructurado: recursos, redes, directorios y requisitos pendientes.
python -m runtime.cli honeypots plan

# Compose YAML por stdout.
python -m runtime.cli honeypots render

# Compose a un fichero (no lo arranca).
python -m runtime.cli honeypots render --output /tmp/cell-1.yaml

# Validación (lanza error si el inventario o el perfil no son seguros).
python -m runtime.cli honeypots validate
```

`--inventory` y `--profile` permiten apuntar a otra celda o a una copia
revisada. Salidas: `plan`/`validate` imprimen JSON; `render` imprime YAML o
escribe el fichero indicado. Ningún subcomando invoca Docker.

### Ejemplo de salida (recortada)

```yaml
name: dystopia-honeypot-cell-1
services:
  cowrie:
    container_name: dystopia-hp-c1-cowrie
    image: dystopia/honeypot-cowrie:3.1.4
    build:
      context: /srv/dystopia/docker/deception/cowrie
      dockerfile: Dockerfile
    user: 999:999
    read_only: true
    init: true
    restart: 'no'
    cap_drop:
    - ALL
    security_opt:
    - no-new-privileges:true
    profiles:
    - authorized-activation
    expose:
    - 2222/tcp
    - 2223/tcp
    volumes:
    - type: bind
      source: /srv/dystopia/docker/deception/cowrie/cowrie.cfg
      target: /etc/cowrie/cowrie.cfg
      read_only: true
    - type: bind
      source: /var/lib/dystopia/honeypots/cells/1/cowrie/var
      target: /cowrie/cowrie-git/var
      read_only: false
    mem_limit: 512m
    cpus: 0.5
    pids_limit: 256
    ...
networks:
  dyhp1-cowrie:
    driver: bridge
    internal: true
    enable_ipv6: false
```

### Bloqueo de activación

```sh
$ python -m runtime.cli honeypots apply
{"action": "apply", "state": "blocked", "containment_verified": false,
 "detail": "honeypots apply is blocked: no Linux containment verification exists. ..."}
$ echo $?
2
```

No existe `--force`, `--contained`, `--isolated` ni equivalente.
`honeypots.blocked()` lanza `HoneypotBlocked` siempre; no consulta ninguna
bandera que el operador pueda activar.

## 4. Validación reproducible

```sh
# Suite requerida
/Users/doker/Deception/.py312/bin/python -m pytest -q tests/hardening tests/deception
/Users/doker/Deception/.py312/bin/python -m ruff check app tests
/Users/doker/Deception/.py312/bin/pyright app --pythonpath /Users/doker/Deception/.py312/bin/python

# Compose: resuelve y valida, no arranca contenedores.
python -m runtime.cli honeypots render --output /tmp/cell-1.yaml
docker compose -f /tmp/cell-1.yaml --profile authorized-activation config --quiet
docker compose -f /tmp/cell-1.yaml --profile authorized-activation config --services
```

El test de Docker se omite automáticamente si no hay binario o daemon. Los
tests de estructura no necesitan Docker y cubren: tags flotantes, socket
Docker, `/proc`/`/sys`/`/dev`, red host, privilegios, capacidades, límites
fuera de rango, duplicados de puerto, sumas del inventario, claves YAML
duplicadas, alias YAML, puertos publicados fuera de `127.0.0.1`, nombres
únicos por celda y el bloqueo de `apply`/`up`/`down`.

## 5. Límites explícitos

- **`internal: true` no es contención.** Aísla el tráfico accidental y reduce
  el movimiento lateral dentro de Docker, pero no impide ataques al kernel, al
  daemon, a los volúmenes ni a la red del host. La frontera real debe
  verificarla la celda Linux.
- **El render no aplica nada.** No crea directorios, no asigna uid/gid, no
  impone cuotas, no arranca nada y no comprueba cgroups.
- **Los límites son declarativos.** `mem_limit`, `cpus`, `pids_limit` y
  `ulimits` son cotas de Compose; que el kernel las aplique debe verificarse de
  forma independiente.
- **Las imágenes están fijadas por tag, no por digest.** El inventario
  documenta el digest de la base, no el de la imagen construida. Fijar
  `a@sha256:…` antes de cualquier activación.
- **No hay colector de logs.** Los binds escriben en el host, pero la ingesta,
  rotación y cuota no forman parte de esta ola.
- **Modo `loopback-lab`**: publica en `127.0.0.1` para pruebas manuales. No es
  un modo de producción y no debe usarse para exponer una celda a tráfico
  real; la exposición legítima es DNAT/nft revisado en la celda.
- **Rutas absolutas**: el Compose generado es específico del host; se regenera
  en cada máquina. No se versiona la salida.
- **Healthcheck de proceso**: verifica que el proceso sigue vivo, no que el
  protocolo responde. Un motor puede estar "healthy" y no capturar tráfico.

## 6. Decisiones pendientes para la ola Linux

1. **Frontera de red real**: definir si la celda usa un bridge dedicado
   (`dybrN`, como `runtime.isolation`) con nftables por celda, o los bridges
   por motor que renderiza este módulo. Hoy son dos modelos que deben
   converger; no se declaran equivalentes.
2. **Verificación de contención**: cómo se demuestra (namespace de red,
   `nft list ruleset` de la tabla de celda, egress denegado, sin ruta por
   defecto) y quién firma la evidencia. Hasta entonces `apply` sigue bloqueado.
3. **Runtime**: Docker rootless/userns, seccomp por motor, AppArmor/SELinux y
   ausencia verificada del socket. `no-new-privileges` vs `NET_BIND_SERVICE`
   debe resolverse: remapear a puertos altos con DNAT es la opción preferida.
4. **Enforcement de cgroups**: comprobar `memory.max`, `pids.max`, `cpu.max`
   y `memory.events` bajo carga sintética, no solo que Compose los declare.
5. **Cuotas y rotación**: provisión de `cells/<N>` con uid/gid correctos,
   cuota XFS/ext4, rotación externa y retención de datos hostiles.
6. **Digests**: reconstruir las seis imágenes, fijar `image@sha256:…` y
   registrar SBOM/CVE. El esquema actual acepta tags versionados y deberá
   admitir (y preferir) digests.
7. **Salida de Dionaea**: bloquear egress en la celda y verificar que el
   módulo `curl` no alcanza Internet.
8. **Integración systemd**: unidad one-shot sin `[Install]` para render, y una
   ruta de activación separada que no reutilice estos comandos de solo
   lectura.
9. **Celdas y direccionamiento**: alinear `cell`, `data_root` y direcciones con
   `runtime.isolation` para que una celda no pueda ser a la vez KVM y
   contenedor, y que dos celdas no compartan proyecto ni red.
10. **Logs y sensor**: decidir formato de entrega al sensor independiente,
    offsets por inode y redacción antes de indexar credenciales o payloads.
