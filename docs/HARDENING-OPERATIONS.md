# Instalación y operación de la base endurecida

**Estado: implementación inicial, NO certificada para producción.** Las pruebas dinámicas no se ejecutaron en esta sesión: el sandbox del host rechazó la ejecución. No se dispone de laboratorio Linux autorizado. La activación de celdas está bloqueada incondicionalmente; no hay opción `force`. El instalador no habilita sensores ni crea interfaces/rutas/firewall.

## Qué es utilizable y qué está bloqueado

| Componente | Entregado | Límite |
|---|---|---|
| Control FastAPI | autenticación, usuarios, configuración y lectura heredada | sin ejecución de listeners/QEMU/firewall; JWT único obligatorio |
| Ingestión | proceso y puerto propios, HTTPS directo, credencial individual, ACL por dispositivo, contrato v1 | despliegue TLS/red y pruebas de integración pendientes |
| Sensor | API `Spool.submit`, drenaje HTTPS, reintentos, cuotas y cuarentena de lotes | NO importa listeners antiguos; adaptadores nativos/Cowrie/OpenCanary aún no portados |
| Procesamiento | eventos + reglas + outbox transaccionales; notificador separado | sin IA; notificaciones externas requieren destino y autorización explícitos |
| Aislamiento | política, XML, nft por celda, helper local, cuarentena | prototipo de laboratorio: no define/arranca VMs; no verificador de topología/kernel |
| Instalador | plan guiado, preflight, aplicación local offline, diagnóstico | bundle/venv y manifiestos reales aprobados son obligatorios; no los descarga |

El control no incluye ahora routers de IA, monitoring, notificaciones, proxy Prometheus o extensiones de seguridad. Es una reducción deliberada de superficie, no compatibilidad completa. Las consultas históricas de deception siguen leyendo la base antigua; la consola de eventos v1 usa el [puente Unix separado](<docs/QUERY-BRIDGE.md>) en código, no instalado ni verificado en Linux. No usar la base antigua como fallback de telemetría.

## 1. Autorizaciones necesarias antes de ejecutar cualquier comando

1. Autorizar un laboratorio Ubuntu Server 24.04 LTS desechable, KVM/libvirt, red físicamente/lógicamente sin salida, destinos sintéticos y consola de recuperación. No usar este Mac como laboratorio.
2. Autorizar por separado preparación del sistema operativo, paquetes versionados desde un repositorio/snapshot aprobado y un bundle Python completo. El instalador **no hace apt/pip/downloads**.
3. Revisar las versiones, dependencias transitivas, licencias y vulnerabilidades. Resolver para Python 3.12/arquitectura Linux y producir un `requirements.lock` con **todas** las versiones exactas y hashes SHA256 reales; solo wheels aprobados. Un fichero de pins directos no sustituye ese lock.
4. Autorizar instalación de archivos bajo `/opt/dystopia`, `/etc/dystopia`, `/var/lib/dystopia`, creación de cuatro usuarios/grupos privados y cinco servicios más un socket systemd. `daemon-reload` es global: recarga definiciones, no reinicia servicios ajenos. Solo se habilita/inicia gestión después del alta local.
5. Cambios futuros de interfaces, rutas, switch, libvirt, nft, certificados o acceso remoto requieren una autorización adicional, ventana de mantenimiento y consola probada. Ningún comando de esta guía se ha ejecutado aquí.

## 2. Preparar artefactos reproducibles (operador, fuera de este host)

El bundle aprobado debe contener todos los wheels, el lock completo y un manifiesto `hashes.json` que mapee nombres de archivos directos a sus SHA256 reales (incluido el lock). No hay valores ficticios de hashes ni imágenes `latest` utilizables en el despliegue endurecido. Las imágenes de invitados tampoco están incluidas; falta su selección/verificación.

Preparar `/opt/dystopia/current` como directorio real, root-owned, sin enlaces ni contenido mutable; solo código/estáticos/artefactos revisados, **sin `.env`, secretos, bases de datos, claves, logs, ISOs ni `.git`**. Preparar `/opt/dystopia/venv` por el procedimiento de construcción aprobado. Ejemplo de instalación offline, únicamente tras autorización:

```sh
/opt/dystopia/venv/bin/python -m pip install --no-index --only-binary=:all: \
  --find-links /srv/dystopia-bundle --require-hashes -r /srv/dystopia-bundle/requirements.lock
```

Registrar en `/opt/dystopia/venv/installed-lock.sha256` el SHA256 real del lock usado. Generar y revisar un manifiesto `release-hashes.json` en **cada** directorio (release y venv), mapeando cada archivo regular relativo, salvo el propio manifiesto, a su SHA256. Esto liga bytes/lock a una construcción aprobada, **no prueba autenticidad del editor ni ausencia de malware**. El administrador es la raíz de confianza del manifiesto. El venv permite enlaces únicamente hacia destinos y ancestros root-owned sin escritura de grupo/otros; el release no permite enlaces. No ejecutar código de la distribución para validar sus propios hashes.

## 3. Plan sin modificaciones

Desde una copia revisada y dentro del entorno de validación:

```sh
python3 -m runtime.install --guided
python3 -m runtime.install --dry-run --config deploy/install.example.json
```

El [ejemplo de instalación](<deploy/install.example.json>) usa nombres y redes **sintéticos**, no detecta ni adivina interfaces. Debe sustituirse por inventario explícito y procedimiento de recuperación probado. El preflight de apply comprueba plataforma, identidad root, interfaces existentes, dirección de gestión, KVM/libvirt/nft, archivos/propietarios y artefactos. No certifica rutas, switches, offloads ni aislamiento. Si las redes se solapan, las interfaces coinciden, faltan hashes o hay configuración existente diferente, aborta.

La primera instalación enlaza únicamente `127.0.0.1:8082`. Para administración remota inicial usar túnel SSH autorizado. No se modifica la red de la sesión SSH. Un bind remoto posterior exige TLS y revisión explícita de la unidad y su filtro IP; no se hace automáticamente.

## 4. Aplicación explícita y primer administrador local

En Linux autorizado, con consola de recuperación disponible:

```sh
/opt/dystopia/venv/bin/python -m runtime.install --apply \
  --config /ruta/revisada/install.json --bundle /srv/dystopia-bundle \
  --confirm APPLY-MANAGEMENT-ONLY
```

Esta operación requiere root local; no es un endpoint web. Crea usuarios `dystopia-control`, `dystopia-ingest`, `dystopia-sensor`, `dystopia-query`, sin login, grupos adicionales ni pertenencia a libvirt/docker. Crea padre de estado root `0711`; control/sensor `0700`, ingest `0710` con grupo query de solo travesía (archivo `events.db` se provisiona por separado a `0640`); usa descriptores sin seguir enlaces y solo cambia propietario de directorios recién creados. Genera secreto JWT aleatorio en archivo root `0600`, nunca lo muestra. Archivos existentes se conservan; diferencias/permisos inesperados provocan error. Una interrupción puede dejar **algunos pasos completos**; no es una transacción del host. No hace rollback destructivo.

En la primera aplicación la gestión **no arranca** hasta crear el administrador:

```sh
cd /opt/dystopia/current
runuser -u dystopia-control -- /opt/dystopia/venv/bin/python -m runtime.cli bootstrap-admin \
  --users /var/lib/dystopia/control/config/users.yaml --username NOMBRE_ELEGIDO
```

Introduce por TTY una contraseña única (mínimo 16 caracteres; máximo 72 bytes UTF-8). No usar argumentos ni variables de entorno para contraseñas. Bootstrap es exclusivo y no sobrescribe usuarios. Repetir apply con los mismos artefactos/configuración; habilitará e iniciará únicamente control.

```sh
/opt/dystopia/venv/bin/python -m runtime.install --diagnose --config /ruta/revisada/install.json
systemctl status dystopia-control.service
```

El diagnóstico de servicio **no equivale a aislamiento verificado**. Revisar permisos efectivos, unidad y logs; no copiar el entorno ni secretos al informe. Las unidades tienen capacidades vacías, `NoNewPrivileges`, filesystem protegido, límites de memoria/procesos/archivos y filtros de dirección/bind. Es necesario validar soporte efectivo de cgroup/BPF/systemd en el laboratorio, no solo la sintaxis de los archivos.

## 5. Ingestión y alta/rotación/revocación de sensores

Ingestión es un proceso independiente `runtime.cli ingest`, no un router del control. Su unidad no se habilita automáticamente. El operador debe provisionar certificado con SAN de la **IP exacta** de ingestión, clave privada `0600` propiedad del servicio, CA confiable para sensores y un bind explícito a red de telemetría (distinto de gestión y sin llegar desde producción). El launcher deshabilita proxy headers y rechaza HTTP; no acepta que `X-Forwarded-Proto` haga seguro un enlace en claro. Las credenciales son bearer aleatorias sobre HTTPS validado; no es mTLS. No usar terminación TLS en proxy sin implementar una frontera adicional equivalente.

La unidad de ingestión solo admite loopback mediante su filtro IP inicialmente. Ampliar únicamente a redes de sensores autorizadas y revisar firewall/switch externos. El emisor rechaza hostnames, redirects, proxies heredados y certificados no válidos; usa IP literal/CA y endpoint `/v1/events`.

Operaciones **locales**, ejecutadas como usuario de ingestión mediante el mecanismo autorizado del administrador:

```sh
python -m runtime.cli rotate-sensor --registry /var/lib/dystopia/ingest/sensors.db \
  --sensor sensor-a --device decoy-a --output /var/lib/dystopia/ingest/nueva-credencial
python -m runtime.cli revoke-sensor --registry /var/lib/dystopia/ingest/sensors.db --sensor sensor-a
```

La salida debe ser un archivo nuevo; nunca se imprime el token. Rotación persiste primero el archivo y luego cambia el registro/revoca claves anteriores. Si falla el commit de registro, el archivo nuevo queda **inactivo**; conservar la credencial anterior y reintentar con una salida nueva. No existe atomicidad entre dos hosts. Transferir el archivo por canal administrativo seguro al sensor, con propietario/permisos exclusivos; nunca montar el registro central en un sensor. Rotación no tiene periodo de gracia. La revocación espera a transacciones ya autorizadas; cuando termina, esas transacciones ya no pueden hacer nuevos commits.

Cada sensor recibe solo su credencial y asignación, no JWT, usuarios, CA privada ni DB central. No puede asignarse otro `sensor_id`: ese campo no existe en el contrato. Los dispositivos se validan frente al registro, sin pertenencia múltiple. No se confía en `simulated` ni en excepciones indicadas por sensores. Hasta portar y validar los adaptadores, solo se entrega el transporte/spool, no un honeypot activable.

## 6. Telemetría, saturación y operación

Contrato: JSON v1 exacto, máximo 64 eventos/lote, 256 KiB/lote y 8 KiB/evento; claves duplicadas, campos desconocidos, flags de supresión y detalles anidados son rechazados. Los detalles son cadenas hostiles acotadas (máximo 16 campos/2 KiB por valor). UUID4 por evento, deduplicación `(sensor, event_id)`; mismo ID con contenido diferente da conflicto. `observed_at` es declaración no confiable; ventanas deterministas usan `received_at` del receptor. IPs canónicas evitan dividir contadores IPv6.

- Spool: 10.000 filas, presupuesto de payload 32 MiB, DB 64 MiB; journal DELETE puede elevar el consumo temporal aproximadamente al doble de la cota DB. No WAL ilimitado. Configurar volumen/cuota de disco del servicio durante provisión aprobada para cubrir journals, logs y margen. No se cambian cuotas del host aquí.
- Receptor: 100.000 eventos, 10.000 por sensor, DB 256 MiB y reserva de disco comprobada; rechazo 503 antes de ACK cuando no puede persistir. No hay borrado automático de eventos ni aceptación sin commit. Cola de notificaciones comparte cota/transaction con eventos.
- Rechazo de nuevos eventos cuando el spool se llena: contador durable cuando es posible, error visible y excepción al productor. Si ni el contador puede escribirse, se emite señal local numérica. Un adaptador debe pausar o contabilizar descartes; aún no hay adaptador heredado certificado.
- Retry exponencial con jitter, máximo aproximado 301 s. 401 conserva eventos y necesita reparar/rotar credencial. 403/409/413/422 ponen el lote en cuarentena **dentro de la misma cota**, dejan pasar lotes posteriores y requieren revisión; no se borra ni se marca como entregado.
- Métricas locales: cola, bytes, antigüedad, descartes persistidos/en proceso, desconexión, próximo retry, cuarentena, eventos/outbox/lag. Contadores en memoria reinician con proceso y se etiquetan como tales. Logs no incluyen comandos/contraseñas.
- La evidencia de sensores comprometidos puede ser falsa aunque esté autenticada. Limitar acceso al almacén, backup cifrado, retención y exportaciones según política del operador. No abrir contenido en shell/hojas de cálculo ni enviarlo indiscriminadamente al modelo.

```sh
python -m runtime.cli status --spool /var/lib/dystopia/sensor/spool.db
python -m runtime.cli status --events /var/lib/dystopia/ingest/events.db
```

Status abre SQLite solo lectura y no crea una DB faltante. El worker de notificaciones conserva eventos si el destino falla; envía solamente sensor/ID/regla. Entrega al menos una vez: el receptor debe deduplicar. La unidad de processor inicialmente observa outbox sin enviar nada; ampliar egress/credencial/destino TLS requiere revisión explícita. Ingestión y outbox comparten identidad Unix de **procesamiento**, pero son procesos separados; no comparten usuario con control o sensores. La unidad del notificador oculta registro de identidades y clave TLS del receptor.

No hay excepciones de detección activas. Se ignoran las allowlists heredadas; una futura excepción debe tener dispositivo/regla/origen acotados, responsable, motivo y caducidad. No se silencian redes privadas, loopback ni eventos marcados simulados. IA permanece fuera del procesamiento v1: no suprime alertas, cambia aislamiento ni bloquea producción.

## 7. Celdas, cuarentena y emergencia

Ver [diseño de aislamiento](<docs/hardening-isolation.md>). La política inicial es estrecha, para laboratorio: direcciones estáticas reservadas, un bridge por celda, vecinos estáticos y ARP/ND/RA/DHCP/VLAN denegados. No es una política de producción genérica.

```sh
python -m runtime.isolation plan --policy deploy/cell.example.json
```

Esto solo renderiza. Para operaciones privilegiadas, el helper acepta exclusivamente un número de celda y carga una política root-owned desde ruta fija; no acepta JSON/argv/XML arbitrarios de la API. Tras autorización específica en laboratorio:

```sh
python -m runtime.isolation apply --cell 1 --confirm CELL-1-APPLY
python -m runtime.isolation quarantine --cell 1 --confirm CELL-1-QUARANTINE
python -m runtime.isolation emergency --cell 1 --confirm CELL-1-EMERGENCY
```

`apply` solo significa que nft aceptó la transacción; **no verifica interfaces, kernel, caminos de tráfico ni conectividad**. `activate` y `verify` siguen fallando por verificador ausente. XML tiene NIC explícita, link down, disco RAW de ruta fija y no expone VNC/serial/filesystems/hostdev. No hay arranque libvirt implementado ni QEMU fallback.

La emergencia es **cuarentena de red**, no un apagado del hipervisor. No se puede confirmar parada de VMs ajenas/heredadas por un PID. Si existían, un administrador debe identificarlas y detenerlas por la herramienta del hipervisor autorizada. Las tablas son exclusivas por celda; no se hace `flush ruleset`, no se borran reglas ajenas ni se retiran al parar/perder control. Reiniciar el host es distinto: persistencia/reconciliación de boot sigue pendiente y no se habilita autostart de VMs. Una tabla existente no se adopta a ciegas: repetir apply/cuarentena puede fallar, conservando filtros existentes.

## 8. Recuperación / reinstalación

- Reejecutar mismo apply reusa secreto/configuración/usuarios. Si difieren archivos, propietarios, unidades o drop-ins, aborta; revisar migración manual, no usar sobreescritura silenciosa.
- Si falló tras crear algunos usuarios/directorios, corregir el prerrequisito y repetir; no borrar secretos válidos. Archivo incompleto preexistente requiere reparación explícita desde backup confiable. Publicación de nuevos archivos usa temporal completo, fsync y enlace exclusivo.
- Revocar inmediatamente un sensor comprometido; mantener filtros y capturar evidencia restringida. Respaldar DB/spool con SQLite backup consistente o servicios parados por el administrador, sin copiar un journal incoherente. No hay purga automática al reinstalar.
- Conservar cuarentena hasta verificar invitado apagado/desconectado y revisar capturas. La retirada de tablas concretas/bridges/discos es operación manual autorizada; inspeccionar nombre/owner/UUID, nunca eliminar por prefijos o limpiar globalmente.
- **Migración obligatoria de bases preexistentes:** los almacenes endurecidos rechazan SQLite legible/escribible por otros (`0644` es habitual); solo `events.db` puede ser `0640` con UID ingest y GID query exactos, tras autorización explícita, mientras que los demás almacenes siguen `0600`. En ese caso la auditoría y las alertas **fallan cerradas**: no se pierden datos, pero no se registran nuevos eventos y el contador `storage_errors` sube en `/api/health`. Antes de arrancar la gestión sobre datos antiguos, verificar y corregir propiedad/modo de forma explícita (`chmod 600 <db>`, mismo propietario que el servicio) y confirmar que `rejected`/`storage_errors` se mantienen en 0. No hay ajuste automático de permisos ni borrado de la base.
- No volver al arranque heredado para resolver un bloqueo: restauraría credencial compartida/default network. Restaurar configuración y datos en frío manteniendo celdas apagadas.
