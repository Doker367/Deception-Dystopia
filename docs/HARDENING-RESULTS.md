# Resultado de la implementación inicial

## 1. Cambios realizados

- Separación de control FastAPI y receptor HTTPS v1; control ya no inicia ni detiene listeners, tailers, QEMU o firewall. Arranques heredados y Compose deception retirados como rutas operativas.
- Identidad individual por sensor con claves aleatorias almacenadas como digest en receptor; ACL por dispositivo, revocación/rotación y serialización de autorización+commit frente a revocación. Sin JWT administrativo como fallback.
- Contrato estricto con límites, UUID/deduplicación, timestamps separados, IP canónica y rechazo de flags de simulación/supresión.
- Spool durable acotado, backpressure y métricas; lotes permanentemente rechazados quedan en cuarentena dentro de la misma cota. Eventos y outbox se confirman juntos; notificador separado, metadatos solamente. Detección determinista también para IPs privadas; sin autoridad de IA.
- Backend inicial local de aislamiento: validación declarativa, XML KVM con NIC explícita down y nft bridge externo por celda, estados distintos y cuarentena aditiva. **No implementa activación/verificación real ni gestión completa libvirt.**
- Instalador guiado/plan sin cambios, apply explícito offline, comprobación de artefactos/propietarios, archivos privados publicados sin sobreescritura, usuarios separados, systemd endurecido y bootstrap local. Solo gestión puede arrancar; requiere bundle/release/venv aprobados previamente.
- JWT sin secreto conocido por defecto; revocación de sesiones al cambiar usuario/rol/hash; auditoría administrativa acotada y sin query/body/tokens. Histórico de usuarios/eventos se migra explícitamente, no se sobrescribe.

## 2. Comprobaciones efectuadas

Estado Git inicial inspeccionado: limpio, commit `1278db4`; host Darwin. Lectura de instrucciones, documentación y código; revisiones estáticas enfocadas de telemetría, aislamiento e instalador, con correcciones de concurrencia/revocación, cuotas SQLite, cuarentena de lotes, permisos/ancestros, publicación de secretos, diagnóstico y extremos temporales. Metadatos de versiones consultados sin obtener paquetes.

**Ejecución del 2026-10-16 (macOS, venv prestado, sin sandbox):**

- Sintaxis: **120 archivos, 0 errores** (AST en modo 3.11).
- `tests/hardening`: **53 passed, 0 failed** (41 subtests), exit 0.
- Suite heredada completa: **105 passed, 17 failed, 4 errores**. Los 21 casos rojos codifican contratos retirados a propósito; el mapeo prueba↔motivo está en [validación](<docs/HARDENING-TESTS.md>). No se arreglan revirtiendo el endurecimiento.
- Arranque real del control en loopback: OK; **único socket en escucha** `127.0.0.1:8099`, ningún puerto de señuelo; `sensors_started: false`.
- Cadena `login → token → /api/auth/me` con usuario de fixture: 200/200; cambio de contraseña revoca el token anterior (401); rutas retiradas devuelven 409/410; credencial de sensor inválida/no asignada/simulada devuelve 401/403/422.
- Sin modificar datos existentes: no se tocaron `config/`, `deception/`, `audit/` ni `backups/`.

**Contención real: NO verificada.** El aislamiento solo se probó con mocks de runner; no se ejecutaron `nft`, libvirt, QEMU, `useradd`, `systemctl` ni nada privilegiado. El resultado acredita lógica de aplicación, no el objetivo soportado (Ubuntu 24.04 / Python 3.12 / pins aprobados).

Defecto real encontrado y corregido: `.gitignore` ignoraba `runtime/`, dejando **todo el código nuevo fuera de Git**; ya está versionable. Segundo hallazgo: un `audit/audit.db` preexistente en `0644` hace fallar la auditoría endurecida de forma cerrada (visible en `/api/health`); requiere migración explícita de permisos.

## 3. Verificaciones y funciones pendientes

- Ejecutar sintaxis/lint/unitarios con sandbox real y dependencias aprobadas; resolver cualquier fallo antes de desplegar. Validar instalación/reinstalación completa y unidades efectivas en Ubuntu 24.04.
- Resolver y aprobar cierre transitivo/hashlock Linux, wheels, venv y disco invitado; revisar aviso de dependencia en [procedencia](<docs/DEPENDENCY-PROVENANCE.md>). Los pins directos son candidatos, no una distribución certificada.
- Portar adaptadores de listeners/Cowrie/OpenCanary al sensor sin configuración administrativa; ahora están bloqueados. El emisor/spool está implementado, no un sensor completo activable.
- Verificador independiente de interfaces, subredes protegidas, topología, kernel, offloads y pruebas guest-root IPv4/IPv6/L2; ciclo libvirt autorizado, AppArmor, boot guard, reconciliación/persistencia tras reinicio y apagado efectivo de VM. **`activate()` siempre falla** hasta que exista esa base. `apply` solo acepta una transacción nft; no significa contención.
- Filtros de servicio/red y TLS efectivos del receptor/sensor, CA, revocación concurrente, saturación y notificaciones. Un ejemplo systemd no prueba aplicación efectiva de cgroup/BPF.

## 4. Riesgos residuales

Un sensor comprometido puede mentir sobre sus dispositivos asignados y perder/falsificar sus propios eventos. Un flujo de respuesta permitido puede transportar datos hostiles. Saturación sigue causando rechazo visible y necesita respuesta operativa; falta automatizar archivo/retención aprobados. Kernel, hipervisor, conntrack, helper, CA y operador siguen siendo confianza crítica. No se ha demostrado resistencia a escapes ni agotamiento de recursos en red. La nueva ingestión no está integrada en el visor histórico; las rupturas están descritas en [migración](<MIGRATION.md>). Esto no es una base lista para producción ni una garantía de seguridad absoluta.

## 5. Pasos que requieren autorización del administrador

1. Facilitar sandbox de ejecución y laboratorio Linux desechable sin conexiones reales; ejecutar la matriz y conservar evidencia sintética.
2. Aprobar suministro de paquetes/imágenes, crear bundle/hashlock y revisar release/venv. No se descarga nada automáticamente.
3. Autorizar creación de archivos/usuarios/unidades y `daemon-reload`; aplicar únicamente con `--apply --confirm APPLY-MANAGEMENT-ONLY`, crear primer administrador local mediante TTY y repetir apply para arrancar gestión en loopback.
4. Autorizar por separado certificados, ruta estricta de telemetría y cada operación de red/nft/libvirt del laboratorio. No autorizar producción ni quitar bloqueos por un campo de configuración.

Los comandos completos, prerrequisitos y recuperación están en [operaciones](<docs/HARDENING-OPERATIONS.md>). No se cambiaron redes, usuarios, firewall ni servicios del host actual; no se inició ningún honeypot/VM ni se ejecutaron ataques.
