# Base de endurecimiento — diagnóstico y plan

## Revisión inicial (2026-10-16)

Base: commit `1278db4`; árbol limpio al iniciar. Host de edición: macOS, no Ubuntu. No se han arrancado señuelos ni cambiado redes/servicios. La prueba de disponibilidad de sandbox fue rechazada por el ejecutor: `sandbox_apply: Operation not permitted`. No ejecutar código del proyecto sin sandbox adecuado; pruebas dinámicas y laboratorio pendientes.

Hallazgos de código (no una auditoría exhaustiva):
- `app/main.py` iniciaba motor y tailer en lifespan al habilitar deception.
- `app/routers/deception.py` mezclaba administración, ingestión con token compartido/JWT, listeners y firewall.
- `app/services/deception/vm_svc.py` lanzaba QEMU sin NIC explícita; control tenía acceso a discos, PID, VNC y serial.
- `app/core/security.py` permitía clave JWT conocida fuera de producción.
- Listeners/tailers importaban configuración global y persistían directamente vía `telemetry_svc`/SQLite. No eran sensores de privilegios mínimos.
- `alert_svc` usaba executor sin límite de pendientes, aceptaba `detail.simulated`, allowlist sin caducidad y gating de IA; telemetría enviaba contenido capturado a Loki.
- Compose confiaba en `internal: true`, usaba imágenes sin fijación y no demostraba contención.

## Fronteras de confianza

```text
administrador -> loopback/TLS gestión -> FastAPI control -> usuarios/configuración
                         X sin listeners, QEMU, libvirt ni socket privilegiado
señuelo comprometido -> sensor por celda (identidad limitada, buffer acotado)
                         -> HTTPS autenticado -> servicio ingestión independiente
                         -> SQLite eventos + outbox -> procesador/notificador
operador local -> helper privilegiado de operaciones cerradas -> nft bridge/libvirt
                                      -> reglas externas al invitado
```

Un invitado con root puede falsificar o perder toda la telemetría de SU celda y robar su credencial. No debe obtener claves JWT, DB central, credenciales de otros sensores, consola/almacenamiento del hipervisor ni iniciar tráfico hacia producción/gestión/Internet/otras celdas. La identidad no hace veraz el contenido del sensor. El kernel/hipervisor, helper, configuración del operador, CA y receptor siguen siendo confianza crítica. Ataques al hipervisor y canales encubiertos en respuestas autorizadas son riesgos residuales. Una VLAN no es contención. La pérdida del controlador no debe retirar filtros.

## Fases / compatibilidad

1. Control: eliminar arranques y bloquear operaciones heredadas; conservar lectura/configuración administrativa segura. Nuevos módulos `runtime` sin importar configuración administrativa: contrato v1, registro por sensor, servicio ingestión separado y emisor HTTPS. Nuevas bases SQLite; no modificar eventos históricos.
2. Aislamiento: `runtime/isolation`, política y render Linux KVM/libvirt/nft, operaciones cerradas y estados. Activación bloqueada mientras no exista verificación externa suficiente. Sin fallback QEMU/bridge/NAT.
3. Instalación: `runtime/install.py`, plantillas systemd, manifiesto de despliegue explícito, plan sin escrituras, aplicación offline autorizada, secretos exclusivos y alta local. Sin descarga automática ni imágenes inventadas.
4. Telemetría: spool acotado, persistencia transaccional con deduplicación y outbox, detección determinista, métricas de saturación. IA sin autoridad. Contenido capturado no se envía a logs/modelo.
5. Pruebas de regresión y laboratorio sintético; guías de migración, cuarentena y recuperación. Revisión estática por fase; ejecución pendiente si el sandbox no está disponible.

Rupturas necesarias: ingestión antigua y arranque de motor/VM desde API ya no son soportados; flags antiguos no reactivan funciones inseguras. Los sensores heredados y el motor Go no son compatibles con el contrato/aislamiento nuevos hasta portar sus adaptadores. No se migra silenciosamente ninguna credencial compartida ni configuración de red.
