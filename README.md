# Dystopia

Plataforma Python/FastAPI de deception, en endurecimiento para Ubuntu Server 24.04 LTS con KVM/libvirt.

**Base inicial, no despliegue certificado.** Control separado de ingestión/sensores. Arranque heredado de listeners/QEMU retirado; activación de celdas bloqueada hasta verificación real. No hay contraseñas predeterminadas ni bootstrap público.

- [Arquitectura y diagnóstico](<docs/HARDENING.md>)
- [Instalación, operación y recuperación](<docs/HARDENING-OPERATIONS.md>)
- [Pruebas y pendientes](<docs/HARDENING-TESTS.md>) — pruebas ASGI ejecutadas; contención Linux pendiente
- [Sistema unificado: arquitectura y operación](<docs/UNIFIED-DECEPTION.md>) — [procedimiento operativo](<docs/UNIFIED-OPERATIONS.md>) — [informe de validación](<docs/UNIFIED-VALIDATION.md>)
- [Consola operativa: contratos, roles y guía](<docs/CONSOLE-OPERATIONS.md>)
- [Puente de consulta Unix: arquitectura, despliegue pendiente y diagnóstico](<docs/QUERY-BRIDGE.md>)
- [Migración](<MIGRATION.md>) y [procedencia de dependencias](<docs/DEPENDENCY-PROVENANCE.md>)

Plan sin cambios: `python3 -m runtime.install --dry-run --config deploy/install.example.json`.

No ejecutar instalación, servicios o laboratorio sin autorización y prerrequisitos. `.env` ya no se carga automáticamente. El material anterior de fases/Compose es histórico, no una guía de despliegue endurecido.
