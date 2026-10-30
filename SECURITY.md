# Seguridad

La frontera está documentada en [arquitectura](<docs/HARDENING.md>). Un sensor o invitado comprometido no debe obtener secretos administrativos ni autoridad de hipervisor. El nuevo receptor valida credenciales individuales sobre HTTPS y dispositivos asignados; la identidad no hace confiable el contenido capturado.

La API no inicia listeners/QEMU ni ejecuta firewall. El helper privilegiado es local, con operaciones cerradas y políticas root-owned; **la activación está bloqueada** por falta de verificador independiente. Las reglas generadas no son prueba de contención. VLAN y Docker internal no bastan.

No hay autorización para usar datos reales, hacer pruebas en producción o cambiar redes/servicios del equipo de desarrollo. Ver [validación pendiente](<docs/HARDENING-TESTS.md>) y [procedencia y avisos de dependencias](<docs/DEPENDENCY-PROVENANCE.md>). No se promete seguridad absoluta ni despliegue reproducible validado mientras falten bundle aprobado y laboratorio.
